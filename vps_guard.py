#!/usr/bin/env python3
"""VPS Guard: explicit, recoverable stages for Debian/Ubuntu. Python 3.10+."""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import datetime as dt
import getpass
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
import uuid

VERSION = "0.1.0"
CONFIG = "/etc/vps-guard/config.json"
STATE = "/var/lib/vps-guard"
NETWORK_FILE = "/etc/sysctl.d/99-vps-guard-network.conf"
SSH_FILE = "/etc/ssh/sshd_config.d/00-vps-guard.conf"
SSH_POLICY = {
    "PubkeyAuthentication": "yes", "PasswordAuthentication": "no",
    "KbdInteractiveAuthentication": "no", "PermitRootLogin": "no",
    "PermitEmptyPasswords": "no", "X11Forwarding": "no",
    "AllowAgentForwarding": "no",
}
TCP_BASE = {
    "net.core.default_qdisc": "fq",
    "net.ipv4.tcp_congestion_control": "bbr",
    "net.ipv4.tcp_moderate_rcvbuf": "1",
    "net.ipv4.tcp_window_scaling": "1", "net.ipv4.tcp_sack": "1",
    "net.ipv4.tcp_timestamps": "1", "net.ipv4.tcp_mtu_probing": "1",
}
STAGES = ("baseline", "access", "ssh", "firewall", "network", "swap", "maintenance", "backup")
ATTESTATIONS = {
    "auth_rejection": "已从外部验证 root 和密码 SSH 被拒绝，运维账号密钥可用",
    "ban_test": "已从独立测试来源验证 Fail2ban 封禁与解除，管理入口正常",
    "application_review": "已验证业务权限、认证、TLS、容器暴露和实际资源限制",
    "external_reachability": "已从外部检查 IPv4／IPv6、业务端口、Docker 和云防火墙",
    "performance": "已完成同端点的修改前后性能比较，记录吞吐、延迟和资源情况",
    "notifications": "已实际测试通知送达，并配置外部离线检测",
    "service_restore": "已恢复业务数据并验证服务启动和数据一致性",
}
DEFAULTS = {
    "admin_user": "ops", "admin_public_keys": [], "provider_console_verified": False,
    "business_ports_confirmed": False, "ssh_port": None, "ssh_sources": [],
    "business_ports": [], "timezone": "UTC", "upgrade_packages": True,
    "swap_mib": None, "rollback_minutes": 5,
    "network": {"devices": [], "target_bandwidth_mbps": None,
                "representative_rtt_ms": None, "tcp_buffer_max_bytes": None,
                "socket_buffer_max_bytes": None},
    "backup": {"enabled": False, "env_file": "/etc/vps-guard/backup.env",
               "paths": ["/etc"], "calendar": "daily"},
    "notify_env_file": "/etc/vps-guard/notify.env",
}


class GuardError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def merge_config(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in extra.items():
        if k not in out:
            raise GuardError(f"未知配置字段：{k}")
        if isinstance(out[k], dict):
            if not isinstance(v, dict):
                raise GuardError(f"{k} 必须是 JSON 对象")
            out[k] = merge_config(out[k], v)
        else:
            out[k] = v
    return out


def valid_key(key: str) -> bool:
    if "\n" in key or "\r" in key:
        return False
    parts = key.split()
    if len(parts) < 2 or parts[0] not in ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
                                        "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
                                        "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"):
        return False
    try:
        raw = base64.b64decode(parts[1], validate=True)
        n = int.from_bytes(raw[:4], "big")
        return 0 < n < 128 and raw[4:4+n].decode() == parts[0] and len(raw) > 4+n+8
    except (ValueError, UnicodeError):
        return False


def validate_config(c: dict) -> None:
    if not isinstance(c["admin_user"], str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", c["admin_user"]):
        raise GuardError("admin_user 仅支持普通 Linux 用户名")
    if c["admin_user"] == "root":
        raise GuardError("admin_user 不能是 root")
    for k in ("provider_console_verified", "business_ports_confirmed", "upgrade_packages"):
        if type(c[k]) is not bool:
            raise GuardError(f"{k} 必须是布尔值")
    for k in ("admin_public_keys", "ssh_sources", "business_ports", "network.devices"):
        value = c["network"]["devices"] if k == "network.devices" else c[k]
        if not isinstance(value, list):
            raise GuardError(f"{k} 必须是数组")
    if any(not isinstance(x, str) or not valid_key(x) for x in c["admin_public_keys"]):
        raise GuardError("公钥格式错误：只填写公钥，不填写私钥或 authorized_keys 选项")
    if c["ssh_port"] is not None and (type(c["ssh_port"]) is not int or not 1 <= c["ssh_port"] <= 65535):
        raise GuardError("ssh_port 必须为 1..65535 或 null")
    for source in c["ssh_sources"]:
        try:
            ipaddress.ip_network(source, strict=False)
        except (ValueError, TypeError):
            raise GuardError("ssh_sources 必须是 IP 或 CIDR") from None
    for item in c["business_ports"]:
        if not isinstance(item, dict) or set(item) != {"port", "protocol", "source"}:
            raise GuardError("业务端口需包含且仅包含 port、protocol、source")
        if type(item["port"]) is not int or not 1 <= item["port"] <= 65535:
            raise GuardError("业务端口越界")
        if item["protocol"] not in ("tcp", "udp"):
            raise GuardError("端口协议必须是 tcp 或 udp")
        if not isinstance(item["source"], str):
            raise GuardError("业务来源必须是字符串")
        if item["source"] != "any":
            try:
                ipaddress.ip_network(item["source"], strict=False)
            except (ValueError, TypeError):
                raise GuardError("业务来源必须是 any、IP 或 CIDR") from None
    if type(c["rollback_minutes"]) is not int or not 3 <= c["rollback_minutes"] <= 30:
        raise GuardError("自动恢复等待时间必须在 3..30 分钟")
    if c["swap_mib"] is not None and (type(c["swap_mib"]) is not int or not 128 <= c["swap_mib"] <= 8192):
        raise GuardError("swap_mib 为 null 或 128..8192；已有 Swap 默认保留")
    if not isinstance(c["timezone"], str) or not re.fullmatch(r"[A-Za-z0-9_+./-]+", c["timezone"]) or ".." in c["timezone"]:
        raise GuardError("时区格式错误")
    for dev in c["network"]["devices"]:
        if not isinstance(dev, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", dev):
            raise GuardError("网卡名称格式错误")
    for k in ("target_bandwidth_mbps", "representative_rtt_ms"):
        v = c["network"][k]
        if v is not None and (type(v) not in (int, float) or not math.isfinite(v) or not 0 < v <= 1e6):
            raise GuardError(f"network.{k} 必须为正数或 null")
    for k in ("tcp_buffer_max_bytes", "socket_buffer_max_bytes"):
        v = c["network"][k]
        if v is not None and (type(v) is not int or not 4096 <= v <= 67108864):
            raise GuardError(f"network.{k} 为 null 或 4096..67108864")
    if type(c["backup"]["enabled"]) is not bool:
        raise GuardError("backup.enabled 必须是布尔值")
    if c["backup"]["calendar"] not in ("daily", "hourly", "weekly"):
        raise GuardError("备份周期支持 daily、hourly、weekly")
    paths = c["backup"]["paths"]
    if not isinstance(paths, list) or not paths:
        raise GuardError("backup.paths 必须是非空数组")
    for p in paths:
        if not isinstance(p, str) or not p.startswith("/") or p == "/" or ".." in Path(p).parts:
            raise GuardError("备份路径必须为明确的绝对目录，不能是整个根目录")
    for p in (c["backup"]["env_file"], c["notify_env_file"]):
        if not isinstance(p, str) or not p.startswith("/etc/vps-guard/") or ".." in Path(p).parts:
            raise GuardError("凭据引用必须位于 /etc/vps-guard/ 内")


class Runner:
    def run(self, args, *, check=True, interactive=False, env=None, timeout=90):
        args = [str(x) for x in args]
        try:
            command_env = dict(os.environ if env is None else env)
            command_env["LC_ALL"] = "C"
            p = subprocess.run(args, text=True, encoding="utf-8", errors="replace",
                               capture_output=not interactive, env=command_env, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            if check:
                raise GuardError(f"命令不可用或超时：{args[0]} ({type(e).__name__})") from None
            return 127, "", type(e).__name__
        out, err = (p.stdout or ""), (p.stderr or "")
        if check and p.returncode:
            # Do not leak arbitrary subprocess output (credentials may be present).
            raise GuardError(f"命令失败：{args[0]}，退出码 {p.returncode}")
        return p.returncode, out.strip(), err.strip()


class Guard:
    def __init__(self, root=Path("/"), runner=None):
        self.root = Path(root).resolve()
        if self.root != Path("/").resolve() and runner is None:
            raise GuardError("测试根目录必须配合模拟命令执行器")
        self.runner = runner or Runner()
        self.tx = None

    def fs(self, path):
        if not str(path).startswith("/") or ".." in Path(path).parts:
            raise GuardError("不安全的文件路径")
        return self.root / str(path).lstrip("/")

    def read(self, path, default=""):
        try:
            return self.fs(path).read_text(encoding="utf-8")
        except FileNotFoundError:
            return default

    def run(self, *args, **kw):
        return self.runner.run(args, **kw)

    def out(self, *args):
        return self.run(*args, check=False)[1]

    def secure_parents(self, path):
        current = self.fs(path).parent
        while current != self.root and current != current.parent:
            if current.is_symlink():
                raise GuardError(f"父目录为符号链接，拒绝写入：{path}")
            if current.exists() and self.root == Path("/"):
                st = current.stat()
                if st.st_uid != 0 or st.st_mode & 0o022:
                    # Home directories are intentionally writable by their owner.
                    if not str(current).startswith("/home/"):
                        raise GuardError(f"父目录权限不安全：{current}")
            current = current.parent

    def atomic(self, path, data, mode=0o600, owner=None):
        p = self.fs(path)
        self.secure_parents(path)
        if p.is_symlink() or (p.exists() and not p.is_file()):
            raise GuardError(f"目标不是普通文件：{path}")
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp-" + uuid.uuid4().hex)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            with os.fdopen(fd, "wb") as f:
                f.write(data if isinstance(data, bytes) else data.encode())
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, mode)
            if owner is not None and hasattr(os, "chown"):
                os.chown(tmp, *owner)
            os.replace(tmp, p)
        finally:
            tmp.unlink(missing_ok=True)

    def config(self):
        p = self.fs(CONFIG)
        if not p.exists():
            raise GuardError("尚未配置。先运行 sudo vps-guard setup")
        if p.is_symlink():
            raise GuardError("配置文件不能是符号链接")
        if self.root == Path("/"):
            st = p.stat()
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise GuardError("配置必须归 root 所有，且其他用户不可写")
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError()
            c = merge_config(DEFAULTS, raw)
        except (ValueError, TypeError):
            raise GuardError("配置不是有效 JSON 对象") from None
        validate_config(c)
        return c

    @contextlib.contextmanager
    def lock(self):
        import fcntl
        p = self.fs(STATE)
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(p, 0o700)
        with (p / "lock").open("a") as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise GuardError("另一个 VPS Guard 任务正在执行") from None
            yield

    def os_release(self):
        d = {}
        for line in self.read("/etc/os-release").splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                d[k] = v.strip('"\'')
        return d

    def preflight(self, *, rescue=False):
        if self.os_release().get("ID") not in ("debian", "ubuntu"):
            raise GuardError("首版应用操作仅支持 Debian／Ubuntu")
        if not self.fs("/run/systemd/system").is_dir():
            raise GuardError("应用操作需要 systemd")
        if rescue and not self.config()["provider_console_verified"]:
            raise GuardError("请先实际验证服务商控制台，再在 setup 中记录")

    def session(self):
        # sudo may filter SSH_CONNECTION. Inspect only this field in ancestor environments.
        value = os.environ.get("SSH_CONNECTION", "")
        pid = os.getppid()
        for _ in range(12):
            if value or pid <= 1:
                break
            try:
                raw = self.fs(f"/proc/{pid}/environ").read_bytes()
                for entry in raw.split(b"\0"):
                    if entry.startswith(b"SSH_CONNECTION="):
                        value = entry.partition(b"=")[2].decode("ascii")
                status = self.read(f"/proc/{pid}/status")
                m = re.search(r"^PPid:\s+(\d+)", status, re.M)
                pid = int(m.group(1)) if m else 0
            except (OSError, UnicodeError):
                break
        parts = value.split()
        if len(parts) != 4:
            return None
        try:
            ipaddress.ip_address(parts[0]); ipaddress.ip_address(parts[2])
            if not all(0 < int(parts[x]) < 65536 for x in (1, 3)):
                return None
        except ValueError:
            return None
        return " ".join(parts)

    def effective_ssh(self, user=None):
        cmd = ["/usr/sbin/sshd", "-T"]
        session = self.session()
        if user and session:
            client, _, local, port = session.split()
            cmd += ["-C", f"user={user},addr={client},host={client},laddr={local},lport={port}"]
        rc, out, _ = self.runner.run(cmd, check=False)
        if rc:
            raise GuardError("无法读取 sshd 最终配置")
        d = {}
        for line in out.splitlines():
            k, _, v = line.partition(" ")
            d.setdefault(k, []).append(v)
        return d

    def ssh_ports(self):
        c = self.config()
        actual = [int(x) for x in self.effective_ssh().get("port", []) if x.isdigit()]
        if c["ssh_port"] is not None and c["ssh_port"] not in actual:
            raise GuardError("配置端口与 sshd 不一致；首版保留原端口，改端口需另行迁移")
        if not actual:
            raise GuardError("无法确认 SSH 端口")
        return actual

    def meminfo(self):
        return {k: int(v) * 1024 for k, v in re.findall(r"^(\w+):\s+(\d+) kB", self.read("/proc/meminfo"), re.M)}

    def audit(self):
        osr = self.os_release()
        try:
            ssh = self.effective_ssh()
            ssh = {k: ssh.get(k) for k in ("port", "permitrootlogin", "passwordauthentication",
                                          "kbdinteractiveauthentication", "pubkeyauthentication")}
        except GuardError:
            ssh = {"status": "无法读取，可能需要 sudo 或安装 OpenSSH"}
        return {
            "version": VERSION, "time": utc(), "hostname": self.out("hostname"),
            "os": {k: osr.get(k) for k in ("ID", "VERSION_ID", "PRETTY_NAME")},
            "kernel": self.out("uname", "-r"), "virtualization": self.out("systemd-detect-virt"),
            "memory": self.meminfo(), "swap": self.out("swapon", "--show", "--bytes"),
            "disk": self.out("df", "-h", "/"), "ssh": ssh,
            "listeners": self.out("ss", "-lntup"),
            "firewall": self.out("ufw", "status", "verbose"),
            "fail2ban": self.out("fail2ban-client", "status", "sshd"),
            "docker_ports": self.out("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"),
            "congestion_control": self.out("sysctl", "-n", "net.ipv4.tcp_congestion_control"),
            "available_algorithms": self.out("sysctl", "-n", "net.ipv4.tcp_available_congestion_control"),
            "qdiscs": self.out("tc", "qdisc", "show"),
            "failed_units": self.out("systemctl", "--failed", "--no-legend", "--plain"),
            "time_sync": self.out("timedatectl", "show", "--property=NTPSynchronized", "--value"),
            "apparmor": self.out("systemctl", "is-active", "apparmor"),
            "selinux": self.out("getenforce"),
            "note": "外部端口可达性、业务认证和性能改善需单独验证；本检查不修改系统配置。",
        }

    def pending(self):
        txdir = self.fs(STATE + "/runs")
        found = []
        if txdir.exists():
            for p in txdir.glob("*/manifest.json"):
                m = json.loads(p.read_text())
                if m["status"] == "awaiting_confirmation":
                    found.append(m)
        return found

    def start(self, stage):
        if self.pending():
            raise GuardError("尚有等待确认的变更；先从新连接确认或执行恢复")
        ident = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:10]
        self.tx = {"id": ident, "stage": stage, "time": utc(), "status": "running",
                   "origin_session": self.session(), "files": {}, "runtime": {}, "notes": [],
                   "boot_id": self.read("/proc/sys/kernel/random/boot_id").strip()}
        self.save_tx()
        return ident

    def save_tx(self):
        self.atomic(f"{STATE}/runs/{self.tx['id']}/manifest.json", json.dumps(self.tx, ensure_ascii=False, indent=2))

    def write(self, path, data, mode=0o600, owner=None):
        raw = data if isinstance(data, bytes) else data.encode()
        p = self.fs(path)
        if p.is_symlink():
            raise GuardError(f"拒绝覆盖符号链接：{path}")
        owner_matches = owner is None or (p.exists() and (p.stat().st_uid, p.stat().st_gid) == owner)
        if p.exists() and p.read_bytes() == raw and stat.S_IMODE(p.stat().st_mode) == mode and owner_matches:
            return False
        files = self.tx["files"]
        if path not in files:
            item = {"existed": p.exists()}
            if p.exists():
                st = p.stat()
                backup = f"{STATE}/runs/{self.tx['id']}/files/{len(files):04d}"
                self.atomic(backup, p.read_bytes())
                item.update(backup=backup, mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid)
            files[path] = item
            self.save_tx()
        # Persist intended postimage BEFORE mutation so crash recovery is possible.
        files[path]["installed_sha256"] = sha(raw)
        self.save_tx()
        self.atomic(path, raw, mode, owner)
        return True

    def arm(self):
        if not self.tx["origin_session"]:
            raise GuardError("SSH／防火墙／队列变更需从可识别的 SSH 会话运行")
        minutes = self.config()["rollback_minutes"]
        unit = "vps-guard-rollback-" + self.tx["id"].lower()
        self.tx.update(status="awaiting_confirmation", guard_unit=unit,
                       deadline=time.time() + minutes * 60)
        self.save_tx()
        self.run("systemd-run", "--quiet", "--unit=" + unit, f"--on-active={minutes}m",
                 "--timer-property=AccuracySec=1s", "--property=Restart=on-failure",
                 "--property=RestartSec=5s", "/usr/local/bin/vps-guard",
                 "rollback", self.tx["id"], "--automatic")
        if self.out("systemctl", "is-active", unit + ".timer") != "active":
            raise GuardError("自动恢复计时器未启动，停止修改")

    def finish(self):
        if self.tx["status"] == "awaiting_confirmation":
            print(f"变更 {self.tx['id']} 等待新 SSH 连接确认，超时将自动恢复。")
            print(f"在新 Netcatty 连接中执行：sudo vps-guard confirm {self.tx['id']}")
        else:
            self.tx["status"] = "committed"
            self.save_tx()
            self.record_stage()
            print(f"阶段完成：{self.tx['stage']}；记录：{self.tx['id']}")
        for note in self.tx["notes"]:
            print("提示：" + note)

    def note(self, msg):
        self.tx["notes"].append(msg)
        self.save_tx()

    def remember_unit(self, unit):
        units = self.tx["runtime"].setdefault("units", {})
        if unit not in units:
            units[unit] = {"enabled": self.out("systemctl", "is-enabled", unit) == "enabled",
                           "active": self.out("systemctl", "is-active", unit) == "active"}
            self.save_tx()

    def wait_ok(self, *args, seconds=8):
        deadline = time.monotonic() + seconds
        while True:
            if self.run(*args, check=False)[0] == 0:
                return
            if time.monotonic() >= deadline:
                raise GuardError(f"服务尚未就绪：{args[0]}")
            time.sleep(0.25)

    def apply(self, stage):
        self.preflight(rescue=True)
        self.config()
        if self.pending():
            raise GuardError("尚有等待确认的变更，先确认或恢复")
        if self.stage_current(stage):
            print(f"阶段 {stage} 已符合本版本及当前配置，未重复应用。")
            return
        self.start(stage)
        try:
            getattr(self, "stage_" + stage)()
            self.finish()
        except Exception:
            ident = self.tx["id"]
            try:
                self.rollback(ident, automatic=True)
            except Exception:
                print(f"自动恢复未完整成功，请通过保留会话／控制台检查记录 {ident}", file=sys.stderr)
            raise

    def record_stage(self):
        files = {}
        for path in self.tx["files"]:
            if self.fs(path).is_file():
                files[path] = sha(self.fs(path).read_bytes())
        marker = {"version": VERSION, "config_digest": sha(json.dumps(self.config(), sort_keys=True).encode()),
                  "files": files, "time": utc()}
        if self.tx["stage"] == "firewall":
            marker["ufw_status"] = self.out("ufw", "status", "verbose")
        self.atomic(STATE + "/stages/" + self.tx["stage"] + ".json", json.dumps(marker))

    def stage_current(self, stage):
        if stage not in ("ssh", "firewall", "network"):
            return False
        marker = json.loads(self.read(STATE + "/stages/" + stage + ".json", "{}"))
        digest = sha(json.dumps(self.config(), sort_keys=True).encode())
        if marker.get("version") != VERSION or marker.get("config_digest") != digest:
            return False
        for path, expected in marker.get("files", {}).items():
            if not self.fs(path).is_file() or sha(self.fs(path).read_bytes()) != expected:
                return False
        try:
            if stage == "ssh":
                self.assert_ssh()
            elif stage == "firewall":
                status = self.out("ufw", "status", "verbose")
                if "Status: active" not in status or marker.get("ufw_status") != status:
                    return False
                if self.out("docker", "ps", "-q") or self.run("fail2ban-client", "status", "sshd", check=False)[0]:
                    return False
            else:
                self.network_ensure(check_only=True)
                for key, value in self.tcp_values().items():
                    if self.out("sysctl", "-n", key).split() != value.split():
                        return False
        except (GuardError, ValueError):
            return False
        return True

    def stage_baseline(self):
        c = self.config()
        rc, audit, _ = self.run("dpkg", "--audit", check=False)
        if rc or audit:
            raise GuardError("软件包状态异常，先处理 dpkg 审计结果")
        self.run("apt-get", "update", interactive=True, timeout=600)
        if c["upgrade_packages"]:
            self.run("apt-get", "upgrade", "--with-new-pkgs", "-y", interactive=True, timeout=1800)
        self.run("apt-get", "install", "-y", "sudo", "openssh-server", "ufw", "fail2ban",
                 "python3-systemd", "unattended-upgrades", "ca-certificates", "iproute2", "kmod",
                 "procps", "logrotate", interactive=True, timeout=1800)
        self.run("timedatectl", "set-timezone", c["timezone"])
        self.run("timedatectl", "set-ntp", "true")
        self.note("软件升级和时区／时间服务操作不属于文件回滚；必要时使用快照或重建。")
        if self.fs("/var/run/reboot-required").exists():
            self.note("系统提示需要重启；请在维护窗口重启后继续。")

    def key_digest(self):
        c = self.config()
        return sha(json.dumps([c["admin_user"], c["admin_public_keys"]], sort_keys=True).encode())

    def stage_access(self):
        import pwd
        c = self.config()
        user = c["admin_user"]
        if not c["admin_public_keys"]:
            raise GuardError("先通过 setup 填入管理公钥")
        try:
            account = pwd.getpwnam(user)
        except KeyError:
            self.run("adduser", "--disabled-password", "--gecos", "", user)
            account = pwd.getpwnam(user)
            self.note(f"创建了账号 {user}；回滚保留账号，避免删除其业务数据。")
        if account.pw_uid == 0 or not account.pw_shell.endswith(("/bash", "/sh", "/zsh")):
            raise GuardError("运维账号 UID／登录 shell 不符合要求")
        home = Path(account.pw_dir)
        if not str(home).startswith("/home/") or home.is_symlink():
            raise GuardError("首版要求运维账号使用 /home 下的普通主目录")
        sshdir = home / ".ssh"
        if sshdir.is_symlink():
            raise GuardError(".ssh 目录不能是符号链接")
        sshdir.mkdir(exist_ok=True, mode=0o700)
        os.chmod(sshdir, 0o700); os.chown(sshdir, account.pw_uid, account.pw_gid)
        path = str(sshdir / "authorized_keys")
        old = self.read(path)
        lines = old.splitlines()
        existing = {" ".join(x.split()[:2]) for x in lines if x.strip()}
        for key in c["admin_public_keys"]:
            if " ".join(key.split()[:2]) not in existing:
                lines.append(key.strip())
        self.write(path, "\n".join(lines) + "\n", 0o600, (account.pw_uid, account.pw_gid))
        self.run("usermod", "-aG", "sudo", user)
        status = self.out("passwd", "-S", user).split()
        if len(status) < 2 or status[1] != "P":
            print(f"请为 {user} 设置本地 sudo 密码；输入不会回显。")
            self.run("passwd", user, interactive=True, timeout=300)
        proof = {"origin": self.session(), "digest": self.key_digest(), "time": utc(),
                 "boot_id": self.read("/proc/sys/kernel/random/boot_id").strip()}
        self.atomic(STATE + "/access-pending.json", json.dumps(proof))
        print(f"在 Netcatty 新建 {user} 的密钥连接，再运行：sudo vps-guard confirm-login")
        self.note("账号、组成员及密码变更不会自动删除或逆转；尚未关闭 root／密码 SSH。")

    def confirm_login(self):
        c = self.config()
        if os.environ.get("SUDO_USER") != c["admin_user"]:
            raise GuardError("请从新运维账号登录，并通过 sudo 执行本命令")
        pending = json.loads(self.read(STATE + "/access-pending.json", "{}"))
        session = self.session()
        if not session or session == pending.get("origin") or pending.get("digest") != self.key_digest():
            raise GuardError("需要独立的新 SSH 连接，且配置公钥须与 access 阶段一致")
        if pending.get("boot_id") != self.read("/proc/sys/kernel/random/boot_id").strip():
            raise GuardError("系统已重启，请重新执行 access 检查")
        answer = input("确认本次在 Netcatty 选择了密钥认证且 sudo 已成功，输入 KEY：").strip()
        if answer != "KEY":
            raise GuardError("未记录密钥登录确认")
        proof = {"digest": self.key_digest(), "session": session, "time": utc(),
                 "boot_id": pending["boot_id"]}
        self.atomic(STATE + "/access-verified.json", json.dumps(proof))
        print("已记录独立运维账号登录和 sudo 确认；可返回原会话执行 SSH 加固。")

    def stage_ssh(self):
        c = self.config()
        proof = json.loads(self.read(STATE + "/access-verified.json", "{}"))
        if proof.get("digest") != self.key_digest() or proof.get("boot_id") != self.read("/proc/sys/kernel/random/boot_id").strip():
            raise GuardError("尚未通过独立的运维账号密钥登录及 sudo 确认")
        text = self.read("/etc/ssh/sshd_config")
        effective_lines = [x.strip() for x in text.splitlines() if x.strip() and not x.lstrip().startswith("#")]
        if not effective_lines or not re.fullmatch(r"(?i)Include\s+/etc/ssh/sshd_config\.d/\*\.conf", effective_lines[0]):
            raise GuardError("SSH Include 布局非标准，首版停止自动修改，请先检查主配置")
        self.run("/usr/sbin/sshd", "-t")
        self.arm()
        policy = "# Managed by VPS Guard\n" + "\n".join(k + " " + v for k, v in SSH_POLICY.items()) + "\n"
        self.write(SSH_FILE, policy, 0o600)
        self.run("/usr/sbin/sshd", "-t")
        self.assert_ssh()
        self.run("systemctl", "reload", "ssh.service")
        self.note("保留 SSH 端口、SFTP 和 TCP 端口转发；重连后另行测试密码及 root 被拒绝。")

    def assert_ssh(self):
        d = self.effective_ssh(self.config()["admin_user"])
        for k, v in SSH_POLICY.items():
            if d.get(k.lower(), [None])[0] != v:
                raise GuardError(f"SSH 最终配置不符合目标：{k}；检查更早的片段和 Match")
        droot = self.effective_ssh("root")
        if droot.get("permitrootlogin", [None])[0] != "no":
            raise GuardError("root 的 Match 条件仍允许 SSH")

    def stage_firewall(self):
        c = self.config()
        if not c["business_ports_confirmed"]:
            raise GuardError("先确认业务端口清单，空清单也需明确确认")
        for svc in ("firewalld", "nftables", "netfilter-persistent"):
            if self.out("systemctl", "is-active", svc) == "active":
                raise GuardError(f"检测到 {svc}，首版不自动与 UFW 混合管理")
        status = self.out("ufw", "status")
        if not status:
            raise GuardError("先执行 baseline 安装 UFW")
        if "Status: active" not in status:
            rules = self.out("iptables", "-S", "INPUT").splitlines()
            if any(x.strip() != "-P INPUT ACCEPT" for x in rules if x.strip()):
                raise GuardError("检测到非 UFW 管理的 INPUT 规则，停止自动启用 UFW")
        ports = self.ssh_ports()
        self.tx["runtime"]["ufw_active"] = "Status: active" in status
        self.save_tx()
        # Preserve UFW's own configuration files, including before/after rules.
        paths = [p for p in self.fs("/etc/ufw").rglob("*") if p.is_file() and not p.is_symlink()]
        for p in paths:
            rel = "/" + p.relative_to(self.root).as_posix()
            self.tx["files"][rel] = {"existed": True, "backup": f"{STATE}/runs/{self.tx['id']}/ufw/{p.relative_to(self.fs('/etc/ufw')).as_posix()}",
                                      "mode": stat.S_IMODE(p.stat().st_mode), "uid": p.stat().st_uid, "gid": p.stat().st_gid,
                                      "ufw_managed": True}
            self.atomic(self.tx["files"][rel]["backup"], p.read_bytes())
        for rel in ("/etc/ufw/user.rules", "/etc/ufw/user6.rules"):
            self.tx["files"].setdefault(rel, {"existed": False, "ufw_managed": True})
        self.save_tx()
        if self.read("/etc/default/ufw") and not re.search(r"^IPV6=yes\s*$", self.read("/etc/default/ufw"), re.M):
            raise GuardError("UFW IPv6 未启用；先评估现有 IPv6 规则再启用")
        if self.out("docker", "ps", "-q"):
            raise GuardError("检测到运行中的容器：先检查 Docker 暴露端口；首版防火墙阶段不自动覆盖容器主机")
        self.arm()
        self.remember_unit("fail2ban.service")
        self.tx["runtime"]["ufw_modified"] = True
        self.save_tx()
        for port in ports:
            for source in c["ssh_sources"] or ["any"]:
                self.run("ufw", "allow", "from", source, "to", "any", "port", str(port), "proto", "tcp", "comment", "vps-guard-ssh")
        for item in c["business_ports"]:
            self.run("ufw", "allow", "from", item["source"], "to", "any", "port", str(item["port"]),
                     "proto", item["protocol"], "comment", "vps-guard-business")
        self.run("ufw", "default", "deny", "incoming")
        self.run("ufw", "default", "allow", "outgoing")
        self.run("ufw", "--force", "enable")
        jail = ("[sshd]\nenabled = true\nbackend = systemd\nport = " + ",".join(map(str, ports)) +
                "\nmaxretry = 5\nfindtime = 600\nbantime = 3600\n")
        self.write("/etc/fail2ban/jail.d/90-vps-guard.local", jail, 0o600)
        self.run("fail2ban-client", "-t")
        self.run("systemctl", "enable", "--now", "fail2ban")
        self.run("systemctl", "restart", "fail2ban")
        self.wait_ok("fail2ban-client", "status", "sshd")
        for path, item in self.tx["files"].items():
            if item.get("ufw_managed") and self.fs(path).exists():
                item["installed_sha256"] = sha(self.fs(path).read_bytes())
        self.save_tx()
        self.note("已有 UFW 放行规则被保留，请审阅额外开放；云防火墙和外部 IPv4／IPv6 可达性仍需验证。")

    def network_devices(self):
        names = self.config()["network"]["devices"]
        if not names:
            for fam in ("-4", "-6"):
                raw = self.out("ip", "-j", fam, "route", "show", "default")
                try:
                    names += [x["dev"] for x in json.loads(raw or "[]") if "dev" in x]
                except ValueError:
                    raise GuardError("无法解析默认路由") from None
        names = sorted(set(names))
        if not names or any(re.match(r"^(lo$|veth|docker|br-|tailscale|tun|wg)", x) for x in names):
            raise GuardError("默认出口含虚拟／隧道接口或无法识别，请显式填写 network.devices")
        return names

    def qdisc_plan(self, devices):
        changes = []
        for dev in devices:
            raw = self.out("tc", "-j", "qdisc", "show", "dev", dev)
            try:
                rows = json.loads(raw)
            except ValueError:
                raise GuardError(f"无法读取 {dev} 的队列") from None
            root = next((x for x in rows if x.get("root")), None)
            if not root:
                raise GuardError(f"{dev} 缺少可识别根队列")
            leaves = [x for x in rows if "parent" in x] if root["kind"] == "mq" else [root]
            if not leaves:
                raise GuardError(f"{dev} 未找到多队列叶子")
            text = self.out("tc", "qdisc", "show", "dev", dev).splitlines()
            for row in leaves:
                kind = row["kind"]
                if kind not in ("fq", "fq_codel", "pfifo_fast"):
                    raise GuardError(f"{dev} 包含 {kind} 队列，停止覆盖；需单独设计兼容方案")
                location = ["parent", row["parent"]] if "parent" in row else ["root"]
                match = next((l for l in text if l.startswith(f"qdisc {kind} {row['handle']} ") and
                              ("parent " + row["parent"] in l if "parent" in row else " root " in l)), None)
                if not match:
                    raise GuardError("无法保存可恢复的队列参数")
                opts = shlex.split(match)[3:]
                if opts[:1] == ["root"]:
                    opts = opts[1:]
                elif opts[:1] == ["parent"]:
                    opts = opts[2:]
                if opts[:1] == ["refcnt"]:
                    opts = opts[2:]
                # pfifo_fast parameters shown by tc are read-only diagnostics.
                if kind == "pfifo_fast":
                    opts = []
                changes.append({"dev": dev, "location": location, "old_kind": kind,
                                "old_options": opts, "changed": kind != "fq"})
            if any(x["changed"] for x in changes if x["dev"] == dev):
                for scope in ("root", "ingress", "egress"):
                    filters = self.out("tc", "-j", "filter", "show", "dev", dev, scope)
                    if filters.strip() not in ("", "[]"):
                        raise GuardError(f"{dev} 存在流量过滤器，停止覆盖队列")
        return changes

    def tcp_values(self):
        c = self.config()["network"]
        values = dict(TCP_BASE)
        requested = c["tcp_buffer_max_bytes"]
        ram = self.meminfo().get("MemTotal", 0)
        budget = min(64 * 1024**2, ram // 16) if ram else 0
        if requested is None and c["target_bandwidth_mbps"] and c["representative_rtt_ms"]:
            bdp = c["target_bandwidth_mbps"] * 1e6 / 8 * c["representative_rtt_ms"] / 1000
            candidate = 2 ** math.ceil(math.log2(max(4096, bdp * 2)))
            requested = max(4096, min(candidate, budget)) if budget >= 4096 else None
        if requested is not None:
            if not budget or requested > budget:
                raise GuardError("缓冲区候选值超过本工具的单连接内存预算；先评估内存和并发")
            for key in ("net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem"):
                current = self.out("sysctl", "-n", key).split()
                if len(current) != 3 or not all(x.isdigit() for x in current):
                    raise GuardError(f"无法读取 {key}")
                # Auto profile only raises a lower current ceiling; never reduces a tuned ceiling.
                current[2] = str(max(int(current[2]), requested, int(current[1])))
                values[key] = " ".join(current)
        socket_max = c["socket_buffer_max_bytes"]
        if socket_max is not None:
            if not budget or socket_max > budget:
                raise GuardError("Socket 缓冲区超过内存预算")
            for key in ("net.core.rmem_max", "net.core.wmem_max"):
                current = self.out("sysctl", "-n", key)
                if not current.isdigit():
                    raise GuardError(f"无法读取 {key}")
                values[key] = str(max(int(current), socket_max))
        return values

    def stage_network(self):
        devices = self.network_devices()
        layout = self.qdisc_plan(devices)
        values = self.tcp_values()
        for key in values:
            current = self.out("sysctl", "-n", key)
            if not current:
                raise GuardError(f"内核缺少参数 {key}")
            self.tx["runtime"].setdefault("sysctl", {})[key] = current
        self.tx["runtime"]["qdiscs"] = layout
        self.save_tx()
        self.run("modprobe", "tcp_bbr", check=False)
        self.run("modprobe", "sch_fq", check=False)
        if "bbr" not in self.out("sysctl", "-n", "net.ipv4.tcp_available_congestion_control").split():
            raise GuardError("当前内核不提供 BBR；请检查发行版内核支持，不自动安装第三方内核")
        self.arm()
        self.write(NETWORK_FILE, "# Managed by VPS Guard\n" + "\n".join(f"{k} = {v}" for k, v in values.items()) + "\n", 0o644)
        self.write("/etc/modules-load.d/vps-guard.conf", "tcp_bbr\nsch_fq\n", 0o644)
        self.run("sysctl", "-p", NETWORK_FILE)
        for item in layout:
            if item["changed"]:
                self.run("tc", "qdisc", "replace", "dev", item["dev"], *item["location"], "fq")
        persisted = [{"dev": x["dev"], "location": x["location"]} for x in layout]
        self.write("/etc/vps-guard/network-layout.json", json.dumps(persisted), 0o600)
        unit = ("[Unit]\nDescription=VPS Guard fq queues\nWants=network-online.target\nAfter=network-online.target\n"
                "[Service]\nType=oneshot\nExecStart=/usr/local/bin/vps-guard network-ensure\nRemainAfterExit=yes\n"
                "[Install]\nWantedBy=multi-user.target\n")
        self.write("/etc/systemd/system/vps-guard-network.service", unit, 0o644)
        self.tx["runtime"]["network_unit_enabled"] = self.out("systemctl", "is-enabled", "vps-guard-network.service") == "enabled"
        self.save_tx()
        self.run("systemctl", "daemon-reload")
        self.run("systemctl", "enable", "vps-guard-network.service")
        self.network_ensure(check_only=True)
        for key, value in values.items():
            if self.out("sysctl", "-n", key).split() != value.split():
                raise GuardError(f"运行参数未生效：{key}")
        self.note("缓冲区输入不足时保留合理现值；未运行测速，不能据此宣称性能改善。")
        self.note("新的默认拥塞算法需在新业务连接中验证；应用可能覆盖，已有监听器可能需要维护窗口重启。")

    def network_ensure(self, check_only=False):
        layout = json.loads(self.read("/etc/vps-guard/network-layout.json", "[]"))
        if not layout:
            raise GuardError("尚无持久化队列配置")
        for item in layout:
            dev, loc = item["dev"], item["location"]
            rows = json.loads(self.out("tc", "-j", "qdisc", "show", "dev", dev) or "[]")
            if loc == ["root"]:
                row = next((x for x in rows if x.get("root")), {})
            else:
                row = next((x for x in rows if x.get("parent") == loc[1]), {})
            if row.get("kind") == "fq":
                continue
            if check_only or row.get("kind") not in ("fq_codel", "pfifo_fast"):
                raise GuardError(f"{dev} 队列不符合目标或存在未知配置，未覆盖")
            self.run("tc", "qdisc", "replace", "dev", dev, *loc, "fq")

    def stage_swap(self):
        size = self.config()["swap_mib"]
        if size is None:
            self.note("Swap 按需配置：未指定新建大小，保留现状。")
            return
        if self.out("swapon", "--show", "--noheadings"):
            self.note("已有 Swap，保留；不自动叠加。")
            return
        path = "/swapfile-vps-guard"
        if self.fs(path).exists():
            raise GuardError("Swap 目标文件已存在，请先检查")
        fstype = self.out("findmnt", "-n", "-o", "FSTYPE", "--target", "/")
        if fstype not in ("ext4", "xfs"):
            raise GuardError("首版仅在 ext4／xfs 新建 Swap；其他文件系统需专门处理")
        if shutil.disk_usage(self.root).free < size * 1024**2 + 1024**3:
            raise GuardError("磁盘余量不足，至少保留 1 GiB")
        self.tx["runtime"]["new_swap"] = path
        self.save_tx()
        self.run("dd", "if=/dev/zero", "of=" + path, "bs=1M", f"count={size}", "status=none", timeout=600)
        os.chmod(self.fs(path), 0o600)
        self.run("mkswap", path)
        self.run("swapon", path)
        old = self.read("/etc/fstab")
        self.write("/etc/fstab", old.rstrip() + "\n" + path + " none swap sw 0 0\n", 0o644)
        if path not in self.out("swapon", "--show", "--noheadings"):
            raise GuardError("Swap 未成功启用")

    def stage_maintenance(self):
        for unit in ("apt-daily.timer", "apt-daily-upgrade.timer", "vps-guard-health.timer"):
            self.remember_unit(unit)
        settings = ('APT::Periodic::Update-Package-Lists "1";\n'
                    'APT::Periodic::Unattended-Upgrade "1";\n'
                    'Unattended-Upgrade::Automatic-Reboot "false";\n')
        self.write("/etc/apt/apt.conf.d/99-vps-guard", settings, 0o644)
        self.run("systemctl", "enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer")
        changed = self.write("/etc/systemd/journald.conf.d/90-vps-guard.conf", "[Journal]\nStorage=persistent\nSystemMaxUse=200M\nRuntimeMaxUse=50M\n", 0o644)
        if changed:
            self.run("systemctl", "restart", "systemd-journald")
        service = ("[Unit]\nDescription=VPS Guard health check\n[Service]\nType=oneshot\n"
                   "ExecStart=/usr/local/bin/vps-guard healthcheck\n")
        timer = ("[Unit]\nDescription=VPS Guard hourly health check\n[Timer]\nOnBootSec=5m\n"
                 "OnUnitActiveSec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n")
        self.write("/etc/systemd/system/vps-guard-health.service", service, 0o644)
        self.write("/etc/systemd/system/vps-guard-health.timer", timer, 0o644)
        self.run("systemctl", "daemon-reload")
        self.run("systemctl", "enable", "--now", "vps-guard-health.timer")
        self.note("服务自动重启策略仍需结合业务评估；Docker 日志限额及外部离线监控列入人工验收。")
        if not self.fs(self.config()["notify_env_file"]).exists():
            self.note("未提供通知地址，健康检查仅记录在本机；尚未完成告警接入。")

    def protected_env(self, path):
        p = self.fs(path)
        if not p.is_file() or p.is_symlink():
            raise GuardError("凭据文件不存在或类型不安全")
        s = p.stat()
        if self.root == Path("/") and (s.st_uid != 0 or s.st_mode & 0o077):
            raise GuardError("凭据文件必须为 root 所有且权限 600")
        env = dict(os.environ)
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            k, sep, v = line.partition("=")
            if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]*", k):
                raise GuardError("凭据文件使用 KEY=value；不执行 Shell 展开")
            if k != "WEBHOOK_URL" and not k.startswith(("RESTIC_", "AWS_", "B2_", "AZURE_", "GOOGLE_", "RCLONE_")):
                raise GuardError("凭据文件含不支持的变量；不可配置 PATH 等执行环境变量")
            if v[:1] in ("'", '"') and v[-1:] == v[:1]:
                v = v[1:-1]
            env[k] = v
        return env

    def stage_backup(self):
        c = self.config()["backup"]
        if not c["enabled"]:
            raise GuardError("尚未配置异地备份目的地；请填写 backup 并启用，不能将其记为完成")
        self.protected_env(c["env_file"])
        for path in c["paths"]:
            if not self.fs(path).exists():
                raise GuardError("备份源路径不存在")
        self.run("apt-get", "install", "-y", "restic", interactive=True, timeout=600)
        # Repository creation is a separate, explicit command.
        self.restic("snapshots", "--json")
        self.remember_unit("vps-guard-backup.timer")
        service = ("[Unit]\nDescription=VPS Guard encrypted backup\nWants=network-online.target\nAfter=network-online.target\n"
                   "[Service]\nType=oneshot\nExecStart=/usr/local/bin/vps-guard backup-run\n")
        timer = ("[Unit]\nDescription=VPS Guard backup schedule\n[Timer]\nOnCalendar=" + c["calendar"] +
                 "\nPersistent=true\nRandomizedDelaySec=15m\n[Install]\nWantedBy=timers.target\n")
        self.write("/etc/systemd/system/vps-guard-backup.service", service, 0o644)
        self.write("/etc/systemd/system/vps-guard-backup.timer", timer, 0o644)
        self.run("systemctl", "daemon-reload")
        self.run("systemctl", "enable", "--now", "vps-guard-backup.timer")
        self.note("备份仓库已连接；还需要首次备份、恢复测试与业务一致性验收。")

    def restic(self, *args):
        c = self.config()["backup"]
        if not c["enabled"]:
            raise GuardError("backup.enabled 尚未启用")
        env = self.protected_env(c["env_file"])
        if not env.get("RESTIC_REPOSITORY") or not (env.get("RESTIC_PASSWORD_FILE") or env.get("RESTIC_PASSWORD")):
            raise GuardError("备份凭据缺少仓库地址或恢复密码引用")
        if not env["RESTIC_REPOSITORY"].startswith(("s3:", "b2:", "sftp:", "rest:", "azure:", "gs:", "rclone:")):
            raise GuardError("固定流程要求异地备份，不能用本机目录作为完成证据")
        password_file = env.get("RESTIC_PASSWORD_FILE")
        if password_file:
            pf = self.fs(password_file)
            if not pf.is_file() or pf.is_symlink():
                raise GuardError("恢复密码文件不存在或为符号链接")
            if self.root == Path("/") and (pf.stat().st_uid != 0 or pf.stat().st_mode & 0o077):
                raise GuardError("恢复密码文件必须归 root 所有且权限 600")
        rc, out, err = self.run("restic", *args, env=env, check=False, timeout=3600)
        # Keep repository paths and diagnostics in a root-only local log.
        self.atomic(STATE + "/restic-last.log", out + "\n" + err)
        if rc:
            raise GuardError(f"restic 失败（退出码 {rc}）；详情保存在 root 专用日志")
        return out

    def backup_run(self):
        c = self.config()["backup"]
        try:
            self.restic("backup", "--json", "--", *c["paths"])
            result = {"time": utc(), "success": True}
        except GuardError:
            self.atomic(STATE + "/backup-last.json", json.dumps({"time": utc(), "success": False}))
            raise
        self.atomic(STATE + "/backup-last.json", json.dumps(result))
        print("备份完成；尚需独立恢复验收。")

    def backup_restore_test(self):
        target = STATE + "/restore-tests/" + uuid.uuid4().hex
        self.fs(target).mkdir(parents=True, mode=0o700)
        self.restic("restore", "latest", "--target", target)
        self.restic("check")
        self.atomic(STATE + "/restore-last.json", json.dumps({"time": utc(), "file_restore_ok": True, "target": target}))
        print("文件恢复及仓库元数据检查完成，业务启动与数据一致性仍需验证。")
        print("恢复文件位于：" + target)

    def healthcheck(self):
        info = self.meminfo()
        disk = shutil.disk_usage(self.root)
        alerts = []
        if disk.free / disk.total < 0.15:
            alerts.append("根分区剩余空间低于 15%")
        if info.get("MemTotal") and info.get("MemAvailable", info["MemTotal"]) / info["MemTotal"] < 0.1:
            alerts.append("可用内存低于 10%")
        if self.out("systemctl", "--failed", "--no-legend", "--plain"):
            alerts.append("存在失败的 systemd 服务")
        if self.config()["backup"]["enabled"]:
            last = json.loads(self.read(STATE + "/backup-last.json", "{}"))
            if not last.get("success"):
                alerts.append("最近备份未成功或尚未运行")
            else:
                try:
                    age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(last["time"])).total_seconds()
                except (KeyError, ValueError, TypeError):
                    age = float("inf")
                limit = {"hourly": 3 * 3600, "daily": 2 * 86400, "weekly": 14 * 86400}[self.config()["backup"]["calendar"]]
                if age > limit:
                    alerts.append("备份记录已过期，请检查调度")
        report = {"time": utc(), "alerts": alerts}
        self.atomic(STATE + "/health-last.json", json.dumps(report, ensure_ascii=False))
        notify = self.config()["notify_env_file"]
        if alerts and self.fs(notify).exists():
            env = self.protected_env(notify)
            url = env.get("WEBHOOK_URL", "")
            if not url.startswith("https://"):
                raise GuardError("通知需要 HTTPS WEBHOOK_URL")
            payload = json.dumps({"text": "VPS Guard " + self.out("hostname") + ": " + "; ".join(alerts)}).encode()
            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.status >= 300:
                        raise OSError()
            except Exception:
                raise GuardError("通知发送失败；未回显通知凭据") from None
        print(json.dumps(report, ensure_ascii=False, indent=2))

    def confirm(self, ident):
        self.load_tx(ident)
        if self.tx["status"] != "awaiting_confirmation" or time.time() >= self.tx["deadline"]:
            raise GuardError("该变更已确认、已恢复或已过期，请检查状态")
        session = self.session()
        if not session or session == self.tx["origin_session"]:
            raise GuardError("必须从独立的新 SSH 连接确认，不能在原会话直接确认")
        if self.tx["stage"] == "ssh":
            if os.environ.get("SUDO_USER") != self.config()["admin_user"]:
                raise GuardError("SSH 加固必须从运维账号的新密钥连接通过 sudo 确认")
            self.assert_ssh()
        if self.tx["stage"] == "firewall" and "Status: active" not in self.out("ufw", "status"):
            raise GuardError("UFW 未生效")
        if self.tx["stage"] == "network":
            self.network_ensure(check_only=True)
            if self.out("sysctl", "-n", "net.ipv4.tcp_congestion_control") != "bbr":
                raise GuardError("BBR 未生效")
        self.run("systemctl", "stop", self.tx["guard_unit"] + ".timer")
        self.tx["status"] = "committed"
        self.tx["confirmed_at"] = utc()
        self.save_tx()
        self.record_stage()
        print("新连接验证已记录，取消本次定时恢复。")

    def load_tx(self, ident):
        if not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{10}", ident):
            raise GuardError("变更编号格式错误")
        raw = self.read(f"{STATE}/runs/{ident}/manifest.json")
        if not raw:
            raise GuardError("找不到变更记录")
        self.tx = json.loads(raw)

    def rollback(self, ident, automatic=False):
        self.load_tx(ident)
        if self.tx["status"] == "rolled_back":
            print("该变更已经恢复。")
            return
        if automatic and self.tx["status"] == "committed":
            return
        errors = []
        # Refuse a stale rollback that would overwrite later user/tool changes.
        for path, item in self.tx["files"].items():
            p = self.fs(path)
            if p.exists() and item.get("installed_sha256") and sha(p.read_bytes()) != item["installed_sha256"]:
                old = self.fs(item["backup"]).read_bytes() if item.get("backup") else None
                if old is None or sha(p.read_bytes()) != sha(old):
                    raise GuardError(f"文件已被后续操作修改，停止恢复以免覆盖：{path}")
        runtime = self.tx["runtime"]
        swap = runtime.get("new_swap")
        if swap and self.fs(swap).exists():
            if self.fs(swap).is_symlink():
                raise GuardError("Swap 路径被替换为符号链接，停止恢复")
            info = self.meminfo()
            used = info.get("SwapTotal", 0) - info.get("SwapFree", 0)
            if info.get("MemAvailable", 0) < used + 64 * 1024**2:
                raise GuardError("内存余量不足，停止 Swap 恢复")
            if swap in self.out("swapon", "--show", "--noheadings"):
                self.run("swapoff", swap)
            self.fs(swap).unlink()
        if runtime.get("ufw_modified"):
            if self.run("ufw", "--force", "disable", check=False)[0]:
                raise GuardError("停止 UFW 以恢复原规则时失败，请使用救援入口检查")
        for path, item in reversed(list(self.tx["files"].items())):
            try:
                if item["existed"]:
                    owner = (item["uid"], item["gid"])
                    self.atomic(path, self.fs(item["backup"]).read_bytes(), item["mode"], owner)
                else:
                    self.fs(path).unlink(missing_ok=True)
            except Exception as e:
                errors.append(f"恢复 {path}: {type(e).__name__}")
        for key, value in runtime.get("sysctl", {}).items():
            if self.run("sysctl", "-w", key + "=" + value, check=False)[0]:
                errors.append("恢复参数 " + key)
        for q in runtime.get("qdiscs", []):
            if q.get("changed") and self.run("tc", "qdisc", "replace", "dev", q["dev"], *q["location"],
                                             q["old_kind"], *q["old_options"], check=False)[0]:
                errors.append("恢复队列 " + q["dev"])
        stage = self.tx["stage"]
        if stage == "ssh":
            if self.run("/usr/sbin/sshd", "-t", check=False)[0] == 0:
                if self.run("systemctl", "reload", "ssh.service", check=False)[0]:
                    errors.append("重载 SSH")
            else:
                errors.append("恢复后 SSH 语法检查")
        if stage == "firewall" and runtime.get("ufw_modified"):
            if runtime["ufw_active"] and self.run("ufw", "--force", "enable", check=False)[0]:
                errors.append("恢复 UFW 状态")
            if runtime.get("units", {}).get("fail2ban.service", {}).get("active"):
                self.run("systemctl", "restart", "fail2ban", check=False)
        self.run("systemctl", "daemon-reload", check=False)
        if stage == "network" and "network_unit_enabled" in runtime and not runtime["network_unit_enabled"]:
            self.run("systemctl", "disable", "vps-guard-network.service", check=False)
        for unit, before in runtime.get("units", {}).items():
            enable = "enable" if before["enabled"] else "disable"
            active = "start" if before["active"] else "stop"
            if self.run("systemctl", enable, unit, check=False)[0] and before["enabled"]:
                errors.append("恢复启用状态 " + unit)
            if self.run("systemctl", active, unit, check=False)[0] and before["active"]:
                errors.append("恢复运行状态 " + unit)
        if stage == "maintenance":
            self.run("systemctl", "restart", "systemd-journald", check=False)
        self.tx["status"] = "rollback_failed" if errors else "rolled_back"
        self.tx["rollback_time"] = utc()
        self.tx["rollback_errors"] = errors
        self.save_tx()
        if self.tx.get("guard_unit"):
            self.run("systemctl", "stop", self.tx["guard_unit"] + ".timer", check=False)
        if errors:
            raise GuardError("部分恢复失败：" + "; ".join(errors))
        print("已恢复本次管理的配置；账号／软件升级等非文件操作请参考记录。")

    def attest(self, check):
        print(ATTESTATIONS[check])
        evidence = input("完成上述验证后填写简短结果（不要填写凭据）；未完成请直接回车：").strip()
        if len(evidence) < 8:
            raise GuardError("没有足够的验收记录；保持待验证状态")
        record = {"check": check, "time": utc(), "evidence": evidence,
                  "config_digest": sha(json.dumps(self.config(), sort_keys=True).encode())}
        self.atomic(STATE + "/attestations/" + check + ".json", json.dumps(record, ensure_ascii=False))
        print("已保存人工验收记录；它是操作人提供的证据，不是程序自动探测结果。")

    def verify(self):
        checks = []
        def add(name, status, detail):
            checks.append({"name": name, "status": status, "detail": detail})
        try:
            self.assert_ssh()
            add("ssh_policy", "passed", "最终配置符合基线；仍需外部拒绝测试")
        except GuardError as e:
            add("ssh_policy", "failed", str(e))
        add("firewall", "passed" if "Status: active" in self.out("ufw", "status") else "failed", "检查 UFW 状态")
        rc = self.run("fail2ban-client", "status", "sshd", check=False)[0]
        add("fail2ban", "passed" if rc == 0 else "failed", "jail 状态；真实封禁需独立测试")
        values = dict(TCP_BASE)
        for line in self.read(NETWORK_FILE).splitlines():
            key, sep, value = line.partition("=")
            if sep and re.fullmatch(r"net\.[a-z0-9_.]+", key.strip()):
                values[key.strip()] = value.strip()
        for k, v in values.items():
            add(k, "passed" if self.out("sysctl", "-n", k).split() == v.split() else "failed", "运行时参数")
        try:
            self.network_ensure(check_only=True)
            add("egress_fq", "passed", "实际出口队列符合目标")
        except GuardError as e:
            add("egress_fq", "failed", str(e))
        ntp = self.out("timedatectl", "show", "--property=NTPSynchronized", "--value")
        add("time_sync", "passed" if ntp == "yes" else "pending_manual", "检查时间同步")
        for unit in ("apt-daily-upgrade.timer", "vps-guard-health.timer"):
            add(unit, "passed" if self.out("systemctl", "is-active", unit) == "active" else "failed", "定时任务状态")
        c = self.config()
        if c["backup"]["enabled"]:
            last = json.loads(self.read(STATE + "/backup-last.json", "{}"))
            restore = json.loads(self.read(STATE + "/restore-last.json", "{}"))
            add("backup", "passed" if last.get("success") else "failed", "最近一次备份结果")
            add("file_restore", "passed" if restore.get("file_restore_ok") else "pending_manual", "文件恢复及仓库检查")
        else:
            add("backup", "pending_manual", "未配置异地备份")
        digest = sha(json.dumps(c, sort_keys=True).encode())
        for name, detail in ATTESTATIONS.items():
            if name == "service_restore" and not c["backup"]["enabled"]:
                continue
            att = json.loads(self.read(STATE + "/attestations/" + name + ".json", "{}"))
            if att.get("config_digest") == digest:
                add(name, "passed", "人工验收：" + att["evidence"])
            else:
                add(name, "not_tested" if name == "performance" else "pending_manual", detail)
        latest = None
        runs = self.fs(STATE + "/runs")
        if runs.exists():
            for path in sorted(runs.glob("*/manifest.json")):
                record = json.loads(path.read_text())
                if record["status"] == "committed":
                    latest = record
        boot = self.read("/proc/sys/kernel/random/boot_id").strip()
        rebooted = bool(latest and boot and latest.get("boot_id") and boot != latest["boot_id"])
        add("post_reboot", "passed" if rebooted else "pending_manual", "最近应用变更后已重启" if rebooted else "维护窗口重启后再次验收；待确认变更期间不要重启")
        for pending in self.pending():
            add("unconfirmed_change", "pending_manual", pending["id"])
        print(json.dumps({"time": utc(), "checks": checks}, ensure_ascii=False, indent=2))
        return 2 if any(x["status"] == "failed" for x in checks) else (3 if any(x["status"] == "pending_manual" for x in checks) else 0)

    def setup(self):
        if self.fs(CONFIG).exists():
            print("已有配置保留。请用 sudoedit /etc/vps-guard/config.json 修改，再执行 plan。")
            return
        c = copy.deepcopy(DEFAULTS)
        c["admin_user"] = input("运维账号 [ops]：").strip() or "ops"
        key = input("粘贴一行 SSH 公钥（或留空稍后填写）：").strip()
        c["admin_public_keys"] = [key] if key else []
        c["provider_console_verified"] = input("已实际测试服务商控制台？输入 YES 才记录：").strip() == "YES"
        spec = input("业务端口，例如 443/tcp,8443/udp；无业务输入 none；未知留空：").strip()
        if spec:
            c["business_ports_confirmed"] = True
            if spec != "none":
                for x in spec.split(","):
                    m = re.fullmatch(r"\s*(\d+)/(tcp|udp)\s*", x)
                    if not m:
                        raise GuardError("端口格式错误，配置尚未保存")
                    c["business_ports"].append({"port": int(m.group(1)), "protocol": m.group(2), "source": "any"})
        validate_config(c)
        self.atomic(CONFIG, json.dumps(c, ensure_ascii=False, indent=2) + "\n")
        print("配置已保存：" + CONFIG + "；接下来运行 audit 与 plan。")

    def plan(self):
        c = self.config()
        summary = {
            "baseline": "安装依赖，按配置升级系统，设置时间；软件升级不提供包级自动降级",
            "access": f"准备 {c['admin_user']} 和 {len(c['admin_public_keys'])} 个公钥，保留其他已授权密钥",
            "ssh": "保留端口，关闭 SSH 密码／root；需独立登录证明及限时恢复",
            "firewall": f"保留公网 SSH，配置 {len(c['business_ports'])} 项业务规则；运行中 Docker／其他防火墙会阻止自动应用",
            "network": "启用当前内核 BBR＋fq，应用 TCP 基线，按输入适配缓冲区；复杂队列停止覆盖",
            "swap": "保留现状" if c["swap_mib"] is None else f"仅无现有 Swap 时评估新建 {c['swap_mib']} MiB",
            "maintenance": "安全更新、日志容量和本机健康检查；通知地址另填",
            "backup": "配置 restic 调度；先连接并初始化仓库" if c["backup"]["enabled"] else "待提供异地备份目的地",
            "optional": "Tailscale 不在本工具固定流程；不自动安装或关闭公网 SSH",
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))


def root_required():
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise GuardError("此操作需要 Linux root 权限，请通过 sudo 执行")


def menu(g):
    choices = [("只读安全检查", "audit"), ("初次填写配置", "setup"), ("查看执行计划", "plan")]
    choices += [("执行阶段：" + s, "apply " + s) for s in STAGES]
    choices += [("验收报告", "verify"), ("查看待确认变更", "pending")]
    for i, (label, _) in enumerate(choices, 1):
        print(f"{i:2d}. {label}")
    value = input("选择编号，或回车退出：").strip()
    if not value:
        return 0
    if not value.isdigit() or not 1 <= int(value) <= len(choices):
        raise GuardError("编号错误")
    return main(shlex.split(choices[int(value)-1][1]))


def main(argv=None):
    p = argparse.ArgumentParser(description="VPS Guard：分阶段加固与网络调优")
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="command")
    for name in ("audit", "setup", "plan", "verify", "menu", "pending", "confirm-login",
                 "network-ensure", "healthcheck", "backup-init", "backup-run", "backup-restore-test"):
        sub.add_parser(name)
    a = sub.add_parser("apply"); a.add_argument("stage", choices=STAGES)
    a = sub.add_parser("attest"); a.add_argument("check", choices=tuple(ATTESTATIONS))
    a = sub.add_parser("confirm"); a.add_argument("run_id")
    a = sub.add_parser("rollback"); a.add_argument("run_id"); a.add_argument("--automatic", action="store_true")
    args = p.parse_args(argv)
    g = Guard()
    try:
        cmd = args.command or "menu"
        if cmd == "audit":
            print(json.dumps(g.audit(), ensure_ascii=False, indent=2)); return 0
        if cmd == "menu":
            return menu(g)
        root_required()
        if cmd in ("backup-run", "backup-restore-test", "backup-init", "healthcheck", "network-ensure"):
            g.preflight()
        with g.lock():
            if cmd == "setup": g.setup()
            elif cmd == "plan": g.plan()
            elif cmd == "verify": return g.verify()
            elif cmd == "pending": print(json.dumps(g.pending(), ensure_ascii=False, indent=2))
            elif cmd == "apply": g.apply(args.stage)
            elif cmd == "confirm-login": g.confirm_login()
            elif cmd == "confirm": g.confirm(args.run_id)
            elif cmd == "attest": g.attest(args.check)
            elif cmd == "rollback": g.rollback(args.run_id, args.automatic)
            elif cmd == "network-ensure": g.network_ensure()
            elif cmd == "healthcheck": g.healthcheck()
            elif cmd == "backup-init":
                if not g.config()["backup"]["enabled"]:
                    raise GuardError("先配置备份目的地并启用 backup")
                g.protected_env(g.config()["backup"]["env_file"])
                g.run("apt-get", "install", "-y", "restic", interactive=True, timeout=600)
                g.restic("init")
                print("仓库初始化完成；恢复密码请独立保存。")
            elif cmd == "backup-run": g.backup_run()
            elif cmd == "backup-restore-test": g.backup_restore_test()
        return 0
    except (GuardError, ValueError, OSError, KeyError) as e:
        print("停止：" + str(e), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("已中断；如有待确认变更，其定时恢复仍会执行。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
