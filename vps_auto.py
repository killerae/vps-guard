"""Personal no-question preset. Authentication checks remain explicit."""
from __future__ import annotations

import contextlib
import copy
import io
import ipaddress
import json
import re
import time

import vps_guard as vg
from vps_wizard import Wizard

PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID5kxFrMhEWqeZxm5P4cr09PKUMUZRVDSRvzZ4cwEVAE lu-admin"
LABELS = {
    "baseline": "系统软件更新、依赖、UTC 时区与时间同步",
    "access": "ops 账号、指定公钥和免密 sudo",
    "network": "当前内核 BBR＋实际出口 fq、保守 TCP 基线",
    "firewall": "UFW 默认拒绝入站、保留 SSH、放行 443/TCP＋443/UDP 和 Fail2ban",
    "ssh": "保留 SSH 端口，关闭 root／密码 SSH，新连接验证",
    "maintenance": "每日安全更新、不自动重启、日志限额与每小时健康检查",
    "backup": "沿用已配置的异地备份调度",
    "swap": "新建 Swap", "tailscale": "安装 Tailscale",
}
BUSINESS_PORTS = ((443, "tcp"), (443, "udp"))


def public_listeners(text):
    """Parse ss -H -lntu. Unknown lines fail closed; never guess a port."""
    found = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ("tcp", "udp"):
            raise vg.GuardError("无法可靠解析监听端口")
        protocol, local = fields[0], fields[4]
        address, sep, port = local.rpartition(":")
        if not sep or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise vg.GuardError("监听端口格式未知")
        address = address.strip("[]").split("%", 1)[0]
        if address != "*":
            try:
                host = ipaddress.ip_address(address)
            except ValueError:
                raise vg.GuardError("监听地址格式未知") from None
            if host.is_loopback or host.is_link_local or host.is_multicast:
                continue
        if protocol == "udp" and int(port) in (68, 546):
            continue  # DHCP client sockets; UFW's shipped before-rules handle DHCP.
        found.add((int(port), protocol))
    return found


class AutoWizard(Wizard):
    def __init__(self, guard):
        super().__init__(guard)
        self.g.automatic = True
        self.current = None

    def skip(self, state, stage, reason):
        if stage in state["selected"]:
            state["selected"].remove(stage)
        if not any(x["stage"] == stage and x["reason"] == reason for x in state["skipped"]):
            state["skipped"].append({"stage": stage, "reason": reason})

    def collect(self):
        if not self.g.session():
            raise vg.GuardError("个人默认方案请在可识别的 SSH 连接中运行，以启用限时恢复与新连接验证")
        if self.g.pending():
            raise vg.GuardError("请先确认或恢复上次待处理的变更")
        previous = self.g.read(vg.CONFIG)
        c = self.g.config() if previous else copy.deepcopy(vg.DEFAULTS)
        c.update(admin_user="ops", admin_public_keys=[PUBLIC_KEY], sudo_mode="key",
                 swap_mib=None, rollback_minutes=10, timezone="UTC", upgrade_packages=True,
                 ssh_port=None, business_ports_confirmed=True,
                 business_ports=[{"port": port, "protocol": protocol, "source": "any"}
                                 for port, protocol in BUSINESS_PORTS])
        devices = c["network"]["devices"]
        c["network"] = copy.deepcopy(vg.DEFAULTS["network"])
        c["network"]["devices"] = devices
        vg.validate_config(c)
        if previous:
            self.g.atomic(vg.STATE + "/config-history/" + str(time.time_ns()) + ".json", previous)
        self.g.atomic(vg.CONFIG, json.dumps(c, ensure_ascii=False, indent=2) + "\n")
        state = {"schema": 1, "profile": "personal-auto", "version": vg.VERSION,
                 "created_at": vg.utc(), "phase": "prepare", "completed": [], "runs": [],
                 "selected": ["baseline", "ssh", "firewall", "network", "maintenance"],
                 "skipped": [], "last_error": None, "active_stage": None,
                 "config_digest": vg.sha(json.dumps(c, sort_keys=True).encode())}
        self.skip(state, "swap", "按默认方案不新建；已启用的 Swap 保留")
        self.skip(state, "tailscale", "按默认方案不安装")
        if c["backup"]["enabled"]:
            state["selected"].append("backup")
        else:
            self.skip(state, "backup", "尚无异地目的地与凭据；仅保留本地配置恢复快照")
        self.save(state)
        print("\n开始个人默认方案：ops＋指定 lu-admin 公钥＋免密 sudo；当前 SSH 端口保留。")
        print("公钥指纹：" + next(iter(self.g.configured_fingerprints())))
        print("不新建 Swap，不安装 Tailscale，不猜测线路带宽或 RTT，不自动整机重启。")
        print("保留原 SSH 窗口；账号准备及关键部署后，各按提示新建一次密钥连接。")
        if not c["provider_console_verified"]:
            print("服务商控制台未记录为已验证；请保留可用的救援入口。")
        facts = self.g.audit()
        self.g.atomic(vg.STATE + "/auto-before.json", json.dumps(facts, ensure_ascii=False, indent=2))
        return state

    def run_stage(self, state, stage):
        if stage in state["completed"]:
            return
        state["active_stage"] = stage
        self.save(state)
        before = self.g.tx["id"] if self.g.tx else None
        try:
            with self.g.lock():
                self.g.apply(stage, require_console=False)
        finally:
            if self.g.tx and self.g.tx["id"] != before and self.g.tx["id"] not in state["runs"]:
                state["runs"].append(self.g.tx["id"])
                self.save(state)
        state["completed"].append(stage)
        self.save(state)

    def firewall_ports(self):
        if self.g.out("docker", "ps", "-q"):
            raise vg.GuardError("已有运行中的 Docker，需审阅容器发布端口，保留当前防火墙")
        for service in ("firewalld", "nftables", "netfilter-persistent"):
            if self.g.out("systemctl", "is-active", service) == "active":
                raise vg.GuardError("已有 " + service + " 管理规则，保留当前防火墙")
        c = self.g.config()
        if c["ssh_sources"]:
            client = ipaddress.ip_address(self.g.session().split()[0])
            if not any(client in ipaddress.ip_network(source, strict=False) for source in c["ssh_sources"]):
                raise vg.GuardError("当前管理来源不在已有 SSH 来源清单内；保留当前防火墙")
        status = self.g.out("ufw", "status")
        if not status:
            raise vg.GuardError("无法读取 UFW 状态")
        if "Status: active" not in status:
            for family in ("iptables", "ip6tables"):
                rc, rules, _ = self.g.run(family, "-S", "INPUT", check=False)
                if rc or any(x.strip() != "-P INPUT ACCEPT" for x in rules.splitlines() if x.strip()):
                    raise vg.GuardError("已有非 UFW 入站规则或无法读取规则，保留现状")
            rc, rules, _ = self.g.run("nft", "-j", "list", "ruleset", check=False)
            if rc == 0:
                try:
                    if any("table" in x or "chain" in x or "rule" in x for x in json.loads(rules or "{}").get("nftables", [])):
                        raise vg.GuardError("检测到现有 nftables 规则，保留现状")
                except ValueError:
                    raise vg.GuardError("无法解析 nftables 规则") from None
        if self.g.read("/etc/default/ufw") and not re.search(r"^IPV6=yes\s*$", self.g.read("/etc/default/ufw"), re.M):
            raise vg.GuardError("当前 UFW 未启用 IPv6，保留已有策略")
        rc, listeners, _ = self.g.run("ss", "-H", "-lntu", check=False)
        if rc or not listeners.strip():
            raise vg.GuardError("无法确认当前监听端口")
        ssh = {(p, "tcp") for p in self.g.ssh_ports()}
        actual = public_listeners(listeners) - ssh
        unknown = actual - set(BUSINESS_PORTS)
        if unknown:
            raise vg.GuardError("存在未确认业务端口 " + ", ".join(str(p)+"/"+proto for p, proto in sorted(unknown)) + "；保留当前防火墙以免中断业务")
        return [{"port": port, "protocol": protocol, "source": "any"}
                for port, protocol in BUSINESS_PORTS]

    def network_ready(self):
        self.g.qdisc_plan(self.g.network_devices())
        self.g.run("modprobe", "tcp_bbr", check=False)
        self.g.run("modprobe", "sch_fq", check=False)
        if "bbr" not in self.g.out("sysctl", "-n", "net.ipv4.tcp_available_congestion_control").split():
            raise vg.GuardError("当前内核不提供 BBR；保留现有内核与网络参数")
        for name in vg.TCP_BASE:
            if not self.g.out("sysctl", "-n", name):
                raise vg.GuardError("当前内核缺少 " + name + "；保留原网络配置")

    def critical_stages(self, state):
        with self.g.lock():
            return self._critical_stages(state)

    def _critical_stages(self, state):
        self.current = state
        c = self.g.config()
        if "firewall" in state["selected"]:
            try:
                c["business_ports"] = self.firewall_ports()
                c["business_ports_confirmed"] = True
            except vg.GuardError as error:
                self.skip(state, "firewall", str(error))
        if "network" in state["selected"]:
            try:
                self.network_ready()
            except vg.GuardError as error:
                self.skip(state, "network", str(error))
        vg.validate_config(c)
        self.g.atomic(vg.CONFIG, json.dumps(c, ensure_ascii=False, indent=2) + "\n")
        state["config_digest"] = vg.sha(json.dumps(c, sort_keys=True).encode())
        self.save(state)
        return super().critical_stages(state)

    def apply_critical(self, stages, on_started):
        def record(ident):
            self.current["runs"].append(ident)
            on_started(ident)
        return self.g.apply_critical(stages, on_started=record, require_console=False)

    def prepare_backup(self, state):
        if "backup" not in state["selected"] or "backup" in state["completed"]:
            return
        try:
            self.g.protected_env(self.g.config()["backup"]["env_file"])
            with self.g.lock():
                self.g.run("apt-get", "install", "-y", "restic", interactive=True, timeout=600)
                self.g.restic("snapshots", "--json")
        except vg.GuardError:
            self.skip(state, "backup", "已有备份凭据／仓库未验证通过，保留原调度，不自动初始化仓库")
            self.save(state)
            return
        self.run_stage(state, "backup")

    def report(self, state):
        completed = [{"stage": s, "detail": LABELS.get(s, s)} for s in state["completed"]]
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                self.g.verify(scope=state["selected"])
            checks = json.loads(buffer.getvalue())["checks"]
        except (vg.GuardError, OSError, ValueError) as error:
            checks = [{"name": "verification", "status": "failed", "detail": str(error)}]
        if not self.g.config()["provider_console_verified"]:
            checks.append({"name": "provider_console", "status": "pending_manual", "detail": "服务商控制台尚未由操作人验证"})
        if self.g.fs("/var/run/reboot-required").exists():
            checks.append({"name": "reboot_required", "status": "pending_manual", "detail": "系统提示需要维护窗口重启；本次未自动重启"})
        runs = []
        for ident in state.get("runs", []):
            raw = self.g.read(vg.STATE + "/runs/" + ident + "/manifest.json")
            if raw:
                run = json.loads(raw)
                runs.append({k: run.get(k) for k in ("id", "stage", "components", "status", "notes", "commands", "rollback_errors")})
        failed = [] if not state.get("last_error") else [{"stage": state.get("active_stage"), "detail": state["last_error"]}]
        report = {"time": vg.utc(), "profile": "personal-auto", "version": vg.VERSION,
                  "phase": state["phase"], "completed": completed, "skipped": state["skipped"],
                  "failed": failed, "checks": checks, "runs": runs,
                  "admin_user": self.g.config()["admin_user"], "sudo_mode": self.g.config()["sudo_mode"],
                  "key_fingerprints": sorted(self.g.configured_fingerprints()),
                  "business_ports": self.g.config()["business_ports"]}
        lines = ["VPS Guard " + vg.VERSION + " 本轮操作报告", "流程状态：" + state["phase"], "", "已完成／已符合："]
        lines += ["  ✓ " + x["detail"] for x in completed] or ["  尚无完成阶段"]
        lines += ["", "未执行／保留现状："]
        lines += ["  - " + LABELS.get(x["stage"], x["stage"]) + "：" + x["reason"] for x in state["skipped"]]
        if failed:
            lines += ["", "执行失败／暂停："] + ["  ! " + x["detail"] for x in failed]
        pending = [x for x in checks if x["status"] in ("failed", "pending_manual", "not_tested")]
        if pending:
            lines += ["", "待检查："] + ["  " + x["status"] + " " + x["name"] + "：" + x["detail"] for x in pending]
        lines += ["", "默认目标：ops＋指定公钥；免密 sudo 具有完整管理员权限。",
                  "默认业务规则：仅 443/TCP＋443/UDP；SSH 管理端口另行保留。",
                  "既有 UFW 额外放行规则不会自动删除；防火墙冲突／未知端口会保留现状并在上方说明。",
                  "新建 Swap：关闭；Tailscale：不安装；系统重启：不自动执行。",
                  "若阶段失败，软件升级、账号与组成员变更可能已经发生；详细命令与恢复结果见 JSON。",
                  "报告：/var/lib/vps-guard/last-report.txt 与 last-report.json",
                  "以后输入 sudo vps-guard 打开菜单；sudo vps-guard report 重看本报告。"]
        text = "\n".join(lines) + "\n"
        self.g.atomic(vg.STATE + "/last-report.txt", text)
        self.g.atomic(vg.STATE + "/last-report.json", json.dumps(report, ensure_ascii=False, indent=2))
        print(text)
        return 2 if failed or any(x["status"] == "failed" for x in checks) else 0

    def run(self, restart=False):
        self.g.preflight()
        with self.g.lock("wizard.lock"):
            state = self.state()
            if state and (restart or state.get("profile") != "personal-auto" or state.get("version") != vg.VERSION):
                if self.g.pending():
                    raise vg.GuardError("先确认或恢复旧变更，再开始默认方案")
                self.g.atomic(vg.STATE + "/wizard-history/" + str(time.time_ns()) + ".json", json.dumps(state))
                state = None
            if state is None:
                with self.g.lock():
                    state = self.collect()
            else:
                self.check_state(state)
                state = self.refresh_transaction(state)
                if state["phase"] == "paused":
                    state["phase"] = state["resume_phase"]
                    state["last_error"] = None
                    self.save(state)
            try:
                return self.drive(state)
            except (vg.GuardError, OSError, ValueError, KeyboardInterrupt) as error:
                current = self.state() or state
                current["resume_phase"] = current["phase"]
                current["phase"] = "paused"
                current["last_error"] = "操作人中断，未确认事务的定时恢复仍会执行" if isinstance(error, KeyboardInterrupt) else str(error)
                self.save(current)
                self.report(current)
                raise
