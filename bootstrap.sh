#!/usr/bin/env bash
# Public entry point. Download the complete file before executing it.
set -euo pipefail
umask 077
readonly VPS_GUARD_COMMIT="12b508de0b6de6088603a1f0ac099a09089fb42b"
readonly VPS_GUARD_MANIFEST_SHA256="058aeb2e2d3bcb3c44c1e54d110184490690f9039a895d62a12193671c6e4e2a"
task_mode=install
task_destination=
case "$#" in
  0) ;;
  1)
    if [ "$1" = --help ]; then
      echo '用法：bash bootstrap.sh [--download-only 新目录]'
      echo '默认安装后进入加固向导；download-only 仅下载并验证，不安装、不提权、不运行工具。'
      exit 0
    fi
    echo '参数错误；使用 --help。' >&2; exit 2 ;;
  2)
    [ "$1" = --download-only ] || { echo '参数错误。' >&2; exit 2; }
    task_mode=download
    task_destination="$2" ;;
  *) echo '参数错误。' >&2; exit 2 ;;
esac

if [ "$task_mode" = install ]; then
  [ "$(uname -s)" = Linux ] || { echo '安装仅支持 Linux。' >&2; exit 1; }
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null || { echo '请先使用 root 登录。' >&2; exit 1; }
    exec sudo -- bash "$0" "$@"
  fi
  [ -r /dev/tty ] || { echo '请在可交互的 SSH 终端运行。' >&2; exit 1; }
  exec </dev/tty
  [ -d /run/systemd/system ] || { echo '需要 systemd。' >&2; exit 1; }
  [ -r /etc/os-release ] || { echo '无法识别发行版。' >&2; exit 1; }
  . /etc/os-release
  case "$ID" in debian|ubuntu) ;; *) echo '仅支持 Debian／Ubuntu。' >&2; exit 1 ;; esac
  # Resume this version without replacing a runtime needed by a pending rollback.
  if [ -x /usr/local/bin/vps-guard ] && [ "$(/usr/local/bin/vps-guard --version)" = 0.2.0 ]; then
    exec /usr/local/bin/vps-guard wizard
  fi
  if [ -d /var/lib/vps-guard/runs ]; then
    echo '检测到旧工具的运行记录；请先用已安装工具检查并完成变更，再手动升级。' >&2
    exit 1
  fi
  task_packages=
  command -v curl >/dev/null || task_packages="$task_packages curl"
  [ -x /usr/bin/python3 ] || task_packages="$task_packages python3"
  if ! command -v curl >/dev/null || [ ! -x /usr/bin/python3 ] || [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
    echo '正在安装下载和校验所需的最小依赖……'
    apt-get update
    # Only the two fixed package names above can be split here.
    apt-get install -y ca-certificates $task_packages
  fi
  task_python=/usr/bin/python3
else
  command -v curl >/dev/null || { echo 'download-only 需要 curl。' >&2; exit 1; }
  command -v python3 >/dev/null || { echo 'download-only 需要 Python 3.10+。' >&2; exit 1; }
  task_python="$(command -v python3)"
fi
"$task_python" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || {
  echo '需要 Python 3.10+；不替换系统 Python。建议使用受维护的新系统镜像。' >&2
  exit 1
}
task_tmp="$(mktemp -d /tmp/vps-guard.XXXXXXXX)"
trap 'rm -rf -- "$task_tmp"' EXIT
task_archive="$task_tmp/source.zip"
[ -n "$task_destination" ] || task_destination="$task_tmp/verified"
echo "正在下载固定版本 $VPS_GUARD_COMMIT ……"
curl --proto '=https' --proto-redir '=https' -fsSL --retry 2 \
  --connect-timeout 15 --max-time 180 --max-filesize 8388608 \
  "https://codeload.github.com/killerae/vps-guard/zip/$VPS_GUARD_COMMIT" -o "$task_archive"

# This verifier executes before any code from the archive.
"$task_python" -I - "$task_archive" "$task_destination" "$VPS_GUARD_MANIFEST_SHA256" <<'PY'
import hashlib
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

archive, output, expected = sys.argv[1:]
try:
    if Path(archive).stat().st_size > 8 * 1024**2:
        raise ValueError("下载包超过大小上限")
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if len(entries) > 100 or sum(x.file_size for x in entries) > 8 * 1024**2:
            raise ValueError("文件数量或解压大小超过上限")
        names = {}
        for info in entries:
            path = PurePosixPath(info.filename)
            if (not info.filename or info.orig_filename != info.filename or "\\" in info.filename or path.is_absolute()
                    or ".." in path.parts or ":" in info.filename
                    or path.as_posix() != info.filename.rstrip("/")
                    or info.filename in names):
                raise ValueError("压缩包包含不安全或重复路径")
            kind = stat.S_IFMT(info.external_attr >> 16)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("压缩包包含符号链接或特殊文件")
            names[info.filename] = info
        manifests = [n for n in names if re.fullmatch(r"[A-Za-z0-9_.-]+/SHA256SUMS.txt", n)]
        if len(manifests) != 1:
            raise ValueError("无法唯一识别校验清单")
        manifest_name = manifests[0]
        manifest = z.read(manifest_name)
        if hashlib.sha256(manifest).hexdigest() != expected:
            raise ValueError("固定清单哈希不匹配；停止执行")
        prefix = manifest_name.rsplit("/", 1)[0] + "/"
        payload = {}
        for line in manifest.decode("ascii").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
            if not match:
                raise ValueError("清单格式错误")
            digest, name = match.groups()
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or path.as_posix() != name or name in payload:
                raise ValueError("清单路径错误或重复")
            info = names.get(prefix + name)
            if info is None or info.is_dir():
                raise ValueError("清单文件缺失")
            data = z.read(info)
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("文件哈希不匹配：" + name)
            payload[name] = data
        required = {"install.sh", "vps_guard.py", "vps_wizard.py", "bin/vps-guard", "tools/build_release.py"}
        if not required.issubset(payload):
            raise ValueError("工具包缺少必要文件")
        payload["SHA256SUMS.txt"] = manifest
    destination = Path(output)
    if destination.exists() or destination.is_symlink():
        raise ValueError("目标目录已存在；请使用新的目录")
    destination.mkdir(mode=0o700, parents=False)
    # Extract only authenticated files. Unlisted Python startup files stay out.
    for name, data in payload.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as f:
            f.write(data)
        target.chmod(0o600)
    print("固定版本与逐文件校验通过：" + str(destination))
except (ValueError, OSError, UnicodeError, zipfile.BadZipFile, KeyError, RuntimeError) as error:
    print("下载校验停止：" + str(error), file=sys.stderr)
    raise SystemExit(1)
PY

if [ "$task_mode" = download ]; then
  echo '仅下载和校验完成，未安装或执行工具。'
  exit 0
fi
bash "$task_destination/install.sh"
echo '开始交互向导；后续按提示选择项目。'
/usr/local/bin/vps-guard wizard
