#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo '请通过 sudo bash install.sh 安装。' >&2
  exit 1
fi
if [ ! -x /usr/bin/python3 ]; then
  echo '需要 Python 3.10+。Debian/Ubuntu 可先安装 python3。' >&2
  exit 1
fi
/usr/bin/python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || {
  echo '需要 Python 3.10 或更新版本。' >&2
  exit 1
}
task_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
/usr/bin/python3 "$task_dir/tools/build_release.py" --check-manifest "$task_dir"
install -d -m 0755 /usr/local/lib/vps-guard /usr/local/bin
install -d -m 0700 /etc/vps-guard /var/lib/vps-guard
if [ -f /usr/local/lib/vps-guard/vps_guard.py ]; then
  task_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  install -m 0600 /usr/local/lib/vps-guard/vps_guard.py "/var/lib/vps-guard/previous-code-$task_stamp.py"
fi
install -m 0755 "$task_dir/vps_guard.py" /usr/local/lib/vps-guard/vps_guard.py
install -m 0755 "$task_dir/bin/vps-guard" /usr/local/bin/vps-guard
install -m 0600 "$task_dir/config.example.json" /etc/vps-guard/config.example.json
echo 'VPS Guard 已安装；未修改 SSH、防火墙或 TCP 参数。'
echo '开始：sudo vps-guard setup，然后 sudo vps-guard audit 和 sudo vps-guard plan。'
