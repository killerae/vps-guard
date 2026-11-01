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
for task_target in /etc/vps-guard /var/lib/vps-guard /var/lib/vps-guard/lock /var/lib/vps-guard/wizard.lock /usr/local/lib/vps-guard /usr/local/bin/vps-guard /usr/local/lib/vps-guard/vps_guard.py /usr/local/lib/vps-guard/vps_wizard.py /usr/local/lib/vps-guard/vps_auto.py; do
  if [ -L "$task_target" ]; then
    echo "安装目标为符号链接，停止：$task_target" >&2
    exit 1
  fi
done
install -d -m 0755 /usr/local/lib/vps-guard /usr/local/bin
install -d -o root -g root -m 0700 /etc/vps-guard /var/lib/vps-guard
command -v flock >/dev/null || { echo '需要 util-linux 提供的 flock。' >&2; exit 1; }
exec 8>/var/lib/vps-guard/wizard.lock
flock -n 8 || { echo '旧向导仍在运行；请先在旧窗口 Ctrl+C 退出，再重新执行安装命令。' >&2; exit 1; }
exec 9>/var/lib/vps-guard/lock
flock -n 9 || { echo '已有加固／恢复任务正在运行，请等它结束后再升级。' >&2; exit 1; }
/usr/bin/python3 -I - <<'PY'
import json
from pathlib import Path
import sys
try:
    for path in Path('/var/lib/vps-guard/runs').glob('*/manifest.json'):
        record = json.loads(path.read_text(encoding='utf-8'))
        if record['status'] in ('running', 'awaiting_confirmation', 'rollback_failed'):
            raise ValueError('存在未完成变更 ' + record['id'] + '；请先用旧工具确认或恢复，再升级')
except (OSError, ValueError, KeyError) as error:
    print('安装停止：' + str(error), file=sys.stderr)
    raise SystemExit(1)
PY
if [ -f /usr/local/lib/vps-guard/vps_guard.py ]; then
  task_previous="$(mktemp -d /var/lib/vps-guard/previous-code.XXXXXXXX)"
  for task_file in vps_guard.py vps_wizard.py vps_auto.py; do
    if [ -f "/usr/local/lib/vps-guard/$task_file" ]; then
      install -m 0600 "/usr/local/lib/vps-guard/$task_file" "$task_previous/$task_file"
    fi
  done
  if [ -f /usr/local/bin/vps-guard ]; then
    install -m 0600 /usr/local/bin/vps-guard "$task_previous/launcher"
  fi
fi
install -m 0755 "$task_dir/vps_guard.py" /usr/local/lib/vps-guard/vps_guard.py
install -m 0644 "$task_dir/vps_wizard.py" /usr/local/lib/vps-guard/vps_wizard.py
install -m 0644 "$task_dir/vps_auto.py" /usr/local/lib/vps-guard/vps_auto.py
install -m 0755 "$task_dir/bin/vps-guard" /usr/local/bin/vps-guard
install -m 0600 "$task_dir/config.example.json" /etc/vps-guard/config.example.json
echo 'VPS Guard 已安装；未修改 SSH、防火墙或 TCP 参数。'
echo '开始：sudo vps-guard auto；以后 sudo vps-guard 打开菜单，回车执行个人默认方案。'
