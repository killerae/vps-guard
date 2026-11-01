#!/usr/bin/env python3
"""Build a deterministic source bundle; never include local host configuration/secrets."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    '.gitignore', '.github/workflows/checks.yml', 'LICENSE', 'README.md',
    'vps_guard.py', 'install.sh', 'bin/vps-guard', 'config.example.json',
    'backup.env.example', 'notify.env.example', 'netcatty/snippets.json',
    'netcatty/README.md', 'docs/OPERATIONS.md', 'docs/TESTING.md',
    'tests/test_vps_guard.py', 'tools/build_release.py',
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(root):
    return ''.join(digest(root / name) + '  ' + name + '\n' for name in FILES)


def check_manifest(root):
    actual = (root / 'SHA256SUMS.txt').read_text(encoding='utf-8')
    expected = manifest(root)
    if actual != expected:
        raise ValueError('文件校验失败：请使用完整、未修改的版本；开发修改后重新生成清单。')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--check-manifest', type=Path)
    p.add_argument('--manifest-only', action='store_true')
    args = p.parse_args()
    if args.check_manifest:
        check_manifest(args.check_manifest.resolve())
        print('校验清单通过')
        return
    (ROOT / 'SHA256SUMS.txt').write_text(manifest(ROOT), encoding='utf-8', newline='\n')
    if args.manifest_only:
        return
    version = re.search(r'^VERSION = "([0-9.]+)"', (ROOT / 'vps_guard.py').read_text(encoding='utf-8'), re.M).group(1)
    dest = ROOT / 'dist'
    dest.mkdir(exist_ok=True)
    archive = dest / ('vps-guard-' + version + '.zip')
    prefix = 'vps-guard-' + version + '/'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name in (*FILES, 'SHA256SUMS.txt'):
            info = zipfile.ZipInfo(prefix + name, (2026, 11, 1, 0, 0, 0))
            mode = 0o755 if name in ('install.sh', 'bin/vps-guard', 'vps_guard.py', 'tools/build_release.py') else 0o644
            info.create_system = 3
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, (ROOT / name).read_bytes())
    check_manifest(ROOT)
    checksum = digest(archive)
    (dest / (archive.name + '.sha256')).write_text(checksum + '  ' + archive.name + '\n', encoding='ascii', newline='\n')
    print(json.dumps({'archive': str(archive), 'sha256': checksum, 'files': len(FILES) + 1}, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, AttributeError) as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1)
