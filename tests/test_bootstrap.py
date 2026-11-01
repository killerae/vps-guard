import hashlib
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'bootstrap.sh').read_text(encoding='utf-8')
VERIFIER = SCRIPT.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.payload = {n:b'fixture content\n' for n in
                        ('install.sh','vps_guard.py','vps_wizard.py','bin/vps-guard','tools/build_release.py')}
        self.manifest = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                                for name, data in self.payload.items()).encode('ascii')
        self.expected = hashlib.sha256(self.manifest).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def bundle(self, *, extra=None, tamper=False, manifest=None, omit=None):
        archive = self.root / 'source.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            for name, data in self.payload.items():
                if name != omit:
                    z.writestr('vps-guard-fixture/' + name, b'tampered' if tamper and name=='install.sh' else data)
            z.writestr('vps-guard-fixture/SHA256SUMS.txt', self.manifest if manifest is None else manifest)
            for name, data in extra or []:
                if isinstance(name, str):
                    info = zipfile.ZipInfo('placeholder')
                    info.filename = name
                    name = info
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    z.writestr(name, data)
        return archive

    def verify(self, archive, expected=None):
        return subprocess.run([sys.executable,'-X','utf8','-I','-c',VERIFIER,str(archive),str(self.root/'verified'),expected or self.expected],
                              text=True,encoding='utf-8',capture_output=True,timeout=15)

    def test_valid_archive_extracts_only_authenticated_files(self):
        archive = self.bundle(extra=[('vps-guard-fixture/sitecustomize.py', b'raise RuntimeError("must not run")')])
        result = self.verify(archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root/'verified/install.sh').read_bytes(), self.payload['install.sh'])
        self.assertFalse((self.root/'verified/sitecustomize.py').exists())

    def test_wrong_pinned_manifest_fails_before_extracting(self):
        result = self.verify(self.bundle(), '0'*64)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root/'verified').exists())

    def test_tampered_payload_fails_before_extracting(self):
        result = self.verify(self.bundle(tamper=True))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root/'verified').exists())

    def test_path_traversal_and_absolute_paths_rejected(self):
        for path in ('../outside','/absolute','vps-guard-fixture/../outside','vps-guard-fixture\\outside'):
            with self.subTest(path=path):
                result = self.verify(self.bundle(extra=[(path,b'bad')]))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root/'verified').exists())

    def test_symlinks_rejected(self):
        info = zipfile.ZipInfo('vps-guard-fixture/link')
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        result = self.verify(self.bundle(extra=[(info,b'/etc/shadow')]))
        self.assertNotEqual(result.returncode, 0)

    def test_duplicate_paths_rejected(self):
        result = self.verify(self.bundle(extra=[('vps-guard-fixture/install.sh',b'duplicate')]))
        self.assertNotEqual(result.returncode, 0)

    def test_missing_required_file_rejected(self):
        result = self.verify(self.bundle(omit='install.sh'))
        self.assertNotEqual(result.returncode, 0)

    def test_expanded_size_limit(self):
        result = self.verify(self.bundle(extra=[('vps-guard-fixture/huge', b'0'*(8*1024**2))]))
        self.assertNotEqual(result.returncode, 0)

    def test_existing_destination_preserved(self):
        directory = self.root/'verified'
        directory.mkdir()
        (directory/'existing').write_text('keep')
        result = self.verify(self.bundle())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((directory/'existing').read_text(), 'keep')

    def test_pins_use_full_commit_and_sha256(self):
        self.assertRegex(SCRIPT, r'VPS_GUARD_COMMIT="[0-9a-f]{40}"')
        self.assertRegex(SCRIPT, r'VPS_GUARD_MANIFEST_SHA256="[0-9a-f]{64}"')
        self.assertIn('--proto-redir', SCRIPT)
        self.assertIn('exec </dev/tty', SCRIPT)


if __name__ == '__main__':
    unittest.main()
