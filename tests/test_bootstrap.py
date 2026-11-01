import hashlib
import os
from pathlib import Path
import re
import shutil
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
CONFIRMATION = SCRIPT.split('# BEGIN START CONFIRMATION\n',1)[1].split('# END START CONFIRMATION',1)[0]
BASH = (str(Path(r'C:\Program Files\Git\bin\bash.exe'))
        if os.name=='nt' and Path(r'C:\Program Files\Git\bin\bash.exe').exists()
        else (shutil.which('bash') if os.name!='nt' else None))


@unittest.skipUnless(BASH, 'requires Bash')
class ConfirmationTests(unittest.TestCase):
    def check_answer(self, value):
        code=CONFIRMATION+'\nif confirm_hardening; then echo BEGIN_AUTHORIZED_WORK; fi\n'
        result=subprocess.run([BASH,'-c',code],input=value.encode('utf-8'),capture_output=True,timeout=10)
        result.stdout=result.stdout.decode('utf-8',errors='replace')
        result.stderr=result.stderr.decode('utf-8',errors='replace')
        return result

    def test_blank_no_and_eof_cancel(self):
        for value in ('\n','n\n','N\n','no\n',''):
            with self.subTest(value=value):
                result=self.check_answer(value)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertNotIn('BEGIN_AUTHORIZED_WORK',result.stdout)
                self.assertIn('已取消',result.stdout)

    def test_only_explicit_yes_starts(self):
        for value in ('y\n','Y\n','yes\n','Yes\n'):
            with self.subTest(value=value):
                result=self.check_answer(value)
                self.assertIn('BEGIN_AUTHORIZED_WORK',result.stdout)

    def test_invalid_answer_is_not_confirmation(self):
        result=self.check_answer('maybe\n\n')
        self.assertNotIn('BEGIN_AUTHORIZED_WORK',result.stdout)
        self.assertIn('请输入 y 或 n',result.stdout)

    @unittest.skipUnless(os.name=='posix','requires a controlling terminal')
    def test_full_entry_cancels_before_installed_fast_path_or_package_commands(self):
        import pty
        import select
        import signal
        import time
        for answer in (b'n\n',b'\n',b'\x04'):
            with self.subTest(answer=answer), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); mockbin=root/'bin'; mockbin.mkdir()
                log=root/'mutations.log'
                for name,body in {
                    'uname':"printf 'Linux\\n'",
                    'id':"printf '0\\n'",
                    'sudo':'echo sudo >> "$VPS_GUARD_TEST_LOG"; exit 91',
                    'apt-get':'echo apt-get >> "$VPS_GUARD_TEST_LOG"; exit 91',
                    'curl':'echo curl >> "$VPS_GUARD_TEST_LOG"; exit 91',
                }.items():
                    path=mockbin/name; path.write_text('#!/bin/sh\n'+body+'\n'); path.chmod(0o755)
                installed=root/'installed'; installed.mkdir()
                (installed/'vps_auto.py').write_text('fixture')
                (installed/'installed-version').write_text('0.3.1\n')
                launcher=mockbin/'installed-vps-guard'
                launcher.write_text('#!/bin/sh\necho installed-tool >> "$VPS_GUARD_TEST_LOG"\nprintf "0.3.1\\n"\n')
                launcher.chmod(0o755)
                # Redirect only installed-file paths to a fixture; execute the full entry.
                entry=SCRIPT.replace('/usr/local/bin/vps-guard',str(launcher)).replace('/usr/local/lib/vps-guard',str(installed))
                script=root/'bootstrap.sh'; script.write_text(entry,encoding='utf-8')
                env=dict(os.environ,PATH=str(mockbin)+os.pathsep+os.environ['PATH'],VPS_GUARD_TEST_LOG=str(log))
                pid,fd=pty.fork()
                if pid==0:
                    os.execve(BASH,[BASH,str(script)],env)
                output=b''; sent=False; status=None; deadline=time.monotonic()+10
                try:
                    while time.monotonic()<deadline:
                        if select.select([fd],[],[],0.1)[0]:
                            try:
                                chunk=os.read(fd,4096)
                            except OSError:
                                break
                            if not chunk: break
                            output+=chunk
                            if not sent and '[y/N]'.encode() in output:
                                os.write(fd,answer); sent=True
                        ended,code=os.waitpid(pid,os.WNOHANG)
                        if ended:
                            status=code; break
                    if status is None:
                        while time.monotonic()<deadline:
                            ended,code=os.waitpid(pid,os.WNOHANG)
                            if ended:
                                status=code; break
                            time.sleep(0.01)
                        if status is None:
                            os.kill(pid,signal.SIGKILL); os.waitpid(pid,0)
                    self.assertTrue(sent,output.decode('utf-8',errors='replace'))
                    self.assertEqual(status,0,output.decode('utf-8',errors='replace'))
                    self.assertFalse(log.exists(),'cancel ran installed software or mutation commands')
                finally:
                    os.close(fd)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.payload = {n:b'fixture content\n' for n in
                        ('install.sh','vps_guard.py','vps_wizard.py','vps_auto.py','bin/vps-guard','tools/build_release.py')}
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


class UpgradeSafetyTests(unittest.TestCase):
    def test_installer_accepts_only_finished_transactions(self):
        script = (ROOT/'install.sh').read_text(encoding='utf-8')
        guard = script.split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
        for status in ('committed','rolled_back','running','awaiting_confirmation','rollback_failed'):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                run = Path(directory)/'runs/example'
                run.mkdir(parents=True)
                (run/'manifest.json').write_text('{"id":"example","status":"'+status+'"}',encoding='utf-8')
                # Execute the actual installer guard against a temporary fixture.
                code = guard.replace("Path('/var/lib/vps-guard/runs')", 'Path('+repr(str(Path(directory)/'runs'))+')')
                result = subprocess.run([sys.executable,'-X','utf8','-I','-c',code],capture_output=True,timeout=15)
                self.assertEqual(result.returncode==0, status in ('committed','rolled_back'))


if __name__ == '__main__':
    unittest.main()
