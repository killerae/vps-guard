import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from test_vps_guard import FakeRunner, public_key
import vps_guard as vg
import vps_wizard as vw


class WizardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.g = vg.Guard(Path(self.tmp.name), FakeRunner())
        self.w = vw.Wizard(self.g)
        self.c = copy.deepcopy(vg.DEFAULTS)
        self.c.update(admin_public_keys=[public_key()], provider_console_verified=True)
        self.g.atomic(vg.CONFIG, json.dumps(self.c))
        self.g.atomic('/etc/os-release', 'ID=debian\nVERSION_ID=13\n')
        self.g.atomic('/proc/sys/kernel/random/boot_id', 'boot-one')
        self.g.fs('/run/systemd/system').mkdir(parents=True)
        self.g.session = lambda: '192.0.2.1 10001 198.51.100.2 2222'
        self.g.lock = lambda name='lock': contextlib.nullcontext()
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()

    def tearDown(self):
        self.output.__exit__(None, None, None)
        self.tmp.cleanup()

    def new_session(self, port=10002):
        self.g.session = lambda: f'192.0.2.1 {port} 198.51.100.2 2222'

    def auth(self, method='publickey', stamp=None, fingerprint=None, uid='0'):
        session = self.g.session().split()
        fingerprint = fingerprint or next(iter(self.g.configured_fingerprints()))
        row = {'_UID': uid, '_EXE': '/usr/sbin/sshd',
               '__REALTIME_TIMESTAMP': str(int((stamp or time.time()) * 1e6)),
               'MESSAGE': f'Accepted {method} for ops from {session[0]} port {session[1]} ssh2: ED25519 {fingerprint}'}
        self.g.runner.answers[('journalctl','-b','--no-pager','-o','json','-n','300','-t','sshd','-t','sshd-session')] = (0,json.dumps(row),'')

    def pending_access(self):
        self.g.atomic(vg.STATE + '/access-pending.json', json.dumps({
            'origin': self.g.session(), 'digest': self.g.key_digest(),
            'boot_id': 'boot-one', 'time': vg.utc()}))
        self.new_session()

    def critical(self, stages=('ssh',)):
        ident = self.g.start('critical')
        self.g.tx['components'] = list(stages)
        self.g.arm()
        self.g.tx['ready_at'] = time.time() - 1
        self.g.save_tx()
        self.new_session(10003)
        return ident

    def state(self, phase, ident=None):
        state = {'schema': 1, 'phase': phase, 'selected': ['ssh'], 'completed': [],
                 'config_digest': vg.sha(json.dumps(self.c, sort_keys=True).encode())}
        if ident:
            state['transaction'] = ident
        self.w.save(state)
        return state

    def test_project_selection(self):
        self.assertEqual(vw.selected_projects(''), ['baseline','ssh','firewall','network','maintenance'])
        self.assertEqual(vw.selected_projects('2，3'), ['baseline','network','maintenance'])
        with self.assertRaises(vg.GuardError):
            vw.selected_projects('0,6')

    def test_ports_require_explicit_none_or_valid_protocol(self):
        self.assertIsNone(vw.parse_ports(''))
        self.assertEqual(vw.parse_ports('none'), [])
        self.assertEqual(vw.parse_ports('443/tcp, 8443/udp')[1]['protocol'], 'udp')
        for value in ('443','0/tcp','65536/tcp','443/tcp;reboot'):
            with self.assertRaises(vg.GuardError):
                vw.parse_ports(value)

    def test_timer_arms_once_across_components(self):
        self.g.start('critical')
        self.g.arm()
        deadline = self.g.tx['deadline']
        self.g.arm()
        self.assertEqual(self.g.tx['deadline'], deadline)
        self.assertEqual(len([x for x in self.g.runner.calls if x[0] == 'systemd-run']), 1)

    def test_expired_batch_stops_next_component(self):
        self.g.start('critical'); self.g.arm()
        self.g.tx['deadline'] = time.time() - 1
        with self.assertRaises(vg.GuardError):
            self.g.arm()

    def test_batch_checkpoint_precedes_changes_and_ssh_is_last(self):
        order = []
        def callback(ident):
            self.g.load_tx(ident)
            self.assertFalse(self.g.tx['files'])
            order.append('checkpoint')
        def stage(name):
            def run():
                self.g.arm(); order.append(name)
            return run
        with patch.object(self.g, 'stage_network', stage('network')), patch.object(self.g, 'stage_firewall', stage('firewall')), patch.object(self.g, 'stage_ssh', stage('ssh')):
            ident = self.g.apply_critical(['ssh','firewall','network'], callback)
        self.g.load_tx(ident)
        self.assertEqual(order, ['checkpoint','network','firewall','ssh'])
        self.assertIn('ready_at', self.g.tx)
        self.assertEqual(self.g.tx['status'], 'awaiting_confirmation')

    def test_batch_failure_restores_multiple_modules(self):
        self.g.atomic('/etc/ufw/user.rules', 'original\n')
        def network():
            self.g.arm()
            self.g.tx['runtime']['sysctl'] = {'net.ipv4.tcp_congestion_control':'cubic'}
            self.g.save_tx()
            self.g.write(vg.NETWORK_FILE, 'managed network')
        def firewall():
            self.g.write('/etc/ufw/user.rules', 'managed firewall')
            self.g.tx['runtime'].update(ufw_active=True, ufw_modified=True)
            self.g.save_tx()
            raise vg.GuardError('simulated firewall failure')
        with patch.object(self.g, 'stage_network', network), patch.object(self.g, 'stage_firewall', firewall):
            with self.assertRaises(vg.GuardError):
                self.g.apply_critical(['network','firewall','ssh'])
        self.assertEqual(self.g.tx['status'], 'rolled_back')
        self.assertEqual(self.g.read('/etc/ufw/user.rules'), 'original\n')
        self.assertFalse(self.g.fs(vg.NETWORK_FILE).exists())
        self.assertEqual(self.g.runner.defaults['net.ipv4.tcp_congestion_control'], 'cubic')
        self.assertIn(('systemctl','reload','ssh.service'), self.g.runner.calls)

    def test_login_accepts_matching_public_key(self):
        self.pending_access(); self.auth()
        with patch.dict(os.environ, {'SUDO_USER':'ops'}), patch('builtins.input', side_effect=AssertionError('unexpected prompt')):
            self.g.confirm_login(automatic=True)
        self.assertIn('session', json.loads(self.g.read(vg.STATE + '/access-verified.json')))

    def test_login_rejects_password_or_wrong_key_or_old_auth(self):
        self.pending_access()
        for method, fp, stamp in [('password',None,None),('publickey','SHA256:unexpected',None),('publickey',None,time.time()-120)]:
            self.auth(method, stamp, fp)
            with patch.dict(os.environ, {'SUDO_USER':'ops'}), self.assertRaises(vg.GuardError):
                self.g.confirm_login(automatic=True)
        self.assertFalse(self.g.fs(vg.STATE + '/access-verified.json').exists())

    def test_untrusted_journal_record_is_ignored(self):
        self.auth(uid='1000')
        self.assertIsNone(self.g.connection_auth(self.g.session()))

    def test_missing_auth_log_requires_explicit_attestation(self):
        self.pending_access()
        with patch.dict(os.environ, {'SUDO_USER':'ops'}), patch('builtins.input', return_value=''), self.assertRaises(vg.GuardError):
            self.g.confirm_login(automatic=True)

    def test_final_confirmation_rejects_prechange_proof_session(self):
        ident = self.critical()
        self.g.tx['blocked_sessions'] = [self.g.session()]; self.g.save_tx()
        with patch.dict(os.environ, {'SUDO_USER':'ops'}), self.assertRaises(vg.GuardError):
            self.g.confirm(ident)

    def test_final_confirmation_requires_postchange_key_login(self):
        ident = self.critical()
        for method, stamp in [('password',None),('publickey',time.time()-120)]:
            self.auth(method, stamp)
            with patch.dict(os.environ, {'SUDO_USER':'ops'}), self.assertRaises(vg.GuardError):
                self.g.confirm(ident)
        self.auth()
        with patch.dict(os.environ, {'SUDO_USER':'ops'}):
            self.g.confirm(ident)
        self.assertEqual(self.g.tx['status'], 'committed')
        self.assertTrue(self.g.fs(vg.STATE + '/stages/ssh.json').exists())

    def test_resume_partial_batch_rolls_back(self):
        ident = self.g.start('critical')
        self.g.tx['components'] = ['network']; self.g.arm()
        self.g.write(vg.NETWORK_FILE, 'partial')
        state = self.state('critical_running', ident)
        self.w.refresh_transaction(state)
        self.assertEqual(state['phase'], 'paused')
        self.assertEqual(state['resume_phase'], 'critical')
        self.assertFalse(self.g.fs(vg.NETWORK_FILE).exists())

    def test_resume_ready_batch_waits_for_confirmation(self):
        ident = self.critical()
        state = self.state('critical_running', ident)
        self.w.refresh_transaction(state)
        self.assertEqual(state['phase'], 'await_confirmation')

    def test_resume_committed_batch_continues_maintenance(self):
        ident = self.critical()
        self.g.tx['status'] = 'committed'; self.g.save_tx()
        state = self.state('await_confirmation', ident)
        self.w.refresh_transaction(state)
        self.assertEqual(state['phase'], 'maintenance')
        self.assertEqual(state['completed'], ['ssh'])

    def test_scope_marks_unselected_modules_skipped(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.g.verify(scope=['baseline'])
        checks = {x['name']: x['status'] for x in json.loads(output.getvalue())['checks']}
        self.assertEqual(checks['firewall'], 'skipped')
        self.assertEqual(checks['ssh_policy'], 'skipped')
        self.assertEqual(checks['backup'], 'skipped')

    def test_backup_secrets_are_not_written_during_collection(self):
        with patch('builtins.input', side_effect=['s3:https://example.invalid/bucket','']), patch('getpass.getpass', side_effect=['restore-test','restore-test','','']):
            self.w.collect_backup(self.c)
        self.assertTrue(self.w.secret_files)
        self.assertFalse(self.g.fs('/etc/vps-guard/restic-password').exists())
        self.assertFalse(self.g.fs('/etc/vps-guard/backup.env').exists())

    def test_config_change_prevents_resume(self):
        state = self.state('prepare')
        self.c['timezone'] = 'Asia/Shanghai'
        self.g.atomic(vg.CONFIG, json.dumps(self.c))
        with self.assertRaises(vg.GuardError):
            self.w.check_state(state)


if __name__ == '__main__':
    unittest.main()
