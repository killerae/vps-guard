import base64
import copy
import io
import json
import os
import stat
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vps_guard as vg


def public_key():
    kind = b'ssh-ed25519'
    raw = len(kind).to_bytes(4, 'big') + kind + (32).to_bytes(4, 'big') + bytes(range(32))
    return 'ssh-ed25519 ' + base64.b64encode(raw).decode() + ' test'


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.answers = {}
        self.defaults = {**vg.TCP_BASE, 'net.ipv4.tcp_available_congestion_control': 'reno cubic bbr',
                         'net.ipv4.tcp_rmem': '4096 131072 6291456',
                         'net.ipv4.tcp_wmem': '4096 16384 4194304',
                         'net.core.rmem_max': '212992', 'net.core.wmem_max': '212992'}

    def run(self, args, **kw):
        args = tuple(str(x) for x in args)
        self.calls.append(args)
        if args in self.answers:
            rc, out, err = self.answers[args]
        elif args[:2] == ('sysctl', '-n'):
            rc, out, err = 0, self.defaults.get(args[2], ''), ''
        elif args[:2] == ('sysctl', '-w'):
            k, v = args[2].split('=', 1)
            self.defaults[k] = v
            rc, out, err = 0, '', ''
        elif args == ('systemctl', 'is-active', 'ssh.socket'):
            rc, out, err = 3, 'inactive', ''
        elif args[:2] == ('systemctl', 'is-active'):
            rc, out, err = 0, 'active', ''
        elif args[:2] == ('systemctl', 'is-enabled'):
            rc, out, err = 1, 'disabled', ''
        elif args[0] == '/usr/sbin/sshd' and '-T' in args:
            text = 'port 2222\n' + '\n'.join(k.lower() + ' ' + v for k, v in vg.SSH_POLICY.items())
            rc, out, err = 0, text, ''
        else:
            rc, out, err = 0, '', ''
        if rc and kw.get('check', True):
            raise vg.GuardError('模拟命令失败')
        return rc, out, err


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.runner = FakeRunner()
        self.g = vg.Guard(self.root, self.runner)
        self.c = copy.deepcopy(vg.DEFAULTS)
        self.c['admin_public_keys'] = [public_key()]
        self.c['provider_console_verified'] = True
        self.write(vg.CONFIG, json.dumps(self.c))
        self.write('/etc/os-release', 'ID=debian\nVERSION_ID="13"\n')
        self.write('/proc/meminfo', 'MemTotal: 1048576 kB\nMemAvailable: 800000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n')
        self.write('/proc/sys/kernel/random/boot_id', 'boot-one')
        self.g.session = lambda: '192.0.2.1 10001 198.51.100.2 2222'

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, path, text):
        p = self.g.fs(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open('w', encoding='utf-8', newline='\n') as f:
            f.write(text)
        return p

    def start(self, stage='network'):
        return self.g.start(stage)

    def test_default_policy(self):
        c = self.g.config()
        self.assertIsNone(c['swap_mib'])
        self.assertIsNone(c['ssh_port'])
        self.assertFalse(c['business_ports_confirmed'])
        self.assertFalse(c['backup']['enabled'])

    def test_unknown_config_rejected(self):
        with self.assertRaises(vg.GuardError):
            vg.merge_config(vg.DEFAULTS, {'shell_command': 'bad'})

    def test_root_admin_rejected(self):
        self.c['admin_user'] = 'root'
        with self.assertRaises(vg.GuardError):
            vg.validate_config(self.c)

    def test_username_injection_rejected(self):
        self.c['admin_user'] = 'ops; reboot'
        with self.assertRaises(vg.GuardError):
            vg.validate_config(self.c)

    def test_private_key_rejected(self):
        self.c['admin_public_keys'] = ['-----BEGIN OPENSSH PRIVATE KEY-----']
        with self.assertRaises(vg.GuardError):
            vg.validate_config(self.c)

    def test_valid_key_checked(self):
        self.assertTrue(vg.valid_key(public_key()))
        self.assertFalse(vg.valid_key('ssh-ed25519 AAAA'))

    def test_multiline_key_rejected(self):
        self.assertFalse(vg.valid_key(public_key() + '\n' + public_key()))

    def test_business_source_requires_string(self):
        self.c['business_ports'] = [{'port': 443, 'protocol': 'tcp', 'source': 123}]
        with self.assertRaises(vg.GuardError):
            vg.validate_config(self.c)

    def test_bad_port_rejected(self):
        self.c['business_ports'] = [{'port': 65536, 'protocol': 'tcp', 'source': 'any'}]
        with self.assertRaises(vg.GuardError):
            vg.validate_config(self.c)

    def test_bad_source_rejected(self):
        self.c['ssh_sources'] = ['any; reboot']
        with self.assertRaises(vg.GuardError):
            vg.validate_config(self.c)

    def test_nan_measurement_rejected(self):
        self.c['network']['representative_rtt_ms'] = float('nan')
        with self.assertRaises(vg.GuardError):
            vg.validate_config(self.c)

    def test_bool_is_not_port(self):
        self.c['ssh_port'] = True
        with self.assertRaises(vg.GuardError):
            vg.validate_config(self.c)

    def test_audit_does_not_write(self):
        before = sorted(str(x.relative_to(self.root)) for x in self.root.rglob('*'))
        report = self.g.audit()
        after = sorted(str(x.relative_to(self.root)) for x in self.root.rglob('*'))
        self.assertEqual(before, after)
        self.assertEqual(report['os']['ID'], 'debian')

    def test_nonstandard_port_preserved(self):
        self.assertEqual(self.g.ssh_ports(), [2222])

    def test_mismatched_ssh_port_rejected(self):
        self.c['ssh_port'] = 22
        self.write(vg.CONFIG, json.dumps(self.c))
        with self.assertRaises(vg.GuardError):
            self.g.ssh_ports()

    def test_socket_activation_uses_actual_listen_port(self):
        self.runner.answers[('systemctl','is-active','ssh.socket')] = (0,'active','')
        self.runner.answers[('systemctl','show','ssh.socket','--property=Listen','--value')] = (0,'[::]:2222 (Stream) 0.0.0.0:2222 (Stream)','')
        self.runner.answers[('/usr/sbin/sshd','-T')] = (0,'port 22','')
        self.assertEqual(self.g.ssh_ports(), [2222])

    def test_unknown_socket_ports_stop_firewall_planning(self):
        self.runner.answers[('systemctl','is-active','ssh.socket')] = (0,'active','')
        with self.assertRaises(vg.GuardError):
            self.g.ssh_ports()

    def test_active_connection_port_mismatch_is_not_guessed(self):
        self.g.session = lambda: '192.0.2.1 10002 198.51.100.2 2200'
        with self.assertRaises(vg.GuardError):
            self.g.ssh_ports()

    def test_write_is_idempotent(self):
        self.write('/etc/example', 'same\n')
        os.chmod(self.g.fs('/etc/example'), 0o600)
        self.start()
        # Windows cannot represent POSIX 0600; Linux CI exercises that mode directly.
        mode = stat.S_IMODE(self.g.fs('/etc/example').stat().st_mode)
        self.assertFalse(self.g.write('/etc/example', 'same\n', mode=mode))
        self.assertEqual(self.g.tx['files'], {})

    def test_backup_and_restore_contents(self):
        self.write('/etc/example', 'original\n')
        ident = self.start()
        self.g.write('/etc/example', 'modified\n')
        self.g.rollback(ident)
        self.assertEqual(self.g.read('/etc/example'), 'original\n')
        self.assertEqual(self.g.tx['status'], 'rolled_back')

    def test_restore_removes_new_file(self):
        ident = self.start()
        self.g.write('/etc/example', 'new\n')
        self.g.rollback(ident)
        self.assertFalse(self.g.fs('/etc/example').exists())

    def test_stale_restore_does_not_overwrite_later_edits(self):
        self.write('/etc/example', 'original\n')
        ident = self.start()
        self.g.write('/etc/example', 'managed\n')
        self.write('/etc/example', 'later user edit\n')
        with self.assertRaises(vg.GuardError):
            self.g.rollback(ident)
        self.assertEqual(self.g.read('/etc/example'), 'later user edit\n')

    def test_crash_before_write_can_restore(self):
        self.write('/etc/example', 'original\n')
        ident = self.start()
        self.g.write('/etc/example', 'managed\n')
        self.write('/etc/example', 'original\n')
        self.g.rollback(ident)
        self.assertEqual(self.g.read('/etc/example'), 'original\n')

    def test_bad_run_path_rejected(self):
        with self.assertRaises(vg.GuardError):
            self.g.load_tx('../../etc/shadow')

    def test_runtime_sysctl_restored(self):
        ident = self.start()
        self.g.tx['runtime']['sysctl'] = {'net.ipv4.tcp_congestion_control': 'cubic'}
        self.g.save_tx()
        self.g.rollback(ident)
        self.assertEqual(self.runner.defaults['net.ipv4.tcp_congestion_control'], 'cubic')

    def test_confirm_requires_different_connection(self):
        ident = self.start('firewall')
        self.g.arm()
        with self.assertRaises(vg.GuardError):
            self.g.confirm(ident)

    def test_expired_change_cannot_be_confirmed(self):
        ident = self.start('firewall')
        self.g.arm()
        self.g.tx['deadline'] = time.time() - 1
        self.g.save_tx()
        self.g.session = lambda: '192.0.2.1 10002 198.51.100.2 2222'
        with self.assertRaises(vg.GuardError):
            self.g.confirm(ident)

    def test_pending_change_blocks_another(self):
        self.start('ssh'); self.g.arm()
        with self.assertRaises(vg.GuardError):
            self.g.start('network')

    def test_ssh_apply_requires_login_proof(self):
        self.start('ssh')
        with self.assertRaises(vg.GuardError):
            self.g.stage_ssh()
        self.assertFalse(self.g.fs(vg.SSH_FILE).exists())

    def test_firewall_requires_port_inventory(self):
        self.start('firewall')
        with self.assertRaises(vg.GuardError):
            self.g.stage_firewall()
        self.assertFalse(any(x[0] == 'ufw' for x in self.runner.calls))

    def test_tcp_baseline_with_unknown_measurements(self):
        values = self.g.tcp_values()
        self.assertEqual(values, vg.TCP_BASE)
        self.assertNotIn('net.ipv4.tcp_rmem', values)

    def test_tcp_profile_bdp_and_budget(self):
        self.c['network'].update(target_bandwidth_mbps=1000, representative_rtt_ms=100)
        self.write(vg.CONFIG, json.dumps(self.c))
        values = self.g.tcp_values()
        self.assertEqual(values['net.ipv4.tcp_rmem'].split()[:2], ['4096', '131072'])
        self.assertEqual(int(values['net.ipv4.tcp_rmem'].split()[2]), 33554432)

    def test_explicit_buffer_cannot_exceed_memory_budget(self):
        self.write('/proc/meminfo', 'MemTotal: 131072 kB\n')
        self.c['network']['tcp_buffer_max_bytes'] = 33554432
        self.write(vg.CONFIG, json.dumps(self.c))
        with self.assertRaises(vg.GuardError):
            self.g.tcp_values()

    def test_complex_qdisc_not_replaced(self):
        self.runner.answers[('tc','-j','qdisc','show','dev','eth0')] = (0,json.dumps([{'kind':'htb','handle':'1:','root':True}]),'')
        with self.assertRaises(vg.GuardError):
            self.g.qdisc_plan(['eth0'])
        self.assertFalse(any('replace' in x for x in self.runner.calls))

    def test_mq_only_changes_leaves(self):
        rows = [{'kind':'mq','handle':'0:','root':True},
                {'kind':'fq_codel','handle':'0:','parent':':1'}]
        self.runner.answers[('tc','-j','qdisc','show','dev','eth0')] = (0,json.dumps(rows),'')
        self.runner.answers[('tc','qdisc','show','dev','eth0')] = (0,'qdisc mq 0: root\nqdisc fq_codel 0: parent :1 limit 10240p flows 1024','')
        plan = self.g.qdisc_plan(['eth0'])
        self.assertEqual(plan[0]['location'], ['parent', ':1'])
        self.assertEqual(plan[0]['old_kind'], 'fq_codel')
        self.assertEqual(len(plan), 1)

    def test_network_rollback_before_mutation_keeps_existing_unit(self):
        ident = self.start('network')
        self.g.rollback(ident)
        self.assertNotIn(('systemctl','disable','vps-guard-network.service'), self.runner.calls)

    def test_firewall_rollback_before_mutation_keeps_firewall(self):
        ident = self.start('firewall')
        self.g.tx['runtime']['ufw_active'] = True
        self.g.save_tx()
        self.g.rollback(ident)
        self.assertFalse(any(x[0] == 'ufw' for x in self.runner.calls))

    def test_firewall_restore_stops_then_reenables_original_rules(self):
        self.write('/etc/ufw/user.rules', 'old rules\n')
        ident = self.start('firewall')
        self.g.write('/etc/ufw/user.rules', 'new rules\n')
        self.g.tx['runtime'].update(ufw_active=True, ufw_modified=True)
        self.g.save_tx()
        self.g.rollback(ident)
        ufw = [x for x in self.runner.calls if x[0] == 'ufw']
        self.assertEqual(ufw, [('ufw','--force','disable'), ('ufw','--force','enable')])
        self.assertEqual(self.g.read('/etc/ufw/user.rules'), 'old rules\n')

    def test_swap_auto_preserves_existing_setup(self):
        self.start('swap')
        self.g.stage_swap()
        self.assertFalse(any(x[0] in ('dd','mkswap','swapon') for x in self.runner.calls))

    def test_protected_env_never_executes_shell(self):
        self.write('/etc/vps-guard/backup.env', 'RESTIC_PASSWORD=$(touch /should-not-exist)\n')
        env = self.g.protected_env('/etc/vps-guard/backup.env')
        self.assertEqual(env['RESTIC_PASSWORD'], '$(touch /should-not-exist)')
        self.assertFalse(self.g.fs('/should-not-exist').exists())

    def test_protected_env_rejects_path_override(self):
        self.write('/etc/vps-guard/backup.env', 'PATH=/tmp\n')
        with self.assertRaises(vg.GuardError):
            self.g.protected_env('/etc/vps-guard/backup.env')

    def test_local_directory_not_counted_as_offsite_backup(self):
        self.c['backup']['enabled'] = True
        self.write(vg.CONFIG, json.dumps(self.c))
        self.write('/etc/vps-guard/backup.env', 'RESTIC_REPOSITORY=/tmp/backup\nRESTIC_PASSWORD=test\n')
        with self.assertRaises(vg.GuardError):
            self.g.restic('snapshots')
        self.assertFalse(any(x[0] == 'restic' for x in self.runner.calls))

    def test_automatic_restore_cannot_undo_committed_change(self):
        ident = self.start('ssh')
        self.g.tx['status'] = 'committed'; self.g.save_tx()
        self.g.rollback(ident, automatic=True)
        self.assertEqual(self.g.tx['status'], 'committed')

    def test_invalid_attestation_not_recorded(self):
        with patch('builtins.input', return_value=''):
            with self.assertRaises(vg.GuardError):
                self.g.attest('performance')
        self.assertFalse(self.g.fs(vg.STATE + '/attestations/performance.json').exists())

    def test_unchanged_ssh_stage_can_be_reused_without_reloading(self):
        self.start('ssh')
        self.g.record_stage()
        self.assertTrue(self.g.stage_current('ssh'))
        self.assertNotIn(('systemctl','reload','ssh.service'), self.runner.calls)

    def test_config_change_invalidates_reuse(self):
        self.start('ssh')
        self.g.record_stage()
        self.c['admin_public_keys'] = []
        self.write(vg.CONFIG, json.dumps(self.c))
        self.assertFalse(self.g.stage_current('ssh'))

    def test_modified_managed_file_invalidates_reuse(self):
        self.start('ssh')
        self.g.write('/etc/example', 'managed')
        self.g.record_stage()
        self.write('/etc/example', 'user edit')
        self.assertFalse(self.g.stage_current('ssh'))


if __name__ == '__main__':
    unittest.main()
