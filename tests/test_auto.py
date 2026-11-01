import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vps_guard import FakeRunner
import vps_guard as vg
import vps_auto as va


class CaptureRunner(FakeRunner):
    def __init__(self):
        super().__init__()
        self.options = []

    def run(self, args, **kwargs):
        self.options.append((tuple(args), kwargs))
        return super().run(args, **kwargs)


class AutoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.g = vg.Guard(Path(self.tmp.name), CaptureRunner())
        self.w = va.AutoWizard(self.g)
        self.g.lock = lambda name='lock': contextlib.nullcontext()
        self.g.session = lambda: '192.0.2.1 10001 198.51.100.2 2222'
        self.g.atomic('/etc/os-release', 'ID=debian\nVERSION_ID=13\n')
        self.g.atomic('/proc/sys/kernel/random/boot_id', 'boot-one')
        self.g.atomic('/proc/meminfo', 'MemTotal: 1048576 kB\nMemAvailable: 800000 kB\n')
        self.g.fs('/run/systemd/system').mkdir(parents=True)
        for name in ('firewalld','nftables','netfilter-persistent'):
            self.g.runner.answers[('systemctl','is-active',name)] = (3,'inactive','')
        self.g.runner.answers[('ufw','status')] = (0,'Status: inactive','')
        self.g.runner.answers[('ss','-H','-lntu')] = (0,'tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*','')
        self.g.runner.answers[('nft','-j','list','ruleset')] = (0,'{"nftables":[{"metainfo":{}}]}','')
        self.stdout = contextlib.redirect_stdout(io.StringIO())
        self.stdout.__enter__()

    def tearDown(self):
        self.stdout.__exit__(None,None,None)
        self.tmp.cleanup()

    def collect(self):
        with patch('builtins.input', side_effect=AssertionError('preset must not ask questions')):
            return self.w.collect()

    def test_personal_key_and_no_swap_defaults_without_prompts(self):
        state = self.collect()
        c = self.g.config()
        self.assertTrue(vg.valid_key(va.PUBLIC_KEY))
        self.assertEqual(c['admin_public_keys'], [va.PUBLIC_KEY])
        self.assertEqual(c['admin_user'], 'ops')
        self.assertEqual(c['sudo_mode'], 'key')
        self.assertIsNone(c['swap_mib'])
        self.assertFalse(c['provider_console_verified'])
        self.assertEqual(c['rollback_minutes'], 10)
        self.assertIsNone(c['network']['target_bandwidth_mbps'])
        self.assertNotIn('swap', state['selected'])
        self.assertNotIn('tailscale', state['selected'])

    def test_existing_swap_setting_reset_without_disabling_active_swap(self):
        c = copy.deepcopy(vg.DEFAULTS)
        c.update(swap_mib=2048, provider_console_verified=True)
        c['network']['tcp_buffer_max_bytes'] = 33554432
        self.g.atomic(vg.CONFIG, json.dumps(c))
        self.collect()
        self.assertIsNone(self.g.config()['swap_mib'])
        self.assertIsNone(self.g.config()['network']['tcp_buffer_max_bytes'])
        self.assertTrue(self.g.config()['provider_console_verified'])
        self.assertFalse(any(x[0] in ('swapoff','dd') or (x[0]=='swapon' and '--show' not in x) for x in self.g.runner.calls))
        self.assertTrue(list(self.g.fs(vg.STATE + '/config-history').glob('*.json')))

    def test_no_ssh_session_stops_before_writing_configuration(self):
        self.g.session = lambda: None
        with self.assertRaises(vg.GuardError):
            self.collect()
        self.assertFalse(self.g.fs(vg.CONFIG).exists())

    def test_package_commands_keep_old_configuration_and_do_not_prompt(self):
        self.g.run('apt-get', 'install', '-y', 'sudo')
        args, options = self.g.runner.options[-1]
        self.assertIn('Dpkg::Options::=--force-confold', args)
        self.assertIn('DPkg::Lock::Timeout=120', args)
        self.assertEqual(options['env']['DEBIAN_FRONTEND'], 'noninteractive')
        self.assertEqual(options['env']['NEEDRESTART_MODE'], 'l')

    def test_key_sudo_is_validated_and_noninteractive_access_checked(self):
        self.collect(); self.g.start('access')
        self.w.g.install_key_sudo('ops')
        text = self.g.read('/etc/sudoers.d/90-vps-guard-ops')
        self.assertIn('ops ALL=(ALL:ALL) NOPASSWD: ALL', text)
        self.assertIn(('visudo','-cf','/etc/sudoers.d/90-vps-guard-ops'), self.g.runner.calls)
        self.assertIn(('sudo','-n','-u','ops','--','sudo','-n','--','/usr/bin/true'), self.g.runner.calls)

    def test_invalid_sudo_mode_rejected(self):
        c = copy.deepcopy(vg.DEFAULTS); c['sudo_mode'] = 'anything'
        with self.assertRaises(vg.GuardError):
            vg.validate_config(c)

    def test_access_writes_only_test_root_and_never_requests_a_password(self):
        self.collect(); self.g.start('access')
        self.g.fs('/home/ops').mkdir(parents=True)
        uid = (os.getuid() or 1000) if hasattr(os,'getuid') else 1000
        gid = os.getgid() if hasattr(os,'getgid') else 1000
        account = SimpleNamespace(pw_uid=uid,pw_gid=gid,pw_shell='/bin/bash',pw_dir='/home/ops')
        with patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwnam=lambda name: account)}), \
                patch('builtins.input', side_effect=AssertionError('must not ask')):
            self.g.stage_access()
        self.assertIn(va.PUBLIC_KEY, self.g.read('/home/ops/.ssh/authorized_keys'))
        self.assertFalse(any(x[0] == 'passwd' for x in self.g.runner.calls))

    def test_public_listener_parser_ipv4_ipv6_and_loopback(self):
        text = ('tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n'
                'tcp LISTEN 0 128 [::]:80 [::]:*\n'
                'tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n'
                'udp UNCONN 0 0 [::]:443 [::]:*\n'
                'udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*')
        self.assertEqual(va.public_listeners(text), {(443,'tcp'),(80,'tcp'),(443,'udp')})

    def test_unknown_listener_format_rejected(self):
        for text in ('unexpected','tcp LISTEN 0 128 bad:443 0.0.0.0:*','tcp LISTEN 0 128 *:x *:*'):
            with self.assertRaises(vg.GuardError):
                va.public_listeners(text)

    def test_fresh_server_opens_only_actual_ssh(self):
        self.collect()
        self.assertEqual(self.w.firewall_ports(), [])

    def test_existing_web_listener_is_retained_without_opening_unused_ports(self):
        self.collect()
        self.g.runner.answers[('ss','-H','-lntu')] = (0,'tcp LISTEN 0 128 *:443 *:*','')
        self.assertEqual(self.w.firewall_ports(), [{'port':443,'protocol':'tcp','source':'any'}])

    def test_unknown_public_database_port_skips_firewall_without_asking(self):
        state = self.collect()
        self.g.runner.answers[('ss','-H','-lntu')] = (0,'tcp LISTEN 0 128 *:5432 *:*','')
        with patch.object(self.w,'network_ready'), patch('builtins.input', side_effect=AssertionError('must not ask')):
            stages = self.w.critical_stages(state)
        self.assertNotIn('firewall', stages)
        self.assertTrue(any('5432' in x['reason'] for x in state['skipped']))
        self.assertFalse(any(x[0] == 'ufw' and 'allow' in x for x in self.g.runner.calls))

    def test_running_docker_preserves_firewall(self):
        self.collect()
        self.g.runner.answers[('docker','ps','-q')] = (0,'container-one','')
        with self.assertRaises(vg.GuardError):
            self.w.firewall_ports()

    def test_unknown_ipv6_input_rules_preserved(self):
        self.collect()
        self.g.runner.answers[('ip6tables','-S','INPUT')] = (0,'-P INPUT DROP','')
        with self.assertRaises(vg.GuardError):
            self.w.firewall_ports()

    def test_existing_nftables_rules_preserved(self):
        self.collect()
        self.g.runner.answers[('nft','-j','list','ruleset')] = (0,'{"nftables":[{"table":{"name":"custom"}}]}','')
        with self.assertRaises(vg.GuardError):
            self.w.firewall_ports()

    def test_unsupported_network_is_skipped_but_ssh_remains(self):
        state = self.collect()
        with patch.object(self.w,'network_ready',side_effect=vg.GuardError('no BBR')):
            stages = self.w.critical_stages(state)
        self.assertEqual(stages, ['firewall','ssh'])
        self.assertTrue(any(x['stage']=='network' for x in state['skipped']))

    def test_security_updates_exclude_general_origins_and_reboot(self):
        self.collect(); self.g.start('maintenance')
        self.g.stage_maintenance()
        text = self.g.read('/etc/apt/apt.conf.d/99-vps-guard')
        self.assertIn('#clear Unattended-Upgrade::Allowed-Origins;', text)
        self.assertIn('label=Debian-Security', text)
        self.assertIn('Automatic-Reboot "false"', text)

    def test_failure_report_contains_partial_completed_and_failed_items(self):
        state = self.collect()
        state.update(phase='paused', completed=['baseline'], active_stage='access', last_error='sudo policy failed')
        with patch.object(self.g,'verify',side_effect=lambda scope: print('{"checks":[]}')):
            self.assertEqual(self.w.report(state), 2)
        report = json.loads(self.g.read(vg.STATE + '/last-report.json'))
        self.assertEqual(report['completed'][0]['stage'], 'baseline')
        self.assertEqual(report['failed'][0]['detail'], 'sudo policy failed')
        self.assertTrue(any(x['stage']=='swap' for x in report['skipped']))
        self.assertTrue(any(x['name']=='provider_console' for x in report['checks']))

    def test_completed_preset_shows_report_without_questions_or_reapplying(self):
        state = self.collect(); state['phase']='done'; self.w.save(state)
        with patch('builtins.input',side_effect=AssertionError('must not ask')), \
                patch.object(self.g,'apply',side_effect=AssertionError('must not reapply')), \
                patch.object(self.g,'verify',side_effect=lambda scope: print('{"checks":[]}')):
            self.assertEqual(self.w.run(), 0)

    def test_default_menu_enter_starts_auto(self):
        with patch('builtins.input', return_value=''), patch.object(vg,'main', return_value=0) as main:
            vg.menu(self.g)
        main.assert_called_once_with(['auto'])

    def test_full_preset_without_configuration_questions_keeps_two_login_checks(self):
        self.collect()
        order = []
        def access():
            self.g.atomic(vg.STATE+'/access-pending.json', json.dumps({'origin':self.g.session(),
                'digest':self.g.key_digest(),'boot_id':'boot-one','time':vg.utc()}))
            order.append('access')
        def guarded(stage):
            def run():
                self.g.arm(); order.append(stage)
                if stage=='firewall':
                    self.g.runner.answers[('ufw','status')] = (0,'Status: active','')
            return run
        def reconnect(phase):
            port = 10002 if phase=='await_login' else 10003
            self.g.session=lambda:f'192.0.2.1 {port} 198.51.100.2 2222'
            row={'_UID':'0','_EXE':'/usr/sbin/sshd','__REALTIME_TIMESTAMP':str(int(time.time()*1e6)),
                'MESSAGE':f'Accepted publickey for ops from 192.0.2.1 port {port} ssh2: ED25519 '+next(iter(self.g.configured_fingerprints()))}
            self.g.runner.answers[('journalctl','-b','--no-pager','-o','json','-n','300','-t','sshd','-t','sshd-session')]=(0,json.dumps(row),'')
            def lock(name='lock'):
                if name=='wizard.lock': raise vg.GuardError('original is running')
                return contextlib.nullcontext()
            with patch.object(self.g,'lock',lock):
                self.assertEqual(self.w.continue_from_login(),0)
            return self.w.state()
        with patch('builtins.input',side_effect=AssertionError('configuration question')), \
                patch.object(self.g,'stage_baseline',lambda:order.append('baseline')), \
                patch.object(self.g,'stage_access',access), \
                patch.object(self.g,'stage_network',guarded('network')), \
                patch.object(self.g,'stage_firewall',guarded('firewall')), \
                patch.object(self.g,'stage_ssh',guarded('ssh')), \
                patch.object(self.g,'stage_maintenance',lambda:order.append('maintenance')), \
                patch.object(self.w,'network_ready'), patch.object(self.g,'network_ensure'), \
                patch.object(self.w,'wait_for',reconnect), \
                patch.object(self.g,'verify',side_effect=lambda scope: print('{"checks":[]}')), \
                patch.dict(os.environ,{'SUDO_USER':'ops'}):
            self.assertEqual(self.w.run(),0)
        self.assertEqual(order,['baseline','access','network','firewall','ssh','maintenance'])
        report=json.loads(self.g.read(vg.STATE+'/last-report.json'))
        self.assertEqual(report['phase'],'done')
        self.assertFalse(report['failed'])
        self.assertEqual(len(report['runs']),4)


if __name__ == '__main__':
    unittest.main()
