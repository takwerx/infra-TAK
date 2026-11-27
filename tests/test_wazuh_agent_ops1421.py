# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""ops #1421: Wazuh agent broker op (Security review ops #1422, conditions C1 to C12).

The broker is the lock: a hacked console must not be able to install anything but the four
pinned files, turn active response or remote commands back on, or leak the enrollment
password into the audit log. Every test here fails on the base branch (there is no
`wazuh_agent` op there) and passes with the change. What only a real Wazuh server or a real
box can show (enrollment with a wrong certificate, a pushed agent.conf block, `ss -lntup`,
purge leaving nothing) is in the PR's box-test list, not here.
"""

import copy
import hashlib
import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, REPO / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _load('takwerx_broker_ops1421', 'broker/takwerx_broker.py')

# The table Security posted on ops #1422 (Fri Nov 27, 2026). Copied here on purpose: a pin
# that moves must be a reviewed change, not a quiet edit in one file.
SECURITY_TABLE = {
    'wazuh-agent_4.14.11-1_amd64.deb': 'af1dd6e83350ecdb3e9c26a6467e3cc701766bf5519f63b3f213148dd5e8e89d',
    'wazuh-agent_4.14.11-1_arm64.deb': '28a57d4bb7cb0c441f7b8046b8f15afd37819f0d768663326b4367dd8a8e0318',
    'wazuh-agent-4.14.11-1.x86_64.rpm': '17362b1e88be0e53704c9c98664c5a92c560ab0abee8e08fcf6c95d6b7f4f316',
    'wazuh-agent-4.14.11-1.aarch64.rpm': '6e53002ecb212d35d13714c4efe87bf37d2ec1f8725852aad2f59346ded82684',
}

HAS_OPENSSL = shutil.which('openssl') is not None


def _make_cert(tmp_path, name='ca'):
    key, crt = tmp_path / f'{name}.key', tmp_path / f'{name}.crt'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                    '-out', str(crt), '-days', '30', '-subj', '/CN=wazuh-test'],
                   check=True, capture_output=True)
    return crt.read_text()


def _good_render(family='debian', sources=('ssh_auth', 'fail2ban')):
    return B._wazuh_render_ossec('wazuh.example.org', 'tak-box-1', list(sources), family)


# ── C1: the package check ────────────────────────────────────────────────────────

def test_pins_are_exactly_the_table_security_posted():
    assert B.WAZUH_PKG_PINS == SECURITY_TABLE
    assert B.WAZUH_VERSION == '4.14.11'


def test_a_pinned_file_passes_and_one_changed_byte_is_refused(tmp_path, monkeypatch):
    good = tmp_path / 'wazuh-agent_4.14.11-1_amd64.deb'
    good.write_bytes(b'pretend package bytes')
    monkeypatch.setitem(B.WAZUH_PKG_PINS, good.name, hashlib.sha256(b'pretend package bytes').hexdigest())
    B._verify_wazuh_pkg(str(good), good.name)                     # passes
    bad = tmp_path / 'copy' / good.name
    bad.parent.mkdir()
    bad.write_bytes(b'pretend package byteZ')
    with pytest.raises(B.Denied) as e:
        B._verify_wazuh_pkg(str(bad), good.name)
    assert 'SHA-256' in str(e.value) and 'pinned' in str(e.value)


@pytest.mark.parametrize('name', [
    'wazuh-agent_4.14.10-1_amd64.deb',        # older than the pin
    'wazuh-agent_4.99.0-1_amd64.deb',         # newer than the pin: still not reviewed
    'wazuh-manager_4.14.11-1_amd64.deb',      # a different Wazuh package
    'wazuh-agent-4.14.11-1.x86_64.deb',       # right look, wrong suffix
    'Wazuh-Agent_4.14.11-1_amd64.deb',
])
def test_any_other_wazuh_file_is_refused(tmp_path, name):
    p = tmp_path / name
    p.write_bytes(b'x')
    with pytest.raises(B.Denied) as e:
        B._verify_wazuh_pkg(str(p), name)
    assert 'pinned' in str(e.value)


def test_package_stage_sends_wazuh_names_to_the_pin_check_before_the_tak_check():
    import inspect
    src = inspect.getsource(B._pkg_stage_verified)
    assert src.index('_verify_wazuh_pkg') < src.index('_verify_caddy_deb') < src.index('_verify_tak_deb')
    assert "startswith('wazuh')" in src


@pytest.mark.parametrize('argv', [
    ['apt-get', 'install', '-y', 'wazuh-agent'],
    ['apt-get', 'install', '-y', 'Wazuh-Agent'],
    ['apt-get', 'reinstall', 'wazuh-manager'],
    ['dnf', 'install', '-y', 'wazuh-agent'],
    ['dnf', 'upgrade', '-y', 'wazuh-agent'],
    ['dnf', 'install', '-y', '--enablerepo=wazuh', 'curl'],
    ['dnf', 'config-manager', '--add-repo', 'https://packages.wazuh.com/4.x/yum/wazuh.repo'],
])
def test_wazuh_cannot_be_installed_by_name_or_from_a_repo(argv):
    with pytest.raises(B.Denied):
        B.check_exec(argv)


def test_a_pinned_package_file_still_gets_past_the_argv_check():
    B.check_exec(['apt-get', 'install', '-y', '/home/takwerx/.config/wazuh/wazuh-agent_4.14.11-1_amd64.deb'])
    B.check_exec(['dnf', 'install', '-y', '/home/takwerx/.config/wazuh/wazuh-agent-4.14.11-1.x86_64.rpm'])


def test_the_pinned_name_for_each_family_and_cpu():
    f = B._wazuh_pkg_name_for
    assert f('debian', 'amd64') == 'wazuh-agent_4.14.11-1_amd64.deb'
    assert f('debian', 'arm64') == 'wazuh-agent_4.14.11-1_arm64.deb'
    assert f('rhel', 'amd64') == 'wazuh-agent-4.14.11-1.x86_64.rpm'
    assert f('rhel', 'arm64') == 'wazuh-agent-4.14.11-1.aarch64.rpm'
    assert f('debian', '') == '' and f('rhel', '') == ''


# ── C3/C5: the lock-down, built in and checked ──────────────────────────────────

@pytest.mark.parametrize('family', ['debian', 'rhel'])
def test_our_own_config_has_no_problems_for_every_source_choice(family):
    for n in range(len(B.WAZUH_SOURCES) + 1):
        keys = list(B.WAZUH_SOURCES)[:n]
        text = _good_render(family, keys)
        assert B._wazuh_conf_problems(text, B.WAZUH_LOCAL_OPTS_TEXT, B.WAZUH_DROPIN_TEXT) == []
        # nothing but the ticked sources is read (C7): the package's whole-journal list is gone
        assert text.count('<localfile>') == n
        assert 'journald' not in text and 'full_command' not in text and 'netstat' not in text


def test_the_rendered_config_never_turns_anything_dangerous_on():
    t = _good_render()
    assert re.search(r'<active-response>\s*<disabled>yes</disabled>', t)
    assert '<ca_verification>yes</ca_verification>' in t
    assert re.search(r'<rootcheck>\s*<disabled>yes</disabled>', t)
    assert re.search(r'<sca>\s*<enabled>no</enabled>', t)
    assert 'report_changes' not in t and 'whodata' not in t and '<integration' not in t
    for k in ('processes', 'users', 'groups', 'services', 'browser_extensions'):
        assert f'<{k}>no</{k}>' in t
    assert f'<server_ca_path>{B.WAZUH_CA_PEM}</server_ca_path>' in t
    assert B.WAZUH_LOCAL_OPTS_TEXT.count('=0') == 4 and 'remote_conf=0' in B.WAZUH_LOCAL_OPTS_TEXT


MUTATIONS = {
    'active response on': lambda t: t.replace('<active-response>\n    <disabled>yes', '<active-response>\n    <disabled>no'),
    'ca_verification off': lambda t: t.replace('<ca_verification>yes', '<ca_verification>no'),
    'server CA dropped': lambda t: re.sub(r'\s*<server_ca_path>.*?</server_ca_path>', '', t),
    'rootcheck on': lambda t: t.replace('<rootcheck>\n    <disabled>yes', '<rootcheck>\n    <disabled>no'),
    'sca on': lambda t: t.replace('<sca>\n    <enabled>no', '<sca>\n    <enabled>yes'),
    'command localfile': lambda t: t.replace('</syscheck>', '</syscheck>\n  <localfile><log_format>full_command</log_format><command>id</command></localfile>'),
    'command in a syslog localfile': lambda t: t.replace('</syscheck>', '</syscheck>\n  <localfile><log_format>syslog</log_format><location>/var/log/auth.log</location><command>id</command></localfile>'),
    'a log file we do not offer': lambda t: t.replace('</syscheck>', '</syscheck>\n  <localfile><log_format>syslog</log_format><location>/etc/shadow</location></localfile>'),
    'command wodle': lambda t: t.replace('</syscheck>', '</syscheck>\n  <wodle name="command"><disabled>no</disabled><command>id</command></wodle>'),
    'integration block': lambda t: t.replace('</syscheck>', '</syscheck>\n  <integration><name>x</name></integration>'),
    'cis-cat on': lambda t: t.replace('<wodle name="cis-cat">\n    <disabled>yes', '<wodle name="cis-cat">\n    <disabled>no'),
    'osquery on': lambda t: t.replace('<wodle name="osquery">\n    <disabled>yes', '<wodle name="osquery">\n    <disabled>no'),
    'process list on': lambda t: t.replace('<processes>no', '<processes>yes'),
    'report_changes on': lambda t: t.replace('<directories>/etc,', '<directories report_changes="yes">/etc,'),
    'whodata on': lambda t: t.replace('<directories>/etc,', '<directories whodata="yes">/etc,'),
    'second server': lambda t: t.replace('</client>', '<server><address>evil.example</address></server></client>'),
    'udp to the server': lambda t: t.replace('<protocol>tcp', '<protocol>udp'),
    'not xml': lambda t: t + '<<<',
}


@pytest.mark.parametrize('what', sorted(MUTATIONS))
def test_every_forbidden_setting_is_reported(what):
    bad = MUTATIONS[what](_good_render())
    assert bad != _good_render(), f'mutation {what!r} changed nothing'
    assert B._wazuh_conf_problems(bad, B.WAZUH_LOCAL_OPTS_TEXT, B.WAZUH_DROPIN_TEXT), what


@pytest.mark.parametrize('opts', [
    B.WAZUH_LOCAL_OPTS_TEXT.replace('agent.remote_conf=0', 'agent.remote_conf=1'),
    B.WAZUH_LOCAL_OPTS_TEXT.replace('logcollector.remote_commands=0', 'logcollector.remote_commands=1'),
    B.WAZUH_LOCAL_OPTS_TEXT.replace('wazuh_command.remote_commands=0', 'wazuh_command.remote_commands=1'),
    B.WAZUH_LOCAL_OPTS_TEXT.replace('sca.remote_commands=0', 'sca.remote_commands=1'),
    B.WAZUH_LOCAL_OPTS_TEXT + 'some.other.remote_commands=1\n',
    '',
])
def test_remote_conf_and_remote_commands_must_stay_zero(opts):
    assert B._wazuh_conf_problems(_good_render(), opts, B.WAZUH_DROPIN_TEXT)


def test_the_unit_drop_in_must_stay_resource_limits_only():
    ok = B.WAZUH_DROPIN_TEXT
    assert B._wazuh_conf_problems(_good_render(), B.WAZUH_LOCAL_OPTS_TEXT, ok) == []
    for bad in (ok + 'ExecStartPre=/bin/sh -c id\n', ok.replace('MemoryMax=256M', 'MemoryMax=infinity'),
                ok + 'User=root\n', ok.replace('[Service]', '[Service]\n[Install]')):
        assert B._wazuh_conf_problems(_good_render(), B.WAZUH_LOCAL_OPTS_TEXT, bad), bad


# ── C3: the request checks ───────────────────────────────────────────────────────

GOOD = {'op': 'wazuh_agent', 'action': 'configure', 'server': 'wazuh.example.org',
        'agent_name': 'tak-box-1', 'sources': ['ssh_auth']}


def _denied(req):
    with pytest.raises(B.Denied):
        B._check_wazuh_agent(req)


def test_a_good_configure_request_passes_the_check():
    B._check_wazuh_agent(dict(GOOD))
    B._check_wazuh_agent(dict(GOOD, server='10.20.30.40'))
    B._check_wazuh_agent(dict(GOOD, server='2001:db8::1', password='a b c1'))


@pytest.mark.parametrize('field,value', [
    ('server', 'a"b.example.org'), ('server', 'host\nname'), ('server', 'evil.example.org<x>'),
    ('server', '0.0.0.0'), ('server', '224.0.0.1'), ('server', ''), ('server', 'a' * 300),
    ('server', '12345'), ('server', 'bad host'), ('server', 'x;id'),
    ('agent_name', 'a'), ('agent_name', 'name with space'), ('agent_name', 'x\ny'),
    ('agent_name', '<script>'), ('agent_name', '-leading'), ('agent_name', 'a' * 64),
    ('sources', ['journald']), ('sources', ['ssh_auth', 'ssh_auth']), ('sources', 'ssh_auth'),
    ('sources', ['/etc/shadow']), ('sources', [1]),
    ('password', 'line1\nline2'), ('password', ''), ('password', 'x' * 129), ('password', ' lead'),
    ('password', 'tab\there'), ('password', 12345),
])
def test_hostile_or_malformed_fields_are_refused(field, value):
    _denied(dict(GOOD, **{field: value}))


def test_unknown_actions_extra_fields_and_missing_fields_are_refused():
    _denied({'op': 'wazuh_agent', 'action': 'exec', 'argv': ['id']})
    _denied({'op': 'wazuh_agent'})
    _denied(dict(GOOD, path='/etc/passwd'))
    _denied(dict(GOOD, ossec_conf='<ossec_config/>'))
    _denied({k: v for k, v in GOOD.items() if k != 'sources'})
    _denied({'op': 'wazuh_agent', 'action': 'service', 'verb': 'disable-and-mask'})
    _denied({'op': 'wazuh_agent', 'action': 'service', 'verb': 'start', 'unit': 'sshd'})
    _denied({'op': 'wazuh_agent', 'action': 'verify', 'x': 1})
    _denied({'op': 'wazuh_agent', 'action': 'install', 'file': '/tmp/evil.deb'})
    _denied({'op': 'wazuh_agent', 'action': 'install', 'file': 'wazuh-agent_4.14.11-1_amd64.deb'})
    _denied({'op': 'wazuh_agent', 'action': 'install', 'file': '/x/wazuh-agent_4.14.11-1_amd64.deb', 'upgrade': 'yes'})


@pytest.mark.parametrize('verb', ['start', 'stop', 'restart', 'enable', 'disable'])
def test_service_verbs_are_the_five_and_nothing_else(verb):
    B._check_wazuh_agent({'op': 'wazuh_agent', 'action': 'service', 'verb': verb})


@pytest.mark.skipif(not HAS_OPENSSL, reason='openssl needed')
def test_the_server_certificate_must_be_one_good_certificate(tmp_path):
    pem = _make_cert(tmp_path)
    B._check_wazuh_agent(dict(GOOD, ca_pem=pem))
    _denied(dict(GOOD, ca_pem=pem + pem))                         # two certificates
    _denied(dict(GOOD, ca_pem='-----BEGIN CERTIFICATE-----\nnot base64 !!\n-----END CERTIFICATE-----\n'))
    _denied(dict(GOOD, ca_pem='hello'))
    _denied(dict(GOOD, ca_pem=''))
    _denied(dict(GOOD, ca_pem=pem + 'x' * 20000))                 # over 16 KB
    clean, why = B._wazuh_clean_pem('  \n' + pem + '\n  ')
    assert clean and not why and clean.count('BEGIN') == 1 and clean.endswith('-----END CERTIFICATE-----\n')


def test_an_expired_certificate_is_refused_with_a_plain_reason(monkeypatch):
    pem = ('-----BEGIN CERTIFICATE-----\n' + 'QUJD' * 20 + '\n-----END CERTIFICATE-----\n')
    real = B.subprocess.run

    def fake(argv, *a, **k):
        if 'x509' in argv:
            return types.SimpleNamespace(returncode=1, stdout=b'Certificate will expire\n', stderr=b'')
        return real(argv, *a, **k)
    monkeypatch.setattr(B, 'shutil', types.SimpleNamespace(which=lambda n, path=None: '/usr/bin/' + n))
    monkeypatch.setattr(B.subprocess, 'run', fake)
    clean, why = B._wazuh_clean_pem(pem)
    assert clean is None and 'expired' in why


# ── the op is wired into evaluate and dispatch; the audit line holds no secret ───

def test_evaluate_allows_a_good_request_and_denies_a_bad_one():
    assert B._evaluate({'op': 'wazuh_agent', 'action': 'verify'})[0] == 'ALLOW'
    verdict, why = B._evaluate({'op': 'wazuh_agent', 'action': 'configure', 'server': 'x y'})
    assert verdict == 'DENY' and why


@pytest.mark.skipif(not HAS_OPENSSL, reason='openssl needed')
def test_the_audit_line_never_holds_the_password_or_the_certificate(tmp_path, monkeypatch):
    pem = _make_cert(tmp_path)
    seen = []
    monkeypatch.setattr(B, 'audit', lambda peer, op, summary, verdict, detail='': seen.append((op, summary, verdict, detail)))
    monkeypatch.setattr(B, '_do_wazuh_agent', lambda req: {'ok': True})
    r = B._dispatch(dict(GOOD, password='Sup3rS3cret!', ca_pem=pem), (0, 0, 0))
    assert r == {'ok': True}
    flat = ' | '.join(' '.join(map(str, x)) for x in seen)
    assert 'wazuh_agent' in flat and 'configure' in flat and 'wazuh.example.org' in flat
    assert 'Sup3rS3cret' not in flat and 'BEGIN CERTIFICATE' not in flat and pem[40:80] not in flat


def test_a_denied_request_is_audited_and_never_runs(monkeypatch):
    seen, ran = [], []
    monkeypatch.setattr(B, 'audit', lambda peer, op, summary, verdict, detail='': seen.append((verdict, detail)))
    monkeypatch.setattr(B, '_do_wazuh_agent', lambda req: ran.append(req) or {'ok': True})
    r = B._dispatch({'op': 'wazuh_agent', 'action': 'configure', 'server': 'a"b'}, (0, 0, 0))
    assert r['ok'] is False and r['code'] == 'DENIED' and not ran
    assert seen and seen[0][0] == 'DENY'


# ── the actions, on a scratch tree ───────────────────────────────────────────────

@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A fake /var/ossec and drop-in dir. Root checks and chown are the only things relaxed."""
    home = tmp_path / 'var' / 'ossec'
    (home / 'etc').mkdir(parents=True)
    (home / 'logs').mkdir()
    dropin = tmp_path / 'etc' / 'systemd' / 'system' / 'wazuh-agent.service.d'
    for name, val in (('WAZUH_HOME', str(home)), ('WAZUH_ETC', str(home / 'etc')),
                      ('WAZUH_OSSEC_CONF', str(home / 'etc' / 'ossec.conf')),
                      ('WAZUH_LOCAL_OPTS', str(home / 'etc' / 'local_internal_options.conf')),
                      ('WAZUH_CA_PEM', str(home / 'etc' / 'infratak-server-ca.pem')),
                      ('WAZUH_PASS', str(home / 'etc' / 'authd.pass')),
                      ('WAZUH_KEYS', str(home / 'etc' / 'client.keys')),
                      ('WAZUH_MARK', str(home / 'etc' / '.infratak-managed')),
                      ('WAZUH_LOG', str(home / 'logs' / 'ossec.log')),
                      ('WAZUH_DROPIN_DIR', str(dropin)), ('WAZUH_DROPIN', str(dropin / 'infratak.conf'))):
        monkeypatch.setattr(B, name, val)
    monkeypatch.setattr(B, '_wazuh_root_dir', lambda p: os.path.isdir(p) and not os.path.islink(p))
    monkeypatch.setattr(B, '_wazuh_home_ok', lambda: os.path.isdir(B.WAZUH_ETC) and not os.path.islink(B.WAZUH_ETC))
    monkeypatch.setattr(B.os, 'fchown', lambda *a, **k: None)
    monkeypatch.setattr(B.grp, 'getgrnam', lambda n: types.SimpleNamespace(gr_gid=os.getgid()))
    calls = []
    monkeypatch.setattr(B, '_wazuh_run', lambda argv, timeout=120: (calls.append(list(argv)) or
                                                                     types.SimpleNamespace(returncode=0, stdout='', stderr=''), ''))
    monkeypatch.setattr(B, '_wazuh_family', lambda: 'debian')
    return types.SimpleNamespace(home=home, dropin=dropin, calls=calls, tmp=tmp_path)


@pytest.mark.skipif(not HAS_OPENSSL, reason='openssl needed')
def test_configure_writes_exactly_the_five_files_and_reports_the_lock_down_intact(tree):
    pem = _make_cert(tree.tmp)
    req = dict(GOOD, password='pw-123', ca_pem=pem, sources=['ssh_auth', 'fail2ban'])
    B._check_wazuh_agent(req)
    r = B._do_wazuh_agent(req)
    assert r['ok'] is True and r['problems'] == [] and r['enrolled'] is False
    etc = tree.home / 'etc'
    assert sorted(p.name for p in etc.iterdir()) == sorted(
        ['ossec.conf', 'local_internal_options.conf', 'infratak-server-ca.pem', 'authd.pass', '.infratak-managed'])
    assert oct((etc / 'authd.pass').stat().st_mode & 0o777) == '0o640'
    assert (etc / 'authd.pass').read_text() == 'pw-123\n'
    assert (etc / 'local_internal_options.conf').read_text() == B.WAZUH_LOCAL_OPTS_TEXT
    assert (tree.dropin / 'infratak.conf').read_text() == B.WAZUH_DROPIN_TEXT
    assert 'wazuh.example.org' in (etc / 'ossec.conf').read_text()
    assert ['systemctl', 'daemon-reload'] in tree.calls
    # nothing is started by configure
    assert not [c for c in tree.calls if c[:2] in (['systemctl', 'start'], ['systemctl', 'enable'])]


@pytest.mark.skipif(not HAS_OPENSSL, reason='openssl needed')
def test_configure_again_without_a_password_keeps_the_certificate_and_makes_none(tree):
    B._do_wazuh_agent(dict(GOOD, password='pw', ca_pem=_make_cert(tree.tmp)))
    B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'drop_password'})
    assert not (tree.home / 'etc' / 'authd.pass').exists()
    r = B._do_wazuh_agent(dict(GOOD, sources=['fail2ban']))       # the Update Now / console start re-assert
    assert r['ok'] is True and not (tree.home / 'etc' / 'authd.pass').exists()
    assert '/var/log/fail2ban.log' in (tree.home / 'etc' / 'ossec.conf').read_text()


def test_configure_with_no_certificate_on_file_is_refused(tree):
    r = B._do_wazuh_agent(dict(GOOD))
    assert r['ok'] is False and 'certificate' in r['error']
    assert not (tree.home / 'etc' / 'ossec.conf').exists()


@pytest.mark.skipif(not HAS_OPENSSL, reason='openssl needed')
def test_a_tampered_config_on_disk_makes_verify_report_it_and_blocks_start(tree):
    B._do_wazuh_agent(dict(GOOD, ca_pem=_make_cert(tree.tmp)))
    assert B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'verify'})['problems'] == []
    conf = tree.home / 'etc' / 'ossec.conf'
    conf.write_text(conf.read_text().replace('<active-response>\n    <disabled>yes', '<active-response>\n    <disabled>no'))
    v = B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'verify'})
    assert v['ok'] and v['problems']
    for verb in ('start', 'restart', 'enable'):
        r = B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'service', 'verb': verb})
        assert r['ok'] is False and 'lock-down' in r['error']
    assert not [c for c in tree.calls if c[:2] in (['systemctl', 'start'], ['systemctl', 'restart'], ['systemctl', 'enable'])]
    # stop and disable are always allowed
    assert B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'service', 'verb': 'stop'})['ok']
    assert ['systemctl', 'stop', 'wazuh-agent'] in tree.calls


@pytest.mark.skipif(not HAS_OPENSSL, reason='openssl needed')
def test_start_runs_the_fixed_unit_only_when_the_lock_down_is_intact(tree):
    B._do_wazuh_agent(dict(GOOD, ca_pem=_make_cert(tree.tmp)))
    assert B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'service', 'verb': 'start'})['ok']
    assert ['systemctl', 'start', 'wazuh-agent'] in tree.calls


def test_a_missing_drop_in_or_certificate_file_counts_as_a_problem(tree):
    (tree.home / 'etc' / 'ossec.conf').write_text(_good_render())
    (tree.home / 'etc' / 'local_internal_options.conf').write_text(B.WAZUH_LOCAL_OPTS_TEXT)
    v = B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'verify'})
    assert any('drop-in' in p for p in v['problems']) and any('certificate' in p for p in v['problems'])


def test_verify_says_enrolled_only_when_client_keys_has_content(tree):
    assert B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'verify'})['enrolled'] is False
    (tree.home / 'etc' / 'client.keys').write_text('')
    assert B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'verify'})['enrolled'] is False
    (tree.home / 'etc' / 'client.keys').write_text('001 tak-box-1 any key\n')
    assert B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'verify'})['enrolled'] is True


def test_verify_returns_a_capped_tail_of_the_agent_log(tree):
    (tree.home / 'logs' / 'ossec.log').write_text('\n'.join(f'line {i} ' + 'x' * 200 for i in range(500)))
    v = B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'verify'})
    assert len(v['log']) <= 4096 and 'line 499' in v['log'] and 'line 10 ' not in v['log']


def test_drop_password_removes_the_file_and_is_fine_when_it_is_already_gone(tree):
    p = tree.home / 'etc' / 'authd.pass'
    p.write_text('pw\n')
    assert B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'drop_password'})['ok'] and not p.exists()
    assert B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'drop_password'})['ok']


def test_install_refuses_when_wazuh_files_or_packages_already_exist(tree, monkeypatch):
    monkeypatch.setattr(B, '_wazuh_arch', lambda: 'amd64')
    req = {'op': 'wazuh_agent', 'action': 'install', 'file': '/x/wazuh-agent_4.14.11-1_amd64.deb'}
    r = B._do_wazuh_agent(req)                  # /var/ossec exists in the tree: someone's own agent
    assert r['ok'] is False and 'already exists' in r['error'] and 'leaves it alone' in r['error']
    shutil.rmtree(tree.home)
    ran = []
    monkeypatch.setattr(B, '_wazuh_run', lambda argv, timeout=120: (ran.append(argv) or types.SimpleNamespace(
        returncode=0, stdout='wazuh-agent ii \n', stderr=''), ''))
    r = B._do_wazuh_agent(req)
    assert r['ok'] is False and 'already installed' in r['error'] and not [a for a in ran if a[0] == 'apt-get']


def test_install_refuses_the_file_for_the_wrong_cpu_and_an_upgrade_of_a_foreign_agent(tree, monkeypatch):
    monkeypatch.setattr(B, '_wazuh_arch', lambda: 'arm64')
    r = B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'install', 'file': '/x/wazuh-agent_4.14.11-1_amd64.deb'})
    assert r['ok'] is False and 'arm64.deb' in r['error']
    monkeypatch.setattr(B, '_wazuh_arch', lambda: 'amd64')
    r = B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'install', 'upgrade': True,
                           'file': '/x/wazuh-agent_4.14.11-1_amd64.deb'})
    assert r['ok'] is False and 'not an agent infra-TAK installed' in r['error']


def test_install_runs_the_checked_file_then_stops_and_disables_whatever_the_package_started(tmp_path, monkeypatch):
    monkeypatch.setattr(B, 'WAZUH_HOME', str(tmp_path / 'nothing-here'))
    monkeypatch.setattr(B, '_wazuh_family', lambda: 'debian')
    monkeypatch.setattr(B, '_wazuh_arch', lambda: 'amd64')
    runs, execs = [], []
    monkeypatch.setattr(B, '_wazuh_run', lambda argv, timeout=120: (runs.append(list(argv)) or types.SimpleNamespace(
        returncode=1, stdout='', stderr=''), ''))      # dpkg-query: nothing installed
    monkeypatch.setattr(B, '_do_exec', lambda req: execs.append(req) or {'ok': True, 'returncode': 0, 'stdout_b64': '', 'stderr_b64': ''})
    r = B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'install', 'file': '/x/wazuh-agent_4.14.11-1_amd64.deb'})
    assert r['ok'] is True
    assert execs == [{'op': 'exec', 'argv': ['apt-get', 'install', '-y', '/x/wazuh-agent_4.14.11-1_amd64.deb'],
                      'timeout': 900, 'cwd': '/'}]
    assert ['systemctl', 'stop', 'wazuh-agent'] in runs and ['systemctl', 'disable', 'wazuh-agent'] in runs


def test_uninstall_purges_on_debian_and_removes_var_ossec_and_the_drop_in(tree):
    (tree.dropin).mkdir(parents=True)
    r = B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'uninstall'})
    assert ['apt-get', 'purge', '-y', 'wazuh-agent'] in tree.calls
    assert not tree.home.exists() and not tree.dropin.exists()


def test_uninstall_on_rpm_removes_the_package_the_selinux_module_and_var_ossec(tree, monkeypatch):
    monkeypatch.setattr(B, '_wazuh_family', lambda: 'rhel')
    calls = []

    def run(argv, timeout=120):
        calls.append(list(argv))
        out = 'wazuh    1.0\nother 2\n' if argv[:2] == ['semodule', '-l'] else ''
        rc = 1 if argv[:2] == ['rpm', '-q'] else 0       # rpm -q after remove: not installed
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=''), ''
    monkeypatch.setattr(B, '_wazuh_run', run)
    r = B._do_wazuh_agent({'op': 'wazuh_agent', 'action': 'uninstall'})
    assert ['dnf', 'remove', '-y', 'wazuh-agent'] in calls
    assert ['semodule', '-r', 'wazuh'] in calls
    assert not tree.home.exists() and r['ok'] is True


def test_the_write_helper_refuses_any_path_that_is_not_one_of_ours(tree):
    with pytest.raises(B.Denied):
        B._wazuh_write('/etc/passwd', 'x', 0o644)
    with pytest.raises(B.Denied):
        B._wazuh_write(str(tree.home / 'etc' / 'client.keys'), 'x', 0o644)


def test_the_write_helper_refuses_when_var_ossec_is_not_a_root_owned_directory(tree, monkeypatch):
    monkeypatch.setattr(B, '_wazuh_home_ok', lambda: False)
    with pytest.raises(B.Denied):
        B._wazuh_write(B.WAZUH_OSSEC_CONF, 'x', 0o640)


def test_the_real_root_check_rejects_a_symlinked_var_ossec(tmp_path):
    real = tmp_path / 'real'
    real.mkdir()
    link = tmp_path / 'link'
    link.symlink_to(real)
    assert B._wazuh_root_dir(str(link)) is False
    assert B._wazuh_root_dir(str(tmp_path / 'missing')) is False


def _fake_lstat(table):
    import stat as _st

    def lstat(p):
        mode, uid = table[p]
        return types.SimpleNamespace(st_mode=mode, st_uid=uid)
    return lstat


def test_the_real_package_layout_passes_the_home_check(monkeypatch):
    """ops #1421, read on a real Ubuntu 22.04 box with the 4.14.11 .deb: /var/ossec is
    root:wazuh 750 and /var/ossec/etc is wazuh:wazuh 770. 'etc must be root-owned' refused every install."""
    import stat as st
    monkeypatch.setattr(B.pwd, 'getpwnam', lambda n: types.SimpleNamespace(pw_uid=114))
    t = {B.WAZUH_HOME: (st.S_IFDIR | 0o750, 0), B.WAZUH_ETC: (st.S_IFDIR | 0o770, 114)}
    monkeypatch.setattr(B.os, 'lstat', _fake_lstat(t))
    assert B._wazuh_home_ok() is True
    t[B.WAZUH_ETC] = (st.S_IFDIR | 0o770, 114)
    t[B.WAZUH_HOME] = (st.S_IFDIR | 0o770, 0)            # group-writable /var/ossec: wazuh could swap etc
    assert B._wazuh_home_ok() is False
    t[B.WAZUH_HOME] = (st.S_IFDIR | 0o750, 1000)         # not root's
    assert B._wazuh_home_ok() is False
    t[B.WAZUH_HOME] = (st.S_IFDIR | 0o750, 0)
    t[B.WAZUH_ETC] = (st.S_IFDIR | 0o770, 1000)          # etc owned by someone else
    assert B._wazuh_home_ok() is False
    t[B.WAZUH_ETC] = (st.S_IFLNK | 0o777, 0)             # a link
    assert B._wazuh_home_ok() is False
