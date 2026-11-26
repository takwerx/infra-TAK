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
"""ops #1200 (infra-TAK GH #703) — the Custom provider can send with no SMTP login.

A company's own mail relay, or Microsoft 365 Direct Send, accepts this server by its IP
address and needs no username or password. The Email Relay used to demand both for every
provider. These tests run deploy() for real against a fake ctx and a fake subprocess, and
check the files it hands to the privileged writer, the commands it runs and what it saves.
"""

import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.emailrelay as er  # noqa: E402

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
FROM = 'noreply@example.org'
SASL = '/etc/postfix/sasl_passwd'


def _req(**kw):
    d = {'provider': 'custom', 'custom_host': 'relay.example.org', 'custom_port': '25',
         'from_addr': FROM, 'from_name': 'TAK'}
    d.update(kw)
    return d


# ── request validation ──────────────────────────────────────────────────────

def test_custom_with_login_off_needs_no_username_or_password():
    """The proof test: red on the base branch ('SMTP username, password ... required')."""
    params, err = er.deploy_validate(_req(smtp_auth=False))
    assert err is None, err
    assert params['smtp_auth'] is False
    assert params['smtp_user'] == '' and params['smtp_pass'] == ''
    assert params['relay_host'] == 'relay.example.org' and params['relay_port'] == '25'


def test_login_off_still_needs_a_from_address():
    _, err = er.deploy_validate(_req(smtp_auth=False, from_addr=''))
    assert err and 'From address' in err


def test_typed_credentials_are_dropped_when_the_login_is_off():
    params, _ = er.deploy_validate(_req(smtp_auth=False, smtp_user='u', smtp_pass='p'))
    assert params['smtp_user'] == '' and params['smtp_pass'] == ''


@pytest.mark.parametrize('off', [False, 'false', 'no', 0, '0'])
def test_the_form_value_for_off_is_understood(off):
    params, err = er.deploy_validate(_req(smtp_auth=off))
    assert err is None and params['smtp_auth'] is False


def test_custom_with_login_still_needs_both():
    for extra in ({}, {'smtp_user': 'u'}, {'smtp_pass': 'p'}):
        _, err = er.deploy_validate(_req(**extra))
        assert err and 'required' in err, extra
    params, err = er.deploy_validate(_req(smtp_user='u', smtp_pass='p'))
    assert err is None and params['smtp_auth'] is True


@pytest.mark.parametrize('provider', ['brevo', 'smtp2go', 'mailgun'])
def test_hosted_providers_can_never_skip_the_login(provider):
    """A hand-made request must not turn the login off for a provider that needs it."""
    _, err = er.deploy_validate({'provider': provider, 'smtp_auth': False, 'from_addr': FROM})
    assert err and 'required' in err
    params, err = er.deploy_validate({'provider': provider, 'smtp_auth': False,
                                      'smtp_user': 'u', 'smtp_pass': 'p', 'from_addr': FROM})
    assert err is None and params['smtp_auth'] is True and params['smtp_tls'] == 'may'


@pytest.mark.parametrize('tls', ['may', 'encrypt', 'none'])
def test_tls_mode_is_its_own_choice_for_custom(tls):
    params, err = er.deploy_validate(_req(smtp_auth=False, smtp_tls=tls))
    assert err is None and params['smtp_tls'] == tls
    params, err = er.deploy_validate(_req(smtp_user='u', smtp_pass='p', smtp_tls=tls))
    assert err is None and params['smtp_tls'] == tls


def test_unknown_tls_mode_is_refused_and_default_is_opportunistic():
    _, err = er.deploy_validate(_req(smtp_auth=False, smtp_tls='verify;rm'))
    assert err and 'TLS' in err
    params, _ = er.deploy_validate(_req(smtp_auth=False))
    assert params['smtp_tls'] == 'may'


@pytest.mark.parametrize('host,port', [('a b', '25'), ('a\nmynetworks = 0.0.0.0/0', '25'),
                                       ('relay.example.org', '25 26'), ('relay.example.org', 'x')])
def test_host_and_port_cannot_carry_a_second_main_cf_line(host, port):
    _, err = er.deploy_validate(_req(smtp_auth=False, custom_host=host, custom_port=port))
    assert err and 'not valid' in err


# ── the main.cf block ───────────────────────────────────────────────────────

def test_no_login_block_turns_sasl_off_and_names_no_credential_map():
    cf = er.render_main_cf_block('relay.example.org', '25', smtp_auth=False)
    assert 'smtp_sasl_auth_enable = no' in cf
    assert 'sasl_passwd' not in cf and 'smtp_sasl_password_maps' not in cf
    assert 'smtp_sasl_security_options' not in cf
    assert 'relayhost = [relay.example.org]:25' in cf


def test_login_block_is_what_it_always_was():
    cf = er.render_main_cf_block('smtp.example.org', '587')
    for line in ('smtp_sasl_auth_enable = yes',
                 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd',
                 'smtp_sasl_security_options = noanonymous',
                 'smtp_tls_security_level = may', 'smtp_use_tls = yes',
                 'header_size_limit = 4096000', 'smtp_generic_maps = hash:/etc/postfix/generic'):
        assert line in cf.splitlines(), line


@pytest.mark.parametrize('auth', [True, False])
def test_tls_does_not_depend_on_the_login(auth):
    assert 'smtp_tls_security_level = encrypt' in er.render_main_cf_block('h', '25', auth, 'encrypt')
    off = er.render_main_cf_block('h', '25', auth, 'none')
    assert 'smtp_tls_security_level = none' in off and 'smtp_use_tls' not in off


@pytest.mark.parametrize('auth', [True, False])
def test_local_access_restriction_is_the_same_with_or_without_a_login(auth):
    """Nobody else on the network may use the relay: mynetworks stays local plus Docker."""
    cf = er.render_main_cf_block('h', '25', auth)
    assert 'mynetworks = 127.0.0.0/8 [::1]/128 172.16.0.0/12' in cf.splitlines()
    assert 'mydestination = $myhostname, localhost.localdomain, localhost' in cf.splitlines()


# ── deploy() end to end against fakes ───────────────────────────────────────

class _Run:
    def __init__(self):
        self.calls = []

    def __call__(self, cmd, *a, **kw):
        self.calls.append(list(cmd))
        out = 'tak-host\n' if list(cmd)[:1] == ['hostname'] else ''
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr='')


def _deploy(monkeypatch, tmp_path, params, existing_cf='', os_type='debian'):
    runner = _Run()
    monkeypatch.setattr(er.subprocess, 'run', runner)
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setattr(er, '_read_name_file', lambda p: '', raising=False)
    writes, saved = [], []
    disk = {'/etc/postfix/main.cf': existing_cf}      # what the privileged reader sees
    settings = {'fqdn': 'tak.example.org'}
    ctx = {
        'load_settings': lambda: settings,
        'save_settings': lambda s: saved.append(dict(s)),
        'os_type': lambda: os_type,
        'wait_for_apt_lock': lambda plog, log: None,
        '_pkg_install': lambda pkgs, log_fn=None, timeout=0: (True, ''),
        '_sudo_wrap': lambda c: list(c),
        '_read_priv': lambda p: disk.get(p, ''),
        '_write_priv': lambda p, text, perm=None, **k: (writes.append((p, text)),
                                                       disk.__setitem__(p, text)),
        '_safe_alert_emails': lambda v: [t for t in (v or '').replace(',', ' ').split() if '@' in t],
        '_takportal_push_settings': lambda plog: False,
    }
    job = {'log': [], 'running': True}
    er.deploy(ctx, job, params)
    assert job.get('complete') is True, job
    return disk, saved, runner


def _params(**kw):
    p, err = er.deploy_validate(_req(**kw))
    assert err is None, err
    return p


@pytest.mark.parametrize('os_type', ['debian', 'rhel'])
def test_no_login_deploy_writes_no_credentials_and_configures_postfix_without_sasl(
        monkeypatch, tmp_path, os_type):
    writes, saved, runner = _deploy(monkeypatch, tmp_path, _params(smtp_auth=False),
                                    os_type=os_type)
    files = dict(writes)
    main_cf = files['/etc/postfix/main.cf']
    assert 'smtp_sasl_auth_enable = no' in main_cf
    assert 'smtp_sasl_password_maps' not in main_cf
    assert SASL not in files                                   # no credential file made
    assert ['postmap', SASL] not in runner.calls               # nothing hashed
    assert not any(c[:1] == ['chmod'] and SASL in c for c in runner.calls)
    assert ['systemctl', 'restart', 'postfix'] in runner.calls  # still applied
    relay = saved[-1]['email_relay']
    assert relay['smtp_auth'] is False and relay['smtp_user'] == '' and relay['smtp_pass'] == ''
    assert relay['relay_host'] == 'relay.example.org' and relay['relay_port'] == '25'


def test_no_login_deploy_removes_old_credentials_from_an_earlier_provider(monkeypatch, tmp_path):
    previous = ('myhostname = tak.example.org\n\n'
                '# TAKWERX Email Relay — managed by TAK-infra\n'
                'relayhost = [smtp-relay.brevo.com]:587\n'
                'smtp_sasl_auth_enable = yes\n'
                'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd\n')
    writes, _, runner = _deploy(monkeypatch, tmp_path, _params(smtp_auth=False),
                                existing_cf=previous)
    assert ['rm', '-f', SASL, SASL + '.db'] in runner.calls
    main_cf = dict(writes)['/etc/postfix/main.cf']
    assert 'smtp_sasl_password_maps' not in main_cf and 'smtp_sasl_auth_enable = yes' not in main_cf
    assert main_cf.count('relayhost =') == 1 and 'brevo' not in main_cf
    assert 'myhostname = tak.example.org' in main_cf          # the rest of main.cf is kept


def test_login_deploy_is_unchanged_credentials_hashed_and_saved(monkeypatch, tmp_path):
    """Existing authenticated providers keep working exactly as before."""
    writes, saved, runner = _deploy(
        monkeypatch, tmp_path, _params(smtp_user='user', smtp_pass='secret'))
    files = dict(writes)
    assert files[SASL] == '[relay.example.org]:25    user:secret\n'
    assert ['postmap', SASL] in runner.calls
    assert ['chmod', '600', SASL, SASL + '.db'] in runner.calls
    assert not any(c[:2] == ['rm', '-f'] and SASL in c for c in runner.calls)
    main_cf = files['/etc/postfix/main.cf']
    assert 'smtp_sasl_auth_enable = yes' in main_cf
    assert 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd' in main_cf
    relay = saved[-1]['email_relay']
    assert relay['smtp_user'] == 'user' and relay['smtp_pass'] == 'secret'
    assert 'smtp_auth' not in relay and 'smtp_tls' not in relay   # same settings as before


def test_a_later_login_deploy_drops_the_no_login_flag(monkeypatch, tmp_path):
    """Switching from a no-login relay back to a login: the saved flag does not stay."""
    _, saved, _ = _deploy(monkeypatch, tmp_path, _params(smtp_user='u', smtp_pass='p'))
    assert saved[-1]['email_relay'].get('smtp_auth') is not False


def test_tls_choice_is_saved_and_applied(monkeypatch, tmp_path):
    writes, saved, _ = _deploy(monkeypatch, tmp_path, _params(smtp_auth=False, smtp_tls='encrypt'))
    assert 'smtp_tls_security_level = encrypt' in dict(writes)['/etc/postfix/main.cf']
    assert saved[-1]['email_relay']['smtp_tls'] == 'encrypt'


# ── "is the relay set up?" must accept a relay with no login ─────────────────

CASES = [({'relay_host': 'h', 'smtp_user': 'u'}, True),
         ({'relay_host': 'h', 'smtp_user': '', 'smtp_auth': False}, True),
         ({'relay_host': 'h', 'smtp_user': ''}, False),
         ({'relay_host': '', 'smtp_user': 'u'}, False),
         ({'relay_host': '', 'smtp_auth': False}, False),
         ({}, False), (None, False)]


@pytest.mark.parametrize('relay,expected', CASES)
def test_relay_configured(relay, expected):
    assert er.relay_configured(relay) is expected


def test_every_configured_test_in_app_py_agrees_with_relay_configured():
    """app.py cannot import the module in the places its tests cut functions out, so the test
    is written inline. Every inline copy must be the one expression, and no copy of the old
    `relay_host and smtp_user` test may remain (it called a no-login relay "not set up",
    so Guard Dog mail, the portal push and the health check all skipped it)."""
    assert not re.search(r"relay_host'\)\s*and\s*\w+\.get\('smtp_user'\)\)?\s*[:)\n]", APP)
    hits = re.findall(r"(\w+)\.get\('relay_host'\) and \((\w+)\.get\('smtp_user'\) or "
                      r"(\w+)\.get\('smtp_auth'\) is False\)", APP)
    assert len(hits) >= 8, hits
    assert all(a == b == c for a, b, c in hits), hits


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


@pytest.mark.parametrize('relay,expected', CASES[:5])
def test_email_relay_ready_in_app_py(relay, expected):
    ns = {'load_settings': lambda: {'email_relay': relay}}
    exec(_cut('_email_relay_ready'), ns)
    assert ns['_email_relay_ready']() is expected


def test_portal_email_settings_for_a_no_login_relay_send_no_credentials():
    ns = {}
    exec(_cut('_portal_email_settings'), ns)
    got = ns['_portal_email_settings']({'email_relay': {
        'relay_host': 'relay.example.org', 'relay_port': '25', 'smtp_user': '', 'smtp_pass': '',
        'smtp_auth': False, 'from_addr': FROM, 'from_name': 'TAK'}})
    assert got['EMAIL_ENABLED'] == 'true'
    assert got['SMTP_HOST'] == 'relay.example.org' and got['SMTP_PORT'] == '25'
    assert got['SMTP_USER'] == '' and got['SMTP_PASS'] == ''


# ── the page ────────────────────────────────────────────────────────────────

def test_page_only_offers_the_login_switch_for_the_custom_provider():
    html = (ROOT / 'templates' / 'email_relay.html').read_text(encoding='utf-8')
    for prefix in ('deploy', 'swap'):
        for el in (f'{prefix}-smtp_auth', f'{prefix}-smtp_tls', f'{prefix}-auth-fields',
                   f'{prefix}-user-group', f'{prefix}-pass-group'):
            assert f'id="{el}"' in html, el
    assert "(key==='custom') ? 'block' : 'none'" in html
    assert 'body.smtp_auth=auth' in html
