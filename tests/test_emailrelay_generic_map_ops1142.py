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
"""ops #1142 (infra-TAK GH #665) — the sender map is keyed on the name Postfix stamps.

Postfix stamps local mail from root with its origin: /etc/mailname (the saved FQDN) on
Debian/Ubuntu. The email relay used to key /etc/postfix/generic on a bare `hostname -f`,
so on a host where that differs from the saved FQDN the key never matched and the sender
was never rewritten, with no message. deploy() runs here for real, against a fake ctx and
a fake subprocess, and the file it hands to the privileged writer is what is checked.
"""

import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.emailrelay as er  # noqa: E402

FQDN = 'tak.example.org'
SHORT = 'vps-1234'
FROM = 'noreply@example.org'


# ── the pure helper ─────────────────────────────────────────────────────────

def test_map_holds_one_line_per_distinct_name_saved_fqdn_first():
    text, names = er._generic_map_text(FROM, FQDN, SHORT)
    assert text == f'root@{FQDN}    {FROM}\nroot@{SHORT}    {FROM}\n'
    assert names == sorted([FQDN, SHORT])


def test_same_name_twice_or_blank_or_zero_gives_one_line():
    text, names = er._generic_map_text(FROM, FQDN, '', None, FQDN.upper(), '0', FQDN)
    assert text == f'root@{FQDN}    {FROM}\n'
    assert names == [FQDN]


def _safe_emails(value):
    return [t for t in (value or '').replace(',', ' ').split() if '@' in t]


# ── deploy() end to end against fakes ───────────────────────────────────────

class _Run:
    def __init__(self, hostname_f=SHORT, postconf=None):
        self.hostname_f = hostname_f
        self.postconf = postconf or {}
        self.calls = []

    def __call__(self, cmd, *a, **kw):
        self.calls.append(list(cmd))
        out = ''
        if list(cmd) == ['hostname', '-f']:
            out = self.hostname_f + '\n'
        elif list(cmd) == ['hostname']:
            out = self.hostname_f.split('.')[0] + '\n'
        elif list(cmd)[:2] == ['postconf', '-hx']:
            out = self.postconf.get(cmd[2], '') + '\n'
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr='')


def _deploy(monkeypatch, tmp_path, *, os_type, saved_fqdn, hostname_f, postconf=None,
            files=None):
    runner = _Run(hostname_f, postconf)
    monkeypatch.setattr(er.subprocess, 'run', runner)
    monkeypatch.setenv('HOME', str(tmp_path))  # no ~/authentik, so no Authentik step
    # raising=False: the deploy-level tests must reach their assertions on the base branch
    # too (where this helper does not exist), so they fail for the right reason.
    monkeypatch.setattr(er, '_read_name_file', lambda path: (files or {}).get(path, ''),
                        raising=False)
    written = {}
    ctx = {
        'load_settings': lambda: {'fqdn': saved_fqdn} if saved_fqdn else {},
        'save_settings': lambda s: None,
        'os_type': lambda: os_type,
        'wait_for_apt_lock': lambda plog, log: None,
        '_pkg_install': lambda pkgs, log_fn=None, timeout=0: (True, ''),
        '_sudo_wrap': lambda c: list(c),
        '_read_priv': lambda p: '',
        '_write_priv': lambda p, text, perm=None: written.__setitem__(p, text),
        '_safe_alert_emails': _safe_emails,
        '_takportal_push_settings': lambda plog: False,
    }
    job = {'log': [], 'running': True}
    params = {'provider': 'custom', 'smtp_user': 'u', 'smtp_pass': 'p', 'from_addr': FROM,
              'from_name': 'TAK', 'relay_host': 'smtp.example.org', 'relay_port': '587'}
    er.deploy(ctx, job, params)
    assert job.get('complete') is True, job
    return written['/etc/postfix/generic'], runner


@pytest.mark.parametrize('os_type', ['debian', 'rhel'])
def test_generic_map_is_keyed_on_the_saved_fqdn_when_hostname_f_differs(
        monkeypatch, tmp_path, os_type):
    """The proof test: red on the base branch (only root@<hostname -f>), green with the fix."""
    text, _ = _deploy(monkeypatch, tmp_path, os_type=os_type,
                      saved_fqdn=FQDN, hostname_f=SHORT)
    keys = [ln.split()[0] for ln in text.splitlines()]
    assert f'root@{FQDN}' in keys, text          # what Postfix stamps (/etc/mailname)
    assert f'root@{SHORT}' in keys, text         # and what `hostname -f` says today
    assert all(ln.split()[1] == FROM for ln in text.splitlines())


def test_what_postfix_says_it_stamps_is_keyed_too_debian_mailname(monkeypatch, tmp_path):
    """myorigin = /etc/mailname, and an OS upgrade or earlier install left it on a third name."""
    text, _ = _deploy(monkeypatch, tmp_path, os_type='debian', saved_fqdn=FQDN,
                      hostname_f=SHORT,
                      postconf={'myorigin': '/etc/mailname', 'myhostname': SHORT},
                      files={'/etc/mailname': 'old.example.org'})
    keys = [ln.split()[0] for ln in text.splitlines()]
    assert keys == [f'root@{FQDN}', 'root@old.example.org', f'root@{SHORT}']


def test_rocky_myhostname_with_localdomain_is_keyed(monkeypatch, tmp_path):
    """nuc (Rocky 9): hostname -f is `infratak`, but Postfix stamps `infratak.localdomain`
    (myorigin = $myhostname), so a key from hostname -f alone never matched there either."""
    text, _ = _deploy(monkeypatch, tmp_path, os_type='rhel', saved_fqdn='nuc.example.org',
                      hostname_f='infratak',
                      postconf={'myorigin': 'infratak.localdomain',
                                'myhostname': 'infratak.localdomain'})
    keys = [ln.split()[0] for ln in text.splitlines()]
    assert keys == ['root@nuc.example.org', 'root@infratak.localdomain', 'root@infratak']


def test_a_failing_postconf_still_writes_the_saved_fqdn_and_hostname(monkeypatch, tmp_path):
    text, _ = _deploy(monkeypatch, tmp_path, os_type='debian', saved_fqdn=FQDN,
                      hostname_f=SHORT, postconf={})
    keys = [ln.split()[0] for ln in text.splitlines()]
    assert keys == [f'root@{FQDN}', f'root@{SHORT}']


def test_matching_names_still_give_a_single_line(monkeypatch, tmp_path):
    text, _ = _deploy(monkeypatch, tmp_path, os_type='debian', saved_fqdn=FQDN,
                      hostname_f=FQDN,
                      postconf={'myorigin': '/etc/mailname', 'myhostname': FQDN},
                      files={'/etc/mailname': FQDN})
    assert text == f'root@{FQDN}    {FROM}\n'


def test_no_saved_fqdn_falls_back_to_hostname_f(monkeypatch, tmp_path):
    text, _ = _deploy(monkeypatch, tmp_path, os_type='rhel', saved_fqdn='', hostname_f=SHORT)
    assert text == f'root@{SHORT}    {FROM}\n'


def test_a_disagreement_is_said_in_the_deploy_log(monkeypatch, tmp_path):
    logged = []
    monkeypatch.setattr(er, '_plog', lambda m: logged.append(m))
    _deploy(monkeypatch, tmp_path, os_type='rhel', saved_fqdn=FQDN, hostname_f=SHORT)
    assert any('disagree' in m and FQDN in m and SHORT in m for m in logged), logged


# ── one name list for both maps (lead's merge of #672 and #673, GH #665 + #667) ──────────

def _three_name_host(monkeypatch, tmp_path, settings_extra=None):
    """The reporter's host: `hostname -f` is the short name, myhostname is a .lan name from
    DHCP and /etc/mailname holds the saved FQDN. Every write of either map is recorded."""
    runner = _Run('tak-host', {'myorigin': '/etc/mailname', 'myhostname': 'tak-host.lan'})
    monkeypatch.setattr(er.subprocess, 'run', runner)
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setattr(er, '_read_name_file',
                        lambda path: FQDN if path == '/etc/mailname' else '', raising=False)
    writes = []
    settings = {'fqdn': FQDN, 'guarddog_alert_email': 'ops@real.example'}
    settings.update(settings_extra or {})
    ctx = {
        'load_settings': lambda: settings,
        'save_settings': lambda s: None,
        'os_type': lambda: 'debian',
        'wait_for_apt_lock': lambda plog, log: None,
        '_pkg_install': lambda pkgs, log_fn=None, timeout=0: (True, ''),
        '_sudo_wrap': lambda c: list(c),
        '_read_priv': lambda p: 'myhostname = tak-host.lan\nrelayhost =\n',
        '_write_priv': lambda p, text, perm=None, **k: writes.append((p, text)),
        '_safe_alert_emails': _safe_emails,
        '_takportal_push_settings': lambda plog: False,
    }
    return ctx, writes, settings


def _keys(text):
    return [ln.split()[0] for ln in text.splitlines() if ln and not ln.startswith('#')]


THREE = [f'root@{FQDN}', 'root@tak-host.lan', 'root@tak-host']


def test_deploy_gives_both_maps_all_three_names_in_every_write(monkeypatch, tmp_path):
    """The reporter's case. Whichever write comes last, it must hold all three names, in the
    sender map and in the root recipient map."""
    ctx, writes, _ = _three_name_host(monkeypatch, tmp_path)
    job = {'log': [], 'running': True}
    er.deploy(ctx, job, {'provider': 'custom', 'smtp_user': 'u', 'smtp_pass': 'p',
                         'from_addr': FROM, 'from_name': 'TAK',
                         'relay_host': 'smtp.example.org', 'relay_port': '587'})
    assert job.get('complete') is True, job
    generic = [t for p, t in writes if p == '/etc/postfix/generic']
    alias = [t for p, t in writes if p == er.ROOT_ALIAS_MAP]
    assert generic and alias, writes
    for text in generic + alias:
        assert sorted(_keys(text)) == sorted(THREE), text
    assert all(ln.split()[1] == FROM for ln in generic[-1].splitlines())
    assert all(ln.split(None, 1)[1].strip() == 'ops@real.example'
               for ln in alias[-1].splitlines() if ln and not ln.startswith('#'))


def test_a_guard_dog_save_without_a_deploy_also_covers_all_three(monkeypatch, tmp_path):
    """app.py calls sync_root_alias(ctx, settings) alone after a Guard Dog address save and
    after an update: it must find the same three names without the deploy's help."""
    ctx, writes, settings = _three_name_host(
        monkeypatch, tmp_path, {'email_relay': {'from_addr': FROM}})
    ok, _ = er.sync_root_alias(ctx, settings, reload=False)
    assert ok
    generic = [t for p, t in writes if p == '/etc/postfix/generic'][-1]
    alias = [t for p, t in writes if p == er.ROOT_ALIAS_MAP][-1]
    assert sorted(_keys(generic)) == sorted(THREE)
    assert sorted(_keys(alias)) == sorted(THREE)


def test_a_name_that_is_not_a_host_name_never_reaches_a_map(monkeypatch, tmp_path):
    """Names go into Postfix tables: a stray character or a space must be dropped."""
    runner = _Run('tak-host', {'myorigin': 'bad name;x', 'myhostname': 'tak-host.lan'})
    monkeypatch.setattr(er.subprocess, 'run', runner)
    names = er.postfix_local_names({'fqdn': FQDN})
    assert names == [FQDN, 'tak-host.lan', 'tak-host']


def test_a_literal_myorigin_reaches_both_maps_after_the_last_write(monkeypatch, tmp_path):
    """The reporter's merge warning: with two writers, the one that runs last wins. A
    myorigin set to a plain domain (not /etc/mailname) must still be in both maps once
    sync_root_alias has run after the deploy's own write."""
    runner = _Run('tak-host', {'myorigin': 'lit.example.org', 'myhostname': 'tak-host.lan'})
    monkeypatch.setattr(er.subprocess, 'run', runner)
    monkeypatch.setattr(er, '_read_name_file', lambda path: '', raising=False)
    writes = []
    ctx = {'_safe_alert_emails': _safe_emails, '_sudo_wrap': lambda c: list(c),
           '_read_priv': lambda p: 'relayhost =\n',
           '_write_priv': lambda p, text, perm=None, **k: writes.append((p, text))}
    ok, _ = er.sync_root_alias(
        ctx, {'fqdn': FQDN, 'guarddog_alert_email': 'ops@real.example'},
        from_addr=FROM, reload=False)
    assert ok
    for path in ('/etc/postfix/generic', er.ROOT_ALIAS_MAP):
        text = [t for p, t in writes if p == path][-1]
        assert 'root@lit.example.org' in _keys(text), (path, text)
        assert f'root@{FQDN}' in _keys(text) and 'root@tak-host.lan' in _keys(text)
