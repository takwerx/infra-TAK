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
"""Mail the host sends to root reaches a person (GH #667, ops #1140).

Before: the only thing written for root was a generic-map line keyed on `hostname -f`,
pointing at the relay From address. Mail to root@<mailname> (a different name) went to the
smarthost and bounced, and mail that did match went to a send-only account nobody reads.
Now: a virtual alias for every name Postfix may use, pointing at Guard Dog's alert address
(else the From address), written on every relay deploy.
"""

import pathlib
import re
import subprocess
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.emailrelay as er  # noqa: E402

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
MAP = '/etc/postfix/virtual_root'
STOCK_MAIN_CF = (
    '# Debian main.cf\nmyhostname = box1.internal\nmyorigin = /etc/mailname\n'
    'mydestination = $myhostname, tak.example.test, localhost\nrelayhost =\n')


def _safe_emails(value):
    # same shape as app._safe_alert_emails: valid addresses, de-duplicated, in order
    out = []
    for tok in re.split(r'[,;\s]+', (value or '').strip()):
        if re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', tok) and tok not in out:
            out.append(tok)
    return out


def _fake_run(calls):
    def run(argv, *a, **kw):
        calls.append(list(argv))
        out = ''
        if argv[:2] == ['hostname', '-f']:
            out = 'box1.internal\n'
        elif argv[:3] == ['postconf', '-h', 'myhostname']:
            out = 'box1.internal\n'
        return types.SimpleNamespace(returncode=0, stdout=out, stderr='')
    return run


def _ctx(files, settings):
    return {
        'load_settings': lambda: settings,
        'save_settings': lambda s: None,
        '_safe_alert_emails': _safe_emails,
        '_sudo_wrap': lambda argv: list(argv),
        '_read_priv': lambda p: files.get(p, ''),
        '_write_priv': lambda p, c, mode='w', perm=None: files.__setitem__(p, c),
        '_pkg_install': lambda *a, **k: (True, ''),
        'wait_for_apt_lock': lambda *a, **k: None,
        'os_type': lambda: 'debian',
        '_configure_authentik_smtp_and_recovery': lambda *a, **k: 'ok',
        '_takportal_push_settings': lambda plog: False,
    }


def _stub(monkeypatch, calls):
    monkeypatch.setattr(subprocess, 'run', _fake_run(calls))
    monkeypatch.setattr(er, 'job_log', lambda *a, **k: None, raising=False)
    monkeypatch.setattr(er, '_read_mailname', lambda: 'tak.example.test', raising=False)


def _deploy(monkeypatch, settings, files=None):
    files = {'/etc/postfix/main.cf': STOCK_MAIN_CF} if files is None else files
    calls, job = [], {'log': []}
    _stub(monkeypatch, calls)
    params = {'provider': 'brevo', 'smtp_user': 'u', 'smtp_pass': 'p',
              'from_addr': 'relay-account@brevo.example', 'from_name': 'TAK',
              'relay_host': 'smtp-relay.brevo.com', 'relay_port': '587'}
    er.deploy(_ctx(files, settings), job, params)
    assert job.get('complete'), job
    return files, calls


def _map_lines(files):
    return [ln.split(None, 1) for ln in files[MAP].splitlines() if ln and not ln.startswith('#')]


def test_deploy_routes_root_mail_to_the_guard_dog_address(monkeypatch):
    files, _ = _deploy(monkeypatch, {'guarddog_alert_email': 'ops@real.example'})
    assert MAP in files, 'deploy must write the root alias map'
    got = {k: v.strip() for k, v in _map_lines(files)}
    # the name in /etc/mailname is the one the reporter's mail bounced on
    assert got['root@tak.example.test'] == 'ops@real.example'
    assert got['root@box1.internal'] == 'ops@real.example'
    assert 'relay-account@brevo.example' not in files[MAP]


def test_every_guard_dog_address_gets_the_mail(monkeypatch):
    files, _ = _deploy(monkeypatch, {'guarddog_alert_email': 'a@real.example,b@real.example'})
    assert _map_lines(files)[0][1].strip() == 'a@real.example, b@real.example'


def test_without_a_guard_dog_address_it_keeps_the_old_target(monkeypatch):
    files, _ = _deploy(monkeypatch, {})
    got = {k: v.strip() for k, v in _map_lines(files)}
    assert got['root@tak.example.test'] == 'relay-account@brevo.example'


def test_main_cf_uses_the_map_and_keeps_the_send_only_design(monkeypatch):
    files, _ = _deploy(monkeypatch, {'guarddog_alert_email': 'ops@real.example'})
    cf = files['/etc/postfix/main.cf']
    assert re.search(r'(?m)^virtual_alias_maps\s*=.*hash:/etc/postfix/virtual_root', cf)
    # GH #48: the FQDN must NOT become a local destination
    assert re.search(r'(?m)^mydestination = \$myhostname, localhost\.localdomain, localhost$', cf)
    assert 'tak.example.test' not in re.findall(r'(?m)^mydestination.*$', cf)[-1]


def test_sender_rewrite_covers_every_host_name(monkeypatch):
    files, _ = _deploy(monkeypatch, {'guarddog_alert_email': 'ops@real.example'})
    gen = files['/etc/postfix/generic']
    assert 'root@box1.internal    relay-account@brevo.example' in gen
    assert 'root@tak.example.test    relay-account@brevo.example' in gen


def test_map_is_built_before_main_cf_names_it(monkeypatch):
    order = []
    files = {'/etc/postfix/main.cf': STOCK_MAIN_CF}
    ctx = _ctx(files, {'guarddog_alert_email': 'ops@real.example'})
    ctx['_write_priv'] = lambda p, c, mode='w', perm=None: (order.append(p), files.__setitem__(p, c))
    _stub(monkeypatch, [])
    ok, _ = er.sync_root_alias(ctx, {'guarddog_alert_email': 'ops@real.example'}, reload=False)
    assert ok
    assert order.index(MAP) < order.index('/etc/postfix/main.cf')


def test_sync_is_repeatable_and_keeps_an_operators_own_maps(monkeypatch):
    own = STOCK_MAIN_CF + 'virtual_alias_maps = hash:/etc/postfix/mine\n'
    files = {'/etc/postfix/main.cf': own}
    ctx = _ctx(files, {})
    _stub(monkeypatch, [])
    s = {'guarddog_alert_email': 'ops@real.example'}
    assert er.sync_root_alias(ctx, s, reload=False)[0]
    first = files['/etc/postfix/main.cf']
    assert 'hash:/etc/postfix/mine hash:/etc/postfix/virtual_root' in first
    assert er.sync_root_alias(ctx, s, reload=False)[0]
    assert files['/etc/postfix/main.cf'] == first, 'second run must change nothing'


def test_new_guard_dog_address_replaces_the_old_one_in_the_map(monkeypatch):
    files = {'/etc/postfix/main.cf': STOCK_MAIN_CF}
    ctx = _ctx(files, {})
    _stub(monkeypatch, [])
    er.sync_root_alias(ctx, {'guarddog_alert_email': 'old@real.example'}, reload=False)
    er.sync_root_alias(ctx, {'guarddog_alert_email': 'new@real.example'}, reload=False)
    assert 'new@real.example' in files[MAP] and 'old@real.example' not in files[MAP]


def test_a_bad_address_never_reaches_the_map(monkeypatch):
    bad = 'x@y.example $(id)@y.example "a;b"@z.example\nevil.example inject@@x'
    files, _ = _deploy(monkeypatch, {'guarddog_alert_email': bad})
    lines = [ln for ln in files[MAP].splitlines() if ln and not ln.startswith('#')]
    assert lines, 'the one valid address must still be used'
    for ln in lines:
        assert re.fullmatch(r'root@[a-z0-9.-]+ {4}x@y\.example', ln), ln


def test_sync_never_raises(monkeypatch):
    _stub(monkeypatch, [])
    ctx = _ctx({}, {})
    ctx['_write_priv'] = lambda *a, **k: (_ for _ in ()).throw(PermissionError('denied'))
    ok, msg = er.sync_root_alias(ctx, {})
    assert ok is False and 'denied' in msg


def test_guard_dog_saves_and_post_update_keep_the_map_current():
    # the three places guarddog_alert_email is saved, and the post-update catch-up
    assert APP.count('_emailrelay_sync_root_alias(settings)') >= 3
    assert re.search(r"'_safe_alert_emails': _safe_alert_emails", APP)
    assert re.search(r'(?m)^            _emailrelay_sync_root_alias\(\)$', APP)
