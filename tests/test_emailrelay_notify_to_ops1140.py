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
"""Email Relay page: a "Send system notifications to" box (GH #667, ops #1140).

The server sends its own mail (sudo warnings, cron failures, update reports) to root. The
box on the Email Relay page says who reads it. Order, first match wins: the box, Guard
Dog's alert address, the relay From address. An empty box changes nothing.
"""

import pathlib
import re
import subprocess
import sys
import types

import pytest
from flask import Flask

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules  # noqa: E402
import modules.emailrelay as er  # noqa: E402

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
PAGE = (ROOT / 'templates' / 'email_relay.html').read_text(encoding='utf-8')
MAP = '/etc/postfix/virtual_root'
STOCK_MAIN_CF = (
    '# Debian main.cf\nmyhostname = box1.internal\nmyorigin = /etc/mailname\n'
    'mydestination = $myhostname, tak.example.test, localhost\nrelayhost =\n')
RELAY = {'provider': 'brevo', 'from_addr': 'relay-account@brevo.example'}


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


class Box:
    """A fake console: settings in memory, privileged files in a dict."""

    def __init__(self, settings, monkeypatch):
        self.settings = settings
        self.files = {'/etc/postfix/main.cf': STOCK_MAIN_CF}
        self.calls = []
        self.saved = 0
        monkeypatch.setattr(subprocess, 'run', _fake_run(self.calls))
        monkeypatch.setattr(er, 'job_log', lambda *a, **k: None, raising=False)
        monkeypatch.setattr(er, '_read_mailname', lambda: 'tak.example.test', raising=False)

    def save(self, s):
        self.saved += 1
        self.settings = s

    @property
    def ctx(self):
        return {
            'load_settings': lambda: self.settings,
            'save_settings': self.save,
            '_safe_alert_emails': _safe_emails,
            '_sudo_wrap': lambda argv: list(argv),
            '_read_priv': lambda p: self.files.get(p, ''),
            '_write_priv': lambda p, c, mode='w', perm=None: self.files.__setitem__(p, c),
            '_pkg_install': lambda *a, **k: (True, ''),
            '_pkg_remove': lambda *a, **k: (True, ''),
            'wait_for_apt_lock': lambda *a, **k: None,
            'os_type': lambda: 'debian',
            '_configure_authentik_smtp_and_recovery': lambda *a, **k: 'ok',
            '_takportal_push_settings': lambda plog: False,
        }

    def deploy(self):
        job = {'log': []}
        params = {'provider': 'brevo', 'smtp_user': 'u', 'smtp_pass': 'p',
                  'from_addr': 'relay-account@brevo.example', 'from_name': 'TAK',
                  'relay_host': 'smtp-relay.brevo.com', 'relay_port': '587'}
        er.deploy(self.ctx, job, params)
        assert job.get('complete'), job

    def map_targets(self):
        return {ln.split(None, 1)[0]: ln.split(None, 1)[1].strip()
                for ln in self.files[MAP].splitlines() if ln and not ln.startswith('#')}


@pytest.fixture
def box(monkeypatch):
    return Box({'email_relay': dict(RELAY)}, monkeypatch)


@pytest.fixture
def notify_view(box):
    """The real view registered by register(ctx), run inside a Flask request."""
    modules.MODULES.pop('emailrelay', None)
    er.register(box.ctx)
    view = next(r['view'] for r in modules.MODULES['emailrelay']['extra_routes']
                if r['url'] == '/api/emailrelay/notify-to')
    app = Flask(__name__)

    def call(payload):
        with app.test_request_context('/api/emailrelay/notify-to', method='POST', json=payload):
            out = view()
        resp, code = out if isinstance(out, tuple) else (out, 200)
        return code, resp.get_json()
    yield call
    modules.MODULES.pop('emailrelay', None)


# -- where root's mail goes ---------------------------------------------------------

def test_the_box_wins_over_guard_dog_and_the_from_address(box):
    box.settings.update({'system_notify_email': 'ops@desk.example',
                         'guarddog_alert_email': 'gd@real.example'})
    assert er.root_destination(box.ctx, box.settings) == ['ops@desk.example']


def test_empty_box_keeps_the_guard_dog_address(box):
    box.settings['guarddog_alert_email'] = 'gd@real.example'
    assert er.root_destination(box.ctx, box.settings) == ['gd@real.example']
    box.settings['system_notify_email'] = ''
    assert er.root_destination(box.ctx, box.settings) == ['gd@real.example']


def test_empty_box_and_no_guard_dog_keeps_the_from_address(box):
    assert er.root_destination(box.ctx, box.settings) == ['relay-account@brevo.example']


def test_source_says_which_address_is_in_use(box):
    assert er.root_destination_source(box.ctx, box.settings) == 'from'
    box.settings['guarddog_alert_email'] = 'gd@real.example'
    assert er.root_destination_source(box.ctx, box.settings) == 'guarddog'
    box.settings['system_notify_email'] = 'ops@desk.example'
    assert er.root_destination_source(box.ctx, box.settings) == 'notify'


def test_deploy_writes_the_box_address_into_the_root_map(box):
    box.settings.update({'system_notify_email': 'ops@desk.example,two@desk.example',
                         'guarddog_alert_email': 'gd@real.example'})
    box.deploy()
    got = box.map_targets()
    assert got['root@box1.internal'] == 'ops@desk.example, two@desk.example'
    assert 'gd@real.example' not in box.files[MAP]


def test_redeploy_keeps_the_box(box):
    box.settings['system_notify_email'] = 'ops@desk.example'
    box.deploy()
    assert box.settings['system_notify_email'] == 'ops@desk.example'


def test_guard_dog_save_does_not_take_over_from_the_box(box):
    box.settings['system_notify_email'] = 'ops@desk.example'
    box.settings['guarddog_alert_email'] = 'new-gd@real.example'
    ok, _ = er.sync_root_alias(box.ctx, box.settings)
    assert ok
    assert set(box.map_targets().values()) == {'ops@desk.example'}


def test_remove_clears_the_box(box):
    box.settings['system_notify_email'] = 'ops@desk.example'
    er.uninstall(box.ctx, {}, {})
    assert 'system_notify_email' not in box.settings
    assert 'email_relay' not in box.settings


# -- the save route -----------------------------------------------------------------

def test_save_applies_at_once(box, notify_view):
    code, body = notify_view({'notify_to': 'ops@desk.example'})
    assert code == 200 and body['success'] is True, body
    assert box.settings['system_notify_email'] == 'ops@desk.example'
    assert set(box.map_targets().values()) == {'ops@desk.example'}
    assert body['source'] == 'notify' and body['goes_to'] == 'ops@desk.example'


def test_save_takes_several_addresses_in_any_separator(box, notify_view):
    code, body = notify_view({'notify_to': 'a@x.example; b@x.example  c@x.example,a@x.example'})
    assert code == 200, body
    assert box.settings['system_notify_email'] == 'a@x.example,b@x.example,c@x.example'


def test_empty_save_clears_it_and_falls_back(box, notify_view):
    box.settings.update({'system_notify_email': 'ops@desk.example',
                         'guarddog_alert_email': 'gd@real.example'})
    code, body = notify_view({'notify_to': '   '})
    assert code == 200, body
    assert 'system_notify_email' not in box.settings
    assert set(box.map_targets().values()) == {'gd@real.example'}
    assert body['source'] == 'guarddog'


@pytest.mark.parametrize('bad', ['not-an-address', 'ok@x.example, nope', 'a@b', 'x@y.example;rm -rf /',
                                 'a@x.example,b@x.example,c@x.example,d@x.example,e@x.example,f@x.example',
                                 'x' * 1001])
def test_a_bad_address_rejects_the_whole_save(box, notify_view, bad):
    box.settings['system_notify_email'] = 'old@desk.example'
    code, body = notify_view({'notify_to': bad})
    assert code == 400 and body['success'] is False, body
    assert box.settings['system_notify_email'] == 'old@desk.example'
    assert box.saved == 0 and MAP not in box.files


def test_save_needs_a_deployed_relay(box, notify_view):
    box.settings.pop('email_relay')
    code, body = notify_view({'notify_to': 'ops@desk.example'})
    assert code == 400 and 'Deploy the relay' in body['error']
    assert 'system_notify_email' not in box.settings


def test_save_says_so_when_the_server_could_not_apply_it(box, notify_view, monkeypatch):
    monkeypatch.setattr(er, 'sync_root_alias', lambda *a, **k: (False, 'could not build the root alias map'))
    code, body = notify_view({'notify_to': 'ops@desk.example'})
    assert code == 500 and body['success'] is False
    assert 'could not build' in body['error']


def test_the_route_is_registered_behind_the_login_wrapper():
    # app.py wraps every registry view (generic and extra_routes) in login_required
    assert re.search(r"'/api/emailrelay/notify-to'", (ROOT / 'modules' / 'emailrelay.py').read_text())
    assert 'wraps every registry view' in APP


# -- the page -----------------------------------------------------------------------

def test_page_has_the_box_and_posts_to_the_route():
    assert 'Send system notifications to' in PAGE
    assert 'id="notify-to"' in PAGE
    assert "fetch('/api/emailrelay/notify-to'" in PAGE
    # inside the running state, with the other settings cards
    assert PAGE.index('Send system notifications to') > PAGE.index('Current Configuration')
    assert PAGE.index('Send system notifications to') < PAGE.index('Send Test Email')


def test_page_view_passes_the_saved_value_and_the_fallback():
    m = re.search(r"def emailrelay_page\(\):.*?deploy_error=_em_job", APP, re.S)
    assert m
    body = m.group(0)
    for needle in ('notify_to=', 'notify_default=', 'notify_default_is_guarddog='):
        assert needle in body
