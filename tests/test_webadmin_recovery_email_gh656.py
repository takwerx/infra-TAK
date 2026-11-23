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
"""webadmin recovery email (infra-TAK #656, ops #1121).

webadmin is born with a made-up address (webadmin@<fqdn>), akadmin with admin@takwerx.local.
"Forgot password?" mails the reset link there, so nobody can recover the account. The console
shows a banner and Guard Dog mails a reminder until Authentik shows a real address.

The tests run the real functions from app.py against a fake Authentik read.
"""

import ast
import json
import pathlib
import re
import threading
import time
import types

import pytest
from flask import Flask, jsonify, request

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
FUNCS = {n.name: n for n in TREE.body if isinstance(n, ast.FunctionDef)}
ASSIGNS = {}
for _n in TREE.body:
    if isinstance(_n, ast.Assign) and len(_n.targets) == 1 and isinstance(_n.targets[0], ast.Name):
        ASSIGNS[_n.targets[0].id] = _n

FQDN = 'tak.example.org'


def _src(node):
    return ast.get_source_segment(APP, node)


class World:
    """Fake Authentik users + a settings dict, shared by every stub."""

    def __init__(self, webadmin_email=f'webadmin@{FQDN}', akadmin_email='admin@takwerx.local', settings=None):
        self.users = {'webadmin': {'pk': 7, 'username': 'webadmin', 'email': webadmin_email},
                      'akadmin': {'pk': 8, 'username': 'akadmin', 'email': akadmin_email}}
        self.settings = {'fqdn': FQDN, 'guarddog_alert_email': 'ops@example.org'}
        self.settings.update(settings or {})
        self.sent = []
        self.patches = []
        self.audits = []

    def ak_get(self, ak_url, path, headers):
        m = re.search(r'username=(\w+)', path)
        u = self.users.get(m.group(1)) if m else None
        return {'results': [dict(u)] if u else []}

    def ak_call(self, url, headers=None, data=None, method='GET', **kw):
        pk = int(re.search(r'/users/(\d+)/', url).group(1))
        body = json.loads(data.decode())
        self.patches.append((pk, method, body))
        for u in self.users.values():
            if u['pk'] == pk:
                u.update(body)

    def save(self, s):
        self.settings = dict(s)

    def send(self, to_addr, subject, body, force=False):
        self.sent.append((to_addr, subject, body))
        return True


@pytest.fixture
def mod(monkeypatch):
    """Namespace with the real #656 functions and constants, wired to a World."""
    world = World()
    flask_app = Flask(__name__)
    g = {
        'json': json, 'time': time, 're': re, 'threading': threading, 'os': __import__('os'),
        'request': request, 'jsonify': jsonify,
        'login_required': lambda f: f,
        'AK_ACTION_NEEDED': 'Action needed:',
    }

    def wire():
        g.update({
            'load_settings': lambda: dict(world.settings),
            'save_settings': world.save,
            '_w1_ak_ctx': lambda: ('http://ak.test', {'Authorization': 'x'}, dict(world.settings)),
            '_w1_ak_get': world.ak_get,
            '_ak_api_call': world.ak_call,
            '_get_authentik_base_url': lambda s: 'https://auth.example.org',
            '_guarddog_send_alert_email_via_relay': world.send,
            'audit': lambda ev, detail='', force=False: world.audits.append((ev, detail)),
        })
    wire()
    for name in ('_AUTHENTIK_RECOVERABLE_USERS', '_AK_ADMIN_PLACEHOLDER_EMAILS', '_AK_ADMIN_EMAIL_RE',
                 'WEBADMIN_EMAIL_CACHE_S', 'WEBADMIN_EMAIL_REMIND_S', '_webadmin_email_lock',
                 '_webadmin_email_state'):
        exec(_src(ASSIGNS[name]), g)
    for name in ('_ak_admin_email_is_placeholder', '_ak_admin_recovery_email_notes', 'authentik_admin_email_api',
                 '_webadmin_email_status', '_webadmin_email_remind_tick',
                 'authentik_webadmin_email_status_api', 'authentik_webadmin_email_confirm_api'):
        exec(_src(FUNCS[name]), g)
    # os.path.exists('/opt/tak') must be true for the status read
    real_exists = g['os'].path.exists
    monkeypatch.setattr(g['os'].path, 'exists', lambda p: True if p == '/opt/tak' else real_exists(p))
    ns = types.SimpleNamespace(world=world, g=g, app=flask_app)
    ns.post = lambda fn, body: _call(flask_app, g[fn], body)
    return ns


def _call(flask_app, fn, body):
    with flask_app.test_request_context('/x', method='POST', json=body):
        rv = fn()
    resp, code = (rv if isinstance(rv, tuple) else (rv, 200))
    return code, resp.get_json()


# ---- which addresses count as made up -----------------------------------------------------------

@pytest.mark.parametrize('user,email', [
    ('webadmin', f'webadmin@{FQDN}'),          # what the Authentik deploy creates
    ('webadmin', f'WebAdmin@{FQDN.upper()}'),
    ('akadmin', 'admin@takwerx.local'),       # AUTHENTIK_BOOTSTRAP_EMAIL
    ('akadmin', ''),
    ('webadmin', 'not-an-address'),
    ('webadmin', 'someone@tak.local'),
    ('webadmin', 'someone@box.localhost'),
    ('webadmin', 'someone@corp.local'),
])
def test_made_up_addresses_are_flagged(mod, user, email):
    assert mod.g['_ak_admin_email_is_placeholder'](user, email, {'fqdn': FQDN}) is True


@pytest.mark.parametrize('user,email', [
    ('webadmin', 'chief@agency.gov'),
    ('akadmin', 'it@example.org'),
    ('webadmin', f'oncall@{FQDN}'),             # a real mailbox on the same domain is not flagged
])
def test_real_addresses_are_not_flagged(mod, user, email):
    assert mod.g['_ak_admin_email_is_placeholder'](user, email, {'fqdn': FQDN}) is False


# ---- banner status: clears only when Authentik shows a real address -------------------------------

def test_status_needs_action_for_the_made_up_address(mod):
    st = mod.g['_webadmin_email_status'](force=True)
    assert st == {'needs_action': True, 'email': f'webadmin@{FQDN}', 'authentik_url': 'https://auth.example.org'}


def test_status_clears_after_a_real_address_is_saved_in_authentik(mod):
    assert mod.g['_webadmin_email_status'](force=True)['needs_action'] is True
    mod.world.users['webadmin']['email'] = 'chief@agency.gov'
    assert mod.g['_webadmin_email_status'](force=True)['needs_action'] is False


def test_status_never_alarms_when_authentik_cannot_be_read(mod):
    def boom(*a, **k):
        raise OSError('authentik down')
    mod.g['_w1_ak_get'] = boom
    assert mod.g['_webadmin_email_status'](force=True)['needs_action'] is False


def test_status_is_cached_between_forced_reads(mod):
    mod.g['_webadmin_email_status'](force=True)
    mod.world.users['webadmin']['email'] = 'chief@agency.gov'
    assert mod.g['_webadmin_email_status']()['needs_action'] is True       # cached 5 minutes
    assert mod.g['_webadmin_email_status'](force=True)['needs_action'] is False


# ---- "I have changed email": typed phrase, and no false clear -------------------------------------

def test_confirm_needs_the_typed_phrase(mod):
    code, body = mod.post('authentik_webadmin_email_confirm_api', {'phrase': 'yes'})
    assert code == 400 and 'I have changed email' in body['message']
    code, body = mod.post('authentik_webadmin_email_confirm_api', {})
    assert code == 400


def test_confirm_with_the_phrase_but_no_change_in_authentik_does_not_clear(mod):
    code, body = mod.post('authentik_webadmin_email_confirm_api', {'phrase': '  I HAVE changed   email '})
    assert code == 200 and body['success'] is False
    assert f'webadmin@{FQDN}' in body['message']
    assert mod.g['_webadmin_email_status']()['needs_action'] is True


def test_confirm_clears_once_authentik_shows_a_real_address(mod):
    mod.world.users['webadmin']['email'] = 'chief@agency.gov'
    code, body = mod.post('authentik_webadmin_email_confirm_api', {'phrase': 'i have changed email'})
    assert code == 200 and body['success'] is True
    assert mod.g['_webadmin_email_status']()['needs_action'] is False


def test_keep_stores_the_address_and_a_later_change_rearms_the_banner(mod):
    code, body = mod.post('authentik_webadmin_email_confirm_api', {'keep': True})
    assert code == 200 and body['success'] is True
    assert mod.world.settings['webadmin_email_ack'] == f'webadmin@{FQDN}'
    assert mod.g['_webadmin_email_status'](force=True)['needs_action'] is False
    # the address changes to another made-up one: the old ack does not cover it
    mod.world.users['webadmin']['email'] = 'webadmin@other.local'
    assert mod.g['_webadmin_email_status'](force=True)['needs_action'] is True


# ---- Guard Dog reminder: every 3 days until fixed ---------------------------------------------

def test_reminder_sends_once_then_waits_three_days(mod):
    mod.g['_webadmin_email_remind_tick']()
    assert len(mod.world.sent) == 1
    to_addr, subject, body = mod.world.sent[0]
    assert to_addr == 'ops@example.org' and 'webadmin' in subject
    assert 'Save Changes' in body and 'I have changed email' in body and 'Admin interface' in body
    assert mod.world.settings['webadmin_email_reminder_last'] > 0
    mod.g['_webadmin_email_remind_tick']()                       # same hour: no second mail
    assert len(mod.world.sent) == 1
    mod.world.settings['webadmin_email_reminder_last'] = int(time.time()) - 72 * 3600 - 5
    mod.g['_webadmin_email_remind_tick']()                       # 3 days later: reminded again
    assert len(mod.world.sent) == 2


def test_reminder_stops_when_the_address_is_real(mod):
    mod.world.users['webadmin']['email'] = 'chief@agency.gov'
    mod.g['_webadmin_email_remind_tick']()
    assert mod.world.sent == []


def test_reminder_needs_an_alert_address(mod):
    mod.world.settings['guarddog_alert_email'] = ''
    mod.g['_webadmin_email_remind_tick']()
    assert mod.world.sent == []


def test_reminder_is_not_marked_sent_when_the_mail_fails(mod):
    mod.g['_guarddog_send_alert_email_via_relay'] = lambda *a, **k: False
    mod.g['_webadmin_email_remind_tick']()
    assert 'webadmin_email_reminder_last' not in mod.world.settings


# ---- set the email from the console (admin-email API) --------------------------------------------

def test_admin_email_api_sets_only_the_email(mod):
    code, body = mod.post('authentik_admin_email_api', {'user': 'webadmin', 'email': 'chief@agency.gov'})
    assert code == 200 and body['success'] is True
    assert mod.world.patches == [(7, 'PATCH', {'email': 'chief@agency.gov'})]
    assert mod.world.users['webadmin']['email'] == 'chief@agency.gov'
    assert mod.g['_webadmin_email_status']()['needs_action'] is False      # status forced fresh after the save
    assert any(ev == 'authentik:admin-recovery-email' for ev, _ in mod.world.audits)


@pytest.mark.parametrize('payload', [
    {'user': 'bob', 'email': 'chief@agency.gov'},                      # only akadmin / webadmin
    {'user': 'webadmin', 'email': 'bad'},
    {'user': 'webadmin', 'email': 'a@b.com;id'},
    {'user': 'webadmin', 'email': 'x@y.local'},
    {'user': 'webadmin', 'email': f'webadmin@{FQDN}'},                 # the placeholder itself
    {'user': 'akadmin', 'email': 'admin@takwerx.local'},
    {'user': 'webadmin', 'email': 'a' * 250 + '@example.org'},
])
def test_admin_email_api_refuses_bad_input_and_writes_nothing(mod, payload):
    code, body = mod.post('authentik_admin_email_api', payload)
    assert code == 400 and body['success'] is False
    assert mod.world.patches == []


def test_update_log_notes_name_each_placeholder_admin(mod):
    notes = mod.g['_ak_admin_recovery_email_notes']()
    assert len(notes) == 2 and all('Action needed:' in n for n in notes)
    assert any('akadmin' in n for n in notes) and any('webadmin' in n for n in notes)
    mod.world.users['akadmin']['email'] = 'it@example.org'
    assert len(mod.g['_ak_admin_recovery_email_notes']()) == 1


# ---- wiring ---------------------------------------------------------------------------------------

def test_every_console_page_with_the_banner_includes_it():
    for page in ('console', 'authentik', 'guarddog'):
        html = (REPO / 'templates' / f'{page}.html').read_text(encoding='utf-8')
        assert "from '_webadmin_email_banner.html' import webadmin_email_banner" in html, page
        assert '{{ webadmin_email_banner() }}' in html, page


def test_banner_confirm_button_is_locked_until_the_phrase_matches():
    html = (REPO / 'templates' / '_webadmin_email_banner.html').read_text(encoding='utf-8')
    assert re.search(r'id="wa-email-done"[^>]*\bdisabled\b', html)
    assert "PHRASE='i have changed email'" in html
    assert 'Save Changes' in html


def test_the_watch_thread_starts_with_the_console():
    assert "target=_webadmin_email_watch" in APP and "name='webadmin-email-watch'" in APP


def test_brand_recovery_flow_is_seeded_only_when_the_brand_has_none():
    body = _src(FUNCS['_ensure_authentik_recovery_flow'])
    assert "if br.get('flow_recovery'):" in body and 'continue' in body.split("if br.get('flow_recovery'):", 1)[1][:60]
    assert "{'flow_recovery': recovery_flow_pk}" in body
