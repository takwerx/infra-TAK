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
"""Guard Dog's "Update pending" email says what the update fixes and where to press (ops #547).

garesponder, Fri Nov 6: the mail for 10.3.8 said only "v10.3.6-alpha → v10.3.8-alpha, open the
console to review and apply". Customers got the version number but no reason to update and no
button to press. The email now carries one plain line per new release (its notes headline) and
"Console page → Update Now", for plain and security updates alike. One email per update and
nothing for a box already on the newest version are unchanged.
"""

import io
import json
import os
import pathlib
import re
import subprocess as _real_subprocess
import sys
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?(?=^\S)', APP, re.S | re.M).group(0)


def _exec(n, *names, consts=()):
    src = '\n'.join([_const(c) for c in consts] + [_cut(x) for x in names])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


NOTES_CONSTS = ('_SECURITY_RELEASE_HEADLINE_RE', '_SECURITY_SECTION_HEADING_RE', '_MD_MARKS_RE')

REL_10_3_8 = (
    '## CloudTAK Update keeps its database working, TAK Portal shows the right state after an '
    'update, and an Ubuntu 24.04 upgrade fix\n\nThis is an emergency patch: on non-root installs, '
    'CloudTAK Update could stop the database.\n\n### CloudTAK\n- **Database keeps accepting '
    'connections:** ...\n\n**Upgrading:** use **Update Now** in the console.\n')
REL_10_3_7 = '## Guard Dog alerts say why a remote-database login failed\n\n### Guard Dog\n- x\n'
REL_10_3_6 = ('## Caddy security update, big uploads, a quieter Guard Dog\n\n### Security\n'
              '- **Caddy security update:** Ubuntu boxes move to Caddy 2.11.8 or newer.\n')


# ── the one-line summary of a release ─────────────────────────────────────────

@pytest.mark.parametrize('body, want', [
    (REL_10_3_8, 'CloudTAK Update keeps its database working, TAK Portal shows the right state '
                 'after an update, and an Ubuntu 24.04 upgrade fix'),
    ('## **Security release:** CloudTAK PostgreSQL 17.11\n\nbody', 'Security release: CloudTAK PostgreSQL 17.11'),
    ('\n\n  \nNode-RED feeds get their groups back. More text follows.\n', 'Node-RED feeds get their groups back. More text follows.'),
    ('---\n\n- **Fixed:** the page said Stopped\n', 'Fixed: the page said Stopped'),
    ('', ''), (None, ''), ('\n  \n---\n', ''),
])
def test_release_notes_line(body, want):
    n = _exec({'re': re}, '_release_notes_line', consts=('_MD_MARKS_RE',))
    assert n['_release_notes_line'](body) == want


def test_release_notes_line_is_capped():
    n = _exec({'re': re}, '_release_notes_line', consts=('_MD_MARKS_RE',))
    assert len(n['_release_notes_line']('## ' + 'word ' * 200)) <= 240
    # a long first paragraph is cut at its first sentence
    assert n['_release_notes_line']('First sentence. ' + 'More text here. ' * 30) == 'First sentence.'


# ── the console item carries one line per new release ─────────────────────────

class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _console(routes, version='10.3.6-alpha', channel='main'):
    import urllib.request as _ur

    def urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, 'full_url') else req
        for k, v in routes.items():
            if k in url:
                if isinstance(v, BaseException):
                    raise v
                return _Resp(json.dumps(v).encode())
        raise AssertionError('unexpected url ' + url)
    fake = types.SimpleNamespace(Request=_ur.Request, urlopen=urlopen)
    n = {'json': json, 'subprocess': _real_subprocess, 'os': os, 're': re, 'VERSION': version,
         'GITHUB_REPO': 'takwerx/infra-TAK'}
    _exec(n, '_console_pending_update', '_release_security_summary', '_security_section_summary',
          '_release_notes_line', consts=NOTES_CONSTS)
    real = sys.modules['urllib.request']
    old_attr = _ur
    import urllib
    sys.modules['urllib.request'] = fake
    urllib.request = fake
    try:
        return n['_console_pending_update']({'update_channel': channel})
    finally:
        urllib.request = old_attr
        sys.modules['urllib.request'] = real


RELEASES = [
    {'tag_name': 'v10.3.8-alpha', 'body': REL_10_3_8},
    {'tag_name': 'v10.3.7-alpha', 'body': REL_10_3_7},
    {'tag_name': 'v10.3.6-alpha', 'body': REL_10_3_6},       # what runs here: not "new"
    {'tag_name': 'v10.3.9-alpha', 'body': '## Draft\n', 'draft': True},
]


def test_console_item_has_a_line_per_new_release_newest_first():
    item = _console({'/releases/latest': {'tag_name': 'v10.3.8-alpha'}, '/releases?': RELEASES})
    assert item['release_notes'] == [
        'v10.3.8-alpha: CloudTAK Update keeps its database working, TAK Portal shows the right '
        'state after an update, and an Ubuntu 24.04 upgrade fix',
        'v10.3.7-alpha: Guard Dog alerts say why a remote-database login failed']
    assert item['how'] == 'Console page → Update Now.'
    assert item['release_url'] == 'https://github.com/takwerx/infra-TAK/releases/tag/v10.3.8-alpha'


def test_console_release_list_unreadable_still_links_the_notes():
    item = _console({'/releases/latest': {'tag_name': 'v10.3.8-alpha'}, '/releases?': OSError('rate limited')})
    assert not item.get('release_notes')
    assert item['release_url'].endswith('/releases/tag/v10.3.8-alpha')


def test_console_on_newest_version_is_quiet():
    assert _console({'/releases/latest': {'tag_name': 'v10.3.8-alpha'}, '/releases?': RELEASES},
                    version='10.3.8-alpha') is None


# ── the email ─────────────────────────────────────────────────────────────────

def _sweep(pending, state):
    sent, saved = [], []
    n = {
        'socket': types.SimpleNamespace(gethostname=lambda: 'box'),
        'load_settings': lambda: {'guarddog_alert_email': 'ops@example.com', 'fqdn': 'tak.example.com',
                                  'console_port': 5001, 'update_channel': 'main'},
        '_safe_alert_email_list': lambda v: v,
        '_gd_quiet_state': lambda: (False, 0, ''),
        '_guarddog_server_identifier': lambda s: 'tak-prod-1',
        '_update_notify_state_load': lambda: json.loads(json.dumps(state)),
        '_update_notify_state_save': lambda s: saved.append(s),
        '_guarddog_send_alert_email_via_relay': lambda to, subj, body: sent.append((subj, body)),
        'print': lambda *a, **k: None,
        'time': time,
        'PATCH_NOW_REPEAT_S': 24 * 3600,
        '_collect_patch_now_items': lambda feed, unknown, now=None: ([], feed),
        '_collect_pending_updates': lambda settings, seen=None, unknown=None, etl=None: json.loads(json.dumps(pending)),
    }
    _exec(n, '_carried_by_unknown', '_update_notify_check_once')
    return n['_update_notify_check_once'](), sent, saved


NOTES = ['v10.3.8-alpha: CloudTAK Update keeps its database working',
         'v10.3.7-alpha: Guard Dog alerts say why a remote-database login failed']
CONSOLE = {'key': 'console', 'label': 'infra-TAK console', 'installed': 'v10.3.6-alpha',
           'target': 'v10.3.8-alpha', 'identity': 'v10.3.8-alpha', 'how': 'Console page → Update Now.',
           'release_notes': NOTES, 'release_url': 'https://github.com/takwerx/infra-TAK/releases/tag/v10.3.8-alpha'}
CONSOLE_SEC = dict(CONSOLE, identity='v10.3.8-alpha+security',
                   security=['v10.3.7-alpha is a security release: Caddy 2.11.8'])


def test_update_pending_email_says_what_is_new_and_where_to_press():
    r, sent, _ = _sweep([CONSOLE], {})
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '⬆ Update pending on tak-prod-1'
    assert "New in this update:" in body
    assert '        - v10.3.8-alpha: CloudTAK Update keeps its database working' in body
    assert '        - v10.3.7-alpha: Guard Dog alerts say why a remote-database login failed' in body
    assert 'Console page → Update Now.' in body


def test_security_email_has_the_notes_and_the_step_too():
    r, sent, _ = _sweep([CONSOLE_SEC], {})
    subj, body = sent[0]
    assert subj.startswith('🔒 Security update pending')
    assert body.startswith('SECURITY UPDATE: you should update this machine')
    assert '        - v10.3.8-alpha: CloudTAK Update keeps its database working' in body
    assert 'Fix it from the infra-TAK console: Console page → Update Now.' in body


def test_notes_unreadable_email_links_the_release():
    item = dict(CONSOLE)
    item.pop('release_notes')
    _, sent, _ = _sweep([item], {})
    body = sent[0][1]
    assert "New in this update: https://github.com/takwerx/infra-TAK/releases/tag/v10.3.8-alpha" in body
    assert 'Console page → Update Now.' in body


def test_long_list_is_cut_at_five_with_a_count():
    item = dict(CONSOLE, release_notes=[f'v10.3.{i}-alpha: fix {i}' for i in range(20, 8, -1)])
    _, sent, _ = _sweep([item], {})
    body = sent[0][1]
    assert body.count('        - v10.3.') == 5 and '(+7 older releases)' in body


def test_still_one_email_per_update_never_repeated():
    r, sent, saved = _sweep([CONSOLE], {})
    assert len(sent) == 1
    r, sent, _ = _sweep([CONSOLE], saved[-1])
    assert sent == [] and r['emailed'] is False


def test_no_pending_update_sends_nothing():
    r, sent, _ = _sweep([], {})
    assert sent == [] and r['emailed'] is False


# ── characters the mail relay turns into codes (ops #547, lead: no apostrophes) ─

def test_notes_have_no_characters_the_relay_turns_into_codes():
    n = _exec({'re': re}, '_release_notes_line', consts=('_MD_MARKS_RE',))
    line = n['_release_notes_line']('## Fixes what\'s broken in "Q&A" pages if a < b > c\n')
    assert not any(c in line for c in '\'"&<>')
    assert line == 'Fixes what\u2019s broken in Q and A pages if a b c'


def test_email_never_says_whats_new_with_an_apostrophe():
    for item in (CONSOLE, CONSOLE_SEC, {k: v for k, v in CONSOLE.items() if k != 'release_notes'}):
        _, sent, _ = _sweep([item], {})
        body = sent[0][1]
        assert 'New in this update:' in body and "What's" not in body
