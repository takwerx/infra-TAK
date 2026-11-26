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
"""Guard Dog tells a box about the 10.4.8 security update for the stream site share links (ops #1272).

The mail is made from the release's own notes: a box on 10.4.7 gets "Security update pending" when the
newest release's notes open with the security headline, and the mail names the version and the exact
step ("Console page → Update Now."). The real _console_pending_update and the real sweep run here;
only GitHub, the mail relay and the saved state are stand-ins. The release notes below are the text
the release must carry: "security update" and nothing about what was wrong (public text).
"""

import json
import pathlib
import re
import time
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?(?=^\S)', APP, re.S | re.M).group(0)


def _exec(n, names, consts=()):
    exec(compile('\n'.join([_const(c) for c in consts] + [_cut(x) for x in names]), 'app.py', 'exec'), n)
    return n


NOTES_SECURITY = '## Security release: security update\n\nUpdate to get it.\n'
NOTES_PLAIN = '## Share link fixes\n\nSmall fixes.\n'


def _console_item(latest_notes, installed='10.4.7-alpha', tag='v10.4.8-alpha', channel='main'):
    rels = [{'tag_name': tag, 'draft': False, 'body': latest_notes},
            {'tag_name': 'v10.4.7-alpha', 'draft': False, 'body': NOTES_PLAIN}]
    n = {
        're': re, 'json': json, 'print': lambda *a, **k: None,
        'VERSION': installed, 'GITHUB_REPO': 'takwerx/infra-TAK',
        '_gh_latest_release_tag': lambda repo, fresh=False: tag,
        '_gh_json_cached': lambda url, *a, **k: rels,
    }
    _exec(n, ('_console_pending_update', '_release_security_summary', '_security_section_summary',
              '_release_notes_line', '_apply_security_identity'),
          consts=('_SECURITY_RELEASE_HEADLINE_RE', '_SECURITY_SECTION_HEADING_RE', '_MD_MARKS_RE'))
    c = n['_console_pending_update']({'update_channel': channel})
    # the same wrap _collect_pending_updates puts around the console's item
    return n['_apply_security_identity']({**c, 'key': 'console'})


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
        '_collect_pending_updates': lambda settings, seen=None, unknown=None, etl=None: json.loads(
            json.dumps(pending)),
    }
    _exec(n, ('_carried_by_unknown', '_update_notify_check_once'))
    return n['_update_notify_check_once'](), sent, saved


def test_a_box_on_10_4_7_gets_the_security_mail_for_10_4_8_with_the_exact_step():
    item = _console_item(NOTES_SECURITY)
    assert item['target'] == 'v10.4.8-alpha'
    assert item['security'] == ['v10.4.8-alpha is a security release: security update']
    assert item['how'] == 'Console page → Update Now.'
    r, sent, saved = _sweep([item], {})
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '🔒 Security update pending on tak-prod-1 — update this machine'
    assert 'v10.4.8-alpha' in body
    assert 'Console page → Update Now.' in body
    # once only: a second sweep adds no mail
    r2, sent2, _ = _sweep([item], saved[-1])
    assert r2['emailed'] is False and sent2 == []


def test_the_mail_says_nothing_about_what_was_wrong():
    item = _console_item(NOTES_SECURITY)
    r, sent, _ = _sweep([item], {})
    text = (sent[0][0] + sent[0][1]).lower()
    for word in ('share link', 'share-link', 'viewer', 'token', 'expire', 'never end'):
        assert word not in text, word


def test_release_notes_without_the_security_headline_make_a_plain_update_mail():
    """The release must open its notes with the security headline, or operators get the plain mail."""
    item = _console_item(NOTES_PLAIN)
    assert not item.get('security')
    r, sent, _ = _sweep([item], {})
    assert not sent[0][0].startswith('🔒 Security update pending')
