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
"""Guard Dog mails about a pending WebODM update (ops #606).

The WebODM 4.0.0 update replaces an end-of-life Django with known flaws, but the operator has
to press Update on the WebODM page after the console update. The pending-update sweep did not
read WebODM, so nobody was told. A box on WebODM 3.3.1 with WEBODM_VERSION 4.0.0 now gets one
security line, once; a box already on 4.0.0, or without WebODM, gets nothing.
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


def _exec(n, *names, consts=()):
    src = '\n'.join([_const(c) for c in consts] + [_cut(x) for x in names])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


def _collect(info, installed=True):
    """_collect_pending_updates with only the WebODM source live."""
    n = {
        're': re, 'os': types.SimpleNamespace(path=types.SimpleNamespace(
            isdir=lambda p: False, expanduser=lambda p: p)),
        'print': lambda *a, **k: None,
        '_console_pending_update': lambda settings: None,
        'detect_modules': lambda: {'webodm': {'installed': installed}},
        '_get_webodm_version_info': lambda: dict(info),
        '_os_security_items': lambda seen, unknown: [],
        '_node_container_versions': lambda: {},
        '_node_security_items': lambda nv: [],
        '_detect_cloudtak_plugins': lambda: [],
        'NODE_MODULE_CONTAINERS': {},
        'KNOWN_SECURITY_RELEASES': None,
    }
    _exec(n, '_semver_tuple', '_apply_security_identity', '_known_security_fixed_by',
          '_collect_pending_updates')
    table = re.search(r'^KNOWN_SECURITY_RELEASES = (\(.*?^\))', APP, re.S | re.M).group(1)
    n['KNOWN_SECURITY_RELEASES'] = eval(table, {})
    return n['_collect_pending_updates']({})


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


OLD = {'version': '3.3.1', 'update_available': True, 'latest': '4.0.0'}


def test_webodm_3_3_1_against_pin_4_0_0_is_one_security_item():
    pending = _collect(OLD)
    assert [p['key'] for p in pending] == ['webodm']
    p = pending[0]
    assert (p['installed'], p['target']) == ('v3.3.1', 'v4.0.0')
    assert p['security'] == ['Fixes an end-of-life Django with known flaws (fixed in v4.0.0)']
    assert p['identity'] == '4.0.0+security'
    assert p['how'].startswith('WebODM page → Update (makes a backup first;')


def test_mail_has_one_webodm_line_and_the_step_then_nothing_the_second_time():
    pending = _collect(OLD)
    r, sent, saved = _sweep(pending, {})
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '🔒 Security update pending on tak-prod-1 — update this machine'
    assert body.count('WebODM: v3.3.1 → v4.0.0') == 1
    assert '      Fixes an end-of-life Django with known flaws (fixed in v4.0.0)' in body
    assert ('Fix it from the infra-TAK console: WebODM page → Update (makes a backup first; '
            'the database upgrade cannot be undone without the backup).') in body
    assert saved and saved[-1]['webodm'] == '4.0.0+security'
    r2, sent2, _ = _sweep(pending, saved[-1])
    assert r2['emailed'] is False and sent2 == []


def test_webodm_already_on_the_pin_is_quiet():
    assert _collect({'version': '4.0.0', 'update_available': False, 'latest': '4.0.0'}) == []


def test_webodm_not_installed_is_quiet():
    assert _collect(OLD, installed=False) == []


def test_version_unreadable_is_quiet():
    assert _collect({'version': '', 'update_available': False, 'latest': '4.0.0'}) == []


def test_a_later_plain_webodm_release_is_not_flagged_as_security():
    p = _collect({'version': '4.0.0', 'update_available': True, 'latest': '4.1.0'})[0]
    assert 'security' not in p and p['identity'] == '4.1.0'
