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
"""Guard Dog tells a box on Authentik 2026.8.6 about the 2026.8.7 security update (ops #1276).

A main-channel box on 2026.8.6 must get the "Security update pending" mail once the pin is
2026.8.7, with the exact step ("Authentik page → Update."), also when GitHub's advisory list
cannot be read (the KNOWN_SECURITY_RELEASES entry carries it). The advisory rows below have the
real shape of Authentik's list (one row per release line, "<= X" ranges); their text is made up.
"""

import json
import pathlib
import re
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _table(name):
    return eval(re.search(rf'^{name} = (\(.*?^\))', APP, re.S | re.M).group(1), {})


def _exec(n, *names):
    exec(compile('\n'.join(_cut(x) for x in names), 'app.py', 'exec'), n)
    return n


ROW = {'state': 'published', 'withdrawn_at': None, 'severity': 'critical', 'cve_id': None,
       'vulnerabilities': [
           {'package': {'name': 'authentik'}, 'vulnerable_version_range': '<= 2026.8.6',
            'patched_versions': '2026.8.7'},
           {'package': {'name': 'authentik'}, 'vulnerable_version_range': '<= 2026.5.8',
            'patched_versions': '2026.5.9'}]}
ADVISORIES = [dict(ROW, ghsa_id='GHSA-aaaa-bbbb-cccc', summary='Example flaw one'),
              dict(ROW, ghsa_id='GHSA-dddd-eeee-ffff', severity='high', summary='Example flaw two'),
              # an old one, fixed long before 2026.8.6: must not be claimed for 8.6 -> 8.7
              dict(ROW, ghsa_id='GHSA-old0-old0-old0', severity='high', summary='Old flaw',
                   vulnerabilities=[{'package': {'name': 'authentik'},
                                     'vulnerable_version_range': '<= 2026.5.6',
                                     'patched_versions': '2026.5.7'}])]


class _Resp:
    def __init__(self, body):
        self._b = body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _ns(info, github_ok=True):
    """The real _module_update_items with the real advisory reader; only the network and the
    version card are stubs."""
    import urllib.request

    def urlopen(req, timeout=10):
        if not github_ok:
            raise OSError('rate limited')
        return _Resp(json.dumps(ADVISORIES).encode())

    n = {
        're': re, 'json': json, 'print': lambda *a, **k: None,
        'detect_modules': lambda: {'authentik': {'installed': True}},
        'mod_registry': types.SimpleNamespace(get_ctx=lambda: {}),
        '_get_authentik_version_info': lambda *a, **k: dict(info),
        'KNOWN_SECURITY_RELEASES': _table('KNOWN_SECURITY_RELEASES'),
        '_MODULE_UPDATE_ROWS': _table('_MODULE_UPDATE_ROWS'),
    }
    _exec(n, '_semver_tuple', '_version_in_range', '_gh_advisories', '_gh_advisories_fixed_by',
          '_apply_security_identity', '_known_security_fixed_by', '_module_update_info',
          '_module_update_candidates', '_module_update_items')
    orig = urllib.request.urlopen
    urllib.request.urlopen = urlopen
    try:
        yield_items = n['_module_update_items'](set())
    finally:
        urllib.request.urlopen = orig
    return yield_items


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
    _exec(n, '_carried_by_unknown', '_update_notify_check_once')
    return n['_update_notify_check_once'](), sent, saved


MAIN_8_6 = {'version': '2026.8.6', 'update_available': True, 'latest': '2026.8.7', 'channel': 'main'}


def test_known_release_table_names_2026_8_7():
    assert {'component': 'authentik', 'fixed_in': '2026.8.7',
            'reason': 'Authentik security flaws'} in _table('KNOWN_SECURITY_RELEASES')


def test_main_box_on_8_6_gets_the_security_mail_with_the_exact_step():
    pending = _ns(MAIN_8_6)
    assert [p['key'] for p in pending] == ['authentik']
    p = pending[0]
    assert p['identity'] == '2026.8.7+security'
    lines = ' | '.join(p['security'])
    assert 'GHSA-aaaa-bbbb-cccc (critical): Example flaw one' in lines
    assert 'GHSA-dddd-eeee-ffff (high): Example flaw two' in lines
    assert 'Old flaw' not in lines                       # fixed before 8.6: never claimed
    assert 'Authentik security flaws (fixed in v2026.8.7)' in lines
    r, sent, saved = _sweep(pending, {})
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '🔒 Security update pending on tak-prod-1 — update this machine'
    assert 'Authentik: v2026.8.6 → v2026.8.7' in body
    assert 'Fix it from the infra-TAK console: Authentik page → Update.' in body
    assert saved[-1]['authentik'] == '2026.8.7+security'
    # once only
    r2, sent2, _ = _sweep(pending, saved[-1])
    assert r2['emailed'] is False and sent2 == []


def test_the_mail_still_says_security_when_github_cannot_be_read():
    pending = _ns(MAIN_8_6, github_ok=False)
    p = pending[0]
    assert p['security'] == ['Fixes Authentik security flaws (fixed in v2026.8.7)']
    assert p['identity'] == '2026.8.7+security'
    r, sent, _ = _sweep(pending, {})
    assert sent[0][0].startswith('🔒 Security update pending')


def test_box_already_on_8_7_is_quiet():
    info = dict(MAIN_8_6, version='2026.8.7', update_available=False)
    assert _ns(info) == []


def test_dev_channel_box_is_not_mailed_for_the_pin():
    assert _ns(dict(MAIN_8_6, channel='dev')) == []


@pytest.mark.parametrize('installed', ['2026.8.1', '2026.8.5'])
def test_older_8_x_boxes_are_told_too(installed):
    pending = _ns(dict(MAIN_8_6, version=installed))
    assert pending and pending[0]['security']
