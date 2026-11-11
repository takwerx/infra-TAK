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
"""Guard Dog's pending-update sweep reads every module that has an Update button (ops #608).

TAK Portal, ATLAS, Authentik, MediaMTX, TAK Server, Federation Hub, NetBird, Remote Assist,
TAK Video Restreamer and the Simulator reported an update on the console and were left out of
the Update pending mail. Each one now gives one line, once. A security fix is mailed as a
security item. The pinned ones (Authentik, NetBird, TAK Server, Federation Hub) are mailed
only for the version infra-TAK pins, never on the dev channel. Node-RED is not in the list
because the console update moves it onto its pinned image by itself.
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


def _registry(infos):
    mod = lambda k: types.SimpleNamespace(get_version_info=lambda ctx: dict(infos[k]))
    return types.SimpleNamespace(atlas=mod('atlas'), tvr=mod('tak_video_restreamer'),
                                 simulator=mod('simulator'), get_ctx=lambda: {})


def _ns(infos, advisories=None):
    """Namespace with `_module_update_items` and the real helpers; the version helpers are
    stubs that answer from `infos` (module key -> the dict the card would read)."""
    def getter(k):
        def f(*a, **kw):
            v = infos[k]
            if isinstance(v, Exception):
                raise v
            return dict(v)
        return f

    def gh(repo, installed, target):
        if isinstance(advisories, Exception):
            raise advisories
        return list((advisories or {}).get(repo, []))

    n = {
        're': re, 'print': lambda *a, **k: None,
        'detect_modules': lambda: {k: {'installed': True} for k in infos},
        'mod_registry': _registry(infos),
        '_get_takportal_version_info': getter('takportal'),
        '_get_authentik_version_info': getter('authentik'),
        '_get_mediamtx_version_info': getter('mediamtx'),
        '_get_takserver_version_info': getter('takserver'),
        '_get_fedhub_version_info': getter('fedhub'),
        '_get_netbird_version_info': getter('netbird'),
        '_get_remote_assist_version_info': getter('remote_assist'),
        '_gh_advisories_fixed_by': gh,
        'KNOWN_SECURITY_RELEASES': _table('KNOWN_SECURITY_RELEASES'),
        '_MODULE_UPDATE_ROWS': _table('_MODULE_UPDATE_ROWS'),
    }
    for k in ('takportal', 'authentik', 'mediamtx', 'takserver', 'fedhub', 'netbird', 'remote_assist'):
        infos.setdefault(k, {})
    for k in ('atlas', 'tak_video_restreamer', 'simulator'):
        infos.setdefault(k, {})
    n['detect_modules'] = lambda: {k: {'installed': bool(v)} for k, v in infos.items()}
    return _exec(n, '_semver_tuple', '_apply_security_identity', '_known_security_fixed_by',
                 '_module_update_info', '_module_update_candidates', '_module_update_items')


def _items(infos, advisories=None):
    unknown = set()
    return _ns(infos, advisories)['_module_update_items'](unknown), unknown


def _sweep(pending, state, unknown_add=()):
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
        '_collect_pending_updates': lambda settings, seen=None, unknown=None, etl=None: (
            unknown.update(unknown_add), json.loads(json.dumps(pending)))[1],
    }
    _exec(n, '_carried_by_unknown', '_update_notify_check_once')
    return n['_update_notify_check_once'](), sent, saved


# One case per component: (module key, version info the card reads, expected mail line,
# expected how-text start). Each is an update that is NOT a security fix.
CASES = {
    'takportal': ({'version': '1.4.9', 'update_available': True, 'latest': '1.5.2'},
                  'TAK Portal: v1.4.9 → v1.5.2', 'TAK Portal page → Update.'),
    'atlas': ({'version': '1.130.2', 'update_available': True, 'latest': '1.132.0'},
              'ATLAS: v1.130.2 → v1.132.0', 'ATLAS page → Update'),
    'authentik': ({'version': '2026.8.5', 'update_available': True, 'latest': '2026.8.6',
                   'channel': 'main'},
                  'Authentik: v2026.8.5 → v2026.8.6', 'Authentik page → Update.'),
    'mediamtx': ({'version': '1.20.0', 'latest': '1.21.3', 'binary_update_available': True,
                  'update_available': True, 'editor_version': '2.1.0', 'editor_latest': None,
                  'editor_update_available': False},
                 'MediaMTX: v1.20.0 → v1.21.3', 'MediaMTX page → open the web editor'),
    'takserver': ({'version': '5.7-RELEASE43', 'update_available': True, 'latest': '5.7-RELEASE50'},
                  'TAK Server: 5.7-RELEASE43 → 5.7-RELEASE50', 'TAK Server page → Update TAK Server.'),
    'fedhub': ({'version': '5.7-RELEASE-43', 'update_available': True, 'latest': '5.7-RELEASE-50'},
               'Federation Hub: 5.7-RELEASE-43 → 5.7-RELEASE-50',
               'Federation Hub page → Update Federation Hub.'),
    'netbird': ({'version': '0.80.0 · dash 2.94.0', 'update_available': True,
                 'latest': '0.82.0 · dash 2.96.0', 'channel': 'main'},
                'NetBird: v0.80.0 · dash 2.94.0 → v0.82.0 · dash 2.96.0', 'NetBird page → Update.'),
    'remote_assist': ({'version': '3.1.4', 'update_available': True, 'latest': '3.4.0'},
                      'Remote Assist: v3.1.4 → v3.4.0', 'Remote Assist page → Update.'),
    'tak_video_restreamer': ({'version': 'abc1234', 'update_available': True, 'latest': 'def5678',
                              'security_update': False},
                             'TAK Video Restreamer: abc1234 → def5678',
                             'TAK Video Restreamer page → Update Now.'),
    'simulator': ({'version': '10.3.9', 'update_available': True, 'latest': '10.3.11'},
                  'TAK Simulator: v10.3.9 → v10.3.11', 'TAK Simulator page → Rebuild Now.'),
}


@pytest.mark.parametrize('key', sorted(CASES))
def test_pending_update_is_one_plain_mail_line_once(key):
    info, line, how = CASES[key]
    pending, unknown = _items({key: info})
    assert [p['key'] for p in pending] == [key] and not unknown
    p = pending[0]
    assert 'security' not in p and p['identity'] == info['latest']
    assert p['how'].startswith(how)
    r, sent, saved = _sweep(pending, {})
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '⬆ Update pending on tak-prod-1'
    assert body.count(line) == 1
    assert saved and saved[-1][key] == info['latest']
    r2, sent2, _ = _sweep(pending, saved[-1])
    assert r2['emailed'] is False and sent2 == []


@pytest.mark.parametrize('key', sorted(CASES))
def test_module_already_current_is_quiet(key):
    info = dict(CASES[key][0], update_available=False, binary_update_available=False)
    assert _items({key: info})[0] == []


def test_module_not_installed_is_quiet():
    infos = {'takportal': {'version': '1.4.9', 'update_available': True, 'latest': '1.5.2'}}
    ns = _ns(infos)
    ns['detect_modules'] = lambda: {'takportal': {'installed': False}}
    assert ns['_module_update_items'](set()) == []


def test_all_modules_pending_give_one_mail_with_one_line_each():
    infos = {k: v[0] for k, v in CASES.items()}
    pending, _ = _items(infos)
    assert sorted(p['key'] for p in pending) == sorted(CASES)
    r, sent, _ = _sweep(pending, {})
    assert len(sent) == 1 and sent[0][0] == '⬆ 10 updates pending on tak-prod-1'
    for _info, line, _how in CASES.values():
        assert sent[0][1].count(line) == 1


# ── gated (pinned) components: only the pinned version, never the dev channel ────────────
@pytest.mark.parametrize('key', ['authentik', 'netbird'])
def test_pinned_module_on_the_dev_channel_is_quiet(key):
    info = dict(CASES[key][0], channel='dev')
    assert _items({key: info})[0] == []


@pytest.mark.parametrize('key', ['takserver', 'fedhub'])
def test_pinned_module_with_no_target_is_quiet(key):
    # the real helpers never name a newer version (the package is uploaded by the operator)
    info = {'version': CASES[key][0]['version'], 'update_available': False, 'latest': None}
    assert _items({key: info})[0] == []


# ── security: always mailed, with the exact fix ────────────────────────────────────────────
def test_authentik_2026_8_4_to_the_pin_is_a_security_item():
    info = {'version': '2026.8.4', 'update_available': True, 'latest': '2026.8.5', 'channel': 'main'}
    pending, _ = _items({'authentik': info})
    p = pending[0]
    assert p['security'] == ['Fixes a certificate bundle that still trusted a distrusted root '
                             '(eMudhra) (fixed in v2026.8.5)']
    assert p['identity'] == '2026.8.5+security'
    r, sent, saved = _sweep(pending, {})
    assert sent[0][0] == '🔒 Security update pending on tak-prod-1 — update this machine'
    assert 'Fix it from the infra-TAK console: Authentik page → Update.' in sent[0][1]
    assert saved[-1]['authentik'] == '2026.8.5+security'


def test_a_published_advisory_makes_a_mediamtx_update_a_security_item():
    info = dict(CASES['mediamtx'][0])
    adv = {'bluenviron/mediamtx': ['GHSA-w334-5mp5-h897 (critical): CSRF on the Control API']}
    pending, _ = _items({'mediamtx': info}, advisories=adv)
    assert pending[0]['security'] == ['Fixes GHSA-w334-5mp5-h897 (critical): CSRF on the Control API']
    assert pending[0]['identity'] == '1.21.3+security'


def test_advisories_that_cannot_be_read_keep_the_dedup_state_and_do_not_drop_the_flag():
    pending, _ = _items({'takportal': CASES['takportal'][0]}, advisories=OSError('rate limited'))
    p = pending[0]
    assert p['security_unknown'] is True and 'security' not in p
    assert p['seen_ok'] == ['1.5.2', '1.5.2+security']
    # mailed before as a security item: no second mail
    r, sent, _ = _sweep(pending, {'takportal': '1.5.2+security'})
    assert r['emailed'] is False and sent == []


def test_tvr_security_update_is_mailed_as_security():
    info = dict(CASES['tak_video_restreamer'][0], security_update=True)
    p = _items({'tak_video_restreamer': info})[0][0]
    assert p['security'] and p['identity'] == 'def5678+security'


# ── one module failing never hides the rest ────────────────────────────────────────────────
def test_a_module_that_raises_is_unknown_and_the_others_still_report():
    infos = {'takportal': RuntimeError('docker timeout'), 'simulator': CASES['simulator'][0]}
    pending, unknown = _items(infos)
    assert [p['key'] for p in pending] == ['simulator']
    assert 'takportal' in unknown


def test_installed_but_unreadable_version_is_unknown_not_fixed():
    infos = {'authentik': {'version': '', 'update_available': False, 'latest': '2026.8.5'}}
    pending, unknown = _items(infos)
    assert pending == [] and 'authentik' in unknown
    # the dedup state of an unreadable module is carried, not pruned; a module that is
    # simply gone from the sweep is pruned
    state = {'authentik': '2026.8.5+security'}
    _, sent, saved = _sweep([], state, unknown_add=unknown)
    assert sent == [] and saved == []
    _, _, saved2 = _sweep([], state)
    assert saved2 and 'authentik' not in saved2[-1]


def test_node_red_is_left_out_on_purpose():
    assert 'nodered' not in {r[0] for r in _table('_MODULE_UPDATE_ROWS')}
