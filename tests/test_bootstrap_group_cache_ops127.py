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
"""CloudTAK Core Events reach channels created after the bootstrap cert connected (ops #127).

nuc, 2026-10-20: a Core Event on RAPID-SOS (created that day) reached no member. TAK stored the CoT;
the bootstrap cert's subscription held the 20 older channels but not RAPID-SOS. CoreConfig's
x509useGroupCacheRequiresExtKeyUsage="false" makes makeCert certs group-cached, and the cache sync
only ever handled `admin`. test8 the same day: no cache entry at all, and the live subscription
still lacked TAKDEV-EMU — ROLE_ADMIN's "all groups" is computed only when the cert authenticates.
"""

import ast
import pathlib
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
CN = 'cloudtak-svc-bootstrap'
BASE = 'https://127.0.0.1:8443/Marti/api'


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _grp(name, direction, bitpos, active=True):
    return {'name': name, 'direction': direction, 'created': '2026-07-29', 'type': 'SYSTEM',
            'bitpos': bitpos, 'active': active}


CHANNELS = [_grp('MPD Main', 'OUT', 4), _grp('RAPID-SOS', 'OUT', 22),
            _grp('ROLE_ADMIN', 'OUT', 2), _grp('__ANON__', 'OUT', 3)]


class FakeTak:
    """The Marti endpoints the sync and detector use, over in-memory state. Re-authentication
    (activeForce, groups/update) recomputes the live subscription the way TAK does: membership is
    every group (ROLE_ADMIN + x509assignAdminAllGroups); a cached cert keeps only its ACTIVE entries."""

    def __init__(self, cache, live=None, channels=CHANNELS, enabled=True, down=False, all_fails=False,
                 connected=True, stuck=False):
        self.cache = [dict(e) for e in cache]
        self.channels = channels
        self.enabled = enabled
        self.down = down
        self.all_fails = all_fails
        self.connected = connected
        self.stuck = stuck  # re-auth changes nothing (the case only a reconnect fixes)
        self.puts, self.reauths, self.calls = [], 0, []
        if live is None:  # what the connection got at its last auth
            live = [(e['name'], e['direction']) for e in self.cache if e['active']]
        self.live = list(live)
        self.uid = 5
        self.extra_subs = []

    def _reauth(self):
        if self.stuck:
            return
        if self.cache:
            self.live = [(e['name'], e['direction']) for e in self.cache if e['active']]
        else:
            self.live = [(g['name'], d) for g in self.channels for d in ('IN', 'OUT')]

    def get(self, url, timeout=12):
        self.calls.append(url)
        if self.down:
            return None, 'curl_exit_7'
        if url.endswith('/groups/groupCacheEnabled'):
            return {'data': self.enabled}, None
        if url.endswith('/groups/all'):
            return (None, 'http_500') if self.all_fails else ({'data': [dict(g) for g in self.channels]}, None)
        if url.endswith(f'/groups/user?username={CN}'):
            return {'data': [dict(e) for e in self.cache]}, None
        if url.endswith('/subscriptions/all'):
            subs = [_sub(f'tls:{self.uid}', self.live)] if self.connected else []
            return {'data': subs + self.extra_subs}, None
        if url == f'{BASE}/groups/update/{CN}':
            self.reauths += 1
            self._reauth()
            return None, 'empty_body'  # TAK answers 200 with no body
        raise AssertionError(f'unexpected GET {url}')

    def req(self, url, timeout=12, method='GET', json_body=None):
        if method == 'GET':
            return self.get(url, timeout)
        assert method == 'PUT' and url == f'{BASE}/groups/activeForce?username={CN}', url
        self.puts.append(json_body)
        self.cache = [dict(e) for e in json_body]  # TAK stores the list as given...
        self._reauth()  # ...and re-authenticates the user's connections
        return True, None


def _sub(uid, groups, user=CN):
    return {'username': user, 'subscriptionUid': uid,
            'groups': [{'name': n, 'direction': d} for n, d in groups]}


def _ns(tak, mode='local', files=('/opt/tak/CoreConfig.xml', f'/opt/tak/certs/files/{CN}.p12'), uaf=''):
    files = set(files)
    fake_os = types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: p in files))
    ns = {
        'os': fake_os,
        'time': types.SimpleNamespace(sleep=lambda s: None),
        'CLOUDTAK_BOOTSTRAP_CERT_CN': CN,
        'load_settings': lambda: {},
        '_cloudtak_bootstrap_cert_target': lambda s: (mode, None),
        '_tak_admin_marti_get': tak.get,
        '_tak_admin_marti_req': tak.req,
        '_read_priv': lambda p: uaf,
    }
    src = '\n'.join(ast.get_source_segment(APP, n) for n in TREE.body
                    if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in (
                        '_TAK_NON_CHANNEL_GROUPS', '_bootstrap_groupcache_splitbox_logged') for t in n.targets))
    exec(compile(src, 'app.py', 'exec'), ns)
    exec(compile('\n\n'.join(_func(n) for n in (
        '_tak_core_is_remote', '_tak_channel_items', '_tak_bootstrap_cert_present',
        '_tak_bootstrap_channel_state', '_tak_sync_bootstrap_group_cache')), 'app.py', 'exec'), ns)
    return ns


def _sync(ns):
    log = []
    res = ns['_tak_sync_bootstrap_group_cache'](plog=log.append)
    return res, log


def _old_cache():
    """A cache made at first connect: the channels of the day active both ways, system groups as TAK left them."""
    return [_grp('MPD Main', 'OUT', 4), _grp('MPD Main', 'IN', 4),
            _grp('ROLE_ADMIN', 'OUT', 2), _grp('ROLE_ADMIN', 'IN', 2, active=False),
            _grp('__ANON__', 'OUT', 3), _grp('__ANON__', 'IN', 3, active=False)]


def _both(*names):
    return [(n, d) for n in names for d in ('IN', 'OUT')]


def _deliverable(tak):
    """Channels a Core Event reaches: the live connection has them IN and OUT (IN is the one that
    decides it — test12 2026-10-20; OUT is kept for uniformity with the admin sync)."""
    return {n for n, d in tak.live if d == 'IN'} & {n for n, d in tak.live if d == 'OUT'}


# ---------------------------------------------------------------- step 1: the group cache

def test_new_channel_missing_from_the_cache_is_added_both_ways():
    tak = FakeTak(_old_cache())
    res, log = _sync(_ns(tak))
    assert len(tak.puts) == 1, 'one activeForce PUT, then the second pass sees it converged'
    rapid = [e for e in tak.puts[0] if e['name'] == 'RAPID-SOS']
    assert rapid == [_grp('RAPID-SOS', 'IN', 22), _grp('RAPID-SOS', 'OUT', 22)], \
        'added IN and OUT active, with the bitpos TAK gave it'
    assert res['added'] == 2 and res['activated'] == 0 and res['changed'] is True
    assert 'RAPID-SOS' in _deliverable(tak), 'activeForce re-authenticated the live connection'
    assert tak.reauths == 0 and res['reauth'] is False, 'no second re-auth needed'
    assert any('RAPID-SOS' in m for m in log)


def test_inactive_entries_are_activated_in_both_directions():
    """The nuc / test12 trap: a channel created after first connect lands in the cache inactive
    both ways. IN is what decides delivery, so leaving it off (the first cut of this fix) did not
    deliver a single Event on test12."""
    cache = _old_cache() + [_grp('RAPID-SOS', 'OUT', 22, active=False), _grp('RAPID-SOS', 'IN', 22, active=False)]
    tak = FakeTak(cache)
    res, log = _sync(_ns(tak))
    assert res['activated'] == 2 and res['added'] == 0
    body = {(e['name'], e['direction']): e['active'] for e in tak.puts[0]}
    assert body[('RAPID-SOS', 'IN')] is True and body[('RAPID-SOS', 'OUT')] is True
    assert 'RAPID-SOS' in _deliverable(tak)
    assert any('RAPID-SOS' in m and 'activated 2' in m for m in log)


def test_only_the_in_entry_inactive_is_still_fixed():
    """OUT active alone is not enough: test12, IN off / OUT on, the Event never arrived."""
    cache = _old_cache() + [_grp('RAPID-SOS', 'OUT', 22), _grp('RAPID-SOS', 'IN', 22, active=False)]
    tak = FakeTak(cache)
    res, _ = _sync(_ns(tak))
    assert res['activated'] == 1 and len(tak.puts) == 1
    assert {(e['name'], e['direction']): e['active'] for e in tak.puts[0]}[('RAPID-SOS', 'IN')] is True


def test_never_shrinks_the_cache():
    """An entry for a channel no longer in /groups/all is passed back, not dropped."""
    cache = _old_cache() + [_grp('OLD CHAN', 'OUT', 9, active=False)]
    tak = FakeTak(cache)
    _sync(_ns(tak))
    names = {(e['name'], e['direction']) for e in tak.puts[0]}
    assert {(e['name'], e['direction']) for e in cache} <= names


def test_already_converged_is_a_no_op_no_put_no_reauth_no_restart():
    cache = _old_cache() + [_grp('RAPID-SOS', 'OUT', 22), _grp('RAPID-SOS', 'IN', 22)]
    tak = FakeTak(cache)
    res, log = _sync(_ns(tak))
    assert tak.puts == [] and tak.reauths == 0 and res['changed'] is False
    assert any('no change' in m for m in log)
    assert 'docker' not in _func('_tak_sync_bootstrap_group_cache'), 'the sync never restarts CloudTAK'


def test_system_groups_are_never_added_or_activated():
    tak = FakeTak([_grp('MPD Main', 'OUT', 4), _grp('MPD Main', 'IN', 4), _grp('__ANON__', 'IN', 3, active=False)])
    _sync(_ns(tak))
    assert {e['name'] for e in tak.puts[0]} - {'MPD Main', '__ANON__'} == {'RAPID-SOS'}, \
        'ROLE_ADMIN / __ANON__ are not channels'
    assert [e['active'] for e in tak.puts[0] if e['name'] == '__ANON__'] == [False], 'passed back unchanged'


def test_cache_disabled_still_fixes_the_live_connection():
    tak = FakeTak([], live=[('MPD Main', 'OUT')], enabled=False)
    res, _ = _sync(_ns(tak))
    assert tak.puts == [] and tak.reauths == 1 and 'RAPID-SOS' in _deliverable(tak)


# ---------------------------------------------------------------- step 2: the live connection

def test_uncached_cert_missing_a_later_channel_is_reauthenticated_in_place():
    """test8: no cache entry, live subscription lacks the newest channel."""
    tak = FakeTak([], live=_both('MPD Main'))
    res, log = _sync(_ns(tak))
    assert tak.puts == [], 'nothing cached, nothing to force'
    assert tak.reauths == 1 and res['reauth'] is True and res['missing'] == []
    assert 'RAPID-SOS' in _deliverable(tak)
    assert any('re-authenticated' in m and 'now in all' in m for m in log)


def test_reauth_that_does_not_help_says_so():
    tak = FakeTak([], live=_both('MPD Main'), stuck=True)
    res, log = _sync(_ns(tak))
    assert tak.reauths == 1 and res['missing'] == ['RAPID-SOS']
    assert any('still missing' in m and 'next sync' in m for m in log)


def test_uncached_and_already_in_every_channel_does_nothing():
    tak = FakeTak([], live=_both('MPD Main', 'RAPID-SOS'))
    res, _ = _sync(_ns(tak))
    assert tak.puts == [] and tak.reauths == 0 and res['changed'] is False


def test_not_connected_is_never_reauthenticated():
    tak = FakeTak([], connected=False)
    res, _ = _sync(_ns(tak))
    assert tak.reauths == 0 and res['changed'] is False


# ---------------------------------------------------------------- no-op rules

def test_cloudtak_bootstrap_cert_absent_makes_no_marti_call():
    tak = FakeTak(_old_cache())
    res, _ = _sync(_ns(tak, files=('/opt/tak/CoreConfig.xml',)))
    assert tak.calls == [] and res['changed'] is False


def test_bootstrap_found_by_its_uaf_entry_when_the_p12_is_not_on_disk():
    tak = FakeTak(_old_cache())
    _sync(_ns(tak, files=('/opt/tak/CoreConfig.xml',), uaf=f'<User identifier="{CN}" role="ROLE_ADMIN">'))
    assert len(tak.puts) == 1


def test_no_tak_on_this_box_is_a_no_op():
    tak = FakeTak(_old_cache())
    _sync(_ns(tak, files=()))
    assert tak.calls == []


def test_tak_down_changes_nothing():
    tak = FakeTak(_old_cache(), down=True)
    res, _ = _sync(_ns(tak))
    assert tak.puts == [] and tak.reauths == 0 and res['changed'] is False


def test_failed_channel_list_read_changes_nothing():
    tak = FakeTak(_old_cache(), live=[], all_fails=True)
    res, _ = _sync(_ns(tak))
    assert tak.puts == [] and tak.reauths == 0 and res['changed'] is False


def test_split_box_with_a_remote_tak_core_logs_once_and_skips():
    tak = FakeTak(_old_cache())
    ns = _ns(tak, mode='remote')
    _, log1 = _sync(ns)
    _, log2 = _sync(ns)
    assert tak.calls == []
    assert len(log1) == 1 and 'split-box' in log1[0] and log2 == []


def test_split_box_with_tak_on_this_box_is_synced():
    """test8's layout: two_server, but TAK is local and only Postgres is remote — Marti is here."""
    tak = FakeTak([], live=[('MPD Main', 'OUT')])
    _sync(_ns(tak, mode='local'))
    assert tak.reauths == 1


# ---------------------------------------------------------------- the detector

def _state(tak, **kw):
    return _ns(tak, **kw)['_tak_bootstrap_channel_state']()


def test_detector_names_the_channel_the_live_subscription_lacks():
    tak = FakeTak([], live=_both('MPD Main'))
    tak.extra_subs = [_sub('tls:30', _both('RAPID-SOS'), user='someone-else')]
    s = _state(tak)
    assert s['state'] == 'missing' and s['missing'] == ['RAPID-SOS'] and s['connected'] is True
    assert s['channels'] == 2


def test_detector_ok_when_every_channel_is_there_both_ways():
    assert _state(FakeTak([], live=_both('MPD Main', 'RAPID-SOS')))['state'] == 'ok'


def test_detector_flags_a_channel_present_out_only():
    """test12 2026-10-20: the first cut of this fix left the connection OUT-only on the new channel;
    the detector said ok and not one Event was delivered. IN is the one that decides it."""
    assert _state(FakeTak([], live=_both('MPD Main') + [('RAPID-SOS', 'OUT')]))['missing'] == ['RAPID-SOS']
    assert _state(FakeTak([], live=_both('MPD Main') + [('RAPID-SOS', 'IN')]))['missing'] == ['RAPID-SOS']


def test_detector_judges_the_newest_subscription():
    tak = FakeTak([], live=_both('MPD Main'))
    tak.uid = 12
    tak.extra_subs = [_sub('tls:9', _both('MPD Main', 'RAPID-SOS'))]
    assert _state(tak)['missing'] == ['RAPID-SOS']


def test_detector_quiet_states():
    assert _state(FakeTak([], connected=False))['state'] == 'disconnected'
    assert _state(FakeTak([], down=True))['state'] == 'unknown'
    assert _state(FakeTak([]), files=('/opt/tak/CoreConfig.xml',))['state'] == 'absent'
    assert _state(FakeTak([]), mode='remote')['state'] == 'absent'


def test_fix_then_detector_agree_on_the_nuc_case():
    tak = FakeTak(_old_cache())
    ns = _ns(tak)
    assert ns['_tak_bootstrap_channel_state']()['missing'] == ['RAPID-SOS']
    ns['_tak_sync_bootstrap_group_cache'](plog=lambda m: None)
    assert ns['_tak_bootstrap_channel_state']()['state'] == 'ok'


def test_fix_then_detector_agree_on_the_test12_case():
    """New channel cached inactive both ways: flagged before, delivered (IN and OUT live) after."""
    tak = FakeTak(_old_cache() + [_grp('RAPID-SOS', 'OUT', 22, active=False), _grp('RAPID-SOS', 'IN', 22, active=False)])
    ns = _ns(tak)
    assert ns['_tak_bootstrap_channel_state']()['missing'] == ['RAPID-SOS']
    ns['_tak_sync_bootstrap_group_cache'](plog=lambda m: None)
    assert ns['_tak_bootstrap_channel_state']()['state'] == 'ok' and 'RAPID-SOS' in _deliverable(tak)


# ---------------------------------------------------------------- wiring

def test_runs_everywhere_the_admin_sync_runs():
    for fn in ('_takportal_mapsync_watchdog_loop', '_takportal_sync_certs', 'cloudtak_bootstrap_channels_fix_api'):
        assert '_tak_sync_bootstrap_group_cache(' in _func(fn), fn
    assert APP.count('_tak_sync_bootstrap_group_cache(') >= 5, \
        'watchdog, cert resync, TAK Portal deploy, startup and the Fix now route'


def test_watchdog_reacts_to_a_channel_change_within_a_minute():
    src = _func('_takportal_mapsync_watchdog_loop')
    assert '_wt.sleep(60)' in src and '_wt.sleep(600)' not in src
    assert '_tak_channel_items()' in src and '_last_channels' in src
    assert 'takportal_mapsync_disabled' in src, 'the kill switch still covers it'


def test_routes_require_login():
    for path in ("'/api/cloudtak/bootstrap-channels'", "'/api/cloudtak/bootstrap-channels/fix'"):
        i = APP.index(f'@app.route({path}')
        assert '@login_required' in APP[i:i + 200], path


def test_cloudtak_page_shows_the_warning_with_a_fix_button():
    i = APP.index("CLOUDTAK_PAGE_JS = r'''")
    js = APP[i:APP.index("'''", i + 30)]
    assert "fetch('/api/cloudtak/bootstrap-channels'" in js
    assert "'/api/cloudtak/bootstrap-channels/fix'" in js and 'Fix now' in js
