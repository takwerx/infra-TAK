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
"""New-user enrollment race — the root cause of ops #565 (nuc 2026-11-09).

TAK Portal created testdev2fire at 10:24:24; the phone enrolled at 10:26:31 and connected to
8089 at 10:26:34. The LDAP outpost (search_mode: cached) had not reloaded its copy of the
directory yet, so TAK's lookup found no entry: the connection got no user and no groups and
kept none, because TAK looks a streaming connection up only when it connects.

The console now watches Authentik's users and tak_ groups, saves the LDAP outpost unchanged on
a change (which makes it reload), confirms LDAP answers, and then drops connections TAK gave no
user and no groups so they reconnect. The fake below models the outpost's stale copy.
"""

import types
import urllib

from test_tak_ldap_recycle import _const, _src

T0 = 1_800_000_000.0
RELOAD_S = 4          # nuc: new user visible in LDAP 4.2 s after the PATCH
API = 'https://127.0.0.1:8443/Marti/api'


class Fake:
    def __init__(self, users):
        self.t = T0
        self.db = dict(users)              # Authentik's database: user -> set of tak_ groups (no prefix)
        self.copy = dict(users)            # what the outpost answers from
        self.reload_at = None
        self.patches = []
        self.subs = []                     # TAK connections
        self.deleted = []
        self.log = []
        self.update = False
        self.db_up = True
        self.patch_ok = True

    # Authentik
    def snapshot(self):
        return {u: frozenset(g) for u, g in self.db.items()} if self.db_up else None

    def refresh(self, plog):
        if not self.patch_ok:
            return False
        self.patches.append(self.t)
        self.reload_at = self.t + RELOAD_S
        return True

    def ldap(self, pw, cns):
        if self.reload_at is not None and self.t >= self.reload_at:
            self.copy, self.reload_at = dict(self.db), None
        return {c: sorted(self.copy[c]) for c in cns if c in self.copy}

    # TAK
    def connect(self, uid, client, user):
        """TAK looks the user up once, at connect, in the outpost's copy."""
        self.ldap(None, [])
        known = user in self.copy
        self.subs.append({'uid': uid, 'client': client, 'callsign': client or uid, 'cn': user if known else '',
                          'username': user if known else None, 'unnamed': not known,
                          'groups': set(self.copy.get(user, ())), 'user': user})

    def sessions(self):
        return [dict(s) for s in self.subs]

    def marti(self, url, timeout=20, method='GET'):
        uid = urllib.parse.unquote(url.rsplit('/', 1)[-1])
        self.deleted.append(uid)
        gone = [s for s in self.subs if s['uid'] == uid]
        self.subs = [s for s in self.subs if s['uid'] != uid]
        for s in gone:      # the client comes straight back and is looked up again
            self.connect(uid + 'r', s['client'], s['user'])
        return {}, None

    def sleep(self, s):
        self.t += s


def watch(fake):
    ns = {
        'os': types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: True)),
        'time': types.SimpleNamespace(time=lambda: fake.t, sleep=fake.sleep),
        'urllib': urllib,
        '_console_update_in_progress': lambda: fake.update,
        '_ak_directory_snapshot': fake.snapshot,
        '_ak_refresh_ldap_outposts': fake.refresh,
        '_ldap_users_tak_groups': fake.ldap,
        '_get_authentik_env_value': lambda s, k: 'sa-pass',
        'load_settings': lambda: {},
        '_coreconfig_has_ldap': lambda: True,
        '_tak_client_sessions': fake.sessions,
        '_tak_admin_marti_req': fake.marti,
        '_TAK_MARTI_API': API,
        '_subscription_num': lambda uid: int(''.join(ch for ch in uid if ch.isdigit()) or -1),
        '_tak_stuck_unnamed_seen': {},
        '_tak_stuck_unnamed_dropped': {},
        '_ak_dir_watch': {'snap': None, 'pending': set(), 'last_refresh': 0.0, 'confirmed_at': 0.0, 'drops': {}},
    }
    for c in ('_AK_DIR_REFRESH_MIN_GAP_S', '_AK_DIR_REFRESH_GAP_PER_USER_MS', '_AK_DIR_REFRESH_MAX_GAP_S',
              '_AK_DIR_CONFIRM_WAIT_S', '_AK_DIR_DROP_WINDOW_S',
              '_AK_DIR_DROP_COOLDOWN_S', '_AK_DIR_DROP_MAX'):
        ns[c] = _const(c)
    ns['re'] = __import__('re')
    exec(compile(_src('_ak_log_names'), 'app.py:_ak_log_names', 'exec'), ns)
    exec(compile(_src('_ak_directory_watch_tick'), 'app.py:_ak_directory_watch_tick', 'exec'), ns)
    tick_s = _const('_AK_DIR_WATCH_TICK_S')

    def tick(dt=tick_s):
        fake.t += dt
        return ns['_ak_directory_watch_tick'](fake.log.append)
    return tick, ns


def base():
    return Fake({'e-1fire': {'FIRE1 OPS'}, 'webadmin': set()})


def test_first_read_after_start_is_not_a_change():
    fake = base()
    tick, _ = watch(fake)
    assert tick(0)['refreshed'] == []
    assert tick()['refreshed'] == [] and fake.patches == []


def test_no_change_means_no_patch_and_no_tak_reads():
    fake = base()
    tick, _ = watch(fake)
    calls = []
    fake.sessions = lambda: calls.append(1) or []
    tick(0)
    tick, ns = watch(fake)
    ns['_tak_client_sessions'] = fake.sessions
    for _ in range(120):          # 30 min idle
        tick()
    assert fake.patches == [] and calls == []


def test_the_nuc_race_phone_connects_before_the_reload_and_gets_its_channels():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    fake.db['testdev2fire'] = {'FIRE1 Main', 'FIRE1 OPS'}       # TAK Portal creates the user
    fake.connect('tls:80', 'ANDROID-6dc85d2378997ddd', 'testdev2fire')  # scanned at once
    [s] = fake.subs
    assert s['unnamed'] and not s['groups']                     # the bug: nothing to send it
    did = tick()
    assert did['refreshed'] == ['testdev2fire'] and did['confirmed']
    assert len(fake.patches) == 1
    assert did['dropped'] == ['tls:80']
    [now] = fake.subs
    assert now['username'] == 'testdev2fire' and now['groups'] == {'FIRE1 Main', 'FIRE1 OPS'}
    assert any('LDAP outpost refreshed' in l for l in fake.log)


def test_phone_that_connects_after_the_reload_is_left_alone():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    fake.db['newuser'] = {'FIRE1 OPS'}
    tick()
    fake.connect('tls:90', 'ANDROID-aa', 'newuser')
    did = tick()
    assert did['dropped'] == [] and fake.deleted == []
    assert fake.subs[0]['groups'] == {'FIRE1 OPS'}


def test_group_added_later_is_a_change_too():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    fake.db['e-1fire'] = {'FIRE1 OPS', 'FIRE1 Main'}
    did = tick()
    assert did['refreshed'] == ['e-1fire'] and did['confirmed']


def test_group_removed_waits_until_ldap_no_longer_shows_it():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    fake.db['e-1fire'] = set()
    did = tick()
    assert did['confirmed'] and fake.copy['e-1fire'] == set()


def test_a_burst_of_users_is_one_patch():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    for i in range(30):
        fake.db[f'bulk{i}'] = {'FIRE1 OPS'}
    did = tick()
    assert len(did['refreshed']) == 30 and len(fake.patches) == 1


def test_changes_inside_the_min_gap_wait_for_the_next_refresh():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    fake.db['a'] = {'X'}
    tick()
    p = len(fake.patches)
    fake.db['b'] = {'X'}
    fake.t = fake.patches[-1] + 1        # straight after the first refresh
    did = tick(0)
    assert did['refreshed'] == [] and len(fake.patches) == p
    fake.t = fake.patches[-1] + _const('_AK_DIR_REFRESH_MIN_GAP_S') - 1
    assert tick(0)['refreshed'] == []           # one second short of the gap
    assert tick(1)['refreshed'] == ['b']


def test_user_ldap_never_finds_is_dropped_at_most_twice_then_left():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    fake.db['x'] = {'FIRE1 OPS'}
    fake.connect('tls:5', 'ANDROID-ghost', 'deleted-user')    # cert of a user not in the directory
    for _ in range(60):
        tick()
    assert sum(1 for d in fake.deleted) == 2


def test_no_drops_after_the_window():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    fake.db['x'] = {'FIRE1 OPS'}
    tick()
    fake.t += _const('_AK_DIR_DROP_WINDOW_S')
    fake.connect('tls:7', 'ANDROID-late', 'deleted-user')
    assert tick()['dropped'] == []


def test_patch_failure_retries_next_tick():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    fake.db['x'] = {'FIRE1 OPS'}
    fake.patch_ok = False
    assert tick()['refreshed'] == []
    fake.patch_ok = True
    assert tick()['refreshed'] == ['x']


def test_ldap_never_catches_up_opens_no_drop_window():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    fake.db['x'] = {'FIRE1 OPS'}
    fake.refresh = lambda plog: fake.patches.append(fake.t) or True   # outpost never reloads
    tick, ns = watch(fake)
    ns['_ak_dir_watch']['snap'] = {'e-1fire': frozenset({'FIRE1 OPS'}), 'webadmin': frozenset()}
    fake.connect('tls:3', 'ANDROID-b', 'x')
    did = tick()
    assert not did['confirmed'] and did['dropped'] == [] and fake.deleted == []
    assert any("didn't show it" in l for l in fake.log)


def test_nothing_during_a_console_update():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    fake.db['x'] = {'FIRE1 OPS'}
    fake.update = True
    assert tick() == {'refreshed': [], 'confirmed': False, 'dropped': []}
    assert fake.patches == []


def test_no_authentik_database_is_idle():
    fake = base()
    fake.db_up = False
    tick, _ = watch(fake)
    for _ in range(5):
        assert tick()['refreshed'] == []
    assert fake.patches == []


def test_snapshot_reads_json_so_no_name_can_split_a_row():
    """nuc: str.splitlines() split on chr(30) and turned every row into nothing; names may hold any
    character, so the query returns one JSON object."""
    import json as _json
    import subprocess
    raw = _json.dumps({'miketestfire': ['tak_FIRE1 Main', 'tak_FIRE1 OPS'], 'adm_ldapservice': [],
                       'odd\nname\x1e': ['tak_MA - Man HUNT', 'authentik Admins']}) + '\n'
    seen = {}

    def run(cmd, **kw):
        seen.update(kw)
        return types.SimpleNamespace(returncode=0, stdout=raw)
    ns = {'subprocess': types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired,
                                              DEVNULL=subprocess.DEVNULL),
          '_sudo_wrap': lambda c: c, 'json': _json}
    exec(compile(_src('_ak_directory_snapshot'), 'app.py:_ak_directory_snapshot', 'exec'), ns)
    snap = ns['_ak_directory_snapshot']()
    assert snap == {'miketestfire': frozenset({'FIRE1 Main', 'FIRE1 OPS'}), 'adm_ldapservice': frozenset(),
                    'odd\nname\x1e': frozenset({'MA - Man HUNT'})}
    assert seen.get('stdin') == subprocess.DEVNULL      # the broker shim waits on an open stdin
    raw = 'not json'
    assert ns['_ak_directory_snapshot']() is None


def test_big_directory_waits_longer_between_reloads():
    """1,000 users: a reload costs ~9 s of Authentik API time, so reloads are >= 100 s apart."""
    fake = Fake({f'u{i}': {'OPS'} for i in range(1000)})
    tick, _ = watch(fake)
    tick(0)
    fake.db['new1'] = {'OPS'}
    assert tick()['refreshed'] == ['new1']
    first = fake.patches[-1]
    fake.db['new2'] = {'OPS'}
    while fake.t + _const('_AK_DIR_WATCH_TICK_S') - first < 100:
        assert tick()['refreshed'] == []
    fake.t = first + 100
    assert tick(0)['refreshed'] == ['new2']


def test_huge_directory_gap_is_capped_at_the_outposts_own_refresh():
    fake = Fake({f'u{i}': {'OPS'} for i in range(20000)})
    tick, _ = watch(fake)
    tick(0)
    fake.db['a'] = {'OPS'}
    tick()
    first = fake.patches[-1]
    fake.db['b'] = {'OPS'}
    fake.t = first + _const('_AK_DIR_REFRESH_MAX_GAP_S')
    assert tick(0)['refreshed'] == ['b']


def test_unhealthy_authentik_gets_no_patch():
    """_ak_refresh_ldap_outposts: /-/health/ready/ not answering -> no list, no PATCH."""
    calls = []

    def api(url, data=None, method='GET', headers=None, max_retries=3, timeout=15):
        calls.append((method, url))
        raise OSError('connection refused')
    ns = {'load_settings': lambda: {}, '_get_authentik_env_value': lambda s, k: 'tok',
          '_get_authentik_api_url': lambda s: 'http://127.0.0.1:9090', '_ak_api_call': api, 'json': __import__('json')}
    exec(compile(_src('_ak_refresh_ldap_outposts'), 'app.py:_ak_refresh_ldap_outposts', 'exec'), ns)
    assert ns['_ak_refresh_ldap_outposts'](lambda m: None) is False
    assert calls == [('GET', 'http://127.0.0.1:9090/-/health/ready/')]


def test_only_removals_open_no_drop_window():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    del fake.db['e-1fire']
    fake.connect('tls:9', 'ANDROID-ghost', 'deleted-user')
    did = tick()
    assert did['refreshed'] == ['e-1fire'] and not did['confirmed'] and did['dropped'] == []
    assert fake.deleted == []


def test_repeated_changes_do_not_reset_the_drop_limit():
    """An admin editing a membership every 20 s must not keep dropping the same clients."""
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    fake.connect('tls:5', 'ANDROID-ghost', 'deleted-user')
    for i in range(40):                     # ~10 min of changes, every tick
        fake.db['e-1fire'] = {'FIRE1 OPS'} if i % 2 else {'FIRE1 OPS', 'FIRE1 Main'}
        tick()
    assert len(fake.deleted) == 2


def test_names_in_logs_cannot_forge_lines():
    fake = base()
    tick, _ = watch(fake)
    tick(0)
    fake.db['evil\n[ak-directory-watch] forged'] = {'FIRE1 OPS'}
    tick()
    assert all('\n' not in l for l in fake.log)
