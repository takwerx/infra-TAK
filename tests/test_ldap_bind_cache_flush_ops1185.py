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
"""A refused LDAP sign-in stays refused after the reason is gone (ops #1185, nuc 2026-11-24).

The LDAP outpost (bind_mode: cached) keeps every bind result per name and password, refusals too,
and an entry for a name with no good sign-in in the last hour never expires. So a user whose account
was disabled and is enabled again, or whose password is set to a value tried before, stays refused
with the CORRECT password until the outpost restarts. The console now saves the LDAP provider with
bind_mode direct and then cached again when it sees such a change; the outpost builds a new cache
only when the binder type changes, so this clears every entry with no restart.

The fake outpost below follows the upstream source (memory.go: a SessionBinder is rebuilt, and its
cache emptied, only when the old binder is not a SessionBinder) and nuc: it applies a provider save
about 6 s after it, reading the provider as it is THEN, and logs 'initialized direct binder' for a
new direct binder and for a new cache.
"""

import json
import re
import types

from test_tak_ldap_recycle import APP, _const, _src

T0 = 1_800_000_000.0
APPLY_S = 6


class Outpost:
    """Authentik's provider row, the outpost's binder and its bind cache, one fake clock."""

    def __init__(self):
        self.t = T0
        self.users = {}              # name -> [is_active, password]
        self.db_mode = 'cached'      # the provider row in Authentik
        self.mode = 'cached'         # what the outpost applied
        self.cache = {}              # (name, password) -> result code
        self.applies = []            # times the outpost will re-read the provider
        self.inits = []              # times it logged 'initialized direct binder'
        self.saves = []              # (time, bind_mode) of every provider save
        self.settings = {}
        self.api_down = False
        self.apply_never = False
        self.snapshot_ok = True

    # time
    def sleep(self, s):
        self.t += s
        due = [a for a in self.applies if a <= self.t]
        self.applies = [a for a in self.applies if a > self.t]
        for _ in due:
            self.apply()

    def apply(self):
        if self.apply_never or self.db_mode == self.mode:
            return                                    # same type: the old cache is kept
        self.mode = self.db_mode
        self.cache = {}                               # a new binder, a new cache
        self.inits.append(self.t)

    # Authentik API
    def api(self, url, data=None, method='GET', headers=None, max_retries=3, timeout=15):
        if self.api_down:
            raise OSError('Authentik is down')
        if url.endswith('/-/health/ready/'):
            return Resp(200, b'')
        if '/api/v3/providers/ldap/?' in url:
            return Resp(200, json.dumps({'results': [{'pk': 2, 'bind_mode': self.db_mode}]}).encode())
        m = re.search(r'/providers/ldap/(\d+)/$', url)
        if m and method == 'PATCH':
            body = json.loads(data.decode())
            self.db_mode = body['bind_mode']
            self.saves.append((self.t, self.db_mode))
            self.applies.append(self.t + APPLY_S)
            return Resp(200, b'{}')
        raise AssertionError(f'unexpected call {method} {url}')

    def built(self, since):
        return sum(1 for t in self.inits if t >= int(since))

    # a client
    def bind(self, name, password):
        if self.mode == 'cached' and (name, password) in self.cache:
            return self.cache[(name, password)]
        active, real = self.users[name]
        rc = 0 if active and password == real else 49
        if self.mode == 'cached':
            self.cache[(name, password)] = rc
        return rc

    # Authentik's database, as the console reads it
    def snapshot(self):
        if not self.snapshot_ok:
            return None
        return {n: (bool(a), f'pw{ver}') for n, (a, _pw, ver) in self.db.items()}


class Resp:
    def __init__(self, status, body):
        self.status, self._b = status, body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def world(users):
    """users: {name: (is_active, password)}. Returns (outpost, tick, ns)."""
    o = Outpost()
    o.users = {n: list(v) for n, v in users.items()}
    o.versions = {n: 0 for n in users}
    o.db = {n: [v[0], v[1], 0] for n, v in users.items()}
    o.busy = ''
    o.update = False
    o.log = []
    ns = {
        'json': json,
        'time': types.SimpleNamespace(time=lambda: o.t, sleep=o.sleep),
        '_ak_api_call': o.api,
        'load_settings': lambda: json.loads(json.dumps(o.settings)),
        'save_settings': lambda s: o.settings.update(json.loads(json.dumps(s))),
        '_get_authentik_env_value': lambda s, k: 'token',
        '_get_authentik_api_url': lambda s: 'http://ak',
        '_console_update_in_progress': lambda: o.update,
        '_authentik_busy_reason': lambda: o.busy,
        '_ak_ldap_binders_built': o.built,
        '_ak_user_credential_snapshot': o.snapshot,
        '_ak_log_names': lambda names, n=10: ', '.join(names[:n]),
    }
    for c in ('_AK_LDAP_CACHE_FLUSH_MIN_GAP_S', '_AK_LDAP_CACHE_APPLY_WAIT_S', '_AK_LDAP_CACHE_FLUSH_TRIES'):
        ns[c] = _const(c)
    ns['_ak_ldap_cache_watch'] = {'snap': None, 'pending': set(), 'last_flush': 0.0, 'tries': 0}
    for f in ('_ak_ldap_cache_changed_users', '_ak_ldap_set_bind_mode', '_ak_ldap_flush_state',
              '_ak_flush_ldap_bind_cache', '_ak_ldap_cache_watch_tick'):
        exec(compile(_src(f), f'app.py:{f}', 'exec'), ns)

    def tick(dt=15):
        o.sleep(dt)
        return ns['_ak_ldap_cache_watch_tick'](o.log.append)
    return o, tick, ns


def disable(o, name):
    o.users[name][0] = False
    o.db[name][0] = False


def enable(o, name):
    o.users[name][0] = True
    o.db[name][0] = True


def set_password(o, name, pw):
    o.users[name][1] = pw
    o.db[name][1] = pw
    o.db[name][2] += 1


# ---- the customer's two cases -------------------------------------------------------------

def test_disabled_then_enabled_user_signs_in_with_the_right_password():
    """The proof test. Without the watch the user stays refused (control, first half)."""
    o, tick, _ = world({'alice': (True, 'right-one')})
    tick(0)                                        # baseline read
    disable(o, 'alice')
    tick()
    assert o.bind('alice', 'right-one') == 49      # the phone tries while the account is off
    enable(o, 'alice')
    assert o.bind('alice', 'right-one') == 49      # stuck: the outpost remembers the refusal
    did = tick()
    assert did is True and o.saves[-2][1] == 'direct' and o.saves[-1][1] == 'cached'
    assert o.bind('alice', 'right-one') == 0       # works again
    assert any('LDAP sign-in cache flushed' in l and 'alice' in l for l in o.log)


def test_password_set_to_a_value_tried_before_works_after_the_flush():
    o, tick, _ = world({'bob': (True, 'old-pass')})
    tick(0)
    assert o.bind('bob', 'Winter2026!') == 49      # the user guesses
    set_password(o, 'bob', 'Winter2026!')           # the admin sets exactly that
    assert o.bind('bob', 'Winter2026!') == 49       # stuck
    assert tick() is True
    assert o.bind('bob', 'Winter2026!') == 0


def test_without_the_flush_the_refusal_never_ends_control():
    """Model check: the fake outpost really keeps the entry for ever, so the tests above prove the flush."""
    o, _tick, _ = world({'carol': (True, 'pw')})
    disable(o, 'carol')
    assert o.bind('carol', 'pw') == 49
    enable(o, 'carol')
    for _ in range(40):
        o.sleep(600)
        assert o.bind('carol', 'pw') == 49


def test_the_flush_does_not_restart_or_leave_direct_mode():
    o, tick, ns = world({'dan': (True, 'x')})
    tick(0)
    disable(o, 'dan')
    tick()
    enable(o, 'dan')
    tick()
    assert o.db_mode == 'cached' and o.mode == 'cached'
    assert [m for _t, m in o.saves] == ['direct', 'cached']
    assert o.settings.get('ak_ldap_cache_flush') in (None, {})      # nothing left to undo


# ---- when it must stay quiet ---------------------------------------------------------------

def test_first_read_after_start_is_not_a_change_and_idle_boxes_are_left_alone():
    o, tick, _ = world({'e': (True, 'p'), 'f': (False, 'q')})
    assert tick(0) is False
    for _ in range(240):                              # an hour idle
        assert tick() is False
    assert o.saves == []


def test_new_users_and_removed_users_are_not_a_reason():
    o, tick, _ = world({'g': (True, 'p')})
    tick(0)
    o.db['newbie'] = [True, 'x', 0]
    o.users['newbie'] = [True, 'x']
    assert tick() is False
    del o.db['g']
    assert tick() is False
    assert o.saves == []


def test_a_disabled_user_and_a_password_set_while_disabled_wait_for_the_enable():
    o, tick, _ = world({'h': (True, 'p')})
    tick(0)
    disable(o, 'h')
    assert tick() is False
    set_password(o, 'h', 'brand-new')
    assert tick() is False
    assert o.saves == []
    enable(o, 'h')
    assert tick() is True


def test_nothing_runs_during_a_console_update_or_an_authentik_update():
    o, tick, _ = world({'i': (True, 'p')})
    tick(0)
    disable(o, 'i')
    tick()
    enable(o, 'i')
    o.update = True
    assert tick() is False and o.saves == []
    o.update, o.busy = False, 'an Authentik update is in progress'
    assert tick() is False and o.saves == []
    o.busy = ''
    assert tick() is True            # the change was kept, not lost


def test_a_burst_of_changes_is_one_flush_and_the_gap_is_kept():
    o, tick, ns = world({f'u{i}': (True, 'p') for i in range(20)})
    tick(0)
    for i in range(20):
        set_password(o, f'u{i}', 'new')
    assert tick() is True
    assert len(o.saves) == 2
    set_password(o, 'u3', 'again')
    assert tick() is False and len(o.saves) == 2                 # inside the gap
    o.t += _const('_AK_LDAP_CACHE_FLUSH_MIN_GAP_S')
    assert tick() is True and len(o.saves) == 4


# ---- when Authentik or the outpost does not answer -----------------------------------------

def test_outpost_that_never_applies_gets_bind_mode_cached_back_and_the_change_is_retried_then_dropped():
    o, tick, ns = world({'j': (True, 'p')})
    tick(0)
    disable(o, 'j')
    tick()
    enable(o, 'j')
    o.apply_never = True
    tries = _const('_AK_LDAP_CACHE_FLUSH_TRIES')
    for n in range(tries):
        o.t += _const('_AK_LDAP_CACHE_FLUSH_MIN_GAP_S')
        assert tick() is False
        assert o.db_mode == 'cached'                       # never left in direct mode
    assert any('gave up' in l for l in o.log)
    assert ns['_ak_ldap_cache_watch']['pending'] == set()
    saves = len(o.saves)
    o.t += 600
    assert tick() is False and len(o.saves) == saves       # dropped: no more tries


def test_authentik_api_down_changes_nothing():
    o, tick, _ = world({'k': (True, 'p')})
    tick(0)
    disable(o, 'k')
    tick()
    enable(o, 'k')
    o.api_down = True
    assert tick() is False and o.saves == [] and o.db_mode == 'cached'


def test_database_unreadable_means_no_decision():
    o, tick, _ = world({'l': (True, 'p')})
    tick(0)
    o.snapshot_ok = False
    assert tick() is False and o.saves == []


def test_console_restart_in_the_middle_puts_bind_mode_back():
    o, tick, ns = world({'m': (True, 'p')})
    tick(0)
    o.db_mode = 'direct'                                    # the console died after the first save
    o.settings['ak_ldap_cache_flush'] = {'restore': [2], 'started': o.t}
    tick()
    assert o.db_mode == 'cached'
    assert not o.settings.get('ak_ldap_cache_flush')


def test_provider_already_direct_has_no_cache_to_flush():
    o, tick, _ = world({'n': (True, 'p')})
    o.db_mode = o.mode = 'direct'
    tick(0)
    disable(o, 'n')
    tick()
    enable(o, 'n')
    assert tick() is False and o.saves == []


# ---- the pieces that read the box ----------------------------------------------------------

def _snapshot_fn(stdout, rc=0):
    ns = {'json': json, '_sudo_wrap': lambda c: c,
          'subprocess': types.SimpleNamespace(
              run=lambda *a, **k: types.SimpleNamespace(returncode=rc, stdout=stdout, stderr=''),
              DEVNULL=None, TimeoutExpired=TimeoutError)}
    exec(compile(_src('_ak_user_credential_snapshot'), 'app.py:snap', 'exec'), ns)
    return ns['_ak_user_credential_snapshot']


def test_snapshot_reads_active_flag_and_password_date():
    out = json.dumps({'a': [True, '2026-11-24 09:30:46.9+00'], 'b': [False, 'None']})
    assert _snapshot_fn(out)() == {'a': (True, '2026-11-24 09:30:46.9+00'), 'b': (False, 'None')}


def test_snapshot_gives_none_when_the_database_cannot_be_read():
    assert _snapshot_fn('', rc=1)() is None
    assert _snapshot_fn('not json')() is None
    assert _snapshot_fn('[]')() is None


def _built_fn(stdout, rc=0):
    seen = []
    ns = {'_sudo_wrap': lambda c: c,
          'subprocess': types.SimpleNamespace(
              run=lambda cmd, **k: seen.append(cmd) or types.SimpleNamespace(returncode=rc, stdout=stdout, stderr=''),
              DEVNULL=None, TimeoutExpired=TimeoutError)}
    exec(compile(_src('_ak_ldap_binders_built'), 'app.py:built', 'exec'), ns)
    return ns['_ak_ldap_binders_built'], seen


def test_binder_count_reads_the_outpost_log_since_the_start_time():
    lines = '\n'.join(['{"event":"initialized direct binder","level":"info"}',
                       '{"event":"Bind request","level":"info"}',
                       '{"event":"initialized direct binder","level":"info"}'])
    fn, seen = _built_fn(lines)
    assert fn(1_800_000_000.7) == 2
    assert seen[0][:3] == ['docker', 'logs', '--since'] and seen[0][3] == '1800000000' and seen[0][-1] == 'authentik-ldap-1'
    assert _built_fn('', rc=1)[0](1) is None


# ---- wiring --------------------------------------------------------------------------------

def test_the_watch_runs_from_the_directory_watch_loop_and_a_failure_cannot_stop_that_loop():
    loop = _src('_ak_directory_watch_loop')
    assert '_ak_ldap_cache_watch_tick(log)' in loop
    assert loop.index('_ak_directory_watch_tick(log)') < loop.index('_ak_ldap_cache_watch_tick(log)')
    assert loop.count('try:') == 2 and loop.count('except Exception') == 2


def test_the_flush_changes_only_bind_mode_and_never_touches_the_outpost_container():
    src = _src('_ak_flush_ldap_bind_cache') + _src('_ak_ldap_set_bind_mode')
    assert "{'bind_mode': mode}" in src
    for banned in ('force-recreate', "'restart'", 'docker compose', 'search_mode'):
        assert banned not in src
    assert APP.count("'bind_mode': 'cached'") >= 1
