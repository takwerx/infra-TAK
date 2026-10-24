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
"""The console's own Authentik watchdogs stand down during an update (ops #214).

test12, 2026-10-24 (Authentik 2026.8.5 update): the ldap-sa-watchdog saw the service
account's bind fail mid-recreate and ran a heal ("heal INCOMPLETE ... Connection
refused"). Guard Dog's watcher already skips while the update marker is fresh (#167);
the console's watchdogs did not. Now the ldap-sa-watchdog, the channels-pool watchdog
(which `docker restart`s authentik-server-1 after two unhealthy ticks) and the spiral
monitor all ask _authentik_busy_reason() first and skip the tick while:
  * someone holds the Authentik compose lock (a recreate is running),
  * Guard Dog's update marker is fresh,
  * this console's own Update has not seen Authentik answer again yet (boxes without
    Guard Dog get no marker), or
  * a deploy is in progress.
"""

import ast
import fcntl
import os
import pathlib
import subprocess
import sys
import threading
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(APP)


def _src(*names):
    found = {}
    for node in _TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            found[node.name] = ast.get_source_segment(APP, node)
    assert set(found) == set(names), f'renamed or removed: {set(names) - set(found)}'
    return '\n\n'.join(found[n] for n in names)


def _const(name):
    for node in _TREE.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], 'id', None) == name):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found')


MAX_S = _const('_GD_AUTHENTIK_UPDATE_MAX_S')


class _Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def time(self):
        return self.now


# ── the helper ───────────────────────────────────────────────────────────────

@pytest.fixture
def busy(tmp_path):
    lock = tmp_path / 'takwerx-authentik-compose.lock'
    marker = tmp_path / 'authentik_update_in_progress'
    clock = _Clock()
    state = {'health': True, 'deploy': False, 'health_calls': 0}

    def http_ok():
        state['health_calls'] += 1
        return state['health']

    def write_priv(path, content, mode='w', perm=None):
        pathlib.Path(path).write_text(content)

    def run(argv, **kw):
        if argv[:2] == ['rm', '-f'] and os.path.exists(argv[2]):
            os.unlink(argv[2])
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    ns = {'os': os, 'time': clock, '_AK_COMPOSE_LOCK_PATH': str(lock),
          '_AK_COMPOSE_LOCK_HELD': threading.local(),
          '_GD_AUTHENTIK_UPDATE_MARKER': str(marker), '_GD_AUTHENTIK_UPDATE_MAX_S': MAX_S,
          '_AK_UPDATE_INPROC': {'since': 0.0}, '_local_authentik_http_ok': http_ok,
          '_authentik_deploy_in_progress': lambda: state['deploy'],
          '_write_priv': write_priv, '_sudo_wrap': lambda c: list(c),
          'subprocess': types.SimpleNamespace(run=run)}
    exec(compile(_src('_authentik_compose_lock_busy', '_guarddog_authentik_update_marker_age',
                      '_authentik_busy_reason', '_guarddog_authentik_update_begin',
                      '_guarddog_authentik_update_end'), 'app.py', 'exec'), ns)
    ns.update(_lock=lock, _marker=marker, _clock=clock, _state=state)
    return ns


def test_idle_box_is_not_busy(busy):
    busy['_lock'].write_text('')
    assert busy['_authentik_busy_reason']() == ''


def test_missing_lock_file_is_not_busy_and_is_not_created(busy):
    assert busy['_authentik_compose_lock_busy']() is False
    assert not busy['_lock'].exists()


def test_lock_held_by_another_process_is_busy(busy):
    busy['_lock'].write_text('')
    # Guard Dog / another worker: a separate process holding the flock.
    holder = subprocess.Popen(
        [sys.executable, '-c',
         'import fcntl, sys, time\n'
         'f = open(sys.argv[1])\n'
         'fcntl.flock(f.fileno(), fcntl.LOCK_EX)\n'
         'print("held", flush=True)\n'
         'time.sleep(60)\n', str(busy['_lock'])],
        stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == 'held'
        assert 'compose lock is held' in busy['_authentik_busy_reason']()
    finally:
        holder.kill()
        holder.wait()
    assert busy['_authentik_busy_reason']() == ''


def test_lock_held_by_another_thread_of_the_console_is_busy(busy):
    busy['_lock'].write_text('')
    with open(busy['_lock']) as fh:            # e.g. the Update's own `with` block
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        assert busy['_authentik_compose_lock_busy']() is True
    assert busy['_authentik_compose_lock_busy']() is False


def test_probe_leaves_the_lock_free_for_the_next_caller(busy):
    busy['_lock'].write_text('')
    busy['_authentik_compose_lock_busy']()
    with open(busy['_lock']) as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)   # raises if the probe kept it


def test_root_owned_read_only_lock_file_still_probes(busy):
    busy['_lock'].write_text('')
    busy['_lock'].chmod(0o444)
    with open(busy['_lock']) as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        assert busy['_authentik_compose_lock_busy']() is True


def test_the_holding_thread_is_not_told_to_stop(busy):
    busy['_lock'].write_text('')
    busy['_AK_COMPOSE_LOCK_HELD'].depth = 1
    assert busy['_authentik_compose_lock_busy']() is False


def test_fresh_update_marker_is_busy(busy):
    busy['_marker'].write_text(f"{int(busy['_clock'].now) - 40} authentik-update 2026.8.4 -> 2026.8.5\n")
    assert busy['_authentik_busy_reason']() == 'an Authentik update is in progress (update marker 40s old)'


@pytest.mark.parametrize('body', ['', 'garbage\n', 'abc authentik-update\n'])
def test_unreadable_marker_is_ignored(busy, body):
    busy['_marker'].write_text(body)
    assert busy['_authentik_busy_reason']() == ''


def test_stale_marker_is_ignored(busy):
    busy['_marker'].write_text(f"{int(busy['_clock'].now) - MAX_S} x\n")
    assert busy['_authentik_busy_reason']() == ''


def test_future_marker_is_ignored(busy):
    busy['_marker'].write_text(f"{int(busy['_clock'].now) + 60} x\n")
    assert busy['_authentik_busy_reason']() == ''


def test_own_update_without_guard_dog_is_busy_until_authentik_answers(busy):
    # No /var/lib/takguard: begin() writes no marker but still tells the console.
    busy['os'] = types.SimpleNamespace(path=types.SimpleNamespace(
        isdir=lambda p: False, dirname=os.path.dirname, exists=os.path.exists), unlink=os.unlink)
    assert busy['_guarddog_authentik_update_begin']('authentik-update') is False
    assert not busy['_marker'].exists()
    busy['_state']['health'] = False               # migrations running
    busy['_clock'].now += 90
    assert busy['_authentik_busy_reason']() == \
        'an Authentik update is in progress (90s, migrations not finished)'
    busy['_state']['health'] = True                # answered again
    assert busy['_authentik_busy_reason']() == ''
    assert busy['_AK_UPDATE_INPROC']['since'] == 0.0
    busy['_state']['health'] = False               # a later outage is not an update
    assert busy['_authentik_busy_reason']() == ''


def test_own_update_flag_expires_at_the_marker_timeout(busy):
    busy['_guarddog_authentik_update_begin']('x')
    busy['_marker'].unlink()
    busy['_state']['health'] = False
    busy['_clock'].now += MAX_S
    assert busy['_authentik_busy_reason']() == ''


def test_update_end_clears_the_console_flag(busy):
    busy['_guarddog_authentik_update_begin']('x')
    assert busy['_AK_UPDATE_INPROC']['since'] == busy['_clock'].now
    busy['_guarddog_authentik_update_end']()
    assert busy['_AK_UPDATE_INPROC']['since'] == 0.0
    assert not busy['_marker'].exists()


def test_no_health_probe_when_no_update_is_running(busy):
    busy['_authentik_busy_reason']()
    assert busy['_state']['health_calls'] == 0


def test_deploy_in_progress_is_busy(busy):
    busy['_state']['deploy'] = True
    assert 'deploy is in progress' in busy['_authentik_busy_reason']()


# ── the watchdog loops ───────────────────────────────────────────────────────

class _Stop(BaseException):
    pass


@pytest.fixture
def ticks(monkeypatch):
    """Let a `while True` loop run until its Nth sleep. The loops import time locally."""
    def run(fn, sleeps):
        n = {'left': sleeps}

        def sleep(_s):
            n['left'] -= 1
            if n['left'] < 0:
                raise _Stop()
        monkeypatch.setattr(time, 'sleep', sleep)
        with pytest.raises(_Stop):
            fn()
    return run


def _ldap_loop(reason, calls):
    def rec(name, ret=None):
        def f(*a, **k):
            calls.append(name)
            return ret
        return f
    settings = {'authentik_ldap_sa_heal_failures': 0}
    ns = {
        'os': types.SimpleNamespace(path=types.SimpleNamespace(
            exists=lambda p: True, expanduser=lambda p: p)),
        'load_settings': lambda: settings, 'save_settings': rec('save_settings'),
        '_coreconfig_has_ldap': lambda: True,
        '_get_authentik_env_value': lambda s, k: 'sa-pass',
        '_authentik_busy_reason': lambda: reason,
        '_test_ldap_bind_dn_verdict': rec('bind_probe', 'fail'),
        'LDAP_SA_HEAL_BACKOFF_AFTER': 3, 'LDAP_SA_POLICY_REPAIR_GRACE_SECS': 900,
        '_ldap_outpost_token_rejected': rec('token_check', False),
        '_repair_ldap_outpost_token': rec('token_repair', (False, '')),
        '_ensure_authentik_ldap_service_account': rec('heal', (False, 'Connection refused')),
        '_record_ldap_sa_heal_failure': rec('record_failure'),
        '_resync_ldap_credential_to_coreconfig': rec('cc_resync', (False, '')),
        '_authentik_webadmin_role_check_and_heal': rec('role_heal', False),
        '_authentik_audit_scrape_recent': rec('audit', 0),
    }
    exec(compile(_src('_authentik_ldap_sa_bind_watchdog_loop'), 'app.py', 'exec'), ns)
    return ns['_authentik_ldap_sa_bind_watchdog_loop']


def test_ldap_sa_watchdog_skips_the_heal_during_an_update(ticks, capsys):
    calls = []
    ticks(_ldap_loop('an Authentik update is in progress (update marker 40s old)', calls), 2)
    assert calls == []                                   # no probe, no heal, no role/audit work
    out = capsys.readouterr().out
    assert ('[ldap-sa-watchdog] skip | an Authentik update is in progress '
            '(update marker 40s old) — not checking this tick') in out
    assert 'heal' not in out


def test_ldap_sa_watchdog_still_heals_a_real_drift(ticks, capsys):
    calls = []
    ticks(_ldap_loop('', calls), 1)
    assert calls[:3] == ['bind_probe', 'token_check', 'heal']
    assert 'bind drift DETECTED' in capsys.readouterr().out


def _channels_loop(reason, calls):
    def run(*a, **k):
        calls.append(a[0])
        return types.SimpleNamespace(returncode=1, stdout='', stderr='')
    ns = {'os': types.SimpleNamespace(path=types.SimpleNamespace(
              exists=lambda p: True, expanduser=lambda p: p)),
          'load_settings': lambda: {}, '_authentik_busy_reason': lambda: reason,
          'subprocess': types.SimpleNamespace(run=run), '_sudo_wrap': lambda c: list(c),
          '_AUTHENTIK_IDLE_IN_TX_WATCHDOG_THRESHOLD': 30, '_AUTHENTIK_IDLE_IN_TX_STALE_S': 30}
    exec(compile(_src('_authentik_channels_pool_watchdog_loop'), 'app.py', 'exec'), ns)
    return ns['_authentik_channels_pool_watchdog_loop']


def test_channels_pool_watchdog_touches_nothing_during_an_update(ticks, capsys):
    calls = []
    ticks(_channels_loop('the Authentik compose lock is held (a recreate is running)', calls), 3)
    assert calls == []                      # no psql, no docker inspect, no docker restart
    assert ('[ak-pg-watchdog] skip | the Authentik compose lock is held '
            '(a recreate is running) — not checking this tick') in capsys.readouterr().out


def test_channels_pool_watchdog_still_checks_otherwise(ticks):
    calls = []
    ticks(_channels_loop('', calls), 2)
    assert calls and calls[0][:3] == ['docker', 'exec', 'authentik-postgresql-1']


def test_channels_pool_watchdog_forgets_unhealthy_ticks_seen_before_an_update():
    body = _src('_authentik_channels_pool_watchdog_loop')
    skip = body[body.index('_busy = _authentik_busy_reason()'):]
    skip = skip[:skip.index('continue')]
    assert '_consecutive_unhealthy = 0' in skip


def test_spiral_monitor_stands_down_before_touching_authentik():
    body = _src('_authentik_spiral_monitor')
    i_busy = body.index('_busy = _authentik_busy_reason()')
    for action in ('_auto_authentik_channel_purge(', '_ensure_authentik_ldap_outpost_on_fqdn(',
                   '_tak_recycle_after_ldap_outage(', '_apply_authentik_ldap_routing_repair('):
        assert i_busy < body.index(action), action
    assert '_authentik_deploy_in_progress()' not in body   # folded into the helper


def test_ldap_sa_watchdog_asks_before_the_bind_probe():
    body = _src('_authentik_ldap_sa_bind_watchdog_loop')
    assert body.index('_authentik_busy_reason()') < body.index('_test_ldap_bind_dn_verdict(')
