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
"""A leftover connection of the CloudTAK bootstrap cert after a Marketplace install (ops #1267).

test12, Nov 25 (found in the ops #1147 box test): after a TAK Portal Marketplace install the CloudTAK container
is replaced. TAK kept the old container's connection of cloudtak-svc-bootstrap with NO groups (tls:29) next to
the new container's connection with every channel (tls:44). The T&E client check (`anon named=0`) and Guard
Dog's no-channel count both read the leftover as a fault, and nothing cleared it.

The 1-minute check drops that one leftover after two checks in a row. It never touches the newest connection,
never restarts anything, and leaves every other user alone. Same fake box as test_tak_ldap_recycle.
"""

import pytest

from test_tak_ldap_recycle import (APP, HOUR, T0, _const, _src, healthy_box, sess)

TICK = 60       # the check's period
CN = 'cloudtak-svc-bootstrap'


def leftover_box(**kw):
    """test12: the new container's connection (tls:44) has its channels; the replaced container's (tls:29) has none.
    The old container is gone, so a dropped connection does not come back."""
    kw.setdefault('tak_start', T0 - 3 * 24 * HOUR)
    kw.setdefault('online', False)
    box = healthy_box(**kw)
    box.subs = [s for s in box.subs if s['_cn'] != CN]
    box.subs += [sess(29, CN, ()), sess(44, CN, ('A', 'B', 'C'))]
    return box


def checker(box):
    """The console's view: one process, so the check's memory lives across ticks."""
    ns = box.ns()
    ns.update({'_tak_core_is_remote': lambda: False, '_tak_bootstrap_cert_present': lambda: True,
               'CLOUDTAK_BOOTSTRAP_CERT_CN': CN})
    for name in ('_tak_bootstrap_leftover_check',):
        if f'def {name}(' in APP:               # absent on the base code: the tests then fail on their own asserts
            exec(compile(_src(name), f'app.py:{name}', 'exec'), ns)
    ns['_tak_bootstrap_leftover'] = {'tak_start': None, 'seen': {}, 'refused': set()}

    def tick(dt=TICK):
        box.t += dt
        return ns['_tak_bootstrap_leftover_check'](box.log.append)
    tick.ns = ns
    return tick


# ── the proof: red on dev, green with the fix ───────────────────────────────────────────

def test_the_empty_leftover_of_the_replaced_container_is_dropped_and_the_new_connection_is_kept():
    box = leftover_box()
    tick = checker(box)
    assert tick() is None                          # first time seen: not yet
    assert tick() == 'dropped'                     # two checks in a row: that one connection is dropped
    assert box.drops() == ['tls:29']
    assert [s['subscriptionUid'] for s in box.live(CN)] == ['tls:44']
    assert len(box.live(CN)[0]['groups']) == 6     # the healthy one is untouched: 3 channels, IN and OUT
    assert box.restarts() == [] and box.messaging_restarts() == [] and box.api_restarts() == []
    assert box.msg_alerts == []                    # nothing to tell the operator: it is housekeeping
    assert any('dropped 1 leftover connection(s) of the CloudTAK bootstrap cert' in l and 'tls:29' in l
               for l in box.log)
    for _ in range(4):                             # and it stays quiet afterwards
        assert tick() is None
    assert box.drops() == ['tls:29']


def test_why_this_is_needed_the_older_checks_leave_the_leftover_on_the_box_for_good():
    """The 1039 check skips file users (the cert is one) and never judges an empty connection older than one with
    groups; the stuck-phones check needs half of all connections. Passes on dev and with the fix: it is the base."""
    box = leftover_box()
    ns = box.ns()
    for _ in range(8):
        box.t += TICK
        assert ns['_tak_groupless_clients_check'](box.log.append) is None
    assert box.drops() == [] and box.messaging_restarts() == []
    assert sorted(s['subscriptionUid'] for s in box.live(CN)) == ['tls:29', 'tls:44']     # still two: the check FAILs


# ── what it must never touch ────────────────────────────────────────────────────────────

def test_the_only_connection_is_never_dropped_even_when_it_has_no_groups():
    """No newer connection with groups: this one may be the real connection (the cache sync re-authenticates it)."""
    box = leftover_box()
    box.subs = [s for s in box.subs if s['subscriptionUid'] != 'tls:44']
    tick = checker(box)
    for _ in range(6):
        assert tick() is None
    assert box.drops() == []


def test_an_empty_connection_NEWER_than_the_one_with_groups_is_the_real_one_and_is_left_alone():
    box = leftover_box()
    box.subs = [s for s in box.subs if s['subscriptionUid'] != 'tls:29'] + [sess(50, CN, ())]
    tick = checker(box)
    for _ in range(6):
        assert tick() is None
    assert box.drops() == []


def test_other_users_old_empty_connections_are_left_to_the_other_checks():
    box = leftover_box()
    box.subs += [sess(30, 'aj5cacor', ()), sess(31, 'aj5cacor'), sess(7, 'admin', ()), sess(8, 'admin', ('A',))]
    tick = checker(box)
    for _ in range(6):
        tick()
    assert box.drops() == ['tls:29']               # only the bootstrap cert's leftover


def test_a_healthy_box_gets_no_action():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, online=False)
    tick = checker(box)
    for _ in range(8):
        assert tick() is None
    assert box.drops() == []


def test_a_leftover_that_gets_its_groups_or_goes_away_before_the_second_check_starts_over():
    box = leftover_box()
    tick = checker(box)
    assert tick() is None
    box.subs = [s for s in box.subs if s['subscriptionUid'] != 'tls:29']      # TAK removed it itself
    assert tick() is None
    box.subs.append(sess(29, CN, ()))                                          # a new one: the count starts at one
    assert tick() is None
    assert box.drops() == []
    assert tick() == 'dropped' and box.drops() == ['tls:29']


# ── the limits ───────────────────────────────────────────────────────────────────────────

def test_limit_a_connection_tak_refuses_to_drop_is_tried_once():
    box = leftover_box(ghosts={'tls:29'})
    tick = checker(box)
    for _ in range(8):
        assert tick() is None
    assert box.drops() == ['tls:29']               # tried once, never again
    assert any('TAK would not drop' in l for l in box.log)


def test_limit_grace_after_tak_started_no_action():
    box = leftover_box(tak_start=T0 - 100)
    tick = checker(box)
    for _ in range(2):
        assert tick() is None
    assert box.drops() == []
    box.t = box.tak_start + _const('_TAK_STUCK_MASS_DEADLINE_S')
    assert tick() is None and tick() == 'dropped'


def test_limit_no_action_while_a_console_update_runs():
    box = leftover_box(update_in_progress=True)
    tick = checker(box)
    for _ in range(6):
        assert tick() is None
    assert box.drops() == []


def test_limit_an_unreadable_client_list_keeps_the_count_and_does_nothing():
    box = leftover_box()
    tick = checker(box)
    assert tick() is None
    box.api_ok = False
    assert tick() is None and box.drops() == []
    box.api_ok = True
    assert tick() == 'dropped'                     # the first check still counts


def test_limit_a_restarted_tak_starts_the_count_over():
    box = leftover_box()
    tick = checker(box)
    assert tick() is None
    box.tak_start = box.t - 10                     # TAK Server restarted: it lists none of the old connections
    assert tick() is None
    assert box.drops() == []


def test_limit_no_cert_no_action_and_a_split_box_with_the_core_elsewhere_is_left_alone():
    box = leftover_box()
    tick = checker(box)
    tick.ns['_tak_bootstrap_cert_present'] = lambda: False
    for _ in range(4):
        assert tick() is None
    tick.ns['_tak_bootstrap_cert_present'] = lambda: True
    tick.ns['_tak_core_is_remote'] = lambda: True
    for _ in range(4):
        assert tick() is None
    assert box.drops() == []


# ── the wiring ───────────────────────────────────────────────────────────────────────────

def test_the_one_minute_loop_runs_the_leftover_check_with_its_own_error_handling():
    loop = _src('_tak_stuck_mass_loop')
    assert loop.index('_tak_groupless_clients_check(log)') < loop.index('_tak_bootstrap_leftover_check(log)')
    call = loop[loop.index('_tak_bootstrap_leftover_check(log)'):]
    assert call.lstrip().startswith('_tak_bootstrap_leftover_check') and 'except Exception' in call
    # a failing check must not stop the checks before it (each has its own try)
    assert loop.count('try:') >= 3


def test_the_drop_is_one_marti_delete_and_never_a_restart_or_a_shell():
    src = _src('_tak_bootstrap_leftover_check')
    assert "method='DELETE'" in src and '/subscriptions/delete/' in src
    assert 'subprocess' not in src and 'systemctl' not in src and 'shell=True' not in src and 'os.system' not in src
