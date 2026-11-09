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
"""A client TAK never looked up stays on __ANON__ until the console drops it (ops #565).

nuc 2026-11-08: a phone enrolled and connected 3 s later; TAK gave the connection no user and
no groups (no LDAP outage, LDAP answered all day). The phone left, its relay kept the sockets
open, and the two connections sat on __ANON__ for 3 h while Guard Dog mailed hourly that the
console reconnects such clients by itself. It only does so after an LDAP outage it can see.

The 10-minute monitor now drops a connection with no user and no groups once it has stayed
that way 10 minutes (two ticks); the client reconnects and is looked up again. Never a TAK
restart. Same fake box as test_tak_ldap_recycle.
"""

import pytest

from test_tak_ldap_recycle import (Box, HOUR, T0, _const, _src, healthy_box, outage_box, sess)

TICK = 600   # the monitor's period


def monitor(box):
    """The monitor's view of the console: one process, so the 'seen' and 'dropped' memory
    lives across ticks. `tick(dt)` = dt seconds later, run the check; returns what it dropped."""
    ns = box.ns()
    for c in ('_TAK_STUCK_UNNAMED_MIN_S', '_TAK_STUCK_UNNAMED_COOLDOWN_S'):
        ns[c] = _const(c)
    ns['_tak_stuck_unnamed_seen'], ns['_tak_stuck_unnamed_dropped'] = {}, {}
    exec(compile(_src('_tak_drop_stuck_unnamed_sessions'), 'app.py:_tak_drop_stuck_unnamed_sessions', 'exec'), ns)

    def tick(dt=TICK):
        box.t += dt
        return ns['_tak_drop_stuck_unnamed_sessions'](box.log.append)
    return tick


def stuck_box(**kw):
    """nuc: an enrolled phone whose connection TAK gave no user and no groups; everyone else fine."""
    kw.setdefault('tak_start', T0 - 3 * 24 * HOUR)
    box = outage_box(**kw)
    # test12 2026-11-08: TAK gave the stuck connection no clientUid either (clientUid "", callsign tls:N)
    for s in box.subs:
        if s['dn'] is None:
            s['clientUid'] = ''
    return box


def test_the_heal_after_an_outage_does_not_cover_it():
    """Why this is needed: with no outage in sight the existing heal does nothing."""
    box = stuck_box()
    assert box.recycle(final=False) is False
    assert box.drops() == []
    assert any(s['subscriptionUid'] == 'tls:16' for s in box.subs)


def test_stuck_connection_is_dropped_after_two_ticks_and_reconnects_with_its_groups():
    box = stuck_box()
    tick = monitor(box)
    assert tick(0) == []                     # first seen now: not yet
    assert tick(TICK - 1) == []              # a second short of 10 min
    assert tick(1) == ['tls:16']             # 10 min: dropped
    assert box.drops() == ['tls:16']         # only the stuck one, not admin / the feeds / the user
    assert box.restarts() == [] and box.reauths() == []
    box.t += 20
    [now] = box.live('takdev-emu')
    assert now['subscriptionUid'] != 'tls:16' and now['username'] == 'takdev-emu' and now['groups']
    assert any('dropped 1 connection(s) TAK gave no user and no groups for 10+ min (tls:16)' in l for l in box.log)


def test_healthy_box_is_left_alone():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR)
    tick = monitor(box)
    for _ in range(6):
        assert tick() == []
    assert box.drops() == [] and box.restarts() == []


def test_named_user_ldap_gives_no_channel_is_not_touched():
    """__ANON__ with a name is a user with no channel assigned: dropping it fixes nothing."""
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR)
    box.subs.append(sess(20, 'nogroups', ('__ANON__',)))
    tick = monitor(box)
    for _ in range(4):
        assert tick() == []
    assert box.drops() == []


def test_a_connection_that_gets_its_groups_in_time_starts_over():
    box = stuck_box()
    tick = monitor(box)
    assert tick(0) == []
    assert tick(300) == []
    [s] = [x for x in box.subs if x['subscriptionUid'] == 'tls:16']
    s['groups'] = sess(0, 'x', ('OPS',))['groups']     # TAK's own refresh gave it its groups
    s['username'] = 'takdev-emu'
    assert tick(300) == []
    s['groups'], s['username'] = [], None              # and it is lost again
    assert tick(TICK) == []                            # the clock restarted: seen for 0 s, not 20 min
    assert box.drops() == []


def test_no_drop_while_ldap_cannot_be_read():
    box = stuck_box(ldap=lambda b: (49, 0))
    tick = monitor(box)
    tick(0)
    assert tick(TICK) == [] and tick(TICK) == []
    assert box.drops() == []


def test_no_drop_while_the_console_is_updating():
    box = stuck_box(update_in_progress=True)
    tick = monitor(box)
    tick(0)
    assert tick(TICK) == []
    assert box.drops() == []


def test_unreadable_client_list_keeps_the_clock_and_drops_nothing():
    box = stuck_box()
    tick = monitor(box)
    tick(0)
    box.api_ok = False
    assert tick(TICK) == []                  # can't tell: no verdict
    box.api_ok = True
    assert tick(1) == ['tls:16']             # seen since the first tick, so due now


def test_a_client_that_comes_back_the_same_way_is_retried_hourly_and_never_restarts_tak():
    box = stuck_box(tak_ldap_ok=False)       # TAK's own lookup keeps failing for it
    tick = monitor(box)
    tick(0)
    assert tick(TICK) == ['tls:16']
    box.t += 20
    [again] = box.live('takdev-emu')
    assert again['dn'] is None and not again['groups']
    for _ in range(5):                       # well past 10 min, still inside the hour (~42 min)
        assert tick(TICK - 100) == []
    assert tick(1100) == [again['subscriptionUid']]    # just over an hour after the first drop
    assert box.restarts() == []


def test_a_stuck_client_with_a_device_uid_is_limited_by_that_uid_not_by_the_box():
    box = stuck_box()
    box.subs.append(sess(30, 'ghost', (), unmapped=True, client='ANDROID-other'))
    tick = monitor(box)
    tick(0)
    assert sorted(tick(TICK)) == ['tls:16', 'tls:30']
    box.t += 20
    assert tick(TICK - 100) == []            # both back, both inside their hour


def test_without_a_device_uid_all_stuck_connections_share_one_hourly_slot():
    """The number TAK gives a connection changes at every reconnect, so it cannot hold the limit."""
    box = stuck_box()
    tick = monitor(box)
    tick(0)
    assert tick(TICK) == ['tls:16']
    box.subs.append(sess(31, 'ghost', (), unmapped=True, client=''))   # another phone, also unnamed
    box.t += 20
    assert tick(0) == [] and tick(TICK) == []                          # inside the hour
    assert 'tls:31' in tick(3000)                                      # an hour after the drop


def test_nothing_to_do_without_ldap_in_coreconfig():
    box = stuck_box(coreconfig=False)
    tick = monitor(box)
    tick(0)
    assert tick(TICK) == []
    assert box.drops() == []
