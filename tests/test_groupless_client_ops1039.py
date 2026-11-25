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
"""A phone TAK named but gave no groups, while LDAP gives its user groups (ops #1039).

test12, Nov 25 (found in the 10.4.4 T&E): the emulator sat on __ANON__ with its name and no groups.
A forced reconnect, a re-authentication and `systemctl restart takserver-api` left it there; LDAP and
TAK's 8443 side gave the user its groups. Only `systemctl restart takserver-messaging` (about 1 min, the
API untouched) cleared it. The console did nothing for one such phone when it had seen no outage.

The 1-minute check drops that one connection after two checks in a row; if it comes back with no groups
again, it restarts only takserver-messaging (never TAK Server, never the API), at most once per 30 min,
and sends one plain Guard Dog mail. The same restart replaces the full TAK restart where the outage heal
finds a client that came back empty. Same fake box as test_tak_ldap_recycle.
"""

import re

import pytest

from test_tak_ldap_recycle import (APP, Box, HOUR, T0, _const, _src, healthy_box, sess)
from test_stuck_unnamed_client_ops565 import monitor   # the 10-min check for a client with no user at all

TICK = 60   # the check's period


def stuck_named_box(**kw):
    """test12: the emulator is connected, TAK named it, TAK gave it only __ANON__; LDAP gives its user a group."""
    kw.setdefault('tak_start', T0 - 3 * 24 * HOUR)
    kw.setdefault('messaging_restart', 'fixes')
    kw.setdefault('stuck_cache', {'takdev-emu'})
    box = healthy_box(**kw)
    box.subs.append(sess(16, 'takdev-emu', ('__ANON__',)))
    return box


def stuck_unnamed_box(**kw):
    """test12 Nov 25 (the real state): TAK gave the connection no DN and no username, only the callsign and
    __ANON__; it comes back the same way after a drop. TAK's client history still knows the device's user."""
    kw.setdefault('tak_start', T0 - 3 * 24 * HOUR)
    kw.setdefault('messaging_restart', 'fixes')
    kw.setdefault('stuck_cache', {'takdev-emu'})
    kw.setdefault('stuck_unmapped', True)
    box = healthy_box(**kw)
    box.subs.append(sess(16, 'takdev-emu', (), unmapped=True))
    return box


def checker(box):
    """The console's view: one process, so the check's memory lives across ticks.
    Returns tick(dt) = dt seconds later, run the check once, and the namespace to tweak."""
    ns = box.ns()

    def tick(dt=TICK):
        box.t += dt
        return ns['_tak_groupless_clients_check'](box.log.append)
    tick.ns = ns
    return tick


def run_until(tick, want, most=10):
    out = []
    for _ in range(most):
        out.append(tick())
        if want in out:
            break
    return out


# ── the proof: red on dev, green with the fix ───────────────────────────────────────────

def test_a_named_phone_with_no_groups_gets_only_the_messaging_process_restarted():
    box = stuck_named_box()
    tick = checker(box)
    assert tick() is None                          # first time seen: not yet
    assert tick() == 'dropped'                     # two checks in a row: that one connection is dropped
    assert box.drops() == ['tls:16'] and box.messaging_restarts() == []
    box.t += 20
    [again] = box.live('takdev-emu')               # it reconnects, and TAK gives it nothing again
    assert again['subscriptionUid'] != 'tls:16' and not [g for g in again['groups'] if g['name'] != '__ANON__']
    assert tick() is None and tick() == 'restart'  # back empty for two checks: restart only the messaging process
    assert box.messaging_restarts() == [['systemctl', 'restart', 'takserver-messaging']]
    assert box.restarts() == [] and box.api_restarts() == []     # never TAK Server, never the API
    [now] = box.live('takdev-emu')
    assert [g for g in now['groups'] if g['name'] != '__ANON__']  # and it has its groups again
    assert [k for k, _d, _a in box.msg_alerts] == ['restarted']   # one mail for the one action
    assert 'takdev-emu' in box.msg_alerts[0][1]
    assert any('Restarting only TAK\'s messaging process' in l for l in box.log)


def test_nothing_happens_to_a_healthy_box():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, messaging_restart='fixes')
    tick = checker(box)
    for _ in range(8):
        assert tick() is None
    assert box.drops() == [] and box.messaging_restarts() == [] and box.msg_alerts == []


def test_why_this_is_needed_the_older_checks_do_nothing_for_a_named_phone_with_no_groups():
    """The outage heal needs an outage it can see, the 10-min check needs a connection with no user at all,
    the stuck-phones check needs half of all connections: none of them acts on one named phone."""
    box = stuck_named_box()
    tick = monitor(box)
    for _ in range(6):
        assert tick() == []
    assert box.recycle(final=False) is False
    assert box.drops() == [] and box.restarts() == [] and box.messaging_restarts() == []
    [still] = box.live('takdev-emu')
    assert not [g for g in still['groups'] if g['name'] != '__ANON__']


# ── the limits the lead set ─────────────────────────────────────────────────────────────

def test_limit_ldap_down_means_no_action():
    box = stuck_named_box()
    tick = checker(box)
    tick.ns['_ldap_users_tak_group_counts'] = lambda *a, **k: None      # LDAP / Authentik does not answer
    for _ in range(8):
        assert tick() is None
    assert box.drops() == [] and box.messaging_restarts() == [] and box.msg_alerts == []


def test_limit_ldap_down_after_the_drop_does_not_restart_either():
    box = stuck_named_box()
    tick = checker(box)
    assert tick() is None and tick() == 'dropped'
    tick.ns['_ldap_users_tak_group_counts'] = lambda *a, **k: None
    for _ in range(6):
        assert tick() is None
    assert box.messaging_restarts() == []


def test_limit_a_user_ldap_gives_no_groups_is_left_alone():
    box = stuck_named_box(ldap_users={'takdev-emu': 0, 'aj5cacor': 1, 'ADSB_PS': 1})
    tick = checker(box)
    for _ in range(8):
        assert tick() is None
    assert box.drops() == [] and box.messaging_restarts() == []


def test_limit_grace_after_tak_started_no_action():
    box = stuck_named_box(tak_start=T0 - 100)      # TAK started 100 s before: the next two checks are inside the boot grace
    tick = checker(box)
    for _ in range(2):
        assert tick() is None
    assert box.drops() == [] and box.messaging_restarts() == []
    box.t = box.tak_start + _const('_TAK_STUCK_MASS_DEADLINE_S')
    assert tick() is None and tick() == 'dropped'   # after the grace it counts: first check, then the drop


def test_limit_no_action_while_a_console_update_runs():
    box = stuck_named_box(update_in_progress=True)
    tick = checker(box)
    for _ in range(8):
        assert tick() is None
    assert box.drops() == [] and box.messaging_restarts() == []


def test_limit_one_messaging_restart_per_30_minutes_then_only_the_alert():
    box = stuck_named_box()
    tick = checker(box)
    assert 'restart' in run_until(tick, 'restart')
    assert len(box.messaging_restarts()) == 1
    # the same problem again 10 min later (TAK's messaging process holds an empty answer once more)
    box.t += 600
    box.stuck_cache.add('takdev-emu')
    box.subs = [s for s in box.subs if s['_cn'] != 'takdev-emu'] + [sess(40, 'takdev-emu', ('__ANON__',))]
    out = run_until(tick, 'alert')
    assert 'alert' in out and len(box.messaging_restarts()) == 1     # not a second restart
    assert [k for k, _d, _a in box.msg_alerts] == ['restarted', 'limited']
    assert box.msg_alerts[1][2] is not None and box.msg_alerts[1][2] < 30      # said how long ago
    assert box.restarts() == []
    # after the gap a new episode is allowed one more
    box.t += _const('_TAK_MESSAGING_RESTART_GAP_S')
    box.stuck_cache.add('takdev-emu')
    box.subs = [s for s in box.subs if s['_cn'] != 'takdev-emu'] + [sess(50, 'takdev-emu', ('__ANON__',))]
    assert 'restart' in run_until(tick, 'restart', most=14)
    assert len(box.messaging_restarts()) == 2


def test_a_phone_that_gets_its_groups_after_the_drop_is_never_restarted_for():
    box = stuck_named_box()
    tick = checker(box)
    assert tick() is None and tick() == 'dropped'
    box.stuck_cache.clear()                         # TAK's own refresh gave the user its groups again
    box.t += 20
    for s in box.live('takdev-emu'):
        s['groups'] = sess(0, 'x', ('OPS',))['groups']
    for _ in range(8):
        assert tick() is None
    assert box.messaging_restarts() == []


def test_a_connection_that_gets_groups_before_the_second_check_starts_over():
    box = stuck_named_box()
    tick = checker(box)
    assert tick() is None
    [s] = box.live('takdev-emu')
    s['groups'] = sess(0, 'x', ('OPS',))['groups']
    assert tick() is None
    s['groups'] = [{'name': '__ANON__', 'direction': 'IN'}]    # lost again: the count starts at one
    assert tick() is None
    assert box.drops() == []


def test_an_empty_connection_newer_than_one_listed_with_groups_is_the_real_one_and_is_healed():
    """nuc Nov 25: the emulator's old socket was still listed with its groups, the new connection sat on __ANON__."""
    box = stuck_named_box()
    box.subs.append(sess(10, 'takdev-emu'))        # the old connection TAK still lists, with its groups
    tick = checker(box)
    assert tick() is None and tick() == 'dropped'
    assert box.drops() == ['tls:16']               # the newer, empty one, not the old one
    box.t += 20
    assert tick() is None and tick() == 'restart'  # it came back empty again
    assert len(box.messaging_restarts()) == 1


def test_one_connection_with_groups_makes_the_users_empty_ghosts_harmless():
    box = stuck_named_box()
    box.subs.append(sess(17, 'takdev-emu'))        # the same user's newer connection has its groups
    tick = checker(box)
    for _ in range(8):
        assert tick() is None
    assert box.drops() == [] and box.messaging_restarts() == []


def test_a_connection_tak_refuses_to_drop_is_not_judged_again_and_never_restarts_messaging():
    box = stuck_named_box(ghosts={'tls:16'})
    tick = checker(box)
    for _ in range(10):
        assert tick() is None
    assert box.drops() == ['tls:16']                # tried once
    assert box.messaging_restarts() == []


def test_a_phone_tak_gave_no_user_at_all_but_client_history_names_is_healed_the_same_way():
    """test12 Nov 25: the stuck emulator had no DN and no username; its device's history says takdev-emu."""
    box = stuck_unnamed_box()
    tick = checker(box)
    assert tick() is None and tick() == 'dropped'
    box.t += 20
    [again] = box.live('takdev-emu')
    assert again['dn'] is None and not again['groups']          # back the same way
    assert tick() is None and tick() == 'restart'
    assert box.messaging_restarts() == [['systemctl', 'restart', 'takserver-messaging']] and box.restarts() == []
    [now] = box.live('takdev-emu')
    assert now['username'] == 'takdev-emu' and now['groups']
    assert [k for k, _d, _a in box.msg_alerts] == ['restarted']


def test_a_phone_with_no_user_and_no_history_is_left_to_the_other_checks():
    box = stuck_unnamed_box(history={})                         # nothing says whose it is
    tick = checker(box)
    for _ in range(8):
        assert tick() is None
    assert box.drops() == [] and box.messaging_restarts() == []


def test_a_client_the_messaging_restart_did_not_fix_never_restarts_messaging_again_for_hours():
    box = stuck_named_box(messaging_restart='no_fix')
    tick = checker(box)
    assert 'restart' in run_until(tick, 'restart')
    assert [k for k, _d, _a in box.msg_alerts] == ['still']
    box.t += _const('_TAK_MESSAGING_RESTART_GAP_S') + 600       # the 30-min limit is over, the client is still stuck
    for _ in range(10):
        tick()
    assert len(box.messaging_restarts()) == 1
    box.t += _const('_TAK_GROUPLESS_FUTILE_S')                  # six hours later it may try once more
    box.subs = [x for x in box.subs if x['_cn'] != 'takdev-emu'] + [sess(70, 'takdev-emu', ('__ANON__',))]
    assert 'restart' in run_until(tick, 'restart', most=14) and len(box.messaging_restarts()) == 2


def test_a_client_name_with_control_characters_cannot_forge_a_log_line():
    box = stuck_named_box()
    tick = checker(box)
    real = tick.ns['_tak_client_sessions']
    tick.ns['_tak_client_sessions'] = lambda devices=None, errs=None: [
        dict(s, cn=s['cn'] + '\nforged line') if s['uid'].endswith(':16') else s for s in (real(devices, errs) or [])]
    tick.ns['_ldap_users_tak_group_counts'] = lambda p, cns: {c.lower(): 1 for c in cns}
    tick()
    tick()
    assert box.drops() == ['tls:16']
    assert any('dropped 1 connection(s)' in l for l in box.log) and not any('\nforged' in l for l in box.log)


def test_file_users_are_never_touched():
    box = stuck_named_box(stuck_cache=())
    box.subs.append(sess(18, 'admin', ('__ANON__',)))
    tick = checker(box)
    tick.ns['_ldap_users_tak_group_counts'] = lambda p, cns: {c.lower(): 1 for c in cns}
    for _ in range(8):
        tick()
    assert 'tls:18' not in box.drops()


def test_unreadable_client_list_keeps_the_count_and_does_nothing():
    box = stuck_named_box()
    tick = checker(box)
    assert tick() is None
    box.api_ok = False
    assert tick() is None and box.drops() == []
    box.api_ok = True
    assert tick() == 'dropped'                      # the first check still counts


def test_a_restarted_tak_starts_the_count_over():
    box = stuck_named_box()
    tick = checker(box)
    assert tick() is None and tick() == 'dropped'
    box.tak_start = box.t - 10                      # TAK Server restarted
    assert tick() is None
    assert box.messaging_restarts() == []


# ── where a restart is not possible ────────────────────────────────────────────────────

def test_a_docker_tak_gets_the_alert_and_no_restart():
    box = stuck_named_box(container=True)
    tick = checker(box)
    out = run_until(tick, 'alert')
    assert 'alert' in out
    assert box.restarts() == [] and box.messaging_restarts() == []
    assert [k for k, _d, _a in box.msg_alerts] == ['docker']


def test_no_takserver_messaging_unit_gives_the_alert_and_never_restarts_tak_server():
    box = stuck_named_box(messaging_restart='unavailable')
    tick = checker(box)
    out = run_until(tick, 'alert')
    assert 'alert' in out
    assert box.restarts() == [] and [k for k, _d, _a in box.msg_alerts] == ['failed']
    # a restart that could not be done leaves the slot free
    assert box.settings['tak_messaging_heal']['restart_epoch'] == 0


def test_a_console_restart_does_not_repeat_the_restart():
    box = stuck_named_box()
    tick = checker(box)
    run_until(tick, 'restart')
    fresh = checker(box)                            # a new console process: no memory in it, only the saved settings
    box.t += 300
    box.stuck_cache.add('takdev-emu')
    box.subs = [s for s in box.subs if s['_cn'] != 'takdev-emu'] + [sess(60, 'takdev-emu', ('__ANON__',))]
    assert 'alert' in run_until(fresh, 'alert')
    assert len(box.messaging_restarts()) == 1


def test_the_check_does_not_run_while_the_ldap_outage_heal_holds_tak():
    box = stuck_named_box()
    tick = checker(box)
    assert tick() is None and tick() == 'dropped'
    tick.ns['_tak_ldap_recycle_lock'].acquire()     # the heal is working
    for _ in range(6):
        assert tick() is None
    assert box.messaging_restarts() == []


# ── the outage heal uses the same restart instead of restarting TAK Server ────────────────

def test_heal_that_finds_a_client_back_empty_restarts_only_messaging_not_tak():
    box = stuck_named_box()
    box.request('PgBouncer image swap')
    assert box.recycle() is False                   # False = TAK Server was not restarted
    assert box.messaging_restarts() == [['systemctl', 'restart', 'takserver-messaging']]
    assert box.restarts() == []
    [now] = box.live('takdev-emu')
    assert [g for g in now['groups'] if g['name'] != '__ANON__']
    assert [k for k, _d, _a in box.msg_alerts] == ['restarted']
    st = box.settings['tak_ldap_recycle']
    assert 'pending' not in st and st['last_outcome'].startswith('clients healed')


def test_heal_that_the_messaging_restart_does_not_fix_is_alerted_and_never_restarts_tak():
    box = stuck_named_box(messaging_restart='no_fix')
    box.request('PgBouncer image swap')
    assert box.recycle() is False
    assert len(box.messaging_restarts()) == 1 and box.restarts() == []
    assert [k for k, _d, _a in box.msg_alerts] == ['still']
    assert box.settings['tak_ldap_recycle']['last_outcome'] == 'messaging restarted, clients still without groups'


def test_heal_inside_the_30_minute_gap_sends_the_alert_and_restarts_nothing():
    box = stuck_named_box(settings={'tak_messaging_heal': {'restart_epoch': T0 - 600}})
    box.request('PgBouncer image swap')
    assert box.recycle() is False
    assert box.messaging_restarts() == [] and box.restarts() == []
    assert [k for k, _d, _a in box.msg_alerts] == ['limited']


def test_heal_with_no_messaging_unit_keeps_the_old_full_restart_once():
    box = stuck_named_box(messaging_restart='unavailable', tak_ldap_ok=False, stuck_cache=())
    box.subs = [s for s in box.subs if s['_cn'] != 'takdev-emu'] + [sess(16, 'takdev-emu', (), unmapped=True)]
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    assert box.restarts() == [['systemctl', 'restart', 'takserver']]
    assert box.settings['tak_messaging_heal']['restart_epoch'] == 0


def test_heal_on_a_docker_tak_keeps_the_old_full_restart():
    box = stuck_named_box(container=True, tak_ldap_ok=False, stuck_cache=())
    box.subs = [s for s in box.subs if s['_cn'] != 'takdev-emu'] + [sess(16, 'takdev-emu', (), unmapped=True)]
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    assert box.restarts() == [['docker', 'restart', 'takserver']] and box.messaging_restarts() == []


def test_a_changed_ldap_credential_still_restarts_tak_server():
    box = stuck_named_box()
    box.request('LDAP credential changed', restart=True)
    assert box.recycle() is True
    assert box.restarts() == [['systemctl', 'restart', 'takserver']] and box.messaging_restarts() == []


# ── the wiring and the mail ───────────────────────────────────────────────────────────────

def test_the_one_minute_loop_runs_the_new_check_after_the_mass_check():
    loop = _src('_tak_stuck_mass_loop')
    assert loop.index('_tak_stuck_mass_check(log)') < loop.index('_tak_groupless_clients_check(log)')


def test_messaging_restart_is_argv_through_the_broker_wrap_and_never_a_shell():
    src = _src('_tak_messaging_only_restart')
    assert "_sudo_wrap(['systemctl', 'restart', 'takserver-messaging'])" in src
    assert 'shell=True' not in src and 'os.system' not in src
    assert "'takserver'" not in src.replace("'takserver-messaging'", '')    # never the whole TAK Server


def _alert_ns(sent, settings):
    import datetime
    import socket
    import time as _time

    class _T:
        now = 1_800_000_000.0
        time = staticmethod(lambda: _T.now)
        sleep = staticmethod(_time.sleep)
    ns = {'datetime': datetime.datetime, 'time': _T, 'socket': socket, 're': re,
          'load_settings': lambda: settings, 'save_settings': lambda s: settings.update(s),
          '_write_priv': lambda *a, **k: None, '_guarddog_server_identifier': lambda s: 'box1',
          '_guarddog_send_alert_email_via_relay': lambda to, subj, body: sent.append((subj, body))}
    for c in ('_TAK_MESSAGING_RESTART_GAP_S', '_TAK_MESSAGING_ALERT_GAP_S'):
        ns[c] = _const(c)
    exec(compile(_src('_tak_messaging_alert'), 'app.py:_tak_messaging_alert', 'exec'), ns)
    return ns, _T


def test_the_mail_is_plain_words_one_per_restart_and_the_repeats_at_most_hourly():
    sent, settings = [], {'guarddog_alert_email': 'ops@example.org'}
    ns, clock = _alert_ns(sent, settings)
    log = []
    ns['_tak_messaging_alert'](log.append, 'restarted', 'one client had no groups')
    ns['_tak_messaging_alert'](log.append, 'restarted', 'one client had no groups')    # a second action = a second mail
    assert len(sent) == 2
    subj, body = sent[0]
    assert 'a phone had no groups' in subj and 'box1' in subj
    assert 'only TAK\'s messaging part' in body and 'Phones reconnect by themselves' in body
    assert 'systemctl' not in body and 'takserver-messaging' not in body
    ns['_tak_messaging_alert'](log.append, 'limited', 'x', minutes_ago=10)
    ns['_tak_messaging_alert'](log.append, 'limited', 'x', minutes_ago=11)             # inside the hour: nothing more
    assert len(sent) == 3
    clock.now += _const('_TAK_MESSAGING_ALERT_GAP_S')
    ns['_tak_messaging_alert'](log.append, 'limited', 'x', minutes_ago=70)
    assert len(sent) == 4
