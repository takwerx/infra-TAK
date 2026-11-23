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
"""GH #616: a reboot right after an update left ~99 % of TAK's streaming clients with no groups
for 8 h, and nothing escalated.

Field timeline (Nov 20, v10.4.3, Ubuntu 24.04, ~55-60 clients): TAK started 12:04:11; the
console's boot LDAP heal saw Authentik's HTTP answer, probed the service-account bind at 12:05:04
while the LDAP outpost was still starting (it resolved groups only at 12:06:23), took the refusal
for password drift, reset the password and force-recreated the outpost twice under the
just-started TAK. The outage check ignored that outpost start (TAK up < 5 min = "box boot"), and
the stuck-client check dropped 538 connections over 8 h without ever escalating. A manual TAK
restart fixed it at once.

Three fixes, one test group each:
  A. the boot heal judges the bind only on a settled outpost, and only a bind that keeps failing
     is drift (no password reset or recreate during outpost startup);
  B. a console recreate of the outpost under a running TAK asks for one TAK restart, at any TAK
     uptime;
  C. when most connections stay stuck while LDAP answers, a 1-minute check restarts TAK once
     (3 stuck checks in a row, never before TAK is up 5 min; one restart per 6 h, then the alert
     only) and sends the Guard Dog alert email, instead of dropping connections forever.
"""

import json
import re
import subprocess
import types
import urllib.request

import pytest

from test_startup_ldap_resync_waits_for_authentik_ops438 import Boot
from test_tak_ldap_recycle import APP, HOUR, T0, Box, _const, _src, healthy_box, sess


# ── A. boot heal: no password reset or outpost recreate while the outpost starts ─────────────

OUTPOST_START = 30        # the outpost container starts 30 s after the console (post-start)
OUTPOST_READY_AFTER = 100  # field: it resolved groups ~100 s after its start


def starting_outpost(t):
    return (t >= OUTPOST_START, OUTPOST_START if t >= OUTPOST_START else None, 'healthy')


def bind_while_starting(t):
    """The outpost refuses the service-account bind (LDAP 49 → 'fail') until it is ready."""
    return 'ok' if t >= OUTPOST_START + OUTPOST_READY_AFTER else 'fail'


def _resyncs(b):
    return [e for e in b.events if e[0] == 'resync']


def test_field_reboot_no_password_reset_while_the_outpost_starts_gh616():
    """The field case: Authentik answers at once, the outpost needs 100 s. Old code: probe at
    t=0 → 'fail' → set_password + force-recreate. Fixed: no heal at all."""
    b = Boot(outpost=starting_outpost, verdict_at=bind_while_starting).go()
    assert _resyncs(b) == []
    assert ('probe', 'fail') not in b.events
    assert any('bind verified' in line for line in b.out)
    assert b.ns['_startup_ldap_resync_done'].is_set()


def test_boot_heal_probes_only_once_the_outpost_has_been_up_long_enough_gh616():
    probe_at = []
    b = Boot(outpost=starting_outpost,
             verdict_at=lambda t: probe_at.append(t) or bind_while_starting(t)).go()
    assert probe_at and probe_at[0] >= OUTPOST_START + b.ns['_STARTUP_LDAP_OUTPOST_UP_S']


def test_a_failed_bind_right_after_settle_is_confirmed_before_any_heal_gh616():
    """Even past the up-time gate, one refusal is not drift: it must fail on every confirm probe."""
    b = Boot(outpost=lambda t: (True, 0, 'healthy'), verdict_at=lambda t: 'ok' if t >= 150 else 'fail')
    b.clock[0] = 125
    b.go()
    assert _resyncs(b) == []
    assert ('probe', 'fail') in b.events and b.events[-1] == ('probe', 'ok')


def test_real_password_drift_still_heals_after_the_confirm_probes_gh616():
    b = Boot(verdicts=('fail', 'fail', 'fail', 'ok'), resync=((True, 'password set'),)).go()
    probes_before = b.events[:b.events.index(('resync', True))]
    assert [e for e in probes_before if e[0] == 'probe'] == [('probe', 'fail')] * b.ns['_STARTUP_LDAP_FAIL_CONFIRM']
    assert len(_resyncs(b)) == 1
    assert any('resync OK' in line for line in b.out)


def test_outpost_that_never_becomes_healthy_is_left_to_the_watchdog_gh616():
    b = Boot(outpost=lambda t: (True, 0, 'unhealthy'), verdicts=('fail',)).go()
    assert not any(e[0] in ('probe', 'resync') for e in b.events)
    assert any('LDAP outpost not settled' in line and 'unhealthy' in line for line in b.out)
    assert b.ns['_startup_ldap_resync_done'].is_set()


def test_outpost_restarting_during_the_confirm_is_not_drift_gh616():
    """A failed probe, then the outpost restarts (Guard Dog, OOM) and keeps restarting: no heal."""
    b = Boot(outpost=lambda t: (True, 0, 'healthy') if t < 200 else (True, t - 5, 'starting'),
             verdicts=('fail',))
    b.clock[0] = 150
    b.go()
    assert _resyncs(b) == []
    assert any('not a password drift' in line for line in b.out)


def test_remote_authentik_keeps_the_old_single_probe_gh616():
    """No local outpost to inspect: behavior unchanged (one probe, heal on 'fail')."""
    b = Boot(compose=False, verdicts=('fail', 'ok'), resync=((True, 'password set'),)).go()
    assert [e[0] for e in b.events][:2] == ['probe', 'resync']


# ── B. a console recreate of the outpost under a running TAK asks for a TAK restart ───────────

class _Resp:
    def __init__(self, body=None, code=200):
        self._b, self._c = json.dumps(body or {}).encode(), code

    def read(self):
        return self._b

    def getcode(self):
        return self._c


def _fake_authentik(req, timeout=10):
    url, method = req.full_url, req.get_method()
    if '/core/users/?search=adm_ldapservice' in url:
        return _Resp({'results': [{'pk': 7, 'username': 'adm_ldapservice', 'is_active': True, 'path': 'users'}]})
    if url.endswith('/set_password/') and method == 'POST':
        return _Resp(code=204)
    if '/core/groups/?search=' in url:
        return _Resp({'results': [{'pk': 1, 'name': 'authentik Admins', 'users': [7]}]})
    raise AssertionError((method, url))


def _ensure(monkeypatch, tak_start):
    monkeypatch.setattr(urllib.request, 'urlopen', _fake_authentik)
    events = []
    ns = {
        'os': __import__('os'), 'json': json, 'subprocess': subprocess,
        'time': types.SimpleNamespace(sleep=lambda s: None, time=lambda: T0),
        '_ensure_ldap_flow_authentication_none': lambda: (True, None),
        'load_settings': lambda: {},
        '_get_authentik_env_value': lambda s, k: 'secret',
        '_get_authentik_api_url': lambda s: 'http://ak.local',
        '_get_module_deployment_config': lambda s, k: {},
        '_sudo_wrap': lambda c: c,
        '_AK_COMPOSE_LOCK_BUSY_RC': 75,
        '_ak_compose_subprocess': lambda cmd, holder, plog, **kw: (
            events.append(('recreate', holder)) or subprocess.CompletedProcess(cmd, 0, stdout=b'', stderr=b'')),
        '_ensure_ldapsearch': lambda: True,
        '_wait_ldap_outpost_ready': lambda timeout_secs=180: (True, 'Up 30 seconds (healthy)'),
        '_test_ldap_bind_dn_verdict': lambda dn, pw: 'ok',
        '_coreconfig_has_ldap': lambda: True,
        '_tak_started_epoch': lambda: tak_start,
        '_TAK_LDAP_RECYCLE_MIN_TAK_UPTIME_S': 300,
        '_tak_ldap_recycle_request': lambda reason, need_groups=True, restart=False, restart_if_young=False: events.append(
            ('request', reason, restart_if_young)),
    }
    exec(compile(_src('_ensure_authentik_ldap_service_account'), 'app.py:_ensure_authentik_ldap_service_account',
                 'exec'), ns)
    ok, msg = ns['_ensure_authentik_ldap_service_account']()
    assert ok, msg
    return events


def test_console_recreate_under_a_just_started_tak_asks_for_a_tak_restart_gh616(monkeypatch):
    events = _ensure(monkeypatch, tak_start=T0 - 60)          # field: TAK up ~1 min
    assert ('recreate', 'ldap-sa-recreate') in events
    [req] = [e for e in events if e[0] == 'request']
    assert req[2] is True and 'recreated the LDAP outpost' in req[1]
    assert events.index(('recreate', 'ldap-sa-recreate')) < events.index(req)


def test_console_recreate_under_an_older_tak_asks_for_the_usual_heal_first_gh616(monkeypatch):
    """TAK up 2 days: the outage check already covers this; the request keeps its heal-first path
    (restart only as the fallback), so a recreate does not drop every client for nothing."""
    events = _ensure(monkeypatch, tak_start=T0 - 2 * 24 * HOUR)
    [req] = [e for e in events if e[0] == 'request']
    assert req[2] is False


def test_no_restart_request_when_tak_is_not_running_gh616(monkeypatch):
    events = _ensure(monkeypatch, tak_start=None)
    assert not [e for e in events if e[0] == 'request']


def test_the_request_restarts_a_tak_the_box_boot_rule_would_skip_gh616():
    """Outpost recreated 60 s after TAK started: the outpost-start rule calls that a box boot and
    does nothing (the field gap). With the request the console now files, TAK is restarted once
    LDAP answers."""
    box = healthy_box(tak_start=T0 - 60, ldap_start=T0)
    assert box.recycle(trigger='boot LDAP service-account heal', final=False) is False
    assert box.restarts() == []
    box.request('the console recreated the LDAP outpost (service-account password resync) under a '
                'running TAK Server', restart_if_young=True)
    assert box.recycle(trigger='boot LDAP service-account heal', final=False) is True
    assert len(box.restarts()) == 1


# ── C. most clients stuck while LDAP answers → one TAK restart and an alert email ─────────────
# AJ (Nov 20, "mission critical"): the stack gets 5 min after TAK starts; then 3 stuck checks in
# a row, 1 min apart, restart TAK once. One restart per 6 h; inside that, the alert only.

MIN = 60


def mass_box(n_stuck=6, **kw):
    """The field state: TAK's own LDAP lookups fail, so every client comes back with no user and
    no groups after a drop; LDAP itself is healthy."""
    kw.setdefault('tak_start', T0 - 3 * 24 * HOUR)
    box = healthy_box(tak_ldap_ok=False, **kw)
    for i in range(n_stuck):
        box.subs.append(sess(40 + i, f'phone{i}', (), unmapped=True, client=f'ANDROID-phone{i}'))
        box.ldap_users[f'phone{i}'] = 1
    box.alerts = []
    return box


def checker(box):
    """The console's 1-minute stuck-phones thread: one process, so its memory lives across
    checks. `check(dt)` = dt seconds later, run one check; returns what it did."""
    ns = box.ns()
    for c in ('_TAK_STUCK_MASS_MIN', '_TAK_STUCK_MASS_PCT', '_TAK_STUCK_MASS_TICK_S', '_TAK_STUCK_MASS_CHECKS',
              '_TAK_STUCK_MASS_DEADLINE_S', '_TAK_STUCK_MASS_RESTART_GAP_S', '_TAK_STUCK_MASS_ALERT_GAP_S'):
        ns[c] = _const(c)
    ns['_tak_stuck_mass'] = {'streak': 0, 'since': 0.0, 'tak_start': None}
    ns['_tak_stuck_clients_alert'] = lambda plog, outcome, detail, **kw: box.alerts.append(
        (box.t, outcome, detail, kw))
    for name in ('_tak_stuck_mass_escalate', '_tak_stuck_mass_check'):
        exec(compile(_src(name), f'app.py:{name}', 'exec'), ns)

    def check(dt=MIN):
        box.t += dt
        return ns['_tak_stuck_mass_check'](box.log.append)
    return check


def test_the_new_numbers_gh616():
    assert _const('_TAK_STUCK_MASS_TICK_S') == 60
    assert _const('_TAK_STUCK_MASS_CHECKS') == 3
    assert _const('_TAK_STUCK_MASS_DEADLINE_S') == 300
    assert _const('_TAK_STUCK_MASS_RESTART_GAP_S') == 6 * HOUR


def test_mass_stuck_clients_restart_tak_after_three_checks_a_minute_apart_gh616():
    box = mass_box()                                   # 6 of 10 connections stuck, TAK up 3 days
    check = checker(box)
    assert check(0) is None and check() is None        # 1st and 2nd stuck check
    assert box.restarts() == []
    assert check() == 'restart'                        # 3rd in a row, 2 min after the first
    assert len(box.restarts()) == 1
    assert len(box.alerts) == 1 and box.alerts[0][1] == 'TAK Server restarted'
    assert '6 of 10' in box.alerts[0][2]
    assert any('restarting TAK Server once' in line for line in box.log)


def test_field_reboot_restart_at_the_5_minute_deadline_not_before_gh616():
    """Field: TAK started, phones stuck from its first minute. Restart when TAK has been up 5 min,
    not at 3 min (a normal slow boot) and not 20 min later."""
    box = mass_box(tak_start=T0)
    check = checker(box)
    done_at = None
    for _ in range(10):
        at = box.t + MIN - T0                          # TAK's age when this check runs
        if check() == 'restart':
            done_at = at
            break
    assert done_at == 5 * MIN
    assert len(box.restarts()) == 1
    assert box.alerts[0][3].get('after_boot') is True


def test_a_healthy_check_starts_the_count_over_gh616():
    box = mass_box()
    check = checker(box)
    check(0)
    check()
    phones = [s for s in box.subs if s['_cn'].startswith('phone')]
    saved = [dict(s) for s in phones]
    for s in phones:                                   # TAK's own refresh gave them their groups
        s.update(sess(0, s['_cn'], ('OPS',)), subscriptionUid=s['subscriptionUid'])
    assert check() is None
    for s, old in zip(phones, saved):                  # and they are lost again
        s.clear()
        s.update(old)
    assert check() is None and check() is None
    assert box.restarts() == []
    assert check() == 'restart'


def test_an_unreadable_client_list_keeps_the_count_but_adds_nothing_gh616():
    box = mass_box()
    check = checker(box)
    check(0)
    check()
    box.api_ok = False
    assert check() is None
    box.api_ok = True
    assert check() == 'restart'                        # 3 stuck checks, not 3 minutes


def test_mass_restart_is_at_most_once_per_six_hours_and_never_loops_gh616():
    box = mass_box()
    check = checker(box)
    check(0)
    check()
    assert check() == 'restart'
    did = [check() for _ in range(110)]                # TAK came back stuck; ~2 h of checks
    assert len(box.restarts()) == 1
    assert did.count('alert') == 2 and 'restart' not in did     # at ~5 min, then an hour later
    assert len(box.alerts) == 3
    assert box.alerts[1][1] == 'TAK Server NOT restarted again'
    assert box.alerts[1][3].get('restarted_min_ago') is not None
    assert any('NOT restarting again' in line for line in box.log)


def test_a_second_stuck_state_inside_six_hours_alerts_again_without_a_restart_gh616():
    box = mass_box()
    check = checker(box)
    check(0)
    check()
    assert check() == 'restart'
    phones = [s for s in box.subs if s['_cn'].startswith('phone')]
    saved = [dict(s) for s in phones]
    for s in phones:                                   # healed by the restart
        s.update(sess(0, s['_cn'], ('OPS',)), subscriptionUid=s['subscriptionUid'])
    for _ in range(90):
        assert check() is None
    for s, old in zip(phones, saved):                  # 1.5 h later: stuck again
        s.clear()
        s.update(old)
    did = [check() for _ in range(10)]
    assert did.count('alert') == 1 and 'restart' not in did
    assert len(box.restarts()) == 1 and len(box.alerts) == 2


def test_after_six_hours_a_new_stuck_state_restarts_again_gh616():
    box = mass_box()
    check = checker(box)
    check(0)
    check()
    assert check() == 'restart'
    for _ in range(6 * 60 + 10):
        check()
    assert len(box.restarts()) == 2


def test_mass_restart_never_into_a_broken_ldap_gh616():
    box = mass_box(ldap=lambda b: (49, 0))
    check = checker(box)
    for _ in range(10):
        check()
    assert box.restarts() == [] and box.alerts == []


def test_mass_restart_waits_for_a_running_console_update_gh616():
    box = mass_box(update_in_progress=True)
    check = checker(box)
    for _ in range(10):
        check()
    assert box.restarts() == [] and box.alerts == []


def test_a_few_stuck_clients_are_never_a_mass_restart_gh616():
    """Two stuck phones among ten connections (the ops #565 enrollment race): the 10-min drop's job."""
    box = mass_box(n_stuck=2)
    check = checker(box)
    for _ in range(30):
        check()
    assert box.restarts() == [] and box.alerts == []


def test_a_minority_stuck_is_never_a_mass_restart_gh616():
    """Five stuck of twelve (below half)."""
    box = mass_box(n_stuck=5)
    for i in range(3):
        box.subs.append(sess(80 + i, f'ok{i}'))
        box.ldap_users[f'ok{i}'] = 1
    check = checker(box)
    for _ in range(30):
        check()
    assert box.restarts() == []


def test_nothing_to_do_without_ldap_in_coreconfig_gh616():
    box = mass_box(coreconfig=False)
    check = checker(box)
    for _ in range(10):
        check()
    assert box.restarts() == [] and box.alerts == []


def test_the_check_runs_on_its_own_1_minute_thread_not_the_10_minute_monitor_gh616():
    assert re.search(r"threading\.Thread\(target=_tak_stuck_mass_loop, daemon=True", APP)
    loop = _src('_tak_stuck_mass_loop')
    assert 'time.sleep(_TAK_STUCK_MASS_TICK_S)' in loop and '_tak_stuck_mass_check(' in loop
    assert '_tak_stuck_mass_escalate(' not in _src('_tak_drop_stuck_unnamed_sessions')
    assert not re.search(r'^_TAK_STUCK_MASS_ESCALATE_S = ', APP, re.M)     # the 20-min rule is gone


class _Mail:
    def __init__(self):
        self.sent = []

    def __call__(self, to, subj, body):
        self.sent.append((to, subj, body))


def _alert_ns(email='ops@example.org'):
    mail, lines = _Mail(), []
    ns = {'datetime': __import__('datetime').datetime, 'socket': __import__('socket'),
          '_write_priv': lambda p, data, mode='w': lines.append((p, data)),
          'load_settings': lambda: {'guarddog_alert_email': email},
          '_guarddog_server_identifier': lambda s: 'box1',
          '_guarddog_send_alert_email_via_relay': mail,
          '_TAK_STUCK_MASS_RESTART_GAP_S': _const('_TAK_STUCK_MASS_RESTART_GAP_S')}
    exec(compile(_src('_tak_stuck_clients_alert'), 'app.py:_tak_stuck_clients_alert', 'exec'), ns)
    return ns['_tak_stuck_clients_alert'], mail, lines


def test_the_restart_alert_is_an_email_in_plain_words_gh616():
    alert, mail, lines = _alert_ns()
    alert(print, 'TAK Server restarted', '6 of 10 ...', after_boot=True)
    [(to, subj, body)] = mail.sent
    assert to == 'ops@example.org'
    assert subj == '⚠ TAK Server restarted: phones had no groups (box1)'
    assert body.startswith('Phones had no groups after a reboot. Guard Dog restarted TAK Server.')
    assert lines and lines[0][0] == '/var/log/takguard/restarts.log' and 'tak-stuck-clients' in lines[0][1]


def test_the_no_restart_alert_says_why_and_what_to_do_gh616():
    alert, mail, _ = _alert_ns()
    alert(print, 'TAK Server NOT restarted again', '6 of 10 ...', restarted_min_ago=7)
    [(_to, subj, body)] = mail.sent
    assert 'NOT restarted' in subj
    assert 'restarted TAK Server 7 min ago' in body and 'at most once every 6 hours' in body
    assert 'open the TAK Server page and restart TAK Server' in body.replace('Open', 'open')
