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
  C. when most connections stay stuck while LDAP answers, the stuck-client check restarts TAK once
     and sends the Guard Dog alert, instead of dropping connections forever.
"""

import json
import re
import subprocess
import types
import urllib.request

import pytest

from test_startup_ldap_resync_waits_for_authentik_ops438 import Boot
from test_tak_ldap_recycle import APP, HOUR, T0, Box, _src, healthy_box, sess
from test_stuck_unnamed_client_ops565 import TICK, monitor


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
        '_tak_ldap_recycle_request': lambda reason, need_groups=True, restart=False: events.append(
            ('request', reason, restart)),
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
                'running TAK Server', restart=True)
    assert box.recycle(trigger='boot LDAP service-account heal', final=False) is True
    assert len(box.restarts()) == 1


# ── C. most clients stuck while LDAP answers → one TAK restart and an alert ───────────────────

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


def test_mass_stuck_clients_restart_tak_once_and_alert_gh616():
    box = mass_box()                                   # 6 of 10 connections stuck
    tick = monitor(box)
    assert tick(0) == []
    assert len(tick(TICK)) == 6                        # 10 min: dropped, as before
    box.t += 20                                        # they reconnect, stuck again
    assert box.restarts() == []
    tick(TICK - 20)                                    # 20 min stuck in all: escalate
    assert len(box.restarts()) == 1
    assert len(box.alerts) == 1 and 'TAK Server restarted' in box.alerts[0][1]
    assert '6 of 10' in box.alerts[0][2]
    assert any('restarting TAK Server once' in line for line in box.log)


def test_mass_restart_is_at_most_once_per_six_hours_gh616():
    box = mass_box()
    tick = monitor(box)
    tick(0)
    tick(TICK)
    box.t += 20
    tick(TICK - 20)
    assert len(box.restarts()) == 1
    for _ in range(12):                                # 2 h more, still stuck: drops only
        tick(TICK)
    assert len(box.restarts()) == 1 and len(box.alerts) == 1


def test_mass_restart_never_into_a_broken_ldap_gh616():
    box = mass_box(ldap=lambda b: (49, 0))
    tick = monitor(box)
    for _ in range(6):
        tick(TICK)
    assert box.restarts() == [] and box.alerts == []


def test_mass_restart_waits_for_a_running_console_update_gh616():
    box = mass_box(update_in_progress=True)
    tick = monitor(box)
    for _ in range(6):
        tick(TICK)
    assert box.restarts() == [] and box.alerts == []


def test_a_few_stuck_clients_are_never_a_mass_restart_gh616():
    """Two stuck phones among ten connections (the ops #565 enrollment race): drops only."""
    box = mass_box(n_stuck=2)
    tick = monitor(box)
    for _ in range(8):
        tick(TICK)
        box.t += 20
    assert box.restarts() == [] and box.alerts == []
    assert box.drops()


def test_a_minority_stuck_is_never_a_mass_restart_gh616():
    """Five stuck of twelve (below half): drops only."""
    box = mass_box(n_stuck=5)
    for i in range(3):
        box.subs.append(sess(80 + i, f'ok{i}'))
        box.ldap_users[f'ok{i}'] = 1
    tick = monitor(box)
    for _ in range(8):
        tick(TICK)
        box.t += 20
    assert box.restarts() == []


def test_mass_escalation_code_exists_in_the_monitor_path_gh616():
    body = _src('_tak_drop_stuck_unnamed_sessions')
    assert '_tak_stuck_mass_escalate(' in body
    assert re.search(r'^_TAK_STUCK_MASS_RESTART_GAP_S = \d+', APP, re.M)
