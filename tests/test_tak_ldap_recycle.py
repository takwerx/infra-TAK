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
"""TAK Server is restarted once LDAP is healthy again after an outage under it (ops #126, GH #189).

After v10.2.22 → v10.2.23 a field box (TAK 5.8) kept ATAK/CloudTAK connected with no CoT:
sessions that logged in while the outpost was down held empty groups and TAK's pooled LDAP
connections stayed dead until `systemctl restart takserver`. Nothing restarted TAK.

_tak_recycle_after_ldap_outage() and its helpers are cut out of app.py and run with docker,
systemctl, ldapsearch, the ports and the clock stubbed.
"""

import datetime
import os
import re
import subprocess
import threading
import types

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(REPO, 'app.py'), encoding='utf-8') as _f:
    APP = _f.read()
SA_PASS = 'sa-secret-do-not-log'
T0 = 1_800_000_000.0          # fake "now" at the start of each test
BOOT = T0 - 400_000           # the box booted ~4.6 days earlier
HOUR = 3600


def _src(name):
    return re.search(r'^def %s\(.*?(?=^def |^# |^_[A-Z_]+ = |\Z)' % name, APP, re.S | re.M).group(0)


def _const(name):
    return int(re.search(r'^%s = (\d+)' % name, APP, re.M).group(1))


def _rfc3339(epoch):
    return datetime.datetime.utcfromtimestamp(int(epoch)).strftime('%Y-%m-%dT%H:%M:%S') + '.123456789Z'


def _ldif(groups):
    out = []
    for i in range(4):
        out.append(f'dn: cn=user{i},ou=users,dc=takldap')
        if i < groups:
            out.append('memberOf: cn=tak_OPS,ou=groups,dc=takldap')
        out.append('')
    return '\n'.join(out) + '\nresult: 0 Success\n'


class Box:
    """A fake single box: TAK (native or container), the LDAP outpost, the clock."""

    def __init__(self, tak_start, ldap_start=None, container=False, ldap=lambda box: (0, 3),
                 settings=None, coreconfig=True, update_in_progress=False, restart_rc=0, tak_running=True):
        self.t = T0
        self.tak_start = tak_start
        self.ldap_start = ldap_start
        self.container = container
        self.ldap = ldap
        self.settings = settings if settings is not None else {}
        self.coreconfig = coreconfig
        self.update_in_progress = update_in_progress
        self.restart_rc = restart_rc
        self.tak_running = tak_running
        self.ports_up_at = 0.0
        self.calls, self.log = [], []

    def run(self, cmd, **kw):
        self.calls.append(list(cmd))
        ok = lambda out='': subprocess.CompletedProcess(cmd, 0, stdout=out, stderr='')
        if cmd[:3] == ['systemctl', 'show', 'takserver']:
            assert not self.container
            if not self.tak_running:
                return ok('ActiveState=inactive\nActiveEnterTimestampMonotonic=0\n')
            mono = int((self.tak_start - BOOT) * 1e6)
            return ok(f'ActiveState=active\nActiveEnterTimestampMonotonic={mono}\n')
        if cmd[:2] == ['docker', 'inspect']:
            name = cmd[-1]
            start = {'takserver': self.tak_start if self.tak_running else None,
                     'authentik-ldap-1': self.ldap_start}.get(name)
            if start is None:
                return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='No such object')
            return ok(f'true {_rfc3339(start)}\n')
        if cmd in (['systemctl', 'restart', 'takserver'], ['docker', 'restart', 'takserver']):
            self.t += 20
            if self.restart_rc == 0:
                self.tak_start = self.t
                self.ports_up_at = self.t + 120
            return subprocess.CompletedProcess(cmd, self.restart_rc, stdout='', stderr='boom' if self.restart_rc else '')
        if cmd[0] == 'ldapsearch':
            rc, groups = self.ldap(self)
            if rc == 49:
                return subprocess.CompletedProcess(cmd, 49, stdout='', stderr='ldap_bind: Invalid credentials (49)\n')
            return ok(_ldif(groups))
        raise AssertionError(cmd)

    def sleep(self, s):
        self.t += s

    def restarts(self):
        return [c for c in self.calls if c[1:2] == ['restart']]

    def ns(self):
        box = self
        ns = {
            'os': types.SimpleNamespace(path=types.SimpleNamespace(
                exists=lambda p: box.coreconfig if p == '/opt/tak/CoreConfig.xml' else os.path.exists(p),
                join=os.path.join)),
            'subprocess': types.SimpleNamespace(run=self.run, TimeoutExpired=subprocess.TimeoutExpired),
            'time': types.SimpleNamespace(time=lambda: box.t, monotonic=lambda: box.t - BOOT, sleep=self.sleep),
            'datetime': datetime.datetime,
            're': re,
            'threading': threading,
            '_sudo_wrap': lambda c: c,
            '_tak_is_container': lambda: box.container,
            'TAK_CONTAINER': 'takserver',
            '_coreconfig_has_ldap': lambda: box.coreconfig,
            'load_settings': lambda: box.settings,
            'save_settings': lambda s: box.settings.update(s),
            '_get_authentik_env_value': lambda s, k: SA_PASS if k == 'AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD' else None,
            '_ensure_ldapsearch': lambda: True,
            '_console_update_in_progress': lambda: box.update_in_progress,
            '_tcp_accepts': lambda port, host='127.0.0.1': box.t >= box.ports_up_at,
        }
        for c in ('_PGB_SWAP_LDAP_WINDOW_S', '_PGB_SWAP_LDAP_STABLE_S', '_PGB_SWAP_LDAP_EVERY_S',
                  '_TAK_LDAP_RECYCLE_MIN_TAK_UPTIME_S', '_TAK_RECYCLE_8089_TIMEOUT_S', '_TAK_RECYCLE_API_TIMEOUT_S'):
            ns[c] = _const(c)
        ns['_tak_ldap_recycle_lock'] = threading.Lock()
        for name in ('_epoch_from_rfc3339', '_docker_started_epoch', '_tak_started_epoch', '_tak_wait_ready',
                     '_tak_ldap_recycle_request', '_tak_recycle_after_ldap_outage',
                     '_authentik_ldap_sa_group_probe', '_authentik_ldap_sa_groups_settle'):
            exec(compile(_src(name), f'app.py:{name}', 'exec'), ns)
        return ns

    def recycle(self, trigger='end of console update', check_outpost=True, final=True):
        return self.ns()['_tak_recycle_after_ldap_outage'](self.log.append, trigger,
                                                           check_outpost=check_outpost, final=final)

    def request(self, reason, need_groups=True):
        self.ns()['_tak_ldap_recycle_request'](reason, need_groups)


# ── restart after a good settle ─────────────────────────────────────────────────────

def test_requested_restart_happens_after_ldap_settles_and_waits_for_the_ports():
    box = Box(tak_start=T0 - 3 * 24 * HOUR)
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    restart = ['systemctl', 'restart', 'takserver']
    assert box.restarts() == [restart]
    i = box.calls.index(restart)
    probes_before = [c for c in box.calls[:i] if c[0] == 'ldapsearch']
    assert len(probes_before) >= _const('_PGB_SWAP_LDAP_STABLE_S') // _const('_PGB_SWAP_LDAP_EVERY_S')
    assert any('held' in l and 'before the TAK Server restart' in l for l in box.log)
    assert any('8089 accepting connections' in l for l in box.log)
    assert any('API (8443) up' in l for l in box.log)
    assert any('✓ TAK LDAP recycle: TAK Server restarted after LDAP settled' in l for l in box.log)
    st = box.settings['tak_ldap_recycle']
    assert 'pending' not in st and st['last_outcome'] == 'restarted'


def test_memberof_zero_window_delays_the_restart_until_groups_are_back():
    box = Box(tak_start=T0 - 3 * 24 * HOUR, ldap=lambda b: (0, 0) if b.t < T0 + 30 else (0, 3))
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    i = box.calls.index(['systemctl', 'restart', 'takserver'])
    assert any('NO tak_ groups' in l for l in box.log)
    assert [c for c in box.calls[:i] if c[0] == 'ldapsearch']


def test_ldap_still_broken_means_no_restart_and_the_request_stays():
    box = Box(tak_start=T0 - 3 * 24 * HOUR, ldap=lambda b: (49, 0))
    box.request('PgBouncer image swap')
    assert box.recycle() is False
    assert box.restarts() == []
    st = box.settings['tak_ldap_recycle']
    assert st['pending'] == ['PgBouncer image swap']
    assert any('NOT restarted' in l for l in box.log)
    # ...and the next console start carries it out once LDAP is good again
    box.ldap = lambda b: (0, 3)
    assert box.recycle(trigger='console start', check_outpost=False) is True
    assert len(box.restarts()) == 1


def test_box_without_tak_groups_needs_only_the_bind():
    box = Box(tak_start=T0 - 3 * 24 * HOUR, ldap=lambda b: (0, 0))
    box.request('PgBouncer image swap', need_groups=False)
    assert box.recycle() is True


# ── no double restart ───────────────────────────────────────────────────────────────

def test_tak_already_restarted_after_the_request_is_reused():
    box = Box(tak_start=T0 - 3 * 24 * HOUR)
    box.request('PgBouncer image swap')
    box.tak_start = box.t + 5          # e.g. run_authentik_deploy restarted TAK later in the run
    box.t += 600
    assert box.recycle() is False
    assert box.restarts() == []
    assert any('reusing that restart' in l for l in box.log)
    assert 'pending' not in box.settings['tak_ldap_recycle']


def test_two_callers_restart_tak_once():
    box = Box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - 2 * HOUR)
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    assert box.recycle(trigger='boot LDAP service-account heal') is False
    assert box.recycle(trigger='Resync LDAP to TAK Server') is False
    assert len(box.restarts()) == 1


def test_outside_an_update_the_boot_heal_does_it_itself_but_during_one_it_defers():
    box = Box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - 60, update_in_progress=True)
    assert box.recycle(trigger='boot LDAP service-account heal', final=False) is False
    assert box.restarts() == []
    assert any('deferred to the end of the console update' in l for l in box.log)
    assert box.settings['tak_ldap_recycle']['pending']
    # the update's own final call restarts TAK once
    box.t += 300
    assert box.recycle(final=True) is True
    assert len(box.restarts()) == 1
    assert 'pending' not in box.settings['tak_ldap_recycle']


def test_request_made_while_recycling_is_not_lost():
    box = Box(tak_start=T0 - 3 * 24 * HOUR)
    box.request('PgBouncer image swap')
    orig = box.ldap

    def ldap_and_a_new_request(b):
        if b.t > T0 and not b.settings.get('_late'):     # mid-settle, after the first probe
            b.settings['_late'] = True
            b.request('late step')
        return orig(b)
    box.ldap = ldap_and_a_new_request
    assert box.recycle() is True
    assert box.settings['tak_ldap_recycle'].get('pending') == ['PgBouncer image swap', 'late step']


# ── the outpost check (item 5: one-time catch-up for boxes already on v10.2.23) ─────

def test_outpost_recreated_under_a_running_tak_triggers_one_restart_on_update():
    # Amos: outpost recreated by v10.2.22 a day ago; TAK running since before that.
    box = Box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=T0 - 24 * HOUR)
    assert box.recycle() is True
    assert len(box.restarts()) == 1
    assert any('LDAP outpost restarted while TAK Server was running' in l for l in box.log)
    # one-time: the next update finds TAK started after the outpost
    box.t += 7 * 24 * HOUR
    assert box.recycle() is False
    assert len(box.restarts()) == 1


def test_box_boot_order_never_restarts_tak():
    # Boot: TAK and Authentik come up together; the boot heal recreates the outpost ~100 s in.
    for gap in (-30, 0, 100, _const('_TAK_LDAP_RECYCLE_MIN_TAK_UPTIME_S') - 1):
        box = Box(tak_start=T0 - 200, ldap_start=T0 - 200 + gap)
        assert box.recycle(trigger='boot LDAP service-account heal', final=False) is False, gap
        assert box.restarts() == []


def test_outpost_check_off_ignores_the_outpost():
    box = Box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=T0 - HOUR)
    assert box.recycle(trigger='console start', check_outpost=False) is False
    assert box.restarts() == []


def test_no_local_outpost_container_no_restart():
    # Remote Authentik: nothing local to compare against.
    box = Box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=None)
    assert box.recycle() is False
    assert box.restarts() == []


# ── nothing to do / can't do ────────────────────────────────────────────────────────

def test_tak_not_running_or_not_on_ldap_does_nothing():
    for kw in ({'tak_running': False}, {'coreconfig': False}):
        box = Box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=T0 - HOUR, **kw)
        box.request('PgBouncer image swap')
        assert box.recycle() is False, kw
        assert box.restarts() == []
        assert 'pending' not in box.settings['tak_ldap_recycle']


def test_failed_restart_is_logged_and_kept():
    box = Box(tak_start=T0 - 4 * 24 * HOUR, restart_rc=1)
    box.request('PgBouncer image swap')
    assert box.recycle() is False
    assert any('TAK Server restart failed' in l for l in box.log)
    assert box.settings['tak_ldap_recycle']['pending']


def test_sa_password_is_never_logged():
    box = Box(tak_start=T0 - 4 * 24 * HOUR, ldap=lambda b: (49, 0))
    box.request('x')
    box.recycle()
    assert not [l for l in box.log if SA_PASS in l]


# ── where TAK runs: container, native, split (two_server) ───────────────────────────

def test_container_tak_is_restarted_with_docker():
    box = Box(tak_start=T0 - 4 * 24 * HOUR, container=True)
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    assert box.restarts() == [['docker', 'restart', 'takserver']]


def test_split_box_restarts_tak_locally_and_never_touches_the_db_host():
    # two_server: Server One is the database only; TAK core runs here (Server Two).
    settings = {'tak_deployment': {'mode': 'two_server', 'server_one': {'host': '10.0.0.9'}}}
    box = Box(tak_start=T0 - 4 * 24 * HOUR, settings=settings)
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    assert box.restarts() == [['systemctl', 'restart', 'takserver']]
    assert not [c for c in box.calls if c[0] in ('ssh', 'scp') or '10.0.0.9' in ' '.join(c)]


def test_native_start_time_uses_the_monotonic_clock():
    box = Box(tak_start=T0 - 12345.0)
    assert box.ns()['_tak_started_epoch']() == pytest.approx(T0 - 12345.0, abs=0.01)


def test_docker_timestamps_parse():
    f = Box(tak_start=T0).ns()['_epoch_from_rfc3339']
    assert f('1970-01-01T00:00:10.5Z') == pytest.approx(10.5)
    assert f('2026-10-21T01:41:16.534837635Z') == pytest.approx(1792546876.534837635, abs=1e-3)
    assert f('2026-10-21T03:41:16+02:00') == pytest.approx(1792546876, abs=1e-3)
    assert f('garbage') is None and f('') is None


def test_request_merges_reasons_and_keeps_need_groups():
    box = Box(tak_start=T0)
    box.request('a', need_groups=True)
    box.request('b', need_groups=False)
    box.request('a', need_groups=False)
    st = box.settings['tak_ldap_recycle']
    assert st['pending'] == ['b', 'a'] and st['need_groups'] is True


# ── wiring ──────────────────────────────────────────────────────────────────────────

def test_update_run_recycles_last_with_the_outpost_check():
    i = APP.index("_tak_recycle_after_ldap_outage(lambda m: print(f\"Post-update:{m}\"")
    before = APP[:i]
    assert before.rindex('_post_update_service_recovery_sweep(') > before.rindex('def _run_post_update')
    call = APP[i:i + 300]
    assert 'check_outpost=True' in call and 'final=True' in call
    assert APP.index('print("Post-update: auto-deploy complete")') > i


def test_same_version_start_only_carries_out_pending_requests():
    i = APP.index("'console start', check_outpost=False, final=True")
    branch_start = APP.index('if last_ver == VERSION and (cur_sha', APP.index('def _post_update_auto_deploy'))
    branch_end = APP.index("lock_path = '/tmp/takwerx-post-update.lock'", branch_start)
    assert branch_start < i < branch_end                  # the same-version (no update run) branch
    assert ".get('pending')" in APP[i - 600:i]


def test_boot_sa_heal_uses_the_helper_not_its_own_restart():
    src = _src('_startup_resync_ldap_service_account')
    assert "'boot LDAP service-account heal', check_outpost=True" in src
    assert 'final=True' not in src.split("'boot LDAP service-account heal'")[1][:80]


def test_resync_ldap_button_recycles_in_the_background():
    src = APP[APP.index('def takserver_connect_ldap'):]
    src = src[:src.index("return jsonify({'success': overall_ok")]
    assert "'Resync LDAP to TAK Server', check_outpost=True" in src
    assert 'threading.Thread(' in src[-1200:]


def test_restart_is_argv_not_shell():
    src = _src('_tak_recycle_after_ldap_outage')
    assert 'shell=True' not in src
    assert "['systemctl', 'restart', 'takserver']" in src and "['docker', 'restart', TAK_CONTAINER]" in src
