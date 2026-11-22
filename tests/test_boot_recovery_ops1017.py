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
"""ops #1017: after a real reboot, the console checks that every module came back, starts what
did not, checks again and tells the operator in plain words.

Why it exists: Guard Dog's boot sequencer stops Authentik, TAK Portal, CloudTAK and Node-RED before
TAK starts, and tak-post-start.service (one shot, 1200 s limit) starts them again. A `docker stop`
keeps `restart: unless-stopped` from restarting them, so when that one shot is slow, killed or
fails, nothing on the box ever starts them again (ops #438, the OS-upgrade path only).
"""

import datetime
import re
import socket
import subprocess
import threading
import time
import types
from pathlib import Path

APP = (Path(__file__).resolve().parent.parent / 'app.py').read_text()


def _block():
    """The new code, taken from app.py: the constants and every _boot_* / _startup_boot_* function."""
    start = APP.index('_BOOT_RECOVERY_FIRST_CHECK_S = ')
    end = APP.index('# ops #284 (field, 2026-10-27): boxes that v10.3.0 stopped')
    return APP[start:end]


class Sys:
    """A fake box: systemd units and Docker containers, and a record of every start."""

    def __init__(self, units=None, containers=None):
        self.units = dict(units or {})              # name -> (enabled, active)
        self.containers = dict(containers or {})    # name -> (policy, state)
        self.started = []
        self.fail = set()

    def run(self, cmd, **kw):
        out, rc = '', 0
        if cmd[:2] == ['systemctl', 'is-enabled']:
            out = 'enabled' if self.units.get(cmd[2], (False, ''))[0] else 'disabled'
            rc = 0 if out == 'enabled' else 1
        elif cmd[:2] == ['systemctl', 'is-active']:
            out = self.units.get(cmd[2], (False, 'inactive'))[1]
        elif cmd[:2] == ['systemctl', 'start']:
            if cmd[2] in self.fail:
                rc = 1
            else:
                self.units[cmd[2]] = (self.units[cmd[2]][0], 'active')
                self.started.append(cmd[2])
        elif cmd[:3] == ['docker', 'ps', '-a']:
            out = '\n'.join(self.containers)
        elif cmd[:2] == ['docker', 'inspect']:
            out = '\n'.join(f'/{n}\t{self.containers[n][0]}\t{self.containers[n][1]}' for n in cmd[4:])
        elif cmd[:2] == ['docker', 'start']:
            if cmd[2] in self.fail:
                rc = 1
            else:
                self.containers[cmd[2]] = (self.containers[cmd[2]][0], 'running')
                self.started.append(cmd[2])
        return types.SimpleNamespace(stdout=out, stderr='', returncode=rc)


def load(**extra):
    ns = {'subprocess': subprocess, 'time': time, 'datetime': datetime.datetime, 'socket': socket,
          'threading': threading, '_sudo_wrap': lambda c: c, 're': re}
    ns.update(extra)
    exec(compile(_block(), 'app-block', 'exec'), ns)
    return ns


FIELD_BOX = dict(
    units={'docker': (True, 'active'), 'takserver': (True, 'active'), 'caddy': (True, 'active'),
           'mediamtx': (True, 'inactive'), 'mediamtx-webeditor': (True, 'inactive'),
           'fail2ban': (True, 'active'), 'takwerx-broker': (True, 'active'), 'tak-health': (True, 'active'),
           'postgresql': (False, 'inactive')},
    containers={'authentik-postgresql-1': ('unless-stopped', 'exited'), 'authentik-redis-1': ('unless-stopped', 'running'),
                'authentik-server-1': ('unless-stopped', 'exited'), 'authentik-ldap-1': ('unless-stopped', 'exited'),
                'tak-portal': ('unless-stopped', 'exited'), 'tak-portal-postgres': ('unless-stopped', 'running'),
                'cloudtak-api-1': ('always', 'running'), 'nodered': ('unless-stopped', 'exited'),
                'webapp': ('unless-stopped', 'exited'),            # not ours
                'cloudtak-init-1': ('no', 'exited')})              # a one-shot


# ── probe ─────────────────────────────────────────────────────────────────────────────────────

def test_probe_lists_what_should_run_and_does_not_ops1017():
    ns = load()
    down = ns['_boot_recovery_probe'](run=Sys(**FIELD_BOX).run)
    names = sorted(i['name'] for i in down)
    assert names == ['authentik-ldap-1', 'authentik-postgresql-1', 'authentik-server-1', 'mediamtx',
                     'mediamtx-webeditor', 'nodered', 'tak-portal'], names


def test_probe_ignores_disabled_units_other_stacks_and_one_shots_ops1017():
    ns = load()
    names = {i['name'] for i in ns['_boot_recovery_probe'](run=Sys(**FIELD_BOX).run)}
    assert 'postgresql' not in names        # unit not enabled on this box
    assert 'webapp' not in names            # not an infra-TAK stack
    assert 'cloudtak-init-1' not in names   # restart policy "no": a one-shot, not meant to stay up


def test_probe_does_not_start_something_that_is_still_starting_ops1017():
    ns = load()
    box = Sys(units={'caddy': (True, 'activating')}, containers={'nodered': ('unless-stopped', 'restarting')})
    down = {i['name']: i for i in ns['_boot_recovery_probe'](run=box.run)}
    assert down['caddy']['repair'] is False and down['nodered']['repair'] is False
    assert box.started == []


def test_start_order_is_docker_then_databases_then_apps_then_ldap_ops1017():
    ns = load()
    items = [{'kind': 'container', 'name': n} for n in ('authentik-ldap-1', 'authentik-server-1', 'authentik-postgresql-1',
                                                         'tak-portal', 'authentik-redis-1')]
    items += [{'kind': 'unit', 'name': 'mediamtx'}, {'kind': 'unit', 'name': 'docker'}]
    order = [i['name'] for i in sorted(items, key=ns['_boot_recovery_start_order'])]
    assert order[:2] == ['docker', 'mediamtx']
    assert order.index('authentik-postgresql-1') < order.index('authentik-server-1') < order.index('authentik-ldap-1')
    assert order[-1] == 'authentik-ldap-1'


# ── the check ─────────────────────────────────────────────────────────────────────────────────

class Clock:
    def __init__(self, uptime):
        self.t = float(uptime)
        self.sleeps = []

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s

    def uptime(self):
        return self.t


def run_check(box, clock, **kw):
    ns = load()
    alerts, logs = [], []
    probe = lambda: ns['_boot_recovery_probe'](run=box.run)
    repair = lambda item: ns['_boot_recovery_repair'](item, run=box.run)
    result = ns['_boot_recovery_run'](logs.append, probe=probe, repair=repair,
                                      alert=lambda plog, r, rem: alerts.append((r, rem)),
                                      sleep=clock.sleep, uptime=clock.uptime,
                                      poststart_busy=kw.get('poststart_busy', lambda: False),
                                      update_busy=lambda: False)
    return result, alerts, logs


def test_everything_up_does_nothing_and_sends_nothing_ops1017():
    box = Sys(units={'docker': (True, 'active')}, containers={'nodered': ('unless-stopped', 'running')})
    result, alerts, _ = run_check(box, Clock(30))
    assert result == 'ok' and alerts == [] and box.started == []


def test_waits_for_the_ten_minute_mark_before_judging_ops1017():
    """At 2 min a stopped Authentik is normal (post-start has not run yet): nothing is started."""
    box = Sys(**FIELD_BOX)
    clock = Clock(120)
    started_at = []
    orig = box.run
    box.run = lambda cmd, **kw: (started_at.append(clock.t) if cmd[1] == 'start' else None) or orig(cmd, **kw)
    run_check(box, clock)
    assert started_at and min(started_at) >= 600


def test_waits_while_post_start_is_still_running_ops1017():
    box = Sys(**FIELD_BOX)
    clock = Clock(700)
    busy = lambda: clock.t < 900
    started_at = []
    orig = box.run
    box.run = lambda cmd, **kw: (started_at.append(clock.t) if cmd[1] == 'start' else None) or orig(cmd, **kw)
    run_check(box, clock, poststart_busy=busy)
    assert started_at and min(started_at) >= 900


def test_post_start_that_never_finishes_is_not_waited_on_forever_ops1017():
    box = Sys(**FIELD_BOX)
    clock = Clock(700)
    result, _, _ = run_check(box, clock, poststart_busy=lambda: True)
    assert clock.t < 1260 + 120 + 300 + 15 and result == 'repaired'


def test_field_state_everything_the_boot_script_never_started_comes_back_ops1017():
    """The field case: post-start was cut off, so Authentik, TAK Portal, Node-RED and MediaMTX are
    stopped 10 min after the boot. Every one is started, in order, and the operator is told."""
    box = Sys(**FIELD_BOX)
    result, alerts, logs = run_check(box, Clock(650))
    assert result == 'repaired'
    assert box.started[0] in ('mediamtx', 'mediamtx-webeditor')
    assert set(box.started) == {'authentik-postgresql-1', 'authentik-server-1', 'authentik-ldap-1', 'tak-portal',
                                'nodered', 'mediamtx', 'mediamtx-webeditor'}
    assert box.started.index('authentik-postgresql-1') < box.started.index('authentik-server-1') < box.started.index('authentik-ldap-1')
    (repaired, remaining), = alerts
    assert remaining == [] and len(repaired) == 7
    assert not ns_probe_down(box)


def ns_probe_down(box):
    return load()['_boot_recovery_probe'](run=box.run)


def test_a_module_that_will_not_start_is_reported_after_two_rounds_ops1017():
    box = Sys(units={'docker': (True, 'active'), 'mediamtx': (True, 'inactive')},
              containers={'nodered': ('unless-stopped', 'exited')})
    box.fail = {'nodered'}
    clock = Clock(700)
    result, alerts, logs = run_check(box, clock)
    assert result == 'down'
    (repaired, remaining), = alerts
    assert [i['name'] for i in repaired] == ['mediamtx'] and [i['name'] for i in remaining] == ['nodered']
    assert clock.sleeps[-2:] == [120, 300]
    assert any('FAILED' in l for l in logs)


def test_a_restart_loop_is_reported_not_started_again_ops1017():
    box = Sys(units={}, containers={'cloudtak-api-1': ('always', 'restarting')})
    result, alerts, _ = run_check(box, Clock(700))
    assert result == 'down' and box.started == []
    assert [i['name'] for i in alerts[0][1]] == ['cloudtak-api-1']


# ── the alert ─────────────────────────────────────────────────────────────────────────────────

def alert_ns(recipient='ops@example.test'):
    sent, lines = [], []
    ns = load(load_settings=lambda: {'guarddog_alert_email': recipient},
              _guarddog_server_identifier=lambda s: 'garesponder',
              _guarddog_send_alert_email_via_relay=lambda to, subj, body: sent.append((to, subj, body)),
              _write_priv=lambda path, text, mode='w': lines.append((path, text)))
    return ns, sent, lines


def test_alert_after_a_repair_says_what_was_started_in_plain_words_ops1017():
    ns, sent, lines = alert_ns()
    ns['_boot_recovery_alert'](lambda m: None, [{'name': 'tak-portal'}, {'name': 'authentik-server-1'}], [])
    (to, subj, body), = sent
    assert 'TAK Portal' in subj and 'Authentik (login and LDAP)' in subj and 'garesponder' in subj
    assert 'You do not need to do anything' in body
    assert lines and 'boot-recovery | repaired' in lines[0][1] and lines[0][0] == '/var/log/takguard/restarts.log'


def test_alert_for_a_module_still_down_says_what_to_press_ops1017():
    ns, sent, lines = alert_ns()
    ns['_boot_recovery_alert'](lambda m: None, [], [{'name': 'mediamtx'}])
    (_, subj, body), = sent
    assert subj.startswith('⚠') and 'MediaMTX (video)' in subj
    assert 'Start button' in body


def test_alert_without_a_recipient_still_writes_the_activity_line_ops1017():
    ns, sent, lines = alert_ns(recipient='')
    logs = []
    ns['_boot_recovery_alert'](logs.append, [{'name': 'nodered'}], [])
    assert sent == [] and lines and any('SUPPRESSED' in l for l in logs)


# ── console startup ───────────────────────────────────────────────────────────────────────────

class FakeThread:
    started = []

    def __init__(self, target=None, **kw):
        self.target = target

    def start(self):
        FakeThread.started.append(self.target)


def startup(uptime, settings, boot_id='boot-A'):
    FakeThread.started = []
    ns = load(load_settings=lambda: settings, save_settings=lambda s: settings.update(s),
              threading=types.SimpleNamespace(Thread=FakeThread))
    ns['_boot_uptime_s'] = lambda: uptime    # after load(): the block defines the real one
    # the function reads /proc/sys/kernel/random/boot_id: give it ours
    real_open = open
    ns['open'] = lambda p, *a, **k: __import__('io').StringIO(boot_id + '\n') if p.endswith('boot_id') else real_open(p, *a, **k)
    return ns, ns['_startup_boot_recovery_check']()


def test_a_console_started_right_after_boot_runs_the_check_once_ops1017():
    st = {}
    ns, started = startup(40, st)
    assert started is True and len(FakeThread.started) == 1


def test_a_console_restart_on_a_long_running_box_is_not_a_reboot_ops1017():
    ns, started = startup(86400, {})
    assert started is False and FakeThread.started == []


def test_a_finished_check_is_not_run_twice_in_one_boot_ops1017():
    ns, started = startup(900, {'boot_recovery': {'boot_id': 'boot-A', 'result': 'ok'}})
    assert started is False
    ns, started = startup(900, {'boot_recovery': {'boot_id': 'boot-OLD', 'result': 'ok'}})
    assert started is True


def test_the_startup_chain_calls_the_check_ops1017():
    assert re.search(r'_startup_boot_recovery_check\(\)\s*:\s*\n\s*print\(', APP)
