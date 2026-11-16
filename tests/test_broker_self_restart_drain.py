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
"""The broker's self-restart (root move, broker_update) waits for nothing in flight.

v10.4.0 T&E, aws-arm 2026-11-16: the first root move restarted the broker 2 s after it came
up, while the console's startup ran a CloudTAK `docker compose up -d --force-recreate`
through it. A restart signals the whole unit cgroup:

    takwerx-broker.service: Killing process 824020 (docker) with signal SIGKILL.

and cloudtak-api-1 stayed removed until the next console start.
"""

import importlib.util
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_sr',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Rec:
    """Records the order of drain / unlink / sleep / restart."""

    def __init__(self, drain_results=(True, True)):
        self.events = []
        self.drain_results = list(drain_results)

    def drain(self, max_secs):
        self.events.append(('drain', max_secs))
        return self.drain_results.pop(0)

    def unlink(self):
        self.events.append(('unlink',))

    def sleep(self, s):
        self.events.append(('sleep', s))

    def run(self, argv, **kw):
        self.events.append(('restart', tuple(argv)))

    def log(self, verdict, summary):
        self.events.append(('log', verdict, summary))


def test_restart_waits_for_in_flight_then_unlinks_then_restarts():
    b = _broker()
    r = _Rec()
    b._self_restart_when_idle(r.run, '/bin/systemctl', drain=r.drain, unlink=r.unlink,
                              sleep=r.sleep, grace=1, log=r.log)
    kinds = [e[0] for e in r.events if e[0] != 'log']
    assert kinds == ['drain', 'unlink', 'sleep', 'drain', 'restart']
    assert r.events[0] == ('drain', b.SELF_RESTART_DRAIN_MAX_SECS)
    assert ('drain', b.SELF_RESTART_LATE_DRAIN_SECS) in r.events
    assert r.events[-1] == ('restart', ('/bin/systemctl', '--no-block', 'restart', 'takwerx-broker'))


def test_drain_bound_outlasts_a_compose_recreate_and_late_drain_fits_console_wait():
    b = _broker()
    # app.py runs `docker compose up -d --force-recreate` for CloudTAK with timeout=240
    assert b.SELF_RESTART_DRAIN_MAX_SECS > 240
    # the console waits 30 s for a missing broker socket (app.py BROKER_RESTART_WAIT_SECS)
    assert b.SELF_RESTART_LATE_DRAIN_SECS + b.RECYCLE_UNLINK_GRACE_SECS < 30


def test_restart_still_happens_when_drain_times_out_and_says_so():
    b = _broker()
    r = _Rec(drain_results=(False, False))
    b._self_restart_when_idle(r.run, '/bin/systemctl', drain=r.drain, unlink=r.unlink,
                              sleep=r.sleep, grace=1, log=r.log)
    assert r.events[-1][0] == 'restart'
    errs = [e for e in r.events if e[0] == 'log' and e[1] == 'ERROR']
    assert len(errs) == 2


def test_real_drain_waits_for_a_running_request():
    b = _broker()
    b._inflight_add(1)
    t = {'now': 0.0}

    def clock():
        return t['now']

    def sleep(s):
        t['now'] += s
        if t['now'] >= 5:
            b._inflight_add(-1)       # the compose up finishes after 5 s
    assert b._drain(max_secs=900, clock=clock, sleep=sleep) is True
    assert t['now'] == 5


def test_restart_self_later_goes_through_the_idle_wait():
    b = _broker()
    seen = {}

    def fake_wait(run, systemctl, **kw):
        seen['called'] = (run, systemctl)
    b._self_restart_when_idle = fake_wait
    t = b._restart_self_later(delay=0.01, run=lambda *a, **k: None)
    t.join(2)
    assert 'called' in seen
    assert seen['called'][1].endswith('systemctl')
