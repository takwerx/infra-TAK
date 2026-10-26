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
"""Guard Dog's CloudTAK drift clock does not run while the console is busy (ops #230).

test6, 2026-10-25: a TAK Portal marketplace install recreated CloudTAK without infra-TAK's
override (expected, ops #197). The auto-repair answered `waiting` the whole time — TAK Portal's
--no-cache api build (~20 min), then the api settling, then a console plugin job — and
tak-cloudtak-watch.sh counted all of it against its 30-min limit, so it emailed "Guard Dog
could not put them back" at 30 min while the console was only waiting its turn. Now a `busy`
wait is not counted; a non-busy wait, a failure or a dead console alarm as before, and a hard
2 h cap still catches a job that never ends.
"""

import time

import pytest

from test_cloudtak_autorepair_ops197 import (  # noqa: F401
    TAKPORTAL_BUILD, Box, PROFILE, _alerts, _iso, _repair_calls, box, gd)

BUILD = {'state': 'waiting', 'busy': True,
         'detail': "a compose/build run is still going (bash -lc set -euo pipefail CT='/home/takwerx/CloudTAK' SVC='api')"}
SETTLE = {'state': 'waiting', 'busy': True, 'detail': 'cloudtak-api-1 started 21s ago'}
CONSOLE_JOB = {'state': 'waiting', 'busy': True, 'detail': 'console busy: cloudtak_plugin_status running'}
API_DOWN = {'state': 'waiting', 'busy': False, 'detail': 'cloudtak-api-1 is not running (exited)'}


def _advance(gd, secs):
    """Move the episode `secs` into the past, as if that much time went by between checks."""
    p = gd.state / 'cloudtak_media_drift_pending'
    if p.exists():
        p.write_text(str(int(p.read_text()) - secs))
    b = gd.state / 'cloudtak_media_drift_busy'
    if b.exists():
        last, busy = b.read_text().split()
        b.write_text(f'{int(last) - secs} {busy}')


def _run(gd, answers):
    """One check a minute; returns every alert sent."""
    sent = []
    for a in answers:
        _advance(gd, 60)
        sent += _alerts(gd(console=a))
    return sent


# ── Guard Dog: tak-cloudtak-watch.sh ─────────────────────────────────────────

def test_gd_replays_test6_without_the_false_alarm(gd):
    # restarts.log on test6, 2026-10-25 11:55:51Z → 12:25:57Z (alarm), repaired after.
    gd()                                                   # first detection
    sent = _run(gd, [BUILD] * 21 + [SETTLE] + [CONSOLE_JOB] * 8)
    assert sent == []                                      # was: alarm at the 30th minute
    assert 'min busy not counted' in gd.log()
    sent = _run(gd, [CONSOLE_JOB] * 10 + [{'state': 'repairing', 'detail': 'recreate'}])
    assert sent == []
    _advance(gd, 60)
    calls = gd(yml=PROFILE, labels={'cloudtak-api-1': gd.clean, 'cloudtak-media-1': gd.clean})
    assert _alerts(calls) == [] and _repair_calls(calls) == []
    assert 'back before the alert threshold' in gd.log()
    assert not (gd.state / 'cloudtak_media_drift_pending').exists()
    assert not (gd.state / 'cloudtak_media_drift_busy').exists()


def test_gd_a_wait_that_is_not_busy_still_alarms_at_30_min(gd):
    gd()
    sent = _run(gd, [API_DOWN] * 29)
    assert sent == []
    sent = _run(gd, [API_DOWN])
    assert len(sent) == 1 and sent[0].startswith('alert Guard Dog: CloudTAK video config drift on ')
    assert 'not fixed after 30 min (console: waiting — cloudtak-api-1 is not running' in gd.body()


def test_gd_busy_time_comes_off_the_clock_but_the_rest_still_counts(gd):
    gd()
    assert _run(gd, [BUILD] * 20) == []
    assert _run(gd, [API_DOWN] * 29) == []                 # 49 min in, 29 of them counted
    sent = _run(gd, [API_DOWN] * 2)
    assert len(sent) == 1
    assert 'not fixed after 50 min (console: waiting' in gd.body()


def test_gd_a_job_that_never_finishes_alarms_at_the_2h_cap(gd):
    gd()
    assert _run(gd, [CONSOLE_JOB] * 118) == []
    sent = _run(gd, [CONSOLE_JOB] * 2)
    assert len(sent) == 1
    body = gd.body()
    assert 'not fixed after 120 min' in body and 'waiting for other work on CloudTAK to finish' in body
    assert 'console busy: cloudtak_plugin_status running' in body
    assert _alerts(gd(console=CONSOLE_JOB)) == []          # once per episode


def test_gd_a_long_gap_between_checks_is_not_banked_as_busy(gd):
    # The watcher did not run for 40 min (box asleep, timer stopped). Only 5 min of that gap
    # can come off the clock, so the episode alarms instead of hiding behind one busy answer.
    gd()
    _advance(gd, 40 * 60)
    sent = _alerts(gd(console=BUILD))
    assert len(sent) == 1 and 'not fixed after 40 min' in gd.body()


def test_gd_failed_and_unreachable_still_alarm_straight_away_while_busy_before(gd):
    gd()
    assert _run(gd, [BUILD] * 5) == []
    _advance(gd, 60)
    assert len(_alerts(gd(console={'state': 'failed', 'detail': 'x'}))) == 1


def test_gd_old_console_without_the_busy_field_keeps_todays_30_min_clock(gd):
    # A console that predates ops #230 sends no `busy`: nothing comes off the clock.
    old = {'state': 'waiting', 'detail': BUILD['detail']}
    gd()
    assert _run(gd, [old] * 29) == []
    assert len(_run(gd, [old])) == 1


def test_gd_a_busy_file_from_an_earlier_episode_is_not_reused(gd):
    gd()
    # Left over from a previous episode, older than this one's first detection.
    (gd.state / 'cloudtak_media_drift_busy').write_text(f'{int(time.time()) - 99999} 99999\n')
    _advance(gd, 31 * 60)
    sent = _alerts(gd(console=API_DOWN))
    assert len(sent) == 1


def test_gd_a_garbled_busy_file_is_ignored(gd):
    gd()
    (gd.state / 'cloudtak_media_drift_busy').write_text('garbage\n')
    calls = gd(console=BUILD)
    assert _alerts(calls) == []
    last, busy = (gd.state / 'cloudtak_media_drift_busy').read_text().split()
    assert int(busy) <= 300


# ── console: which waits are busy ────────────────────────────────────────────

class ApiDownBox(Box):
    def run(self, argv, **kw):
        r = super().run(argv, **kw)
        if list(argv)[:3] == ['docker', 'inspect', 'cloudtak-api-1'] and '.State.Status' in argv[-1]:
            r.stdout = f'exited {_iso(self.api_started)}\n'
        return r


def test_console_marks_a_build_in_progress_as_busy(box):
    box.procs.append(TAKPORTAL_BUILD)
    r = box.request()
    assert r['state'] == 'waiting' and r['busy'] is True


def test_console_marks_an_api_that_just_started_as_busy(box):
    box.api_started = time.time() - 20
    r = box.request()
    assert r['state'] == 'waiting' and r['busy'] is True


def test_console_marks_its_own_job_as_busy(box):
    box.busy = 'cloudtak_plugin_status running'
    r = box.request()
    assert r == {'state': 'waiting', 'busy': True, 'detail': 'console busy: cloudtak_plugin_status running'}


def test_console_does_not_mark_a_stopped_api_as_busy(tmp_path):
    r = ApiDownBox(tmp_path).request()
    assert r['state'] == 'waiting' and r['busy'] is False and 'not running (exited)' in r['detail']


@pytest.mark.parametrize('field', ['repairing', 'ok', 'failed'])
def test_console_only_waiting_answers_carry_busy(box, field):
    if field == 'ok':
        box.labels = {n: f'{box.ct}/docker-compose.yml,{box.ct}/docker-compose.override.yml'
                      for n in box.labels}
        box.hls = True
    elif field == 'failed':
        (box.ct / 'COMPROMISE-DETECTED.txt').write_text('x')
    r = box.request()
    assert r['state'] == field and 'busy' not in r
