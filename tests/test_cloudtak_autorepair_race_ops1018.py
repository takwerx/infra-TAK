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
"""A CloudTAK repair that a TAK Portal job undoes is repeated, not left failed (ops #1018).

Seen on a fresh-install box (ops #1013): the Marketplace reinstall check runs an Uninstall job and an
Install job back to back. The console repaired CloudTAK after the Uninstall job. The Install job then
recreated the stack without infra-TAK's override while the next repair was running, that repair ended
`failed: still drifted after the repair`, and the failure hold (15 min) turned away every later ask.
CloudTAK ran 20+ minutes on TAK Portal's own compose file: old database image, old media image, no
upload rule, no HLS profile.

Now a repair that still shows drift looks at the process list. If a compose/build run or TAK Portal's
helper was changing the stack, it waits for that job to end and repairs again (3 passes at most). A drift
that no job explains stays a failed repair, as before.

Same fake box as the ops #197 tests (the shipped functions cut out of app.py, docker faked).
"""

import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_cloudtak_autorepair_ops197 import APP, Box  # noqa: E402

HELPER = ('/bin/bash /usr/local/libexec/tak-portal/marketplace-helper '
          'rebuild /home/takwerx/CloudTAK api')


class RaceBox(Box):
    """A box where TAK Portal's Install job starts during the repair: right after the repair's own
    recreate and HLS heal it recreates the stack stock again (what `-f docker-compose.yml -f
    docker-compose.marketplace.yml up --force-recreate api` does) and its helper is on the process
    list for `looks` looks."""

    def __init__(self, home, jobs=1, looks=3):
        super().__init__(home)
        self.jobs_left = jobs        # how many repair passes TAK Portal's job undoes
        self.looks = looks           # process-list looks the job stays visible for
        self.job_running = 0
        self.job_runs = 0

    def run(self, argv, **kw):
        if list(argv)[:2] == ['ps', '-eo'] and self.job_running > 0:
            self.job_running -= 1
            self.procs.append(HELPER)
            try:
                return super().run(argv, **kw)
            finally:
                self.procs.remove(HELPER)
        return super().run(argv, **kw)

    def heal(self, plog=None, remote_cfg=None, wait=False):
        ok = super().heal(plog, remote_cfg, wait)
        if self.jobs_left > 0:
            self.jobs_left -= 1
            self.job_runs += 1
            self.takportal_recreate()          # the Install job's recreate lands after our repair
            self.job_running = self.looks
        return ok


@pytest.fixture
def race(tmp_path):
    return RaceBox(tmp_path)


def _run_repair(box):
    assert box.request()['state'] == 'repairing'
    box.finish()


def test_a_job_that_undoes_the_repair_is_waited_for_and_repaired_again(race):
    # Proof test (ops #1018): on the base commit the repair ends `failed: still drifted` after one
    # recreate; with the fix it waits for the job to end and repairs again.
    _run_repair(race)
    assert len(race.ups()) == 2, 'the repair is repeated once the job is over'
    assert race.record()['last']['result'] == 'repaired'
    assert race.media_image == 'ghcr.io/dfpc-coe/media-infra:v9.12.1' and race.api_ca is True and race.hls is True
    assert race.upload is True
    assert any('another job changed CloudTAK during the repair' in l for l in race.logs)
    assert race.request()['state'] == 'ok'
    assert race.mails == []                                  # a repaired stack never emails (ops #230)
    assert not race.pending()


def test_it_waits_while_the_job_is_still_running_not_before(race):
    race.looks = 6
    _run_repair(race)
    assert len(race.ups()) == 2
    # 6 looks with the helper on the list: nothing recreated the stack in that time
    assert race.job_running == 0
    assert any('waiting for it to end' in l for l in race.logs)


def test_the_note_names_what_was_found_first(race):
    _run_repair(race)
    assert len(race.guard_log) == 1
    line = race.guard_log[0][1]
    assert "created without infra-TAK's compose override: cloudtak-api-1, cloudtak-media-1, cloudtak-postgis-1" in line
    assert 'repaired automatically' in line


def test_a_drift_no_job_explains_is_still_a_failed_repair(race):
    race.jobs_left = 0
    race.heal_ok = True
    original = race.heal

    def heal_without_effect(plog=None, remote_cfg=None, wait=False):
        original(plog, remote_cfg, wait)
        race.hls = False                    # the profile did not stick, and no job touched the stack
        return True
    race.heal = heal_without_effect
    _run_repair(race)
    assert len(race.ups()) == 1, 'no job was seen, so no second pass'
    last = race.record()['last']
    assert last['result'] == 'failed' and 'still drifted after the repair' in last['detail']
    # the 15 minute failure hold still applies to the next ask
    assert race.request()['state'] == 'failed'


def test_a_job_that_keeps_undoing_it_stops_after_three_passes(race):
    race.jobs_left = 99
    _run_repair(race)
    assert len(race.ups()) == 3
    last = race.record()['last']
    assert last['result'] == 'failed' and 'still drifted after the repair' in last['detail']


def test_a_stack_that_is_still_busy_after_the_wait_is_a_failure(race):
    race.looks = 10 ** 6
    ns = race.ns()
    race._ns = ns
    ns['CLOUDTAK_AUTOREPAIR_COMPOSE_WAIT_S'] = 0     # give the job no time at all
    _run_repair(race)
    assert len(race.ups()) == 1
    assert race.record()['last']['result'] == 'failed'
    assert any('still busy after' in l for l in race.logs)


def test_an_unreadable_process_list_is_never_read_as_idle(race):
    ns = race.ns()

    def boom(argv, **kw):
        raise OSError('ps failed')
    ns['subprocess'].run = boom
    ns['CLOUDTAK_AUTOREPAIR_COMPOSE_WAIT_S'] = 0
    assert ns['_cloudtak_autorepair_await_quiet'](lambda m: race.logs.append(m)) is False


def test_a_quiet_stack_with_no_job_answers_false_at_once(race):
    ns = race.ns()
    assert ns['_cloudtak_autorepair_await_quiet'](lambda m: race.logs.append(m)) is False


def test_the_repair_loop_is_bounded_and_uses_the_one_repair_path():
    src = APP[APP.index('def _cloudtak_autorepair_run'):APP.index('def _cloudtak_autorepair_notify')]
    assert 'for _pass in range(CLOUDTAK_AUTOREPAIR_PASSES)' in src
    assert '_cloudtak_autorepair_await_quiet(_log)' in src
    assert '_cloudtak_recreate_and_heal(ct_dir, _log, pull=True' in src      # not a second copy of the recreate
    assert 'CLOUDTAK_AUTOREPAIR_PASSES = 3' in APP
