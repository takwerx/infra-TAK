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
"""CloudTAK is repaired the moment a TAK Portal Marketplace job ends (ops #850).

TAK Portal recreates the CloudTAK containers without infra-TAK's compose override. Guard Dog's
cloudtak-autorepair fixed that, but only on its timer: a first look, a second look a minute later,
then the console waited for the api to be up 90 seconds. A user saw a wrong CloudTAK for about 5
minutes. Now the console watches for the stack to go from busy (a compose/build run, or TAK
Portal's marketplace-helper) to quiet and asks for the SAME repair at once.

The shipped functions are cut out of app.py (it cannot be imported in a test) and run against the
fake box of the ops #197 tests: a temp ~/CloudTAK with docker faked.
"""

import os
import pathlib
import sys
import threading
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_cloudtak_autorepair_ops197 import (  # noqa: E402
    APP, Box, PINNED_MEDIA, TAKPORTAL_BUILD, _assign, _converged, _fn)

HELPER = ('/bin/bash /usr/local/libexec/tak-portal/marketplace-helper '
          'rebuild /home/takwerx/CloudTAK api')
HELPER_SUDO = ('sudo -n /usr/local/libexec/tak-portal/marketplace-helper '
               'install-plugin /home/takwerx/CloudTAK mapsync /x /tmp/y')


@pytest.fixture
def box(tmp_path, monkeypatch):
    b = Box(tmp_path)
    monkeypatch.setenv('HOME', str(tmp_path))     # the shipped code reads ~/CloudTAK
    ns = b.ns()
    src = '\n\n'.join(
        [_assign(n) for n in ('CLOUDTAK_JOBEND_POLL_S', 'CLOUDTAK_JOBEND_QUIET_S',
                              'CLOUDTAK_JOBEND_RETRY_S', 'CLOUDTAK_JOBEND_GIVEUP_S')]
        + [_fn(n) for n in ('_cloudtak_jobend_step', '_cloudtak_jobend_tick')])
    exec(compile(src, 'app.py', 'exec'), ns)
    b._ns = ns
    b.look = lambda st, now: ns['_cloudtak_jobend_tick'](st, now)
    b.quiet_s = ns['CLOUDTAK_JOBEND_QUIET_S']
    return b


# ── the matcher ──────────────────────────────────────────────────────────────

def test_the_portal_helper_counts_as_a_stack_change(box):
    rx = box._ns['_CLOUDTAK_PORTAL_JOB_RE']
    for hit in (HELPER, HELPER_SUDO,
                'sudo /usr/local/libexec/tak-portal/marketplace-helper rm-plugin /h/CloudTAK /x',
                '/usr/local/libexec/tak-portal/marketplace-helper reclaim /h/CloudTAK u g'):
        assert rx.search(hit), hit
    for miss in ('/usr/local/libexec/tak-portal/marketplace-helper version',
                 '/usr/local/libexec/tak-portal/marketplace-helper write-caddy-route m p',
                 'tail -f /var/log/tak-portal/marketplace-helper.log', 'sleep 30'):
        assert not rx.search(miss), miss


def test_an_unreadable_process_list_is_not_read_as_idle(box):
    def boom(argv, **kw):
        raise OSError('ps failed')
    box._ns['subprocess'].run = boom
    assert box._ns['_cloudtak_stack_busy_procs']() is None
    st = {'active': True}
    assert box._ns['_cloudtak_jobend_step'](st, None, 1000.0) is False
    assert st['active'] is True and st.get('quiet_since') is None


# ── the step machine ─────────────────────────────────────────────────────────

def test_fires_once_when_the_stack_has_been_quiet_long_enough(box):
    step, q = box._ns['_cloudtak_jobend_step'], box.quiet_s
    st = {}
    assert step(st, False, 0) is False                       # nothing was running: nothing ended
    assert step(st, True, 10) is False                       # a job starts
    assert step(st, True, 40) is False                       # ...and runs
    assert step(st, False, 50) is False                      # it ends: start the quiet clock
    assert step(st, False, 50 + q - 1) is False
    assert step(st, False, 50 + q) is True                   # quiet long enough: repair now
    st['pending_since'] = None                               # the answer was not "waiting" (the tick does this)
    assert step(st, False, 50 + q + 5) is False              # and only once
    assert step(st, False, 50 + q + 600) is False


def test_a_new_run_in_the_gap_restarts_the_quiet_clock(box):
    # TAK Portal's install is build -> up --force-recreate -> wait for the api -> prune.
    step, q = box._ns['_cloudtak_jobend_step'], box.quiet_s
    st = {}
    step(st, True, 0)
    step(st, False, 5)
    assert step(st, False, 5 + q - 1) is False
    step(st, True, 5 + q)                                    # the next command starts in time
    assert step(st, False, 5 + q + 1) is False
    assert step(st, False, 5 + q + 1 + q) is True


def test_a_waiting_answer_is_asked_again_and_then_given_up(box):
    step, q = box._ns['_cloudtak_jobend_step'], box.quiet_s
    retry = box._ns['CLOUDTAK_JOBEND_RETRY_S']
    giveup = box._ns['CLOUDTAK_JOBEND_GIVEUP_S']
    st = {}
    step(st, True, 0)
    step(st, False, 1)
    assert step(st, False, 1 + q) is True
    t = 1 + q
    assert step(st, False, t + retry - 1) is False
    assert step(st, False, t + retry) is True                # still pending: ask again
    assert step(st, False, t + giveup) is False              # too long: Guard Dog's timer is it now
    assert st['pending_since'] is None
    assert step(st, False, t + giveup + 3 * retry) is False


def test_a_new_job_cancels_a_pending_retry(box):
    step, q = box._ns['_cloudtak_jobend_step'], box.quiet_s
    st = {}
    step(st, True, 0)
    step(st, False, 1)
    assert step(st, False, 1 + q) is True
    step(st, True, 1 + q + 2)                                # another install begins
    assert st['pending_since'] is None
    assert step(st, False, 1 + q + 3 + 1000) is False        # idle again but nothing active before


# ── the whole path on a fake box ─────────────────────────────────────────────

def test_repair_runs_within_seconds_of_the_job_ending_not_on_the_timer(box):
    # The customer case: a TAK Portal install recreated CloudTAK without the override. Guard Dog
    # would first need two looks and then an api that has been up 90 s; the hook does not.
    box.api_started = time.time() - 20            # the api came back 20 s ago
    box.procs.append(HELPER)                      # the Portal job is still running
    st, t0 = {}, 1000.0
    assert box.look(st, t0) is None
    box.procs.remove(HELPER)                      # job over
    assert box.look(st, t0 + 3) is None           # the quiet clock starts
    assert box.look(st, t0 + 3 + box.quiet_s - 1) is None
    r = box.look(st, t0 + 3 + box.quiet_s)
    assert r['state'] == 'repairing'
    box.finish()
    assert box.ups() == [['docker', 'compose', 'up', '-d', '--force-recreate']]
    assert box.media_image == PINNED_MEDIA and box.api_ca is True and box.hls is True
    assert all('docker-compose.override.yml' in f for f in box.labels.values())
    assert box.record()['last']['result'] == 'repaired'
    # the same state asked the old way (Guard Dog's timer) still has to wait for the api
    box.takportal_recreate()
    box.api_started = time.time() - 20
    assert box.request()['state'] == 'waiting'


def test_a_build_and_recreate_in_the_gap_is_not_repaired_early(box):
    box.procs.append(HELPER)
    st = {}
    box.look(st, 0)
    box.procs[-1] = TAKPORTAL_BUILD                           # helper's compose child only
    assert box.look(st, 20) is None
    box.procs.pop()
    box.look(st, 21)
    assert box.look(st, 21 + box.quiet_s - 1) is None
    assert box.threads == [] and box.ups() == []


def test_nothing_to_repair_is_a_quiet_no_op(box):
    _converged(box)
    box.procs.append(HELPER)
    st = {}
    box.look(st, 0)
    box.procs.remove(HELPER)
    box.look(st, 1)
    r = box.look(st, 1 + box.quiet_s)
    assert r['state'] == 'ok'
    assert box.threads == [] and box.ups() == [] and box.record() == {}
    assert box.mails == [] and box.guard_log == []


def test_busy_console_is_retried_until_it_is_free(box):
    box.busy = 'cloudtak_update_status running'
    box.procs.append(HELPER)
    st = {}
    box.look(st, 0)
    box.procs.remove(HELPER)
    box.look(st, 1)
    assert box.look(st, 1 + box.quiet_s)['state'] == 'waiting'
    assert box.look(st, 1 + box.quiet_s + 5) is None          # not before the retry time
    box.busy = None
    r = box.look(st, 1 + box.quiet_s + box._ns['CLOUDTAK_JOBEND_RETRY_S'])
    assert r['state'] == 'repairing'
    assert st['pending_since'] is None


def test_does_nothing_where_cloudtak_is_not_installed(box):
    (box.ct / '.env').unlink()
    box.procs.append(HELPER)
    st = {}
    assert box.look(st, 0) is None and st == {}
    box.procs.remove(HELPER)
    assert box.look(st, 100) is None and box.threads == []


def test_the_rate_limit_and_failure_hold_still_apply(box):
    # The hook is the same repair, so a failing repair is not retried in a loop.
    box.up_rc = 1
    box.procs.append(HELPER)
    st = {}
    box.look(st, 0)
    box.procs.remove(HELPER)
    box.look(st, 1)
    assert box.look(st, 1 + box.quiet_s)['state'] == 'repairing'
    box.finish()
    assert box.record()['last']['result'] == 'failed'
    box.procs.append(HELPER)
    box.look(st, 100)
    box.procs.remove(HELPER)
    box.look(st, 101)
    r = box.look(st, 101 + box.quiet_s)
    assert r['state'] == 'failed' and len(box.ups()) == 1


# ── two repairs at once ──────────────────────────────────────────────────────

def test_the_hook_and_guard_dog_asking_together_start_one_repair(box):
    box.api_started = time.time() - 600
    request = box._ns['_cloudtak_autorepair_request']
    go, answers = threading.Barrier(8), []

    def ask(i):
        go.wait()
        answers.append(request(settle_s=None if i % 2 else box.quiet_s)['state'])

    ts = [threading.Thread(target=ask, args=(i,)) for i in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(set(answers)) == ['repairing']
    assert len(box.threads) == 1                              # one repair thread, not eight
    box.finish()
    assert len(box.ups()) == 1
    assert request()['state'] == 'ok'


def test_a_second_ask_while_the_repair_runs_does_not_start_another(box):
    box.api_started = time.time() - 600
    assert box.request()['state'] == 'repairing'
    st = {'pending_since': 990, 'last_try': 0}
    assert box.look(st, 1000)['state'] == 'repairing'
    assert len(box.threads) == 1
    box.finish()
    assert len(box.ups()) == 1


# ── wiring in the shipped file ───────────────────────────────────────────────

def test_the_console_starts_the_watcher_thread():
    assert "threading.Thread(target=_cloudtak_jobend_loop, daemon=True, name='cloudtak-jobend-repair').start()" in APP


def test_the_hook_asks_for_the_existing_repair_and_adds_no_second_copy():
    body = _fn('_cloudtak_jobend_tick')
    assert '_cloudtak_autorepair_request(' in body
    for forbidden in ('_cloudtak_recreate_and_heal', '_cloudtak_write_override_file',
                      'docker compose', 'subprocess'):
        assert forbidden not in body, forbidden
