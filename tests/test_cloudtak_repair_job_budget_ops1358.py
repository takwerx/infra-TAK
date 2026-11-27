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
"""A few TAK Portal Marketplace jobs in one hour no longer stop the CloudTAK repair (ops #1358).

Found in a fresh-install test (ops #1308): three Marketplace jobs ended at 00:06, 00:17 and 00:48, each
followed by a repair. The fourth, at 00:58, was refused ("3 automatic repairs in the last hour") and
CloudTAK stayed on TAK Portal's compose file. The limit is there to stop a repair loop. A Marketplace job
is not a loop: each one recreates CloudTAK again. Repairs after a job now have their own budget, the
limit is stated in plain words on the Activity log, and the console repairs again by itself when the
hour window frees.

Same fake box as the ops #197 / #850 tests; the shipped functions are cut out of app.py.
"""

import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_cloudtak_jobend_repair_ops850 import box, HELPER  # noqa: E402,F401
from test_cloudtak_autorepair_ops197 import TAKPORTAL_BUILD, PINNED_MEDIA  # noqa: E402


def end_job(box, st, t, proc=HELPER):
    """One TAK Portal job: it runs, recreates CloudTAK without the override, ends, the stack goes quiet.
    Returns what the console answered to the repair it asked for (None if it asked nothing)."""
    box.takportal_recreate()
    box.api_started = time.time() - 600
    box.procs.append(proc)
    box.look(st, t)
    box.procs.remove(proc)
    box.look(st, t + 1)
    r = box.look(st, t + 1 + box.quiet_s)
    box.finish()
    return r


def test_five_jobs_in_an_hour_are_all_repaired(box):
    st, t = {}, 1000.0
    for n in range(5):
        r = end_job(box, st, t)
        assert r['state'] == 'repairing', (n, r)
        assert all('docker-compose.override.yml' in f for f in box.labels.values()), n
        assert box.media_image == PINNED_MEDIA
        t += 600
    assert len(box.ups()) == 5
    rec = box.record()
    assert len(rec['job_attempts']) == 5 and 'attempts' not in rec     # the loop budget is untouched


def test_job_budget_used_up_says_so_and_repairs_again_when_the_hour_frees(box):
    now = time.time()
    oldest = now - 3500                                    # frees in about 100 s
    (box.home / '.config' / 'cloudtak-autorepair.json').write_text(json.dumps(
        {'job_attempts': [oldest] + [now - 600] * 9}))
    st, t = {}, 1000.0
    r = end_job(box, st, t)
    assert r['state'] == 'rate_limited' and r['retry_at'] == oldest + 3600
    assert 'paused repairs' in r['detail'] and 'tries again by itself' in r['detail']
    assert box.ups() == [] and box.threads == []
    # one plain line on the Activity log, and nothing emailed
    assert len(box.guard_log) == 1
    path, line, mode = box.guard_log[0]
    assert path == '/var/log/takguard/restarts.log' and mode == 'a'
    assert 'CloudTAK repair paused' in line and 'restart the infra-TAK console' in line
    assert box.mails == []
    # before the window frees: nothing. After it frees, with no new job: the repair runs by itself.
    assert box.look(st, t + 50) is None
    assert box.ups() == []
    # (the fake box cannot move the real clock: age the saved attempts by the same two minutes)
    rec = box.record()
    rec['job_attempts'] = [t - 120 for t in rec['job_attempts']]
    (box.home / '.config' / 'cloudtak-autorepair.json').write_text(json.dumps(rec))
    r2 = box.look(st, oldest + 3600 + 10)
    assert r2['state'] == 'repairing'
    box.finish()
    assert len(box.ups()) == 1 and box.media_image == PINNED_MEDIA
    assert all('docker-compose.override.yml' in f for f in box.labels.values())
    assert 'retry_at' not in st or st['retry_at'] is None
    assert box.look(st, oldest + 3600 + 20) is None        # and only once


def test_repairs_with_no_job_behind_them_keep_the_old_limit(box):
    # Guard Dog's own request (no TAK Portal job seen): three an hour, then the alarm. Job repairs do not use it up.
    (box.home / '.config' / 'cloudtak-autorepair.json').write_text(json.dumps(
        {'job_attempts': [time.time() - 60] * 9}))
    for _ in range(3):
        assert box.request()['state'] == 'repairing'
        box.finish()
        box.takportal_recreate()
        box.api_started = time.time() - 600
    r = box.request()
    assert r['state'] == 'rate_limited' and '3 automatic repairs in the last hour' in r['detail']
    assert 'retry_at' not in r
    assert len(box.record()['job_attempts']) == 9           # never touched by the no-job path


def test_a_job_whose_helper_was_not_seen_counts_against_the_old_limit(box):
    # Only the compose child was seen (a newer TAK Portal that renamed its helper): today's behaviour, not worse.
    st, t = {}, 1000.0
    states = [(end_job(box, st, t + 600 * n, proc=TAKPORTAL_BUILD) or {}).get('state') for n in range(4)]
    assert states == ['repairing'] * 3 + ['rate_limited']
    assert 'job_attempts' not in box.record()


def test_an_old_format_record_still_loads_and_is_kept(box):
    # What every box on 10.4.8 and older has: attempts and last, no job_attempts.
    old = {'attempts': [time.time() - 120] * 3,
           'last': {'result': 'repaired', 'at': time.time() - 100, 'detail': '', 'found': 'x'}}
    (box.home / '.config' / 'cloudtak-autorepair.json').write_text(json.dumps(old))
    st = {}
    r = end_job(box, st, 1000.0)
    assert r['state'] == 'repairing'
    rec = box.record()
    assert rec['attempts'] == old['attempts'] and len(rec['job_attempts']) == 1
    assert rec['last']['result'] == 'repaired'


def test_a_bad_job_attempts_value_is_ignored(box):
    (box.home / '.config' / 'cloudtak-autorepair.json').write_text(json.dumps(
        {'job_attempts': ['x', None, {'a': 1}]}))
    assert end_job(box, {}, 1000.0)['state'] == 'repairing'
