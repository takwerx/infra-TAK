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
"""A CloudTAK repair that outlasts the console's 240 seconds is not a failure (ops #889).

test6 (a busy box, load 10 to 20) was repaired right after a TAK Portal Marketplace job. The
`docker compose up -d --force-recreate` ran longer than the console's 240 s limit. The console
gave up and recorded 'failed', while the broker kept running the compose and finished minutes
later. For about 10 minutes every ask got "failed: automatic repair failed" and Guard Dog's alarm
path had its answer; CloudTAK was down while the containers came up.

Now the repair waits for the running compose (up to CLOUDTAK_AUTOREPAIR_COMPOSE_WAIT_S), then
judges by a fresh drift check, and an ask meanwhile hears "still repairing".

The shipped functions are cut out of app.py and run on the fake box of the ops #197 tests.
"""

import pathlib
import subprocess
import sys
import time
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_cloudtak_autorepair_ops197 import Box, PINNED_MEDIA  # noqa: E402

COMPOSE_UP = '/usr/bin/docker compose up -d --force-recreate'


class SlowBox(Box):
    """`compose up --force-recreate` takes longer than the console waits: the console's call times
    out, the broker's compose keeps running (it shows in the process list for `polls` looks) and
    then finishes having done its work."""

    def __init__(self, home, polls=3):
        super().__init__(home)
        self.polls = polls          # process-list looks that still show the compose; None: never ends
        self.compose_running = False
        self.slow_up = True

    def run(self, argv, **kw):
        argv = list(argv)
        if argv[:2] == ['ps', '-eo'] and self.compose_running:
            self.calls.append((argv, kw.get('cwd')))
            out = '\n'.join(self.procs + [COMPOSE_UP]) + '\n'
            if self.polls is not None:
                self.polls -= 1
                if self.polls < 0:
                    self.compose_running = False
            return types.SimpleNamespace(stdout=out, stderr='', returncode=0)
        if argv[:5] == ['docker', 'compose', 'up', '-d', '--force-recreate'] and self.slow_up:
            super().run(argv, **kw)         # the broker does the work...
            self.compose_running = True     # ...but is still at it when the console stops waiting
            raise subprocess.TimeoutExpired(argv, 240)
        return super().run(argv, **kw)

    def ns(self):
        ns = super().ns()
        # no real sleeping while the fake compose "runs"
        ns['time'] = types.SimpleNamespace(time=time.time, sleep=lambda s: None,
                                           strptime=time.strptime)
        return ns


@pytest.fixture
def slow(tmp_path):
    return SlowBox(tmp_path)


def _converge_after_recreate(box):
    """The recreate's own work is done; the heals put the rest back (the ops #197 fake)."""
    box.hls = True


def test_a_recreate_that_outlasts_the_console_limit_is_waited_for_and_succeeds(slow):
    assert slow.request()['state'] == 'repairing'
    slow.finish()
    rec = slow.record()['last']
    assert rec['result'] == 'repaired', rec                  # not 'failed: timed out after 240 seconds'
    assert slow.compose_running is False                     # it really waited for the compose to end
    assert any('still running after 240s' in l for l in slow.logs)
    assert len(slow.ups()) == 1                              # no second compose started on top of it
    assert not slow.pending()
    assert slow.request()['state'] == 'ok'                   # CloudTAK is repaired: nothing more to do
    assert slow.mails == []                                  # and no alarm


def test_an_ask_during_the_wait_hears_still_repairing_with_the_time(slow):
    assert slow.request()['state'] == 'repairing'            # the repair thread is started, not run yet
    slow._ns['cloudtak_autorepair_status']['started'] = time.time() - 7 * 60
    r = slow.request()
    assert r['state'] == 'repairing'
    assert r['detail'].startswith('still repairing (running 7 min)')
    assert 'failed' not in r['detail']
    assert len(slow.ups()) == 0                              # the ask changed nothing


def test_a_compose_that_never_ends_is_a_real_failure_after_the_wait(slow):
    slow.polls = None                                        # the compose is still going when the wait ends
    slow.request()
    slow._ns['CLOUDTAK_AUTOREPAIR_COMPOSE_WAIT_S'] = 0.05
    slow.finish()
    rec = slow.record()['last']
    assert rec['result'] == 'failed' and 'force-recreate failed' in rec['detail']
    assert slow.pending()                                    # the next console start redoes it
    assert len(slow.ups()) == 1


def test_a_recreate_that_finishes_wrong_is_judged_by_the_fresh_check(slow):
    slow.heal_ok = False                                     # the compose ended, the HLS heal does not confirm
    slow.request()
    slow.finish()
    rec = slow.record()['last']
    assert rec['result'] == 'failed' and 'HLS' in rec['detail']


def test_the_console_start_path_keeps_the_old_timeout_behaviour(slow):
    """It runs before the web server is up: it must not sit for 15 minutes, so it still raises."""
    (slow.ct / '.env').write_text((slow.ct / '.env').read_text() + 'COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml\n')
    ns = slow.ns()
    with pytest.raises(subprocess.TimeoutExpired):
        ns['_cloudtak_recreate_and_heal'](str(slow.ct), lambda m: None)


def test_the_repair_passes_the_wait_and_the_startup_path_does_not():
    app = (pathlib.Path(__file__).resolve().parent.parent / 'app.py').read_text(encoding='utf-8')
    assert 'pull=True, wait_s=CLOUDTAK_AUTOREPAIR_COMPOSE_WAIT_S)' in app
    assert ('_ct_dir, lambda m: print(f"Startup migration: {m}", flush=True),\n'
            '                pull=_override_changed or _pending is not None or bool(_no_override))') in app
