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
"""ops #1186: ATLAS administrator sign-in is back within a minute after Authentik takes
the signing key off, not within five.

✅ Seen on a box (Rocky 9, Authentik 2026.8.5, ops #1151): a restart of Authentik's worker
takes the key off 15 seconds later with no audit event, and ATLAS on `jwt` refused every
administrator until the console's five-minute check (276 s, 291 s, 4 min 35 s).

Three things are tested:

1. the key check has its own loop, and the loop waits at most 60 seconds between checks;
2. the five-minute revocation loop no longer carries the check (one check, not two);
3. two checks never run at the same time (the loop, the console's own calls and a slow
   repair can meet; two runs would restart `api` twice and write `.env` together).

The loop's sleep is replaced on the module's own name for `time`, never on the shared
`time` module (a patch of `time.sleep` there records other threads' sleeps).
"""

import pathlib
import sys
import threading
import time as real_time
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ATLAS_SRC = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')


@pytest.fixture
def atlas():
    import modules.atlas
    return modules.atlas


class _StopLoop(BaseException):
    """Ends the endless loop in a test; not an Exception, so the loop cannot swallow it."""


def _run_the_loop(atlas, monkeypatch, ticks):
    """Start the signing-key loop, run its body for `ticks` checks. Returns (sleeps, checks)."""
    sleeps, checks, bodies = [], [], []

    class FakeThread:
        def __init__(self, target=None, daemon=None, name=None):
            bodies.append((target, name))

        def start(self):
            pass

    def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(checks) >= ticks:
            raise _StopLoop()

    monkeypatch.setattr(atlas, '_signing_key_loop_started', False)
    monkeypatch.setattr(atlas, 'threading', types.SimpleNamespace(Thread=FakeThread))
    monkeypatch.setattr(atlas, 'time', types.SimpleNamespace(sleep=fake_sleep))
    monkeypatch.setattr(atlas, 'converge_signed_identity',
                        lambda ctx, log: checks.append(True) or {})

    atlas._start_signing_key_loop({})
    assert len(bodies) == 1 and bodies[0][1] == 'atlas-signing-key'
    with pytest.raises(_StopLoop):
        bodies[0][0]()
    return sleeps, checks


def test_the_key_is_checked_at_least_once_a_minute(atlas, monkeypatch):
    sleeps, checks = _run_the_loop(atlas, monkeypatch, ticks=4)

    assert len(checks) == 4
    # The first wait is the start-up pause. Every wait after a check is what bounds how
    # long ATLAS refuses administrators once Authentik has taken the key off.
    assert len(sleeps) == 5               # the pause, then one wait after each check
    assert all(wait <= 60 for wait in sleeps[1:]), sleeps
    assert sleeps[1:] == [atlas.SIGNING_KEY_CHECK_INTERVAL_S] * 4


def test_a_check_that_raises_does_not_end_the_loop(atlas, monkeypatch, capsys):
    sleeps, checks, bodies = [], [], []

    class FakeThread:
        def __init__(self, target=None, daemon=None, name=None):
            bodies.append(target)

        def start(self):
            pass

    def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(checks) >= 3:
            raise _StopLoop()

    def broken(ctx, log):
        checks.append(True)
        raise RuntimeError('authentik is restarting')

    monkeypatch.setattr(atlas, '_signing_key_loop_started', False)
    monkeypatch.setattr(atlas, 'threading', types.SimpleNamespace(Thread=FakeThread))
    monkeypatch.setattr(atlas, 'time', types.SimpleNamespace(sleep=fake_sleep))
    monkeypatch.setattr(atlas, 'converge_signed_identity', broken)

    atlas._start_signing_key_loop({})
    with pytest.raises(_StopLoop):
        bodies[0]()

    assert len(checks) == 3
    assert 'authentik is restarting' in capsys.readouterr().out


def test_the_loop_starts_once_per_console_process(atlas, monkeypatch):
    started = []

    class FakeThread:
        def __init__(self, target=None, daemon=None, name=None):
            pass

        def start(self):
            started.append(True)

    monkeypatch.setattr(atlas, '_signing_key_loop_started', False)
    monkeypatch.setattr(atlas, 'threading', types.SimpleNamespace(Thread=FakeThread))
    atlas._start_signing_key_loop({})
    atlas._start_signing_key_loop({})
    assert started == [True]


def test_the_module_starts_the_loop_when_it_registers():
    register = ATLAS_SRC[ATLAS_SRC.index('\ndef register(ctx):'):]
    register = register[:register.index('def _requested_instance')]
    assert '_start_signing_key_loop(ctx)' in register


def test_the_five_minute_revocation_loop_does_not_check_the_key_too():
    loop = ATLAS_SRC[ATLAS_SRC.index('def _start_revocation_loop(ctx):'):]
    loop = loop[:loop.index('\ndef ', 10)]
    assert 'converge_signed_identity' not in loop


def test_two_checks_never_run_at_the_same_time(atlas, monkeypatch):
    """The first thing a check does is read the deployments. If two checks are inside
    that read together, nothing stops them from restarting `api` twice."""
    state = {'active': 0, 'most': 0, 'calls': 0}
    guard = threading.Lock()

    def slow_read(ctx):
        with guard:
            state['active'] += 1
            state['calls'] += 1
            state['most'] = max(state['most'], state['active'])
        real_time.sleep(0.15)
        with guard:
            state['active'] -= 1
        return []

    monkeypatch.setattr(atlas, 'load_instances', slow_read)
    workers = [threading.Thread(target=atlas.converge_signed_identity,
                                args=({}, lambda m: None)) for _ in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(10)

    assert state['calls'] == 4
    assert state['most'] == 1
