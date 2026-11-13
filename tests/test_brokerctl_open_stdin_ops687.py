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
"""ops #687 round 3: the broker client must not wait forever on a held-open stdin.

TAK Portal runs its Marketplace job over SSH. When the host refuses a pty it falls back to a
session with no terminal, and its stdin is a pipe that is never written and never closed.
The PATH shim for `docker` runs `takwerx_brokerctl.py exec -- docker info`, which used to read
stdin to EOF, so the job log stopped at the first docker call and every Marketplace install
and uninstall hung (verified on a kept update-check box, Thu Nov 12, 2026: no pty + open pipe
hung, pty answered, closed stdin answered).

The clients are run exactly as the shim runs them, with stdin = a pipe the test holds open.
"""

import base64
import os
import subprocess
import sys
import tempfile
import time

import pytest

import test_brokerctl as tb
from test_brokerctl import broker_factory, ok_reply  # noqa: F401  (fixture + helper)


def _env(sock, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith('TAKWERX_BROKER')}
    env['TAKWERX_BROKER_SOCKET'] = sock
    env.update(extra)
    return env


def _run_with_pipe(sock, args, *, writer=None, hold=60, env_extra=None, limit=25):
    """Run the new client with stdin = a pipe held open for `hold` seconds. `writer(fd)` may
    write to it first. Returns (CompletedProcess-like, seconds) or raises TimeoutExpired."""
    p = subprocess.Popen([sys.executable, '-I', '-S', str(tb.NEW)] + args,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env=_env(sock, **(env_extra or {})), cwd=tempfile.gettempdir())
    t0 = time.monotonic()
    try:
        if writer:
            writer(p.stdin)
        p.wait(timeout=limit)
        out, err = p.stdout.read(), p.stderr.read()
        return p.returncode, out, err, time.monotonic() - t0
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
        for f in (p.stdin, p.stdout, p.stderr):
            try:
                f.close()
            except Exception:
                pass


def test_open_silent_pipe_does_not_hang_the_client(broker_factory):
    """No terminal, stdin held open and never written (what TAK Portal's no-pty session gives)."""
    b = broker_factory(ok_reply(stdout=b'Server: Docker\n'))
    rc, out, err, secs = _run_with_pipe(b.path, ['exec', '--', 'docker', 'info'])
    assert rc == 0, err
    assert out == b'Server: Docker\n'
    assert len(b.requests) == 1
    assert b.requests[0]['argv'] == ['docker', 'info']
    assert b.requests[0]['input_b64'] is None
    assert secs < 15


def test_the_wait_can_be_shortened_with_the_env(broker_factory):
    b = broker_factory(ok_reply())
    rc, _, _, secs = _run_with_pipe(b.path, ['exec', '--', 'docker', 'info'],
                                    env_extra={'TAKWERX_BROKER_STDIN_WAIT': '0'})
    assert rc == 0
    assert secs < 3


def test_data_already_in_the_pipe_is_still_forwarded(broker_factory):
    """A producer that writes at once and closes (the console's subprocess input=) is unchanged."""
    b = broker_factory(ok_reply())

    def w(fd):
        fd.write(b'payload\x00\n')
        fd.close()
    rc, _, err, _ = _run_with_pipe(b.path, ['exec', '--', 'tee', '/etc/x'], writer=w)
    assert rc == 0, err
    assert base64.b64decode(b.requests[0]['input_b64']) == b'payload\x00\n'


def test_a_producer_that_starts_within_the_wait_is_not_lost(broker_factory):
    b = broker_factory(ok_reply())
    import threading
    p = subprocess.Popen([sys.executable, '-I', '-S', str(tb.NEW), 'exec', '--', 'tee', '/etc/x'],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env=_env(b.path, TAKWERX_BROKER_STDIN_WAIT='6'), cwd=tempfile.gettempdir())

    def late():
        time.sleep(1.0)
        p.stdin.write(b'late-data')
        p.stdin.close()
    t = threading.Thread(target=late)
    t.start()
    p.wait(timeout=30)
    t.join()
    assert p.returncode == 0, p.stderr.read()
    assert base64.b64decode(b.requests[0]['input_b64']) == b'late-data'
    for f in (p.stdout, p.stderr):
        f.close()


def test_closed_stdin_and_devnull_answer_at_once(broker_factory):
    b = broker_factory(ok_reply())
    t0 = time.monotonic()
    p = tb.run_client('new', ['exec', '--', 'docker', 'info'], b.path)   # stdin=DEVNULL
    assert p.returncode == 0
    assert time.monotonic() - t0 < 5
    assert b.requests[0]['input_b64'] is None


def test_default_wait_is_short_enough_not_to_stall_a_job():
    """A Marketplace job makes many shim calls; each one waits this long when stdin is silent."""
    assert 0 < float(tb._module_assigns(tb.NEW)['STDIN_FIRST_BYTE_WAIT'].value) <= 3
