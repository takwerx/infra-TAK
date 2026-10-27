#!/usr/bin/env python3
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
"""infra-TAK light broker client  (v10.2.2)

`takwerx_brokerctl.py exec -- <argv...>` — the SAME contract as
`takwerx_broker.py exec` (cli_exec), without the cost of starting the daemon's
3,300-line script for every privileged call. python3 never caches bytecode for
a script run as __main__, so each `takwerx_broker.py exec` re-compiled the whole
daemon (~100–140 ms on test6) and ran its import-time work before sending one
request. The console's `_sudo_wrap()` and the `.shims/` PATH wrappers exec this
file instead; `takwerx_broker.py exec` keeps working for anything still calling it.

This file only SENDS. The daemon decides — allow-list, audit log, socket
permissions and SO_PEERCRED are all on the other end and unchanged; nothing here
can widen what the daemon allows.

STDLIB ONLY and no venv: the shims run it with the SYSTEM python3.

Exit code = the command's; 125 when the broker is unreachable or its response is
empty/truncated/not JSON; 126 when the daemon refuses; 2 on bad usage.
"""
import base64
import json
import os
import socket
import subprocess
import sys
import time

# Duplicated from takwerx_broker.py on purpose (importing it is the cost this
# file exists to avoid). tests/test_brokerctl.py asserts they stay equal.
SOCKET_PATH = os.environ.get('TAKWERX_BROKER_SOCKET', '/run/takwerx-broker.sock')
MAX_MSG = 32 * 1024 * 1024
DEFAULT_TIMEOUT = 600
MAX_TIMEOUT = 7200

# ops #113: the broker restarts itself once a day (idle recycle) and on every source
# change; for ~2-3 s its socket is gone (or still there but refusing). A call landing in
# that gap used to fail with exit 125. Nothing was sent yet, so retrying the CONNECT cannot
# run a command twice — wait for the broker, bounded, while systemd says it is up or on its
# way back up (a stopped or failed broker fails fast, as before).
UNIT_SOCKET = '/run/takwerx-broker.sock'
RESTART_WAIT_SECS = 30
LIVE_STATES = ('active', 'activating', 'deactivating', 'reloading')


# ops #262: a first Print install from TAK Portal's marketplace (`docker compose ... up -d
# --build cloudtak-print`, 2 GB Chromium image) was killed at exactly the 600 s default on a
# busy box and the job showed failed although the image finished building. That call comes
# from TAK Portal through the docker shim, so no caller sets TAKWERX_BROKER_TIMEOUT for it.
# When the env is unset, an image-build or image-pull command gets BUILD_TIMEOUT instead.
# Everything else keeps the default; an explicit TAKWERX_BROKER_TIMEOUT always wins.
BUILD_TIMEOUT = 3600
_DOCKER_VALUE_FLAGS = frozenset((
    '-c', '--context', '-H', '--host', '-l', '--log-level', '--config',          # docker
    '-f', '--file', '-p', '--project-name', '--profile', '--env-file',           # compose
    '--project-directory', '--progress', '--ansi', '--parallel'))


def default_timeout(argv):
    """BUILD_TIMEOUT for `docker build|pull`, `docker buildx build` and `docker compose
    build|up|pull|create`; 0 (no opinion, the daemon's own default) for anything else."""
    if not argv or os.path.basename(argv[0]) != 'docker':
        return 0
    words, skip = [], False
    for a in argv[1:]:
        if skip:
            skip = False
        elif a.startswith('-'):
            skip = a in _DOCKER_VALUE_FLAGS
        else:
            words.append(a)
            if len(words) == 2:
                break
    if words[:1] in (['build'], ['pull']):
        return BUILD_TIMEOUT
    if words[:2] == ['buildx', 'build']:
        return BUILD_TIMEOUT
    if words[:1] == ['compose'] and words[1:2] and words[1] in ('build', 'up', 'pull', 'create'):
        return BUILD_TIMEOUT
    return 0


def broker_restarting():
    """True while systemd has takwerx-broker up or coming back. False when it cannot
    tell, and for a socket that is not the unit's (tests, TAKWERX_BROKER_SOCKET)."""
    if SOCKET_PATH != UNIT_SOCKET:
        return False
    for sc in ('/usr/bin/systemctl', '/bin/systemctl'):
        if os.path.exists(sc):
            break
    else:
        return False
    try:
        r = subprocess.run([sc, 'is-active', 'takwerx-broker'], capture_output=True,
                           text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return (r.stdout or '').strip() in LIVE_STATES


def connect(timeout, wait=RESTART_WAIT_SECS, clock=time.monotonic, sleep=time.sleep):
    """A socket connected to the broker; waits out a broker restart (see above)."""
    deadline = None
    while True:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(SOCKET_PATH)
            return s
        except (FileNotFoundError, ConnectionRefusedError):
            s.close()
            if deadline is None:
                deadline = clock() + wait
            if clock() >= deadline or not broker_restarting():
                raise
            sleep(0.25)
        except BaseException:
            s.close()
            raise


def client_send(req, timeout=DEFAULT_TIMEOUT):
    s = connect(timeout)
    try:
        s.sendall(json.dumps(req).encode())
        s.shutdown(socket.SHUT_WR)
        buf = bytearray()
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > MAX_MSG:
                break
    finally:
        s.close()
    return json.loads(bytes(buf).decode())


def cli_exec(args):
    if args and args[0] == '--':
        args = args[1:]
    if not args:
        sys.stderr.write('takwerx_broker exec: no command\n')
        return 2
    stdin_data = b''
    if sys.stdin is not None and not sys.stdin.isatty():
        try:
            stdin_data = sys.stdin.buffer.read()
        except Exception:
            stdin_data = b''
    req = {
        'op': 'exec',
        'argv': args,
        'cwd': os.getcwd(),
        'input_b64': base64.b64encode(stdin_data).decode() if stdin_data else None,
    }
    # TAKWERX_BROKER_TIMEOUT (seconds) rides the request — the daemon clamps it —
    # and stretches the socket wait past the daemon-side deadline.
    try:
        _env_t = int(os.environ.get('TAKWERX_BROKER_TIMEOUT') or 0)
    except ValueError:
        _env_t = 0
    if _env_t > 0:
        req['timeout'] = min(_env_t, MAX_TIMEOUT)
    elif default_timeout(args):
        req['timeout'] = default_timeout(args)
    try:
        resp = client_send(req, timeout=(req.get('timeout') or DEFAULT_TIMEOUT) + 60)
    except (OSError, socket.timeout, ValueError) as e:
        # ValueError = json.JSONDecodeError / UnicodeDecodeError: the daemon died
        # mid-request and the response is empty or truncated (v10.1.40 B3a).
        sys.stderr.write(f'takwerx_broker: cannot reach broker: {e}\n')
        return 125
    if not isinstance(resp, dict):
        sys.stderr.write('takwerx_broker: cannot reach broker: response is not a JSON object\n')
        return 125
    if not resp.get('ok'):
        sys.stderr.write(f"takwerx_broker: {resp.get('code')}: {resp.get('error')}\n")
        return 126
    sys.stdout.buffer.write(base64.b64decode(resp.get('stdout_b64') or ''))
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(base64.b64decode(resp.get('stderr_b64') or ''))
    sys.stderr.buffer.flush()
    return int(resp.get('returncode', 0))


def main(argv):
    if argv and argv[0] == 'exec':
        return cli_exec(argv[1:])
    sys.stderr.write('usage: takwerx_brokerctl.py exec -- <cmd...>\n')
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
