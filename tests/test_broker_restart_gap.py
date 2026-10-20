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
"""A broker restart must never turn a privileged call into a failed `sudo -n` (ops #113).

test6, 2026-10-20 13:14:58Z (T&E v10.2.22):

    recycle: idle after 23.0h uptime — exiting for a clean restart     13:14:58.207
    listening on /run/takwerx-broker.sock                              13:15:01.494

The recycle fired between two calls of the post-update Guard Dog timer loop (a call every
<1 s). In the 3.3 s gap the console fell back to `sudo -n` 46 times — which fails on a
non-root box — so post-update logged "Node-RED container not running" and skipped the flow
sync, and the Authentik reconfigure logged a false `FATAL: port conflict`.

Two halves, both tested here:
  * the broker recycles only after a real quiet window, and unlinks its socket before it
    stops accepting;
  * every client (app.py, the light client, the PATH shims) waits for a broker systemd
    still has up or coming back, instead of falling back.
"""

import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import pytest

from test_brokerctl import FakeBroker, ok_reply

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# broker: the recycle waits for a quiet window
# ---------------------------------------------------------------------------
class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class _Srv:
    def __init__(self, events):
        self.events = events

    def shutdown(self):
        self.events.append('shutdown')


def _watch(activity_at, after=100, quiet=15, quiet_max=3600, until=20_000):
    """Drive _recycle_watch with a fake clock. `activity_at(t)` -> (in_flight, last_activity)."""
    b = _load('takwerx_broker_gap', REPO / 'broker' / 'takwerx_broker.py')
    clock, events, logs = _Clock(), [], []

    def sleep(secs):
        clock.t += secs
        if clock.t > until:
            raise AssertionError('watcher never recycled')
        b._INFLIGHT, b._LAST_ACTIVITY = activity_at(clock.t)
        events.append(('sleep', secs))

    b._INFLIGHT, b._LAST_ACTIVITY = activity_at(0)
    out = b._recycle_watch(_Srv(events), after, 0.0, clock=clock, sleep=sleep, poll=5,
                           note_every=50, log=logs.append, quiet=quiet, quiet_max=quiet_max,
                           unlink=lambda: events.append(('unlink', clock.t)), grace=1)
    return out, clock.t, events, logs


def _burst(start, end, every=0.8):
    """Back-to-back short calls: never in flight at a poll, last activity always recent."""
    def at(t):
        if start <= t < end:
            return 0, t - ((t - start) % every)
        return 0, (min(end, max(start, t)) if t >= start else None)
    return at


def test_a_burst_of_short_calls_defers_the_recycle():
    # The 13:14:58Z failure: nothing in flight at the poll, but calls every <1 s.
    out, t, events, logs = _watch(_burst(50, 400))
    assert out == 'idle'
    unlink_t = next(e[1] for e in events if isinstance(e, tuple) and e[0] == 'unlink')
    assert unlink_t >= 400 + 15, 'recycled inside the burst'
    assert any(l.startswith('recycle deferred: busy') for l in logs)
    assert logs[-1].startswith('recycle: idle') and 'last request' in logs[-1]


def test_recycles_after_the_quiet_window():
    out, t, events, logs = _watch(lambda t: (0, 10.0))     # one request at t=10, then nothing
    assert out == 'idle' and 100 <= t <= 100 + 5 + 1


def test_quiet_window_is_bounded_so_a_chatty_box_still_recycles():
    # test6 has a background request every ~30 s all day; a box busier than the quiet
    # window must still recycle (at an idle instant) once quiet_max has passed.
    out, t, events, logs = _watch(_burst(0, 10**9, every=3), quiet=15, quiet_max=600)
    assert out == 'idle'
    unlink_t = next(e[1] for e in events if isinstance(e, tuple) and e[0] == 'unlink')
    assert 100 + 600 <= unlink_t <= 100 + 600 + 5


def test_never_recycles_with_a_request_in_flight_even_past_quiet_max():
    out, t, events, logs = _watch(lambda t: (1, t) if t < 5000 else (0, 5000.0), quiet_max=60)
    unlink_t = next(e[1] for e in events if isinstance(e, tuple) and e[0] == 'unlink')
    assert unlink_t >= 5000


def test_socket_is_unlinked_before_accepting_stops():
    out, t, events, logs = _watch(lambda t: (0, None))
    kinds = [e if isinstance(e, str) else e[0] for e in events]
    i_unlink, i_shut = kinds.index('unlink'), kinds.index('shutdown')
    assert i_unlink < i_shut
    assert ('sleep', 1) in events[i_unlink:i_shut], 'no grace for a client that just connected'


def test_serve_passes_the_real_unlink_and_tests_never_do():
    src = (REPO / 'broker' / 'takwerx_broker.py').read_text()
    assert re.search(r"target=_recycle_watch,.*?kwargs=\{'unlink': _unlink_socket\}", src, re.S)
    sig = re.search(r'def _recycle_watch\((.*?)\):', src, re.S).group(1)
    assert 'unlink=None' in sig            # a test driving the watcher cannot delete /run/…


def test_activity_is_stamped_on_start_and_finish():
    b = _load('takwerx_broker_gap2', REPO / 'broker' / 'takwerx_broker.py')
    assert b._last_activity() is None
    b._inflight_add(1)
    t1 = b._last_activity()
    time.sleep(0.01)
    b._inflight_add(-1)
    assert t1 is not None and b._last_activity() > t1


# ---------------------------------------------------------------------------
# light client: retries the connect while the broker restarts
# ---------------------------------------------------------------------------
@pytest.fixture
def ctl():
    return _load('takwerx_brokerctl_gap', REPO / 'broker' / 'takwerx_brokerctl.py')


def test_client_waits_for_a_restarting_broker(ctl):
    b = FakeBroker(ok_reply(stdout=b'ok\n'))
    path = b.path
    b.close()                                       # socket gone: broker mid-restart
    ctl.SOCKET_PATH = path
    ctl.broker_restarting = lambda: True
    revived = {}

    def revive():
        time.sleep(0.6)
        nb = FakeBroker(ok_reply(stdout=b'ok\n'))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.rename(nb.path, path)
        revived['b'] = nb
    threading.Thread(target=revive, daemon=True).start()
    try:
        resp = ctl.client_send({'op': 'exec', 'argv': ['true']}, timeout=5)
        assert resp['ok'] is True
        assert revived['b'].requests[0]['argv'] == ['true']
    finally:
        if 'b' in revived:
            revived['b'].close()
        shutil.rmtree(os.path.dirname(path), ignore_errors=True)


def test_client_fails_fast_when_the_broker_is_not_coming_back(ctl):
    ctl.SOCKET_PATH = os.path.join(tempfile.mkdtemp(prefix='bgap', dir='/tmp'), 'absent')
    calls = []
    ctl.broker_restarting = lambda: calls.append(1) or False
    t0 = time.monotonic()
    with pytest.raises(FileNotFoundError):
        ctl.connect(5)
    assert time.monotonic() - t0 < 1 and calls == [1]


def test_client_wait_is_bounded(ctl):
    ctl.SOCKET_PATH = os.path.join(tempfile.mkdtemp(prefix='bgap', dir='/tmp'), 'absent')
    ctl.broker_restarting = lambda: True
    clock = _Clock()

    def sleep(s):
        clock.t += s
    with pytest.raises(FileNotFoundError):
        ctl.connect(5, wait=30, clock=clock, sleep=sleep)
    assert 30 <= clock.t <= 31


def test_client_only_trusts_systemd_for_the_units_own_socket(ctl):
    ctl.SOCKET_PATH = '/tmp/some-test-socket'
    assert ctl.broker_restarting() is False         # never runs systemctl for a test socket


# ---------------------------------------------------------------------------
# app.py: _broker_available / _sudo_wrap / _broker_connect wait instead of falling back
# ---------------------------------------------------------------------------
def _cut(name, kind='def'):
    pat = (rf'^def {name}\(.*?(?=^\S)' if kind == 'def' else
           rf'^class {name}\(.*?(?=^\S)' if kind == 'class' else
           rf'^{name} = .*?(?=^\S)')
    m = re.search(pat, APP, re.S | re.M)
    assert m, name
    return m.group(0)


SRC = '\n'.join([
    _cut('BrokerError', 'class'), _cut('BROKER_RESTART_WAIT_SECS', 'assign'),
    _cut('_BROKER_UNIT_SOCKET', 'assign'), _cut('_BROKER_LIVE_STATES', 'assign'),
    _cut('_broker_wait_note_at', 'assign'),
    _cut('_broker_socket_present'), _cut('_broker_restarting'), _cut('_broker_wait'),
    _cut('_broker_available'), _cut('_broker_connect'), _cut('_broker_request'),
    _cut('_sudo_wrap'),
])


class Console:
    def __init__(self, sock, routing=True, restarting=True):
        import json
        import socket
        import stat
        self.ns = {'os': os, 'json': json, 'subprocess': subprocess, 'shutil': shutil,
                   'time': time, '_socket': socket, '_stat': stat, '_sys': sys,
                   'BROKER_SOCKET': sock, '_BROKER_CLIENT': '/x/takwerx_brokerctl.py',
                   '_BROKER_CLIENT_PYFLAGS': ['-I', '-S']}
        exec(compile(SRC, 'app.py:ops113', 'exec'), self.ns)
        self.ns['_broker_should_route'] = lambda: routing
        self.state_checks = 0

        def _restarting():
            self.state_checks += 1
            return restarting
        self.ns['_broker_restarting'] = _restarting


def _revive_at(path, delay, reply=None):
    out = {}

    def go():
        time.sleep(delay)
        nb = FakeBroker(reply or ok_reply())
        os.rename(nb.path, path)
        out['b'] = nb
    threading.Thread(target=go, daemon=True).start()
    return out


@pytest.fixture
def gap_path():
    d = tempfile.mkdtemp(prefix='bgap', dir='/tmp')
    yield os.path.join(d, 's')
    shutil.rmtree(d, ignore_errors=True)


def test_sudo_wrap_waits_for_the_broker_instead_of_sudo_n(gap_path):
    c = Console(gap_path)
    revived = _revive_at(gap_path, 0.5)
    try:
        argv = c.ns['_sudo_wrap'](['docker', 'ps'])
        assert argv[:4] == [sys.executable, '-I', '-S', '/x/takwerx_brokerctl.py']
        assert 'sudo' not in argv
    finally:
        revived.get('b') and revived['b'].close()


def test_a_down_broker_still_falls_back_at_once(gap_path):
    c = Console(gap_path, restarting=False)
    t0 = time.monotonic()
    assert c.ns['_broker_available']() is False
    assert time.monotonic() - t0 < 0.5
    if os.getuid() != 0:
        assert c.ns['_sudo_wrap'](['true'])[:2] == ['sudo', '-n']


def test_root_console_not_routing_never_waits(gap_path):
    c = Console(gap_path, routing=False)
    assert c.ns['_broker_available']() is False
    assert c.state_checks == 0


def test_the_wait_is_bounded(gap_path, monkeypatch):
    c = Console(gap_path)
    t0 = time.monotonic()
    assert c.ns['_broker_wait'](lambda: False, max_secs=0.5) is False
    assert 0.5 <= time.monotonic() - t0 < 2


def test_inprocess_request_retries_the_connect_through_a_restart(gap_path):
    c = Console(gap_path)
    revived = _revive_at(gap_path, 0.5, ok_reply(stdout=b'active\n'))
    try:
        resp = c.ns['_broker_request']({'op': 'exec', 'argv': ['systemctl', 'is-active', 'x']},
                                       timeout=5)
        assert resp['ok'] is True
        assert revived['b'].requests[0]['argv'] == ['systemctl', 'is-active', 'x']
    finally:
        revived.get('b') and revived['b'].close()


def test_inprocess_request_to_a_down_broker_is_still_brokererror(gap_path):
    c = Console(gap_path, restarting=False)
    with pytest.raises(c.ns['BrokerError']):
        c.ns['_broker_request']({'op': 'exec', 'argv': ['true']}, timeout=5)


def test_app_only_trusts_systemd_for_the_units_own_socket(gap_path):
    import json
    import socket
    import stat
    ns = {'os': os, 'json': json, 'subprocess': subprocess, 'shutil': shutil, 'time': time,
          '_socket': socket, '_stat': stat, '_sys': sys, 'BROKER_SOCKET': gap_path}
    exec(compile(SRC, 'app.py:ops113', 'exec'), ns)
    assert ns['_broker_restarting']() is False


# ---------------------------------------------------------------------------
# PATH shims: wait for the socket before falling through to the bare binary
# ---------------------------------------------------------------------------
@pytest.fixture
def shims():
    d = tempfile.mkdtemp(prefix='bgapshim', dir='/tmp')
    client = os.path.join(d, 'client.py')
    open(client, 'w').close()
    sd = os.path.join(d, 'shims')
    r = subprocess.run(['bash', str(REPO / 'broker' / 'install-shims.sh'), sd, client],
                       capture_output=True, text=True,
                       env=dict(os.environ, PATH='/usr/sbin:/usr/bin:/sbin:/bin'))
    assert r.returncode == 0, r.stderr
    yield sd
    shutil.rmtree(d, ignore_errors=True)


def test_every_routing_shim_waits_before_it_falls_through(shims):
    for name in os.listdir(shims):
        text = open(os.path.join(shims, name)).read()
        assert 'is-active takwerx-broker' in text, name
        wait = text.index('while [ ! -S /run/takwerx-broker.sock ]')
        route = text.index('python3 -I -S')
        assert wait < route, name
        # the old guard skipped routing (and the wait) whenever the socket was missing
        assert '[ -S /run/takwerx-broker.sock ] && [ -f' not in text, name
        assert '[ ! -S /run/takwerx-broker.sock ] || [ ! -f' not in text, name
        assert re.search(r'-lt (\d+) \]', text).group(1) == '120', name   # 120 x 0.25 s = 30 s
        r = subprocess.run(['bash', '-n', os.path.join(shims, name)], capture_output=True)
        assert r.returncode == 0, (name, r.stderr)


def test_shims_ask_the_real_systemctl_not_themselves(shims):
    text = open(os.path.join(shims, 'docker')).read()
    sc = re.search(r'"\$\((\S+) is-active takwerx-broker', text).group(1)
    assert sc.startswith('/') and shims not in sc


@pytest.mark.skipif(os.getuid() == 0, reason='shims never route as root')
@pytest.mark.parametrize('name,args', [('docker', ['--version']), ('mkdir', ['-p', '/etc']),
                                       ('systemctl', ['--version'])])
def test_no_broker_unit_falls_through_without_hanging(shims, name, args):
    # A box (or this Mac) with no takwerx-broker unit: `is-active` is not one of the live
    # states, so the wait breaks at once and the real binary runs as before.
    if os.path.exists('/run/takwerx-broker.sock'):
        pytest.skip('a real broker is running here')
    t0 = time.monotonic()
    subprocess.run(['bash', os.path.join(shims, name)] + args, capture_output=True, timeout=10)
    assert time.monotonic() - t0 < 3
