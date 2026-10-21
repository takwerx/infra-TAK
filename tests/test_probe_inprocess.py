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
"""_probe_run() talks to the broker in-process (v10.2.2 W4).

The promise is "the caller cannot tell": for every scenario the in-process path
must return the same CompletedProcess (returncode, stdout, stderr, text vs bytes)
as running the REAL light client through subprocess.run, against the same fake
daemon. The functions under test are cut out of app.py, not copied.
"""

import base64
import json
import os
import pathlib
import re
import socket
import subprocess
import sys

import pytest

from test_brokerctl import FakeBroker, ok_reply

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
CLIENT = str(REPO / 'broker' / 'takwerx_brokerctl.py')


def _cut(name, kind='def'):
    pat = (rf'^def {name}\(.*?(?=^\S)' if kind == 'def' else
           rf'^class {name}\(.*?(?=^\S)' if kind == 'class' else
           rf'^{name} = .*?(?=^\S)')
    m = re.search(pat, APP, re.S | re.M)
    assert m, name
    return m.group(0)


SRC = '\n'.join([
    _cut('BrokerError', 'class'), _cut('_broker_connect'), _cut('_broker_request'),
    _cut('_probe_run'),
    _cut('_PROBE_SHIMMED', 'assign'), _cut('_probe_shim_equivalent'),
    _cut('_BROKER_INPROCESS_KW', 'assign'), _cut('_broker_client_prefix'),
    _cut('_broker_inprocess_eligible'), _cut('_broker_exec_inprocess'),
])


class Console:
    def __init__(self, sock):
        self.forced_subprocess = False
        self.ns = {
            'os': os, 'json': json, 'subprocess': subprocess, '_socket': socket,
            '_b64': base64, '_sys': sys,
            '_BROKER_CLIENT': CLIENT, '_BROKER_CLIENT_PYFLAGS': ['-I', '-S'],
            'BROKER_SOCKET': sock,
            '_broker_shim_env': lambda env: env,
            '_broker_should_route': lambda: True, '_broker_available': lambda: True,
            '_broker_wait': lambda ready, *a, **k: False,       # no broker restart here
            '_BROKER_SHIM_DIR': str(REPO / 'tests'),            # replaced per test when needed
        }
        self.ns['_sudo_wrap'] = lambda cmd: [sys.executable, '-I', '-S', CLIENT, 'exec', '--'] + list(cmd)
        exec(compile(SRC, 'app.py:W4', 'exec'), self.ns)
        real = self.ns['_broker_inprocess_eligible']
        self.ns['_broker_inprocess_eligible'] = lambda a, kw: (not self.forced_subprocess) and real(a, kw)
        self.sock = sock

    def wrap(self, cmd):
        return [sys.executable, '-I', '-S', CLIENT, 'exec', '--'] + list(cmd)

    def probe(self, cmd, inprocess, **kw):
        self.forced_subprocess = not inprocess
        env = {k: v for k, v in os.environ.items() if not k.startswith('TAKWERX_BROKER')}
        env['TAKWERX_BROKER_SOCKET'] = self.sock
        env.update(kw.pop('env_extra', {}))
        kw.setdefault('env', env)
        return self.ns['_probe_run'](self.wrap(cmd), **kw)


def both(make_broker, reply, cmd=('systemctl', 'is-active', 'caddy'), **kw):
    out = {}
    for mode in ('subprocess', 'inprocess'):
        b = make_broker(reply)
        c = Console(b.path)
        r = c.probe(cmd, mode == 'inprocess', **dict(kw))
        out[mode] = (r, b.requests)
    return out


@pytest.fixture
def make_broker():
    made = []

    def make(reply):
        made.append(FakeBroker(reply))
        return made[-1]

    yield make
    for b in made:
        b.close()


def same(res):
    (rs, qs), (ri, qi) = res['subprocess'], res['inprocess']
    assert (ri.returncode, ri.stdout, ri.stderr) == (rs.returncode, rs.stdout, rs.stderr)
    assert type(ri.stdout) is type(rs.stdout)
    for q in (qs, qi):
        for r in q:
            r['cwd'] = os.path.realpath(r['cwd'])
    assert qi == qs
    return ri, qi


@pytest.mark.parametrize('text', [True, False])
def test_success_bytes_and_text_match(make_broker, text):
    reply = ok_reply(stdout=b'active\r\nline2\rx\n', stderr=b'warn\n', rc=3)
    r, q = same(both(make_broker, reply, text=text))
    assert r.returncode == 3
    assert r.stdout == ('active\nline2\nx\n' if text else b'active\r\nline2\rx\n')
    assert q[0]['argv'] == ['systemctl', 'is-active', 'caddy']


def test_denied_matches(make_broker):
    reply = json.dumps({'ok': False, 'code': 'DENIED', 'error': 'nope'}).encode()
    r, _ = same(both(make_broker, reply, text=True))
    assert (r.returncode, r.stderr) == (126, 'takwerx_broker: DENIED: nope\n')


@pytest.mark.parametrize('reply', [None, b'{"ok": tr'], ids=['empty', 'truncated'])
def test_garbled_response_is_125_both_ways(make_broker, reply):
    res = both(make_broker, reply, text=True)
    for r, _ in res.values():
        assert r.returncode == 125
        assert r.stderr.startswith('takwerx_broker: cannot reach broker: ')


def test_unreachable_is_125_both_ways(tmp_path):
    sock = '/tmp/bctl-absent-%d' % os.getpid()
    for inproc in (False, True):
        r = Console(sock).probe(['true'], inproc, text=True)
        assert r.returncode == 125
        assert r.stderr.startswith('takwerx_broker: cannot reach broker: ')


def test_invalid_utf8_in_text_mode_degrades_to_124_both_ways(make_broker):
    res = both(make_broker, ok_reply(stdout=b'\xff\xfe'), text=True)
    assert [r.returncode for r, _ in res.values()] == [124, 124]


def test_cwd_and_timeout_env_ride_the_request(make_broker, tmp_path):
    cwd = str(tmp_path)
    r, q = same(both(make_broker, ok_reply(), cwd=cwd, env_extra={'TAKWERX_BROKER_TIMEOUT': '9999'}))
    assert os.path.realpath(q[0]['cwd']) == os.path.realpath(cwd)
    assert q[0]['timeout'] == 7200


def test_a_slow_broker_times_out_like_subprocess(make_broker):
    import threading
    gate = threading.Event()
    b = make_broker(ok_reply())
    orig = b._serve

    def slow():      # accept, then never answer within the probe timeout
        conn, _ = b.sock.accept()
        gate.wait(5)
        conn.close()
    b._t = threading.Thread(target=slow, daemon=True)
    b.sock.close()
    b.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    os.unlink(b.path)
    b.sock.bind(b.path)
    b.sock.listen(1)
    b._t.start()
    r = Console(b.path).probe(['sleep', '9'], True, timeout=0.5, text=True)
    gate.set()
    assert r.returncode == 124


@pytest.mark.parametrize('cmd,kw', [
    ('docker ps --filter name=x', {'shell': True}),            # shell strings: subprocess
    (['systemctl', 'is-active', 'x'], {'input': b'x'}),         # stdin data: subprocess
    (['systemctl', 'is-active', 'x'], {'stdout': subprocess.DEVNULL}),
    (['systemctl', 'is-active', 'x'], {'capture_output': False}),
])
def test_anything_unusual_stays_on_subprocess(cmd, kw):
    c = Console('/tmp/unused')
    args = cmd if isinstance(cmd, str) else c.wrap(cmd)
    kw = dict({'capture_output': True, 'timeout': 8, 'env': None}, **kw)
    assert c.ns['_broker_inprocess_eligible'](args, kw) is False


def test_a_plain_argv_not_routed_by_sudo_wrap_stays_on_subprocess():
    c = Console('/tmp/unused')
    kw = {'capture_output': True, 'timeout': 8, 'env': None}
    assert c.ns['_broker_inprocess_eligible'](['which', 'caddy'], kw) is False
    old = [sys.executable, str(REPO / 'broker' / 'takwerx_broker.py'), 'exec', '--', 'true']
    assert c.ns['_broker_inprocess_eligible'](old, kw) is False
    assert c.ns['_broker_inprocess_eligible'](c.wrap(['true']), kw) is True


def test_inprocess_path_spawns_no_process(make_broker):
    b = make_broker(ok_reply(stdout=b'active\n'))
    c = Console(b.path)

    class NoSpawn:
        CompletedProcess = subprocess.CompletedProcess
        TimeoutExpired = subprocess.TimeoutExpired
        CalledProcessError = subprocess.CalledProcessError

        @staticmethod
        def run(*a, **kw):
            raise AssertionError('subprocess.run called for a broker-routed probe')
    c.ns['subprocess'] = NoSpawn
    r = c.probe(['systemctl', 'is-active', 'caddy'], True, text=True)
    assert (r.returncode, r.stdout) == (0, 'active\n')


def test_only_the_exact_client_prefix_qualifies():
    c = Console('/tmp/unused')
    kw = {'capture_output': True, 'timeout': 8, 'env': None}
    long_plain = ['docker', 'ps', '-a', '--filter', 'name=x', '--format', '{{.Names}}', '-q']
    assert c.ns['_broker_inprocess_eligible'](long_plain, kw) is False
    assert c.ns['_broker_inprocess_eligible'](c.wrap(['true']), dict(kw, shell=True)) is False


# ---------------------------------------------------------------------------
# W4b: a bare docker/systemctl/fail2ban-client probe goes where its PATH shim would
# ---------------------------------------------------------------------------
def _always_list():
    sh = (REPO / 'broker' / 'install-shims.sh').read_text()
    body = re.search(r'ALWAYS=\((.*?)\)', sh, re.S).group(1)
    return set(body.split())


def test_rewritten_binaries_are_ones_the_shims_always_route():
    c = Console('/tmp/unused')
    assert set(c.ns['_PROBE_SHIMMED']) <= _always_list()


def _shimdir(tmp_path, *names):
    for n in names:
        (tmp_path / n).write_text('#!/bin/bash\n')
    return str(tmp_path)


def test_bare_docker_probe_runs_in_process_like_its_shim(make_broker, tmp_path):
    b = make_broker(ok_reply(stdout=b'true\n'))
    c = Console(b.path)
    c.ns['_BROKER_SHIM_DIR'] = _shimdir(tmp_path, 'docker', 'systemctl')

    class NoSpawn:
        CompletedProcess = subprocess.CompletedProcess
        TimeoutExpired = subprocess.TimeoutExpired
        CalledProcessError = subprocess.CalledProcessError

        @staticmethod
        def run(*a, **kw):
            raise AssertionError('spawned')
    c.ns['subprocess'] = NoSpawn
    r = c.ns['_probe_run'](['docker', 'inspect', '--format', '{{.State.Running}}', 'x'],
                           capture_output=True, text=True, timeout=3)
    assert (r.returncode, r.stdout) == (0, 'true\n')
    assert b.requests[0]['argv'] == ['docker', 'inspect', '--format', '{{.State.Running}}', 'x']


@pytest.mark.parametrize('argv,shims,routing,expect_rewrite', [
    (['docker', 'ps'], ('docker',), True, True),
    (['docker', 'cp', 'c:/a', '/tmp/b'], ('docker',), True, False),   # staged by its shim
    (['docker', 'ps'], (), True, False),                               # no shim installed
    (['docker', 'ps'], ('docker',), False, False),                     # root / no broker
    (['/usr/bin/docker', 'ps'], ('docker',), True, False),             # absolute path skips PATH
    (['which', 'caddy'], ('which',), True, False),                     # not an always-route binary
    ('docker ps', ('docker',), True, False),                           # shell string
])
def test_shim_equivalence_rule(tmp_path, argv, shims, routing, expect_rewrite):
    c = Console('/tmp/unused')
    c.ns['_BROKER_SHIM_DIR'] = _shimdir(tmp_path, *shims)
    c.ns['_broker_should_route'] = lambda: routing
    out = c.ns['_probe_shim_equivalent'](argv)
    assert (out != argv) is expect_rewrite
    if expect_rewrite:
        assert out == c.wrap(argv)
