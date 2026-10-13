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
"""v10.3.0 W4.c — a connection that dies before the TLS handshake must not kill the console.

Field: aws-jammy right after its 22.04 -> 24.04 upgrade (Python 3.12), 2026-10-13 — 29
worker deaths in ~30 minutes, each re-running every startup migration (and restarting TAK
Server via the 8446 cert heal), which starved Guard Dog's post-start of a stable TAK and
left CloudTAK's retention container down. Reproduced on demand on aws-noble by resetting
three queued connections during a console boot (3 deaths); with this worker class the same
attack logged "dropped a connection…" six times and the worker lived.

The real gunicorn is not installed in the test environment, so a stand-in ThreadWorker with
gunicorn 23's enqueue_req contract is injected before gunicorn.conf.py is loaded.
"""

import pathlib
import runpy
import ssl
import sys
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
CONF = REPO / 'gunicorn.conf.py'


class _BaseThreadWorker:
    """gunicorn 23 gthread.ThreadWorker.enqueue_req, verbatim in behavior."""
    def enqueue_req(self, conn):
        conn.init()
        fs = self.tpool.submit(self.handle, conn)
        self._wrap_future(fs, conn)


@pytest.fixture
def conf(monkeypatch):
    g = types.ModuleType('gunicorn')
    w = types.ModuleType('gunicorn.workers')
    gt = types.ModuleType('gunicorn.workers.gthread')
    gt.ThreadWorker = _BaseThreadWorker
    monkeypatch.setitem(sys.modules, 'gunicorn', g)
    monkeypatch.setitem(sys.modules, 'gunicorn.workers', w)
    monkeypatch.setitem(sys.modules, 'gunicorn.workers.gthread', gt)
    return runpy.run_path(str(CONF))


class _Conn:
    def __init__(self, exc=None):
        self.exc, self.closed, self.client = exc, False, ('127.0.0.1', 60858)

    def init(self):
        if self.exc:
            raise self.exc

    def close(self):
        self.closed = True


def _worker(cls):
    w = object.__new__(cls)
    w.nr_conns = 1
    w.submitted, w.wrapped, w.logged = [], [], []
    w.handle = object()
    w.tpool = types.SimpleNamespace(submit=lambda fn, c: w.submitted.append(c) or 'future')
    w._wrap_future = lambda fs, c: w.wrapped.append((fs, c))
    w.log = types.SimpleNamespace(info=lambda *a: w.logged.append(a))
    return w


def test_the_console_uses_the_safe_worker(conf):
    assert conf['worker_class'] is conf['SafeThreadWorker']
    assert issubclass(conf['SafeThreadWorker'], _BaseThreadWorker)


@pytest.mark.parametrize('exc', [
    ssl.SSLError(107, 'Closed before TLS handshake with data in recv buffer.'),   # Python 3.12 / RHEL 3.9
    OSError(107, 'Transport endpoint is not connected'),
    ConnectionResetError(104, 'Connection reset by peer'),
])
def test_a_dead_connection_is_dropped_and_the_worker_lives(conf, exc):
    w = _worker(conf['SafeThreadWorker'])
    c = _Conn(exc)
    assert w.enqueue_req(c) is None                 # no exception escapes to the run loop
    assert c.closed and w.nr_conns == 0             # closed, and gunicorn's count stays honest
    assert w.submitted == [] and w.wrapped == []    # never handed to a request thread
    assert w.logged and 'before the TLS handshake' in w.logged[0][0]


def test_the_unpatched_worker_really_dies_on_it(conf):
    """Guard the guard: the base class (gunicorn 23 behavior) lets it escape."""
    w = _worker(_BaseThreadWorker)
    with pytest.raises(ssl.SSLError):
        w.enqueue_req(_Conn(ssl.SSLError(107, 'Closed before TLS handshake with data in recv buffer.')))


def test_a_healthy_connection_is_served_exactly_as_before(conf):
    w = _worker(conf['SafeThreadWorker'])
    c = _Conn()
    w.enqueue_req(c)
    assert w.submitted == [c] and w.wrapped == [('future', c)]
    assert not c.closed and w.nr_conns == 1


def test_without_gunicorn_the_file_still_loads(monkeypatch):
    monkeypatch.setitem(sys.modules, 'gunicorn.workers.gthread', None)   # import fails
    ns = runpy.run_path(str(CONF))
    assert ns['worker_class'] == 'gthread'


def test_nothing_else_is_configured_here():
    """Command-line flags in the console unit must stay authoritative: this file sets
    only the worker class (a bind/workers/timeout here would silently fight start.sh)."""
    ns_names = {'worker_class'}
    import ast
    tree = ast.parse(CONF.read_text())
    assigned = {t.id for n in tree.body if isinstance(n, ast.Assign) for t in n.targets
                if isinstance(t, ast.Name) and not t.id.startswith('_')}
    assert assigned == ns_names
