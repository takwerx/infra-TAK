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
"""infra-TAK — one bad TLS client must not kill the console worker (v10.2.23).

Field (nuc, Rocky 9, 2026-10-15 and 2026-10-19): the console's single gunicorn
worker died 16 and 9 times in ~7 minutes with `Exception in worker process`, exit
255. Each respawn re-imported app.py, so the console was down ~50 s per crash
while the startup migrations re-ran.

Root cause, in gunicorn 23.0.0's gthread worker (held at 23.0.0: the last release
that supports RHEL 9's Python 3.9 — see requirements.txt):

  run() -> on_client_socket_readable() -> enqueue_req() -> conn.init()
        -> sock.ssl_wrap_socket() -> SSLContext.wrap_socket()

runs on the worker's MAIN event-loop thread, not in the request thread pool, and
nothing on that path catches anything. Python's ssl module (CVE-2023-40217 fix,
in 3.9.18+ and RHEL 9's 3.9) checks at wrap time whether the peer is still there:
getpeername() -> ENOTCONN, then recv(1). A client that connected and then reset
the TCP connection before the TLS handshake makes that recv raise
`ConnectionResetError: [Errno 104]`; one that sent bytes and then reset raises
`ssl.SSLError: Closed before TLS handshake with data in recv buffer`. Either
escapes run(), and the arbiter treats it as a dead worker. `do_handshake_on_connect`
is already False, so the handshake itself is not on this path — only the wrap.

install() wraps ThreadWorker.enqueue_req so an OSError there (ssl.SSLError is
one) drops THAT connection only, and logs who sent it, at most once a minute per
address so a scanner can't flood the journal. Nothing was submitted to the pool
when conn.init() fails, so closing the socket and releasing its nr_conns slot is
the whole cleanup — the same thing gthread's own finish_request() does for a
failed request.

Applied at app.py import: gunicorn loads the app in the worker (no --preload)
BEFORE worker.run(), and run() looks enqueue_req up on the class on every call,
so the already-built worker picks up the wrapper. No systemd unit change, so
existing boxes get it from a normal Update Now.

STDLIB ONLY and imports nothing from app.py. install() never raises.
"""
import threading
import time

LOG_WINDOW_S = 60.0     # at most one log line per peer address per window
_MAX_TRACKED = 1024     # bound the per-address table (a scan of many sources)

_seen = {}              # address -> [window_start, suppressed_count]
_seen_lock = threading.Lock()


def _peer(conn):
    """('1.2.3.4', '1.2.3.4:5555') for an inet peer; best effort otherwise."""
    client = getattr(conn, 'client', None)
    if isinstance(client, (tuple, list)) and client:
        host = str(client[0])
        port = client[1] if len(client) > 1 else '?'
        return host, (f'[{host}]:{port}' if ':' in host else f'{host}:{port}')
    text = str(client) if client else 'unknown peer'
    return text, text


def _should_log(addr, now=None):
    """(log_it, suppressed_since_last_line) for one drop from `addr`."""
    now = time.monotonic() if now is None else now
    with _seen_lock:
        entry = _seen.get(addr)
        if entry is not None and now - entry[0] < LOG_WINDOW_S:
            entry[1] += 1
            return False, 0
        suppressed = entry[1] if entry is not None else 0
        if entry is None and len(_seen) >= _MAX_TRACKED:
            _seen.clear()
        _seen[addr] = [now, 0]
        return True, suppressed


def _log_drop(log, conn, exc):
    addr, shown = _peer(conn)
    log_it, suppressed = _should_log(addr)
    if not log_it:
        return
    more = (f' (+{suppressed} more from this address in the previous '
            f'{int(LOG_WINDOW_S)}s window)') if suppressed else ''
    try:
        log.warning('[tls-guard] dropped a connection from %s that closed before '
                    'its TLS handshake (%s: %s); the worker stays up%s',
                    shown, type(exc).__name__, exc, more)
    except Exception:
        pass


def _wrap(original):
    def enqueue_req(self, conn):
        try:
            return original(self, conn)
        except OSError as exc:
            # conn.init() failed before anything reached the thread pool: this
            # connection is dead, the worker is not.
            self.nr_conns -= 1
            try:
                conn.close()
            except Exception:
                pass
            _log_drop(self.log, conn, exc)
            return None
    enqueue_req._infratak_tls_guard = True
    enqueue_req.__wrapped__ = original
    return enqueue_req


def install(worker_cls=None):
    """Guard gthread's enqueue_req. Idempotent; True when the guard is in place."""
    try:
        if worker_cls is None:
            from gunicorn.workers.gthread import ThreadWorker as worker_cls
        current = worker_cls.enqueue_req
        if getattr(current, '_infratak_tls_guard', False):
            return True
        worker_cls.enqueue_req = _wrap(current)
        return True
    except Exception:
        # No gunicorn (dev server, tests) or an incompatible gthread — run as before.
        return False
