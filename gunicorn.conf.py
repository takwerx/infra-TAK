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
"""gunicorn settings for the infra-TAK console.

gunicorn reads ./gunicorn.conf.py from its working directory by default, and the
console unit runs with WorkingDirectory=<install dir>, so this file is picked up by
every console — root-era and born-non-root, Ubuntu and RHEL — on the next restart
after a console update. Nothing in start.sh or the systemd unit needs to change
(console-path delivery). Command-line flags in the unit (bind, workers, threads,
timeout, certfile/keyfile) still win over anything set here.

Only one setting lives here: the worker class.

v10.3.0 W4.c — a dead TLS connection must not kill the console.
gunicorn 23's threaded worker wraps each accepted socket in TLS inside
`enqueue_req -> TConn.init -> ssl_wrap_socket` with no handler around it. A client
that opened :5001 and gave up before the worker accepted it (Caddy's 10-second TLS
handshake timeout, a browser tab polling the console, a health probe) leaves a socket
whose TLS wrap raises — `OSError [Errno 107] Transport endpoint is not connected`
or `ssl.SSLError: Closed before TLS handshake with data in recv buffer` (the
CVE-2023-40217 check, present in Python 3.12 and in the RHEL 9 3.9 builds). The
exception escapes the worker's run loop, the single worker exits, the arbiter boots a
new one, and that boot re-runs every startup migration (~60 s, including a TAK Server
restart on some boxes). Anything still polling during that minute poisons the queue
again: a crash loop. Seen on nuc since 2026-08-24 (Python 3.9), and on aws-jammy right
after its 22.04 -> 24.04 upgrade (Python 3.12): 22 worker deaths in 22 minutes, while
the fresh 24.04 box with nobody polling it had none.

SafeThreadWorker closes that one connection and carries on. A failed TLS wrap only
ever concerns the client that sent it, so dropping it is exactly what a server should
do — the worker, every other connection and every in-flight request are unaffected.
"""

try:
    from gunicorn.workers.gthread import ThreadWorker as _ThreadWorker
except Exception:            # gunicorn not importable (e.g. the file read by a test or a linter)
    _ThreadWorker = object


class SafeThreadWorker(_ThreadWorker):
    """gunicorn's threaded worker, minus the one unhandled exception that kills it."""

    def enqueue_req(self, conn):
        try:
            conn.init()
        except OSError as e:     # ssl.SSLError is an OSError subclass
            # Accounting mirrors gunicorn's own close paths (finish_request /
            # murder_keepalived): the connection was counted in accept().
            self.nr_conns -= 1
            try:
                conn.close()
            except Exception:
                pass
            try:
                self.log.info("dropped a connection that failed before the TLS handshake "
                              "(%s): %s", getattr(conn, 'client', '?'), e)
            except Exception:
                pass
            return
        fs = self.tpool.submit(self.handle, conn)
        self._wrap_future(fs, conn)


worker_class = SafeThreadWorker if _ThreadWorker is not object else 'gthread'
