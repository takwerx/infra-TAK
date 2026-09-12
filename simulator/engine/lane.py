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
"""A lane: one enrolled identity, one TLS connection to TAK Server 8089 (PLAN v10.1.61 §4.1).

The lane's TAK Server group membership IS the channel selector — the server delivers a
connection's traffic to everyone sharing its active groups, so a lane that is a member of
exactly `tak_<channel>` reaches exactly that channel. The engine never picks a destination
per message; it picks a lane.

TLS: the server certificate is verified against the CA bundle the enrollment returned
(`ca.pem`, pinned), client-authenticated with the lane's enrolled certificate. Hostname
matching is deliberately off: TAK Server certificates carry `SAN=takserver` (the name
`makeCert.sh server takserver` bakes in), not the operator's host, so no TAK client —
ATAK, WinTAK, CloudTAK — matches the hostname; the pinned CA is the trust anchor, exactly
as in an ATAK truststore. Chain verification stays CERT_REQUIRED.

I/O model: one thread per lane owns the socket (Python's ssl objects are not safe for
concurrent read/write from two threads). The run loop enqueues; the lane thread drains the
queue and reads whatever the server sends back (the TakControl offer, other clients'
traffic in the channel) so the receive window never fills.
"""
import collections
import http.client
import json
import queue
import select
import socket
import ssl
import threading
import time


class LaneError(Exception):
    pass


class Lane:
    def __init__(self, lane_id, channel, cert_path, ca_path, host, port=8089, api_port=8443,
                 exercise=False, log=None, dry_run=False):
        self.id = str(lane_id)
        self.channel = channel
        self.cert_path = cert_path
        self.ca_path = ca_path
        self.host = host
        self.port = int(port)
        self.api_port = int(api_port)
        self.exercise = bool(exercise)
        self.log = log or (lambda m: None)
        self.dry_run = bool(dry_run)

        self.sock = None
        self.connected = False
        self.connected_at = None
        self.sent = 0
        self.dropped = 0
        self.received = 0
        self.bytes_in = 0
        self.errors = 0
        self.last_error = None
        self.takp_seen = False
        self._sent_times = collections.deque()
        self._q = queue.Queue(maxsize=20000)
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()

    # ── TLS ──────────────────────────────────────────────────────────────────
    def _ssl_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False          # pinned CA; see module docstring
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=self.ca_path)
        ctx.load_cert_chain(self.cert_path)
        return ctx

    def _connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=10)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        s = self._ssl_context().wrap_socket(raw, server_hostname=self.host)
        s.settimeout(10)
        with self._lock:
            self.sock = s
            self.connected = True
            self.connected_at = time.time()
        peer = s.getpeercert() or {}
        subj = ','.join('='.join(x) for rdn in peer.get('subject', ()) for x in rdn)
        self.log(f'lane {self.id}: connected to {self.host}:{self.port} (server cert {subj or "?"}, '
                 f'{s.version()}) channel={self.channel}')

    def _disconnect(self, why):
        with self._lock:
            self.connected = False
            s, self.sock = self.sock, None
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
        if why is not None:
            self.errors += 1
            self.last_error = str(why)[:200]
            self.log(f'lane {self.id}: disconnected ({self.last_error})')

    # ── I/O thread ───────────────────────────────────────────────────────────
    def start(self):
        if self.dry_run:
            self.connected = True
            self.connected_at = time.time()
            self.log(f'lane {self.id}: DRY RUN — nothing is sent (channel={self.channel})')
            return
        self._thread = threading.Thread(target=self._io_loop, name=f'lane-{self.id}', daemon=True)
        self._thread.start()

    def _io_loop(self):
        backoff = 1.0
        while not self._stop.is_set():
            if not self.connected:
                try:
                    self._connect()
                    backoff = 1.0
                except (OSError, ssl.SSLError) as e:
                    self.errors += 1
                    self.last_error = str(e)[:200]
                    self.log(f'lane {self.id}: connect failed ({self.last_error}); retry in {backoff:.0f}s')
                    self._stop.wait(backoff)
                    backoff = min(backoff * 2, 30.0)
                    continue
            s = self.sock
            try:
                readable, _, _ = select.select([s], [], [], 0.05)
                if readable or s.pending():
                    data = s.recv(65536)
                    if not data:
                        raise LaneError('server closed the connection')
                    self._on_data(data)
                for _ in range(512):
                    try:
                        item = self._q.get_nowait()
                    except queue.Empty:
                        break
                    s.sendall(item)
                    self.sent += 1
                    self._sent_times.append(time.monotonic())
            except (OSError, ssl.SSLError, LaneError) as e:
                self._disconnect(e)
        self._disconnect(None)

    def _on_data(self, data):
        self.bytes_in += len(data)
        self.received += data.count(b'<event')
        if not self.takp_seen and b't-x-takp-v' in data:
            self.takp_seen = True
            self.log(f'lane {self.id}: server offers TAK protocol negotiation; staying on XML')

    # ── API for the run loop ─────────────────────────────────────────────────
    def send(self, xml, block=False):
        """Queue one event. Non-blocking by default (the governor is the real limiter);
        `block=True` is for stop-deletes, which must never be dropped."""
        if self.dry_run:
            self.sent += 1
            self._sent_times.append(time.monotonic())
            return True
        try:
            self._q.put(xml.encode('utf-8'), block=block, timeout=10 if block else None)
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def flush(self, timeout=5.0):
        """Wait until the queue has drained (best effort) — used before closing."""
        deadline = time.monotonic() + timeout
        while not self._q.empty() and time.monotonic() < deadline and self.connected:
            time.sleep(0.05)
        return self._q.empty()

    def msgs_per_sec(self, window=5.0):
        cutoff = time.monotonic() - window
        while self._sent_times and self._sent_times[0] < cutoff:
            self._sent_times.popleft()
        return round(len(self._sent_times) / window, 1)

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self.dry_run:
            self.connected = False

    def stats(self):
        return {
            'id': self.id, 'channel': self.channel, 'exercise': self.exercise,
            'connected': self.connected, 'connected_at': self.connected_at,
            'sent': self.sent, 'received': self.received, 'dropped': self.dropped,
            'queued': self._q.qsize(), 'errors': self.errors, 'last_error': self.last_error,
            'msgs_per_s': self.msgs_per_sec(),
        }

    # ── channel activation (Marti API with the lane's own cert) ─────────────
    def ensure_groups_active(self):
        """Make every group this identity belongs to ACTIVE for it.

        TAK Server's x509 group cache (`x509useGroupCache`) remembers a certificate's
        per-channel on/off state, and a channel the user is ADDED TO after first login
        defaults to OFF (`x509useGroupCacheDefaultUpdatesActive`, default false). A lane
        re-targeted to a new channel would therefore connect with that channel switched
        off and reach nobody. This is what ATAK does when you toggle a channel on:
        GET groups/all -> flip active -> PUT groups/active. Own cert, own groups only.
        Returns (group_names, changed_count). Never raises — the caller logs."""
        if self.dry_run:
            return [self.channel], 0
        try:
            conn = http.client.HTTPSConnection(self.host, self.api_port, context=self._ssl_context(), timeout=15)
            conn.request('GET', '/Marti/api/groups/all?useCache=false', headers={'Accept': 'application/json'})
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200:
                self.log(f'lane {self.id}: groups/all -> HTTP {resp.status}')
                return [], 0
            groups = json.loads(body.decode('utf-8')).get('data') or []
            names = sorted({g.get('name', '?') for g in groups})
            changed = [g for g in groups if not g.get('active')]
            if changed:
                for g in groups:
                    g['active'] = True
                conn.request('PUT', '/Marti/api/groups/active', body=json.dumps(groups),
                             headers={'Content-Type': 'application/json'})
                r2 = conn.getresponse()
                r2.read()
                self.log(f'lane {self.id}: activated {len(changed)} channel(s) -> HTTP {r2.status}')
            conn.close()
            return names, len(changed)
        except (OSError, ssl.SSLError, ValueError) as e:
            self.log(f'lane {self.id}: channel activation skipped ({str(e)[:120]})')
            return [], 0
