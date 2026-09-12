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
"""Control API (PLAN v10.1.61 §4.2): a bearer-token JSON HTTP server the console talks to.

Published by compose on 127.0.0.1:5090 only; inside the container it listens on its own
network namespace, which since W10 is also joined to the private `infratak` Docker network
so the CloudTAK API container can reach it by name. Every request needs
`Authorization: Bearer <token>` (compared in constant time); bodies are capped at 2 MB;
nothing here takes a file path from a client.

Director routes (W9): POST /live, POST /cmd, POST /save, GET /state.
"""
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import scenario as sc

MAX_BODY = 2 * 1024 * 1024


class ControlServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, engine, token):
        self.engine = engine
        self.token = token
        super().__init__(addr, Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = 'tak-simulator'
    sys_version = ''
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):     # keep docker logs for the run log, not access lines
        pass

    # ── helpers ──────────────────────────────────────────────────────────
    def _authed(self):
        h = self.headers.get('Authorization', '')
        tok = h[7:].strip() if h.startswith('Bearer ') else ''
        return bool(self.server.token) and hmac.compare_digest(tok, self.server.token)

    def _send(self, code, obj):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > MAX_BODY:
            raise ValueError('body too large')
        raw = self.rfile.read(n) if n else b''
        if not raw:
            return {}
        obj = json.loads(raw.decode('utf-8'))
        if not isinstance(obj, dict):
            raise ValueError('body must be a JSON object')
        return obj

    # ── routes ───────────────────────────────────────────────────────────
    def do_GET(self):
        if not self._authed():
            return self._send(401, {'error': 'unauthorized'})
        eng = self.server.engine
        path = self.path.split('?', 1)[0]
        if path == '/health':
            return self._send(200, {'ok': True, 'version': eng.cfg['version'],
                                    'state': eng.run.state if eng.run else 'idle'})
        if path == '/status':
            return self._send(200, eng.status())
        if path == '/log':
            return self._send(200, {'lines': eng.log_lines(500)})
        if path == '/scenarios':
            return self._send(200, {'scenarios': eng.list_scenarios()})
        if path == '/state':
            return self._send(200, eng.state())
        return self._send(404, {'error': 'not found'})

    def do_POST(self):
        if not self._authed():
            return self._send(401, {'error': 'unauthorized'})
        eng = self.server.engine
        path = self.path.split('?', 1)[0]
        try:
            body = self._body()
        except (ValueError, UnicodeDecodeError) as e:
            return self._send(400, {'error': f'bad request: {str(e)[:120]}'})
        try:
            if path == '/run':
                return self._send(200, eng.start_run(body))
            if path == '/live':
                return self._send(200, eng.start_live(body))
            if path == '/cmd':
                return self._send(200, eng.command(body))
            if path == '/save':
                return self._send(200, eng.save(body))
            if path == '/validate':
                doc = sc.validate(body.get('scenario') if 'scenario' in body else body)
                return self._send(200, {'valid': True, 'summary': sc.summarize(doc)})
            if path == '/pause':
                return self._send(200, {'ok': eng.pause(), 'state': eng.run.state if eng.run else 'idle'})
            if path == '/resume':
                return self._send(200, {'ok': eng.resume(), 'state': eng.run.state if eng.run else 'idle'})
            if path == '/stop':
                return self._send(200, {'ok': eng.stop(), 'state': eng.run.state if eng.run else 'idle'})
        except sc.ScenarioError as e:
            return self._send(400, {'error': 'invalid scenario or parameters', 'errors': e.errors[:20]})
        except LookupError as e:
            return self._send(404, {'error': str(e)[:300]})
        except RuntimeError as e:
            return self._send(409, {'error': str(e)[:300]})
        except OSError as e:
            return self._send(500, {'error': str(e)[:300]})
        except Exception as e:          # a bug must answer, not drop the connection
            eng.log(f'control: {path} failed: {type(e).__name__}: {str(e)[:200]}')
            return self._send(500, {'error': f'internal error: {type(e).__name__}'})
        return self._send(404, {'error': 'not found'})


def serve(engine, bind, token):
    host, _, port = bind.rpartition(':')
    srv = ControlServer((host or '0.0.0.0', int(port or 5090)), engine, token)
    return srv
