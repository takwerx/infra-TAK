#!/usr/bin/env python3
"""Guard Dog health endpoint. Returns 200 if TAK Server is healthy, 503 otherwise.
In two-server mode, also checks remote DB reachability (reads config from
/opt/tak-guarddog/guarddog.conf if present).

The console publishes this at https://<console name>/health with no login, for outside
monitors. So one caller must not be able to make it answer late or not at all, because
then the monitor reports a healthy box as down (ops #815):
- each connection has its own thread and a socket timeout, so a caller that connects
  and sends nothing holds one thread for a few seconds, not the whole service;
- the number of connections served at once is capped; one over the cap is closed;
- the answer is kept for a few seconds, so a steady caller does not start systemctl, ss
  and pgrep for every request, and each of those has its own timeout.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess, json, socket, os, threading, time

_conf_path = '/opt/tak-guarddog/guarddog.conf'
_conf = {}
if os.path.isfile(_conf_path):
    try:
        with open(_conf_path) as f:
            _conf = json.load(f)
    except Exception:
        pass

REQUEST_TIMEOUT_S = 5      # per connection: read the request, write the answer
CHECK_TIMEOUT_S = 5        # per command
CACHE_TTL_S = 3            # one set of checks answers every caller for this long
MAX_CONNECTIONS = 32       # served at once

_cache_lock = threading.Lock()
_cache = {'at': None, 'checks': None}
_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)


def _run(cmd, **kw):
    """Run one check command. None when it did not finish in time or could not start."""
    try:
        return subprocess.run(cmd, capture_output=True, timeout=CHECK_TIMEOUT_S, **kw)
    except (subprocess.TimeoutExpired, OSError):
        return None


def run_checks():
    checks = {}

    r = _run(['systemctl', 'is-active', 'takserver'])
    checks['takserver'] = bool(r) and r.returncode == 0

    r = _run(['ss', '-ltn', 'sport = :8089'], text=True)
    checks['port_8089'] = bool(r) and 'LISTEN' in (r.stdout or '')

    r = _run(['pgrep', '-f', 'spring.profiles.active=messaging'])
    checks['messaging'] = bool(r) and r.returncode == 0

    r = _run(['pgrep', '-f', 'spring.profiles.active=api'])
    checks['api'] = bool(r) and r.returncode == 0

    # Two-server: check remote DB port
    db_host = _conf.get('db_host', '')
    db_port = int(_conf.get('db_port', 0))
    if db_host and db_port:
        try:
            s = socket.create_connection((db_host, db_port), timeout=5)
            s.close()
            checks['remote_db'] = True
        except Exception:
            checks['remote_db'] = False

    checks['healthy'] = all(checks.values())
    return checks


def cached_checks():
    """The checks, at most CACHE_TTL_S old. Callers that arrive while a run is in
    progress wait for that run and share its answer."""
    with _cache_lock:
        now = time.monotonic()
        if _cache['at'] is None or now - _cache['at'] >= CACHE_TTL_S:
            _cache['checks'] = run_checks()
            _cache['at'] = time.monotonic()
        return dict(_cache['checks'])


class HealthHandler(BaseHTTPRequestHandler):
    timeout = REQUEST_TIMEOUT_S     # socket timeout, set by StreamRequestHandler.setup()

    def log_message(self, format, *args):
        pass

    def check_health(self):
        return cached_checks()

    def do_HEAD(self):
        if self.path == '/health':
            checks = self.check_health()
            self.send_response(200 if checks['healthy'] else 503)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()

    def do_GET(self):
        if self.path == '/health':
            checks = self.check_health()
            self.send_response(200 if checks['healthy'] else 503)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(checks).encode() + b'\n')
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found\n')


class HealthServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def process_request(self, request, client_address):
        if not _slots.acquire(blocking=False):
            self.shutdown_request(request)      # over the cap: close, start no thread
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            _slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            _slots.release()

    def handle_error(self, request, client_address):
        pass    # a caller that timed out or hung up is not worth a traceback in the journal


if __name__ == '__main__':
    server = HealthServer(('0.0.0.0', 8080), HealthHandler)
    server.serve_forever()
