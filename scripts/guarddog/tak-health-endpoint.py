#!/usr/bin/env python3
"""Guard Dog health endpoint. Returns 200 if TAK Server is healthy, 503 otherwise.
In two-server mode, also checks remote DB reachability (reads config from
/opt/tak-guarddog/guarddog.conf if present).

The console publishes this at https://<console name>/health with no login, for outside
monitors. So one caller must not be able to make it answer late or not at all, because
then the monitor reports a healthy box as down (ops #815):
- each connection has its own thread, a socket timeout and a deadline for the whole
  request, so a caller that sends nothing, or one byte now and then, holds one thread
  for a few seconds, not the whole service;
- the number of connections served at once is capped, in total and per outside
  address; one over a cap is closed;
- the answer is kept for a few seconds, so a steady caller does not start systemctl, ss
  and pgrep for every request; each of those has its own timeout; and while one caller
  waits for new checks, the others get the last answer at once.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess, json, socket, os, sys, threading, time

_conf_path = '/opt/tak-guarddog/guarddog.conf'
_conf = {}
if os.path.isfile(_conf_path):
    try:
        with open(_conf_path) as f:
            _conf = json.load(f)
    except Exception:
        pass

REQUEST_TIMEOUT_S = 5      # per read or write on a connection
REQUEST_DEADLINE_S = 10    # per connection, from accept to the end of the answer
CHECK_TIMEOUT_S = 5        # per command
CACHE_TTL_S = 3            # one set of checks answers every caller for this long
MAX_CONNECTIONS = 64       # served at once
MAX_PER_ADDRESS = 4        # served at once for one outside address (this box itself,
                           # which is how the console's web server calls, is not counted)

_cache_lock = threading.Lock()
_cache = {'at': None, 'checks': None}
_slots_lock = threading.Lock()
_slots = {'total': 0, 'by_address': {}}


def _is_loopback(address):
    return address.startswith('127.') or address in ('::1', '::ffff:127.0.0.1')


def take_slot(address):
    """True when this connection may be served. Every True needs one give_slot()."""
    with _slots_lock:
        if _slots['total'] >= MAX_CONNECTIONS:
            return False
        if not _is_loopback(address):
            if _slots['by_address'].get(address, 0) >= MAX_PER_ADDRESS:
                return False
            _slots['by_address'][address] = _slots['by_address'].get(address, 0) + 1
        _slots['total'] += 1
        return True


def give_slot(address):
    with _slots_lock:
        _slots['total'] = max(0, _slots['total'] - 1)
        if not _is_loopback(address):
            left = _slots['by_address'].get(address, 0) - 1
            if left > 0:
                _slots['by_address'][address] = left
            else:
                _slots['by_address'].pop(address, None)


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
    """The checks, at most CACHE_TTL_S old when nobody is running them. One caller at a
    time runs them; callers that arrive meanwhile get the last answer at once (only
    before the first answer exists do they wait for it)."""
    answer, at = _cache['checks'], _cache['at']
    if answer is not None and time.monotonic() - at < CACHE_TTL_S:
        return dict(answer)
    if not _cache_lock.acquire(blocking=answer is None):
        return dict(answer)
    try:
        if _cache['at'] is None or time.monotonic() - _cache['at'] >= CACHE_TTL_S:
            fresh = run_checks()
            _cache['checks'], _cache['at'] = fresh, time.monotonic()
        return dict(_cache['checks'])
    finally:
        _cache_lock.release()


class HealthHandler(BaseHTTPRequestHandler):
    timeout = REQUEST_TIMEOUT_S     # socket timeout, set by StreamRequestHandler.setup()

    def setup(self):
        super().setup()
        # The socket timeout is per read, so a caller that sends one byte every few
        # seconds would never reach it. This ends the connection whatever it does.
        self._deadline = threading.Timer(REQUEST_DEADLINE_S, self._too_slow)
        self._deadline.daemon = True
        self._deadline.start()

    def _too_slow(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        self._deadline.cancel()
        try:
            super().finish()
        except OSError:
            pass

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
        if not take_slot(client_address[0]):
            self.shutdown_request(request)      # over a cap: close, start no thread
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            give_slot(client_address[0])
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            give_slot(client_address[0])

    def handle_error(self, request, client_address):
        # A caller that timed out or hung up is not worth a line; anything else is.
        exc = sys.exc_info()[1]
        if not isinstance(exc, OSError):
            print('health endpoint error: %s: %s' % (type(exc).__name__, str(exc)[:200]),
                  file=sys.stderr, flush=True)


if __name__ == '__main__':
    server = HealthServer(('0.0.0.0', 8080), HealthHandler)
    server.serve_forever()
