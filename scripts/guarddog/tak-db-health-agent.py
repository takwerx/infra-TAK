#!/usr/bin/env python3
"""Lightweight health endpoint for a TAK Server database server (Server One).
Deployed by Guard Dog in two-server mode. Listens on port 8080 and exposes
/health which checks PostgreSQL cluster status and cot database reachability.
No dependencies beyond Python 3 stdlib + psql on the host."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess, json, os, glob, shutil


def _find_pg_bin(name):
    """Resolve a PostgreSQL client binary. On Debian it's on PATH, but on RHEL/Rocky the
    PGDG packages install it under /usr/pgsql-*/bin — which is NOT on the systemd service's
    PATH, so a bare `pg_isready`/`psql` raised FileNotFoundError and crashed /health."""
    p = shutil.which(name)
    if p:
        return p
    for base in sorted(glob.glob('/usr/pgsql-*/bin'), reverse=True) + \
            sorted(glob.glob('/usr/lib/postgresql/*/bin'), reverse=True):
        cand = os.path.join(base, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return name  # fall back to bare name (may fail; the check below catches it)


_PG_ISREADY = _find_pg_bin('pg_isready')
_PSQL = _find_pg_bin('psql')


class DBHealthHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _check(self):
        checks = {}
        # PostgreSQL cluster running
        try:
            r = subprocess.run([_PG_ISREADY, '-q'], capture_output=True, timeout=5)
            checks['pg_ready'] = r.returncode == 0
        except Exception as e:
            checks['pg_ready'] = False
            checks['pg_ready_err'] = str(e)[:120]

        # cot database exists and is accessible
        try:
            r = subprocess.run(
                ['sudo', '-u', 'postgres', _PSQL, '-lqt'],
                capture_output=True, text=True, timeout=10, cwd='/'
            )
            checks['cot_db'] = 'cot' in (r.stdout or '') if r.returncode == 0 else False
        except Exception as e:
            checks['cot_db'] = False
            checks['cot_db_err'] = str(e)[:120]

        # Disk usage on root
        try:
            r = subprocess.run(['df', '--output=pcent', '/'], capture_output=True, text=True, timeout=5)
            pct = int(r.stdout.strip().split('\n')[-1].strip().rstrip('%'))
            checks['disk_ok'] = pct < 90
            checks['disk_pct'] = pct
        except Exception:
            checks['disk_ok'] = True
            checks['disk_pct'] = -1

        checks['healthy'] = bool(checks.get('pg_ready') and checks.get('cot_db') and checks.get('disk_ok'))
        return checks

    def _safe_check(self):
        # A missing binary / unexpected error must NEVER crash the handler — that drops the
        # TCP connection (curl 000) and Guard Dog can't tell "unhealthy" from "agent broken".
        try:
            return self._check()
        except Exception as e:
            return {'healthy': False, 'error': str(e)[:160]}

    def do_HEAD(self):
        checks = self._safe_check()
        self.send_response(200 if checks.get('healthy') else 503)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        if self.path == '/health':
            checks = self._safe_check()
            self.send_response(200 if checks.get('healthy') else 503)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(checks).encode() + b'\n')
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found\n')


if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), DBHealthHandler)
    server.serve_forever()
