#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Drive a test box's console the way an operator does (ops #285): log in, ask the OS-upgrade
preflight, press Start, press Update Now, wait for the status. Stdlib only.

    drive.py BASE_URL [--insecure] [--target core|dbserver] preflight
    drive.py BASE_URL [--target core|dbserver] start [--no-stack-backup]   # prints the HTTP status and the answer
    drive.py BASE_URL [--target core|dbserver] wait-status [--timeout S] [--ignore-failed-for S]
    drive.py BASE_URL update-now [--channel dev]      # Update Now on the console (the answer only: then use wait-status)

--target dbserver is the split install's database server, upgraded from the CORE's console (W4.e).

BASE_URL is the box's console, e.g. https://20.1.2.3:5001 (password only, no username: the dev-box
console rule). The certificate is verified unless --insecure is given, which is accepted only for an
IP-literal URL (a restored test box with its self-signed certificate). The console password is read from the file named by INFRATAK_CONSOLE_PASSWORD_FILE
(mode 600) and is never printed, logged or put on a command line. Output is one JSON object on
stdout; progress lines go to stderr.

Exit status: 0 the call was made and answered, 1 the wait ended without `done`, 2 bad input or the
box could not be reached.
"""
import argparse
import http.cookiejar
import ipaddress
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ACK = 'I have a snapshot'   # _OS_UPGRADE_ACK in app.py: the typed snapshot acknowledgment


class DriveError(Exception):
    pass


def _is_ip_literal(base):
    host = urllib.parse.urlsplit(base).hostname or ''
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class Console:
    def __init__(self, base, password, insecure=False):
        self.base = base.rstrip('/')
        self.password = password
        ctx = ssl.create_default_context()
        if insecure:
            # A restored test box answers on its bare IP with the self-signed console certificate.
            # Skipping verification is allowed for that and nothing else: an explicit flag, and only
            # for an IP literal, never for a name (a name has a certificate that can be checked).
            if not _is_ip_literal(self.base):
                raise DriveError('--insecure is only for a test box addressed by IP, not %s' % self.base)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=ctx))

    def _open(self, req, timeout):
        try:
            with self.opener.open(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (urllib.error.URLError, OSError) as e:
            raise DriveError('cannot reach %s: %s' % (self.base, getattr(e, 'reason', e)))

    def login(self):
        body = urllib.parse.urlencode({'password': self.password}).encode()
        req = urllib.request.Request(self.base + '/login', data=body, method='POST')
        status, raw = self._open(req, 30)
        if b'name="password"' in raw and b'Invalid' in raw:
            raise DriveError('the console refused the password')
        if not list(self.jar):
            raise DriveError('login gave no session (HTTP %s)' % status)

    def call(self, method, path, payload=None, timeout=60):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={'Content-Type': 'application/json'} if data else {})
        status, raw = self._open(req, timeout)
        try:
            return status, json.loads(raw.decode('utf-8', 'replace') or '{}')
        except ValueError:
            return status, {'_raw': raw.decode('utf-8', 'replace')[:300]}


def read_password():
    path = os.environ.get('INFRATAK_CONSOLE_PASSWORD_FILE', '')
    if not path:
        raise DriveError('set INFRATAK_CONSOLE_PASSWORD_FILE to a mode-600 file holding the console password')
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise DriveError('%s must be mode 600 (it holds a password)' % path)
    with open(path, encoding='utf-8') as f:
        return f.read().strip()


def log(msg):
    print(msg, file=sys.stderr, flush=True)


PATHS = {
    'core': {'preflight': '/api/console/os-upgrade/preflight', 'start': '/api/console/os-upgrade/start',
             'status': '/api/console/os-upgrade/status'},
    'dbserver': {'preflight': '/api/console/dbserver/preflight', 'start': '/api/console/dbserver/os-upgrade/start',
                 'status': '/api/console/dbserver/status'},
}


def status_state(target, st):
    """('done' | 'failed' | other, label) from a status answer of either target."""
    if target == 'dbserver':
        state = st.get('state', '')
        if st.get('job') != 'os-upgrade':
            return 'other', state or 'idle'
        return ('done' if state == 'done' else 'failed' if state.startswith('failed') else 'other'), 'os-upgrade:' + (state or 'idle')
    raw = st.get('raw', '')
    return ('done' if raw == 'done' else 'failed' if raw.startswith('failed:') else 'other'), raw or 'idle'


def wait_status(con, timeout, ignore_failed_for=0, target='core'):
    """Poll the OS-upgrade status until `done`. The console restarts and the box reboots during an
    upgrade, so an unreachable box is normal and just means "keep waiting". A `failed:` status ends
    the wait, except for `ignore_failed_for` seconds (a box that STARTS as failed:reassert, ops #318,
    still shows that for a moment before the new console takes it over)."""
    start = time.time()
    last = {}
    seen = ''
    while time.time() - start < timeout:
        try:
            con.login()   # a reboot or console restart drops the session
            code, st = con.call('GET', PATHS[target]['status'], timeout=20)
            if code == 200:
                last = st
                kind, label = status_state(target, st)
                if label != seen:
                    log('[%ds] status: %s' % (time.time() - start, label))
                    seen = label
                if kind == 'done':
                    return True, last
                if kind == 'failed' and time.time() - start >= ignore_failed_for:
                    return False, last
        except DriveError as e:
            if seen != 'unreachable':
                log('[%ds] console not answering (%s): rebooting or restarting, waiting' % (time.time() - start, e))
                seen = 'unreachable'
        time.sleep(15)
    return False, dict(last, timeout=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('base')
    ap.add_argument('--target', choices=('core', 'dbserver'), default='core')
    ap.add_argument('--insecure', action='store_true',
                    help='do not verify the console certificate (a test box addressed by IP, self-signed)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('preflight')
    s = sub.add_parser('start')
    s.add_argument('--no-stack-backup', action='store_true', help='skip the full-stack backup the console offers (the UI default is on)')
    u = sub.add_parser('update-now')
    u.add_argument('--channel', choices=('main', 'dev'), default='main')
    w = sub.add_parser('wait-status')
    w.add_argument('--timeout', type=int, default=3600)
    w.add_argument('--ignore-failed-for', type=int, default=0)
    args = ap.parse_args(argv)
    try:
        con = Console(args.base, read_password(), insecure=args.insecure)
        con.login()
        if args.cmd == 'preflight':
            code, pf = con.call('GET', PATHS[args.target]['preflight'], timeout=120)
            print(json.dumps(dict(pf, http_status=code)))
            return 0
        if args.cmd == 'start':
            code, ans = con.call('POST', PATHS[args.target]['start'], {
                'admin_password': con.password, 'acknowledge': ACK,
                'stack_backup': args.target == 'core' and not args.no_stack_backup}, timeout=120)
            print(json.dumps(dict(ans, http_status=code)))
            return 0
        if args.cmd == 'update-now':
            if args.channel == 'dev':
                code, ans = con.call('POST', '/api/update/channel', {'channel': 'dev', 'password': con.password})
                if code != 200:
                    raise DriveError('could not switch to the dev channel (HTTP %s)' % code)
            code, ans = con.call('POST', '/api/update/apply', {}, timeout=300)
            print(json.dumps(dict(ans, http_status=code)))
            return 0
        ok, last = wait_status(con, args.timeout, args.ignore_failed_for, args.target)
        print(json.dumps(dict(last, reached_done=ok)))
        return 0 if ok else 1
    except (DriveError, OSError) as e:
        print('drive.py: %s' % e, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
