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
            try:
                return e.code, e.read()
            except OSError as e2:   # the server answered with a status and then dropped the connection
                raise DriveError('cannot reach %s: HTTP %s then %s' % (self.base, e.code, e2))
        except (urllib.error.URLError, OSError) as e:
            raise DriveError('cannot reach %s: %s' % (self.base, getattr(e, 'reason', e)))

    def login(self):
        body = urllib.parse.urlencode({'password': self.password}).encode()
        req = urllib.request.Request(self.base + '/login', data=body, method='POST', headers={'Origin': self.base})
        status, raw = self._open(req, 30)
        if b'name="password"' in raw and b'Invalid' in raw:
            raise DriveError('the console refused the password')
        if not list(self.jar):
            raise DriveError('login gave no session (HTTP %s)' % status)

    def call(self, method, path, payload=None, timeout=60):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers=dict({'Content-Type': 'application/json'} if data else {},
                                                  **{'Origin': self.base} if method != 'GET' else {}))   # the console's CSRF check wants the Origin of a POST to match the host
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
    ran = False
    while time.time() - start < timeout:
        try:
            code, st = con.call('GET', PATHS[target]['status'], timeout=20)
            if code != 200 or 'raw' not in st and 'state' not in st:
                con.login()   # a reboot or console restart drops the session (and the login is rate-limited: only when needed)
                code, st = con.call('GET', PATHS[target]['status'], timeout=20)
            if code == 200:
                last = st
                kind, label = status_state(target, st)
                if label != seen:
                    log('[%ds] status: %s' % (time.time() - start, label))
                    seen = label
                if kind == 'done':
                    return True, last
                if label.startswith('running'):
                    ran = True
                # a failed status counts at once when the job has run since we started watching (the finish
                # itself failed); before that it is the old status, and the new console's finish starts a
                # minute after the restart and waits for the post-update deploy
                if kind == 'failed' and (ran or time.time() - start >= ignore_failed_for):
                    return False, last
        except DriveError as e:
            if seen != 'unreachable':
                log('[%ds] console not answering (%s): rebooting or restarting, waiting' % (time.time() - start, e))
                seen = 'unreachable'
        time.sleep(15)
    return False, dict(last, timeout=True)


def _red(pf):
    return [c.get('name') for c in (pf.get('checks') or []) if not c.get('pass')]


def _wait_console_back(con, down_for=240, back_for=900):
    """After a reboot request: wait until the console stops answering, then until it answers again."""
    deadline = time.time() + down_for
    while time.time() < deadline:
        try:
            con.call('GET', '/login', timeout=8)
        except DriveError:
            break
        time.sleep(5)
    deadline = time.time() + back_for
    while time.time() < deadline:
        try:
            con.login()
            return
        except DriveError:
            time.sleep(10)
    raise DriveError('the console did not come back within %ds of the reboot' % back_for)


def _retry(con, method, path, payload=None, timeout=60, for_s=600):
    """One console call that rides out a console restart (it restarts itself after some updates)."""
    deadline = time.time() + for_s
    while True:
        try:
            return con.call(method, path, payload, timeout=timeout)
        except DriveError:
            if time.time() >= deadline:
                raise
            time.sleep(15)
            try:
                con.login()
            except DriveError:
                pass


def _reboot(con):
    try:
        con.call('POST', '/api/system/kernel-patch/reboot', {}, timeout=30)
    except DriveError:
        pass   # the box went down before it answered: that is the reboot


def prepare(con, timeout=3600):
    """What an operator does on the Console page before the upgrade: Install updates, Reboot if asked,
    Re-check, until nothing is red for a reason a click fixes. A snapshot gets older every day, so
    every restored box has updates pending (ops #285). Returns the last preflight.
    Anything else red (a real refusal reason) is left alone: that is what the cell is testing."""
    deadline = time.time() + timeout
    for _ in range(40):
        if time.time() > deadline:
            break
        code, pf = _retry(con, 'GET', PATHS['core']['preflight'], timeout=120)
        red = _red(pf)
        if red == ['no_job_running'] or ('no_job_running' in red and len(red) == 1):
            log('a console job is still finishing (%s), waiting' % ', '.join(c.get('detail', '')[:80] for c in pf.get('checks', []) if c.get('name') == 'no_job_running'))
            time.sleep(30)
            continue
        if 'os_up_to_date' in red:
            log('installing the pending Ubuntu updates (Install updates)')
            _retry(con, 'POST', '/api/system/kernel-patch/start', {}, timeout=60)
            while time.time() < deadline:
                time.sleep(15)
                try:
                    con.login()
                    _, st = con.call('GET', '/api/system/kernel-patch/job-status', timeout=20)
                except DriveError:
                    continue
                if st.get('error') and not st.get('running'):
                    raise DriveError('Install updates failed: %s' % (st.get('log_tail') or '')[-300:].replace('\n', ' | '))
                if not st.get('running') and (st.get('done') or not st.get('log_present')):
                    break
            continue
        if 'no_reboot_pending' in red:
            log('rebooting for the installed updates (Reboot)')
            _reboot(con)
            _wait_console_back(con)
            continue
        return pf
    raise DriveError('could not bring the box to a clean preflight in %ds (still red: %s)' % (timeout, ', '.join(_red(pf)) or 'unknown'))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('base')
    ap.add_argument('--target', choices=('core', 'dbserver'), default='core')
    ap.add_argument('--wait-ready', type=int, default=0, metavar='S',
                    help='a box that has just been restored is still booting: keep trying to log in for up to S seconds')
    ap.add_argument('--insecure', action='store_true',
                    help='do not verify the console certificate (a test box addressed by IP, self-signed)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('preflight')
    sub.add_parser('prepare', help='Install updates + Reboot until no pending-update / reboot check is red (a snapshot ages)')
    s = sub.add_parser('start')
    s.add_argument('--no-stack-backup', action='store_true', help='skip the full-stack backup the console offers (the UI default is on)')
    u = sub.add_parser('update-now')
    u.add_argument('--channel', choices=('main', 'dev'), default='main')
    u.add_argument('--wait', action='store_true', help='then wait for the console to restart onto the new code and answer again')
    w = sub.add_parser('wait-status')
    w.add_argument('--timeout', type=int, default=3600)
    w.add_argument('--ignore-failed-for', type=int, default=0)
    args = ap.parse_args(argv)
    try:
        con = Console(args.base, read_password(), insecure=args.insecure)
        if args.cmd != 'wait-status':   # waiting logs in by itself, and a console mid-reboot or rate-limiting logins is normal there
            ready_by = time.time() + args.wait_ready
            while True:
                try:
                    con.login()
                    break
                except DriveError:
                    if time.time() >= ready_by:
                        raise
                    time.sleep(10)
        if args.cmd == 'preflight':
            code, pf = con.call('GET', PATHS[args.target]['preflight'], timeout=120)
            print(json.dumps(dict(pf, http_status=code)))
            return 0
        if args.cmd == 'prepare':
            pf = prepare(con)
            print(json.dumps(dict(pf, prepared=True)))
            return 0
        if args.cmd == 'start':
            body = {'admin_password': con.password, 'acknowledge': ACK,
                    'stack_backup': args.target == 'core' and not args.no_stack_backup}
            deadline = time.time() + 1500
            while True:
                code, ans = _retry(con, 'POST', PATHS[args.target]['start'], body, timeout=120, for_s=180)
                # a job the console started by itself after its restart (an Authentik re-apply) is still finishing:
                # an operator waits and presses Start again. Any other refusal is final.
                if code == 409 and (ans.get('error') == 'preflight failed: no_job_running' or 'try again in a few minutes' in str(ans.get('error'))) and time.time() < deadline:
                    log('a console job is still finishing, pressing Start again in 30s')
                    time.sleep(30)
                    continue
                break
            print(json.dumps(dict(ans, http_status=code)))
            return 0
        if args.cmd == 'update-now':
            if args.channel == 'dev':
                code, ans = con.call('POST', '/api/update/channel', {'channel': 'dev', 'password': con.password})
                if code != 200:
                    raise DriveError('could not switch to the dev channel (HTTP %s)' % code)
            try:
                code, ans = con.call('POST', '/api/update/apply', {}, timeout=300)
            except DriveError as e:
                if not args.wait:
                    raise
                code, ans = 0, {'note': 'the console restarted before it answered: %s' % e}   # it restarts onto the new code mid-request
            if args.wait:
                _wait_console_back(con, down_for=120)
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
