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
"""Module deploys say "Caddy config updated" only when it is true (ops #580).

The TAK Portal deploy reloaded Caddy, ignored the result, printed "Caddy config updated for
TAK Portal" and waited a fixed 2 minutes. In the 10.3.9 real-name fresh install the name did
not answer at the check: Caddy had no certificate for it yet. The deploy log had already said
"updated".

`_caddy_apply_and_verify` reloads Caddy, checks the Caddyfile has a site for the name, and
waits (up to 3 minutes) until Caddy serves a valid certificate for it. Only then does it say
"updated". app.py cannot be imported in a test, so the helpers are cut out of it and run
against stubs: the code under test is the shipped text.
"""

import ast
import pathlib
import shutil
import socket
import ssl
import subprocess
import threading
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _ns(**extra):
    ns = {'ssl': ssl, 'socket': socket, 'time': time, 'CADDYFILE_PATH': '/etc/caddy/Caddyfile'}
    ns.update(extra)
    exec(compile('\n\n'.join(_segment(n) for n in (
        'CADDY_CERT_WAIT_S', 'CADDY_CERT_POLL_S', '_caddy_serves_cert',
        '_caddy_wait_for_cert', '_caddy_apply_and_verify')), 'app.py:ops580', 'exec'), ns)
    return ns


CADDYFILE = '# infra-TAK\n\n# TAK Portal\ntakportal.example.org {\n    reverse_proxy 127.0.0.1:3000\n}\n'


def _run(reload=(True, ''), caddyfile=CADDYFILE, cert=(True, '', 0), hosts=('takportal.example.org',),
         wait_for_cert=True):
    ns = _ns()
    out = []
    waited = []

    def fake_wait(h):
        waited.append(h)
        return cert

    res = ns['_caddy_apply_and_verify'](
        out.append, 'TAK Portal', hosts, {}, wait_for_cert=wait_for_cert,
        reload=lambda plog=None: reload, read_caddyfile=lambda: caddyfile, wait=fake_wait)
    return res, '\n'.join(out), waited


# ── the deploy log tells the truth ───────────────────────────────────────────

def test_updated_is_printed_when_caddy_loaded_and_cert_is_served():
    res, log, waited = _run()
    assert res == 'ok'
    assert 'Caddy config updated for TAK Portal' in log
    assert waited == ['takportal.example.org']


def test_no_certificate_after_the_wait_is_not_called_updated():
    # The ops #580 case: reload fine, site present, Caddy has no certificate for the name yet.
    res, log, _ = _run(cert=(False, 'tlsv1 alert internal error', 180))
    assert res == 'no-cert'
    assert 'Caddy config updated' not in log
    assert 'No valid certificate for takportal.example.org after 180s' in log
    assert 'tlsv1 alert internal error' in log


def test_failed_reload_is_not_called_updated_and_skips_the_wait():
    res, log, waited = _run(reload=(False, 'unrecognized directive'))
    assert res == 'reload-failed'
    assert 'Caddy config updated' not in log
    assert 'unrecognized directive' in log
    assert waited == []


def test_missing_site_is_named_and_the_wait_is_skipped():
    res, log, waited = _run(caddyfile='# infra-TAK\n\ninfratak.example.org {\n}\n')
    assert res == 'no-vhost'
    assert 'Caddy config updated' not in log
    assert 'no site for takportal.example.org' in log
    assert waited == []


def test_suffix_hostname_does_not_count_as_the_site():
    # `tak.example.org` is a suffix of `infratak.example.org`.
    res, _log, _ = _run(caddyfile='infratak.example.org {\n}\n', hosts=('tak.example.org',))
    assert res == 'no-vhost'


def test_no_hostnames_checks_only_the_reload():
    res, log, waited = _run(hosts=())
    assert res == 'ok' and waited == []
    assert 'Caddy config updated for TAK Portal' in log
    res, log, _ = _run(reload=(False, 'rc=1'), hosts=())
    assert res == 'reload-failed' and 'Caddy config updated' not in log


def test_reload_that_raises_does_not_fail_the_deploy():
    ns = _ns()
    out = []

    def boom(plog=None):
        raise RuntimeError('broker down')

    assert ns['_caddy_apply_and_verify'](out.append, 'X', ('a.example.org',), {}, reload=boom) == 'reload-failed'
    assert 'broker down' in '\n'.join(out)


# ── the wait ─────────────────────────────────────────────────────────────────

class _Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


def test_wait_returns_as_soon_as_the_certificate_appears():
    ns = _ns()
    clock = _Clock()
    calls = []

    def check(h):
        calls.append(h)
        return (len(calls) >= 4), 'not yet'

    ok, detail, secs = ns['_caddy_wait_for_cert']('a.example.org', {}, max_wait=180, poll=5,
                                                   check=check, sleep=clock.sleep, clock=clock.now)
    assert ok and detail == '' and secs == 15 and len(calls) == 4


def test_wait_gives_up_after_max_wait_and_returns_the_last_error():
    ns = _ns()
    clock = _Clock()
    calls = []

    def check(h):
        calls.append(h)
        return False, 'internal error'

    ok, detail, secs = ns['_caddy_wait_for_cert']('a.example.org', {}, max_wait=180, poll=5,
                                                   check=check, sleep=clock.sleep, clock=clock.now)
    assert not ok and detail == 'internal error'
    assert 175 <= secs <= 180 and 30 <= len(calls) <= 37


# ── the TLS probe, against a real local TLS listener ─────────────────────────

OPENSSL = shutil.which('openssl')


@pytest.fixture
def tls_server(tmp_path):
    if not OPENSSL:
        pytest.skip('openssl not installed')
    key, crt = tmp_path / 'k.pem', tmp_path / 'c.pem'
    subprocess.run([OPENSSL, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                    '-out', str(crt), '-days', '1', '-subj', '/CN=a.example.org',
                    '-addext', 'subjectAltName=DNS:a.example.org'],
                   check=True, capture_output=True)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(crt), str(key))
    lsock = socket.socket()
    lsock.bind(('127.0.0.1', 0))
    lsock.listen(5)
    stop = threading.Event()

    def serve():
        lsock.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = lsock.accept()
            except OSError:
                continue
            try:
                with sctx.wrap_socket(c, server_side=True):
                    pass
            except Exception:
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield lsock.getsockname()[1]
    stop.set()
    t.join(2)
    lsock.close()


def _probe(port, settings):
    ns = _ns(_caddy_https_port=lambda s=None: port)
    return ns['_caddy_serves_cert']('a.example.org', settings, timeout=3)


def test_probe_rejects_a_certificate_that_does_not_verify(tls_server):
    # A self-signed certificate is not "a valid certificate for the name" on a Let's Encrypt box.
    ok, detail = _probe(tls_server, {'ssl_mode': 'fqdn'})
    assert not ok and detail


def test_probe_accepts_any_certificate_in_custom_mode(tls_server):
    assert _probe(tls_server, {'ssl_mode': 'custom'}) == (True, '')


def test_probe_fails_when_nothing_listens():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    ok, detail = _probe(port, {})
    assert not ok and detail


# ── no deploy prints "updated" on its own ────────────────────────────────────

def _string_pieces(call):
    for n in ast.walk(call):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            yield n.value


def test_only_the_helper_prints_caddy_config_updated():
    # The old deploys printed this line unconditionally after `_caddy_reload()`. It is now
    # printed in one place, after the checks.
    owners = set()
    for fn in ast.walk(TREE):
        if not isinstance(fn, ast.FunctionDef):
            continue
        for call in ast.walk(fn):
            if isinstance(call, ast.Call) and any('Caddy config updated' in s for s in _string_pieces(call)):
                owners.add(fn.name)
    assert owners == {'_caddy_apply_and_verify'}, owners


def test_takportal_deploy_checks_caddy_before_it_says_so():
    fn = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == 'run_takportal_deploy')
    src = ast.get_source_segment(APP, fn)
    assert "_caddy_apply_and_verify(plog, 'TAK Portal'" in src
    assert '_caddy_reload()' not in src
