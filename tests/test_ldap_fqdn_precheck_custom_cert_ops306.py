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
"""A custom (bring-your-own) certificate no longer keeps the LDAP outpost on internal routing
(ops #306).

On Authentik 2026.x the outpost on `http://authentik-server-1:9000` fails every bind with
"exceeded stage recursion depth", so the console moves it to https://<fqdn> through Caddy. That
move was gated on Caddy's certificate verifying against this box's trust store, which a
Cloudflare Origin cert (or any private CA) never does — so a custom-cert box stayed on internal
routing forever: webadmin and the LDAP service account could not log in, TAK Server's retries
became an LDAP flow herd, and Guard Dog's restarts could not drain it. The outpost runs with
AUTHENTIK_INSECURE=true and does not verify the chain, so an untrusted chain is waived — only on
a custom-cert box, only for a trust-chain failure, only when the outpost really is insecure-mode,
and the TLS handshake with a certificate for the name must still complete.

app.py cannot be imported in a test, so the functions are cut out of it and run against a real
local TLS server: the code under test is the shipped text.
"""

import ast
import hashlib
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import threading

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
FQDN = 'tak.example.org'

pytestmark = pytest.mark.skipif(shutil.which('openssl') is None, reason='openssl CLI needed')


def _segment(name):
    for node in TREE.body:
        if (isinstance(node, ast.FunctionDef) and node.name == name) or \
                (isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets)):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _sh(*cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def pki(tmp_path):
    """A private CA and a leaf for FQDN signed by it (what a Cloudflare Origin cert is to this
    box: a good certificate whose issuer the box does not trust), plus a bare self-signed leaf."""
    d = tmp_path / 'pki'
    d.mkdir()
    _sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem',
        '-days', '2', '-subj', '/CN=Test Origin CA', cwd=d)
    _sh('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr',
        '-subj', f'/CN={FQDN}', cwd=d)
    (d / 'ext.cnf').write_text(f'subjectAltName=DNS:{FQDN}\n')
    _sh('openssl', 'x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
        '-out', 'leaf.pem', '-days', '2', '-extfile', 'ext.cnf', cwd=d)
    _sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'self.key', '-out', 'self.pem',
        '-days', '2', '-subj', f'/CN={FQDN}', '-addext', f'subjectAltName=DNS:{FQDN}', cwd=d)
    return d


def _serve(cert, key, names):
    """Caddy stand-in on 127.0.0.1: presents (cert, key) for the SNI names in `names`, and fails
    the handshake (like Caddy with no certificate) for any other name."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.sni_callback = lambda sock, name, c: None if name in names else ssl.ALERT_DESCRIPTION_INTERNAL_ERROR
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(8)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                ctx.wrap_socket(conn, server_side=True).close()
            except (ssl.SSLError, OSError):
                conn.close()
    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]


@pytest.fixture
def check(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    servers = []

    def _check(cert, key, names=(FQDN,), ssl_mode='custom', insecure=True, compose=True):
        srv, port = _serve(cert, key, set(names))
        servers.append(srv)
        ak = tmp_path / 'authentik'
        ak.mkdir(exist_ok=True)
        if compose:
            (ak / 'docker-compose.yml').write_text(
                'services:\n  ldap:\n    environment:\n'
                '      AUTHENTIK_HOST: http://authentik-server-1:9000\n'
                f'      AUTHENTIK_INSECURE: "{"true" if insecure else "false"}"\n')
        ns = {'os': __import__('os'), 're': re, 'ssl': ssl, 'socket': socket, 'hashlib': hashlib,
              '_dns_resolve_ipv4': lambda h: (['203.0.113.7'], None),
              '_caddy_https_port': lambda s=None: port,
              'load_settings': lambda: {'ssl_mode': ssl_mode}}
        for name in ('_LDAP_UNTRUSTED_CHAIN_CODES', '_ldap_outpost_skips_tls_verify', '_ldap_outpost_fqdn_precheck'):
            exec(compile(_segment(name), 'app.py', 'exec'), ns)
        return ns['_ldap_outpost_fqdn_precheck'](FQDN)
    yield _check
    for s in servers:
        s.close()


def test_custom_cert_from_a_private_ca_is_accepted(check, pki):
    ok, problem, sha = check(pki / 'leaf.pem', pki / 'leaf.key')
    assert ok and problem == '' and len(sha) == 64


def test_cert_fingerprint_is_the_served_leaf(check, pki):
    ok, _, sha = check(pki / 'leaf.pem', pki / 'leaf.key')
    der = ssl.PEM_cert_to_DER_cert((pki / 'leaf.pem').read_text())
    assert ok and sha == hashlib.sha256(der).hexdigest()


def test_custom_self_signed_cert_is_accepted(check, pki):
    ok, problem, _ = check(pki / 'self.pem', pki / 'self.key')
    assert ok, problem


def test_untrusted_cert_on_a_lets_encrypt_box_is_still_refused(check, pki):
    ok, problem, _ = check(pki / 'leaf.pem', pki / 'leaf.key', ssl_mode='fqdn')
    assert not ok and 'is not valid' in problem


def test_untrusted_cert_is_refused_when_the_outpost_verifies_certificates(check, pki):
    ok, problem, _ = check(pki / 'leaf.pem', pki / 'leaf.key', insecure=False)
    assert not ok and 'is not valid' in problem


def test_untrusted_cert_is_refused_without_a_compose_file(check, pki):
    ok, problem, _ = check(pki / 'leaf.pem', pki / 'leaf.key', compose=False)
    assert not ok and 'is not valid' in problem


def test_a_name_caddy_has_no_certificate_for_is_still_refused(check, pki):
    ok, problem, _ = check(pki / 'leaf.pem', pki / 'leaf.key', names=('other.example.org',))
    assert not ok and 'no working certificate' in problem
