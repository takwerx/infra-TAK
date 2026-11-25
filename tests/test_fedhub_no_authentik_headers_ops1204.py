# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Michael Leckliter
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
"""Federation Hub behind Authentik: no identity header goes to the hub (ops #1204).

Field report (atakendusers Slack, Nov 24): `HTTP ERROR 431 Request Header Fields Too Large` when
Federation Hub sits behind Authentik through infra-TAK. Reproduced on a fresh box (two TAK Servers
and a hub, Nov 24): Caddy's `forward_auth ... copy_headers X-Authentik-Groups` sent the person's
whole group list to the hub (10,638 bytes for an admin in 200 groups; the whole request was 12,027
bytes), and the hub's web server (Jetty) answers 431 above 8,192 bytes. With 60 groups the page
opened; with 200 it gave 431. Federation Hub reads none of the X-Authentik-* headers: it signs its
own users in. So the hub's Caddy block sends it none, and takes out any a client sends.

app.py cannot be imported in a test, so the helper is cut out of it and run: the code under test
is the shipped text.
"""
import ast
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
JETTY_HEADER_LIMIT = 8192      # bytes of request headers Federation Hub's web server accepts (measured: 7,900 ok, 8,100 gives 431)


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _fedhub_vhost_source():
    """The text of generate_caddyfile that writes the Federation Hub site."""
    start = APP.index('# TAK Federation Hub — Caddy terminates public TLS')
    end = APP.index("_emit_alias_redirect(_get_service_alias(settings, 'fedhub'), fh_host)", start)
    return APP[start:end]


def _gate():
    # ops #1081: the hub gate comes from the one writer of every forward_auth block.
    ns = {'re': re}
    for name in ('_CADDY_FORWARD_AUTH_URI', '_CADDY_FORWARD_AUTH_PIN', '_CADDY_APP_HEADER',
                 '_CADDY_APP_LOCK_MATCHER', '_CADDY_APP_LOCK_TEXT', '_CADDY_APP_SLUG_RE',
                 '_caddy_forward_auth_lines', '_fedhub_forward_auth_lines'):
        exec(compile(_segment(name), 'app.py', 'exec'), ns)
    return ns['_fedhub_forward_auth_lines']('127.0.0.1:9090', '    ')


def test_the_hub_gate_asks_authentik_and_copies_nothing():
    gate = '\n'.join(_gate())
    assert 'forward_auth 127.0.0.1:9090 {' in gate
    assert 'uri /outpost.goauthentik.io/auth/caddy' in gate
    # ops #1081: no trust line; Caddy sets the two forwarded headers itself.
    assert 'trusted_proxies' not in gate
    assert 'header_up X-Forwarded-Host {http.request.hostport}' in gate
    assert 'header_up X-Forwarded-Proto {http.request.scheme}' in gate
    # ops #1108: no application compare in the hub's `handle` block (Caddy sorts its lines).
    assert '@ak_other_app' not in gate
    assert 'copy_headers' not in gate          # the whole bug: the group list went to the hub in X-Authentik-Groups


def test_the_hub_site_has_no_copy_headers_line():
    block = _fedhub_vhost_source()
    assert 'copy_headers' not in block
    assert 'X-Authentik-Groups' not in block


def test_the_hub_site_uses_the_gate_and_strips_client_identity_headers():
    block = _fedhub_vhost_source()
    assert '_fedhub_forward_auth_lines(' in block
    # a client cannot hand the hub an identity header of its own, and the strip comes first in the route
    assert '_CADDY_STRIP_AUTHENTIK_HEADERS' in block
    assert block.index('_CADDY_STRIP_AUTHENTIK_HEADERS') < block.index('@fh_pub')
    assert _segment('_CADDY_STRIP_AUTHENTIK_HEADERS').strip().endswith("'request_header -X-Authentik-*'")


def test_the_login_still_goes_through_authentik():
    """Removing the headers must not remove the gate: the hub site still sends every page request to
    Authentik, and the outpost's own paths stay reachable for the callback."""
    block = _fedhub_vhost_source()
    assert 'reverse_proxy /outpost.goauthentik.io/*' in block
    assert block.index('_fedhub_forward_auth_lines(') > block.index('reverse_proxy /outpost.goauthentik.io/*')
    assert 'handle @fh_pub' in block       # static files stay outside the gate (Authentik would answer them with HTML)


def test_why_the_old_line_broke_the_hub():
    """The size arithmetic from the field report, so nobody 'fixes' this with a longer list of headers:
    a TAK Portal admin is in one Authentik group per agency or mission, and the groups header grows
    with each one, past what Federation Hub's web server accepts, however the other headers are cut."""
    names = ['TAK-Agency-Group-%03d-County-Fire-and-Rescue-Dispatch' % i for i in range(1, 201)]
    header = 'X-Authentik-Groups: ' + '|'.join(names) + '\r\n'
    assert len(header) > JETTY_HEADER_LIMIT
