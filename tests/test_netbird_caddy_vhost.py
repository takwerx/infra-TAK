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
"""NetBird vhost routes for the combined netbird-server (ops #150).

Field: a peer enrolled through Caddy registered (got an IP) but never connected. The vhost
sent signal gRPC to 127.0.0.1:10000, where nothing listens (the combined server logs
"Signal server registered on port :443"), and the relay WebSocket over h2c, which Caddy
answers with 502. Upstream (https://docs.netbird.io/selfhosted/reverse-proxy): gRPC over
h2c to the server's one port; /relay*, /ws-proxy/* over plain HTTP.

generate_caddyfile needs the whole box to run, so these are static guards on its text and
on the startup migration that rewrites existing boxes.
"""

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _nb_block():
    src = next(ast.get_source_segment(APP, n) for n in ast.parse(APP).body
               if isinstance(n, ast.FunctionDef) and n.name == 'generate_caddyfile')
    i = src.index('lines.append(f"# NetBird VPN")')
    return src[i:src.index("_emit_alias_redirect(_get_service_alias(settings, 'netbird')", i)]


def _handle(block, matcher):
    i = block.index(f'handle @{matcher} {{{{')
    return block[i:block.index('lines.append(f"    }}")', i)]


def test_signal_goes_to_the_combined_server_over_h2c():
    blk = _nb_block()
    assert '127.0.0.1:10000' not in blk
    assert 'reverse_proxy h2c://127.0.0.1:33073' in _handle(blk, 'netbird_signal')


def test_relay_and_ws_proxy_are_plain_http():
    blk = _nb_block()
    assert 'path /relay /relay/* /ws-proxy/*' in blk
    ws = _handle(blk, 'netbird_ws')
    assert 'reverse_proxy 127.0.0.1:33073' in ws and 'h2c' not in ws
    # and the h2c IdP matcher no longer swallows /relay
    idp = blk[blk.index('@netbird_idp {{'):blk.index('handle @netbird_idp')]
    assert '/relay' not in idp


def test_ws_matcher_is_declared_before_the_catch_all():
    blk = _nb_block()
    assert blk.index('handle @netbird_ws') < blk.index('lines.append(f"    handle {{")')


def test_startup_migration_rewrites_old_vhosts_and_checks_the_live_file():
    body = APP[APP.index('def _startup_migrations():'):]
    mig = body[body.index('# ops #150: the NetBird vhost'):]
    mig = mig[:mig.index('NetBird vhost regenerate error')]
    assert "'reverse_proxy h2c://127.0.0.1:10000' in _cf" in mig
    assert 'generate_caddyfile(s)' in mig and '_caddy_reload()' in mig
    # verified against the LIVE file: a rejected Caddyfile is restored to the old one
    assert "not in (_read_priv(CADDYFILE_PATH) or '')" in mig
