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
"""GH #206 — Caddy on ports other than 443/80.

A host where something else already owns 443 could not run Caddy at all. The operator can
now move Caddy's HTTPS and HTTP listeners; Caddy's global `https_port`/`http_port` move
every site, and every public URL the console builds gains `:PORT`.

The promise to every other box: with the setting unset nothing changes — no `:443` suffix,
no new Caddyfile line. Those helpers are cut out of app.py and run (app.py cannot be
imported in a test), so the code under test is the shipped text.
"""

import ast
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_WANT = {'CADDY_HTTPS_PORT_DEFAULT', 'CADDY_HTTP_PORT_DEFAULT', 'PORT_EXPOSURE_POLICY',
         'REMOTE_ASSIST_DEVICE_PORT', 'ATLAS_DEVICE_PORT',
         '_caddy_reserved_ports', '_caddy_port_value', '_caddy_https_port', '_caddy_http_port',
         '_caddy_ports_custom', '_pub_hostport', '_pub_http_hostport', '_pub_url',
         '_validate_caddy_ports', '_caddy_port_option_lines', '_caddy_global_options_lines',
         '_policy_port'}


def _load(settings):
    parts = []
    for n in ast.parse(APP).body:
        name = n.name if isinstance(n, ast.FunctionDef) else None
        if isinstance(n, ast.Assign):
            name = next((t.id for t in n.targets if isinstance(t, ast.Name)), None)
        if name in _WANT:
            parts.append(ast.get_source_segment(APP, n))
    assert len(parts) == len(_WANT), 'a function under test was renamed or removed'
    ns = {'load_settings': lambda: settings, 'CADDY_GRACE_PERIOD': '10s',
          '_caddy_acme_inner_lines': lambda cfg=None: [],
          '_caddy_read_body_idle_lines': lambda grpc: []}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


def test_unset_ports_change_nothing():
    ns = _load({'fqdn': 'example.com'})
    assert ns['_pub_hostport']('tak.example.com') == 'tak.example.com'
    assert ns['_pub_http_hostport']('atlas.example.com') == 'atlas.example.com'
    assert ns['_pub_url']('tak.example.com') == 'https://tak.example.com'
    assert ns['_caddy_port_option_lines']() == []
    assert not ns['_caddy_ports_custom']()
    # The global block every box already has, byte for byte.
    assert ns['_caddy_global_options_lines']() == ['{', '    grace_period 10s', '}', '']


def test_moved_ports_reach_urls_and_the_global_block():
    ns = _load({'fqdn': 'example.com', 'caddy_https_port': 4443, 'caddy_http_port': 8081})
    assert ns['_pub_hostport']('tak.example.com') == 'tak.example.com:4443'
    assert ns['_pub_http_hostport']('atlas.example.com') == 'atlas.example.com:8081'
    assert ns['_pub_url']('tak.example.com') == 'https://tak.example.com:4443'
    assert ns['_caddy_global_options_lines']() == [
        '{', '    grace_period 10s', '    https_port 4443', '    auto_https disable_redirects',
        '    http_port 8081', '}', '']
    assert ns['_caddy_ports_custom']()


def test_only_the_moved_port_is_emitted():
    ns = _load({'caddy_https_port': 4443})
    assert ns['_caddy_port_option_lines']() == ['    https_port 4443', '    auto_https disable_redirects']
    assert ns['_pub_http_hostport']('a.example.com') == 'a.example.com'


def test_empty_host_stays_empty_so_callers_keep_their_fallbacks():
    ns = _load({'caddy_https_port': 4443})
    assert ns['_pub_hostport']('') == ''
    assert ns['_pub_url']('') == ''


def test_a_garbage_stored_value_falls_back_to_the_default():
    ns = _load({'caddy_https_port': 'nope', 'caddy_http_port': 99999})
    assert ns['_caddy_https_port']() == 443
    assert ns['_caddy_http_port']() == 80


@pytest.mark.parametrize('hp,cp,why', [
    (8443, 80, 'TAK'),            # TAK Server's own HTTPS
    (443, 8089, 'TAK'),           # TAK streaming
    (5001, 80, 'console'),        # the console
    (2019, 80, 'admin API'),      # Caddy's own admin endpoint
    (4443, 4443, 'different'),
    (0, 80, 'range'),
    (70000, 80, 'range'),
    ('abc', 80, 'whole numbers'),
])
def test_refused_ports(hp, cp, why):
    ns = _load({'console_port': 5001})
    ok, err, _ = ns['_validate_caddy_ports'](hp, cp)
    assert not ok and why in err


@pytest.mark.parametrize('hp,cp', [(443, 80), (4443, 8081), ('4443', '8081')])
def test_accepted_ports(hp, cp):
    ns = _load({'console_port': 5001})
    ok, err, ports = ns['_validate_caddy_ports'](hp, cp)
    assert ok and not err and ports == (int(hp), int(cp))


def test_preflight_and_exposure_follow_the_setting():
    ns = _load({})
    rows = {r['label']: r for r in ns['PORT_EXPOSURE_POLICY']}
    s = {'caddy_https_port': 4443, 'caddy_http_port': 8081}
    assert ns['_policy_port'](rows['Caddy HTTPS'], s, 5001) == 4443
    assert ns['_policy_port'](rows['Caddy HTTP'], s, 5001) == 8081
    assert ns['_policy_port'](rows['Caddy HTTPS'], {}, 5001) == 443
    assert ns['_policy_port'](rows['infra-TAK Console'], s, 5001) == 5001
    assert ns['_policy_port'](rows['TAK Server (mTLS)'], s, 5001) == 8089


def _fn(name):
    node = next(n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(APP, node)


def test_selinux_labels_the_moved_ports():
    # The globals name no site address, so the site-address scan alone would miss them.
    src = _fn('_selinux_sync_caddy_ports')
    pat = re.search(r"finditer\(r'(\(\?m\)\^\\s\+https\?_port[^']*)'", src)
    assert pat, 'the https_port/http_port scan is gone'
    cad = '{\n    grace_period 10s\n    https_port 4443\n    http_port 8081\n}\n'
    assert sorted(int(m.group(1)) for m in re.finditer(pat.group(1), cad)) == [4443, 8081]


def test_firewall_and_generated_links_use_the_setting():
    assert '_fw_allow(_caddy_https_port(_s)' in _fn('_startup_ensure_console_ports')
    gen = _fn('generate_caddyfile')
    assert 'redir https://{canonical}' not in gen
    assert 'redir {_pub_url(canonical, settings)}{{uri}}' in gen
    assert '_emit_outpost_callback_rescue(f"https://' not in gen
    assert "_pub_hostport('{host}', settings)" in gen          # ATLAS plain-HTTP redirect
    assert 'X-Forwarded-Port 443"' not in gen                  # Federation Hub
    assert 'settings=settings)' in gen                         # global block sees the ports
    # Caddy's own redirect omits a moved https_port; ours names it.
    assert 'redir https://{{host}}:{_hp}{{uri}} permanent' in gen


def test_authentik_canonical_external_hosts_carry_the_port():
    # The startup migration would otherwise strip the port off every proxy provider on
    # every console start, and SSO would bounce users back to 443.
    src = _fn('_ensure_authentik_proxy_external_hosts_canonical')
    assert src.count('_pub_hostport(_get_service_domain(') == 5
