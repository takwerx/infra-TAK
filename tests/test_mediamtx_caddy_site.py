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
"""MediaMTX stream-domain vhost (v10.2.6).

With Authentik, /hls-proxy/* used to go straight to MediaMTX, which asks every off-box
browser for its password: a logged-in vid_public/vid_private viewer clicking Watch got a
password box and no video. It now goes through the login (forward_auth) to the editor,
whose overlay applies per-stream visibility — streams stay login-only. The admin player's
`Authorization: Basic hlsviewer` is dropped first (the provider intercepts header auth).
Client X-Authentik-* is stripped on every route: the overlay believes those headers from
Caddy's address, and a forged admin group on /watch/ earned an admin session.

Split boxes keep /hls-proxy/* straight to MediaMTX — a console update cannot reach their
remote overlay — and so does a box without Authentik.

app.py cannot be imported in a test, so `_emit_mediamtx_site` is cut out of it and run:
the code under test is the shipped text. The emitted text is pinned whole — this file is
the Caddyfile for every service on the box, and one wrong character takes all of them
down. Static guards cover how generate_caddyfile and the startup migration use it.
"""

import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_WANT = {'MEDIAMTX_OPEN_PATHS', '_emit_mediamtx_site'}


def _load():
    parts = []
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name in _WANT:
            parts.append(ast.get_source_segment(APP, node))
        elif isinstance(node, ast.Assign) and any(getattr(t, 'id', None) in _WANT for t in node.targets):
            parts.append(ast.get_source_segment(APP, node))
    assert len(parts) == 2, 'MEDIAMTX_OPEN_PATHS / _emit_mediamtx_site not found at module level in app.py'
    ns = {'_pub_url': lambda h, s=None: f'https://{h}' if h else ''}
    exec(compile('\n\n'.join(parts), 'app.py:_emit_mediamtx_site', 'exec'), ns)
    return ns['_emit_mediamtx_site']


emit_site = _load()

# What generate_caddyfile's own _emit_ak_header_strip emits (pinned by the static guard below).
AK_HEADERS = ('X-Authentik-Username', 'X-Authentik-Groups', 'X-Authentik-Email',
              'X-Authentik-Name', 'X-Authentik-Uid', 'X-Infratak-Proxy-Auth')
HOST = 'stream.example.com'


def site(mtx_up='127.0.0.1:5080', ak_up='127.0.0.1:9090', hls=None):
    lines = []

    def strip(indent):
        lines.extend(f'{indent}request_header -{h}' for h in AK_HEADERS)

    def rescue(root_url):
        lines.append(f'        #rescue {root_url}')
    emit_site(lines, HOST, mtx_up, ak_up, hls, strip, rescue)
    return '\n'.join(lines)


STRIP8 = '\n'.join(f'        request_header -{h}' for h in AK_HEADERS)


def _open_route(path, up):
    return f'    route {path} {{\n{STRIP8}\n        reverse_proxy {up}\n    }}'


def _expected_ak(up, direct_hls=None):
    return '\n'.join([
        '# MediaMTX Web Console',
        f'{HOST} {{',
        *(direct_hls or []),
        _open_route('/watch/*', up),
        _open_route('/shared/*', up),
        _open_route('/shared-hls/*', up),
        '    route {',
        STRIP8,
        *([] if direct_hls else ['        request_header /hls-proxy/* -Authorization']),
        f'        #rescue https://{HOST}/',
        '        reverse_proxy /outpost.goauthentik.io/* 127.0.0.1:9090',
        '        forward_auth 127.0.0.1:9090 {',
        '            uri /outpost.goauthentik.io/auth/caddy',
        '            copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid',
        '            trusted_proxies private_ranges',
        '        }',
        f'        reverse_proxy {up}',
        '    }',
        '}',
        '',
    ])


def _direct(up, enc):
    proxy = ([f'        reverse_proxy https://{up} {{', '            transport http {',
              f'                tls_server_name {HOST}', '            }',
              '            header_down Location ^ /hls-proxy', '        }'] if enc else
             [f'        reverse_proxy {up} {{', '            header_down Location ^ /hls-proxy', '        }'])
    return ['    handle_path /hls-proxy/* {', *proxy, '    }']


def test_hls_needs_a_login_and_goes_to_the_editor():
    out = site()
    assert out == _expected_ak('127.0.0.1:5080')
    # No route of its own: /hls-proxy/* falls into the forward_auth catch-all, and nothing
    # on this vhost reaches MediaMTX directly.
    assert 'route /hls-proxy' not in out
    assert '8888' not in out and 'handle_path' not in out


def test_the_admin_players_basic_header_is_dropped_before_the_login_check():
    out = site().split('\n')
    assert out.index('        request_header /hls-proxy/* -Authorization') < \
        out.index('        forward_auth 127.0.0.1:9090 {')


@pytest.mark.parametrize('enc', [True, False])
def test_split_box_keeps_hls_straight_to_mediamtx(enc):
    # A console update cannot reach the remote overlay, and an old one drops ?session=.
    # The header strip still applies.
    out = site(mtx_up='10.0.0.5:5080', hls=('10.0.0.5:8888', enc))
    assert out == _expected_ak('10.0.0.5:5080', direct_hls=_direct('10.0.0.5:8888', enc))
    assert '-Authorization' not in out


def test_every_route_strips_before_it_proxies_and_the_open_ones_sit_before_forward_auth():
    out = site().split('\n')
    catch_all = out.index('    route {')
    for path in ('/watch/*', '/shared/*', '/shared-hls/*'):
        i = out.index(f'    route {path} {{')
        assert i < catch_all
        assert out[i + 1:i + 1 + len(AK_HEADERS)] == STRIP8.split('\n')
    fa = out.index('        forward_auth 127.0.0.1:9090 {')
    assert out[catch_all + 1:catch_all + 1 + len(AK_HEADERS)] == STRIP8.split('\n')
    assert catch_all < fa


@pytest.mark.parametrize('enc', [True, False])
def test_without_authentik_the_vhost_is_exactly_what_it_was(enc):
    # No overlay deciding anything -> byte-identical to v10.2.5.
    out = site(ak_up=None, hls=('127.0.0.1:8888', enc))
    assert out == '\n'.join(['# MediaMTX Web Console', f'{HOST} {{', *_direct('127.0.0.1:8888', enc),
                             '    reverse_proxy 127.0.0.1:5080', '}', ''])


# ── how app.py uses it ──────────────────────────────────────────────────────────


def _gen_src():
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name == 'generate_caddyfile':
            return ast.get_source_segment(APP, node)
    raise AssertionError('generate_caddyfile not found')


def test_generate_caddyfile_passes_its_real_strip_and_authentik_only_when_installed():
    src = _gen_src()
    assert "_AK_FWD_HEADERS = ('X-Authentik-Username', 'X-Authentik-Groups', 'X-Authentik-Email',\n" \
           "                       'X-Authentik-Name', 'X-Authentik-Uid', 'X-Infratak-Proxy-Auth')" in src
    call = src[src.index('_emit_mediamtx_site('):]
    call = call[:call.index('\n        _emit_alias_redirect')]
    assert 'ak_up if _mtx_ak else None' in call
    assert '_get_mediamtx_hls_upstream(settings) if _mtx_direct else None' in call
    assert '_emit_ak_header_strip, _emit_outpost_callback_rescue' in call
    assert "_mtx_ak = ak.get('installed')" in src
    # Straight to MediaMTX without Authentik or when the editor is not the local one.
    assert "_mtx_direct = not _mtx_ak or mtx_up != '127.0.0.1:5080'" in src


def test_tvr_vhost_is_unchanged():
    # TAK Video Restreamer has its own Flask login and its own /hls-proxy/ — out of scope.
    src = _gen_src()
    assert ('        lines.append(f"    handle_path /hls-proxy/* {{")\n'
            '        lines.append(f"        reverse_proxy 127.0.0.1:8888 {{")\n'
            '        lines.append(f"            header_down Location ^ /hls-proxy")') in src


def test_startup_migration_runs_after_the_overlay_that_can_serve_it():
    # Only the shipped overlay forwards MediaMTX's ?session= query; pointing Caddy at an
    # old one would stop every stream after its first playlist.
    i = APP.index('def _startup_migrations():')
    body = APP[i:]
    assert body.index('_startup_converge_mediamtx_overlay()') < body.index("'caddy_mtx_hls_overlay_v1'")
    mig = body[body.index("not s.get('caddy_mtx_hls_overlay_v1')"):]
    mig = mig[:mig.index("s['caddy_mtx_hls_overlay_v1'] = True")]
    assert "'request_header -X-Authentik-Groups' in _mtx_blk" in mig and '_caddy_reload()' in mig
    # The LIVE file, not generate's return value: a rejected Caddyfile is restored to the old one.
    assert '_cf = _read_priv(CADDYFILE_PATH)' in mig
