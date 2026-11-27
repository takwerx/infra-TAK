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
"""ops #1081: Caddy alone sets X-Forwarded-Host and -Proto for the Authentik sign-in check.

The Authentik outpost reads X-Forwarded-Host to pick the application it checks. Every
forward_auth block that infra-TAK writes therefore has no `trusted_proxies` line and sets
both headers from the request Caddy itself received. One helper writes all of them.

app.py cannot be imported in a test, so the helpers are cut out of it and run: the code
under test is the shipped text. The helpers that exist on older trees are loaded when the
new ones are missing, so the tests fail there on what the old code writes.
"""

import ast
import json
import pathlib
import re
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_NAMES = ('_caddy_forward_auth_lines', '_caddyfile_forward_auth_pinned', '_takportal_vhost_lines',
          '_emit_mediamtx_site')
_CONSTS = ('_CADDY_AK_COPY_HEADERS', '_CADDY_FORWARD_AUTH_URI', '_CADDY_FORWARD_AUTH_PIN',
           '_TAKPORTAL_PUBLIC_PATHS', '_CADDY_STRIP_AUTHENTIK_HEADERS', '_TAKPORTAL_AK_COPY_HEADERS',
           'CADDYFILE_USER_BLOCKS_MARKER', 'MEDIAMTX_OPEN_PATHS', '_MEDIAMTX_VHOST_MARKER',
           '_CADDY_APP_HEADER', '_CADDY_APP_LOCK_MATCHER', '_CADDY_APP_LOCK_TEXT', '_CADDY_APP_SLUG_RE',
           '_MEDIAMTX_AK_COPY_HEADERS', '_MEDIAMTX_IDENTITY_MARKER')
AK = '127.0.0.1:9090'
PIN_HOST = 'header_up X-Forwarded-Host {http.request.hostport}'
PIN_PROTO = 'header_up X-Forwarded-Proto {http.request.scheme}'
COPY5 = 'X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid'

# Lines of source that write a Caddyfile directive: the directive is the first word of a string.
_EMITS_FORWARD_AUTH = re.compile(r'''["'][ \t]*forward_auth [^"'\n]*\{\{?["']''')
_EMITS_TRUST = re.compile(r'''["'][ \t]*trusted_proxies[ \t]''')
# A forward_auth block in Caddyfile text (it has no nested block).
_BLOCK = re.compile(r'(?ms)^[ \t]*forward_auth [^\n]*\{\n(.*?)^[ \t]*\}')


def _ns():
    ns = {'re': re, '_pub_url': lambda h, s=None: f'https://{h}' if h else ''}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _NAMES:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') in _CONSTS:
            exec(ast.get_source_segment(APP, node), ns)
    return ns


def _need(ns, name):
    assert name in ns, f'{name} is missing from app.py (ops #1081)'
    return ns[name]


def _func_src(name):
    found = [ast.get_source_segment(APP, n) for n in TREE.body
             if isinstance(n, ast.FunctionDef) and n.name == name]
    assert found, f'{name} is missing from app.py (ops #1081)'
    return found[0]


def _assert_blocks_are_pinned(text, want_blocks):
    blocks = _BLOCK.findall(text)
    assert len(blocks) == want_blocks, text
    for b in blocks:
        assert 'trusted_proxies' not in b, b
        assert PIN_HOST in b and PIN_PROTO in b, b
        assert 'uri /outpost.goauthentik.io/auth/caddy' in b


# --- what the shipped code writes -------------------------------------------------------------

def test_takportal_sign_in_check_takes_no_forwarded_header_from_a_client():
    ns = _ns()
    text = '\n'.join(ns['_takportal_vhost_lines']('127.0.0.1:3000', AK, True, []))
    _assert_blocks_are_pinned(text, 1)
    structure = re.sub(r'\{http\.request\.[a-z]+\}', '', text)       # placeholders are not blocks
    assert structure.count('{') == structure.count('}')
    # still the full header set TAK Portal reads, and still before the proxy to TAK Portal
    assert 'copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Entitlements' in text
    assert text.index('forward_auth') < text.rindex('reverse_proxy 127.0.0.1:3000')


def test_stream_site_sign_in_check_takes_no_forwarded_header_from_a_client():
    ns = _ns()
    lines = []
    ns['_emit_mediamtx_site'](lines, 'stream.example.com', '127.0.0.1:5080', AK, None,
                              lambda indent: None, lambda root: None)
    text = '\n'.join(lines)
    _assert_blocks_are_pinned(text, 1)
    # ops #1208: the stream site gets the name and the signed token only
    assert 'copy_headers X-Authentik-Username X-Authentik-Jwt\n' in text


def test_the_writer_emits_the_exact_block():
    ns = _ns()
    fa = _need(ns, '_caddy_forward_auth_lines')
    assert fa(AK, '        ') == [
        '        forward_auth 127.0.0.1:9090 {',
        '            uri /outpost.goauthentik.io/auth/caddy',
        '            ' + PIN_HOST,
        '            ' + PIN_PROTO,
        '        }']
    assert fa('10.0.0.5:9090', '    ', COPY5, matcher='@needs_sso') == [
        '    forward_auth @needs_sso 10.0.0.5:9090 {',
        '        uri /outpost.goauthentik.io/auth/caddy',
        '        copy_headers ' + COPY5,
        '        ' + PIN_HOST,
        '        ' + PIN_PROTO,
        '    }']
    assert ns['_CADDY_AK_COPY_HEADERS'] == COPY5


# --- no other writer, in any file that runs on a box --------------------------------------------

def test_no_source_line_writes_trusted_proxies_into_a_caddyfile():
    hits = []
    for path in [REPO / 'app.py', *sorted((REPO / 'modules').glob('*.py'))]:
        for n, line in enumerate(path.read_text(encoding='utf-8').split('\n'), 1):
            if _EMITS_TRUST.search(line):
                hits.append(f'{path.name}:{n}: {line.strip()}')
    assert not hits, 'a Caddy trusted_proxies line is written again:\n' + '\n'.join(hits)


def test_one_writer_for_every_forward_auth_block():
    hits = []
    for path in [REPO / 'app.py', *sorted((REPO / 'modules').glob('*.py'))]:
        for n, line in enumerate(path.read_text(encoding='utf-8').split('\n'), 1):
            if _EMITS_FORWARD_AUTH.search(line):
                hits.append(f'{path.name}:{n}: {line.strip()}')
    assert len(hits) == 1 and hits[0].startswith('app.py:'), \
        'forward_auth is written outside _caddy_forward_auth_lines:\n' + '\n'.join(hits)
    assert _EMITS_FORWARD_AUTH.search(_func_src('_caddy_forward_auth_lines'))


def test_generate_caddyfile_uses_the_writer_for_all_five_of_its_sites():
    src = _func_src('generate_caddyfile')
    assert 'trusted_proxies' not in src
    calls = re.findall(r'_caddy_forward_auth_lines\(([^\n]*)', src)
    assert len(calls) == 5, calls                    # console, Node-RED, WebODM, MeshRelay, ATLAS
    assert all(c.startswith('ak_up, ') for c in calls)
    # Federation Hub (ops #1204: no header is copied to it) calls the writer in its own helper
    assert src.count("_fedhub_forward_auth_lines(ak_up, '            ')") == 1
    assert 'return _caddy_forward_auth_lines(ak_up, indent)\n' in _func_src('_fedhub_forward_auth_lines') + '\n'
    # the console check keeps its matcher: /api/* never goes through the sign-in redirect
    assert "matcher='@needs_sso'" in src
    assert src.index("matcher='@needs_sso'") < src.index('lines.append(f"# Node-RED flow editor")')


# --- existing boxes ---------------------------------------------------------------------------

def _old_block(indent, copy=''):
    return '\n'.join([f'{indent}forward_auth 127.0.0.1:9090 {{',
                      f'{indent}    uri /outpost.goauthentik.io/auth/caddy',
                      *([f'{indent}    copy_headers {copy}'] if copy else []),
                      f'{indent}    trusted_proxies private_ranges',
                      f'{indent}}}'])


def _site(body):
    return f'nodered.example.com {{\n    route {{\n{body}\n        reverse_proxy 127.0.0.1:1880\n    }}\n}}\n'


def test_old_caddyfiles_are_seen_and_new_ones_are_left_alone():
    ns = _ns()
    pinned = _need(ns, '_caddyfile_forward_auth_pinned')
    fa = ns['_caddy_forward_auth_lines']
    marker = ns['CADDYFILE_USER_BLOCKS_MARKER']
    new = _site('\n'.join(fa(AK, '        ')))
    assert pinned(new)
    assert pinned(new + _site('\n'.join(fa(AK, '        ', COPY5, matcher='@needs_sso'))))
    assert pinned('')                                        # no Caddyfile text
    assert pinned('example.com {\n    reverse_proxy 127.0.0.1:5001\n}\n')   # no Authentik
    # every old shape: with and without copy_headers, both indents
    assert not pinned(_site(_old_block('        ')))
    assert not pinned(_site(_old_block('        ', COPY5)))
    assert not pinned(_site(_old_block('            ', COPY5)))
    # one old block among new ones
    assert not pinned(new + _site(_old_block('        ')))
    # the trust line removed by hand, the headers not set
    assert not pinned(_site(_old_block('        ').replace('            trusted_proxies private_ranges\n', '')))
    # an operator's own block below the marker is the operator's
    assert pinned(new + marker + '\n' + _site(_old_block('        ')))


def test_existing_boxes_are_rebuilt_on_the_console_update():
    conv = _func_src('_startup_caddy_forward_auth_converge')
    assert conv.index('_caddyfile_forward_auth_pinned(') < conv.index('generate_caddyfile(s)')
    # before the module registry loads the write is deferred to the catch-up regen
    assert conv.index('_CADDY_REGISTRY_READY.is_set()') < conv.index('_caddy_reload_if_changed(')
    # checked against the live file: a rejected Caddyfile is rolled back, say so
    assert 'STILL the' in conv
    mig = APP[APP.index('def _startup_migrations():'):]
    tp = mig.index('_startup_caddy_takportal_login_converge()')
    fa = mig.index('_startup_caddy_forward_auth_converge()')
    assert tp < fa < mig.index('_startup_caddy_selfheal()', tp)


# --- what Caddy makes of it ---------------------------------------------------------------------

@pytest.mark.skipif(not shutil.which('caddy'), reason='caddy not installed here (checked on the box)')
def test_caddy_sends_its_own_host_and_proto_and_trusts_no_proxy(tmp_path):
    ns = _ns()
    fa = _need(ns, '_caddy_forward_auth_lines')
    f = tmp_path / 'Caddyfile'
    f.write_text('\n'.join(['{', '    admin off', '    auto_https off', '}', 'http://127.0.0.1:18095 {',
                            '    route {', '        @needs_sso {', '            not path /api/*',
                            '        }', *fa(AK, '        ', COPY5, matcher='@needs_sso'),
                            '        reverse_proxy 127.0.0.1:5001', '    }', '}', '']))
    r = subprocess.run(['caddy', 'adapt', '--config', str(f), '--adapter', 'caddyfile'],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert 'trusted_proxies' not in r.stdout
    found = []

    def walk(o):
        if isinstance(o, dict):
            if o.get('handler') == 'reverse_proxy' and 'rewrite' in o:
                found.append(o)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(json.loads(r.stdout))
    assert len(found) == 1, 'expected one forward_auth handler'
    sets = found[0]['headers']['request']['set']
    assert sets['X-Forwarded-Host'] == ['{http.request.hostport}']
    assert sets['X-Forwarded-Proto'] == ['{http.request.scheme}']
    assert found[0]['rewrite']['uri'] == '/outpost.goauthentik.io/auth/caddy'
