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
"""ops #648: TAK Portal is only ever published behind Authentik.

TAK Portal has no login of its own; Authentik forward_auth in front of it is the login, and
TAK Portal reads the user from the X-Authentik-* headers. So the vhost is forward_auth (with
client X-Authentik-* headers removed first, on every path) or a 503, never a bare
reverse_proxy, also when the Authentik check fails. generate_caddyfile needs the whole box,
so the vhost lines come from pure helpers that these tests run for real, and the wiring is
checked on the source.
"""

import ast
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_NAMES = ('_caddy_vhost_block', '_vhost_uses_sso', '_takportal_vhost_lines',
          '_takportal_vhost_is_closed')
_CONSTS = ('_TAKPORTAL_VHOST_MARKER', '_TAKPORTAL_PUBLIC_PATHS', '_CADDY_STRIP_AUTHENTIK_HEADERS',
           '_TAKPORTAL_AK_COPY_HEADERS', 'CADDYFILE_USER_BLOCKS_MARKER')
PORTAL = '127.0.0.1:3000'
AK = '127.0.0.1:9090'

# What dev generated before ops #648 for a box with no Authentik (or a failed Authentik check).
OLD_BARE = '# TAK Portal\nportal.example.com {\n    reverse_proxy 127.0.0.1:3000\n}\n'
# What dev generated with Authentik: forward_auth, but client X-Authentik-* headers not removed.
OLD_AK = ('# TAK Portal\nportal.example.com {\n    route {\n'
          '        reverse_proxy /outpost.goauthentik.io/* 127.0.0.1:9090\n'
          '        handle @public {\n            reverse_proxy 127.0.0.1:3000\n        }\n'
          '        forward_auth 127.0.0.1:9090 {\n            uri /outpost.goauthentik.io/auth/caddy\n'
          '        }\n        reverse_proxy 127.0.0.1:3000\n    }\n}\n')


def _ns():
    ns = {'re': re}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _NAMES:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') in _CONSTS:
            exec(ast.get_source_segment(APP, node), ns)
    missing = [n for n in _NAMES + _CONSTS if n not in ns]
    assert not missing, f'ops #648 helpers missing from app.py: {missing}'
    return ns


def _caddyfile(portal_block, user_blocks=''):
    ns = _ns()
    return ('# infra-TAK - Auto-generated Caddyfile\n\n'
            "# TAK Portal's Print plugin, published on loopback by infra-TAK (ops #222)\n"
            '(print) {\n    reverse_proxy 127.0.0.1:3005\n}\n\n'
            + portal_block + '\n' + ns['CADDYFILE_USER_BLOCKS_MARKER'] + '\n' + user_blocks)


def _vhost(ns, ak, existing):
    """The TAK Portal vhost generate_caddyfile writes, from the same helpers it calls."""
    sso = ns['_vhost_uses_sso'](ak, existing, ns['_TAKPORTAL_VHOST_MARKER'])
    return '\n'.join(['# TAK Portal', 'portal.example.com {']
                     + ns['_takportal_vhost_lines'](PORTAL, AK, sso, ['        # rescue'])
                     + ['}', ''])


def test_no_authentik_means_503_and_never_a_proxy():
    ns = _ns()
    for ak in ({'installed': False, 'probe_ok': True}, {'installed': False}):
        for existing in ('', _caddyfile(OLD_BARE), _caddyfile(OLD_AK)):
            text = _vhost(ns, ak, existing)
            assert 'reverse_proxy' not in text, (ak, existing)
            assert re.search(r'^    respond ".*" 503$', text, re.M)
            assert ns['_takportal_vhost_is_closed'](text)


def test_failed_authentik_check_never_publishes_a_bare_portal():
    """The probe failed (or gave no answer): keep Authentik if it was there, else 503."""
    ns = _ns()
    for ak in ({'installed': False, 'probe_ok': False}, {}, None):
        bare = _vhost(ns, ak, _caddyfile(OLD_BARE))
        assert 'reverse_proxy' not in bare and ' 503' in bare
        kept = _vhost(ns, ak, _caddyfile(OLD_AK))
        assert 'forward_auth' in kept and ns['_takportal_vhost_is_closed'](kept)
        none = _vhost(ns, ak, '')
        assert 'reverse_proxy' not in none and ' 503' in none


def test_forward_auth_elsewhere_in_the_file_does_not_count():
    ns = _ns()
    mk = ns['_TAKPORTAL_VHOST_MARKER']
    ak = {'installed': False, 'probe_ok': False}
    # an operator block with forward_auth below the marker
    user = '# TAK Portal\nmine.example.com {\n    forward_auth 1.2.3.4:9000 {\n    }\n}\n'
    assert not ns['_vhost_uses_sso'](ak, _caddyfile(OLD_BARE, user), mk)
    # the Print plugin comment starts with the same words
    assert ns['_caddy_vhost_block'](_caddyfile(OLD_BARE), mk).startswith('# TAK Portal\nportal.')


def test_authentik_vhost_strips_client_headers_before_everything():
    ns = _ns()
    lines = ns['_takportal_vhost_lines'](PORTAL, AK, True, ['        # rescue'])
    text = '\n'.join(lines)
    assert lines[0] == '    route {'
    assert lines[1] == '        request_header -X-Authentik-*'
    strip = text.index('request_header -X-Authentik-*')
    # removed before the public paths, the outpost and forward_auth, so no path keeps them
    assert strip < text.index('# rescue') < text.index('reverse_proxy /outpost.goauthentik.io/*')
    assert strip < text.index('handle @public') < text.index('forward_auth') < text.rindex('reverse_proxy')
    assert f'path {ns["_TAKPORTAL_PUBLIC_PATHS"]}' in text
    assert 'copy_headers X-Authentik-Username X-Authentik-Groups' in text
    assert text.count('{') == text.count('}')
    assert ns['_takportal_vhost_is_closed'](_vhost(ns, {'installed': True}, ''))


def test_old_vhosts_are_seen_as_open():
    ns = _ns()
    closed = ns['_takportal_vhost_is_closed']
    blk = lambda t: ns['_caddy_vhost_block'](_caddyfile(t), ns['_TAKPORTAL_VHOST_MARKER'])
    assert not closed(blk(OLD_BARE))
    assert not closed(blk(OLD_AK))
    assert closed('')                                      # no TAK Portal: nothing to fix


def test_generate_caddyfile_uses_the_helpers_and_has_no_bare_proxy():
    src = next(ast.get_source_segment(APP, n) for n in TREE.body
               if isinstance(n, ast.FunctionDef) and n.name == 'generate_caddyfile')
    i = src.index('lines.append(f"# TAK Portal")')
    blk = src[i:src.index("_emit_alias_redirect(_get_service_alias(settings, 'takportal')", i)]
    assert 'reverse_proxy {portal_up}' not in blk
    assert '_vhost_uses_sso(ak, _tp_existing, _TAKPORTAL_VHOST_MARKER)' in blk
    assert '_takportal_vhost_lines(portal_up, ak_up, _tp_sso, _tp_rescue)' in blk
    assert "if ak.get('installed')" not in blk


def test_deploy_is_refused_without_authentik():
    src = APP[APP.index('def takportal_deploy():'):APP.index('def takportal_deploy_log_api():')]
    gate = src.index("detect_modules(fresh=True).get('authentik', {}).get('installed')")
    assert gate < src.index('threading.Thread(target=run_takportal_deploy')
    assert gate < src.index('takportal_deploy_log.clear()')


def test_existing_boxes_are_fixed_on_the_console_update():
    conv = APP[APP.index('def _startup_caddy_takportal_login_converge():'):]
    conv = conv[:conv.index('\ndef ')]
    assert 'generate_caddyfile(s)' in conv
    # before the module registry loads the write is deferred to the catch-up regen
    assert conv.index('_CADDY_REGISTRY_READY.is_set()') < conv.index('_caddy_reload_if_changed(')
    # checked against the live file: a rejected Caddyfile is rolled back, say so
    assert 'STILL open' in conv
    assert 'treat this box as taken over' in conv
    mig = APP[APP.index('def _startup_migrations():'):]
    nr = mig.index('_startup_caddy_nodered_login_converge()')
    tp = mig.index('_startup_caddy_takportal_login_converge()')
    assert nr < tp < mig.index('_startup_caddy_selfheal()', nr)
