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
"""HSTS on every HTTPS site, nosniff on the Authentik sites (ops #1103).

The Security lead's first baseline (ZAP, Low) found no Strict-Transport-Security on the
console, Authentik, CloudTAK, TAK Portal, Node-RED, stream and TAK Server sites, and no
X-Content-Type-Options on Authentik's. Only ATLAS and Remote Assist sent HSTS. The generated
Caddyfile now adds it to every `host {` site through one pure function, and Authentik's two
sites carry nosniff. Both use Caddy's `header ?Name value` form, so a header the upstream or an
operator's sites.d include already sends is never replaced.

app.py cannot be imported in a test, so its helpers are cut out of it and run on their own:
the code under test is the shipped text.
"""

import ast
import os
import pathlib
import re
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _load(names, ns=None):
    ns = {} if ns is None else ns
    ns.setdefault('os', os)
    ns.setdefault('re', re)
    exec(compile('\n\n'.join(_segment(n) for n in names), 'app.py:' + names[-1], 'exec'), ns)
    return ns


def _inject():
    return _load(['CADDY_HSTS_LINE', 'CADDY_NOSNIFF_LINE', '_CADDY_SITE_PORT_RE',
                  '_inject_security_headers'])


HSTS = '    header ?Strict-Transport-Security "max-age=31536000;"'

# A trimmed render in the generator's own shapes.
RENDER = [
    '# infra-TAK - Auto-generated Caddyfile', '',
    '{', '    grace_period 10s', '}', '',
    'example.com {', '    route /health* {', '        reverse_proxy 127.0.0.1:8080', '    }', '}', '',
    '# Alias → redirect to canonical example.com',
    'console.example.com {', '    redir https://example.com{uri} permanent', '}', '',
    'authentik.example.com {', '    reverse_proxy 127.0.0.1:9000', '}', '',
    'video.example.com:9997 {', '    bind 0.0.0.0', '    reverse_proxy 127.0.0.1:9997', '}', '',
    'atlas.example.com {', '    header Strict-Transport-Security "max-age=31536000;"',
    '    reverse_proxy 127.0.0.1:8443', '}', '',
    'http://atlas.example.com {', '    respond 404', '}', '',
    'atlas.example.com:8449 {', '    tls {', '        client_auth {', '        }', '    }', '}', '',
    '(snippet) {', '    header X-Foo bar', '}', '',
]


def _sites(out):
    """{address line: [its direct (4-space) directive lines]}"""
    res, cur = {}, None
    for ln in out:
        if ln and not ln[0].isspace() and ln.rstrip().endswith('{') and ln.rstrip() != '{':
            cur = ln
            res[cur] = []
        elif ln.rstrip() == '}':
            cur = None
        elif cur is not None and ln.startswith('    ') and not ln.startswith('     '):
            res[cur].append(ln)
    return res


def test_every_https_host_site_gets_hsts():
    out = _inject()['_inject_security_headers'](RENDER)
    sites = _sites(out)
    for addr in ('example.com {', 'console.example.com {', 'authentik.example.com {'):
        assert sites[addr][0] == HSTS, addr          # first directive, right after the address
        assert sites[addr].count(HSTS) == 1, addr


def test_plain_http_site_ports_snippets_and_global_block_are_left_alone():
    out = _inject()['_inject_security_headers'](RENDER)
    sites = _sites(out)
    for addr in ('http://atlas.example.com {', 'video.example.com:9997 {',
                 'atlas.example.com:8449 {', '(snippet) {', '{'):
        assert HSTS not in sites.get(addr, []), addr
    # the whole global block and the http:// site are unchanged
    assert out[out.index('{'):out.index('{') + 3] == ['{', '    grace_period 10s', '}']


def test_a_site_with_its_own_hsts_is_byte_identical():
    out = _inject()['_inject_security_headers'](RENDER)
    i = out.index('atlas.example.com {')
    assert out[i:i + 4] == ['atlas.example.com {',
                            '    header Strict-Transport-Security "max-age=31536000;"',
                            '    reverse_proxy 127.0.0.1:8443', '}']
    assert sum('Strict-Transport-Security' in l for l in out[i:i + 4]) == 1


def test_idempotent_and_total_lines_added():
    fn = _inject()['_inject_security_headers']
    once = fn(RENDER)
    assert fn(once) == once
    assert len(once) - len(RENDER) == 3             # example, console alias, authentik


def test_hsts_is_not_a_hard_override_of_the_upstream_or_an_operator_include():
    ns = _inject()
    assert ns['CADDY_HSTS_LINE'].strip().startswith('header ?Strict-Transport-Security')
    assert ns['CADDY_NOSNIFF_LINE'].strip() == 'header ?X-Content-Type-Options nosniff'


def test_generate_caddyfile_applies_it_before_custom_cert_and_includes():
    gen = _segment('generate_caddyfile')
    assert gen.count('lines = _inject_security_headers(lines)') == 1
    i = gen.index('lines = _inject_security_headers(lines)')
    assert i > gen.index('# EUD Remote Assist')                   # after the last vhost is written
    assert i < gen.index('_inject_custom_cert_tls(lines')
    assert i < gen.index('_inject_operator_includes(lines)')


def test_both_authentik_sites_carry_nosniff_and_nothing_else_does():
    gen = _segment('generate_caddyfile')
    for opener in ('lines.append(f"{ak_host} {{")', 'lines.append(f"authentik.{fqdn_base} {{")'):
        nxt = gen[gen.index(opener):].split('\n')[1].strip()
        assert nxt.startswith('lines.append(CADDY_NOSNIFF_LINE)'), opener
    assert gen.count('CADDY_NOSNIFF_LINE') == 2


# ── existing boxes converge at the console update ───────────────────────────

def _converge(caddyfile, regen_to=None, registry=True):
    state = {'file': caddyfile}
    calls, printed = [], []
    ev = threading.Event()
    if registry:
        ev.set()

    def gen(s):
        calls.append('generate')
        if regen_to is not None:
            state['file'] = regen_to

    def reload_if_changed(timeout=None):
        calls.append('reload')
        return True, ''

    ns = {'os': type('o', (), {'path': type('p', (), {'exists': staticmethod(lambda p: True)})}),
          'CADDYFILE_PATH': '/etc/caddy/Caddyfile', 'CADDYFILE_USER_BLOCKS_MARKER': '# --- USER ---',
          '_read_priv': lambda p: state['file'], 'load_settings': lambda: {'fqdn': 'x.example'},
          'generate_caddyfile': gen, '_caddy_reload_if_changed': reload_if_changed,
          '_CADDY_REGISTRY_READY': ev, 'print': lambda *a, **k: printed.append(' '.join(map(str, a)))}
    _load(['CADDY_HSTS_LINE', '_startup_caddy_security_headers_converge'], ns)
    ns['_startup_caddy_security_headers_converge']()
    return calls, printed


OLD = 'portal.x.example {\n    reverse_proxy 127.0.0.1:3000\n}\n'
NEW = OLD.replace('{\n', '{\n' + HSTS + '\n', 1)


def test_converge_regenerates_and_reloads_an_old_file():
    calls, printed = _converge(OLD, regen_to=NEW)
    assert calls == ['generate', 'reload'] and any('ops #1103' in p for p in printed)


def test_converge_is_a_noop_when_already_done():
    assert _converge(NEW)[0] == []
    # HSTS only in operator blocks below the marker does not count as done
    assert _converge(OLD + '# --- USER ---\nfoo {\n' + HSTS + '\n}\n', regen_to=NEW)[0] == ['generate', 'reload']


def test_converge_does_not_reload_a_rejected_regen():
    calls, _ = _converge(OLD, regen_to=OLD)
    assert calls == ['generate']


def test_converge_defers_to_the_registry_regen():
    calls, printed = _converge(OLD, regen_to=OLD, registry=False)
    assert calls == ['generate'] and any('queued' in p for p in printed)


def test_converge_is_wired_into_startup_migrations():
    src = APP[APP.index('def _startup_migrations'):]
    assert '_startup_caddy_security_headers_converge()' in src
