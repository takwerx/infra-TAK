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
"""Caddyfile regeneration wiped operator lines inside generated site blocks (GH #176).

An update regenerated the Caddyfile and dropped the reporter's `import cloudtak_print`
from the CloudTAK map site, so /print-api fell through to CloudTAK's SPA. The generated
file now imports operator-owned files it never writes: snippets.d/*.caddy at the top,
sites.d/<host>/*.caddy as the first line of each site. A broken include must not take
the box down: the file is then written without any includes.

app.py cannot be imported in a test, so its helpers are cut out of it and run against
stubs: the code under test is the shipped text.
"""

import ast
import os
import pathlib
import re
import shutil
import subprocess
import time

import pytest

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
    ns.setdefault('time', time)
    exec(compile('\n\n'.join(_segment(n) for n in names), 'app.py:' + names[-1], 'exec'), ns)
    return ns


_CONSTS = ('CADDYFILE_PATH', 'CADDYFILE_USER_BLOCKS_MARKER',
           'CADDY_SNIPPETS_INCLUDE_DIR', 'CADDY_SITES_INCLUDE_DIR')


def _inject():
    return _load(_CONSTS + ('_CADDY_INCLUDE_HOST_RE', '_inject_operator_includes'))


# A trimmed render in the generator's own shapes: header comments, the mandatory global
# block (with a nested block), plain sites, a nested handle, an alias, the ATLAS http://
# and :8449 listeners, and a multi-line element the way some vhosts are appended.
RENDER = [
    '# infra-TAK - Auto-generated Caddyfile', '# Base Domain: example.com', '',
    '{', '    grace_period 10s', '    acme_eab {', '        key_id x', '    }', '}', '',
    'example.com {', '    route /health* {', '        reverse_proxy 127.0.0.1:8080', '    }', '}', '',
    '# Alias → redirect to canonical example.com',
    'Console.Example.com {', '    redir https://example.com{uri} permanent', '}', '',
    'map.example.com {', '    handle {', '        reverse_proxy 127.0.0.1:5000', '    }', '}', '',
    'http://atlas.example.com {', '    respond 404', '}',
    'atlas.example.com:8449 {', '    tls {', '    }', '}',
    '*.wild.example.com {', '    respond 404', '}',
    'tiles.example.com {\n    reverse_proxy 127.0.0.1:5002\n}',
]


def test_snippets_import_follows_the_global_block():
    out = _inject()['_inject_operator_includes'](list(RENDER))
    close = out.index('}', out.index('{'))
    assert out[close + 1] == 'import /etc/caddy/snippets.d/*.caddy'
    assert out.count('import /etc/caddy/snippets.d/*.caddy') == 1
    # Nothing before the global block may become a block: it must stay first.
    assert all(l.startswith('#') or not l for l in out[:out.index('{')])


def test_each_plain_site_gets_its_import_as_the_first_line():
    out = _inject()['_inject_operator_includes'](list(RENDER))
    for host in ('example.com', 'console.example.com', 'map.example.com', 'tiles.example.com'):
        opener = next(i for i, l in enumerate(out) if l.lower() == f'{host} {{')
        assert out[opener + 1] == f'    import /etc/caddy/sites.d/{host}/*.caddy'


def test_listeners_wildcards_and_nested_blocks_get_no_import():
    out = _inject()['_inject_operator_includes'](list(RENDER))
    imports = [l for l in out if 'sites.d' in l]
    assert len(imports) == 4
    for bad in ('atlas.example.com', 'wild', 'health', 'acme'):
        assert not any(bad in l for l in imports), bad


def test_without_a_global_block_no_snippet_import_is_emitted():
    # It must never land above the global options (Caddy: "must be first").
    out = _inject()['_inject_operator_includes'](['map.example.com {', '    respond 200', '}'])
    assert not any('snippets.d' in l for l in out)
    assert out[1] == '    import /etc/caddy/sites.d/map.example.com/*.caddy'


def test_each_import_has_exactly_one_wildcard():
    # Caddy refuses an import pattern with more than one wildcard.
    out = _inject()['_inject_operator_includes'](list(RENDER))
    for l in out:
        if l.strip().startswith('import '):
            assert l.count('*') == 1, l


def test_include_files_lists_only_caddy_files(tmp_path):
    ns = _load(_CONSTS + ('_caddy_operator_include_files',))
    sites, snips = tmp_path / 'sites.d', tmp_path / 'snippets.d'
    (sites / 'map.example.com').mkdir(parents=True)
    snips.mkdir()
    (sites / 'README').write_text('x')
    (sites / 'stray.caddy').write_text('x')               # not inside a host folder
    (sites / 'map.example.com' / '10-print.caddy').write_text('x')
    (sites / 'map.example.com' / '10-print.caddy.bak').write_text('x')
    (sites / 'map.example.com' / '10-print.caddy~').write_text('x')
    (snips / 'print.caddy').write_text('x')
    (snips / 'README').write_text('x')
    got = ns['_caddy_operator_include_files'](str(sites), str(snips))
    assert got == sorted([str(sites / 'map.example.com' / '10-print.caddy'), str(snips / 'print.caddy')])


def test_include_files_with_no_folders_is_empty(tmp_path):
    ns = _load(_CONSTS + ('_caddy_operator_include_files',))
    assert ns['_caddy_operator_include_files'](str(tmp_path / 'a'), str(tmp_path / 'b')) == []


def _validator(verdicts):
    ns = {'written': [], 'verdicts': list(verdicts)}
    ns['_caddy_validate_config'] = lambda: ns['verdicts'].pop(0)
    ns['_write_priv'] = lambda path, text, **k: ns['written'].append((path, text))
    ns['_caddy_operator_include_files'] = lambda: ['/etc/caddy/sites.d/map.example.com/10-print.caddy']
    _load(_CONSTS + ('_caddy_include_rejected', '_caddy_validate_operator_includes'), ns)
    return ns


def test_good_includes_are_kept_and_clear_an_old_rejection():
    ns = _validator([('ok', '')])
    ns['_caddy_include_rejected']['err'] = 'old'
    text, done = ns['_caddy_validate_operator_includes']('WITH', 'PLAIN')
    assert (text, done) == ('WITH', True)
    assert ns['written'] == []
    assert ns['_caddy_include_rejected']['err'] == ''


def test_inconclusive_validate_is_not_a_rejection():
    # Permission denied as the non-root console is 'unknown' (GH #59/#137): never drop on it.
    ns = _validator([('unknown', 'permission denied')])
    assert ns['_caddy_validate_operator_includes']('WITH', 'PLAIN') == ('WITH', True)
    assert ns['written'] == []


def test_a_broken_include_falls_back_to_the_file_without_includes():
    ns = _validator([('bad', 'Error: unrecognized directive: reverse_prox'), ('ok', '')])
    text, done = ns['_caddy_validate_operator_includes']('WITH', 'PLAIN')
    assert (text, done) == ('PLAIN', True)
    assert ns['written'] == [('/etc/caddy/Caddyfile', 'PLAIN')]
    rej = ns['_caddy_include_rejected']
    assert 'reverse_prox' in rej['err'] and rej['files'] and rej['ts'] > 0


def test_when_the_plain_file_is_bad_too_the_normal_backstop_runs():
    ns = _validator([('bad', 'e1'), ('bad', 'e2')])
    text, done = ns['_caddy_validate_operator_includes']('WITH', 'PLAIN')
    assert (text, done) == ('PLAIN', False)          # generate_caddyfile then restores prev
    assert ns['_caddy_include_rejected']['err'] == ''


def test_generate_caddyfile_wires_the_fallback():
    seg = _segment('generate_caddyfile')
    assert '_inject_operator_includes(lines)' in seg
    assert '_caddy_validate_operator_includes(caddyfile, caddyfile_plain)' in seg
    assert '_caddy_ensure_include_dirs()' in seg
    # The new help line is re-emitted on every regen; it must not pile up as user content.
    assert "+ '# Directives INSIDE a generated site:" in seg
    prefixes = seg[seg.index('_help_prefixes'):seg.index('user_lines')]
    assert "'# Directives INSIDE a generated site'" in prefixes


def test_summary_reads_hooked_hosts_from_the_generated_part_only():
    ns = {'_caddy_include_rejected': {'err': '', 'files': []},
          '_caddy_operator_include_files': lambda: []}
    _load(_CONSTS + ('_caddy_includes_summary',), ns)
    text = ('map.example.com {\n    import /etc/caddy/sites.d/map.example.com/*.caddy\n}\n'
            '# --- User-added blocks (do not remove) ---\n'
            'x.example.com {\n    import /etc/caddy/sites.d/x.example.com/*.caddy\n}\n')
    assert ns['_caddy_includes_summary'](text)['hosts'] == ['map.example.com']


@pytest.mark.skipif(not shutil.which('caddy'), reason='caddy binary not on PATH')
def test_real_caddy_accepts_missing_includes_and_uses_present_ones(tmp_path):
    ns = _inject()
    sites, snips = tmp_path / 'sites.d', tmp_path / 'snippets.d'
    render = ['{', '    admin off', '}', '', 'map.example.com {', '    respond "spa"', '}',
              'tiles.example.com {', '    respond "tiles"', '}']
    out = ns['_inject_operator_includes'](render, str(sites), str(snips))
    cf = tmp_path / 'Caddyfile'
    cf.write_text('\n'.join(out) + '\n')
    r = subprocess.run(['caddy', 'adapt', '--config', str(cf), '--adapter', 'caddyfile'],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    (sites / 'map.example.com').mkdir(parents=True)
    snips.mkdir()
    (snips / 'p.caddy').write_text('(cloudtak_print) {\n    @p path /print-api /print-api/*\n'
                                   '    handle @p {\n        respond "print"\n    }\n}\n')
    (sites / 'map.example.com' / '10-print.caddy').write_text('import cloudtak_print\n')
    r = subprocess.run(['caddy', 'adapt', '--config', str(cf), '--adapter', 'caddyfile'],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert '/print-api' in r.stdout
