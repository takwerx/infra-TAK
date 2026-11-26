# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #897: the console's CSP lets scripts come from the console only.

`script-src` had `https:` in it, so script that got into a console page could load a second
script from any host. No console page needs that: every script is inline or a file of the
console itself. This test holds both halves:

  1. the header: `script-src` is exactly 'self' and 'unsafe-inline';
  2. the pages: nothing in the console's pages asks for a script (or a worker) from another host,
     so the header cannot break a page. A new page that needs one fails here, with its line.
"""
import ast
import pathlib
import re
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _csp():
    """The CSP header the console's after_request hook sets, as {directive: [sources]}."""
    fn = [n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef) and n.name == 'apply_security_headers']
    assert len(fn) == 1
    fn[0].decorator_list = []
    ns = {'request': types.SimpleNamespace(headers={}, is_secure=False)}
    exec(compile(ast.Module(body=fn, type_ignores=[]), 'app.py', 'exec'), ns)
    response = ns['apply_security_headers'](types.SimpleNamespace(headers={}))
    out = {}
    for part in response.headers['Content-Security-Policy'].split(';'):
        words = part.split()
        if words:
            out[words[0]] = words[1:]
    return out


def test_script_src_is_the_console_itself_and_inline_only():
    assert sorted(_csp()['script-src']) == ["'self'", "'unsafe-inline'"]


def test_the_other_directives_are_as_before():
    csp = _csp()
    assert csp['default-src'] == ["'self'", 'https:', 'data:', 'blob:']
    assert csp['style-src'] == ["'self'", "'unsafe-inline'", 'https:']
    assert csp['img-src'] == ["'self'", 'data:', 'https:']
    assert csp['font-src'] == ["'self'", 'data:', 'https:']
    assert csp['connect-src'] == ["'self'", 'https:', 'wss:']
    assert csp['frame-ancestors'] == ["'none'"] and csp['base-uri'] == ["'self'"] and csp['form-action'] == ["'self'"]
    assert 'worker-src' not in csp and "'unsafe-eval'" not in ' '.join(sum(csp.values(), []))


# Every way a page can ask for script from another host. `(?:https?:)?//` is a URL with a host.
_HOST = r'''["'`]\s*(?:https?:)?//'''
_ASKS = [
    ('a <script src> with a host', re.compile(r'<script\b[^>]*\bsrc\s*=\s*' + _HOST, re.I)),
    ('a script element given a host', re.compile(r'''createElement\(\s*["']script["']\s*\)''')),
    ('import() of a host', re.compile(r'\bimport\s*\(\s*' + _HOST)),
    ('a static import from a host', re.compile(r'''\bfrom\s+["'](?:https?:)?//''')),
    ('importScripts()', re.compile(r'\bimportScripts\s*\(')),
    ('a worker', re.compile(r'\bnew\s+(?:Shared)?Worker\s*\(|serviceWorker\s*\.\s*register\s*\(')),
]


def _console_page_sources():
    files = sorted((REPO / 'templates').glob('*.html')) + sorted((REPO / 'static').glob('*.js'))
    files += [REPO / 'app.py'] + sorted((REPO / 'modules').glob('*.py'))
    return files


@pytest.mark.parametrize('what,pattern', _ASKS, ids=[w for w, _ in _ASKS])
def test_no_console_page_asks_for_script_from_another_host(what, pattern):
    hits = []
    for f in _console_page_sources():
        for n, line in enumerate(f.read_text(encoding='utf-8').split('\n'), 1):
            if pattern.search(line):
                hits.append('%s:%d: %s' % (f.relative_to(REPO), n, line.strip()[:120]))
    assert not hits, ('%s. script-src is the console itself and inline only (ops #897): serve the '
                      'file from /static, or widen the CSP on purpose.\n' % what) + '\n'.join(hits[:20])
