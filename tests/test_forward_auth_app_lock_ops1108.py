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
"""ops #1108: after the Authentik sign-in check, each site compares the application.

The outpost names the application it answered for in X-authentik-meta-app. Every site that
infra-TAK puts behind Authentik lets a request through only when that name is the site's own
application. The name of each site comes from Authentik's provider list; a site that is not
in the list keeps the sign-in check with no compare. The group header is never read.

app.py cannot be imported in a test, so the helpers are cut out of it and run. Helpers that
older trees do not have are left out, and the tests then fail on what the old code writes.
"""

import ast
import http.server
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import threading
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_NAMES = ('_caddy_forward_auth_lines', '_caddyfile_forward_auth_pinned', '_takportal_vhost_lines',
          '_emit_mediamtx_site', '_caddy_app_lock_map', '_caddy_app_lock_saved',
          '_caddy_app_lock_save', '_caddy_app_lock_refresh', '_caddy_app_lock_apps',
          '_caddy_app_lock_slug', '_caddyfile_app_locks', '_caddy_app_lock_converge')
_CONSTS = ('_CADDY_AK_COPY_HEADERS', '_CADDY_FORWARD_AUTH_URI', '_CADDY_FORWARD_AUTH_PIN',
           '_TAKPORTAL_PUBLIC_PATHS', '_CADDY_STRIP_AUTHENTIK_HEADERS', '_TAKPORTAL_AK_COPY_HEADERS',
           'CADDYFILE_USER_BLOCKS_MARKER', 'MEDIAMTX_OPEN_PATHS', '_MEDIAMTX_VHOST_MARKER',
           '_CADDY_APP_HEADER', '_CADDY_APP_LOCK_MATCHER', '_CADDY_APP_LOCK_TEXT',
           '_CADDY_APP_SLUG_RE', '_CADDY_APP_LOCK_FILE', '_caddy_app_lock_cache',
           '_MEDIAMTX_AK_COPY_HEADERS', '_MEDIAMTX_IDENTITY_MARKER')
AK = '127.0.0.1:9090'
COPY5 = 'X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid'
STRIP = 'request_header -X-Authentik-Meta-App'
TEXT = 'Sign-in was checked for another application. Restart the infra-TAK console, then try again.'


def _compare(app):
    return f'@ak_other_app not header X-Authentik-Meta-App {app}'


def _ns(config_dir='/nonexistent'):
    ns = {'re': re, 'os': os, 'json': json, 'time': time, 'CONFIG_DIR': str(config_dir),
          '_pub_url': lambda h, s=None: f'https://{h}' if h else '',
          '_pub_hostport': lambda h, s=None: (f'{h}:{s["port"]}' if (s or {}).get('port') else h)}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _NAMES:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') in _CONSTS:
            exec(ast.get_source_segment(APP, node), ns)
    return ns


def _need(ns, name):
    assert name in ns, f'{name} is missing from app.py (ops #1108)'
    return ns[name]


def _func_src(name):
    found = [ast.get_source_segment(APP, n) for n in TREE.body
             if isinstance(n, ast.FunctionDef) and n.name == name]
    assert found, f'{name} is missing from app.py (ops #1108)'
    return found[0]


def _with_app(fn, *args, app):
    """Call a site writer with the site's application. A tree whose writer takes no
    application writes the site without one, and the test fails on that text."""
    try:
        return fn(*args, app=app)
    except TypeError:
        return fn(*args)


def _takportal_text(ns, app):
    return '\n'.join(_with_app(ns['_takportal_vhost_lines'], '127.0.0.1:3000', AK, True, [], app=app))


def _stream_text(ns, app):
    lines = []
    _with_app(ns['_emit_mediamtx_site'], lines, 'stream.example.com', '127.0.0.1:5080', AK, None,
              lambda indent: None, lambda root: None, app=app)
    return '\n'.join(lines)


def _assert_compares(text, app):
    """One sign-in check, and right after it the compare and the refusal."""
    lines = [l.strip() for l in text.split('\n')]
    assert lines.count(_compare(app)) == 1, f'no application compare for {app}:\n{text}'
    fa = next(i for i, l in enumerate(lines) if l.startswith('forward_auth '))
    end = lines.index('}', fa)
    assert lines[end + 1] == _compare(app)
    assert lines[end + 2] == f'respond @ak_other_app "{TEXT}" 403'
    # the client's own copy of the header is removed before the check
    assert STRIP in lines[:fa]
    # the answer's copy is what Caddy compares
    copy = next(l for l in lines[fa:end] if l.startswith('copy_headers '))
    assert 'X-Authentik-Meta-App' in copy.split()
    # nothing between the site's first line and the compare lets a request to the backend
    # after the sign-in check: the first proxy to the backend after the check is below it
    after = [i for i, l in enumerate(lines) if i > end and l.startswith('reverse_proxy ')]
    assert after and after[0] > end + 2


# --- what the shipped code writes -------------------------------------------------------------

def test_tak_portal_site_compares_the_application():
    ns = _ns()
    text = _takportal_text(ns, 'tak-portal')
    _assert_compares(text, 'tak-portal')
    # TAK Portal reads the header, so it is still handed on
    assert text.count(STRIP) == 1
    structure = re.sub(r'\{http\.request\.[a-z]+\}', '', text)
    assert structure.count('{') == structure.count('}')


def test_stream_site_compares_the_application():
    ns = _ns()
    text = _stream_text(ns, 'stream')
    _assert_compares(text, 'stream')
    # the stream site backend did not get this header before, and does not get it now
    lines = [l.strip() for l in text.split('\n')]
    assert lines[lines.index(_compare('stream')) + 2] == STRIP


def test_a_site_with_no_known_application_keeps_the_plain_check():
    ns = _ns()
    for text in (_takportal_text(ns, ''), _stream_text(ns, '')):
        assert '@ak_other_app' not in text
        assert text.count('forward_auth ') == 1
        assert 'header_up X-Forwarded-Host {http.request.hostport}' in text


def test_the_writer_emits_the_exact_lines():
    ns = _ns()
    fa = _need(ns, '_caddy_forward_auth_lines')
    pin = ['header_up X-Forwarded-Host {http.request.hostport}',
           'header_up X-Forwarded-Proto {http.request.scheme}']
    assert _with_app(fa, AK, '    ', app='node-red') == [
        '    ' + STRIP,
        '    forward_auth 127.0.0.1:9090 {',
        '        uri /outpost.goauthentik.io/auth/caddy',
        '        copy_headers X-Authentik-Meta-App',
        '        ' + pin[0],
        '        ' + pin[1],
        '    }',
        '    ' + _compare('node-red'),
        f'    respond @ak_other_app "{TEXT}" 403',
        '    ' + STRIP]
    # a check behind a matcher: only the requests that were checked are compared
    assert _with_app(fa, AK, '', COPY5, '@needs_sso', app='infratak') == [
        STRIP,
        'route @needs_sso {',
        '    forward_auth 127.0.0.1:9090 {',
        '        uri /outpost.goauthentik.io/auth/caddy',
        f'        copy_headers {COPY5} X-Authentik-Meta-App',
        '        ' + pin[0],
        '        ' + pin[1],
        '    }',
        '    ' + _compare('infratak'),
        f'    respond @ak_other_app "{TEXT}" 403',
        '    ' + STRIP,
        '}']
    # the compare does not read the group header
    assert not any('Groups' in l for l in _with_app(fa, AK, '', app='node-red'))


def test_a_name_that_is_not_a_slug_writes_no_compare():
    ns = _ns()
    fa = _need(ns, '_caddy_forward_auth_lines')
    plain = fa(AK, '    ', COPY5)
    for bad in ('node red', 'node-red\n    respond 200', 'a*', 'x"y', 'a|b', '{http.request.host}',
                'a' * 101, None):
        assert _with_app(fa, AK, '    ', COPY5, app=bad) == plain, bad


def test_generate_caddyfile_gives_every_site_its_own_application():
    src = _func_src('generate_caddyfile')
    for host in ('infratak_host', 'nodered_host', 'portal_host', 'mtx_host', 'wo_host', 'at_host'):
        assert src.count(f'app=_fa_app({host})') == 1, host
    # four direct calls of the writer, and each gives an application. Federation Hub has its
    # own helper (ops #1204) and gives none: its check sits in a `handle`, where Caddy sorts
    # the directives, so the compare would run before the check and refuse every request.
    calls = re.findall(r'_caddy_forward_auth_lines\((.*?)\)\)\n', src, re.S)
    assert len(calls) == 4, calls
    assert all('app=_fa_app(' in c for c in calls), calls
    assert 'app=_fa_app(fh_host)' not in src
    assert src.count("_fedhub_forward_auth_lines(ak_up, '            ')") == 1
    assert 'return _caddy_forward_auth_lines(ak_up, indent)\n' in _func_src('_fedhub_forward_auth_lines') + '\n'
    # every check that gets an application is a direct line of the site's `route` block
    # (8 spaces)
    assert [c.split(',')[1].strip() for c in calls] == ['"        "'] * 4
    # a failed lookup never stops the Caddyfile build
    look = src[src.index('_fa_apps = _caddy_app_lock_apps()') - 40:src.index('def _fa_app(host):')]
    assert 'try:' in look and 'except Exception:' in look


# --- where the application names come from ------------------------------------------------------

def _prov(host, slug, mode='forward_single'):
    return {'external_host': host, 'assigned_application_slug': slug, 'mode': mode}


def test_the_map_is_built_from_authentik_provider_list_only():
    ns = _ns()
    build = _need(ns, '_caddy_app_lock_map')
    assert build([_prov('https://infratak.example.com', 'infratak'),
                  _prov('https://NodeRED.example.com/', 'node-red'),
                  _prov('https://takportal.example.com:8443', 'tak-portal')]) == {
        'infratak.example.com': 'infratak', 'nodered.example.com': 'node-red',
        'takportal.example.com:8443': 'tak-portal'}
    # no application, a name that is not a slug, a path, another mode: no entry
    assert build([_prov('https://a.example.com', ''), _prov('https://b.example.com', None),
                  _prov('https://c.example.com', 'x y'), _prov('https://d.example.com/sub', 'd'),
                  _prov('https://e.example.com', 'e', 'forward_domain'),
                  _prov('https://f.example.com', 'f', 'proxy'), _prov('', 'g'), 'junk', None]) == {}
    # two providers on one host: nobody knows which one answers, so no compare there
    assert build([_prov('https://a.example.com', 'one'), _prov('https://A.example.com', 'two'),
                  _prov('https://b.example.com', 'b')]) == {'b.example.com': 'b'}
    # also when the second one is of another kind or has no application
    assert build([_prov('https://a.example.com', 'one'),
                  _prov('https://a.example.com', 'dom', 'forward_domain')]) == {}
    assert build([_prov('https://a.example.com', 'one'), _prov('https://a.example.com', '', 'proxy')]) == {}
    # a provider with unauthenticated paths: the outpost passes those with no application
    # named, so a compare would refuse them
    skip = dict(_prov('https://hook.example.com', 'hook'), skip_path_regex='^/webhook/.*')
    assert build([skip, _prov('https://b.example.com', 'b')]) == {'b.example.com': 'b'}
    assert build([dict(skip, skip_path_regex='  ')]) == {'hook.example.com': 'hook'}
    assert build(None) == {} and build([]) == {}


def test_the_site_name_is_looked_up_as_the_browser_types_it():
    ns = _ns()
    slug = _need(ns, '_caddy_app_lock_slug')
    apps = {'nodered.example.com': 'node-red', 'nodered.example.com:8443': 'other', 'x.example.com': 'a b'}
    assert slug(apps, 'nodered.example.com', {}) == 'node-red'
    assert slug(apps, 'NodeRED.example.com', {}) == 'node-red'
    assert slug(apps, 'nodered.example.com', {'port': 8443}) == 'other'
    assert slug(apps, 'webodm.example.com', {}) == ''
    assert slug(apps, 'x.example.com', {}) == ''          # a saved name that is not a slug
    assert slug(apps, '', {}) == '' and slug(None, 'nodered.example.com', {}) == ''


class _Answer:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body


def _refresh_ns(tmp_path, monkeypatch, answer):
    """The refresh helpers with a stand-in Authentik. `answer` is the JSON body, or an
    exception to raise. Returns (ns, calls)."""
    home = tmp_path / 'home'
    (home / 'authentik').mkdir(parents=True)
    (home / 'authentik' / '.env').write_text('X=1\n')
    monkeypatch.setenv('HOME', str(home))
    cfg = tmp_path / 'config'
    ns = _ns(cfg)
    _need(ns, '_caddy_app_lock_refresh')
    ns['_CADDY_APP_LOCK_FILE'] = str(cfg / 'forward_auth_apps.json')
    calls = []

    def api(url, **kw):
        calls.append((url, kw))
        if isinstance(answer['v'], Exception):
            raise answer['v']
        return _Answer(json.dumps(answer['v']).encode())

    ns.update({'load_settings': lambda: {'fqdn': 'example.com'},
               '_get_authentik_env_value': lambda s, k: 'tok' if k == 'AUTHENTIK_BOOTSTRAP_TOKEN' else '',
               '_get_authentik_api_url': lambda s: 'http://127.0.0.1:9090',
               '_ak_api_call': api})
    return ns, calls


def test_no_answer_from_authentik_keeps_the_saved_names(tmp_path, monkeypatch):
    answer = {'v': {'results': [_prov('https://nodered.example.com', 'node-red')]}}
    ns, calls = _refresh_ns(tmp_path, monkeypatch, answer)
    assert ns['_caddy_app_lock_saved']() == {}
    assert ns['_caddy_app_lock_refresh']() == {'nodered.example.com': 'node-red'}
    assert calls[0][0] == 'http://127.0.0.1:9090/api/v3/providers/proxy/?page_size=200'
    assert calls[0][1]['headers']['Authorization'] == 'Bearer tok'
    assert ns['_caddy_app_lock_saved']() == {'nodered.example.com': 'node-red'}
    saved = pathlib.Path(ns['_CADDY_APP_LOCK_FILE'])
    assert (saved.stat().st_mode & 0o777) == 0o600
    # Authentik stopped, an answer that is not a list, a list that is not complete
    for bad in (OSError('connection refused'), {'detail': 'nope'}, {'results': 'x'},
                {'results': [], 'pagination': {'next': 2}}):
        answer['v'] = bad
        assert ns['_caddy_app_lock_refresh']() is None
        assert ns['_caddy_app_lock_saved']() == {'nodered.example.com': 'node-red'}
    # a real answer with no provider is an answer: the names go away with the providers
    answer['v'] = {'results': [], 'pagination': {'next': 0}}
    assert ns['_caddy_app_lock_refresh']() == {}
    assert ns['_caddy_app_lock_saved']() == {}


def test_no_authentik_on_the_box_asks_nothing(tmp_path, monkeypatch):
    answer = {'v': {'results': []}}
    ns, calls = _refresh_ns(tmp_path, monkeypatch, answer)
    os.remove(os.path.expanduser('~/authentik/.env'))
    assert ns['_caddy_app_lock_refresh']() is None and calls == []


def test_the_caddyfile_build_asks_authentik_at_most_once_in_five_minutes(tmp_path, monkeypatch):
    answer = {'v': {'results': [_prov('https://nodered.example.com', 'node-red')]}}
    ns, calls = _refresh_ns(tmp_path, monkeypatch, answer)
    clock = {'t': 1000.0}
    ns['time'] = type('T', (), {'time': staticmethod(lambda: clock['t'])})
    apps = _need(ns, '_caddy_app_lock_apps')
    assert apps() == {'nodered.example.com': 'node-red'} and len(calls) == 1
    assert calls[0][1]['timeout'] <= 5 and calls[0][1]['max_retries'] == 1     # one short try
    answer['v'] = {'results': [_prov('https://nodered.example.com', 'renamed')]}
    clock['t'] += 299
    assert apps() == {'nodered.example.com': 'node-red'} and len(calls) == 1
    clock['t'] += 2
    assert apps() == {'nodered.example.com': 'renamed'} and len(calls) == 2
    answer['v'] = OSError('down')
    clock['t'] += 301
    assert apps() == {'nodered.example.com': 'renamed'} and len(calls) == 3
    # no answer: it asks again after 30 seconds, not 5 minutes
    clock['t'] += 29
    assert apps() == {'nodered.example.com': 'renamed'} and len(calls) == 3
    clock['t'] += 2
    assert apps() == {'nodered.example.com': 'renamed'} and len(calls) == 4


def test_a_deploy_that_puts_a_provider_on_the_outpost_makes_the_next_build_ask_again():
    src = _func_src('_outpost_add_providers_safe')
    assert "_caddy_app_lock_cache['ts'] = 0.0" in src
    # a missing name in a cut-out copy of the function (other tests) must not stop it
    head = src[:src.index("_caddy_app_lock_cache['ts'] = 0.0") + 60]
    assert 'try:' in head and 'except Exception:' in src[len(head) - 60:len(head) + 60]


# --- existing boxes ---------------------------------------------------------------------------

def _converge_ns(tmp_path, monkeypatch, answer, caddyfile):
    ns, calls = _refresh_ns(tmp_path, monkeypatch, answer)
    _need(ns, '_caddy_app_lock_converge')
    cf = tmp_path / 'Caddyfile'
    cf.write_text(caddyfile)
    did = {'generate': 0, 'reload': 0, 'log': []}

    def generate(s):
        did['generate'] += 1
        fa = ns['_caddy_forward_auth_lines']
        slug = ns['_caddy_app_lock_slug'](ns['_caddy_app_lock_saved'](), 'nodered.example.com', s)
        cf.write_text('nodered.example.com {\n    route {\n'
                      + '\n'.join(fa(AK, '        ', app=slug)) + '\n    }\n}\n')

    def reload_(timeout=0):
        did['reload'] += 1
        return True, ''

    ready = threading.Event()
    ready.set()
    ns.update({'CADDYFILE_PATH': str(cf), '_read_priv': lambda p: pathlib.Path(p).read_text(),
               'generate_caddyfile': generate, '_caddy_reload_if_changed': reload_,
               '_CADDY_REGISTRY_READY': ready})
    return ns, did, cf


_OLD_SITE = ('nodered.example.com {\n    route {\n        forward_auth 127.0.0.1:9090 {\n'
             '            uri /outpost.goauthentik.io/auth/caddy\n        }\n    }\n}\n')


def test_an_existing_box_gets_the_compare_when_authentik_answers(tmp_path, monkeypatch):
    answer = {'v': {'results': [_prov('https://nodered.example.com', 'node-red')]}}
    ns, did, cf = _converge_ns(tmp_path, monkeypatch, answer, _OLD_SITE)
    log = did['log'].append
    ns['_caddy_app_lock_converge'](log)
    assert did['generate'] == 1 and did['reload'] == 1
    assert ns['_caddyfile_app_locks'](cf.read_text()) == ['node-red']
    assert any('1 site(s) (node-red)' in m for m in did['log']), did['log']
    # nothing changed: the next run writes nothing
    ns['_caddy_app_lock_converge'](log)
    assert did['generate'] == 1
    # a fresh console start with nothing changed writes nothing and reloads nothing
    ns['_caddy_app_lock_cache']['ts'] = 0.0
    reloads = did['reload']
    ns['_caddy_app_lock_converge'](log)
    assert did['generate'] == 1 and did['reload'] == reloads
    # an earlier Caddyfile build of this start already wrote the compares, with no reload:
    # the converge writes nothing more and still hands the file to Caddy
    ns['_caddy_app_lock_cache']['ts'] = time.time()
    ns['_caddy_app_lock_converge'](log)
    assert did['generate'] == 1 and did['reload'] == reloads + 1
    # Authentik gives no answer: nothing is written, the compare stays
    answer['v'] = OSError('down')
    ns['_caddy_app_lock_converge'](log)
    assert did['generate'] == 1 and ns['_caddyfile_app_locks'](cf.read_text()) == ['node-red']
    # the application got another name in Authentik: the compare follows it
    answer['v'] = {'results': [_prov('https://nodered.example.com', 'node-red-2')]}
    ns['_caddy_app_lock_converge'](log)
    assert did['generate'] == 2 and ns['_caddyfile_app_locks'](cf.read_text()) == ['node-red-2']


def test_the_converge_never_stops_a_console_start(tmp_path, monkeypatch):
    answer = {'v': {'results': [_prov('https://nodered.example.com', 'node-red')]}}
    ns, did, cf = _converge_ns(tmp_path, monkeypatch, answer, _OLD_SITE)

    def boom(s):
        raise RuntimeError('caddy validate failed')
    ns['generate_caddyfile'] = boom
    ns['_caddy_app_lock_converge'](did['log'].append)            # no exception
    assert any('non-fatal' in m for m in did['log'])
    # an operator's own block below the marker is not counted as ours
    marker = ns['CADDYFILE_USER_BLOCKS_MARKER']
    assert ns['_caddyfile_app_locks'](_OLD_SITE + marker + '\n        ' + _compare('mine') + '\n') == []


def test_the_converge_runs_at_console_start_and_after_an_update():
    mig = APP[APP.index('def _startup_migrations():'):]
    pinned = mig.index('_startup_caddy_forward_auth_converge()')
    lock = mig.index('_caddy_app_lock_converge()')
    assert pinned < lock < mig.index('_startup_caddy_selfheal()', pinned)
    # at start it runs after the step that sets the provider hosts
    assert mig.index('_ensure_authentik_proxy_external_hosts_canonical(') < lock
    # after an update it runs once Authentik answers and the provider chain is healed
    post = APP[APP.index('def _post_update_auto_deploy():'):]
    heal = post.index('_heal_authentik_proxy_chain_all_services(')
    assert heal < post.index('_caddy_app_lock_converge(', heal) < heal + 1200


def test_the_proxy_auth_gate_check_reads_both_forms_of_the_console_check():
    """The startup step that arms the console's proxy-auth secret looks for the console's
    sign-in check in the built Caddyfile. With an application the check is written as
    `route @needs_sso {`, so the step must know that form too, or it arms with no secret."""
    mig = APP[APP.index('def _startup_migrations():'):]
    gate = mig[mig.index("'request_header -X-Infratak-Proxy-Auth' in _cf"):][:600]
    assert "'forward_auth @needs_sso' not in _cf" in gate
    assert "'route @needs_sso' not in _cf" in gate
    assert "or 'request_header @needs_sso X-Infratak-Proxy-Auth' in _cf" in gate
    # and the two forms are what the writer really emits
    ns = _ns()
    fa = _need(ns, '_caddy_forward_auth_lines')
    assert any(l.startswith('forward_auth @needs_sso ') for l in fa(AK, '', COPY5, '@needs_sso'))
    assert 'route @needs_sso {' in _with_app(fa, AK, '', COPY5, '@needs_sso', app='infratak')


# --- what Caddy does with it --------------------------------------------------------------------

class _StandIn(http.server.BaseHTTPRequestHandler):
    """Sign-in service and backend on one port. X-Test-Mode says how the sign-in service
    answers: app=<slug>, noheader (signed in, no application named), or deny."""

    def do_GET(self):
        if self.path.startswith('/outpost.goauthentik.io/auth/caddy'):
            mode = self.headers.get('X-Test-Mode') or 'deny'
            if mode == 'deny':
                self.send_response(302)
                self.send_header('Location', 'https://signin.example/')
            else:
                self.send_response(200)
                self.send_header('X-Authentik-Username', 'someone')
                if mode.startswith('app='):
                    self.send_header('X-Authentik-Meta-App', mode[4:])
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        seen = sorted(k.lower() for k in self.headers.keys() if k.lower().startswith('x-authentik'))
        out = ('BACKEND ' + ' '.join(seen)).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _get(port, path, mode, extra=None):
    import urllib.error
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}',
                                 headers={'X-Test-Mode': mode, **(extra or {})})
    try:
        r = urllib.request.build_opener(_NoRedirect).open(req, timeout=10)
        return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


@pytest.mark.skipif(not shutil.which('caddy'), reason='caddy not installed here (checked on the box)')
def test_caddy_refuses_an_answer_for_another_application(tmp_path):
    ns = _ns()
    fa = _need(ns, '_caddy_forward_auth_lines')
    auth, plain, console = _free_port(), _free_port(), _free_port()
    up = f'127.0.0.1:{auth}'
    f = tmp_path / 'Caddyfile'
    f.write_text('\n'.join([
        '{', '    admin off', '    auto_https off', '}',
        f'http://127.0.0.1:{plain} {{', '    route {',
        *_with_app(fa, up, '        ', app='node-red'),
        f'        reverse_proxy {up}', '    }', '}',
        f'http://127.0.0.1:{console} {{', '    route {',
        '        @needs_sso {', '            not path /api/*', '        }',
        *_with_app(fa, up, '        ', COPY5, '@needs_sso', app='infratak'),
        '        request_header @needs_sso X-Proxy-Auth secret',
        f'        reverse_proxy {up}', '    }', '}', '']))
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', auth), _StandIn)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    caddy = subprocess.Popen(['caddy', 'run', '--config', str(f), '--adapter', 'caddyfile'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 20
        while True:
            try:
                socket.create_connection(('127.0.0.1', console), timeout=1).close()
                socket.create_connection(('127.0.0.1', plain), timeout=1).close()
                break
            except OSError:
                assert caddy.poll() is None, 'caddy refused the Caddyfile'
                assert time.time() < deadline, 'caddy did not start'
                time.sleep(0.2)
        # the right application passes, and the backend gets the same headers as before
        # (this site hands none on; the console site hands on the five it always did)
        # (Caddy 2.7 also hands on the asked headers that the answer did not have, empty)
        status, body = _get(plain, '/page', 'app=node-red')
        assert status == 200 and body.startswith('BACKEND') and 'meta-app' not in body
        status, body = _get(console, '/console', 'app=infratak')
        assert status == 200 and 'x-authentik-username' in body and 'meta-app' not in body
        # an answer for another application is refused: this is the lock
        assert _get(plain, '/page', 'app=tak-portal') == (403, TEXT)
        assert _get(plain, '/page', 'app=node-red-2')[0] == 403
        assert _get(plain, '/page', 'app=Node-RED')[0] == 403
        # an answer that names no application is refused, also when the client names one
        assert _get(plain, '/page', 'noheader')[0] == 403
        assert _get(plain, '/page', 'noheader', {'X-Authentik-Meta-App': 'node-red'})[0] == 403
        assert _get(plain, '/page', 'app=tak-portal', {'X-Authentik-Meta-App': 'node-red'})[0] == 403
        # not signed in: the sign-in redirect, as before
        assert _get(plain, '/page', 'deny')[0] == 302
        # the console form: pages are compared, /api/* is not checked here (the console checks it)
        assert _get(console, '/console', 'app=tak-portal') == (403, TEXT)
        assert _get(console, '/console', 'deny')[0] == 302
        assert _get(console, '/api/x', 'deny') == (200, 'BACKEND ')
        assert _get(console, '/api/x', 'deny', {'X-Authentik-Meta-App': 'infratak'}) == (200, 'BACKEND ')
        assert _get(console, '/api/x', 'app=tak-portal') == (200, 'BACKEND ')
    finally:
        caddy.terminate()
        caddy.wait(timeout=10)
        srv.shutdown()
