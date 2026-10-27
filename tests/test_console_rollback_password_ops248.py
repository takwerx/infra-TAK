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
"""POST /api/console/rollback password gate (ops #248).

The route checked the password against settings.json['auth'] — a key no box has; the
console password lives in auth.json — so it answered "Incorrect password" to every
request and the documented way off a bad release never worked. It now goes through
the shared fail-closed gate (_require_admin_password / load_auth).

The route is exercised for real (its source is lifted out of app.py by AST and run
under a Flask test client); git and the restart are stubbed, so nothing here touches
the machine. The strictness half pins that no request shape gets past the gate.
"""

import ast
import pathlib
import re
import sys

import pytest

flask = pytest.importorskip('flask')
werkzeug_security = pytest.importorskip('werkzeug.security')

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
APP = (REPO / 'app.py').read_text(encoding='utf-8')

_FUNCS = {'verify_password', 'hash_password', '_hash_method_error', 'stored_hash_unusable',
          '_require_admin_password', 'console_rollback_api'}
_ASSIGNS = {'PASSWORD_HASH_METHOD', '_HASH_METHOD_ERRORS', 'check_password_hash',
            'generate_password_hash'}


def _load():
    parts = []
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name in _FUNCS:
            parts.append(ast.get_source_segment(APP, node))
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
              and getattr(node.targets[0], 'id', None) in _ASSIGNS):
            parts.append(ast.get_source_segment(APP, node))
    assert len(parts) == len(_FUNCS) + len(_ASSIGNS), 'a name under test was renamed or removed'
    return '\n\n'.join(parts)


SRC = _load()

PASSWORD = 'right-pw'
PWHASH = werkzeug_security.generate_password_hash(PASSWORD, method='pbkdf2:sha256')


class _Calls(list):
    pass


@pytest.fixture
def box():
    """A console whose settings.json has NO 'auth' key (like every real box) and whose
    auth.json holds the password hash; one rollback snapshot is available."""
    state = {
        'auth': {'password_hash': PWHASH},
        'settings': {'console_rollback': {'available': True, 'tag': 'v10.2.30',
                                          'version': '10.2.30'}},
        'runs': _Calls(),
        'restarts': _Calls(),
    }

    class _R:
        def __init__(self, rc=0):
            self.returncode, self.stdout, self.stderr = rc, '', ''

    def _run(argv, **kw):
        state['runs'].append(argv)
        return _R(0)

    def _save(s):
        state['settings'] = s

    subprocess = type('subprocess', (), {'run': staticmethod(_run)})
    app = flask.Flask(__name__)
    g = {
        'jsonify': flask.jsonify, 'request': flask.request, 'os': __import__('os'),
        'subprocess': subprocess, '__file__': str(REPO / 'app.py'),
        'hashlib': __import__('hashlib'),
        '_werkzeug_check_password_hash': werkzeug_security.check_password_hash,
        '_werkzeug_generate_password_hash': werkzeug_security.generate_password_hash,
        'load_auth': lambda: state['auth'],
        'load_settings': lambda: state['settings'],
        'save_settings': _save,
        '_detached_console_restart': lambda: state['restarts'].append(1),
    }
    exec(SRC, g)
    app.add_url_rule('/api/console/rollback', view_func=g['console_rollback_api'],
                     methods=['POST'])
    state['client'] = app.test_client()
    return state


def _post(box, **kw):
    return box['client'].post('/api/console/rollback', **kw)


# --------------------------------------------------------------------------- #
# The reporter's case: right password, password in auth.json
# --------------------------------------------------------------------------- #


def test_right_password_is_accepted_and_rolls_back(box):
    assert 'auth' not in box['settings']          # the real shape: no settings['auth']
    r = _post(box, json={'password': PASSWORD})
    assert r.status_code == 200, r.get_json()
    d = r.get_json()
    assert d['ok'] is True and d['tag'] == 'v10.2.30'
    assert any(a[-2:] == ['checkout', 'v10.2.30'] or 'v10.2.30' in a for a in box['runs'])
    assert box['restarts'] == [1]
    assert box['settings']['console_rollback'] == {'available': False}


def test_wrong_password_is_rejected_and_nothing_runs(box):
    r = _post(box, json={'password': 'wrong'})
    assert r.status_code == 403
    d = r.get_json()
    assert d['ok'] is False and d['error']
    assert box['runs'] == [] and box['restarts'] == []
    assert box['settings']['console_rollback']['available'] is True   # snapshot untouched


# --------------------------------------------------------------------------- #
# The gate stays strict: no request shape bypasses it
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize('kw', [
    {},                                                     # no body at all (old UI)
    {'json': {}},
    {'json': {'password': ''}},
    {'json': {'password': None}},
    {'json': {'password': 12345}},
    {'json': {'password': ['right-pw']}},
    {'json': {'pasword': PASSWORD}},                        # misspelt key
    {'json': {'password': PASSWORD + ' '}},
    {'json': {'password': PASSWORD.upper()}},
    {'data': 'password=right-pw',                           # form body, not JSON
     'content_type': 'application/x-www-form-urlencoded'},
    {'data': 'not json', 'content_type': 'application/json'},
    {'json': {'ok': True, 'skip_password': True, 'auth': {'password_hash': PWHASH}}},
])
def test_no_bypass(box, kw):
    r = _post(box, **kw)
    assert r.status_code == 403, kw
    assert r.get_json()['ok'] is False
    assert box['runs'] == [] and box['restarts'] == []


def test_password_hash_in_settings_json_is_not_trusted(box):
    # The old (wrong) store must not become an alternative way in.
    box['auth'] = {}
    box['settings']['auth'] = {'password_hash': PWHASH}
    r = _post(box, json={'password': PASSWORD})
    assert r.status_code == 403
    assert box['runs'] == []


@pytest.mark.parametrize('auth', [{}, {'password_hash': ''}, {'password_hash': 'garbage'},
                                  {'password_hash': None}])
def test_missing_or_broken_stored_hash_denies(box, auth):
    box['auth'] = auth
    r = _post(box, json={'password': PASSWORD})
    assert r.status_code == 403
    assert box['runs'] == [] and box['restarts'] == []


def test_password_checked_before_snapshot_state_leaks(box):
    # A wrong password must not reveal whether a rollback is available.
    box['settings']['console_rollback'] = {'available': False}
    r = _post(box, json={'password': 'wrong'})
    assert r.status_code == 403
    assert 'rollback' not in (r.get_json().get('error') or '').lower()


def test_right_password_but_nothing_to_roll_back(box):
    box['settings']['console_rollback'] = {'available': False}
    r = _post(box, json={'password': PASSWORD})
    assert r.status_code == 400
    assert box['runs'] == [] and box['restarts'] == []


# --------------------------------------------------------------------------- #
# Source / UI pins
# --------------------------------------------------------------------------- #


def _route_src():
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name == 'console_rollback_api':
            return ast.get_source_segment(APP, node), node
    raise AssertionError('console_rollback_api missing')


def test_route_uses_shared_gate_and_login_required():
    src, node = _route_src()
    assert '_require_admin_password(' in src
    assert "load_settings().get('auth'" not in src, 'settings.json has no auth key (ops #248)'
    decos = [ast.get_source_segment(APP, d) for d in node.decorator_list]
    assert 'login_required' in decos, decos


@pytest.mark.parametrize('rel', ['templates/console.html', 'templates/help.html',
                                 'static/guarddog.js'])
def test_every_ui_sends_the_password(rel):
    text = (REPO / rel).read_text(encoding='utf-8')
    posts = re.findall(r"fetch\('/api/console/rollback'[^;]*;", text)
    assert posts, rel
    for p in posts:
        assert 'password' in p and "'Content-Type':'application/json'" in p, (rel, p)


@pytest.mark.parametrize('rel', ['templates/console.html', 'templates/help.html'])
def test_console_and_help_prompt_before_posting(rel):
    text = (REPO / rel).read_text(encoding='utf-8')
    body = text[text.index('async function doConsoleRollback()'):]
    body = body[:body.index('\n}\n')]
    assert body.index('prompt(') < body.index("fetch('/api/console/rollback'")
    assert 'if(!pw)return' in body      # cancel / empty never posts
