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
"""The console password check on a box without OpenSSL scrypt (GH #137).

Field log (v10.2.14, Python 3.10 venv): removing ATLAS 500'd in
`_check_admin_password` → werkzeug `check_password_hash` → `hashlib.scrypt` with
`ValueError: [digital envelope routines] unsupported`. werkzeug's default hash is
scrypt, and an OpenSSL without it (FIPS mode) makes the check RAISE. Every login
and admin-password gate went through that call.

The contract pinned here: the check fails CLOSED (deny, never allow, never a 500),
an uncheckable stored hash says "reset the password" instead of "invalid password",
new hashes are PBKDF2-SHA256, and a good login upgrades an old scrypt hash.
"""

import ast
import hashlib
import pathlib
import re
import sys

import pytest

werkzeug_security = pytest.importorskip('werkzeug.security')

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
APP = (REPO / 'app.py').read_text(encoding='utf-8')

_FUNCS = {'verify_password', 'hash_password', '_hash_method_error', 'stored_hash_unusable',
          '_upgrade_password_hash', '_require_admin_password'}
_ASSIGNS = {'PASSWORD_HASH_METHOD', '_HASH_METHOD_ERRORS', 'check_password_hash',
            'generate_password_hash'}

FIPS_ERROR = '[digital envelope routines] unsupported'


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


@pytest.fixture
def ns():
    saved = []
    g = {
        'hashlib': hashlib,
        '_werkzeug_check_password_hash': werkzeug_security.check_password_hash,
        '_werkzeug_generate_password_hash': werkzeug_security.generate_password_hash,
        'save_auth': saved.append,
    }
    exec(SRC, g)
    g['saved'] = saved
    return g


@pytest.fixture
def no_scrypt(monkeypatch):
    """This box's OpenSSL has no scrypt — the reporter's exact error."""
    def scrypt(*a, **kw):
        raise ValueError(FIPS_ERROR)
    monkeypatch.setattr(hashlib, 'scrypt', scrypt)


# Made BEFORE scrypt goes away, like the reporter's stored hash.
SCRYPT_HASH = werkzeug_security.generate_password_hash('right-pw', method='scrypt')


# --------------------------------------------------------------------------- #
# verify_password fails closed
# --------------------------------------------------------------------------- #


def test_reporter_case_denies_instead_of_raising(ns, no_scrypt):
    with pytest.raises(ValueError):
        werkzeug_security.check_password_hash(SCRYPT_HASH, 'right-pw')   # the old 500
    assert ns['verify_password'](SCRYPT_HASH, 'right-pw') is False
    assert ns['verify_password'](SCRYPT_HASH, 'wrong') is False


def test_every_call_site_name_is_the_wrapper(ns, no_scrypt):
    # The ~25 inline `check_password_hash(...)` sites in app.py resolve to this name.
    assert ns['check_password_hash'] is ns['verify_password']
    assert ns['generate_password_hash'] is ns['hash_password']
    assert ns['check_password_hash'](SCRYPT_HASH, 'right-pw') is False


@pytest.mark.parametrize('pwhash', ['', None, 'garbage', 'scrypt:1:2$x$y', 'md5$a$b',
                                    'pbkdf2:nosuchdigest:1000$salt$abc'])
def test_bad_or_missing_hashes_deny(ns, pwhash):
    assert ns['verify_password'](pwhash, 'anything') is False


def test_a_working_box_still_verifies_scrypt(ns):
    assert ns['verify_password'](SCRYPT_HASH, 'right-pw') is True
    assert ns['verify_password'](SCRYPT_HASH, 'wrong') is False
    assert ns['stored_hash_unusable'](SCRYPT_HASH) is None


# --------------------------------------------------------------------------- #
# New hashes work without scrypt
# --------------------------------------------------------------------------- #


def test_new_hashes_are_pbkdf2_and_verify_without_scrypt(ns, no_scrypt):
    h = ns['hash_password']('new-pw')
    assert h.startswith('pbkdf2:sha256:')
    assert ns['verify_password'](h, 'new-pw') is True
    assert ns['verify_password'](h, 'nope') is False
    assert ns['stored_hash_unusable'](h) is None


# --------------------------------------------------------------------------- #
# The operator is told to reset, not to retype
# --------------------------------------------------------------------------- #


def test_uncheckable_hash_explains_the_way_out(ns, no_scrypt):
    msg = ns['stored_hash_unusable'](SCRYPT_HASH)
    assert msg and 'scrypt' in msg
    assert 'reset-console-password.sh' in msg
    assert FIPS_ERROR in msg


def test_admin_gate_answers_403_json_with_the_reason(ns, no_scrypt):
    flask = pytest.importorskip('flask')
    app = flask.Flask('gh137pw')
    ns.update(request=flask.request, jsonify=flask.jsonify,
              load_auth=lambda: {'password_hash': SCRYPT_HASH})
    with app.test_request_context(json={'password': 'right-pw'}):
        resp, status = ns['_require_admin_password']()
    assert status == 403
    body = resp.get_json()
    assert body['success'] is False
    assert 'reset-console-password.sh' in body['error']


def test_admin_gate_wrong_password_unchanged(ns):
    flask = pytest.importorskip('flask')
    app = flask.Flask('gh137pw2')
    h = ns['hash_password']('right-pw')
    ns.update(request=flask.request, jsonify=flask.jsonify, load_auth=lambda: {'password_hash': h})
    with app.test_request_context(json={'password': 'wrong'}):
        resp, status = ns['_require_admin_password']()
    assert (status, resp.get_json()['error']) == (403, 'Invalid admin password')
    with app.test_request_context(json={'password': 'right-pw'}):
        assert ns['_require_admin_password']() is None


# --------------------------------------------------------------------------- #
# Upgrade on a good login
# --------------------------------------------------------------------------- #


def test_good_login_upgrades_a_scrypt_hash(ns):
    auth = {'password_hash': SCRYPT_HASH, 'created': 'then'}
    ns['_upgrade_password_hash'](auth, 'right-pw')
    assert len(ns['saved']) == 1
    new = ns['saved'][0]
    assert new['password_hash'].startswith('pbkdf2:sha256:')
    assert new['created'] == 'then'
    assert ns['verify_password'](new['password_hash'], 'right-pw') is True
    assert auth['password_hash'] == SCRYPT_HASH, 'caller dict mutated'


def test_pbkdf2_hash_is_left_alone(ns):
    ns['_upgrade_password_hash']({'password_hash': ns['hash_password']('pw')}, 'pw')
    assert ns['saved'] == []


def test_upgrade_failure_never_breaks_login(ns):
    def boom(_a):
        raise OSError('read-only config')
    ns['save_auth'] = boom
    ns['_upgrade_password_hash']({'password_hash': SCRYPT_HASH}, 'right-pw')   # no raise


def test_login_routes_upgrade_only_after_success_and_explain_failure():
    for name in ('login', 'index'):
        node = next(n for n in ast.parse(APP).body
                    if isinstance(n, ast.FunctionDef) and n.name == name)
        body = ast.get_source_segment(APP, node)
        ok = body.index("if check_password_hash(auth['password_hash']")
        up = body.index('_upgrade_password_hash(auth')
        sess = body.index("session['authenticated'] = True")
        assert ok < up < sess, name
        assert "stored_hash_unusable(auth['password_hash']) or 'Invalid password'" in body, name


# --------------------------------------------------------------------------- #
# The registry gate (modules/__init__._check_admin_password)
# --------------------------------------------------------------------------- #


def test_registry_gate_denies_with_reason(ns, no_scrypt):
    import modules as mod_registry
    ctx = {'load_auth': lambda: {'password_hash': SCRYPT_HASH},
           'verify_password': ns['verify_password'],
           'stored_hash_unusable': ns['stored_hash_unusable']}
    err = mod_registry._check_admin_password(ctx, {'password': 'right-pw'})
    assert err and 'reset-console-password.sh' in err


def test_registry_gate_fails_closed_without_the_seam(no_scrypt):
    """A ctx without verify_password (tests, old callers) falls back to werkzeug — its
    raise is still a deny, not an exception out of the route."""
    import modules as mod_registry
    ctx = {'load_auth': lambda: {'password_hash': SCRYPT_HASH}}
    assert mod_registry._check_admin_password(ctx, {'password': 'right-pw'}) == 'Invalid admin password'


def test_registry_gate_fails_closed_when_the_check_raises():
    import modules as mod_registry

    def raising(h, p):
        raise RuntimeError('boom')
    ctx = {'load_auth': lambda: {'password_hash': 'x'}, 'verify_password': raising}
    assert mod_registry._check_admin_password(ctx, {'password': 'pw'}) == 'Invalid admin password'


def test_registry_gate_passes_a_good_password(ns, no_scrypt):
    import modules as mod_registry
    h = ns['hash_password']('pw')
    ctx = {'load_auth': lambda: {'password_hash': h}, 'verify_password': ns['verify_password']}
    assert mod_registry._check_admin_password(ctx, {'password': 'pw'}) is None
    assert mod_registry._check_admin_password(ctx, {'password': 'no'}) == 'Invalid admin password'
    assert mod_registry._check_admin_password(ctx, {}) == 'Invalid admin password'


def test_app_hands_the_registry_the_seam():
    assert "'verify_password': verify_password," in APP
    assert "'stored_hash_unusable': stored_hash_unusable," in APP
    assert "mod_registry._check_admin_password({'load_auth': load_auth,\n" \
           "                                           'verify_password': verify_password}" in APP


# --------------------------------------------------------------------------- #
# One hash method everywhere
# --------------------------------------------------------------------------- #


def test_app_never_calls_raw_werkzeug_outside_the_wrappers():
    assert len(re.findall(r'^from werkzeug\.security import', APP, re.M)) == 1
    raw = [m.start() for m in re.finditer(r'_werkzeug_(check|generate)_password_hash\(', APP)]
    spans = []
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name in ('verify_password', 'hash_password'):
            lines = APP.splitlines(keepends=True)
            start = sum(len(l) for l in lines[:node.lineno - 1])
            end = sum(len(l) for l in lines[:node.end_lineno])
            spans.append((start, end))
    assert raw and all(any(s <= p < e for s, e in spans) for p in raw)


@pytest.mark.parametrize('script', ['start.sh', 'reset-console-password.sh'])
def test_shell_scripts_hash_with_the_same_method(ns, script):
    text = (REPO / script).read_text(encoding='utf-8')
    calls = re.findall(r'generate_password_hash\(([^)]*)\)', text)
    assert calls, script
    for args in calls:
        assert f"method='{ns['PASSWORD_HASH_METHOD']}'" in args, (script, args)
