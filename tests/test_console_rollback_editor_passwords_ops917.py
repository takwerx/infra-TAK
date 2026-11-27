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
"""Console rollback and the MediaMTX web editor's hashed passwords (ops #917).

Web editor 2.1.15 and later store passwords as hashes. 2.1.14 and earlier compare the typed text
with the stored text, so a hash locks every account out. Rolling the console back to a release
that pins editor 2.1.14 leaves the newer editor file on the box, and that release's own "Patch web
editor" then downloads 2.1.14. The older console cannot be changed, so the rollback (still the
newer code) must give every hashed account a plain random password BEFORE it checks out the
older release, and must stop, changing nothing, when it cannot.

The password script runs for real (a temp users.json, `python -I -`, as on a box). The route is
lifted out of app.py by AST and run under a Flask test client with git and the editor stubbed, so
the order (passwords first, checkout second) is what is checked.
"""

import ast
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

flask = pytest.importorskip('flask')
werkzeug_security = pytest.importorskip('werkzeug.security')

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _src(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], 'id', None) == name):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py (ops #917 not applied)')


def _ns(*names, **extra):
    g = {'re': re, 'os': os, 'json': json, 'subprocess': subprocess, 'time': __import__('time')}
    g.update(extra)
    exec('\n\n'.join(_src(n) for n in names), g)
    return g


# --------------------------------------------------------------------------- #
# The password script, run for real
# --------------------------------------------------------------------------- #

SCRIPT = None


def _script():
    return _ns('_MEDIAMTX_EDITOR_UNHASH_SCRIPT')['_MEDIAMTX_EDITOR_UNHASH_SCRIPT']


def _run_script(users_file):
    r = subprocess.run([sys.executable, '-I', '-', str(users_file)], input=_script(),
                       capture_output=True, text=True, timeout=60)
    return [ln for ln in r.stdout.splitlines() if ln.startswith('MTXRESET ')]


def _hashed(pw):
    return werkzeug_security.generate_password_hash(pw)   # scrypt:..$salt$hex, as the editor stores


@pytest.fixture
def editor_dir(tmp_path):
    d = tmp_path / 'mediamtx-webeditor'
    d.mkdir()
    return d


def test_hashed_accounts_get_plain_passwords_and_the_file_is_written_first(editor_dir):
    uf = editor_dir / 'users.json'
    admin_hash, op_hash = _hashed('old-admin-pw'), _hashed('old-op-pw')
    assert re.match(r'^(scrypt|pbkdf2):[^$]+\$[^$]+\$[0-9a-f]+$', admin_hash)
    uf.write_text(json.dumps([
        {'username': 'admin', 'password': admin_hash, 'role': 'admin'},
        {'username': 'op', 'password': op_hash, 'role': 'user'},
        {'username': 'legacy', 'password': 'already-plain', 'role': 'user'},
    ]))
    lines = _run_script(uf)

    users = {u['username']: u for u in json.loads(uf.read_text())}
    # Every account can now be checked by an editor that compares plain text.
    assert users['admin']['password'] != admin_hash and users['op']['password'] != op_hash
    assert not re.match(r'^(scrypt|pbkdf2):', users['admin']['password'])
    assert not re.match(r'^(scrypt|pbkdf2):', users['op']['password'])
    assert users['legacy']['password'] == 'already-plain'          # untouched
    assert users['admin']['role'] == 'admin'                        # nothing else changed
    # The new passwords are in the root/account-only file, one line each.
    pwf = editor_dir / 'initial_admin_password.txt'
    assert oct(pwf.stat().st_mode & 0o777) == '0o600'
    body = pwf.read_text()
    assert f"admin: {users['admin']['password']}" in body and f"op: {users['op']['password']}" in body
    assert 'legacy' not in body
    assert oct(uf.stat().st_mode & 0o777) == '0o600'
    # The console gets the names and the admin password only.
    assert 'MTXRESET reset ["admin", "op"]' in lines
    assert f"MTXRESET admin {users['admin']['password']}" in lines
    assert not any(users['op']['password'] in ln for ln in lines)


def test_second_run_finds_nothing_to_do(editor_dir):
    uf = editor_dir / 'users.json'
    uf.write_text(json.dumps([{'username': 'admin', 'password': _hashed('x'), 'role': 'admin'}]))
    assert any(ln.startswith('MTXRESET reset') for ln in _run_script(uf))
    first = uf.read_text()
    assert _run_script(uf) == ['MTXRESET none']
    assert uf.read_text() == first


def test_no_hashed_accounts_and_no_file_change_nothing(editor_dir):
    uf = editor_dir / 'users.json'
    assert _run_script(uf) == ['MTXRESET none']                   # editor never started
    assert not uf.exists() and not (editor_dir / 'initial_admin_password.txt').exists()
    uf.write_text(json.dumps([{'username': 'admin', 'password': 'plain', 'role': 'admin'}]))
    before = uf.read_text()
    assert _run_script(uf) == ['MTXRESET none']
    assert uf.read_text() == before
    assert not (editor_dir / 'initial_admin_password.txt').exists()


def test_when_the_password_file_cannot_be_written_users_json_is_not_changed(editor_dir):
    uf = editor_dir / 'users.json'
    h = _hashed('keep-me')
    uf.write_text(json.dumps([{'username': 'admin', 'password': h, 'role': 'admin'}]))
    (editor_dir / 'initial_admin_password.txt').mkdir()           # cannot be opened as a file
    lines = _run_script(uf)
    assert len(lines) == 1 and lines[0].startswith('MTXRESET fail'), lines
    assert json.loads(uf.read_text())[0]['password'] == h         # still the hash: nothing lost


def test_a_planted_link_for_the_password_file_is_not_followed(editor_dir, tmp_path):
    uf = editor_dir / 'users.json'
    h = _hashed('keep-me')
    uf.write_text(json.dumps([{'username': 'admin', 'password': h, 'role': 'admin'}]))
    victim = tmp_path / 'victim.txt'
    victim.write_text('do not touch')
    os.symlink(victim, editor_dir / 'initial_admin_password.txt')
    lines = _run_script(uf)
    assert lines and lines[0].startswith('MTXRESET fail'), lines
    assert victim.read_text() == 'do not touch'
    assert json.loads(uf.read_text())[0]['password'] == h


def test_a_users_file_that_is_not_a_list_is_a_failure_not_a_crash(editor_dir):
    uf = editor_dir / 'users.json'
    uf.write_text('{"admin": "x"}')
    lines = _run_script(uf)
    assert lines and lines[0].startswith('MTXRESET fail')


# --------------------------------------------------------------------------- #
# Which releases need it
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize('ref,expected', [
    ('v2.1.14', True), ('2.1.14', True), ('v2.1.0', True), ('v2.0.99', True), ('v1.9.9', True),
    ('v2.1.15', False), ('v2.1.16', False), ('v2.2.0', False), ('v3.0.0', False), ('v2.1.100', False),
    ('main', False), ('dev', False), ('', False), (None, False), ('v2.1.14-rc1', False),
])
def test_only_editor_pins_older_than_hashing_need_the_reset(ref, expected):
    g = _ns('_MEDIAMTX_EDITOR_HASHING_SINCE', '_mediamtx_editor_ref_lacks_hashing')
    assert g['_mediamtx_editor_ref_lacks_hashing'](ref) is expected


def _git(cwd, *args):
    subprocess.run(['git', '-c', 'user.email=t@example.invalid', '-c', 'user.name=t',
                    '-c', 'commit.gpgsign=false'] + list(args), cwd=cwd, check=True,
                   capture_output=True, text=True)


def test_the_pin_is_read_from_the_old_releases_own_app_py_not_from_the_checkout(tmp_path):
    repo = tmp_path / 'repo'
    repo.mkdir()
    _git(repo, 'init', '-q')
    (repo / 'app.py').write_text('X = 1\nMEDIAMTX_EDITOR_REF = "v2.1.14"\nY = 2\n')
    _git(repo, 'add', 'app.py')
    _git(repo, 'commit', '-q', '-m', 'old release')
    old = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=repo, capture_output=True, text=True,
                         check=True).stdout.strip()
    (repo / 'app.py').write_text('MEDIAMTX_EDITOR_REF = "v2.1.16"\n')   # what the box runs now
    _git(repo, 'commit', '-q', '-a', '-m', 'new release')
    g = _ns('_console_release_editor_ref')
    assert g['_console_release_editor_ref'](str(repo), old) == 'v2.1.14'
    assert g['_console_release_editor_ref'](str(repo), 'HEAD') == 'v2.1.16'
    # A release with no such line, or a name git does not know, answers '' (no reset).
    (repo / 'app.py').write_text('Z = 3\n')
    _git(repo, 'commit', '-q', '-a', '-m', 'no pin')
    assert g['_console_release_editor_ref'](str(repo), 'HEAD') == ''
    assert g['_console_release_editor_ref'](str(repo), 'no-such-release') == ''
    # A stored value that looks like a git option never reaches git.
    for bad in ('--help', '-p', '', None, 'a b', 'x;y'):
        assert g['_console_release_editor_ref'](str(repo), bad) == ''


# --------------------------------------------------------------------------- #
# What the console does with the script's answer
# --------------------------------------------------------------------------- #


def _unhash(output, installed=True):
    state = {}
    ran = state.setdefault('ran', [])
    g = _ns('_mediamtx_editor_unhash_for_rollback',
            detect_modules=lambda: {'mediamtx': {'installed': installed}},
            _mediamtx_editor_run_users_script=lambda settings, script: (ran.append(1), output)[1],
            _MEDIAMTX_EDITOR_UNHASH_SCRIPT='SCRIPT',
            _mediamtx_editor_login_load=lambda: dict(state.get('login', {})),
            _mediamtx_editor_login_target=lambda settings: 'local',
            _mediamtx_editor_login_save=lambda st: state.__setitem__('login', dict(st)))
    return g['_mediamtx_editor_unhash_for_rollback']({}), state


def test_admin_password_is_kept_for_the_mediamtx_page_to_show_once():
    res, state = _unhash('MTXRESET reset ["admin", "op"]\nMTXRESET admin NewPw123\n')
    assert res == {'state': 'reset', 'count': 2}
    assert state['login']['reveal'] == 'NewPw123' and state['login']['user'] == 'admin'
    assert state['login']['ok'] is True and state['login']['target'] == 'local'


def test_other_accounts_only_are_reset_without_a_reveal():
    res, state = _unhash('MTXRESET reset ["op"]\n')
    assert res == {'state': 'reset', 'count': 1}
    assert 'login' not in state


def test_nothing_to_reset_is_not_an_error():
    assert _unhash('MTXRESET none\n')[0] == {'state': 'none', 'count': 0}


def test_a_box_without_mediamtx_never_runs_the_script_and_is_never_blocked():
    # Most boxes have no MediaMTX: the script has nothing to run on there (no account, no folder),
    # and "no answer" is a failure that stops the rollback. It must not even be tried.
    res, state = _unhash('', installed=False)
    assert res == {'state': 'none', 'count': 0}
    assert state['ran'] == []


@pytest.mark.parametrize('out', ['', 'MTXRESET fail OSError\n', 'garbage', 'MTXRESET admin x\n'])
def test_no_clear_answer_is_a_failure(out):
    # An SSH blip or a crash must never read as "nothing to do": that would roll back and lock out.
    assert _unhash(out)[0]['state'] == 'fail'


# --------------------------------------------------------------------------- #
# The rollback route: checkout first (ops #1330), passwords second, stop and put back on failure
# --------------------------------------------------------------------------- #

PASSWORD = 'right-pw'
PWHASH = werkzeug_security.generate_password_hash(PASSWORD, method='pbkdf2:sha256')

_ROUTE_FUNCS = ['verify_password', 'hash_password', '_hash_method_error', 'stored_hash_unusable',
                '_require_admin_password', 'console_rollback_api',
                # ops #1330: the route makes sure the release is on the box, and checks out first
                '_rollback_git', '_rollback_resolve_target', '_rollback_current_ref',
                '_console_release_const', '_rollback_pin_short', '_rollback_pin_changes',
                '_rollback_pin_message', '_rollback_redis_hazard', '_rollback_redis_hazard_here',
                '_console_release_app_has']
_ROUTE_ASSIGNS = ['PASSWORD_HASH_METHOD', '_HASH_METHOD_ERRORS', 'check_password_hash',
                  'generate_password_hash', '_ROLLBACK_REPO_URL', '_ROLLBACK_REF_RE',
                  '_ROLLBACK_SHA_RE', '_ROLLBACK_PIN_WATCH']


def _route(ref, unhash_result):
    log = []
    state = {'settings': {'console_rollback': {'available': True, 'tag': 'v10.2.30'}}, 'log': log,
             'restarts': []}

    class _R:
        returncode, stdout, stderr = 0, '', ''

    def _run(argv, **kw):
        r = _R()
        if 'checkout' in argv:
            log.append('checkout')
            return r
        log.append('git')
        if 'rev-parse' in argv and '--verify' in argv:
            r.stdout = 'a' * 40          # the release's commit
        elif 'rev-parse' in argv:
            r.stdout = 'b' * 40
        elif 'symbolic-ref' in argv:
            r.stdout = 'dev'
        elif 'grep' in argv:
            r.returncode = 1
        return r

    def _unhash_stub(settings):
        log.append('reset')
        return unhash_result

    g = {
        'jsonify': flask.jsonify, 'request': flask.request, 'os': os, 're': re,
        'subprocess': type('subprocess', (), {'run': staticmethod(_run)}), '__file__': str(REPO / 'app.py'),
        'hashlib': __import__('hashlib'),
        '_werkzeug_check_password_hash': werkzeug_security.check_password_hash,
        '_werkzeug_generate_password_hash': werkzeug_security.generate_password_hash,
        'load_auth': lambda: {'password_hash': PWHASH},
        'load_settings': lambda: state['settings'],
        'save_settings': lambda s: state.__setitem__('settings', s),
        '_detached_console_restart': lambda: state['restarts'].append(1),
        '_console_release_editor_ref': lambda d, t: ref,
        '_mediamtx_editor_ref_lacks_hashing': lambda r: r == 'v2.1.14',
        '_mediamtx_editor_unhash_for_rollback': _unhash_stub,
    }
    parts = [_src(n) for n in _ROUTE_FUNCS + _ROUTE_ASSIGNS if n not in g]
    exec('\n\n'.join(parts), g)
    app = flask.Flask(__name__)
    app.add_url_rule('/api/console/rollback', view_func=g['console_rollback_api'], methods=['POST'])
    state['client'] = app.test_client()
    return state


def _post(state):
    return state['client'].post('/api/console/rollback', json={'password': PASSWORD})


def test_rollback_to_a_release_pinning_editor_2_1_14_resets_passwords_after_the_checkout():
    st = _route('v2.1.14', {'state': 'reset', 'count': 2})
    r = _post(st)
    assert r.status_code == 200, r.get_json()
    d = r.get_json()
    assert d['ok'] is True and d['editor_passwords_reset'] == 2
    assert 'new passwords' in d['message'] and 'MediaMTX page' in d['message']
    assert '<' not in d['message']                      # shown as HTML by the console page
    log = st['log']
    assert 'reset' in log, 'the rollback never changed the editor passwords'
    # ops #1330: the older release is checked out FIRST; a checkout that cannot be made no longer
    # leaves the passwords changed with the console still on the new version.
    assert log.index('checkout') < log.index('reset')
    assert st['restarts'] == [1]


def test_rollback_stops_with_nothing_changed_when_the_passwords_cannot_be_changed():
    st = _route('v2.1.14', {'state': 'fail', 'count': 0})
    r = _post(st)
    assert r.status_code == 500
    d = r.get_json()
    assert d['ok'] is False and 'Nothing was changed' in d['error']
    # checked out, the reset failed, checkout put back (a second one), no restart
    assert [x for x in st['log'] if x in ('checkout', 'reset')] == ['checkout', 'reset', 'checkout']
    assert st['restarts'] == []
    assert st['settings']['console_rollback']['available'] is True    # can be tried again


@pytest.mark.parametrize('ref', ['v2.1.16', 'v2.1.15', 'main', ''])
def test_a_release_whose_editor_reads_hashes_leaves_the_passwords_alone(ref):
    st = _route(ref, {'state': 'reset', 'count': 5})
    r = _post(st)
    assert r.status_code == 200
    assert 'reset' not in st['log']
    assert r.get_json()['editor_passwords_reset'] == 0
    assert 'new passwords' not in r.get_json()['message']


def test_pin_old_but_nothing_hashed_rolls_back_with_the_plain_message():
    st = _route('v2.1.14', {'state': 'none', 'count': 0})
    r = _post(st)
    d = r.get_json()
    assert r.status_code == 200 and d['ok'] is True
    assert 'new passwords' not in d['message'] and d['editor_passwords_reset'] == 0


def test_the_real_route_calls_the_reset_after_the_first_git_checkout():
    route = _src('console_rollback_api')
    assert route.index("'checkout'") < route.index('_mediamtx_editor_unhash_for_rollback(')
