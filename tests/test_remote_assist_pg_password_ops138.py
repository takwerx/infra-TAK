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
"""Remote Assist Deploy/Update never rotates the DB password of an existing database (ops #138).

Postgres takes POSTGRES_PASSWORD only when its data volume is first created. Deploy and Update
used to write the saved password or a random one, so a box with none saved got a .env its own
database had never seen and Remote Assist could not log in. Now the password in use is adopted
(.env, then the postgres container), a new one is made only when there is no database, and
after the rebuild the role is set to match .env — a no-op unless an earlier Update broke it.
"""

import base64
import hashlib
import hmac
import os
import re
import secrets
import types

REPO = __import__('pathlib').Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
HELPERS = (APP[APP.index('def _remote_assist_compose_files('):APP.index('def _ensure_authentik_remote_assist_app(')]
           + APP[APP.index('def _remote_assist_env_value('):APP.index('def _run_remote_assist_deploy(')])


def _r(rc=0, out='', err=''):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def _ns(responder):
    calls = []

    def run(argv, **kw):
        calls.append((argv, kw))
        return responder(argv, kw)

    n = {'os': os, 're': re, 'secrets': secrets, 'hashlib': hashlib, 'hmac': hmac, '_b64': base64,
         'subprocess': types.SimpleNamespace(run=run)}
    exec(compile(HELPERS, 'app.py', 'exec'), n)
    return n, calls


def _docker(container_env=None, volume=False):
    """Fake docker: a postgres container with `container_env` (None = no container)."""
    def respond(argv, kw):
        if argv[:3] == ['docker', 'ps', '-a']:
            return _r(out='abc123\n' if container_env is not None else '')
        if argv[:2] == ['docker', 'inspect']:
            return _r(out=''.join(f'{k}={v}\n' for k, v in (container_env or {}).items()))
        if argv[:3] == ['docker', 'volume', 'ls']:
            return _r(out='eud-remote-assist_postgres_data\n' if volume else '')
        raise AssertionError(f'unexpected command {argv}')
    return respond


def _ra_dir(tmp_path, env=None):
    d = tmp_path / 'eud-remote-assist'
    d.mkdir()
    if env is not None:
        (d / '.env').write_text(''.join(f'{k}={v}\n' for k, v in env.items()))
    return str(d)


# ── which password ────────────────────────────────────────────────────────────────────────────

def test_saved_password_is_used_as_is(tmp_path):
    n, calls = _ns(_docker())
    ra = _ra_dir(tmp_path, {'POSTGRES_PASSWORD': 'in-env'})
    assert n['_remote_assist_pg_password'](ra, {'remote_assist_pg_password': 'saved'}, lambda m: None) == 'saved'
    assert calls == []


def test_no_saved_password_and_existing_db_adopts_env(tmp_path):
    # test6/test8/test12: .env from the first deploy, nothing in settings.json.
    logs = []
    n, calls = _ns(_docker({'POSTGRES_PASSWORD': 'in-env'}))
    ra = _ra_dir(tmp_path, {'POSTGRES_USER': 'cfd', 'POSTGRES_PASSWORD': 'in-env', 'POSTGRES_DB': 'x'})
    assert n['_remote_assist_pg_password'](ra, {}, logs.append) == 'in-env'
    assert calls == []
    assert any('.env' in m for m in logs)


def test_no_saved_password_no_env_adopts_running_container(tmp_path):
    n, calls = _ns(_docker({'PATH': '/usr/bin', 'POSTGRES_PASSWORD': 'from-container'}))
    ra = _ra_dir(tmp_path)
    assert n['_remote_assist_pg_password'](ra, {}, lambda m: None) == 'from-container'
    ps = calls[0][0]
    assert f'label=com.docker.compose.project.working_dir={ra}' in ps
    assert 'label=com.docker.compose.service=postgres' in ps


def test_fresh_deploy_makes_a_new_password(tmp_path):
    logs = []
    n, _ = _ns(_docker())
    pw = n['_remote_assist_pg_password'](_ra_dir(tmp_path), {}, logs.append)
    assert re.fullmatch(r'[0-9a-f]{48}', pw)
    assert logs == []


def test_existing_volume_without_any_password_warns(tmp_path):
    logs = []
    n, calls = _ns(_docker(volume=True))
    pw = n['_remote_assist_pg_password'](_ra_dir(tmp_path), {}, logs.append)
    assert re.fullmatch(r'[0-9a-f]{48}', pw)
    assert any('Existing database' in m for m in logs)
    assert 'label=com.docker.compose.project=eud-remote-assist' in calls[-1][0]


def test_docker_missing_counts_as_no_database(tmp_path):
    def boom(argv, kw):
        raise FileNotFoundError('docker')
    n, _ = _ns(boom)
    assert n['_remote_assist_db_state'](_ra_dir(tmp_path)) == (False, '')


# ── verifier check ────────────────────────────────────────────────────────────────────────────

def _scram(password, salt=b'0123456789abcdef', iters=4096):
    salted = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iters)
    stored = hashlib.sha256(hmac.new(salted, b'Client Key', hashlib.sha256).digest()).digest()
    server = hmac.new(salted, b'Server Key', hashlib.sha256).digest()
    b = lambda x: base64.b64encode(x).decode()
    return f'SCRAM-SHA-256${iters}:{b(salt)}${b(stored)}:{b(server)}'


def test_verifier_check():
    n, _ = _ns(_docker())
    m = n['_remote_assist_pw_matches']
    assert m(_scram('right') + '\n', 'right', 'cfd')
    assert not m(_scram('right'), 'wrong', 'cfd')
    md5 = 'md5' + hashlib.md5(b'rightcfd').hexdigest()
    assert m(md5, 'right', 'cfd') and not m(md5, 'wrong', 'cfd')
    assert not m('', 'right', 'cfd') and not m('SCRAM-SHA-256$junk', 'right', 'cfd')


# ── making the database match .env ────────────────────────────────────────────────────────────

def _psql(verifier, alter_rc=0):
    def respond(argv, kw):
        if '-c' in argv:
            return _r(out=verifier + '\n')
        if 'psql' in argv:
            return _r(rc=alter_rc, err=f"ERROR: x\nLINE 1: ALTER ROLE CURRENT_USER PASSWORD '{kw['input']}'")
        return _r()
    return respond


def test_sync_is_a_noop_when_the_password_matches(tmp_path):
    logs = []
    n, calls = _ns(_psql(_scram('pw')))
    ra = _ra_dir(tmp_path, {'POSTGRES_USER': 'cfd', 'POSTGRES_PASSWORD': 'pw'})
    assert n['_remote_assist_sync_db_password'](ra, 'pw', logs.append) is False
    assert len(calls) == 1
    assert calls[0][0][:7] == ['docker', 'compose', '-f', os.path.join(ra, 'docker-compose.yml'), 'exec', '-T', 'postgres']
    assert any('matches' in m for m in logs)


def test_sync_repairs_a_rotated_password_and_restarts_the_server(tmp_path):
    # A box an earlier Update already broke: .env and settings hold the new password, the DB the old.
    logs = []
    n, calls = _ns(_psql(_scram('old')))
    ra = _ra_dir(tmp_path, {'POSTGRES_USER': 'cfd', 'POSTGRES_PASSWORD': "n'ew"})
    assert n['_remote_assist_sync_db_password'](ra, "n'ew", logs.append) is True
    alter_argv, alter_kw = calls[1]
    assert alter_kw['input'] == "ALTER ROLE CURRENT_USER PASSWORD 'n''ew';\n"
    assert not any("n'ew" in a for a in alter_argv)            # never on the command line
    assert calls[2][0][-2:] == ['restart', 'server']
    assert any('restarted the server' in m for m in logs)


def test_failed_alter_does_not_log_the_password(tmp_path):
    logs = []
    n, calls = _ns(_psql(_scram('old'), alter_rc=3))
    ra = _ra_dir(tmp_path, {'POSTGRES_PASSWORD': 'secretpw'})
    assert n['_remote_assist_sync_db_password'](ra, 'secretpw', logs.append) is False
    assert len(calls) == 2                                      # no restart
    assert not any('secretpw' in m for m in logs)


def test_sync_check_failure_changes_nothing(tmp_path):
    logs = []
    n, calls = _ns(lambda argv, kw: _r(rc=1, err='service "postgres" is not running'))
    ra = _ra_dir(tmp_path, {'POSTGRES_PASSWORD': 'pw'})
    assert n['_remote_assist_sync_db_password'](ra, 'pw', logs.append) is False
    assert len(calls) == 1
    assert any('not running' in m for m in logs)


# ── wiring ────────────────────────────────────────────────────────────────────────────────────

def _body(start, end):
    return APP[APP.index(start):APP.index(end)]


def test_deploy_and_update_never_generate_their_own_password():
    for start, end in (('def _run_remote_assist_deploy(', 'def _remote_assist_github_repo_path('),
                       ('def _run_remote_assist_update(', "@app.route('/api/remote-assist/version')")):
        body = _body(start, end)
        assert 'token_hex' not in body, start
        pw = body.index('pg_password = _remote_assist_pg_password(ra_dir, settings, plog)')
        env = body.index('_remote_assist_write_env(ra_dir, settings, client_id, pg_password)')
        up = body.index("_remote_assist_compose_cmd(ra_dir, 'up', '-d', '--build')")
        sync = body.index('_remote_assist_sync_db_password(ra_dir, pg_password, plog)')
        save = body.index("s['remote_assist_pg_password'] = pg_password")
        assert pw < env < up < sync < save, start
