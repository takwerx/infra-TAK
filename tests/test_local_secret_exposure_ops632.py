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
"""ops #632 — secrets other local users (tak, postgres) could read.

Every local account can read a 0644 file and every process's argv (`ps`). These pin:
module .env files are 0600 from the moment they exist; the TAK admin key never lands
at a fixed /tmp path; the TAK cert password and Postgres passwords never ride in argv;
the MediaMTX editor's Authentik token is not in its 0644 unit file; and the Postfix
SMTP password is 0600 before it is written. The helpers are cut out of app.py and run
here (app.py cannot be imported in a test), so the code under test is the shipped text.
"""

import ast
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
EMAILRELAY = (REPO / 'modules' / 'emailrelay.py').read_text(encoding='utf-8')


def _fn(name):
    node = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(APP, node)


def _assign(name):
    node = next(n for n in TREE.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return ast.get_source_segment(APP, node)


def _load(*names, **extra):
    ns = {'os': os, 'subprocess': subprocess, 'tempfile': tempfile, 'shutil': shutil}
    ns.update(extra)
    for n in names:
        try:
            src = _fn(n)
        except StopIteration:
            src = _assign(n)
        exec(compile(src, f'app.py:{n}', 'exec'), ns)
    return ns


# ── module .env files: 0600 at creation ─────────────────────────────────────

def test_new_secret_file_is_0600_even_with_a_loose_umask(tmp_path):
    ns = _load('_open_secret_w')
    p = tmp_path / '.env'
    old = os.umask(0o022)
    try:
        with ns['_open_secret_w'](str(p)) as f:
            f.write('AUTHENTIK_SECRET_KEY=s3cret\n')
    finally:
        os.umask(old)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert p.read_text() == 'AUTHENTIK_SECRET_KEY=s3cret\n'


def test_existing_0644_secret_file_is_tightened_on_rewrite(tmp_path):
    ns = _load('_open_secret_w')
    p = tmp_path / '.env'
    p.write_text('OLD=1\n')
    os.chmod(p, 0o644)
    with ns['_open_secret_w'](str(p)) as f:
        f.write('NEW=2\n')
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert p.read_text() == 'NEW=2\n'


def test_no_module_env_is_written_with_a_plain_open():
    # Every module .env (Authentik, CloudTAK, TAK Portal, Node-RED, remote assist) and the
    # CloudTAK remote staging copy. A plain open() creates them 0644 until the next restart.
    bad = re.findall(r"with open\((\w*env\w*), 'w'\)", APP)
    assert bad == [], bad
    assert APP.count('with _open_secret_w(env_path)') >= 20


def test_remote_staging_secrets_use_private_temp_files():
    # A fixed /tmp name can be pre-created by another local user (and was 0644).
    assert "'/tmp/authentik_remote.env'" not in APP
    assert "'/tmp/nodered_env'" not in APP
    assert 'chmod 600 ~/authentik/.env' in APP
    assert APP.count('chmod 600 ~/CloudTAK/.env') == 2


# ── TAK admin key and cert password ─────────────────────────────────────────

def test_takserver_groups_keeps_the_admin_key_in_a_private_dir():
    src = _fn('takserver_groups')
    assert "admin_key = '/tmp/" not in src and "'/tmp/tak-admin-curl.key'" not in src
    assert 'mkdtemp(' in src and 'shutil.rmtree(_work' in src
    assert 'pass:' not in src and 'shell=True' not in src


@pytest.mark.parametrize('name', ['takserver_groups', '_p12_bytes_to_pem'])
def test_cert_password_never_in_openssl_argv(name):
    src = _fn(name)
    assert 'pass:' not in src
    assert '_openssl_pass_env(' in src


def test_no_console_run_openssl_puts_the_password_in_argv():
    # The two remaining `pass:` hits are root-run renewal SCRIPTS (separate follow-up);
    # every openssl the console runs itself must use the environment.
    hits = [m.start() for m in re.finditer(r'-pass(in|out)? pass:\{', APP)]
    assert hits == []
    lines = [ln for ln in APP.splitlines() if '-password pass:{' in ln]
    assert len(lines) == 2 and all('"$' in ln for ln in lines), lines   # shell-script text only


def test_p12_to_pem_password_reaches_openssl_only_through_env(tmp_path):
    if not shutil.which('openssl'):
        pytest.skip('no openssl')
    pw = 'Sup3r-s3cret-pw'
    key, crt, p12 = tmp_path / 'k.pem', tmp_path / 'c.pem', tmp_path / 'b.p12'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                    '-out', str(crt), '-days', '1', '-subj', '/CN=ops632'],
                   check=True, capture_output=True)
    env = dict(os.environ, P=pw)
    subprocess.run(['openssl', 'pkcs12', '-export', '-in', str(crt), '-inkey', str(key),
                    '-out', str(p12), '-passout', 'env:P'], check=True, capture_output=True, env=env)
    seen = []

    def spy(args, **kw):
        seen.append(list(args))
        return subprocess.run(args, **kw)

    ns = _load('_OPENSSL_PASS_ENV', '_openssl_pass_env', '_p12_bytes_to_pem',
               subprocess=type('S', (), {'run': staticmethod(spy)}))
    cert_pem, key_pem = ns['_p12_bytes_to_pem'](p12.read_bytes(), pw)
    assert 'BEGIN CERTIFICATE' in cert_pem and 'PRIVATE KEY' in key_pem
    assert seen and all(pw not in ' '.join(a) for a in seen)


# ── Postgres passwords ──────────────────────────────────────────────────────

def test_no_docker_exec_carries_pgpassword_in_argv():
    assert "f'PGPASSWORD={pw}'" not in APP
    assert "WITH PASSWORD '{pw}'\"]" not in APP      # the postgis ALTER USER was a -c arg


# ── MediaMTX editor unit ────────────────────────────────────────────────────

UNIT = """[Unit]
Description=MediaMTX Web Configuration Editor

[Service]
Type=simple
Environment=PORT=5080
Environment=LDAP_ENABLED=1
Environment=AUTHENTIK_TOKEN=tok-123
Environment=INFRATAK_MEDIAMTX_TRUSTED_PROXIES=127.0.0.1
Restart=always
User=takwerx
"""


def test_editor_unit_token_moves_to_the_env_file():
    ns = _load('_MEDIAMTX_EDITOR_SECRET_ENV', '_MEDIAMTX_EDITOR_ENVFILE_LINE',
               '_unit_text_token_to_envfile')
    out, tok = ns['_unit_text_token_to_envfile'](UNIT)
    assert tok == 'tok-123'
    assert 'AUTHENTIK_TOKEN' not in out
    assert 'EnvironmentFile=-/usr/local/etc/mediamtx-webeditor.env' in out
    assert 'Environment=LDAP_ENABLED=1' in out and 'User=takwerx' in out
    again, tok2 = ns['_unit_text_token_to_envfile'](out)
    assert again == out and tok2 is None                       # idempotent


def test_editor_env_file_is_created_empty_at_600_before_the_token():
    writes = []
    ns = _load('_MEDIAMTX_EDITOR_SECRET_ENV', '_mediamtx_editor_secret_env_text',
               '_write_mediamtx_editor_secret_env',
               _write_priv=lambda p, c, mode='w', perm=None: writes.append((p, c, perm)))
    ns['_write_mediamtx_editor_secret_env']('tok-123')
    assert writes[0] == ('/usr/local/etc/mediamtx-webeditor.env', '', 0o600)
    assert writes[1][2] == 0o600 and 'AUTHENTIK_TOKEN=tok-123' in writes[1][1]


def test_no_editor_unit_text_carries_the_token():
    assert "f'Environment=AUTHENTIK_TOKEN={ak_token_val}" not in APP
    assert _fn('_startup_converge_mediamtx_overlay').count('_unit_text_token_to_envfile(') == 1


# ── Postfix SASL password ───────────────────────────────────────────────────

def test_sasl_passwd_is_0600_before_the_password_is_written():
    empty = EMAILRELAY.index("ctx['_write_priv']('/etc/postfix/sasl_passwd', '', perm=0o600)")
    full = EMAILRELAY.index("ctx['_write_priv']('/etc/postfix/sasl_passwd', sasl_line + '\\n', perm=0o600)")
    assert empty < full
