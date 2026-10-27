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
"""ops #198 — CloudTAK Deploy over an installed CloudTAK keeps the secrets it already has.

Found on a RHEL non-root box: Deploy (not Update config) over a local CloudTAK wrote .env
from scratch with a new SigningSecret and a new store key, and dropped GARAGE_RPC_SECRET, which
the Garage step then regenerated. Garage keeps the key it was first started with, so the store
crash-looped. The remote Deploy did the same. Update config already kept them.

run_cloudtak_deploy() is cut out of app.py and run up to the point the new .env is written
(app.py cannot be imported in a test), so the code under test is the shipped text.
"""

import ast
import datetime
import json
import os
import pathlib
import re
import shlex
import shutil
import tempfile
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

GARAGE_COMPOSE = """services:
    store:
        image: dxflrs/garage:v2.4.1
        environment:
            - GARAGE_RPC_SECRET=${GARAGE_RPC_SECRET}
"""

EXISTING_ENV = """CLOUDTAK_Mode=docker-compose
SigningSecret=sig-original
ASSET_BUCKET=cloudtak
AWS_S3_Endpoint=http://store:3900
AWS_S3_AccessKeyId=cloudtakminioadmin
AWS_S3_SecretAccessKey=store-original
MINIO_ROOT_USER=cloudtakminioadmin
MINIO_ROOT_PASSWORD=store-original
POSTGRES_PASSWORD=pg-original
GARAGE_RPC_SECRET=%s
""" % ('ab' * 32)

HELPERS = ('_cloudtak_build_env_content', '_cloudtak_env_secrets', '_cloudtak_env_preserve_unknown',
           '_cloudtak_store_endpoint', 'run_cloudtak_deploy')


class _Stop(Exception):
    """Raised by the first stub after .env is written: the deploy stops there."""


def _src():
    return '\n\n'.join(ast.get_source_segment(APP, n) for n in TREE.body
                       if isinstance(n, ast.FunctionDef) and n.name in HELPERS)


def _env(text):
    return dict(l.split('=', 1) for l in text.splitlines() if '=' in l and not l.startswith('#'))


def _ns(settings, **stubs):
    status = {'running': True}
    fake_sub = types.SimpleNamespace(
        run=lambda *a, **k: types.SimpleNamespace(returncode=0, stdout='true\n', stderr=''),
        TimeoutExpired=TimeoutError)
    ns = {
        'os': os, 're': re, 'json': json, 'shlex': shlex, 'shutil': shutil, 'tempfile': tempfile,
        'time': __import__('time'), 'datetime': datetime.datetime, 'subprocess': fake_sub,
        'load_settings': lambda: settings, 'save_settings': lambda s: None,
        '_get_cloudtak_deployment_config': lambda s: s['cloudtak_deployment'],
        '_get_service_domain': lambda s, k: '',
        '_get_cloudtak_target_release_tag': lambda use_cache=True: 'v13.113.0',
        '_cloudtak_release_cache': {'tag': None, 'ts': 0},
        '_REMOTE_DOCKER_GROUP_SH': 'true',   # row 5: remote step 2 joins the SSH user to docker
        'cloudtak_deploy_log': [], 'cloudtak_deploy_status': status,
    }
    ns.update(stubs)
    exec(compile(_src(), 'app.py', 'exec'), ns)
    return ns, status


# ── local Deploy ──────────────────────────────────────────────────────────────

@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    ct = tmp_path / 'CloudTAK'
    ct.mkdir()
    (ct / 'docker-compose.yml').write_text(GARAGE_COMPOSE)
    return tmp_path


def _local_deploy(settings):
    def _stop(*a, **k):
        raise _Stop()
    ns, status = _ns(
        settings,
        _docker_probe=lambda: (0, 'Docker version 27'),
        _ensure_docker_log_limits=lambda plog: None,
        _cloudtak_git_prep=lambda d, plog: None,
        _cloudtak_carry_plugins=lambda d, plog: [],   # ops #216
        _cloudtak_build_override_yml=_stop)       # the first call after .env is written
    ns['run_cloudtak_deploy']()
    return ns, status


LOCAL = {'cloudtak_deployment': {'target_mode': 'local'}, 'fqdn': 'example.com'}


def test_local_deploy_over_an_install_keeps_every_secret(home):
    (home / 'CloudTAK' / '.env').write_text(EXISTING_ENV + 'SOME_FUTURE_KEY=theirs\n')
    _local_deploy(dict(LOCAL))
    env = _env((home / 'CloudTAK' / '.env').read_text())
    assert env['SigningSecret'] == 'sig-original'
    assert env['AWS_S3_SecretAccessKey'] == 'store-original'
    assert env['MINIO_ROOT_PASSWORD'] == 'store-original'
    assert env['POSTGRES_PASSWORD'] == 'pg-original'
    assert env['GARAGE_RPC_SECRET'] == 'ab' * 32
    assert env['AWS_S3_Endpoint'] == 'http://store:3900'
    assert env['SOME_FUTURE_KEY'] == 'theirs'


def test_local_deploy_keeps_the_garage_key_when_only_it_is_there(home):
    # a Garage-era .env written by upstream's cloudtak.sh has no MINIO_ROOT_PASSWORD
    (home / 'CloudTAK' / '.env').write_text(
        'SigningSecret=s1\nAWS_S3_SecretAccessKey=garage-key\nPOSTGRES_PASSWORD=p\n')
    _local_deploy(dict(LOCAL))
    env = _env((home / 'CloudTAK' / '.env').read_text())
    assert env['AWS_S3_SecretAccessKey'] == env['MINIO_ROOT_PASSWORD'] == 'garage-key'
    assert env['SigningSecret'] == 's1'


def test_local_fresh_install_generates_the_secrets(home):
    ns, _ = _local_deploy(dict(LOCAL))
    env = _env((home / 'CloudTAK' / '.env').read_text())
    assert re.fullmatch(r'[0-9a-f]{64}', env['SigningSecret'])
    assert re.fullmatch(r'[0-9a-f]{32}', env['AWS_S3_SecretAccessKey'])
    assert env['MINIO_ROOT_PASSWORD'] == env['AWS_S3_SecretAccessKey']
    assert re.fullmatch(r'[0-9a-f]{48}', env['POSTGRES_PASSWORD'])
    assert 'GARAGE_RPC_SECRET' not in env          # the Garage step generates it, later
    assert not any('Preserving' in l for l in ns['cloudtak_deploy_log'])


def test_local_deploy_still_prefers_the_stored_postgis_password(home):
    (home / 'CloudTAK' / '.env').write_text(EXISTING_ENV)
    _local_deploy(dict(LOCAL, cloudtak_postgres_password='pg-from-settings'))
    env = _env((home / 'CloudTAK' / '.env').read_text())
    assert env['POSTGRES_PASSWORD'] == 'pg-from-settings'
    assert env['SigningSecret'] == 'sig-original'


# ── remote Deploy ─────────────────────────────────────────────────────────────

REMOTE = {'cloudtak_deployment': {'target_mode': 'remote', 'remote': {'host': '10.0.0.20'}},
          'fqdn': 'example.com'}


def _remote_deploy(settings, remote_env, env_read_ok=True):
    sent = {'cmds': []}

    def _ssh_probe(cfg, cmd, timeout=15):
        sent['cmds'].append(cmd)
        if cmd.startswith('cat ~/CloudTAK/.env'):
            return (True, remote_env) if env_read_ok else (False, 'ssh: connect timed out')
        if cmd == 'echo REMOTE_OK':
            return True, 'REMOTE_OK'
        return True, ''

    def _scp_to_host(cfg, local, remote):
        sent[remote] = pathlib.Path(local).read_text()
        return True, ''

    def _stop():
        raise _Stop()

    ns, status = _ns(
        settings,
        _ssh_probe=_ssh_probe, _scp_to_host=_scp_to_host,
        _ensure_docker_log_limits_remote=lambda cfg, log_fn=None: None,
        _cloudtak_remote_media_bufs=lambda cfg, plog: None,
        _cloudtak_remote_reclone_sh=lambda tag: 'RECLONE',
        _cloudtak_remote_store_endpoint=lambda cfg: 'http://store:3900',
        _cloudtak_build_override_yml=lambda s: 'services: {}\n',
        _cloudtak_remote_custom_compose_sh=_stop)   # the first call after .env is copied
    ns['run_cloudtak_deploy']()
    return ns, sent, status


def test_remote_deploy_over_an_install_keeps_every_secret():
    ns, sent, _ = _remote_deploy(dict(REMOTE), EXISTING_ENV)
    env = _env(sent['/tmp/.env'])
    assert env['SigningSecret'] == 'sig-original'
    assert env['AWS_S3_SecretAccessKey'] == env['MINIO_ROOT_PASSWORD'] == 'store-original'
    assert env['POSTGRES_PASSWORD'] == 'pg-original'
    assert env['GARAGE_RPC_SECRET'] == 'ab' * 32


def test_remote_deploy_reads_the_env_before_the_repo_prep():
    # the re-clone fallback deletes ~/CloudTAK, .env included
    _, sent, _ = _remote_deploy(dict(REMOTE), EXISTING_ENV)
    cat = next(i for i, c in enumerate(sent['cmds']) if c.startswith('cat ~/CloudTAK/.env'))
    assert cat < sent['cmds'].index('RECLONE')


def test_remote_deploy_stops_when_the_remote_env_cannot_be_read():
    _, sent, status = _remote_deploy(dict(REMOTE), EXISTING_ENV, env_read_ok=False)
    assert status.get('error') is True
    assert 'RECLONE' not in sent['cmds'] and '/tmp/.env' not in sent


def test_remote_fresh_install_generates_the_secrets():
    ns, sent, _ = _remote_deploy(dict(REMOTE), '')
    env = _env(sent['/tmp/.env'])
    assert re.fullmatch(r'[0-9a-f]{64}', env['SigningSecret'])
    assert re.fullmatch(r'[0-9a-f]{32}', env['AWS_S3_SecretAccessKey'])
    assert re.fullmatch(r'[0-9a-f]{48}', env['POSTGRES_PASSWORD'])
    assert 'GARAGE_RPC_SECRET' not in env


# ── the pre-start sweep keeps the database ───────────────────────────────────
# Box test for this fix: Deploy kept every secret, and then CloudTAK came back with an EMPTY
# database. The sweep before `up` ran `docker rm -f` on every cloudtak-* container, postgis
# included; its data lives in an anonymous volume, which only `up --force-recreate` carries to
# the new container, so compose made a fresh one. The old data sat orphaned on disk.

def _foreign():
    src = ast.get_source_segment(APP, next(n for n in TREE.body if isinstance(n, ast.FunctionDef)
                                           and n.name == '_cloudtak_foreign_containers'))
    ns = {}
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns['_cloudtak_foreign_containers']


def test_sweep_leaves_the_projects_own_containers_for_compose():
    ps = ('aaa111 cloudtak\n'          # cloudtak-postgis-1, ours: up --force-recreate keeps its volume
          'bbb222 \n'                  # an unlabeled leftover of a failed run
          'ccc333 cloudtak-dispatcher\n'
          'ddd444\n')
    assert _foreign()(ps, 'cloudtak') == ['bbb222', 'ccc333', 'ddd444']
    assert _foreign()('', 'cloudtak') == [] and _foreign()(None, 'cloudtak') == []


def test_local_deploy_sweeps_only_foreign_containers_before_up():
    body = ast.get_source_segment(APP, next(n for n in TREE.body if isinstance(n, ast.FunctionDef)
                                            and n.name == 'run_cloudtak_deploy'))
    code = re.sub(r'#.*', '', body)
    i_ps = code.index("'docker', 'ps', '-a', '--filter', 'name=cloudtak'")
    i_pick = code.index('_stale = _cloudtak_foreign_containers(_pre.stdout, _project)')
    i_up = code.index("'up', '-d', '--force-recreate'")
    assert i_ps < i_pick < i_up
    assert '{{.Label "com.docker.compose.project"}}' in code[i_ps:i_pick]
    # the old "every cloudtak-* id" sweep is gone
    assert "['docker', 'ps', '-aq', '--filter', 'name=cloudtak']" not in code


def test_remote_deploy_still_prefers_the_stored_postgis_password():
    _, sent, _ = _remote_deploy(dict(REMOTE, cloudtak_postgres_password='p' * 48), EXISTING_ENV)
    assert _env(sent['/tmp/.env'])['POSTGRES_PASSWORD'] == 'p' * 48
