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
"""CloudTAK >= 13.102.0: the MinIO -> Garage store switch through our own buttons (v10.2.7).

CloudTAK v13.102.0 (2026-10-02, PR #1847) moved its object store to Garage and its web app
from api/web/ to app/. v10.2.0 had made our .env writers Garage-aware; the rest was on the
ROADMAP "for when Garage is in a release". Measured on test12 2026-10-07 through the Update
button: "CloudTAK is running" was reported while the store crash-looped on
    Error: Invalid RPC secret key: expected 32 bytes of random hex
and every installed plugin was left in api/web/plugins, where Vite no longer looks.

The store step mirrors upstream's `cloudtak.sh migrate-store`. These tests pin its order, that
nothing is archived until the copy verified, the rollback, and that .env keys we do not own are
left byte-identical. app.py cannot be imported in a test, so the functions are cut out of it.
"""

import ast
import os
import pathlib
import re
import shlex
import secrets

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_FUNCS = {
    '_cloudtak_store_endpoint', '_cloudtak_compose_is_garage', '_cloudtak_env_read',
    '_cloudtak_env_set', '_cloudtak_migrate_minio_to_garage', '_cloudtak_garage_converge',
    '_cloudtak_garage_rollback', '_cloudtak_web_dir', '_cloudtak_plugins_dir',
    '_cloudtak_remote_garage_sh',
}

GARAGE_COMPOSE = """services:
    store:
        image: dxflrs/garage:v2.4.1
        command: /garage server --single-node --default-bucket
        ports:
            - 127.0.0.1:3900:3900
        environment:
            - GARAGE_RPC_SECRET=${GARAGE_RPC_SECRET}
    minio-legacy:
        profiles: ['migrate']
        image: ${MINIO_LEGACY_IMAGE:-quay.io/minio/minio:RELEASE.2024-08-17T01-24-54Z}
"""
MINIO_COMPOSE = """services:
    store:
        image: quay.io/minio/minio:RELEASE.2024-08-17T01-24-54Z
        command: server /data
"""
ENV = """# CloudTAK .env (written by infra-TAK)
ASSET_BUCKET=cloudtak
AWS_S3_Endpoint=http://store:9000
AWS_S3_AccessKeyId=cloudtak
AWS_S3_SecretAccessKey=abc123
MINIO_ROOT_USER=cloudtak
MINIO_ROOT_PASSWORD=abc123
OPERATOR_KEY=keep me exactly   # with a comment
"""


def _load():
    tree = ast.parse(APP)
    parts = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in _FUNCS:
            parts.append(ast.get_source_segment(APP, node))
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id.startswith('_CT_') for t in node.targets):
            parts.append(ast.get_source_segment(APP, node))
    names = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert _FUNCS <= names, 'a function under test was renamed or removed'
    ns = {'os': os, 're': re, 'shlex': shlex, 'secrets': secrets,
          'time': type('T', (), {'sleep': staticmethod(lambda s: None),
                                 'strftime': staticmethod(lambda f: '20261007_235959')}),
          'subprocess': None, '_sudo_wrap': lambda a: a}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


class Compose:
    """Records `docker compose` calls; fails the first call whose args contain `fail_on`."""
    def __init__(self, fail_on=None):
        self.calls, self.fail_on = [], fail_on

    def __call__(self, cloudtak_dir, args, timeout=600):
        self.calls.append(list(args))
        if self.fail_on and self.fail_on in args:
            return 1, 'boom: ' + self.fail_on
        if 'sync' in args:
            return 0, '2026/10/07 INFO  : a.png: Copied (new)\n2026/10/07 INFO  : b.kml: Copied (new)\n'
        return 0, ''


@pytest.fixture
def ct(tmp_path):
    (tmp_path / 'docker-compose.yml').write_text(GARAGE_COMPOSE)
    (tmp_path / '.env').write_text(ENV)
    return tmp_path


def _ns(compose, legacy='quay.io/minio/minio:RELEASE.2024-08-17T01-24-54Z'):
    ns = _load()
    ns['_cloudtak_compose_run'] = compose
    ns['_cloudtak_legacy_minio_image'] = lambda d: legacy
    ns['_cloudtak_revert_checkout'] = lambda *a, **k: True
    return ns


def test_minio_era_tree_is_left_alone(tmp_path):
    (tmp_path / 'docker-compose.yml').write_text(MINIO_COMPOSE)
    (tmp_path / '.env').write_text(ENV)
    c = Compose()
    ok, err = _ns(c)['_cloudtak_garage_converge'](str(tmp_path), lambda m: None)
    assert ok and err == '' and c.calls == []
    assert (tmp_path / '.env').read_text() == ENV


def test_fresh_garage_install_gets_secret_and_endpoint_only(ct):
    c, log = Compose(), []
    ok, err = _ns(c)['_cloudtak_garage_converge'](str(ct), log.append, start=False)
    assert ok, err
    env = (ct / '.env').read_text()
    sec = re.search(r'(?m)^GARAGE_RPC_SECRET=(\w+)$', env).group(1)
    assert re.fullmatch(r'[0-9a-f]{64}', sec)
    assert 'AWS_S3_Endpoint=http://store:3900' in env and 'store:9000' not in env
    assert 'OPERATOR_KEY=keep me exactly   # with a comment' in env    # not ours: byte-identical
    assert c.calls == []                                               # no .docker-store, no start
    # a second pass changes nothing (the secret is the store's identity — never regenerated)
    ok, _ = _ns(c)['_cloudtak_garage_converge'](str(ct), log.append, start=False)
    assert ok and (ct / '.env').read_text() == env


def test_all_zero_or_short_secret_is_replaced(ct):
    (ct / '.env').write_text(ENV + 'GARAGE_RPC_SECRET=' + '0' * 64 + '\n')
    _ns(Compose())['_cloudtak_garage_converge'](str(ct), lambda m: None, start=False)
    sec = re.search(r'(?m)^GARAGE_RPC_SECRET=(\w+)$', (ct / '.env').read_text()).group(1)
    assert sec != '0' * 64 and re.fullmatch(r'[0-9a-f]{64}', sec)
    assert (ct / '.env').read_text().count('GARAGE_RPC_SECRET=') == 1


def test_migration_runs_upstreams_steps_in_order_then_archives(ct):
    (ct / '.docker-store' / 'cloudtak').mkdir(parents=True)
    c, log = Compose(), []
    ok, err = _ns(c)['_cloudtak_garage_converge'](str(ct), log.append, start=False)
    assert ok, err
    flat = [' '.join(a) for a in c.calls]
    want = ['stop api events tiles retention',
            '--profile migrate up -d --pull missing store minio-legacy',
            '--profile migrate run --rm --quiet-pull migrate lsd garage:',
            '--profile migrate run --rm --quiet-pull migrate lsd minio:',
            '--profile migrate run --rm --quiet-pull migrate sync -v minio:cloudtak garage:cloudtak',
            '--profile migrate run --rm --quiet-pull migrate check --size-only minio:cloudtak garage:cloudtak',
            '--profile migrate rm -sf minio-legacy']
    assert flat == want
    assert not (ct / '.docker-store').exists()
    assert (ct / '.docker-store-migrated-20261007_235959' / 'cloudtak').is_dir()
    assert 'MINIO_LEGACY_IMAGE' not in (ct / '.env').read_text()   # only while migrating
    assert any('2 file(s) copied' in l for l in log)


@pytest.mark.parametrize('fail_on', ['sync', 'check', 'minio-legacy'])
def test_failed_migration_never_moves_the_minio_data(ct, fail_on):
    (ct / '.docker-store' / 'cloudtak').mkdir(parents=True)
    c = Compose(fail_on=fail_on)
    ok, err = _ns(c)['_cloudtak_garage_converge'](str(ct), lambda m: None, start=False)
    assert not ok and err
    assert (ct / '.docker-store' / 'cloudtak').is_dir()
    assert not list(ct.glob('.docker-store-migrated-*'))


def test_no_cached_minio_image_is_a_clear_refusal(ct):
    (ct / '.docker-store').mkdir()
    c = Compose()
    ok, err = _ns(c, legacy='')['_cloudtak_garage_converge'](str(ct), lambda m: None, start=False)
    assert not ok and 'no MinIO image is cached' in err and 'safe' in err
    assert c.calls == [] and (ct / '.docker-store').is_dir()


def test_rollback_to_a_minio_tree_restores_env_and_sets_garage_aside(ct):
    (ct / '.env').write_text(ENV.replace('store:9000', 'store:3900')
                             + 'GARAGE_RPC_SECRET=' + 'a' * 64 + '\nMINIO_LEGACY_IMAGE=x\n')
    (ct / '.docker-garage' / 'meta').mkdir(parents=True)
    ns, c = _ns(Compose()), None
    c = ns['_cloudtak_compose_run']
    # the revert puts the MinIO-era compose back
    ns['_cloudtak_revert_checkout'] = lambda *a, **k: (ct / 'docker-compose.yml').write_text(MINIO_COMPOSE)
    log = []
    ns['_cloudtak_garage_rollback'](str(ct), 'f' * 40, log.append)
    env = (ct / '.env').read_text()
    assert 'AWS_S3_Endpoint=http://store:9000' in env
    assert 'GARAGE_RPC_SECRET' not in env and 'MINIO_LEGACY_IMAGE' not in env
    assert 'OPERATOR_KEY=keep me exactly   # with a comment' in env
    assert not (ct / '.docker-garage').exists() and list(ct.glob('.docker-garage-failed-*'))
    assert c.calls[-1] == ['up', '-d']


def test_web_dir_follows_the_tree(tmp_path):
    ns = _load()
    (tmp_path / 'api' / 'web' / 'src').mkdir(parents=True)
    assert ns['_cloudtak_plugins_dir'](str(tmp_path)) == str(tmp_path / 'api' / 'web' / 'plugins')
    (tmp_path / 'app' / 'src').mkdir(parents=True)
    assert ns['_cloudtak_plugins_dir'](str(tmp_path)) == str(tmp_path / 'app' / 'plugins')


def test_remote_script_quotes_a_valid_image_and_drops_an_invalid_one():
    ns = _load()
    sh = ns['_cloudtak_remote_garage_sh']('quay.io/minio/minio:RELEASE.2024-08-17T01-24-54Z')
    assert "MINIO_LEGACY_IMAGE=quay.io/minio/minio:RELEASE.2024-08-17T01-24-54Z ./cloudtak.sh migrate-store" in sh
    bad = ns['_cloudtak_remote_garage_sh']('x; rm -rf /')
    assert 'rm -rf' not in bad and 'MINIO_LEGACY_IMAGE' not in bad and './cloudtak.sh migrate-store' in bad


def _body(name):
    return re.search(rf'^def {name}\(.*?(?=^def )', APP, re.S | re.M).group(0)


def test_update_runs_the_store_step_before_the_build_and_captures_minio_first():
    body = re.sub(r'#.*', '', _body('run_cloudtak_update'))
    i_capture = body.index('legacy_minio_img = _cloudtak_legacy_minio_image(cloudtak_dir)')
    i_checkout = body.index("'checkout', '-f'") if "'checkout', '-f'" in body else body.index('checkout -f {release_tag}')
    i_store = body.index('_cloudtak_garage_converge(cloudtak_dir, plog, legacy_image=legacy_minio_img, start=False)')
    i_build = body.index('Step 3/3: Rebuilding and restarting')
    assert i_capture < i_checkout < i_store < i_build
    assert '_cloudtak_garage_rollback(cloudtak_dir, prev_sha, plog)' in body
    assert '_cloudtak_remote_garage_rollback(remote_cfg, prev_sha, plog)' in body
    assert 'plugins_base = _cloudtak_plugins_dir(cloudtak_dir)' in body


def test_every_env_writer_runs_the_store_step():
    for fn in ('run_cloudtak_deploy', 'run_cloudtak_redeploy'):
        body = re.sub(r'#.*', '', _body(fn))
        assert '_cloudtak_garage_converge(cloudtak_dir, plog, start=False)' in body, fn
        assert '_cloudtak_remote_garage_sh(' in body, fn


def test_no_plugin_path_is_hardcoded_to_api_web_any_more():
    code = re.sub(r'#.*', '', APP)
    hits = [m.start() for m in re.finditer(r"'api', 'web', 'plugins'", code)]
    # only the "look in both roots" list in the update path may still name the old root
    assert len(hits) == 1
    assert '_plugin_bases_before' in code[hits[0] - 200:hits[0]]
