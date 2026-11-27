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
"""An Authentik redis service that already exists is moved to the pin (ops #1147).

ops #637 pinned AUTHENTIK_REDIS_IMAGE, but the compose patchers only wrote it when the compose had
no redis service. A box deployed before the pin kept its floating tag, and the next pull of that
tag gave whatever it meant by then (8.12.0 came out Nov 22, untested). test12 and nuc both ran the
floating tag (verified Mon Nov 23, 2026).

app.py cannot be imported in a test, so the functions are cut out of it and run: the code under
test is the shipped text.
"""

import ast
import pathlib
import re

import pytest

yaml = pytest.importorskip('yaml')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
_WANT = {'_yaml_duplicate_keys', '_ensure_authentik_compose_patches', '_authentik_loopback_port',
         '_authentik_volume_is_docker_socket', '_authentik_strip_docker_socket'}   # the last two: ops #1103, called by the patcher
_HELPER = '_authentik_redis_image_target'   # added by the fix; optional here so the base branch fails on behaviour

PIN = 'docker.io/library/redis:8.10.3-alpine'
PG_CMD = 'postgres -c max_connections=300 -c shared_buffers=2GB -c effective_cache_size=6GB'


def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found at module level in app.py')


def _load(legacy=None):
    parts = []
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _WANT | {_HELPER}:
            parts.append(ast.get_source_segment(APP, node))
    assert len(parts) >= len(_WANT), 'a function under test was renamed or removed'
    ns = {
        'os': __import__('os'),
        're': re,
        '_authentik_pg_command_for_ram': lambda ram: (PG_CMD, 'test-tier'),
        '_local_ram_mb': lambda: 16000,
        'AUTHENTIK_REDIS_IMAGE': _const('AUTHENTIK_REDIS_IMAGE'),
        '_DOCKER_SOCKET_PATHS': _const('_DOCKER_SOCKET_PATHS'),
        '_ensure_authentik_compose_patches_legacy': legacy or (lambda *a, **k: pytest.fail('legacy patcher reached')),
        '_authentik_redis_seen_version': lambda image: '',   # ops #1306: no newer redis on this box
    }
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


NS = _load()


def TARGET(image):
    assert _HELPER in NS, f'{_HELPER} is missing from app.py'
    return NS[_HELPER](image)


def _compose(redis_image):
    """An existing box: server, worker and a redis service on the image the box was deployed with."""
    return f"""services:
  postgresql:
    healthcheck:
      interval: 30s
      retries: 5
      start_period: 20s
      test:
      - CMD-SHELL
      - pg_isready -d $${{POSTGRES_DB}} -U $${{POSTGRES_USER}}
      timeout: 5s
    image: docker.io/library/postgres:16-alpine
    command: {PG_CMD}
    restart: unless-stopped
  redis:
    command: --save 60 1 --loglevel warning
    healthcheck:
      interval: 30s
      retries: 5
      start_period: 20s
      test:
      - CMD-SHELL
      - redis-cli ping | grep PONG
      timeout: 3s
    image: {redis_image}
    restart: unless-stopped
    volumes:
    - redis:/data
  server:
    command: server
    environment:
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
    healthcheck:
      interval: 30s
      retries: 5
      start_period: 600s
      test:
      - CMD
      - ak
      - healthcheck
      timeout: 10s
    image: ${{AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}}:${{AUTHENTIK_TAG:-2026.8.3}}
  worker:
    command: worker
    environment:
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
    healthcheck:
      interval: 30s
      retries: 5
      start_period: 600s
      test:
      - CMD
      - ak
      - healthcheck
      timeout: 10s
    image: ${{AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}}:${{AUTHENTIK_TAG:-2026.8.3}}
volumes:
  database:
    driver: local
  redis:
"""


def _patch(path, ns=None):
    log = []
    return (ns or NS)['_ensure_authentik_compose_patches'](str(path), log.append), log


# ---- the proof: a compose with the floating tag comes back with the pin, a second run is a no-op

def test_existing_redis_on_the_floating_tag_is_moved_to_the_pin(tmp_path):
    f = tmp_path / 'docker-compose.yml'
    f.write_text(_compose('docker.io/library/redis:alpine'))
    changed, log = _patch(f)
    assert changed, log
    data = yaml.safe_load(f.read_text())
    assert data['services']['redis']['image'] == PIN
    assert any('Pinned redis image' in l and 'redis:alpine' in l for l in log), log
    assert 'redis:alpine' not in f.read_text()
    # the rest of the redis service is untouched
    assert data['services']['redis']['command'] == '--save 60 1 --loglevel warning'
    assert data['services']['redis']['volumes'] == ['redis:/data']


def test_second_run_changes_nothing(tmp_path):
    f = tmp_path / 'docker-compose.yml'
    f.write_text(_compose('redis:alpine'))
    _patch(f)
    first = f.read_text()
    changed, log = _patch(f)
    assert not changed and f.read_text() == first, log


@pytest.mark.parametrize('image', [
    'redis:alpine', 'redis', 'redis:latest', 'redis:7-alpine', 'redis:8-alpine', 'redis:8.10-alpine',
    'docker.io/library/redis:alpine', 'library/redis:alpine', '"redis:alpine"',
    'docker.io/library/redis:7.0.10', 'docker.io/library/redis:8.10.2-alpine', 'redis:8.10.2-alpine',
    'redis:7.4.1-alpine', 'redis:8.9.9',
])
def test_floating_tags_and_older_pins_move_to_the_pin(image):
    assert TARGET(image) == PIN, image


@pytest.mark.parametrize('image', [
    PIN,                                   # already the pin
    'redis:8.10.3-alpine',                 # the pin in the short form: no pointless recreate
    'redis:8.12.0-alpine',                 # newer than the pin: never a downgrade
    'redis:9.0.0-alpine',
    'redis:8.10.4',
    'valkey/valkey:8-alpine',              # not the redis image: the operator's choice
    'registry.example.com/mirror/redis:alpine',
    'redis@sha256:' + 'a' * 64,            # a digest pin is exact
    'redis:bookworm',                      # a variant we do not know
    '',
    None,
    5,
])
def test_pin_newer_versions_and_other_images_are_left_alone(image):
    assert TARGET(image) is None, image


def test_a_compose_already_on_the_pin_is_not_rewritten(tmp_path):
    f = tmp_path / 'docker-compose.yml'
    f.write_text(_compose(PIN))
    first = f.read_text()
    changed, log = _patch(f)
    assert not changed and f.read_text() == first, log


def test_a_newer_redis_is_not_downgraded(tmp_path):
    f = tmp_path / 'docker-compose.yml'
    f.write_text(_compose('docker.io/library/redis:8.12.0-alpine'))
    changed, log = _patch(f)
    assert not changed, log
    assert yaml.safe_load(f.read_text())['services']['redis']['image'] == 'docker.io/library/redis:8.12.0-alpine'


def test_a_compose_with_no_redis_service_still_gets_the_pin(tmp_path):
    f = tmp_path / 'docker-compose.yml'
    f.write_text(_compose(PIN).replace('  redis:\n    command', '  cache:\n    command', 1))
    changed, log = _patch(f)
    assert changed
    assert yaml.safe_load(f.read_text())['services']['redis']['image'] == PIN


# ---- the legacy (text) patcher gets the same rule

def _legacy_ns():
    parts = []
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in {'_ensure_authentik_compose_patches_legacy', _HELPER}:
            parts.append(ast.get_source_segment(APP, node))
    ns = {'os': __import__('os'), 're': re, '_authentik_pg_command_for_ram': lambda ram: (PG_CMD, 'test-tier'),
          '_local_ram_mb': lambda: 16000, 'AUTHENTIK_REDIS_IMAGE': _const('AUTHENTIK_REDIS_IMAGE'),
          '_DOCKER_SOCKET_PATHS': _const('_DOCKER_SOCKET_PATHS'),
          '_authentik_redis_seen_version': lambda image: ''}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


def test_legacy_text_patcher_moves_an_existing_redis_to_the_pin(tmp_path):
    ns = _legacy_ns()
    f = tmp_path / 'docker-compose.yml'
    f.write_text(_compose('docker.io/library/redis:alpine'))
    log = []
    assert ns['_ensure_authentik_compose_patches_legacy'](str(f), log.append), log
    text = f.read_text()
    assert f'    image: {PIN}\n' in text and 'redis:alpine' not in text
    assert 'docker.io/library/postgres:16-alpine' in text           # only the redis image moved
    first = text
    assert not ns['_ensure_authentik_compose_patches_legacy'](str(f), log.append)
    assert f.read_text() == first


# ---- wiring: the boot converge applies it to the running container, and the old test constants hold

def test_boot_converge_recreates_a_redis_container_that_runs_another_image():
    i = APP.index('# ops #1147 canary')
    block = APP[i:i + 1800]
    assert "'authentik-redis-1'" in block and '{{.Config.Image}}' in block
    assert 'force_up = True' in block
    # it sits before the single compose apply, so one `up -d` recreates only redis
    assert i < APP.index('# ── ONE compose apply for everything above ──')


def test_no_floating_redis_tag_is_written_into_app():
    # the helper names the floating forms by pattern, never as a literal image string
    assert 'redis:alpine' not in APP
