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
"""The redis pin never moves a floating tag back to an older redis (ops #1306, GH #759).

10.4.8 moved an existing Authentik redis on the floating `alpine` tag to the pin, 8.10.3. On a
box where that tag had already pulled 8.12.0, the 8.12.0 container saved an RDB v17 dump on stop,
8.10.3 could not read it ("Can't handle RDB format version 17") and redis crash-looped.

Two parts: the pin asks Docker which redis the floating tag really ran, and the boot converge
un-sticks boxes already in the loop by moving the unreadable dump aside.

app.py cannot be imported in a test, so the functions are cut out of it and run: the code under
test is the shipped text.
"""

import ast
import pathlib
import re
import subprocess as _real_subprocess

import pytest

yaml = pytest.importorskip('yaml')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

PIN = 'docker.io/library/redis:8.10.3-alpine'
PG_CMD = 'postgres -c max_connections=300 -c shared_buffers=2GB -c effective_cache_size=6GB'
FATAL = "# Can't handle RDB format version 17\n# Fatal error loading the DB, check server logs. Exiting.\n"


def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found at module level in app.py')


def _const_or(name, default):
    try:
        return _const(name)
    except AssertionError:
        return default


def _src(*names, optional=()):
    parts = {}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in set(names) | set(optional):
            parts[node.name] = ast.get_source_segment(APP, node)
    missing = set(names) - set(parts)
    assert not missing, f'missing from app.py: {sorted(missing)}'
    return '\n\n'.join(parts[n] for n in (*names, *optional) if n in parts)


class _R:
    def __init__(self, rc=0, out='', err=''):
        self.returncode, self.stdout, self.stderr = rc, out, err


class FakeDocker:
    """Answers the docker calls the redis helpers make. `container` / `images` map a name to the
    redis version it carries (None: not on the box)."""

    def __init__(self, container=None, images=None, state='true true', logs='', fail=None,
                 broken=False):
        self.container, self.images = container, images or {}
        self.state, self.logs, self.fail, self.broken = state, logs, fail or {}, broken
        self.calls = []

    @staticmethod
    def _env(ver):
        return f'PATH=/usr/local/bin\nREDIS_VERSION={ver}\n' if ver else 'PATH=/usr/local/bin\n'

    def run(self, argv, **kw):
        argv = list(argv)
        self.calls.append(argv)
        if self.broken:
            return _R(1, '', 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock.')
        if argv[:4] == ['docker', 'inspect', '--type', 'container']:
            if self.container is None:
                return _R(1, '', f'Error: No such container: {argv[-1]}')
            return _R(0, self._env(self.container))
        if argv[:4] == ['docker', 'inspect', '--type', 'image']:
            ver = self.images.get(argv[-1], 'absent')
            if ver == 'absent':
                return _R(1, '', f'Error: No such image: {argv[-1]}')
            return _R(0, self._env(ver))
        if argv[:2] == ['docker', 'inspect']:
            if self.container is None:
                return _R(1, '', 'Error: No such object: authentik-redis-1')
            return _R(0, self.state + '\n')
        if argv[:2] == ['docker', 'logs']:
            return _R(0, self.logs)
        if argv[:2] == ['docker', 'compose']:
            sub = argv[2]
            return _R(self.fail.get(sub, 0), f'{sub} output')
        return _R(0)

    @property
    def compose(self):
        return [c[2] for c in self.calls if c[:2] == ['docker', 'compose']]


def _ns(docker, *names, optional=()):
    ns = {
        'os': __import__('os'), 're': re,
        'subprocess': type('S', (), {'run': staticmethod(docker.run), 'PIPE': _real_subprocess.PIPE,
                                     'STDOUT': _real_subprocess.STDOUT}),
        'time': type('T', (), {'time': staticmethod(lambda: 1764190000), 'sleep': staticmethod(lambda s: None)}),
        '_sudo_wrap': lambda argv: list(argv),
        'AUTHENTIK_REDIS_IMAGE': _const('AUTHENTIK_REDIS_IMAGE'),
        '_DOCKER_SOCKET_PATHS': _const('_DOCKER_SOCKET_PATHS'),
        '_AK_REDIS_RDB_FATAL': _const_or('_AK_REDIS_RDB_FATAL', None),   # added by the fix
        '_AK_COMPOSE_LOCK_WAIT_S': 90,
        '_authentik_pg_command_for_ram': lambda ram: (PG_CMD, 'test-tier'),
        '_local_ram_mb': lambda: 16000,
    }

    class _Lock:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return True

        def __exit__(self, *a):
            return False

    ns['_authentik_compose_lock'] = _Lock
    exec(compile(_src(*names, optional=optional), 'app.py', 'exec'), ns)
    return ns


def _target(docker, image):
    # the version lookup is added by the fix: optional here so the base branch fails on behaviour
    ns = _ns(docker, '_authentik_redis_image_target', optional=('_authentik_redis_seen_version',))
    return ns['_authentik_redis_image_target'](image)


# ---- the proof: the reporter's box. `alpine` ran 8.12.0, so the pin (8.10.3) is a downgrade

def test_floating_alpine_that_ran_a_newer_redis_is_not_pinned_back():
    d = FakeDocker(container='8.12.0', images={'docker.io/library/redis:alpine': '8.12.0'})
    assert _target(d, 'docker.io/library/redis:alpine') is None


def test_newer_local_image_alone_blocks_the_pin():
    # the tag was pulled to 8.12.0 but the container still runs 8.10.2: a recreate would
    # start 8.12.0, and the pin must not undo that later either
    d = FakeDocker(container='8.10.2', images={'redis:alpine': '8.12.0'})
    assert _target(d, 'redis:alpine') is None


def test_newer_container_alone_blocks_the_pin():
    # the container (which wrote the dump) is newer than what the tag points at now
    d = FakeDocker(container='8.12.0', images={'redis:alpine': '8.10.1'})
    assert _target(d, 'redis:alpine') is None


@pytest.mark.parametrize('image', ['redis:8-alpine', 'redis:8.10-alpine', 'redis:latest', 'redis'])
def test_every_floating_form_checks_the_version(image):
    d = FakeDocker(container='8.10.4', images={image: '8.10.4'})
    assert _target(d, image) is None, image


# ---- the ops #1147 pin still happens when nothing newer ran

@pytest.mark.parametrize('container, local', [
    ('8.10.2', '8.10.2'),      # older: the pin is an upgrade
    ('8.10.3', '8.10.3'),      # the same redis: only the tag text changes
    (None, '7.4.1'),           # no container yet
    (None, 'absent'),          # nothing on the box at all
])
def test_floating_tag_with_nothing_newer_still_moves_to_the_pin(container, local):
    d = FakeDocker(container=container, images={'redis:alpine': local})
    assert _target(d, 'redis:alpine') == PIN


def test_docker_not_answering_leaves_the_floating_tag_alone():
    assert _target(FakeDocker(broken=True), 'redis:alpine') is None


def test_an_image_that_does_not_say_its_version_is_unknown():
    d = FakeDocker(container='', images={'redis:alpine': ''})
    assert _target(d, 'redis:alpine') is None


def test_exact_tags_never_ask_docker():
    d = FakeDocker(broken=True)
    assert _target(d, 'redis:8.10.2-alpine') == PIN       # older exact: upgrade, no lookup needed
    assert _target(d, 'redis:8.12.0-alpine') is None
    assert _target(d, PIN) is None
    assert d.calls == []


def test_seen_version_takes_the_newest_of_container_and_image():
    d = FakeDocker(container='8.9.0', images={'redis:alpine': '8.12.0'})
    ns = _ns(d, '_authentik_redis_seen_version')
    assert ns['_authentik_redis_seen_version']('redis:alpine') == '8.12.0'
    assert ns['_authentik_redis_seen_version']('redis:absent') == '8.9.0'


# ---- both compose patchers leave the reporter's compose alone

def _compose(redis_image):
    return f"""services:
  postgresql:
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
    healthcheck:
      interval: 30s
      retries: 5
      start_period: 600s
      test:
      - CMD
      - ak
      - healthcheck
      timeout: 10s
    image: ghcr.io/goauthentik/server:2026.8.6
  worker:
    command: worker
    environment:
      AUTHENTIK_REDIS__HOST: redis
    healthcheck:
      interval: 30s
      retries: 5
      start_period: 600s
      test:
      - CMD
      - ak
      - healthcheck
      timeout: 10s
    image: ghcr.io/goauthentik/server:2026.8.6
volumes:
  database:
    driver: local
  redis:
"""


def test_yaml_patcher_keeps_the_floating_tag_that_ran_8_12(tmp_path):
    d = FakeDocker(container='8.12.0', images={'docker.io/library/redis:alpine': '8.12.0'})
    ns = _ns(d, '_yaml_duplicate_keys', '_authentik_redis_image_target',
             '_ensure_authentik_compose_patches', '_authentik_loopback_port',
             '_authentik_volume_is_docker_socket', '_authentik_strip_docker_socket',
             optional=('_authentik_redis_seen_version',))
    ns['_ensure_authentik_compose_patches_legacy'] = lambda *a, **k: pytest.fail('legacy patcher reached')
    f = tmp_path / 'docker-compose.yml'
    f.write_text(_compose('docker.io/library/redis:alpine'))
    log = []
    ns['_ensure_authentik_compose_patches'](str(f), log.append)
    assert yaml.safe_load(f.read_text())['services']['redis']['image'] == 'docker.io/library/redis:alpine', log
    assert not any('Pinned redis image' in l for l in log), log


def test_legacy_patcher_keeps_the_floating_tag_that_ran_8_12(tmp_path):
    d = FakeDocker(container='8.12.0', images={'docker.io/library/redis:alpine': '8.12.0'})
    ns = _ns(d, '_ensure_authentik_compose_patches_legacy', '_authentik_redis_image_target',
             optional=('_authentik_redis_seen_version',))
    f = tmp_path / 'docker-compose.yml'
    f.write_text(_compose('docker.io/library/redis:alpine'))
    log = []
    ns['_ensure_authentik_compose_patches_legacy'](str(f), log.append)
    assert '    image: docker.io/library/redis:alpine\n' in f.read_text(), log
    assert not any('Pinned redis image' in l for l in log), log


# ---- the heal: boxes 10.4.8 already put in the crash loop

def _heal(d, tmp_path):
    ns = _ns(d, '_authentik_redis_rdb_heal')
    log = []
    return ns['_authentik_redis_rdb_heal'](str(tmp_path), log.append), log


def test_crash_looping_redis_gets_its_dump_moved_aside_and_restarted(tmp_path):
    d = FakeDocker(container='8.10.3', state='true true',
                   logs='1:C Starting\n' + FATAL + '1:C Starting\n' + FATAL)
    healed, log = _heal(d, tmp_path)
    assert healed, log
    assert d.compose == ['stop', 'run', 'up'], d.calls
    run = next(c for c in d.calls if c[:3] == ['docker', 'compose', 'run'])
    assert run[3:10] == ['--rm', '--no-deps', '-T', '--entrypoint', 'mv', 'redis', '/data/dump.rdb']
    assert run[10] == '/data/dump.rdb.unreadable-1764190000.bak'
    up = next(c for c in d.calls if c[:3] == ['docker', 'compose', 'up'])
    assert up[3:] == ['-d', '--no-deps', 'redis']           # only redis, nothing else recreated
    assert any('moving it aside' in l for l in log) and any('redis started' in l for l in log), log


def test_exited_redis_with_the_fatal_line_is_healed_too(tmp_path):
    d = FakeDocker(container='8.10.3', state='false false', logs=FATAL)
    assert _heal(d, tmp_path)[0]


def test_healthy_redis_is_left_alone(tmp_path):
    d = FakeDocker(container='8.10.3', state='true false', logs=FATAL)    # an old line, but it is up
    healed, log = _heal(d, tmp_path)
    assert not healed and d.compose == [], d.calls


def test_a_fatal_line_followed_by_a_good_start_is_left_alone(tmp_path):
    d = FakeDocker(container='8.10.3', state='true true',
                   logs=FATAL + '1:M * Ready to accept connections tcp\n')
    assert not _heal(d, tmp_path)[0] and d.compose == []


@pytest.mark.parametrize('logs', ['', '# Bad file format reading the append only file\n',
                                  '# Short read or OOM loading DB. Unrecoverable error, aborting now.\n'])
def test_other_crashes_are_not_ours_to_heal(tmp_path, logs):
    d = FakeDocker(container='8.10.3', state='true true', logs=logs)
    assert not _heal(d, tmp_path)[0] and d.compose == []


def test_no_redis_container_is_a_no_op(tmp_path):
    d = FakeDocker(container=None)
    assert not _heal(d, tmp_path)[0] and d.compose == []


def test_a_failed_move_still_starts_redis_again(tmp_path):
    d = FakeDocker(container='8.10.3', state='true true', logs=FATAL, fail={'run': 1})
    healed, log = _heal(d, tmp_path)
    assert not healed
    assert d.compose == ['stop', 'run', 'up'], d.calls     # never left stopped
    assert any('failed' in l and 'retries next boot' in l for l in log), log


# ---- wiring: the boot converge runs the heal after its one compose apply

def test_boot_converge_runs_the_heal_after_the_compose_apply():
    body = _src('_startup_authentik_idle_load_converge')
    apply_at = body.index('# ── ONE compose apply for everything above ──')
    heal_at = body.index('_authentik_redis_rdb_heal(ak_dir, _l)')
    assert apply_at < heal_at < body.index('# ── W2: delete the stock rules via API AFTER the bounce')
