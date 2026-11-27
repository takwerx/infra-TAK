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
"""Real Docker, real data: a redis NEWER than the pin writes dump.rdb (ops #1306, GH #759).

The unit tests in test_authentik_redis_no_downgrade_ops1306.py answer the docker calls with
fakes. This one runs the shipped functions against a real Docker daemon, with the same redis
service the Authentik compose writes (`--save 60 1 --loglevel warning`, a /data volume):

1. redis 8.12.0 (what the floating `alpine` tag pulled on customer boxes) starts, a key is
   written, and the dump is saved on stop: an RDB file only a redis that new can read.
2. The pin is asked about the floating tag: it must leave it alone (the bug: it returned the
   pin, 8.10.3). With the tag kept, 8.12.0 starts again and the key is still there.
3. What 10.4.8 did on those boxes, done for real: the pin image starts on that volume and
   crash-loops with "Can't handle RDB format version".
4. The boot heal un-sticks it: redis comes up, and the newer dump is moved aside, not deleted
   (the .bak still holds the key).

Needs Docker and network access to Docker Hub. Skipped where there is no Docker, except in
GitHub Actions (PR checks run on ubuntu-24.04, which has Docker): there a missing Docker fails.
"""

import ast
import os
import pathlib
import shutil
import subprocess
import time
import uuid

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

NEWER = 'docker.io/library/redis:8.12.0-alpine'   # what floating `alpine` ran on customer boxes
FLOATING = 'docker.io/library/redis:alpine'
KEY, VALUE = 'ops1306', 'newer-data'


def _docker_ok():
    if not shutil.which('docker'):
        return False
    for argv in (['docker', 'info'], ['docker', 'compose', 'version']):
        try:
            if subprocess.run(argv, capture_output=True, timeout=30).returncode != 0:
                return False
        except Exception:
            return False
    return True


if not _docker_ok():
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        raise RuntimeError('ops #1306 real-Docker proof test needs Docker in CI and found none')
    pytest.skip('needs a Docker daemon with compose', allow_module_level=True)


def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    return None


def _src(names, optional=()):
    parts = {}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in set(names) | set(optional):
            parts[node.name] = ast.get_source_segment(APP, node)
    missing = set(names) - set(parts)
    assert not missing, f'missing from app.py: {sorted(missing)}'
    return '\n\n'.join(parts[n] for n in (*names, *optional) if n in parts)


class _Lock:
    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return True

    def __exit__(self, *a):
        return False


def _ns(project, names, optional=()):
    """The shipped functions, run against real Docker. The only change: the hard-coded
    container name authentik-redis-1 is mapped to this test's own compose project, so the
    test never touches a real Authentik on the machine it runs on."""
    real = f'{project}-redis-1'

    def run(argv, **kw):
        return subprocess.run([real if a == 'authentik-redis-1' else a for a in argv], **kw)

    shim = type('S', (), {'run': staticmethod(run), 'PIPE': subprocess.PIPE,
                          'STDOUT': subprocess.STDOUT})
    ns = {
        'os': os, 're': __import__('re'), 'time': time, 'subprocess': shim,
        '_sudo_wrap': lambda argv: list(argv),
        'AUTHENTIK_REDIS_IMAGE': _const('AUTHENTIK_REDIS_IMAGE'),
        '_AK_REDIS_RDB_FATAL': _const('_AK_REDIS_RDB_FATAL'),
        '_AK_COMPOSE_LOCK_WAIT_S': 90,
        '_authentik_compose_lock': _Lock,
    }
    exec(compile(_src(names, optional), 'app.py', 'exec'), ns)
    return ns


class Box:
    """A compose project shaped like the Authentik redis service."""

    def __init__(self, path):
        self.dir = path
        self.project = f'ops1306t{uuid.uuid4().hex[:10]}'
        self.container = f'{self.project}-redis-1'

    def write(self, image):
        (self.dir / 'docker-compose.yml').write_text(
            f'name: {self.project}\n'
            'services:\n'
            '  redis:\n'
            f'    image: {image}\n'
            '    command: --save 60 1 --loglevel warning\n'
            '    restart: unless-stopped\n'
            '    volumes:\n'
            '      - redis:/data\n'
            'volumes:\n'
            '  redis: {}\n', encoding='utf-8')

    def dc(self, *args, check=True, timeout=180, text=True):
        r = subprocess.run(['docker', 'compose', *args], cwd=self.dir, capture_output=True,
                           text=text, timeout=timeout)
        if check:
            assert r.returncode == 0, f'docker compose {" ".join(args)}: {r.stdout}{r.stderr}'
        return r

    def cli(self, *args):
        return self.dc('exec', '-T', 'redis', 'redis-cli', *args).stdout.strip()

    def logs(self):
        r = subprocess.run(['docker', 'logs', '--tail', '60', self.container],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        return r.stdout or ''

    def wait(self, pred, what, secs=90):
        end = time.time() + secs
        while time.time() < end:
            if pred():
                return
            time.sleep(1)
        raise AssertionError(f'timed out waiting for {what}; redis log:\n{self.logs()}')

    def answers(self):
        r = self.dc('exec', '-T', 'redis', 'redis-cli', 'ping', check=False, timeout=30)
        return r.returncode == 0 and 'PONG' in r.stdout

    def data_files(self):
        r = self.dc('run', '--rm', '--no-deps', '-T', '--entrypoint', 'ls', 'redis', '/data')
        return r.stdout.split()

    def read(self, name):
        r = self.dc('run', '--rm', '--no-deps', '-T', '--entrypoint', 'cat', 'redis', f'/data/{name}',
                    text=False)
        return r.stdout


@pytest.fixture
def box(tmp_path):
    pin = _const('AUTHENTIK_REDIS_IMAGE')
    for image in (NEWER, pin):
        r = subprocess.run(['docker', 'pull', '-q', image], capture_output=True, text=True, timeout=240)
        assert r.returncode == 0, f'docker pull {image}: {r.stderr}'
    b = Box(tmp_path)
    b.write(NEWER)
    try:
        yield b
    finally:
        b.dc('down', '-v', '--remove-orphans', check=False)


@pytest.mark.timeout(600)
def test_newer_redis_data_is_kept_and_a_stuck_box_heals(box):
    pin = _const('AUTHENTIK_REDIS_IMAGE')
    log = []

    # 1. the newer redis writes real data, saved to dump.rdb on stop
    box.dc('up', '-d', 'redis')
    box.wait(box.answers, 'redis 8.12.0 to answer')
    assert box.cli('INFO', 'server').count('redis_version:8.12.0') == 1
    assert box.cli('SET', KEY, VALUE) == 'OK'
    box.dc('stop', 'redis')
    assert 'dump.rdb' in box.data_files()

    # 2. the pin must not move the floating tag back over that data
    ns = _ns(box.project, ['_authentik_redis_image_target'], optional=('_authentik_redis_seen_version',))
    assert ns['_authentik_redis_image_target'](FLOATING) is None, (
        'the pin moved a floating redis tag that ran 8.12.0 back to ' + pin)
    box.dc('up', '-d', 'redis')                # the tag stays: the same newer redis restarts
    box.wait(box.answers, 'redis 8.12.0 to answer again')
    assert box.cli('GET', KEY) == VALUE, 'the newer redis lost its own data'
    box.dc('stop', 'redis')

    # 3. what 10.4.8 did on those boxes: the older pin starts on the newer dump and crash-loops
    box.write(pin)
    box.dc('up', '-d', 'redis')
    box.wait(lambda: "Can't handle RDB format version" in box.logs(), 'the RDB crash loop')
    assert not box.answers()

    # 4. the boot heal moves the dump aside and starts redis on the pin
    heal = _ns(box.project, ['_authentik_redis_rdb_heal'])['_authentik_redis_rdb_heal']
    # the heal acts only while the container is down or restarting; a crash-looping redis is
    # "running" for a few milliseconds per try, so ask again like the next boot would
    healed = False
    for _ in range(30):
        healed = heal(str(box.dir), log.append)
        if healed:
            break
        time.sleep(1)
    assert healed is True, log
    box.wait(box.answers, 'the healed redis to answer')
    assert box.cli('INFO', 'server').count('redis_version:' + pin.rsplit(':', 1)[1].split('-')[0]) == 1
    baks = [f for f in box.data_files() if f.startswith('dump.rdb.unreadable-') and f.endswith('.bak')]
    assert len(baks) == 1, box.data_files()
    kept = box.read(baks[0])
    assert kept.startswith(b'REDIS') and KEY.encode() in kept and VALUE.encode() in kept, (
        'the newer dump was not kept intact')
    assert any('moving it aside' in m for m in log), log

    # a redis that is up is never touched again
    assert heal(str(box.dir), log.append) is False
    assert box.answers()
