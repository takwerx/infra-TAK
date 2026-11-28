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
"""The local Authentik Update judges the version that really runs, not tag text (ops #1331).

Six findings from the stack audit (ops #1311), one proof each:
  1. a floating tag (`2026.8`) on a NEWER build: Update must refuse (409), not pin it back down;
  2. a STOPPED stack whose `.env` pins a newer version than the compose default: refuse;
  3. the dev channel skipped a release family (2026.5.x to latest 2026.11): go through 2026.8.7;
  4. a family move dumps the database first and stops when the dump fails;
  5. the target images are pulled BEFORE any pin is written;
  6. the Postgres converge never recreates a database over another MAJOR version's data.

app.py cannot be imported in a test, so `authentik_control` and its helpers are cut out of it and
run against a fake Docker host in a temp HOME: the code under test is the shipped text. Names the
fix adds are loaded only when the tree has them, so on the base commit the OLD `authentik_control`
runs and the tests fail on what it DOES, not because a helper was missing.
"""

import ast
import contextlib
import importlib.util
import pathlib
import re
import subprocess as _real_subprocess
import threading
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_NAMES = {
    '_ak_ver_tuple', '_ak_upgrade_hop', '_get_authentik_target_release', '_ak_tag_is_sane',
    '_ak_tags_from_text', '_ak_env_path', '_ak_env_read', '_ak_env_tag', '_ak_env_pin_tag',
    '_ak_resolved_authentik_tags', '_get_authentik_version_info', 'authentik_control',
    'AUTHENTIK_VETTED_RELEASE', 'AUTHENTIK_DEV_RELEASE', 'AUTHENTIK_UPGRADE_STEPS',
}
_NEW = {
    '_ak_version_from_output', '_ak_current_version', '_ak_resolved_authentik_images', '_ak_family_move',
    '_ak_premove_dump', '_AK_FULL_VERSION_RE', '_AK_VERSION_PROBE_PY', 'AK_FAMILY_DUMP_MIN_FREE',
    'AK_POSTGRES_CONTAINER',
}


def _cut(names):
    parts = {}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            parts[node.name] = ast.get_source_segment(APP, node)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and \
                getattr(node.targets[0], 'id', None) in names:
            parts[node.targets[0].id] = ast.get_source_segment(APP, node)
    return parts


PARTS = _cut(_NAMES | _NEW)
assert not (_NAMES - set(PARTS)), 'missing from app.py: %s' % sorted(_NAMES - set(PARTS))
VETTED = ast.literal_eval(next(n.value for n in TREE.body if isinstance(n, ast.Assign)
                               and getattr(n.targets[0], 'id', None) == 'AUTHENTIK_VETTED_RELEASE'))
STEP = ast.literal_eval(next(n.value for n in TREE.body if isinstance(n, ast.Assign)
                             and getattr(n.targets[0], 'id', None) == 'AUTHENTIK_UPGRADE_STEPS'))[0]
HAS_FIX = '_ak_current_version' in PARTS


class Box:
    """One local Authentik stack on a fake Docker host. `running` is the tag TEXT of the server
    image that runs (None: stack stopped), `real` the version that image really holds. `images`
    maps every tag present on the host to the version it holds (a floating label on a newer build).
    The compose default and the `.env` pin live in real files under HOME, so what the code writes is
    what the fake reads back."""

    def __init__(self, home, running=VETTED, real=None, env=None, compose=VETTED, images=None,
                 pull_fails=False, dump_fails=False, pg_up=True, exec_ok=True, free=10 * 1024 ** 3):
        self.dir = home / 'authentik'
        self.dir.mkdir()
        self.running, self.exec_ok = running, exec_ok
        self.real = real or running
        self.images = dict(images or {})
        self.pull_fails, self.dump_fails, self.pg_up, self.free = pull_fails, dump_fails, pg_up, free
        self.events = []
        (self.dir / 'docker-compose.yml').write_text(
            'services:\n  server:\n    image: ghcr.io/goauthentik/server:${AUTHENTIK_TAG:-%s}\n'
            '  ldap:\n    image: ghcr.io/goauthentik/ldap:${AUTHENTIK_TAG:-%s}\n' % (compose, compose))
        if env is not None:
            (self.dir / '.env').write_text('PG_PASS=x\nAUTHENTIK_TAG=%s\n' % env)

    def pin(self):
        env = ''
        if (self.dir / '.env').exists():
            m = re.search(r'(?m)^AUTHENTIK_TAG=(.*)$', (self.dir / '.env').read_text())
            env = m.group(1).strip() if m else ''
        comp = re.search(r'AUTHENTIK_TAG:-([^}]+)\}', (self.dir / 'docker-compose.yml').read_text()).group(1)
        return env or comp

    def env_text(self):
        p = self.dir / '.env'
        return p.read_text() if p.exists() else None

    def writes(self):
        return [e for e in self.events if e.startswith('write ')]

    def mutations(self):
        return [e for e in self.events if e.split(' ')[0] in ('write', 'pull', 'down', 'up', 'dump', 'compose-pull')]

    def run(self, argv, **k):
        a = list(argv)

        def cp(rc=0, out='', err=''):
            return _real_subprocess.CompletedProcess(a, rc, out, err)
        if a[:2] == ['docker', 'ps']:
            flt = a[a.index('--filter') + 1]
            if 'authentik-postgresql' in flt:
                return cp(0, 'authentik-postgresql-1\n' if self.pg_up else '')
            if not self.running:
                return cp(0, '')
            img = 'ghcr.io/goauthentik/server:%s' % self.running
            return cp(0, ('authentik-server-1 %s\n' % img) if '{{.Names}}' in ' '.join(a) else img + '\n')
        if a[:2] == ['docker', 'exec']:
            return cp(0, '%s\n' % self.real) if self.exec_ok and self.running else cp(1, '', 'not running')
        if a[:3] == ['docker', 'compose', 'config']:
            t = self.pin()
            return cp(0, 'image: ghcr.io/goauthentik/server:%s\nimage: ghcr.io/goauthentik/ldap:%s\n' % (t, t))
        if a[:2] == ['docker', 'run']:
            tag = a[-3].rsplit(':', 1)[1]
            return cp(0, '%s\n' % self.images[tag]) if tag in self.images else cp(125, '', 'no such image')
        if a[:2] == ['docker', 'pull']:
            self.events.append('pull %s' % a[2])
            if self.pull_fails:
                return cp(1, '', 'Error response from daemon: manifest unknown')
            tag = a[2].rsplit(':', 1)[1]
            self.images.setdefault(tag, tag)
            return cp()
        if a[:3] == ['docker', 'compose', 'pull']:
            self.events.append('compose-pull')
            return cp()
        if a[:3] == ['docker', 'compose', 'down']:
            self.events.append('down')
            self.running = None
            return cp()
        if a[:3] == ['docker', 'compose', 'up']:
            self.events.append('up')
            self.running = self.pin()
            self.real = self.images.get(self.running, self.running)
            return cp()
        if a[:3] == ['docker', 'image', 'prune']:
            return cp()
        raise AssertionError('unexpected docker call: %r' % (a,))


def run_update(box, monkeypatch, home, channel='main', dev_latest=None):
    monkeypatch.setenv('HOME', str(home))
    steps = []

    def run_chain(cmds, mode='and', timeout=0, **kw):
        last = None
        for c in cmds:
            last = box.run(c, **kw)
            if last.returncode != 0 and mode == 'and':
                break
        return last

    def write_priv(path, text, perm=None):
        box.events.append('write %s' % pathlib.Path(path).name)
        pathlib.Path(path).write_text(text)

    def read_priv(path):
        p = pathlib.Path(path)
        return p.read_text() if p.exists() else None

    def pg_dump(container, dest, timeout=0):
        box.events.append('dump')
        if box.dump_fails:
            raise RuntimeError('pg_dump in %s failed: disk full' % container)
        return 123456, 'abc'

    @contextlib.contextmanager
    def lock(holder, plog=None, timeout=0):
        yield True

    ns = {
        're': re, 'os': __import__('os'), 'time': types.SimpleNamespace(sleep=lambda s: None, time=lambda: 0),
        'threading': types.SimpleNamespace(Thread=lambda **kw: types.SimpleNamespace(start=lambda: None)),
        'subprocess': types.SimpleNamespace(run=box.run, CompletedProcess=_real_subprocess.CompletedProcess),
        'datetime': __import__('datetime').datetime,
        'request': types.SimpleNamespace(json={'action': 'update'}),
        'jsonify': lambda d: d,
        'load_settings': lambda: {'update_channel': channel},
        '_get_module_deployment_config': lambda s, k: {},
        '_ssh_probe': lambda *a, **k: (False, ''),
        '_sudo_wrap': lambda c: list(c),
        '_run_priv_chain': run_chain, '_write_priv': write_priv, '_read_priv': read_priv,
        '_get_authentik_latest_release_tag': lambda use_cache=True: dev_latest,
        '_patch_authentik_compose_network': lambda *a, **k: None,
        '_authentik_compose_lock': lock,
        '_guarddog_authentik_update_begin': lambda why: False,
        '_guarddog_authentik_update_end': lambda: None,
        '_ensure_authentik_compose_patches': lambda *a, **k: None,
        '_ak_compose_without_broker_patch': lambda *a, **k: None,
        '_startup_authentik_idle_load_converge': lambda: None,
        '_authentik_release_cache': {},
        '_mod_result_step': lambda m, s: steps.append(s),
        '_update_error_line': lambda t, limit=600: (t or '').strip()[-300:],
        '_stack_backup_free_bytes': lambda: box.free,
        '_makedirs_priv': lambda *a, **k: None,
        '_stack_pg_dump_priv': pg_dump,
        'STACK_BACKUP_DIR': '/var/lib/infratak-backups',
    }
    exec(compile('\n\n'.join(PARTS[n] for n in sorted(PARTS)), 'app.py', 'exec'), ns)
    rv = ns['authentik_control']()
    if isinstance(rv, tuple):
        return rv[0], rv[1], steps
    return rv, 200, steps


@pytest.fixture
def home(tmp_path):
    return tmp_path


# ── 1. a floating tag on a NEWER build ───────────────────────────────────────

def test_floating_tag_on_a_newer_build_is_refused_and_nothing_is_changed(home, monkeypatch):
    box = Box(home, running='2026.8', real='2026.11.0-rc2', env='2026.8', compose='2026.8',
              images={'2026.8': '2026.11.0-rc2'})
    env_before = box.env_text()
    body, status, _ = run_update(box, monkeypatch, home)
    assert status == 409, body
    assert 'Refusing to downgrade Authentik' in body['error'] and '2026.11.0' in body['error']
    assert box.mutations() == []
    assert box.env_text() == env_before and box.pin() == '2026.8'


def test_latest_tag_on_a_newer_build_is_refused(home, monkeypatch):
    box = Box(home, running='latest', real='2026.11.0-rc2', env='latest', compose='latest',
              images={'latest': '2026.11.0-rc2'})
    body, status, _ = run_update(box, monkeypatch, home)
    assert status == 409 and box.mutations() == [], body


def test_floating_tag_on_an_older_or_equal_build_still_updates(home, monkeypatch):
    box = Box(home, running='2026.8', real='2026.8.4', env='2026.8', compose='2026.8',
              images={'2026.8': '2026.8.4'})
    body, status, _ = run_update(box, monkeypatch, home)
    assert status == 200 and body.get('success'), body
    assert box.pin() == VETTED and box.running == VETTED


def test_a_server_that_will_not_say_its_version_under_a_floating_tag_is_refused(home, monkeypatch):
    box = Box(home, running='2026.8', real='2026.8.4', env='2026.8', compose='2026.8', exec_ok=False)
    body, status, _ = run_update(box, monkeypatch, home)       # no local image to ask either
    assert status == 500 and 'Nothing was changed' in body['error'], body
    assert box.mutations() == []


def test_full_version_tag_is_enough_when_the_server_will_not_answer(home, monkeypatch):
    box = Box(home, running='2026.8.4', real='2026.8.4', env='2026.8.4', compose='2026.8.4', exec_ok=False)
    body, status, _ = run_update(box, monkeypatch, home)
    assert status == 200 and body.get('success'), body


def test_same_family_patch_update_takes_no_dump(home, monkeypatch):
    box = Box(home, running='2026.8.4', real='2026.8.4', env='2026.8.4', compose='2026.8.4')
    body, status, _ = run_update(box, monkeypatch, home)
    assert status == 200, body
    assert 'dump' not in box.events


# ── 2. a STOPPED stack: the .env pin counts ───────────────────────────────────

def test_stopped_stack_with_a_newer_env_pin_is_refused(home, monkeypatch):
    box = Box(home, running=None, real='2026.11.0-rc2', env='2026.11.0-rc2', compose=VETTED,
              images={'2026.11.0-rc2': '2026.11.0-rc2'})
    env_before = box.env_text()
    body, status, _ = run_update(box, monkeypatch, home)
    assert status == 409, body
    assert box.mutations() == [] and box.env_text() == env_before


def test_stopped_stack_with_an_older_env_pin_still_updates(home, monkeypatch):
    box = Box(home, running=None, env='2026.8.4', compose=VETTED, images={'2026.8.4': '2026.8.4'})
    body, status, _ = run_update(box, monkeypatch, home)
    assert status == 200 and body.get('success'), body
    assert box.pin() == VETTED


# ── 3. the dev channel does not skip a family ─────────────────────────────────

def _target(installed, latest, channel='dev'):
    ns = {'re': re, 'load_settings': lambda: {'update_channel': channel},
          '_get_authentik_latest_release_tag': lambda use_cache=True: latest}
    exec(compile('\n\n'.join(PARTS[n] for n in ('_ak_ver_tuple', '_ak_upgrade_hop', '_get_authentik_target_release',
                                                'AUTHENTIK_VETTED_RELEASE', 'AUTHENTIK_DEV_RELEASE',
                                                'AUTHENTIK_UPGRADE_STEPS')), 'app.py', 'exec'), ns)
    return ns['_get_authentik_target_release']({'update_channel': channel}, installed=installed)


@pytest.mark.parametrize('installed,latest,expected', [
    ('2026.5.7', '2026.11.0', VETTED),          # skips 2026.8 today
    ('2026.5.9', '2026.11.0', VETTED),
    ('2026.2.2', '2026.11.0', STEP),            # 2026.2 -> the 2026.5 step first (unchanged)
    ('2026.8.4', '2026.11.0', '2026.11.0'),     # one family ahead: straight there (unchanged)
    ('2026.8.7', '2026.11.0', '2026.11.0'),
    ('2026.5.7', '2026.8.9', '2026.8.9'),       # latest is the next family: unchanged
    (None, '2026.11.0', '2026.11.0'),           # fresh database: straight there
])
def test_dev_channel_passes_through_the_vetted_family(installed, latest, expected):
    assert _target(installed, latest) == expected


def test_main_channel_is_unchanged():
    assert _target('2026.5.7', '2026.11.0', channel='main') == VETTED


# ── 4. a family move dumps the database first ─────────────────────────────────

def test_family_move_dumps_the_database_before_the_first_write(home, monkeypatch):
    box = Box(home, running='2026.5.9', real='2026.5.9', env='2026.5.9', compose='2026.5.9')
    body, status, steps = run_update(box, monkeypatch, home)
    assert status == 200 and body.get('success'), body
    assert box.events.index('dump') < box.events.index(box.writes()[0])
    assert box.events.count('dump') == 1


def test_family_move_stops_when_the_dump_fails_and_changes_nothing(home, monkeypatch):
    box = Box(home, running='2026.5.9', real='2026.5.9', env='2026.5.9', compose='2026.5.9', dump_fails=True)
    env_before = box.env_text()
    body, status, _ = run_update(box, monkeypatch, home)
    assert status == 500 and 'dump' in body['error'] and 'Nothing was changed' in body['error'], body
    assert box.events == ['dump'] and box.env_text() == env_before and box.running == '2026.5.9'


def test_family_move_stops_when_the_database_container_is_not_running(home, monkeypatch):
    box = Box(home, running='2026.5.9', real='2026.5.9', env='2026.5.9', compose='2026.5.9', pg_up=False)
    body, status, _ = run_update(box, monkeypatch, home)
    assert status == 500 and box.mutations() == [], body


def test_family_move_stops_when_there_is_no_room_for_the_dump(home, monkeypatch):
    box = Box(home, running='2026.5.9', real='2026.5.9', env='2026.5.9', compose='2026.5.9', free=100 * 1024 ** 2)
    body, status, _ = run_update(box, monkeypatch, home)
    assert status == 500 and 'MB is free' in body['error'] and box.mutations() == [], body


# ── 5. the images are pulled BEFORE any pin is written ────────────────────────

def test_images_are_pulled_before_the_first_file_is_written(home, monkeypatch):
    box = Box(home, running='2026.8.4', real='2026.8.4', env='2026.8.4', compose='2026.8.4')
    body, status, _ = run_update(box, monkeypatch, home)
    assert status == 200, body
    pulls = [i for i, e in enumerate(box.events) if e.startswith('pull ')]
    assert pulls, box.events
    assert {box.events[i] for i in pulls} == {'pull ghcr.io/goauthentik/server:%s' % VETTED,
                                              'pull ghcr.io/goauthentik/ldap:%s' % VETTED}
    assert max(pulls) < box.events.index(box.writes()[0])


def test_a_failed_pull_leaves_no_pin_written(home, monkeypatch):
    box = Box(home, running='2026.8.4', real='2026.8.4', env='2026.8.4', compose='2026.8.4', pull_fails=True)
    compose_before = (box.dir / 'docker-compose.yml').read_text()
    env_before = box.env_text()
    body, status, _ = run_update(box, monkeypatch, home)
    assert status == 500 and 'Nothing was changed' in body['error'], body
    assert box.writes() == [] and box.env_text() == env_before
    assert (box.dir / 'docker-compose.yml').read_text() == compose_before and box.running == '2026.8.4'


# ── 6. the Postgres converge never recreates over another major's data ────────

def _pg754():
    spec = importlib.util.spec_from_file_location('pg754', str(REPO / 'tests' / 'test_postgres_security_ops754.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_postgres_converge_refuses_a_compose_tag_of_another_major():
    pg = _pg754()

    class Fake(pg.FakeDocker):
        def run(self, argv, *a, **k):
            av = list(argv)[1:]
            out = lambda rc=0, o='', e='': _real_subprocess.CompletedProcess(av, rc, o, e)
            if av[:3] == ['docker', 'compose', 'config']:
                return out(0, 'services:\n  postgresql:\n    image: postgres:17-alpine\n')
            if av[:2] == ['docker', 'run']:
                img = av[av.index('--entrypoint') + 2]
                ver = '17.5' if img == 'postgres:17-alpine' else self.tag_ver
                self.calls.append((av, k.get('cwd')))
                return out(0, 'postgres (PostgreSQL) %s\n' % ver)
            return super().run(argv, *a, **k)

    fake = Fake(pull_brings=('sha256:new', '16.16'))
    res, logs, _ = pg._run_converge(fake)
    assert res == {'authentik': 'skipped'}, (res, logs)
    assert fake.recreates == []
    assert any('major change needs a dump and restore' in l for l in logs), logs


def test_postgres_converge_still_recreates_a_same_major_compose_tag():
    pg = _pg754()

    class Fake(pg.FakeDocker):
        def run(self, argv, *a, **k):
            av = list(argv)[1:]
            if av[:3] == ['docker', 'compose', 'config']:
                return _real_subprocess.CompletedProcess(av, 0, 'services:\n  postgresql:\n    image: postgres:16-alpine\n', '')
            return super().run(argv, *a, **k)

    fake = Fake(pull_brings=('sha256:new', '16.16'))
    res, logs, _ = pg._run_converge(fake)
    assert res == {'authentik': 'fixed'}, (res, logs)
    assert len(fake.recreates) == 1


# ── the shared helper reads the server's own answer ───────────────────────────

@pytest.mark.skipif(not HAS_FIX, reason='helper added by ops #1331')
@pytest.mark.parametrize('out,expected', [
    ('2026.8.7\n', (2026, 8, 7)),
    ('Warning: something\n2026.11.0-rc2\n', (2026, 11, 0)),
    ('', None), ('Traceback (most recent call last):\nImportError: x\n', None), ('latest\n', None),
])
def test_version_is_read_from_the_last_line_only(out, expected):
    ns = {'re': re}
    exec(compile('\n\n'.join(PARTS[n] for n in ('_AK_FULL_VERSION_RE', '_ak_version_from_output')), 'app.py', 'exec'), ns)
    assert ns['_ak_version_from_output'](out) == expected
