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
"""The scheduler broker.py patch must follow the image, not outlive it (GH #111 follow-up).

Field (test8, 2026-10-11): Authentik 2026.5.7 was running with `patches/broker.py` written on
2026-08-03 from an earlier 2026.5.x image. 5.7 no longer carries the scheduler typo, and its
broker.py replaced the one-shot expired-task DELETE with a chunked cleanup — the stale patch
put the old DELETE back. The converge kept any existing mount ("already applied") and Update
never touched it, so the patch survived every same-minor upgrade.

app.py cannot be imported in a test, so the converge and its helpers are cut out of it and
run against a fake docker: the code under test is the shipped text.
"""

import ast
import os
import pathlib
import re
import threading

import pytest

yaml = pytest.importorskip('yaml')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_FUNCS = {'_ak_broker_patch_name', '_ak_image_broker_source', '_ak_compose_without_broker_patch',
          '_startup_authentik_idle_load_converge'}
_CONSTS = {'_AK_BROKER_CONTAINER_PATH', '_AK_BROKER_TYPO_LINE', '_AK_BROKER_FIXED_LINE',
           '_AK_EVENTS_BP_CONTAINER_PATH', '_AK_EVENTS_BP_MASK'}

TYPO = 'self.schedule_last_run = timezone.now()'
FIXED = 'self.scheduler_last_run = timezone.now()'
OLD_ID = 'sha256:' + 'a1' * 32          # the 2026.5.x image the Aug-3 patch was cut from
NEW_ID = 'sha256:' + '76bf433fd434' + '0' * 52


def _image_file(version, typo):
    return (f'# django_dramatiq_postgres/broker.py from {version}\n'
            f'def tick(self):\n    {TYPO if typo else FIXED}\n')


def _load():
    parts = []
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name in _FUNCS:
            parts.append(ast.get_source_segment(APP, node))
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
              and getattr(node.targets[0], 'id', None) in _CONSTS):
            parts.append(ast.get_source_segment(APP, node))
    assert len(parts) == len(_FUNCS) + len(_CONSTS), 'a name under test was renamed or removed'
    return '\n\n'.join(parts)


SRC = _load()


class _R:
    def __init__(self, rc=0, out='', err=''):
        self.returncode, self.stdout, self.stderr = rc, out, err


class FakeDocker:
    """Just enough docker for the W1/W2 path: one worker container, per-image files."""

    def __init__(self, ak_dir, img, img_id, images, run_error=False):
        self.ak_dir, self.img, self.img_id = ak_dir, img, img_id
        self.images = images            # image ID -> its own broker.py text (None = missing)
        self.run_error = run_error
        self.calls = []

    def _container_view(self):
        """What the worker sees at the broker path: the mounted patch, else the image's file."""
        data = yaml.safe_load((self.ak_dir / 'docker-compose.yml').read_text())
        for v in data['services']['worker'].get('volumes') or []:
            if '/django_dramatiq_postgres/broker.py' in str(v):
                return (self.ak_dir / str(v).split(':', 1)[0]).read_text()
        return self.images.get(self.img_id) or ''

    def run(self, argv, **kw):
        self.calls.append(list(argv))
        if argv[:2] == ['docker', 'inspect']:
            return _R(0, f'{self.img} {self.img_id}\n')
        if argv[:2] == ['docker', 'run']:
            assert '--rm' in argv and argv[argv.index('--entrypoint') + 1] == 'cat'
            if self.run_error:
                return _R(125, '', 'docker: Error response from daemon: no space left on device')
            text = self.images.get(argv[-2])
            if text is None:
                return _R(1, '', f'cat: {argv[-1]}: No such file or directory')
            return _R(0, text)
        if argv[:3] == ['docker', 'exec', 'authentik-worker-1'] and argv[3] == 'grep':
            needle, path = argv[-2], argv[-1]
            view = (self._container_view() if 'broker.py' in path else 'entries: []')
            return _R(0 if needle in view else 1)
        if argv[:2] == ['docker', 'compose']:
            return _R(0)
        return _R(0)

    @property
    def ups(self):
        return [c for c in self.calls if c[:2] == ['docker', 'compose']]

    @property
    def image_reads(self):
        return [c for c in self.calls if c[:2] == ['docker', 'run']]


def _compose(broker_spec=None):
    # W2's mask mount is already in place, so every compose change below is W1's.
    vols = ['./data:/data', './custom-templates:/templates',
            './patches/events-default.yaml:/blueprints/default/events-default.yaml:ro']
    if broker_spec:
        vols.append(broker_spec)
    svc = lambda cmd: {'command': cmd, 'image': 'ghcr.io/goauthentik/server:${AUTHENTIK_TAG:-2026.5.7}',
                       'volumes': list(vols)}
    return yaml.safe_dump({'services': {'server': svc('server'), 'worker': svc('worker')}},
                          sort_keys=False)


LEGACY_SPEC = './patches/broker.py:/ak-root/packages/django-dramatiq-postgres/django_dramatiq_postgres/broker.py:ro'


@pytest.fixture
def box(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    ak = tmp_path / 'authentik'
    (ak / 'patches').mkdir(parents=True)
    (ak / '.env').write_text('PG_PASS=x\n')
    return ak


def _converge(ak, docker):
    logs = []
    done = threading.Event()
    done.set()
    ns = {
        'os': os, 're': re, 'subprocess': type('S', (), {'run': staticmethod(docker.run)}),
        'time': type('T', (), {'sleep': staticmethod(lambda s: None)}),
        '_sudo_wrap': lambda argv: argv,
        '_STARTUP_IMPORT_DONE': done, '_AK_IDLE_CONVERGE_LOCK': threading.Lock(),
        '_ensure_authentik_compose_patches': lambda *a, **k: False,
        '_w1_ak_ctx': lambda: (None, None, None),
        'load_settings': lambda: {'ak_event_backlog_reclaimed': {'done': True}},
        'print': lambda *a, **k: None,
        # ops #178: the compose `up -d` goes through the locked runner; no lock in this sandbox.
        '_ak_compose_subprocess': lambda argv, holder, plog=None, wait=None, **kw: docker.run(argv, **kw),
        '_AK_COMPOSE_LOCK_WAIT_LONG_S': 420,
    }
    exec(compile(SRC, 'app.py', 'exec'), ns)
    ns['_startup_authentik_idle_load_converge'](log=logs.append)
    assert not any('error (non-fatal)' in l for l in logs), logs
    return logs, yaml.safe_load((ak / 'docker-compose.yml').read_text())


def _broker_vols(data, svc):
    return [v for v in data['services'][svc]['volumes'] if 'django_dramatiq_postgres/broker.py' in v]


def test_stale_patch_retired_when_new_image_has_no_typo(box):
    """The test8 case: Aug-3 patch mounted over 2026.5.7, which no longer has the typo."""
    (box / 'docker-compose.yml').write_text(_compose(LEGACY_SPEC))
    (box / 'patches' / 'broker.py').write_text(_image_file('2026.5.2', typo=False))
    d = FakeDocker(box, 'ghcr.io/goauthentik/server:2026.5.7', NEW_ID,
                   {NEW_ID: _image_file('2026.5.7', typo=False)})
    logs, data = _converge(box, d)
    assert _broker_vols(data, 'server') == [] and _broker_vols(data, 'worker') == []
    assert len(d.ups) == 1, d.calls
    assert d.image_reads and d.image_reads[0][-2] == NEW_ID       # read from the IMAGE by ID
    assert any('retiring the patch cut from an older image' in l for l in logs), logs
    # the old file stays on disk: a container still pointing at it must be able to restart
    assert (box / 'patches' / 'broker.py').exists()


def test_stale_patch_rederived_from_new_image_that_still_has_the_typo(box):
    (box / 'docker-compose.yml').write_text(_compose(LEGACY_SPEC))
    (box / 'patches' / 'broker.py').write_text(_image_file('2026.5.2', typo=False))
    d = FakeDocker(box, 'ghcr.io/goauthentik/server:2026.5.6', NEW_ID,
                   {NEW_ID: _image_file('2026.5.6', typo=True)})
    logs, data = _converge(box, d)
    want = f'./patches/broker-76bf433fd434.py:{LEGACY_SPEC.split(":", 1)[1]}'
    assert _broker_vols(data, 'server') == [want] and _broker_vols(data, 'worker') == [want]
    patch = (box / 'patches' / 'broker-76bf433fd434.py').read_text()
    assert 'from 2026.5.6' in patch and FIXED in patch and TYPO not in patch
    assert len(d.ups) == 1
    assert any('replaces a patch cut from another image' in l for l in logs), logs

    # second pass: the patch belongs to this image → trusted, no image read, no bounce
    d2 = FakeDocker(box, d.img, NEW_ID, d.images)
    _converge(box, d2)
    assert d2.image_reads == [] and d2.ups == []


def test_fresh_box_with_typo_gets_the_patch_once(box):
    (box / 'docker-compose.yml').write_text(_compose())
    d = FakeDocker(box, 'ghcr.io/goauthentik/server:2026.5.4', OLD_ID,
                   {OLD_ID: _image_file('2026.5.4', typo=True)})
    _, data = _converge(box, d)
    assert len(_broker_vols(data, 'worker')) == 1 and len(_broker_vols(data, 'server')) == 1
    assert (box / 'patches' / 'broker-a1a1a1a1a1a1.py').exists()
    assert len(d.ups) == 1


def test_unreadable_image_retires_a_stale_mount_but_never_adds_one(box):
    (box / 'docker-compose.yml').write_text(_compose(LEGACY_SPEC))
    (box / 'patches' / 'broker.py').write_text(_image_file('2026.5.2', typo=False))
    d = FakeDocker(box, 'ghcr.io/goauthentik/server:2026.5.6', NEW_ID, {}, run_error=True)
    logs, data = _converge(box, d)
    assert _broker_vols(data, 'worker') == []
    assert any('retiring the unverified patch mount' in l for l in logs), logs

    (box / 'docker-compose.yml').write_text(_compose())
    d = FakeDocker(box, 'ghcr.io/goauthentik/server:2026.5.6', NEW_ID, {}, run_error=True)
    logs, data = _converge(box, d)
    assert _broker_vols(data, 'worker') == [] and d.ups == []


def test_image_outside_2026_5_still_retires_without_reading_it(box):
    (box / 'docker-compose.yml').write_text(_compose(LEGACY_SPEC))
    (box / 'patches' / 'broker.py').write_text('x')
    d = FakeDocker(box, 'ghcr.io/goauthentik/server:2026.8.3', NEW_ID, {})
    _, data = _converge(box, d)
    assert _broker_vols(data, 'worker') == [] and d.image_reads == []


def test_patch_name_takes_only_a_hex_image_id():
    ns = {'re': re}
    exec(compile(SRC, 'app.py', 'exec'), ns)
    name = ns['_ak_broker_patch_name']
    assert name(NEW_ID) == 'broker-76bf433fd434.py'
    for bad in ('', 'ghcr.io/goauthentik/server:2026.5.7', 'sha256:../../etc/x',
                'sha256:ABCDEF012345', 'sha256:76bf43', 'sha256:76bf433fd434:ro'):
        assert name(bad) == '', bad


def test_update_drops_the_mount_before_the_new_image_starts():
    ns = {'re': re}
    exec(compile(SRC, 'app.py', 'exec'), ns)
    strip = ns['_ak_compose_without_broker_patch']
    out = strip(_compose(LEGACY_SPEC), yaml)
    data = yaml.safe_load(out)
    assert _broker_vols(data, 'server') == [] and _broker_vols(data, 'worker') == []
    assert './data:/data' in data['services']['worker']['volumes']
    assert strip(_compose(), yaml) is None and strip('a: [unclosed', yaml) is None

    # Wiring in the local Update action: strip before the pull/recreate, record it for the
    # failure rollback, and re-run the converge only after the new image is confirmed.
    m = re.search(r"    elif action == 'update':\n        # v10\.1\.39 \(COPIX", APP)
    body = APP[m.start():APP.index("@app.route('/api/authentik/deploy'", m.end())]
    i_strip = body.index('_ak_compose_without_broker_patch(')
    assert i_strip < body.index("['docker', 'compose', 'pull']")
    assert "_pin_orig['compose_changed'] = True" in body[i_strip:i_strip + 400]
    i_kick = body.index('target=_startup_authentik_idle_load_converge')
    assert body.index('if _run_tag != latest:') < i_kick
