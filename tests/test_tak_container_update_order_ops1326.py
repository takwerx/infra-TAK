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
"""Docker TAK Server "Update TAK Server" checks first and deletes last (ops #1326).

Before: run_takserver_upgrade_container removed both TAK containers, THEN looked at the zip,
deleted the old bundle folder (snapshots, setenv.sh, plugins, logs) BEFORE the build, and built
last. A build that failed left TAK down with nothing to retry from; a 5.7 zip on a 5.8 box built
a PostgreSQL 15 image on a PostgreSQL 18 volume.

The real function runs here against a fake Docker and a real temporary folder tree: the fake
records every docker call, so "no container was touched" and "the old folder is still there" are
asserted on what actually happened, not on source text. Set INFRATAK_APP_PY to run the same
tests against another app.py (that is how the base branch is shown red).
"""

import os
import pathlib
import re
import shutil
import time
import types
import zipfile

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = pathlib.Path(os.environ.get('INFRATAK_APP_PY') or REPO / 'app.py').read_text(encoding='utf-8')

HARDENED_DB = ('FROM registry.access.redhat.com/ubi10/ubi:10.2\n'
               'RUN dnf -y install postgresql18-server postgresql18 glibc-locale-source\n'
               'VOLUME /var/lib/postgresql/data\nENV PGDATA=/var/lib/postgresql/data\n')
LEGACY_DB = 'FROM postgres:15.1\nRUN echo legacy\n'
HEAP = ('# >>> infra-TAK managed heap >>>\nexport CONFIG_MAX_HEAP=512\n'
        '# <<< infra-TAK managed heap <<<\n')
STOCK_SETENV = '#!/bin/sh\n# stock for the new release\nexport FOO=1\n'


def _try_cut(name):
    m = re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M)
    return m.group(0) if m else None


def _const(name):
    m = re.search(rf'^{name} = .*?(?=^\S)', APP, re.S | re.M)
    return m.group(0) if m else None


def _load(ns, names):
    for n in names:
        src = _try_cut(n)
        if src:
            exec(src, ns)


def _make_zip(path, top, db_text, hardened=True):
    app_df = 'Dockerfile.hardened-takserver' if hardened else 'Dockerfile.takserver'
    db_df = app_df + '-db'
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr(f'{top}/docker/{app_df}', 'FROM scratch\n')
        z.writestr(f'{top}/docker/{db_df}', db_text)
        z.writestr(f'{top}/tak/setenv.sh', STOCK_SETENV)
        z.writestr(f'{top}/tak/CoreConfig.example.xml', '<x/>')


class Box:
    """A fake Docker host plus the real folder tree of one container TAK Server box."""

    def __init__(self, tmp, old_top='takserver-docker-hardened-5.8-RELEASE-105',
                 layout='ROOT=18 LEGACY=none'):
        self.root = tmp / 'tak-docker'
        self.root.mkdir()
        self.layout = layout
        self.calls = []                    # every docker / file command, in order
        self.fail = set()                  # 'build_db' 'build_app' 'start_new' 'no_messaging'
        self.old_ctx = self.root / old_top
        old_tak = self.old_ctx / 'tak'
        for d in ('certs/files', 'snapshots/pre-1', 'logs', 'lib', 'conf/plugins', 'docker'):
            (old_tak / d).mkdir(parents=True)
        (old_tak / 'certs/files/takserver.jks').write_text('jks')
        (old_tak / 'snapshots/pre-1/cot.pgdump').write_text('dump')
        (old_tak / 'logs/takserver-messaging.log').write_text('old log')
        (old_tak / 'lib/my-plugin.jar').write_text('jar')
        (old_tak / 'conf/plugins/my.plugin.yaml').write_text('y')
        (old_tak / 'CoreConfig.xml').write_text('<core pw="x"/>')
        (old_tak / 'UserAuthenticationFile.xml').write_text('<uaf/>')
        (old_tak / 'setenv.sh').write_text(HEAP + '#!/bin/sh\n# old stock\nexport OLD=1\n')
        (self.old_ctx / 'docker/Dockerfile.hardened-takserver').parent.mkdir(exist_ok=True)
        (self.old_ctx / 'docker/Dockerfile.hardened-takserver').write_text('x')
        (self.old_ctx / 'docker/Dockerfile.hardened-takserver-db').write_text(HARDENED_DB)
        self.link = old_tak
        self.images = {'takserver': 'img-old-app', 'takserver_db': 'img-old-db'}
        self.containers = {'takserver': {'image': 'img-old-app', 'bundle': str(old_tak)},
                           'takserver-db': {'image': 'img-old-db', 'bundle': str(old_tak)}}
        self.n = 0
        self.vol_created = '2000-01-01T00:00:00Z'     # the database volume is older than any folder made now
        self.zip_dir = tmp / 'uploads'
        self.zip_dir.mkdir()

    # -- fake subprocess.run ------------------------------------------------
    def run(self, cmd, shell=False, capture_output=False, text=False, timeout=None,
            input=None, cwd=None, env=None, **kw):
        r = types.SimpleNamespace(returncode=0, stdout='', stderr='')
        self.calls.append(cmd if isinstance(cmd, str) else ' '.join(cmd))
        if isinstance(cmd, str):
            return self._shell(cmd, r)
        return self._argv(list(cmd), r)

    def _shell(self, cmd, r):
        if cmd.startswith('ln -sfn '):
            self.link = pathlib.Path(cmd.split()[2].strip("'"))
        elif ' docker build ' in cmd:
            tag = cmd.split(' -t ')[1].split()[0]
            if ('build_db' in self.fail and 'db' in cmd.split(' -f ')[1].split()[0]) or \
                    ('build_app' in self.fail and 'db' not in cmd.split(' -f ')[1].split()[0]):
                r.returncode, r.stderr = 1, 'registry unreachable'
            else:
                self.n += 1
                self.images[tag] = f'img-new-{self.n}'
        elif cmd.startswith('docker run '):
            r.returncode = self._start('takserver-db', cmd, 'takserver_db')
        elif cmd.startswith('docker create '):
            r.returncode = self._start('takserver', cmd, 'takserver', created=True)
        elif cmd.startswith('docker start '):
            if 'start_new' in self.fail and self.containers.get('takserver', {}).get('new'):
                r.returncode = 1
        return r

    def _start(self, name, cmd, image, created=False):
        bundle = re.search(r"-v '?([^ :']+):/opt/tak", cmd).group(1)
        is_new = bundle != str(self.old_ctx / 'tak')
        if is_new and 'start_new' in self.fail and name == 'takserver-db':
            return 1
        if not is_new and 'rollback_once' in self.fail and name == 'takserver-db':
            self.fail.discard('rollback_once')       # the first try to put the old version back fails
            return 1
        self.containers[name] = {'image': self.images[image], 'bundle': bundle, 'new': is_new}
        return 0

    def _argv(self, a, r):
        if a[0] == 'docker':
            sub = a[1]
            if sub == 'rm':
                for c in a[3:]:
                    self.containers.pop(c, None)
            elif sub == 'tag':
                if a[2] in self.images:
                    self.images[a[3]] = self.images[a[2]]
                else:
                    r.returncode = 1
            elif sub == 'image' and a[2] == 'rm':
                if self.images.pop(a[3], None) is None:
                    r.returncode = 1
            elif sub == 'inspect':
                r.stdout = 'true\n' if a[-1] in self.containers else ''
                r.returncode = 0 if a[-1] in self.containers else 1
            elif sub == 'container' and a[2] == 'inspect':       # containers only, never an image (ops #1367)
                r.returncode = 0 if (a[-1] in self.containers and 'docker_down' not in self.fail) else 1
            elif sub == 'ps':
                r.returncode = 1 if 'docker_down' in self.fail else 0
            elif sub == 'volume':
                if '-f' in a:                                  # `docker volume inspect -f {{.CreatedAt}}` (ops #1367)
                    r.stdout = self.vol_created + '\n'
            elif sub == 'run' and '--entrypoint' in a:
                if 'grep' not in ' '.join(a):
                    r.stdout = self.layout if self.layout else ''
                    r.returncode = 0 if self.layout else 1
            elif sub == 'exec' and 'grep' in a:
                r.returncode = 1 if 'no_messaging' in self.fail else 0
            return r
        op, rest = a[0], a[1:]
        paths = [x for x in rest if not x.startswith('-')]
        try:
            if op == 'rm':
                for p in paths:
                    if p == '/opt/tak':
                        self.link = None
                    elif os.path.isdir(p) and not os.path.islink(p):
                        shutil.rmtree(p)
                    elif os.path.exists(p):
                        os.remove(p)
            elif op == 'mkdir':
                os.makedirs(paths[0], exist_ok=True)
            elif op == 'cp':
                src, dst = paths[0], paths[1]
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(src, dst)
            elif op == 'mv':
                shutil.move(paths[0], paths[1])
            elif op == 'ls':
                r.stdout = '\n'.join(sorted(os.listdir(paths[0]))) + '\n' if os.path.isdir(paths[0]) else ''
                r.returncode = 0 if os.path.isdir(paths[0]) else 2
            elif op == 'chmod':
                pass
        except Exception as e:                                   # a failed command, like the real one
            r.returncode, r.stderr = 1, str(e)
        return r


def _ns(box):
    """The globals the real function sees, with Docker and /opt/tak faked."""
    class FakeOS:
        path = types.SimpleNamespace(
            **{k: getattr(os.path, k) for k in dir(os.path) if not k.startswith('__')})

        def __getattr__(self, n):
            return getattr(os, n)
    fos = FakeOS()
    fos.path.realpath = lambda p: str(box.link) if p == '/opt/tak' and box.link else os.path.realpath(p)
    logged = []
    ns = {
        'os': fos, 're': re, 'shlex': __import__('shlex'), 'shutil': shutil,
        'subprocess': types.SimpleNamespace(run=box.run, TimeoutExpired=Exception),
        'time': types.SimpleNamespace(sleep=lambda s: None, strftime=time.strftime, time=time.time),
        'datetime': __import__('datetime').datetime,
        'upgrade_log': logged, 'upgrade_status': {'running': True, 'complete': False, 'error': False},
        'TAK_DOCKER_ROOT': str(box.root), 'TAK_CONTAINER': 'takserver', 'TAK_DB_CONTAINER': 'takserver-db',
        'TAK_DB_IMAGE': 'takserver_db', 'TAK_DB_VOLUME': 'takserver_pgsql', 'TAK_DOCKER_NET': 'takserver',
        'TAK_PG_MAJOR': 18,
        '_sudo_wrap': lambda c: c,
        '_safe_extract_zip': lambda zf, dest, strip_prefix='', apply_modes=False: zf.extractall(dest),
        '_tak_bundle_repair_exec_bits': lambda *a, **k: None,
        '_patch_tak_db_dockerfile': lambda *a, **k: None,
        '_patch_tak_hardened_dockerfile': lambda *a, **k: None,
        '_patch_tak_hardened_java_pin': lambda *a, **k: None,
        '_patch_tak_db_pgdg_releasever': lambda *a, **k: None,
        '_patch_tak_dockerfile_cacerts': lambda *a, **k: None,
        '_carry_cert_metadata': lambda *a, **k: [],
        '_container_own_tree': lambda *a, **k: True,
        '_ensure_tak_on_authentik_network': lambda: (None, None),
        '_tak_repair_container_healthchecks': lambda *a, **k: None,
        '_takportal_web_running': lambda: False,
        '_read_priv': lambda p: pathlib.Path(p).read_text(),
        '_write_priv': lambda p, c, **k: pathlib.Path(p).write_text(c),
        '_makedirs_priv': lambda p, mode=None, exist_ok=True: os.makedirs(p, exist_ok=True),
        '_tak58_db_password': lambda: 'pw',
        '_tak58_container_pgbin': lambda c, m: '/usr/pgsql-18/bin' if m == 18 else None,
        '_TAK_SETENV_JVM_A': '# >>> infra-TAK managed JVM >>>',
        '_TAK_SETENV_JVM_B': '# <<< infra-TAK managed JVM <<<',
    }

    def fake_backup(pgbin, pw, say, stamp, prefix='pre-dbrefresh'):
        d = box.root / 'snapshots' / f'{prefix}-{stamp}'
        d.mkdir(parents=True, exist_ok=True)
        (d / 'cot.pgdump').write_text('dump')
        return str(d / 'cot.pgdump'), ''
    ns['_tak_db_refresh_backup'] = fake_backup
    for c in ('_TAK_RELEASE_RE', '_TAK_UPDATE_BACKUP_KEEP', '_TAK_UPDATE_BACKUP_RE',
              '_TAK_SETENV_HEAP_A', '_TAK_SETENV_HEAP_B'):
        src = _const(c)
        if src:
            exec(src, ns)
    ns['_TAK_DOCKERFILES'] = (
        ('docker/Dockerfile.hardened-takserver', 'docker/Dockerfile.hardened-takserver-db'),
        ('docker/Dockerfile.takserver', 'docker/Dockerfile.takserver-db'))
    _load(ns, ['_pg_run', '_tak_release_key', '_tak_fmt_release', '_tak_bundle_dockerfiles',
               '_tak_is_bundle_dir', '_tak_db_volume_mount', '_tak_dockerfile_pg_major',
               '_tak_zip_bundle_info', '_tak_db_volume_layout', '_tak_volume_check',
               '_tak_container_missing', '_tak_docker_time', '_tak_volume_predates_folder',
               '_tak_container_update_preflight', '_tak_pre_update_backup',
               '_tak_setenv_carry',
               '_tak_carry_missing', 'run_takserver_upgrade_container'])
    return ns


def _update(tmp_path, new_top, new_db=HARDENED_DB, hardened=True, fail=(), layout='ROOT=18 LEGACY=none',
            old_top='takserver-docker-hardened-5.8-RELEASE-105', zip_name=None, **kw):
    box = Box(tmp_path, old_top=old_top, layout=layout)
    box.fail = set(fail)
    z = box.zip_dir / (zip_name or f'{new_top}.zip')
    _make_zip(z, new_top, new_db, hardened)
    ns = _ns(box)
    ns['run_takserver_upgrade_container'](str(z), **kw)
    return box, ns, ns['upgrade_status'], '\n'.join(ns['upgrade_log'])


def _docker_rm_calls(box):
    return [c for c in box.calls if c.startswith('docker rm ')]


def _old_untouched(box):
    assert box.link == box.old_ctx / 'tak', 'the /opt/tak link moved'
    assert (box.old_ctx / 'tak/snapshots/pre-1/cot.pgdump').read_text() == 'dump'
    assert (box.old_ctx / 'tak/setenv.sh').read_text().startswith(HEAP)
    assert (box.old_ctx / 'tak/lib/my-plugin.jar').exists()
    assert (box.old_ctx / 'tak/logs/takserver-messaging.log').exists()
    assert (box.old_ctx / 'tak/certs/files/takserver.jks').exists()


# ── what the update refuses BEFORE it touches anything ──────────────────────

def test_older_minor_zip_is_refused_and_no_container_is_touched(tmp_path):
    box, ns, st, log = _update(tmp_path, 'takserver-docker-5.7-RELEASE-43', LEGACY_DB, hardened=False)
    assert st['error'] and not st['complete']
    assert 'older than the 5.8' in log
    assert _docker_rm_calls(box) == [], box.calls
    assert set(box.containers) == {'takserver', 'takserver-db'}
    assert box.images == {'takserver': 'img-old-app', 'takserver_db': 'img-old-db'}
    _old_untouched(box)


def test_zip_that_does_not_fit_the_database_volume_is_refused(tmp_path):
    # 5.8 hardened image (PostgreSQL 18) but the volume holds a PostgreSQL 17 cluster.
    box, ns, st, log = _update(tmp_path, 'takserver-docker-hardened-5.8-RELEASE-106',
                               layout='ROOT=17 LEGACY=none')
    assert st['error']
    assert 'PostgreSQL 18 but your data is PostgreSQL 17' in log
    assert _docker_rm_calls(box) == []
    _old_untouched(box)


def test_zip_with_the_other_volume_layout_would_start_an_empty_database_and_is_refused(tmp_path):
    # Legacy-layout (5.7 era) image on a volume whose cluster sits at the volume root (5.8).
    box, ns, st, log = _update(tmp_path, 'takserver-docker-5.8-RELEASE-106', LEGACY_DB, hardened=False,
                               layout='ROOT=18 LEGACY=none')
    assert st['error'] and 'EMPTY database' in log
    assert _docker_rm_calls(box) == []
    _old_untouched(box)


def test_unreadable_volume_refuses_instead_of_guessing(tmp_path):
    box, ns, st, log = _update(tmp_path, 'takserver-docker-hardened-5.8-RELEASE-106', layout='')
    assert st['error'] and 'could not be read' in log
    assert _docker_rm_calls(box) == []
    _old_untouched(box)


def test_the_installed_version_again_is_refused_without_unpacking(tmp_path):
    box, ns, st, log = _update(tmp_path, 'takserver-docker-hardened-5.8-RELEASE-105')
    assert st['error'] and 'already installed' in log
    assert _docker_rm_calls(box) == []
    _old_untouched(box)


def test_a_zip_that_is_not_a_takserver_bundle_is_refused(tmp_path):
    box = Box(tmp_path)
    z = box.zip_dir / 'junk.zip'
    with zipfile.ZipFile(z, 'w') as zf:
        zf.writestr('junk/readme.txt', 'x')
    ns = _ns(box)
    ns['run_takserver_upgrade_container'](str(z))
    assert ns['upgrade_status']['error'] and _docker_rm_calls(box) == []
    _old_untouched(box)


# ── a failed build leaves TAK running on the old version ────────────────────

@pytest.mark.parametrize('which', ['build_db', 'build_app'])
def test_failed_build_keeps_the_old_tak_running_and_the_old_folder(tmp_path, which):
    box, ns, st, log = _update(tmp_path, 'takserver-docker-hardened-5.8-RELEASE-106', fail=[which])
    assert st['error'] and not st['complete']
    assert 'still runs the old version' in log
    assert _docker_rm_calls(box) == [], 'a container was removed before the build worked'
    assert set(box.containers) == {'takserver', 'takserver-db'}
    assert box.images['takserver'] == 'img-old-app' and box.images['takserver_db'] == 'img-old-db'
    assert not any(k.startswith(('takserver:', 'takserver_db:')) for k in box.images), box.images
    assert not (box.root / 'takserver-docker-hardened-5.8-RELEASE-106').exists(), 'half-made folder left'
    _old_untouched(box)
    # and pressing Update again with the same zip works once the build can run
    z = next(box.zip_dir.glob('*.zip'))
    box.fail.clear()
    st.update({'running': True, 'complete': False, 'error': False})
    ns['run_takserver_upgrade_container'](str(z))
    assert st['complete'] and not st['error']


def test_backup_is_taken_outside_the_bundle_before_anything_changes(tmp_path):
    box, ns, st, log = _update(tmp_path, 'takserver-docker-hardened-5.8-RELEASE-106', fail=['build_app'])
    snaps = [d for d in (box.root / 'snapshots').iterdir() if d.name.startswith('pre-update-')]
    assert len(snaps) == 1
    assert (snaps[0] / 'cot.pgdump').exists() and (snaps[0] / 'CoreConfig.xml').exists()
    assert (snaps[0] / 'setenv.sh').read_text().startswith(HEAP)


# ── the swap ────────────────────────────────────────────────────────────────

def test_new_tak_that_does_not_start_puts_the_old_version_back(tmp_path):
    box, ns, st, log = _update(tmp_path, 'takserver-docker-hardened-5.8-RELEASE-106', fail=['start_new'])
    assert st['error'] and 'old version is running again' in log
    assert set(box.containers) == {'takserver', 'takserver-db'}
    assert box.containers['takserver']['bundle'] == str(box.old_ctx / 'tak')
    assert box.containers['takserver-db']['bundle'] == str(box.old_ctx / 'tak')
    assert box.images['takserver'] == 'img-old-app' and box.images['takserver_db'] == 'img-old-db'
    assert not any(k.startswith(('takserver:', 'takserver_db:')) for k in box.images), box.images
    assert not (box.root / 'takserver-docker-hardened-5.8-RELEASE-106').exists()
    _old_untouched(box)


def test_old_version_is_tried_again_when_the_first_try_to_put_it_back_fails(tmp_path):
    box, ns, st, log = _update(tmp_path, 'takserver-docker-hardened-5.8-RELEASE-106',
                               fail=['start_new', 'rollback_once'])
    assert st['error'] and 'old version is running again' in log
    assert 'once more' in log
    assert box.containers['takserver']['bundle'] == str(box.old_ctx / 'tak')
    _old_untouched(box)


def test_failed_database_dump_stops_before_any_change_and_leaves_no_half_backup(tmp_path):
    box = Box(tmp_path)
    z = box.zip_dir / 'takserver-docker-hardened-5.8-RELEASE-106.zip'
    _make_zip(z, 'takserver-docker-hardened-5.8-RELEASE-106', HARDENED_DB)
    ns = _ns(box)
    ns['_tak_db_refresh_backup'] = lambda *a, **k: ('', 'pg_dump exit 1')
    ns['run_takserver_upgrade_container'](str(z))
    assert ns['upgrade_status']['error']
    assert 'backup failed' in '\n'.join(ns['upgrade_log'])
    assert _docker_rm_calls(box) == []
    assert not [d for d in (box.root / 'snapshots').glob('pre-update-*')], 'half-made backup folder left'
    _old_untouched(box)


def test_successful_update_carries_the_old_files_and_deletes_the_old_folder_last(tmp_path):
    box, ns, st, log = _update(tmp_path, 'takserver-docker-hardened-5.8-RELEASE-106')
    assert st['complete'] and not st['error'], log
    new_tak = box.root / 'takserver-docker-hardened-5.8-RELEASE-106' / 'tak'
    assert box.link == new_tak
    assert not box.old_ctx.exists()
    assert (new_tak / 'snapshots/pre-1/cot.pgdump').read_text() == 'dump'
    assert (new_tak / 'lib/my-plugin.jar').exists() and (new_tak / 'conf/plugins/my.plugin.yaml').exists()
    assert (new_tak / 'logs').is_dir() and any(
        p.name.startswith('before-update-') and (p / 'takserver-messaging.log').exists()
        for p in (new_tak / 'logs').iterdir())
    se = (new_tak / 'setenv.sh').read_text()
    assert se.startswith(HEAP) and 'stock for the new release' in se and 'OLD=1' not in se
    assert (new_tak / 'certs/files/takserver.jks').exists()
    assert box.containers['takserver']['bundle'] == str(new_tak)
    assert box.images['takserver'].startswith('img-new') and box.images['takserver_db'].startswith('img-new')
    assert not any(':' in k for k in box.images), 'temporary image tags were left behind'
    # the old folder goes after the new TAK reported it is up
    rm_old = next(i for i, c in enumerate(box.calls) if c.startswith('rm -rf') and str(box.old_ctx) in c)
    up = max(i for i, c in enumerate(box.calls) if c.startswith('docker exec') and 'grep' in c)
    assert up < rm_old


def test_old_folder_is_kept_when_the_new_tak_does_not_report_it_is_up(tmp_path):
    box, ns, st, log = _update(tmp_path, 'takserver-docker-hardened-5.8-RELEASE-106', fail=['no_messaging'])
    assert box.old_ctx.exists(), 'the old folder was deleted though the new TAK never came up'
    assert 'KEPT' in log
    assert (box.old_ctx / 'tak/snapshots/pre-1/cot.pgdump').exists()


def test_same_minor_older_zip_is_allowed_with_a_warning(tmp_path):
    box, ns, st, log = _update(tmp_path, 'takserver-docker-hardened-5.8-RELEASE-104')
    assert st['complete'], log
    assert 'DOWNGRADE' in log


# ── the 5.8 migration calls this function after it removed the volume ───────

def test_migration_call_needs_no_volume_check_and_takes_no_backup(tmp_path):
    # the migration already removed the old containers and the volume (nothing to read)
    box = Box(tmp_path, old_top='takserver-docker-5.7-RELEASE-43', layout='')
    box.containers.clear()
    z = box.zip_dir / 'takserver-docker-hardened-5.8-RELEASE-105.zip'
    _make_zip(z, 'takserver-docker-hardened-5.8-RELEASE-105', HARDENED_DB)
    ns = _ns(box)
    ns['run_takserver_upgrade_container'](str(z), mark_complete=False, migration=True)
    st = ns['upgrade_status']
    assert not st['error'] and st['running'], '\n'.join(ns['upgrade_log'])
    assert not (box.root / 'snapshots').exists()
    assert set(box.containers) == {'takserver', 'takserver-db'}


def test_migration_call_with_a_failed_build_keeps_the_old_bundle_folder(tmp_path):
    box = Box(tmp_path, old_top='takserver-docker-5.7-RELEASE-43', layout='')
    box.containers.clear()
    box.fail = {'build_app'}
    z = box.zip_dir / 'takserver-docker-hardened-5.8-RELEASE-105.zip'
    _make_zip(z, 'takserver-docker-hardened-5.8-RELEASE-105', HARDENED_DB)
    ns = _ns(box)
    ns['run_takserver_upgrade_container'](str(z), mark_complete=False, migration=True)
    assert ns['upgrade_status']['error']
    _old_untouched(box)


def test_the_migration_passes_migration_true(tmp_path):
    assert 'run_takserver_upgrade_container(zip_path, mark_complete=False, migration=True)' in APP


# ── pure helpers ────────────────────────────────────────────────────────────

def _pure():
    ns = {'re': re}
    _load(ns, ['_tak_dockerfile_pg_major', '_tak_volume_check'])
    return ns


def test_dockerfile_pg_major_reads_both_eras():
    f = _pure()['_tak_dockerfile_pg_major']
    assert f(HARDENED_DB) == 18
    assert f(LEGACY_DB) == 15
    assert f('FROM docker.io/library/postgres:17-bookworm\n') == 17
    assert f('FROM busybox\n') is None


@pytest.mark.parametrize('hardened,image,vol,ok', [
    (True, 18, {'exists': True, 'root': 18, 'legacy': None}, True),
    (True, 18, {'exists': True, 'root': 17, 'legacy': None}, False),
    (True, 18, {'exists': True, 'root': None, 'legacy': 15}, False),      # 5.8 zip on a 5.7 volume
    (False, 15, {'exists': True, 'root': None, 'legacy': 15}, True),
    (False, 15, {'exists': True, 'root': 18, 'legacy': None}, False),     # 5.7 zip on a 5.8 volume
    (True, 18, {'exists': False, 'root': None, 'legacy': None}, True),
    (True, 18, {'exists': True, 'root': None, 'legacy': None}, True),     # empty volume
    (True, None, {'exists': True, 'root': 18, 'legacy': None}, True),     # image major unknown, layout fits
    (True, 18, None, False),                                              # unreadable
])
def test_volume_check_table(hardened, image, vol, ok):
    assert _pure()['_tak_volume_check'](hardened, image, vol)[0] is ok


def test_backups_older_than_the_newest_two_are_removed(tmp_path):
    box = Box(tmp_path)
    for s in ('20261101-010101', '20261102-010101', '20261103-010101'):
        (box.root / 'snapshots' / f'pre-update-{s}').mkdir(parents=True)
    (box.root / 'snapshots' / 'pre-58-container-20261001-010101').mkdir()
    ns = _ns(box)
    ok, d = ns['_tak_pre_update_backup']('20261104-010101', str(box.old_ctx / 'tak'), lambda m: None)
    assert ok
    left = sorted(p.name for p in (box.root / 'snapshots').iterdir())
    assert left == ['pre-58-container-20261001-010101', 'pre-update-20261103-010101',
                    'pre-update-20261104-010101']
