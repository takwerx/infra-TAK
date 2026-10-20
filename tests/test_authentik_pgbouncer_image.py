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
"""Existing PgBouncer sidecars are moved onto the pinned image (ops #91).

_ensure_authentik_pgbouncer() writes `_AUTHENTIK_PGBOUNCER_IMAGE` only when it first adds
the service, so bumping the pin never reached a box that already had PgBouncer.
_ensure_authentik_pgbouncer_image() is cut out of app.py and run against a temp compose
with docker stubbed.
"""

import contextlib
import datetime
import os
import pathlib
import re
import subprocess
import types

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
PIN = re.search(r"^_AUTHENTIK_PGBOUNCER_IMAGE = '([^']+)'", APP, re.M).group(1)
OLD = 'edoburu/pgbouncer:v1.25.1-p0'


def _compose(image):
    return {'services': {
        'postgresql': {'image': 'docker.io/library/postgres:16-alpine'},
        'pgbouncer': {'image': image, 'environment': {'DB_HOST': 'postgresql'}},
        'server': {'environment': {'AUTHENTIK_POSTGRESQL__HOST': 'pgbouncer'}},
    }}


def _run(tmp_path, image, pull_rc=0, up_rc=0, inspect=None):
    ak = tmp_path / 'authentik'
    ak.mkdir()
    (ak / 'docker-compose.yml').write_text(yaml.safe_dump(_compose(image), sort_keys=False))
    src = re.search(r'^def _ensure_authentik_pgbouncer_image\(.*?(?=^def )', APP, re.S | re.M).group(0)
    calls, settings, log = [], {}, []
    live = {'image': image}

    def run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ['docker', 'pull']:
            return subprocess.CompletedProcess(cmd, pull_rc, stdout='', stderr='pull boom' if pull_rc else '')
        if cmd[:3] == ['docker', 'compose', 'up']:
            live['image'] = yaml.safe_load((ak / 'docker-compose.yml').read_text())['services']['pgbouncer']['image']
            return subprocess.CompletedProcess(cmd, up_rc, stdout='', stderr='up boom' if up_rc else '')
        if cmd[:2] == ['docker', 'inspect']:
            return subprocess.CompletedProcess(cmd, 0, stdout=inspect or f"{live['image']} running healthy\n")
        raise AssertionError(cmd)

    @contextlib.contextmanager
    def lock(holder, plog=None):
        yield True

    ns = {
        'os': types.SimpleNamespace(path=types.SimpleNamespace(
            expanduser=lambda p: str(ak) if p == '~/authentik' else p,
            join=os.path.join, exists=os.path.exists)),
        'subprocess': types.SimpleNamespace(run=run),
        'time': types.SimpleNamespace(sleep=lambda s: None),
        'datetime': datetime.datetime,
        '_sudo_wrap': lambda c: c,
        '_authentik_compose_lock': lock,
        '_AUTHENTIK_PGBOUNCER_IMAGE': PIN,
        'load_settings': lambda: settings,
        'save_settings': lambda s: settings.update(s),
    }
    exec(compile(src, 'app.py:_ensure_authentik_pgbouncer_image', 'exec'), ns)
    out = ns['_ensure_authentik_pgbouncer_image'](log.append)
    on_disk = yaml.safe_load((ak / 'docker-compose.yml').read_text())
    return out, on_disk, calls, settings, log


def test_pin_is_an_exact_v_tag_past_the_vulnerable_releases():
    m = re.fullmatch(r'edoburu/pgbouncer:v(\d+)\.(\d+)\.(\d+)-p\d+', PIN)
    assert m, PIN
    assert tuple(map(int, m.groups())) >= (1, 26, 1)


def test_old_image_is_moved_to_the_pin(tmp_path):
    out, compose, calls, settings, _ = _run(tmp_path, OLD)
    assert out is True
    assert compose['services']['pgbouncer']['image'] == PIN
    assert calls[0] == ['docker', 'pull', PIN]                    # pulled before compose is touched
    up = [c for c in calls if c[:3] == ['docker', 'compose', 'up']]
    assert up == [['docker', 'compose', 'up', '-d', '--force-recreate', '--no-deps', 'pgbouncer']]
    assert settings['authentik_pgbouncer']['image'] == PIN
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'applied'
    assert compose['services']['server']['environment']['AUTHENTIK_POSTGRESQL__HOST'] == 'pgbouncer'


def test_already_on_pin_is_a_noop(tmp_path):
    out, compose, calls, _, _ = _run(tmp_path, PIN)
    assert out is False
    assert calls == []


def test_non_edoburu_image_is_left_alone(tmp_path):
    out, compose, calls, _, _ = _run(tmp_path, 'bitnami/pgbouncer:1.26.1')
    assert out is False
    assert calls == []
    assert compose['services']['pgbouncer']['image'] == 'bitnami/pgbouncer:1.26.1'


def test_failed_pull_changes_nothing(tmp_path):
    out, compose, calls, settings, _ = _run(tmp_path, OLD, pull_rc=1)
    assert out is None
    assert compose['services']['pgbouncer']['image'] == OLD
    assert not [c for c in calls if c[:2] == ['docker', 'compose']]
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'pull-failed'


def test_unhealthy_container_rolls_back(tmp_path):
    out, compose, calls, settings, log = _run(tmp_path, OLD, inspect=f'{PIN} running unhealthy\n')
    assert out is None
    assert compose['services']['pgbouncer']['image'] == OLD
    assert len([c for c in calls if c[:3] == ['docker', 'compose', 'up']]) == 2   # new, then back
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'rolled-back'
    assert 'image' not in settings['authentik_pgbouncer']


def test_failed_recreate_rolls_back(tmp_path):
    out, compose, _, settings, _ = _run(tmp_path, OLD, up_rc=1)
    assert out is None
    assert compose['services']['pgbouncer']['image'] == OLD
    assert settings['authentik_pgbouncer']['image_last_outcome'] == 'recreate-failed'


def test_startup_migration_calls_it():
    boot = APP[APP.index('_ensure_authentik_worker_direct_pg(lambda m:'):]
    assert '_ensure_authentik_pgbouncer_image(lambda m:' in boot[:2000]
