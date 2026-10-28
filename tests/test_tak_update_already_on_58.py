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
"""Update TAK Server on a box already on 5.8 + PostgreSQL 18 (ops #309).

Field (Cape Security Patrol): with a 5.8 package uploaded, the Update button always ran
the 5.8 migration, even on a box already on 5.8 and PostgreSQL 18. The migration stopped
TAK, "installed" the same version, upgrade-db.sh found no PostgreSQL 15 and exited 1, and
the console printed "MID-UPGRADE" for a healthy server. The plain path was blocked for any
5.8 package by the gate, so such a box could not take a 5.8.x update at all.

takserver_update is cut out of app.py and run with the package directory, the pre-flight
and the thread launcher faked, so what is asserted is WHICH worker the button starts.
"""

import os
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?(?=^\S)', APP, re.S | re.M).group(0)


def _env(installed, pf_facts, upload_dir, container=False, family='debian',
         deployment=None, allow_58=False):
    started = []

    class FakeThread:
        def __init__(self, target=None, args=(), kwargs=None, daemon=None):
            self.target, self.args = target, args

        def start(self):
            started.append((self.target, self.args))

    n = {
        'os': os, 're': re, 'threading': types.SimpleNamespace(Thread=FakeThread),
        'jsonify': lambda d: d,
        'UPLOAD_DIR': str(upload_dir),
        'upgrade_status': {'running': False}, 'upgrade_log': [],
        'TAK_PG_MAJOR': 18,
        'load_settings': lambda: {'allow_tak_58': allow_58},
        '_tak_is_container': lambda: container,
        '_distro_family': lambda: family,
        '_get_tak_deployment_config': lambda s: deployment or {},
        '_get_takserver_version_info': lambda: {'version': installed},
        '_tak_58_preflight': lambda: {'ready': True, 'blockers': [], 'facts': pf_facts},
        # the worker's name says which one the button chose
        '_tak_update_job': lambda label, fn, log, status: fn.__name__,
    }
    for w in ('run_takserver_upgrade', 'run_takserver_upgrade_rhel',
              'run_takserver_upgrade_container', 'run_takserver_58_migration',
              'run_takserver_58_container_migration'):
        n[w] = (lambda name: type(name, (), {'__call__': lambda self: None,
                                              '__name__': name})())(w)
    for c in ('_TAK_VER_RE', 'TAK_GATE_BLOCK_FROM'):
        exec(_const(c), n)
    n['TAK_GATE_MESSAGE'] = 'gate'
    for f in ('_tak_artifact_version', '_tak_target_version_gate', '_tak_already_on_58',
              'takserver_update'):
        exec(_cut(f), n)
    return n, started


def _click(tmp_path, pkg, installed, facts, **kw):
    (tmp_path / pkg).write_bytes(b'x')
    n, started = _env(installed, facts, tmp_path, **kw)
    os_exists = os.path.exists
    n['os'] = types.SimpleNamespace(
        listdir=os.listdir, path=types.SimpleNamespace(
            exists=lambda p: True if p == '/opt/tak' else os_exists(p),
            join=os.path.join, getmtime=os.path.getmtime, basename=os.path.basename,
            realpath=os.path.realpath, dirname=os.path.dirname))
    resp = n['takserver_update']()
    return resp, [t for t, _ in started]


DEB = 'takserver_5.8-RELEASE92_all.deb'


def test_box_already_on_58_pg18_takes_the_plain_upgrade_not_the_migration(tmp_path):
    resp, started = _click(tmp_path, DEB, '5.8-RELEASE90',
                           {'already_migrated': True, 'pg_running_major': 18})
    assert resp == {'success': True}
    assert started == ['run_takserver_upgrade']


def test_pg15_box_still_gets_the_guided_migration(tmp_path):
    resp, started = _click(tmp_path, DEB, '5.7-RELEASE32', {'pg_running_major': 15})
    assert resp.get('migration') is True
    assert started == ['run_takserver_58_migration']


def test_57_package_on_a_57_box_is_unaffected(tmp_path):
    resp, started = _click(tmp_path, 'takserver_5.7-RELEASE40_all.deb', '5.7-RELEASE32',
                           {'pg_running_major': 15})
    assert resp == {'success': True}
    assert started == ['run_takserver_upgrade']


def test_58_installed_but_database_unreadable_is_not_treated_as_current(tmp_path):
    # Pre-flight could not read the database major: no already_migrated, so the guarded
    # migration (which refuses with a reason) is what runs - never a blind plain install.
    resp, started = _click(tmp_path, DEB, '5.8-RELEASE90', {'pg_running_major': None})
    assert started == ['run_takserver_58_migration']


def test_57_installed_with_pg18_is_not_treated_as_current(tmp_path):
    # PG already on 18 but TAK still 5.7: installing 5.8 is the migration's job.
    resp, started = _click(tmp_path, DEB, '5.7-RELEASE32',
                           {'already_migrated': True, 'pg_running_major': 18})
    assert started == ['run_takserver_58_migration']


def test_rhel_box_already_on_58_uses_the_dnf_upgrade(tmp_path):
    resp, started = _click(tmp_path, 'takserver-5.8-RELEASE92.noarch.rpm', '5.8-RELEASE90',
                           {'already_migrated': True, 'pg_running_major': 18}, family='rhel')
    assert resp == {'success': True}
    assert started == ['run_takserver_upgrade_rhel']


def test_container_already_on_58_uses_the_data_preserving_upgrade(tmp_path):
    resp, started = _click(tmp_path, 'takserver-docker-5.8-RELEASE92.zip', '5.8-RELEASE90',
                           {'already_migrated': True, 'pg_running_major': 18}, container=True)
    assert resp == {'success': True}
    assert started == ['run_takserver_upgrade_container']


def test_preflight_crash_falls_back_to_the_old_behaviour(tmp_path):
    (tmp_path / DEB).write_bytes(b'x')
    n, _ = _env('5.8-RELEASE90', {}, tmp_path)

    def boom():
        raise RuntimeError('db down')
    n['_tak_58_preflight'] = boom
    assert n['_tak_already_on_58']() is False
