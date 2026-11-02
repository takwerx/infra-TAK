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
"""Single-server deploy: TAK Server must not be reported deployed without its database (#128).

Field, lutak2.net 2026-10-07: Remove (drops cot + martiuser), then Deploy 5.8 on a box whose
only PostgreSQL cluster was 15. TAK's 5.8 postinst sees PG15 binaries and skips its database
step ("A pg15 install has been detected…"), leaving no PG18 cluster, no role, no database.
Step 4 only checked `pg_lsclusters | grep 15`, so the deploy reported success and TAK ran
against nothing for days. Now the deploy runs TAK's upgrade-db.sh in that state, and stops
instead of starting TAK when the database still is not there.
"""

import ast
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
PKG58 = '/opt/infratak/uploads/takserver_5.8-RELEASE84_all.deb'
PKG57 = '/opt/infratak/uploads/takserver_5.7-RELEASE43_all.deb'


def _load(names, ns):
    parts = [ast.get_source_segment(APP, n) for n in ast.parse(APP).body
             if isinstance(n, (ast.FunctionDef, ast.Assign)) and (
                 getattr(n, 'name', None) in names or
                 (isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                  and n.targets[0].id in names))]
    assert len(parts) == len(names), 'a function or constant under test was renamed or removed'
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


class _Box:
    """A fake local PostgreSQL that the vendor scripts change, like the real one."""

    def __init__(self, major, role, db, sv=None, upgrade_rc=0, setup_rc=0, upgrade_builds=True,
                 prepare_ok=True):
        self.major, self.role, self.db, self.sv = major, role, db, sv
        self.upgrade_rc, self.setup_rc, self.upgrade_builds = upgrade_rc, setup_rc, upgrade_builds
        self.prepare_ok = prepare_ok
        self.calls = []
        self.prepare_who = None

    def pg_exec(self, args, timeout=30, **kw):
        self.calls.append(('psql', args[-1]))
        out = '%d,%d,%d\n' % (self.major, int(self.role), int(self.db))
        return types.SimpleNamespace(returncode=0, stdout=out, stderr='')

    def schema_version(self):
        return self.sv if self.db else None

    def run_upgrade_db(self, timeout_sec=None, log=None):
        self.calls.append(('upgrade-db.sh',))
        if log is not None:
            log.append('  Upgrade completed, running remaining setups scripts')
        if self.upgrade_rc == 0 and self.upgrade_builds:
            self.major, self.role, self.db, self.sv = 18, True, True, 112
        return self.upgrade_rc

    def run_setup_db(self, timeout_sec=None):
        self.calls.append(('takserver-setup-db.sh',))
        self.role, self.db, self.sv = True, True, (112 if self.major == 18 else 99)
        return self.setup_rc

    def heal(self, say):
        self.calls.append(('heal',))
        return True

    def prepare_local_db(self, plog, who='rollback'):
        """Stands in for _tak_rollback_prepare_local_db (v10.3.5 W16): creates martiuser and cot."""
        self.calls.append(('prepare-local-db',))
        self.prepare_who = who
        if self.prepare_ok:
            self.role = self.db = True
        return self.prepare_ok


def _run(box, pkg=PKG58):
    ns = _load({'_tak_deploy_local_db_state', '_tak_deploy_ensure_local_db', '_TAK_VER_RE',
                '_tak_artifact_version', 'TAK_GATE_BLOCK_FROM'}, {
        're': re, 'os': __import__('os'),
        'TAK_PG_MAJOR': 18, '_TAK58_MIN_SCHEMA_VERSION': 100,
        '_pg_exec': box.pg_exec, '_tak58_schema_version': box.schema_version,
        '_tak58_run_upgrade_db': box.run_upgrade_db, '_tak58_run_setup_db': box.run_setup_db,
        '_tak58_heal_md5_scram': box.heal,
        '_tak_rollback_prepare_local_db': box.prepare_local_db,
    })
    said, log = [], []
    ok = ns['_tak_deploy_ensure_local_db'](pkg, said.append, log)
    return ok, [c[0] for c in box.calls if c[0] != 'psql'], said, log


def test_lutak2_state_runs_upgrade_db_and_ends_with_a_database():
    box = _Box(major=15, role=False, db=False)
    ok, calls, said, log = _run(box)
    assert ok
    assert calls == ['upgrade-db.sh']                  # never setup-db.sh alone on PG15
    assert any('skipped its database setup' in s for s in said)
    assert any('Upgrade completed' in l for l in log)  # vendor output reaches the deploy log
    assert said[-1].startswith('✓ Database ready (PostgreSQL 18')


def test_lutak2_state_upgrade_failure_stops_the_deploy():
    box = _Box(major=15, role=False, db=False, upgrade_rc=1)
    ok, calls, said, _ = _run(box)
    assert not ok and calls == ['upgrade-db.sh']
    assert 'upgrade-db.sh failed (exit 1)' in said[-1]


def test_upgrade_that_exits_0_but_builds_nothing_is_still_a_failure():
    box = _Box(major=15, role=False, db=False, upgrade_builds=False)
    ok, _, said, _ = _run(box)
    assert not ok
    assert 'no usable database' in said[-1] and 'MISSING' in said[-1]


def test_healthy_fresh_install_is_left_alone():
    box = _Box(major=18, role=True, db=True, sv=112)
    ok, calls, said, _ = _run(box)
    assert ok and calls == []
    assert said[-1] == '✓ Database ready (PostgreSQL 18, schema_version 112)'


def test_pg18_cluster_without_cot_runs_setup_db():
    box = _Box(major=18, role=True, db=False)
    ok, calls, _, _ = _run(box)
    # The deploy makes martiuser and cot itself first (nuc, 2026-11-02: setup-db.sh skips
    # them on a box that once moved 15 -> 18), and only then runs TAK's script.
    assert ok and calls == ['prepare-local-db', 'takserver-setup-db.sh']
    assert box.prepare_who == 'deploy'


def test_pg18_cluster_where_the_database_prep_fails_stops_before_setup_db():
    box = _Box(major=18, role=True, db=False, prepare_ok=False)
    ok, calls, _, _ = _run(box)
    assert not ok and calls == ['prepare-local-db']


def test_schema_left_behind_gets_the_md5_scram_heal():
    box = _Box(major=18, role=True, db=True, sv=99)
    box.run_setup_db = lambda timeout_sec=None: (box.calls.append(('takserver-setup-db.sh',)), 0)[1]
    def heal(say):
        box.calls.append(('heal',)); box.sv = 112
    box.heal = heal
    ok, calls, _, _ = _run(box)
    assert ok and calls == ['takserver-setup-db.sh', 'heal']


def test_wrong_cluster_is_never_handed_to_the_setup_script():
    # 5.7 package, but port 5432 is a PG18 cluster with no cot: setup-db.sh would
    # rewrite that cluster's config for the wrong version, so stop and say why.
    box = _Box(major=18, role=False, db=False)
    ok, calls, said, _ = _run(box, pkg=PKG57)
    assert not ok and calls == []
    assert 'expects PostgreSQL 15 but port 5432 is PostgreSQL 18' in said[-1]


def test_57_install_on_pg15_needs_only_its_own_schema():
    box = _Box(major=15, role=True, db=True, sv=99)
    ok, calls, _, _ = _run(box, pkg=PKG57)
    assert ok and calls == []


def test_unreachable_postgres_stops_the_deploy():
    box = _Box(major=15, role=False, db=False)
    box.pg_exec = lambda args, timeout=30, **kw: types.SimpleNamespace(
        returncode=2, stdout='', stderr='could not connect')
    ok, calls, said, _ = _run(box)
    assert not ok and calls == []
    assert 'Could not ask the local PostgreSQL' in said[-1]


def test_deploy_calls_the_check_before_the_first_start_and_stops_on_failure():
    body = APP[APP.index('def run_takserver_deploy('):]
    body = body[:body.index('\ndef ', 1)]
    call = body.index('_tak_deploy_ensure_local_db(pkg, log_step, deploy_log)')
    assert body.index('━━━ Step 4/9') < call < body.index('━━━ Step 5/9')
    guard = body[body.rindex('\n', 0, call - 60):call]
    assert "not config.get('two_server')" in guard and "not config.get('external_db')" in guard
    after = body[call:call + 600]
    assert "deploy_status.update({'error': True, 'running': False}); return" in after
