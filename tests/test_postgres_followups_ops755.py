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
"""PostgreSQL security release of 2026-11-12, the databases ops #754 left out (ops #755).

  1. TAK Server's own database container (built once at install, never refreshed): the refresh
     builds first, stops only when the new image really carries the fix, backs up, swaps ONLY the
     database container on the same volume, checks the rows, and puts the old image back on any
     failure after the stop. The 5.7 bundle is rebased on a Debian that can reach the fix.
  2. ATLAS's database container (`db`; Update only rebuilt `api`): refreshed through ATLAS's own
     compose helper, for the plain deployment and for an agency.
"""

import pathlib
import re
import sys
import time
import types
from datetime import datetime

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
APP = (REPO / 'app.py').read_text(encoding='utf-8')
ATLAS_SRC = (REPO / 'modules' / 'atlas.py').read_text(encoding='utf-8')
TEMPLATE = (REPO / 'templates' / 'takserver.html').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?\n(?=\n)', APP, re.S | re.M).group(0)


VERSION_FUNCS = ('_pg_version_tuple', '_pg_fixed_tuple', '_pg_releases_missing')


def _versions_ns():
    n = {'re': re}
    exec(compile('\n'.join([_const('POSTGRES_SECURITY_RELEASES')] + [_cut(f) for f in VERSION_FUNCS]),
                 'app.py', 'exec'), n)
    return n


# ── 1a. the 5.7 Dockerfile is rebased, the 5.8 one is not ─────────────────────

BBN = """FROM postgres:15.1

# this is slow - updates all packages
RUN apt-get update && apt install -y postgresql-15-postgis-3 openjdk-17-jdk

ENTRYPOINT ["/opt/tak/db-utils/configureInDocker.sh"]
"""


def _rebase_ns():
    n = {'re': re}
    src = '\n'.join([_const('TAK_DB_LEGACY_BASE'), _const('_TAK_DB_LEGACY_FROM_RE'),
                     _const('_TAK_DB_BULLSEYE_RUN_RE'), _cut('_tak_db_legacy_refresh_dockerfile')])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


def _install_patched(tmp_path, body):
    """The bundle's Dockerfile as the INSTALL left it: run through the real GH #69/#84 patcher."""
    import ast
    import os
    (tmp_path / 'docker').mkdir()
    (tmp_path / 'docker' / 'Dockerfile.takserver-db').write_text(body)
    fn = [x for x in ast.parse(APP).body if isinstance(x, ast.FunctionDef)
          and x.name == '_patch_tak_db_dockerfile'][0]
    ns = {'os': os, 're': re}
    exec(ast.get_source_segment(APP, fn), ns)
    assert ns['_patch_tak_db_dockerfile'](str(tmp_path), lambda m: None) is True
    return (tmp_path / 'docker' / 'Dockerfile.takserver-db').read_text()


def test_stock_5_7_dockerfile_moves_to_the_bookworm_base_and_keeps_everything_else():
    ns = _rebase_ns()
    out = ns['_tak_db_legacy_refresh_dockerfile'](BBN)
    assert out.splitlines()[0] == 'FROM postgres:15-bookworm'
    assert 'RUN apt-get update && apt install -y postgresql-15-postgis-3 openjdk-17-jdk' in out
    assert 'ENTRYPOINT ["/opt/tak/db-utils/configureInDocker.sh"]' in out


def test_the_installs_bullseye_repairs_are_undone_because_pgdg_live_has_the_new_minor(tmp_path):
    # The install pointed PGDG at apt-archive.postgresql.org (bullseye only, tops out at 15.19).
    # On bookworm that line would pin the new image to the archive and lose 15.20.
    patched = _install_patched(tmp_path, BBN)
    assert 'apt-archive.postgresql.org' in patched
    out = _rebase_ns()['_tak_db_legacy_refresh_dockerfile'](patched)
    assert 'apt-archive' not in out and 'archive.debian.org' not in out
    assert 'FROM postgres:15-bookworm' in out
    # the package list BBN asked for is the one installed, once, in a plain install
    run = [l for l in out.splitlines() if l.startswith('RUN ')]
    assert len(run) == 1 and run[0].endswith('postgresql-15-postgis-3 openjdk-17-jdk')
    assert 'ca-certificates' not in run[0]


@pytest.mark.parametrize('base', ['postgres:15.1', 'postgres:15', 'postgres:15.2-bullseye',
                                  'library/postgres:15.1', 'docker.io/library/postgres:15.1'])
def test_every_postgres_15_base_spelling_is_rebased(base):
    out = _rebase_ns()['_tak_db_legacy_refresh_dockerfile'](BBN.replace('postgres:15.1', base))
    assert out.splitlines()[0] == 'FROM postgres:15-bookworm'


def test_a_dockerfile_without_a_postgres_15_base_is_left_alone():
    f = _rebase_ns()['_tak_db_legacy_refresh_dockerfile']
    assert f('FROM registry.access.redhat.com/ubi10/ubi:10.2\nRUN dnf update -y\n') is None
    assert f('FROM postgres:16\nRUN true\n') is None
    assert f('') is None and f(None) is None


# ── 1b. the refresh job ───────────────────────────────────────────────────────

JOB_FUNCS = ('run_tak_db_refresh',)


class Box:
    """A scripted Docker host. Records every command and answers the ones the job reads."""

    def __init__(self, new_version='18.7', build_ok=True, backup_ok=True, db_up=True,
                 counts_after='same', running_version='18.6', era='hardened', collation_mismatch=False,
                 reindex_ok=True):
        self.cmds = []
        self.new_version, self.build_ok, self.backup_ok = new_version, build_ok, backup_ok
        self.db_up, self.counts_after, self.era = db_up, counts_after, era
        self.running_version, self.collation_mismatch, self.reindex_ok = running_version, collation_mismatch, reindex_ok
        self.db_runs = 0
        self.sql = []
        self.count_calls = 0

    def _r(self, rc=0, out=''):
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr='')

    def pg_run(self, argv, timeout=30, cwd=None):
        self.cmds.append(list(argv))
        a = list(argv)
        if a[:2] == ['docker', 'build']:
            return self._r(0 if self.build_ok else 1, '' if self.build_ok else 'boom')
        if a[:2] == ['docker', 'run'] and '--rm' in a:                    # version of the NEW image
            return self._r(0, 'postgres (PostgreSQL) %s' % self.new_version)
        if a[:2] == ['docker', 'run']:                                    # recreate the database
            self.db_runs += 1
            return self._r(0)
        if a[:2] == ['docker', 'inspect']:
            return self._r(0, 'sha256:oldimage')
        if a[:2] == ['docker', 'exec'] and a[3:4] and a[3].endswith('/pg_isready'):
            # the first start after the swap is the one that may fail; a rollback start always works
            return self._r(0 if (self.db_up or self.db_runs > 1) else 1)
        if a[:2] == ['docker', 'exec'] and a[2] == 'takserver':           # messaging log grep
            return self._r(0)
        if a[:2] == ['docker', 'images']:
            return self._r(0, 'refresh\npre-refresh-19990101-000000\nlatest')
        return self._r(0)

    def counts(self, container, pgbin, pw):
        self.count_calls += 1
        if self.count_calls == 1 or self.counts_after == 'same':
            return {'cot_router': 900, 'schema_version': 40}
        return {'cot_router': 899, 'schema_version': 40}

    def psql(self, container, pgbin, pw, sql, timeout=300):
        self.sql.append(sql)
        if 'datcollversion' in sql:
            return '1\n' if self.collation_mismatch else '0\n'
        if sql.startswith('REINDEX'):
            return '' if self.reindex_ok else None
        return ''

    def backup(self, pgbin, pw, say, stamp):
        self.cmds.append(['BACKUP', 'pre-dbrefresh', stamp])
        if self.backup_ok:
            return '/home/t/tak-docker/snapshots/pre-dbrefresh-%s/cot.pgdump' % stamp, ''
        return '', 'archive unreadable'

    def verbs(self):
        return [' '.join(c[:3]) if c[0] == 'docker' else c[0] for c in self.cmds]


def _facts(box, **kw):
    f = {'applicable': True, 'version': box.running_version, 'pgbin': '/usr/pgsql-18/bin',
         'missing': _versions_ns()['_pg_releases_missing'](box.running_version),
         'bundle': '/home/t/tak-docker/takserver-docker-5.8', 'db_dockerfile': 'docker/Dockerfile.hardened-takserver-db',
         'era': box.era, 'why': ''}
    f.update(kw)
    return f


class _FakeFile:
    def __init__(self, text=''):
        self.text, self.written = text, None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self.text

    def write(self, t):
        self.written = t


def _fake_open(path, mode='r', *a, **k):
    return _FakeFile(BBN)


def _run_job(box, monkeypatch, facts=None):
    monkeypatch.setattr(time, 'sleep', lambda s: None)
    ticks = iter(range(0, 10_000_000, 7))
    monkeypatch.setattr(time, 'time', lambda: next(ticks))
    ns = _versions_ns()
    log, status = [], {'running': True, 'complete': False, 'error': False}
    ns.update({
        're': re, 'time': time, 'datetime': datetime, 'print': lambda *a, **k: None,
        'os': types.SimpleNamespace(path=types.SimpleNamespace(
            join=lambda *a: '/'.join(a), realpath=lambda p: '/home/t/tak-docker/takserver-docker-5.8/tak'),
            ), 'open': _fake_open,
        'TAK_CONTAINER': 'takserver', 'TAK_DB_CONTAINER': 'takserver-db', 'TAK_DB_VOLUME': 'takserver_pgsql',
        'TAK_DOCKER_NET': 'takserver', 'TAK_DB_REFRESH_TAG': 'takserver_db:refresh',
        'TAK_DB_LEGACY_BASE': 'postgres:15-bookworm',
        'tak_dbr_log': log, 'tak_dbr_status': status, '_tak_dbr_cache': {'at': 0.0, 'data': 'x'},
        '_pg_run': box.pg_run, '_tak58_db_password': lambda: 'pw',
        '_tak_db_refresh_facts': lambda: facts if facts is not None else _facts(box),
        '_tak_db_pg_version': lambda pgbin: box.running_version if not box.db_runs else box.new_version,
        '_tak58_container_counts': box.counts, '_tak58_container_psql': box.psql,
        '_tak_db_refresh_backup': box.backup, '_tak_db_volume_mount': lambda ctx: '--mount source=takserver_pgsql,destination=/var/lib/postgresql/data',
        '_patch_tak_hardened_dockerfile': lambda *a, **k: False,
        '_patch_tak_db_pgdg_releasever': lambda *a, **k: False,
        '_tak_db_legacy_refresh_dockerfile': lambda s: s,
    })
    exec(compile(_cut('run_tak_db_refresh'), 'app.py', 'exec'), ns)
    ns['run_tak_db_refresh']()
    return log, status


def _index(box, prefix):
    for i, c in enumerate(box.cmds):
        if c[:len(prefix)] == prefix:
            return i
    return -1


def test_happy_path_builds_first_then_backs_up_then_swaps_only_the_database(monkeypatch):
    box = Box()
    log, status = _run_job(box, monkeypatch)
    assert status == {'running': False, 'complete': True, 'error': False}
    i_build = _index(box, ['docker', 'build'])
    i_backup = box.cmds.index([c for c in box.cmds if c[0] == 'BACKUP'][0])
    i_stop_tak = _index(box, ['docker', 'stop', '-t', '120', 'takserver'])
    i_stop_db = _index(box, ['docker', 'stop', '-t', '120', 'takserver-db'])
    i_swap = _index(box, ['docker', 'tag', 'takserver_db:refresh', 'takserver_db'])
    i_run = [i for i, c in enumerate(box.cmds) if c[:2] == ['docker', 'run'] and '--rm' not in c][0]
    i_start = _index(box, ['docker', 'start', 'takserver'])
    assert -1 < i_build < i_backup < i_stop_tak < i_stop_db < i_swap < i_run < i_start
    # TAK keeps serving until the backup is proven; the build never touches a running container
    assert all(c[:3] != ['docker', 'stop', 'takserver'] for c in box.cmds[:i_backup])
    assert box.cmds[i_build][:5] == ['docker', 'build', '--no-cache', '--pull', '-t']


def test_the_data_volume_and_the_tak_container_are_never_removed(monkeypatch):
    box = Box()
    _run_job(box, monkeypatch)
    for c in box.cmds:
        assert c[:3] != ['docker', 'volume', 'rm'] and c[:3] != ['docker', 'volume', 'prune']
        assert c[:3] != ['docker', 'rm', 'takserver'] and c[:4] != ['docker', 'rm', '-f', 'takserver']
        assert 'down' not in c
    run = [c for c in box.cmds if c[:2] == ['docker', 'run'] and '--rm' not in c][0]
    assert '--mount' in run and 'source=takserver_pgsql,destination=/var/lib/postgresql/data' in run
    assert run[run.index('--name') + 1] == 'takserver-db' and '--network-alias' in run


def test_the_backup_has_its_own_snapshot_name_not_the_5_8_one(monkeypatch):
    box = Box()
    _run_job(box, monkeypatch)
    assert [c for c in box.cmds if c[0] == 'BACKUP'][0][:2] == ['BACKUP', 'pre-dbrefresh']


def test_old_image_is_kept_as_a_rollback_handle_before_the_swap(monkeypatch):
    box = Box()
    _run_job(box, monkeypatch)
    tag = [c for c in box.cmds if c[:2] == ['docker', 'tag'] and c[2] == 'sha256:oldimage']
    assert len(tag) == 1 and tag[0][3].startswith('takserver_db:pre-refresh-')
    assert _index(box, tag[0]) < _index(box, ['docker', 'stop', '-t', '120', 'takserver-db'])


def test_a_new_image_without_the_fix_changes_nothing(monkeypatch):
    # the image maker has not published it yet (webodm / postgis on Nov 14): never stop anything for that
    box = Box(new_version='18.6')
    log, status = _run_job(box, monkeypatch)
    assert status['complete'] and not status['error']
    assert all(c[0] != 'BACKUP' for c in box.cmds)
    assert all(c[:2] != ['docker', 'stop'] and c[:2] != ['docker', 'start'] for c in box.cmds)
    assert any('not the security fix yet' in l for l in log)
    assert ['docker', 'rmi', 'takserver_db:refresh'] in box.cmds


def test_unreadable_version_in_the_new_image_is_not_trusted(monkeypatch):
    box = Box(new_version='garbage')
    log, status = _run_job(box, monkeypatch)
    assert all(c[:2] != ['docker', 'stop'] for c in box.cmds)
    assert any('PostgreSQL unknown' in l for l in log)


def test_failed_build_changes_nothing(monkeypatch):
    box = Box(build_ok=False)
    log, status = _run_job(box, monkeypatch)
    assert status == {'running': False, 'complete': False, 'error': True}
    assert all(c[:2] != ['docker', 'stop'] for c in box.cmds)
    assert any('Nothing was changed' in l for l in log)


def test_unreadable_backup_changes_nothing(monkeypatch):
    box = Box(backup_ok=False)
    log, status = _run_job(box, monkeypatch)
    assert status['error'] and not status['complete']
    assert all(c[:2] != ['docker', 'stop'] for c in box.cmds)
    assert any('Nothing was changed' in l and 'backup' in l for l in log)


def test_not_applicable_install_is_refused_with_the_reason(monkeypatch):
    box = Box()
    f = _facts(box, applicable=False, why='TAK Server does not run as containers here')
    log, status = _run_job(box, monkeypatch, facts=f)
    assert status['error'] and box.cmds == []
    assert any('containers' in l for l in log)


def test_already_fixed_database_is_left_alone(monkeypatch):
    box = Box(running_version='18.7')
    log, status = _run_job(box, monkeypatch)
    assert status['complete'] and box.cmds == []


def test_new_database_that_does_not_start_puts_the_old_image_back(monkeypatch):
    box = Box(db_up=False)
    log, status = _run_job(box, monkeypatch)
    assert status == {'running': False, 'complete': False, 'error': True}
    runs = [c for c in box.cmds if c[:2] == ['docker', 'run'] and '--rm' not in c]
    assert len(runs) == 2 and runs[1][-1].startswith('takserver_db:pre-refresh-')
    assert ['docker', 'start', 'takserver'] in box.cmds
    assert any('Nothing was lost' in l for l in log)
    # the plain name points at the old image again, so a later `docker start` gets what ran before
    last_tag = [c for c in box.cmds if c[:2] == ['docker', 'tag'] and c[-1] == 'takserver_db'][-1]
    assert last_tag[2].startswith('takserver_db:pre-refresh-')


def test_a_row_count_that_differs_after_the_swap_rolls_back(monkeypatch):
    box = Box(counts_after='less')
    log, status = _run_job(box, monkeypatch)
    assert status['error'] and not status['complete']
    assert any('row counts' in l for l in log)
    assert ['docker', 'start', 'takserver'] in box.cmds
    assert len([c for c in box.cmds if c[:2] == ['docker', 'run'] and '--rm' not in c]) == 2


def test_5_7_collation_change_rebuilds_the_indexes_before_tak_starts(monkeypatch):
    box = Box(era='legacy', running_version='15.1', new_version='15.20', collation_mismatch=True)
    f = _facts(box, pgbin='/usr/lib/postgresql/15/bin', db_dockerfile='docker/Dockerfile.takserver-db')
    log, status = _run_job(box, monkeypatch, facts=f)
    assert any(s.startswith('REINDEX DATABASE cot') for s in box.sql)
    assert any('REFRESH COLLATION VERSION' in s for s in box.sql)
    assert status['complete']


def test_5_7_without_a_collation_change_does_not_reindex(monkeypatch):
    box = Box(era='legacy', running_version='15.1', new_version='15.20', collation_mismatch=False)
    f = _facts(box, pgbin='/usr/lib/postgresql/15/bin', db_dockerfile='docker/Dockerfile.takserver-db')
    log, status = _run_job(box, monkeypatch, facts=f)
    assert not any(s.startswith('REINDEX') for s in box.sql) and status['complete']


def test_failed_reindex_rolls_back(monkeypatch):
    box = Box(era='legacy', running_version='15.1', new_version='15.20', collation_mismatch=True, reindex_ok=False)
    f = _facts(box, pgbin='/usr/lib/postgresql/15/bin', db_dockerfile='docker/Dockerfile.takserver-db')
    log, status = _run_job(box, monkeypatch, facts=f)
    assert status['error'] and ['docker', 'start', 'takserver'] in box.cmds


def test_hardened_5_8_never_gets_the_collation_step(monkeypatch):
    box = Box()
    _run_job(box, monkeypatch)
    assert box.sql == []


# ── 1c. the email item and the page card ──────────────────────────────────────

def _items_ns(facts):
    ns = _versions_ns()
    ns['_tak_db_refresh_facts_cached'] = lambda: facts
    exec(compile(_cut('_tak_db_refresh_items'), 'app.py', 'exec'), ns)
    return ns


def test_old_database_container_is_in_the_update_email():
    facts = {'applicable': True, 'version': '18.6', 'missing': _versions_ns()['_pg_releases_missing']('18.6')}
    (item,) = _items_ns(facts)['_tak_db_refresh_items']()
    assert item['key'] == 'pg-tak-container'
    assert 'security update pending' in item['summary']
    assert 'Refresh database image' in item['how']          # the exact fix, as Guard Dog emails promise
    assert 'PostgreSQL 2026-11-12' in item['identity'] and '18.6' in item['identity']


@pytest.mark.parametrize('facts', [
    {'applicable': True, 'version': '18.7', 'missing': []},                         # fixed
    {'applicable': False, 'version': '', 'missing': [], 'why': 'not containers'},   # native install
])
def test_fixed_or_native_install_is_not_in_the_email(facts):
    assert _items_ns(facts)['_tak_db_refresh_items']() == []


def test_the_email_sweep_collects_the_container_item_and_marks_a_failed_probe_unknown():
    src = _cut('_collect_pending_updates')
    assert '_tak_db_refresh_items()' in src and "unknown.add('pg-tak-container')" in src


def test_the_page_card_shows_only_when_there_is_something_to_refresh():
    assert '{% if tak_db_refresh %}' in TEMPLATE and 'takDbRefreshStart' in TEMPLATE
    assert 'tak_db_refresh=_tak_dbr_page(' in APP
    dbr = _cut('_tak_dbr_page')
    assert "f['applicable'] and f['missing']" in dbr


def test_the_start_route_asks_for_the_admin_password_and_refuses_overlap():
    start = _cut('takserver_db_refresh_start')
    assert '_require_admin_password()' in start
    assert start.index('_require_admin_password()') < start.index('threading.Thread(')
    assert "tak_dbr_status.get('running')" in start and "tak58_status.get('running')" in start
    assert re.search(r"@app\.route\('/api/takserver/db-refresh', methods=\['POST'\]\)\n@login_required", APP)


# ── 2. ATLAS ─────────────────────────────────────────────────────────────────

class AtlasBox:
    def __init__(self, running='16.15', pulled='16.16', same_image=False, running_container=True,
                 pull_rc=0, up_rc=0, ready=True):
        self.running, self.pulled, self.same_image = running, pulled, same_image
        self.running_container, self.pull_rc, self.up_rc, self.ready = running_container, pull_rc, up_rc, ready
        self.root, self.compose = [], []
        self.recreated = False

    def run_root(self, argv, timeout=120):
        self.root.append(list(argv))
        a = list(argv)
        if a[:3] == ['docker', 'ps', '-q']:
            return (0, 'cid1\n') if self.running_container else (0, '')
        if a[:2] == ['docker', 'exec'] and a[3:] == ['postgres', '--version']:
            return 0, 'postgres (PostgreSQL) %s' % (self.pulled if self.recreated else self.running)
        if a[:2] == ['docker', 'exec'] and a[3:] == ['pg_isready', '-q']:
            return (0 if self.ready else 1), ''
        if a[:2] == ['docker', 'inspect']:
            return 0, 'sha256:aaa postgres:16-alpine'
        if a[:3] == ['docker', 'image', 'inspect']:
            return 0, 'sha256:aaa' if self.same_image else 'sha256:bbb'
        if a[:2] == ['docker', 'run']:
            return 0, 'postgres (PostgreSQL) %s' % self.pulled
        return 0, ''

    def comp(self, ctx, action, timeout=180, inst=None):
        self.compose.append((action, inst))
        if action.startswith('up -d'):
            self.recreated = self.up_rc == 0
            return types.SimpleNamespace(returncode=self.up_rc, stdout='', stderr='nope')
        return types.SimpleNamespace(returncode=self.pull_rc, stdout='', stderr='nope')


@pytest.fixture
def atlas(monkeypatch):
    from modules import atlas as m
    monkeypatch.setattr(time, 'sleep', lambda s: None)
    return m


def _atlas_run(atlas, monkeypatch, box, inst=None, with_ctx=True):
    monkeypatch.setattr(atlas, '_run_root', box.run_root)
    monkeypatch.setattr(atlas, '_compose', box.comp)
    slug = (inst or {}).get('slug')
    monkeypatch.setattr(atlas, 'instance_paths',
                        lambda ctx=None, inst=None: {'compose_project': 'takmdm-%s' % slug if slug else 'takmdm'})
    ctx = {'_pg_releases_missing': _versions_ns()['_pg_releases_missing']} if with_ctx else {}
    logs = []
    return atlas.refresh_database(ctx, inst, logs.append), logs


def test_atlas_old_database_is_pulled_and_recreated_alone(atlas, monkeypatch):
    box = AtlasBox()
    res, logs = _atlas_run(atlas, monkeypatch, box)
    assert res == 'fixed'
    assert box.compose == [('pull db', None), ('up -d --no-deps db', None)]
    assert any('now runs PostgreSQL 16.16' in l for l in logs)


def test_atlas_agency_database_goes_through_its_own_project(atlas, monkeypatch):
    box = AtlasBox()
    inst = {'slug': 'corona'}
    res, _ = _atlas_run(atlas, monkeypatch, box, inst=inst)
    assert res == 'fixed'
    # both compose calls carry the agency, so `-p takmdm-corona` is added; and the container is looked
    # up by that project, never the plain deployment's
    assert box.compose == [('pull db', inst), ('up -d --no-deps db', inst)]
    ps = [c for c in box.root if c[:3] == ['docker', 'ps', '-q']]
    assert ps and all('label=com.docker.compose.project=takmdm-corona' in c for c in ps)
    assert all('label=com.docker.compose.service=db' in c for c in ps)


def test_atlas_no_newer_image_restarts_nothing(atlas, monkeypatch):
    box = AtlasBox(same_image=True)
    res, logs = _atlas_run(atlas, monkeypatch, box)
    assert res == 'waiting' and box.compose == [('pull db', None)]


def test_atlas_rebuilt_image_without_the_fix_restarts_nothing(atlas, monkeypatch):
    box = AtlasBox(pulled='16.15')
    res, logs = _atlas_run(atlas, monkeypatch, box)
    assert res == 'waiting' and box.compose == [('pull db', None)]
    assert any('not the security fix yet' in l for l in logs)


def test_atlas_fixed_database_is_not_even_pulled(atlas, monkeypatch):
    box = AtlasBox(running='16.16')
    res, _ = _atlas_run(atlas, monkeypatch, box)
    assert res == 'ok' and box.compose == []


def test_atlas_without_a_running_database_or_without_the_console_table_does_nothing(atlas, monkeypatch):
    res, _ = _atlas_run(atlas, monkeypatch, AtlasBox(running_container=False))
    assert res == 'skipped'
    box = AtlasBox()
    res, _ = _atlas_run(atlas, monkeypatch, box, with_ctx=False)
    assert res == 'skipped' and box.compose == [] and box.root == []


def test_atlas_failed_pull_or_recreate_is_reported_and_never_raises(atlas, monkeypatch):
    assert _atlas_run(atlas, monkeypatch, AtlasBox(pull_rc=1))[0] == 'failed'
    assert _atlas_run(atlas, monkeypatch, AtlasBox(up_rc=1))[0] == 'failed'
    assert _atlas_run(atlas, monkeypatch, AtlasBox(ready=False))[0] == 'failed'


def test_atlas_never_recreates_api_or_removes_the_store(atlas, monkeypatch):
    box = AtlasBox()
    _atlas_run(atlas, monkeypatch, box)
    for action, _inst in box.compose:
        assert 'api' not in action.split() and 'down' not in action and ' -v' not in action


def test_atlas_update_and_the_console_update_both_refresh_the_database():
    calls = [l for l in ATLAS_SRC.splitlines() if l.strip() == 'refresh_database(ctx, inst, plog)']
    assert len(calls) == 2                                                     # rebuilt path + already-newest path
    assert "'refresh_databases': refresh_databases" in ATLAS_SRC
    assert "'_pg_releases_missing': _pg_releases_missing" in APP
    post = re.search(r'def _post_update_auto_deploy\(.*?(?=^def )', APP, re.S | re.M).group(0)
    assert "get('refresh_databases')" in post
    assert post.index('_postgres_compose_converge(') < post.index("get('refresh_databases')") \
        < post.index('Final orphan postgres kill')


# ── 1d. the backup runs inside the container: a container box has no PostgreSQL client on the host ──
# Field (ARM box, Nov 14): the host-side proof stopped the job with "pg_restore not found on trusted PATH".

class BackupBox:
    def __init__(self, dump_rc=0, toc='41\n', size=2048, host_size=2048, cp_rc=0):
        self.calls, self.dump_rc, self.toc, self.size = [], dump_rc, toc, size
        self.host_size, self.cp_rc = host_size, cp_rc
        self.dirs = []

    def detached(self, container, pw, shell_cmd, tag, say, progress=None, timeout=0, every=30):
        self.calls.append(['DETACHED', container, shell_cmd])
        return self.dump_rc

    def pg_run(self, argv, timeout=30, cwd=None):
        self.calls.append(list(argv))
        r = types.SimpleNamespace(returncode=0, stdout='', stderr='')
        if argv[:2] == ['docker', 'exec'] and argv[3:5] == ['sh', '-c']:
            r.stdout = '%s%d\n' % (self.toc, self.size)
        if argv[:2] == ['docker', 'cp']:
            r.returncode = self.cp_rc
        return r


def _backup(box):
    fake_os = types.SimpleNamespace(
        path=types.SimpleNamespace(join=lambda *a: '/'.join(a), exists=lambda p: box.host_size >= 0,
                                   getsize=lambda p: box.host_size),
        makedirs=lambda d, mode=0, exist_ok=False: box.dirs.append(d), chmod=lambda *a: None)
    ns = {'os': fake_os, 'TAK_DB_CONTAINER': 'takserver-db', 'TAK_DOCKER_ROOT': '/home/t/tak-docker',
          '_tak58_container_run_detached': box.detached, '_pg_run': box.pg_run,
          '_makedirs_priv': lambda *a, **k: None, '_cotdb_fmt_bytes': lambda n: '%d B' % n}
    exec(compile(_cut('_tak_db_refresh_backup'), 'app.py', 'exec'), ns)
    logs = []
    return ns['_tak_db_refresh_backup']('/usr/pgsql-18/bin', 'pw', logs.append, '20261114-100000'), logs


def test_backup_is_dumped_read_back_and_copied_out_without_any_host_postgresql_client():
    box = BackupBox()
    (path, why), logs = _backup(box)
    assert path == '/home/t/tak-docker/snapshots/pre-dbrefresh-20261114-100000/cot.pgdump' and why == ''
    dump = [c for c in box.calls if c[0] == 'DETACHED'][0]
    assert '/usr/pgsql-18/bin/pg_dump' in dump[2] and ' -Fc ' in dump[2] and dump[1] == 'takserver-db'
    read_back = [c for c in box.calls if c[:2] == ['docker', 'exec'] and 'sh' in c][0]
    assert 'pg_restore --list' in read_back[-1]                       # the proof runs in the container
    assert all(c[0] in ('DETACHED', 'docker', 'chmod') for c in box.calls)   # never a bare host pg_restore
    assert ['chmod', '600', path] in box.calls                        # the whole CoT database: not world-readable
    assert any(c[:4] == ['docker', 'exec', 'takserver-db', 'rm'] for c in box.calls)   # no copy left in the container
    assert box.dirs == ['/home/t/tak-docker/snapshots/pre-dbrefresh-20261114-100000']   # outside the bundle tree


@pytest.mark.parametrize('box,reason', [
    (BackupBox(dump_rc=1), 'pg_dump exit 1'),
    (BackupBox(dump_rc=None), 'pg_dump exit None'),
    (BackupBox(toc='0\n'), 'could not read the dump back'),                 # bytes but no table of contents
    (BackupBox(size=0), 'could not read the dump back'),
    (BackupBox(host_size=1024), 'could not copy'),                           # truncated copy
    (BackupBox(cp_rc=1), 'could not copy'),
])
def test_a_backup_that_is_not_provably_complete_is_refused(box, reason):
    (path, why), _ = _backup(box)
    assert path == '' and reason in why
    assert ['chmod', '600'] not in [c[:2] for c in box.calls]
