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
"""Disk growers no Guard Dog job handled (GH #273).

Field (Ubuntu 22.04, TAK on PostgreSQL 18 after the 15 -> 18 upgrade): data_feed_cot held
71.7M rows / 4.5 GB, every one linked to a cot_router row retention had already deleted;
the PostgreSQL 15 cluster sat at 15 GB, stopped, next to the live 18 one. test6 showed
both (45M orphans / 2.8 GB, a 3 GB 15 cluster) with its retention policy running hourly.
The build-cache half lives in test_disk_reclaim_at_warning.py.
"""

import importlib.util
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
GUARD = (REPO / 'scripts' / 'guarddog' / 'tak-retention-guard.sh').read_text()


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_gh273',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── 1. retention guard: orphaned data_feed_cot rows ─────────────────────────────

LIB_STUB = r'''
gd_psql_scalar() { echo "$1" >> "%(dir)s/sql"; case "$1" in
  "SELECT 1;") echo 1 ;;
  *to_regclass*) cat "%(dir)s/has_table" ;;
  *"COUNT(*) FROM pg_stat_activity"*) echo 0 ;;
  *"FROM cot_router cr WHERE"*) echo 0 ;;
esac; }
gd_psql_raw() { echo "$1" >> "%(dir)s/sql"; case "$1" in
  "DELETE FROM data_feed_cot"*)
    n=$(head -1 "%(dir)s/answers"); sed -i.bak 1d "%(dir)s/answers"; echo "$n" ;;
esac; }
'''


@pytest.fixture
def guard(tmp_path):
    (tmp_path / 'lib.sh').write_text(LIB_STUB % {'dir': tmp_path})
    policy = tmp_path / 'retention-policy.yml'
    script = (GUARD.replace('/opt/tak-guarddog/_gd-tak-lib.sh', str(tmp_path / 'lib.sh'))
                   .replace('/opt/tak-guarddog/guarddog.conf', str(tmp_path / 'none.conf'))
                   .replace('/opt/tak/conf/retention/retention-policy.yml', str(policy))
                   .replace('/var/log/takguard', str(tmp_path / 'log'))
                   .replace('BATCH_SLEEP=2', 'BATCH_SLEEP=0'))
    sp = tmp_path / 'guard.sh'
    sp.write_text(script)

    def run(answers, has_table='t', policy_secs=None):
        (tmp_path / 'answers').write_text('\n'.join(answers) + '\n')
        (tmp_path / 'has_table').write_text(has_table + '\n')
        (tmp_path / 'sql').write_text('')
        if policy_secs is None:
            policy.write_text('dataRetentionMap:\n  cot: null\n')
        else:
            policy.write_text('dataRetentionMap:\n  cot: %d\n' % policy_secs)
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, timeout=60)
        log = (tmp_path / 'log' / 'restarts.log')
        return r, (tmp_path / 'sql').read_text(), log.read_text() if log.exists() else ''
    return run


def test_orphans_are_deleted_in_batches_until_a_short_batch(guard):
    r, sql, log = guard(['DELETE 50000', 'DELETE 50000', 'DELETE 1234'], policy_secs=86400)
    assert r.returncode == 0, r.stderr
    assert sql.count('DELETE FROM data_feed_cot') == 3
    assert 'removed 101234 orphaned data_feed_cot rows' in log and 'in 3 batches' in log
    # and the cot_router cleanup still ran after it
    assert sql.index('DELETE FROM data_feed_cot') < sql.index('FROM cot_router cr WHERE')


def test_orphans_go_even_with_no_retention_policy(guard):
    # A link to a deleted row is dead whatever the TTL; only the cot_router step is skipped.
    r, sql, log = guard(['DELETE 7'])
    assert r.returncode == 0
    assert 'removed 7 orphaned data_feed_cot rows' in log
    assert 'no CoT retention policy set' in log
    assert 'FROM cot_router cr WHERE' not in sql


def test_only_links_to_missing_rows_older_than_an_hour_are_touched(guard):
    _r, sql, _log = guard(['DELETE 0'])
    stmt = [l for l in sql.splitlines() if l.startswith('DELETE FROM data_feed_cot')][0]
    assert 'NOT EXISTS (SELECT 1 FROM cot_router c WHERE c.id = d.cot_router_id)' in stmt
    assert "servertime < now() - interval '1 hour'" in stmt
    assert 'LIMIT 50000' in stmt


def test_a_failed_orphan_delete_is_logged_and_does_not_stop_retention(guard):
    r, sql, log = guard(['ERROR:  canceling statement'], policy_secs=86400)
    assert r.returncode == 0
    assert 'ERROR — orphaned data_feed_cot delete failed in batch 1' in log
    assert 'FROM cot_router cr WHERE' in sql


def test_no_table_no_delete(guard):
    _r, sql, log = guard([], has_table='f')
    assert 'DELETE FROM data_feed_cot' not in sql and 'data_feed_cot' not in log


def test_orphan_loop_has_its_own_smaller_cap():
    cap = int(re.search(r'^ORPHAN_MAX_BATCHES=(\d+)', GUARD, re.M).group(1))
    main = int(re.search(r'^MAX_BATCHES=(\d+)', GUARD, re.M).group(1))
    assert cap < main
    assert '-lt "$ORPHAN_MAX_BATCHES"' in GUARD


# ── 2. CoT DB card: data_feed_cot is counted and explained ──────────────────────

def test_card_sizes_data_feed_cot_from_the_catalog_not_tuple_stats():
    body = _cut('_cotdb_facts')
    assert "pg_total_relation_size('public.data_feed_cot')" in body
    assert "to_regclass('public.data_feed_cot')" in body
    assert 'n_live_tup' not in body.split("f['feed_cot_bytes'] = None")[1].split("f['dup_packages']")[0]


def test_verdict_points_orphans_at_the_retention_guard():
    ns = {'_COTDB_TABLES': ('cot_router',)}
    exec(compile(_cut('_cotdb_verdict'), 'app.py', 'exec'), ns)
    ns['_cotdb_verdict_tree'] = lambda f: ('retention_stalled', 'h', 'd.', ['retention_run', 'purge'])
    v, _h, detail, rec = ns['_cotdb_verdict']({'feed_cot_orphans': True, 'feed_cot_human': '5.6 GB',
                                              'largest_table': 'data_feed_cot'})
    assert 'data_feed_cot holds 5.6 GB' in detail and 'Run Retention Now' in detail
    assert rec[0] == 'retention_run'
    assert 'Purge Old CoT does NOT touch' not in detail       # replaced, not stacked
    ns['_cotdb_verdict_tree'] = lambda f: ('healthy', 'h', 'Nothing to do.', [])
    _v, _h, detail, rec = ns['_cotdb_verdict']({'feed_cot_orphans': False, 'largest_table': 'cot_router'})
    assert detail == 'Nothing to do.' and rec == []


def test_duplicate_packages_are_reported_never_deleted():
    body = _cut('_cotdb_facts')
    dup = body.split("f['dup_packages'] = []")[1].split("f['retention_hours']")[0]
    assert 'GROUP BY hash HAVING count(*) > 1' in dup
    assert 'DELETE' not in dup.upper().replace('DELETED', '').replace('DELETING', '')


# ── 3. leftover PostgreSQL 15 cluster ───────────────────────────────────────────

def _cluster(root, layout, major, running=False):
    d = root / layout.format(major=major).lstrip('/')
    (d / 'base').mkdir(parents=True)
    (d / 'PG_VERSION').write_text('%d\n' % major)
    (d / 'base' / 'seg').write_bytes(b'x' * 65536)
    if running:
        (d / 'postmaster.pid').write_text('123\n')
    return d


@pytest.fixture
def broker(tmp_path):
    m = _broker()
    m._PG_CLUSTER_LAYOUTS = tuple((fam, str(tmp_path) + t) for fam, t in m._PG_CLUSTER_LAYOUTS)
    m.BROKER_TRUSTED_PATH = str(tmp_path / 'nobin')       # no pg_dropcluster / systemctl
    return m


def test_broker_op_takes_an_action_and_nothing_else(broker):
    broker._check_pg_old_cluster({'op': 'pg_old_cluster', 'action': 'inspect'})
    for bad in ({'action': 'rm'}, {'action': 'drop', 'path': '/etc'}, {'action': 'drop', 'major': 18},
                {'action': 'drop', 'argv': ['x']}):
        with pytest.raises(broker.Denied):
            broker._check_pg_old_cluster(dict(bad, op='pg_old_cluster'))
    assert broker._evaluate({'op': 'pg_old_cluster', 'action': 'inspect'})[0] == 'ALLOW'
    assert broker._evaluate({'op': 'pg_old_cluster', 'action': 'drop', 'path': '/'})[0] == 'DENY'


def test_inspect_reports_the_stopped_15_cluster(broker, tmp_path):
    _cluster(tmp_path, '/var/lib/postgresql/{major}/main', 15)
    _cluster(tmp_path, '/var/lib/postgresql/{major}/main', 18, running=True)
    f = broker._do_pg_old_cluster({'action': 'inspect'})
    assert f['found'] and f['family'] == 'debian' and not f['running'] and f['new_running']
    assert f['bytes'] >= 65536


def test_drop_refuses_unless_15_is_stopped_and_18_is_running(broker, tmp_path):
    old = _cluster(tmp_path, '/var/lib/pgsql/{major}/data', 15, running=True)
    new = _cluster(tmp_path, '/var/lib/pgsql/{major}/data', 18)
    r = broker._do_pg_old_cluster({'action': 'drop'})
    assert not r['ok'] and 'running' in r['error'] and old.exists()
    (old / 'postmaster.pid').unlink()
    r = broker._do_pg_old_cluster({'action': 'drop'})
    assert not r['ok'] and 'no running PostgreSQL 18' in r['error'] and old.exists()
    (new / 'postmaster.pid').write_text('1\n')
    r = broker._do_pg_old_cluster({'action': 'drop'})
    assert r['ok'] and r['removed'] and r['freed_bytes'] >= 65536
    assert not old.exists() and new.exists()


def test_drop_never_follows_a_symlink_or_a_wrong_pg_version(broker, tmp_path):
    victim = tmp_path / 'victim'
    victim.mkdir()
    (victim / 'PG_VERSION').write_text('15\n')
    link = tmp_path / 'var/lib/postgresql/15/main'
    link.parent.mkdir(parents=True)
    link.symlink_to(victim)
    _cluster(tmp_path, '/var/lib/pgsql/{major}/data', 18, running=True)
    assert not broker._do_pg_old_cluster({'action': 'drop'})['ok'] and victim.exists()
    link.unlink()
    d = _cluster(tmp_path, '/var/lib/postgresql/{major}/main', 15)
    (d / 'PG_VERSION').write_text('18\n')
    assert not broker._do_pg_old_cluster({'action': 'drop'})['ok'] and d.exists()


def _sh_script(tmp_path, action):
    m = re.search(r"^_PG_OLD_CLUSTER_SH = r'''(.*?)'''", APP, re.S | re.M)
    s = (m.group(1).replace('__ACTION__', action)
         .replace('/var/lib/postgresql/', str(tmp_path) + '/var/lib/postgresql/')
         .replace('/var/lib/pgsql/', str(tmp_path) + '/var/lib/pgsql/'))
    return subprocess.run(['bash', '-c', s], capture_output=True, text=True, timeout=60,
                          env={'PATH': '/usr/bin:/bin'})


def test_server_one_script_matches_the_broker_rules(tmp_path):
    # Two-server: the same checks run on Server One over SSH.
    assert _sh_script(tmp_path, 'inspect').stdout.strip() == 'found=0'
    old = _cluster(tmp_path, '/var/lib/pgsql/{major}/data', 15)
    r = _sh_script(tmp_path, 'drop')
    assert r.returncode == 1 and 'error=no running PostgreSQL 18' in r.stdout and old.exists()
    _cluster(tmp_path, '/var/lib/pgsql/{major}/data', 18, running=True)
    r = _sh_script(tmp_path, 'inspect')
    assert 'found=1' in r.stdout and 'running=0' in r.stdout and 'new_running=1' in r.stdout
    assert re.search(r'^bytes=(\d+)$', r.stdout, re.M) and old.exists()
    (old / 'postmaster.pid').write_text('1\n')
    assert _sh_script(tmp_path, 'drop').returncode == 1 and old.exists()
    (old / 'postmaster.pid').unlink()
    r = _sh_script(tmp_path, 'drop')
    assert r.returncode == 0 and 'removed=1' in r.stdout and not old.exists()


def test_remove_route_is_gated_like_purge():
    body = _cut('guarddog_pg_old_cluster_remove')
    assert '_check_admin_password' in body
    assert "(data.get('confirm') or '').strip() != want" in body
    assert "if not st.get('removable')" in body
    assert body.index('_check_admin_password') < body.index("_pg_old_cluster_call('drop'")
    route = APP[APP.index("@app.route('/api/guarddog/pg-old-cluster/remove'"):][:200]
    assert '@login_required' in route


def test_removal_is_only_offered_when_18_is_the_live_database():
    body = _cut('_pg_old_cluster_state')
    for reason in ('is still running', 'Could not confirm that the live database is healthy',
                   'is still the live database', 'is not running'):
        assert reason in body
    assert "res['removable'] = why is None" in body
