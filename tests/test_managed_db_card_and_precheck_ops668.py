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
"""Managed PostgreSQL: the 5.8 pre-check and the Guard Dog CoT card read the wrong
database (ops #668; infra-TAK #472 and #475, one root cause).

On a TAK Server that uses a managed database (Azure Flexible Server, AWS RDS):
  #472  the 5.8 pre-check printed "database 0 B, 0 B free" (it skipped the whole disk
        block because there is no local data directory);
  #475  every CoT-card read went to the LOCAL cluster, so a leftover local PostgreSQL
        showed its stale size and age and a false "Retention: STALLED".

Both are run here against stubs of the two seams (the managed connection and the local
cluster). The local cluster stub holds the stale numbers from the field report and FAILS
the test if anything reads it.
"""

import os
import pathlib
import re
import shlex
import subprocess
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
GD_JS = (REPO / 'static' / 'guarddog.js').read_text(encoding='utf-8')
TAKSERVER_HTML = (REPO / 'templates' / 'takserver.html').read_text(encoding='utf-8')

GIB = 1024 ** 3
DAY = 86400
MANAGED = {'mode': 'external_db', 'external_db': {'host': 'db.example.postgres.database.azure.com',
                                                  'port': 5432, 'name': 'cot', 'user': 'martiuser',
                                                  'password': 'x'}}


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?(?=^\S)', APP, re.S | re.M).group(0)


def _done(stdout='', rc=0, stderr=''):
    return subprocess.CompletedProcess([], rc, stdout=stdout, stderr=stderr)


# ── Guard Dog CoT card (#475) ───────────────────────────────────────────────────

class _Clusters:
    """The two databases on the box in the field report: the managed one TAK uses, and
    a stale local cluster nobody writes to."""

    def __init__(self, topology='remote', managed_age=3600, managed_ok=True):
        self.topology = topology
        self.managed_age = managed_age
        self.managed_ok = managed_ok
        self.local_calls, self.managed_calls, self.df_calls = [], [], []

    @staticmethod
    def _answer(sql, size, age):
        if 'pg_database_size' in sql:
            return str(size)
        if 'FROM pg_stat_user_tables s JOIN pg_class' in sql:
            return '%d|%d|%d|0|20' % (9_000_000, 1000, 9_000_000)
        if 'pg_statio_user_tables' in sql:
            return 'cot_router|%d' % (3 * GIB)
        if 'min(servertime)' in sql and 'FROM cot_router;' in sql:
            return '2026-11-10 00:00:00+00|2026-11-11 00:00:00+00|%d' % age
        return ''

    def local(self, args, timeout=30, **_kw):
        sql = args[args.index('-c') + 1]
        self.local_calls.append(sql)
        # the stale cluster: 18 MB, oldest row 5 months, retention "stalled"
        return _done(self._answer(sql, 18 * 1024 ** 2, 150 * DAY))

    def managed(self, args, timeout=30):
        sql = args[args.index('-c') + 1]
        self.managed_calls.append((list(args), sql))
        if not self.managed_ok:
            return _done('', 2, 'connection to server failed: timeout')
        return _done(self._answer(sql, 4 * GIB, self.managed_age))


def _ns(clusters):
    start = APP.index('_COTDB_TABLES = (')
    end = APP.index("@app.route('/api/guarddog/cotdb/diagnose')")
    ns = {'re': re, 'time': time, 'os': os, 'shlex': shlex, 'subprocess': subprocess,
          'jsonify': lambda d: d}
    exec(compile(APP[start:end], 'app.py', 'exec'), ns)

    def df(_cfg, _path):
        clusters.df_calls.append(_path)
        return 910 * GIB, 992 * GIB          # the VM's own disk: must never be reported

    ns.update({
        '_tak_db_topology': lambda: (clusters.topology, 'db.example.postgres.database.azure.com', 5432),
        '_pg_exec': clusters.local,
        '_cot_pg_exec': clusters.managed,
        '_cotdb_df': df,
        '_cotdb_retention_hours': lambda: 24,
        '_cotdb_retention_proc_alive': lambda: True,
        # the Guard Dog timer is off on a managed box (the guard stands down there)
        '_cotdb_systemctl': lambda _a, timeout=6: 'disabled',
        '_detect_disk_layout': lambda: {},
        '_tak_is_container': lambda: False,
    })
    return ns


def _card(clusters, cfg=MANAGED):
    ns = _ns(clusters)
    facts = ns['_cotdb_facts'](cfg)
    verdict, headline, detail, rec = ns['_cotdb_verdict'](facts)
    return facts, verdict, headline, detail


def test_managed_card_reads_the_managed_database_not_a_stray_local_cluster():
    c = _Clusters()
    facts, verdict, _h, _d = _card(c)
    assert c.local_calls == [], 'the card read the local cluster: %r' % c.local_calls
    assert facts['managed_db'] is True
    assert facts['db_bytes'] == 4 * GIB                     # not the stale 18 MB
    assert facts['largest_table'] == 'cot_router'           # not spatial_ref_sys
    assert facts['oldest_age_secs'] == 3600                 # not 5 months
    assert facts['retention_stalled'] is False
    assert verdict != 'retention_stalled'


def test_managed_card_never_reports_the_vm_disk_or_a_disk_verdict():
    c = _Clusters()
    facts, verdict, _h, detail = _card(c)
    assert c.df_calls == []
    assert facts['fs_free_bytes'] is None and facts['fs_pct'] is None
    assert facts['fs_free_human'] == 'provider-managed'
    assert facts['data_directory'] is None
    assert verdict != 'no_disk'
    assert '910' not in detail and '0 B' not in detail
    assert 'provider-managed' in detail                     # the healthy line says why there is no number


def test_managed_card_does_not_ask_for_data_directory():
    # current_setting('data_directory') needs a privileged role on RDS / Azure
    c = _Clusters()
    _card(c)
    assert not [s for _a, s in c.managed_calls if 'data_directory' in s]


def test_managed_queries_go_over_the_seam_with_fixed_sql_only():
    c = _Clusters()
    _card(c)
    assert c.managed_calls
    for args, sql in c.managed_calls:
        assert args[0] == 'psql' and args.count('-c') == 1


def test_stalled_only_when_the_managed_database_really_is_stale():
    c = _Clusters(managed_age=30 * DAY)
    # the old row is a plain position report, so retention should have deleted it
    ns = _ns(c)
    orig = ns['_cotdb_psql']

    def psql(cfg, sql, db='cot', timeout=25):
        if 'min(cr.servertime)' in sql:
            return True, 'SET\n%d' % (30 * DAY)
        return orig(cfg, sql, db=db, timeout=timeout)
    ns['_cotdb_psql'] = psql
    facts = ns['_cotdb_facts'](MANAGED)
    assert facts['retention_stalled'] is True
    verdict, _h, detail, _r = ns['_cotdb_verdict'](facts)
    assert verdict == 'retention_stalled'
    # the Guard Dog timer is not blamed: it stands down on a managed database
    assert 'timer' not in detail
    assert c.local_calls == []


def test_unreadable_managed_database_is_unknown_not_stalled():
    c = _Clusters(managed_ok=False)
    facts, verdict, _h, _d = _card(c)
    assert c.local_calls == []                              # no fallback to the local cluster
    assert facts['db_bytes'] is None and facts['oldest_age_secs'] is None
    assert facts['retention_stalled'] is False
    assert verdict != 'retention_stalled'
    assert facts['errors']                                  # and it says why


def test_local_single_server_card_is_unchanged():
    c = _Clusters(topology='local')
    ns = _ns(c)
    facts = ns['_cotdb_facts']({'mode': 'local'})
    assert facts['managed_db'] is False
    assert c.managed_calls == []
    assert c.local_calls, 'a local box must still read the local cluster'
    assert c.df_calls == ['/']                              # no data_directory from the stub
    assert facts['fs_free_bytes'] == 910 * GIB
    assert facts['fs_free_human'] == '910 GB'


def test_two_server_keeps_the_ssh_path_even_though_topology_says_remote():
    c = _Clusters(topology='remote')
    ns = _ns(c)
    ssh = []

    def probe(s1, cmd, timeout=15):
        ssh.append(cmd)
        return True, ''
    ns['_ssh_probe'] = probe
    cfg = {'mode': 'two_server', 'server_one': {'host': '10.0.0.5'}}
    assert ns['_cotdb_managed'](cfg) is False
    ns['_cotdb_psql'](cfg, 'SELECT 1;')
    assert ssh and 'sudo -u postgres psql' in ssh[0]
    assert c.managed_calls == [] and c.local_calls == []


def test_container_tak_is_not_treated_as_managed():
    c = _Clusters(topology='container')
    assert _ns(c)['_cotdb_managed']({'mode': 'local'}) is False


def test_topology_lookup_failure_falls_back_to_the_old_behaviour():
    c = _Clusters()
    ns = _ns(c)

    def boom():
        raise RuntimeError('coreconfig unreadable')
    ns['_tak_db_topology'] = boom
    assert ns['_cotdb_managed']({'mode': 'local'}) is False


# ── The card's action buttons (#475, "Actions") ─────────────────────────────────

def _route_ns(clusters, tak_cfg=MANAGED, json_body=None):
    ns = {'os': types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda _p: True)),
          'jsonify': lambda *a, **k: dict(*a, **k),
          'load_settings': lambda: {}, '_get_tak_deployment_config': lambda _s: tak_cfg,
          're': re, 'subprocess': subprocess, 'time': time,
          'threading': types.SimpleNamespace(Thread=lambda **k: types.SimpleNamespace(start=lambda: None)),
          'request': types.SimpleNamespace(get_json=lambda silent=False: json_body or {}),
          'audit': lambda *a, **k: None, '_tak_db_topology': lambda: (clusters.topology, 'h', 5432),
          '_pg_exec': clusters.local, '_cot_pg_exec': clusters.managed,
          '_cotdb_clean': lambda t: (t or '').strip(), '_COTDB_NOISE_RE': re.compile('^$'),
          '_vacuum_status': {'running': False, 'full': False, 'started': None, 'result': None,
                             'error': None},
          'datetime': __import__('datetime').datetime}
    for f in ('_cotdb_managed', '_cotdb_managed_refusal', '_cotdb_pg'):
        exec(_cut(f), ns)
    exec(_const('_COTDB_MANAGED_STORAGE'), ns)
    return ns


@pytest.mark.parametrize('action', ['vacuum_full', 'repack', 'purge', 'retention_run'])
def test_destructive_or_blind_actions_are_refused_with_a_reason_on_managed(action):
    ns = _route_ns(_Clusters())
    body, status = ns['_cotdb_managed_refusal'](action)
    assert status == 400 and body['success'] is False and body['managed_db'] is True
    assert 'managed database' in body['error'] and len(body['error']) > 60


def test_routes_refuse_before_touching_any_cluster():
    c = _Clusters()
    ns = _route_ns(c, json_body={'full': True, 'mode': 'all', 'confirm': 'cot_router'})
    ns['_cotdb_facts'] = lambda cfg: pytest.fail('read facts before refusing')
    ns['_run_cotdb_purge_background'] = lambda *a: pytest.fail('purge started')
    for route, action in (('takserver_vacuum', 'vacuum_full'),
                          ('guarddog_cotdb_repack', 'repack'),
                          ('guarddog_cotdb_purge', 'purge'),
                          ('guarddog_cotdb_retention_run', 'retention_run')):
        exec(_cut(route), ns)
        body, status = ns[route]()
        assert status == 400 and body['managed_db'] is True, route
        assert body['error'] == ns['_cotdb_managed_refusal'](action)[0]['error'], route
    assert c.local_calls == [] and c.managed_calls == []


def test_vacuum_analyze_runs_on_the_managed_database_never_the_local_one():
    c = _Clusters()
    ns = _route_ns(c)
    exec(_cut('_run_vacuum_background'), ns)
    ns['_run_vacuum_background'](False, MANAGED)
    assert c.local_calls == []
    assert [a for a, _s in c.managed_calls if a[-1] == 'VACUUM ANALYZE;']
    assert ns['_vacuum_status']['running'] is False


def test_reindex_and_size_route_use_the_managed_database():
    c = _Clusters()
    ns = _route_ns(c)
    exec(_cut('takserver_reindex'), ns)
    out = ns['takserver_reindex']()
    assert out['success'] is True
    exec(_cut('takserver_cot_db_size'), ns)
    size = ns['takserver_cot_db_size']()
    assert size['size_bytes'] == 4 * GIB
    assert c.local_calls == []


def test_local_box_routes_still_use_the_local_cluster():
    c = _Clusters(topology='local')
    ns = _route_ns(c, tak_cfg={'mode': 'local'})
    exec(_cut('_run_vacuum_background'), ns)
    ns['_run_vacuum_background'](False, {'mode': 'local'})
    assert c.managed_calls == [] and c.local_calls


def test_card_js_shows_provider_managed_and_does_not_flag_the_stood_down_timer():
    assert 'f.managed_db' in GD_JS
    assert "storage: '+(f.fs_free_human" in GD_JS
    assert '!f.guard_timer_ok&&!f.managed_db' in GD_JS


# ── 5.8 pre-check (#472) ────────────────────────────────────────────────────────

def _precheck(deployment, mode='remote', managed_major=18, size=2 * GIB, local_calls=None):
    n = {
        'os': os, 're': re, 'subprocess': subprocess, 'shutil': __import__('shutil'),
        'TAK_PG_MAJOR': 18, 'html': __import__('html'),
        '_sudo_wrap': lambda a: a,
        '_tak_db_topology': lambda: (mode, 'db.example.postgres.database.azure.com', 5432),
        '_get_tak_deployment_config': lambda _s: deployment,
        'load_settings': lambda: {},
        '_tak58_managed_pg_major': lambda _edb: (managed_major, ''),
        '_cot_db_size_for_dump': lambda _cfg, _edb=None: size,
        '_tak_is_container': lambda: False,
        '_cotdb_fmt_bytes': None,
    }

    def local_pg(args, **_kw):
        (local_calls if local_calls is not None else []).append(args)
        return _done('', 1)
    n['_pg_exec'] = local_pg
    exec(_cut('_cotdb_fmt_bytes'), n)
    for c in ('_TAK58_MIN_DISK_RATIO', '_TAK58_MANAGED_STORAGE'):
        exec(_const(c), n)
    for f in ('_tak58_fmt_measured', '_tak58_preflight_summary_line', '_tak_58_preflight'):
        exec(_cut(f), n)
    return n['_tak_58_preflight'](), n


def test_precheck_on_managed_db_shows_the_real_size_and_provider_managed():
    local = []
    pf, n = _precheck(MANAGED, local_calls=local)
    f = pf['facts']
    assert f['data_bytes'] == 2 * GIB and f['data_human'] == '2.0 GB'
    assert f.get('avail_bytes') is None
    assert f['avail_human'] == 'provider-managed'
    line = n['_tak58_preflight_summary_line'](f)
    assert line == '  PostgreSQL 18 → 18, database 2.0 GB, storage: provider-managed.'
    assert '0 B' not in line and 'free' not in line
    # the local cluster is not asked anything on a managed box
    assert not [a for a in local if 'data_directory' in ' '.join(map(str, a))]
    assert pf['ready'] is True


def test_precheck_on_managed_db_with_unreadable_size_says_unknown_not_zero():
    pf, n = _precheck(MANAGED, size=None)
    f = pf['facts']
    assert f['data_human'] == 'unknown'
    line = n['_tak58_preflight_summary_line'](f)
    assert '0 B' not in line and 'database unknown' in line


def test_precheck_local_disk_gate_still_blocks_when_space_is_short(monkeypatch):
    local = {
        'SHOW data_directory;': '/var/lib/postgresql/15/main',
        'SHOW server_version_num;': '150000',
    }

    def _pg(args, **_kw):
        sql = args[-1]
        if 'pg_database_size' in sql:
            return _done(str(10 * GIB))
        return _done(local.get(sql, ''))
    # a local box: no deployment external_db, db_mode local
    import shutil
    monkeypatch.setattr(shutil, 'disk_usage', lambda _p: types.SimpleNamespace(free=5 * GIB))
    n = {
        'os': os, 're': re, 'subprocess': subprocess, 'shutil': shutil, 'TAK_PG_MAJOR': 18,
        '_sudo_wrap': lambda a: a, '_tak_db_topology': lambda: ('local', '127.0.0.1', 5432),
        '_get_tak_deployment_config': lambda _s: {}, 'load_settings': lambda: {},
        '_tak_is_container': lambda: False, '_pg_exec': _pg,
        '_cot_db_size_for_dump': lambda *a, **k: pytest.fail('local box asked the managed reader'),
    }
    exec(_cut('_cotdb_fmt_bytes'), n)
    for c in ('_TAK58_MIN_DISK_RATIO', '_TAK58_MANAGED_STORAGE'):
        exec(_const(c), n)
    for f in ('_tak58_fmt_measured', '_tak58_preflight_summary_line', '_tak_58_preflight'):
        exec(_cut(f), n)
    pf = n['_tak_58_preflight']()
    f = pf['facts']
    assert f['data_human'] == '10 GB' and f['avail_human'] == '5.0 GB' and f['need_human'] == '15 GB'
    assert any('Not enough disk' in b for b in pf['blockers'])       # the gate still runs
    assert n['_tak58_preflight_summary_line'](f) == '  PostgreSQL 15 → 18, database 10 GB, 5.0 GB free.'


def test_unmeasured_is_unknown_but_a_real_zero_stays_zero():
    n = {}
    exec(_cut('_cotdb_fmt_bytes'), n)
    exec(_cut('_tak58_fmt_measured'), n)
    assert n['_tak58_fmt_measured'](None) == 'unknown'
    assert n['_tak58_fmt_measured'](0) == '0 B'


def test_precheck_card_says_storage_is_provider_managed_on_managed_db():
    assert '{% if tak58.facts.external_db %}storage: {{ tak58.facts.avail_human }}' in TAKSERVER_HTML
    assert '{{ tak58.facts.avail_human }} free (needs {{ tak58.facts.need_human }})' in TAKSERVER_HTML
