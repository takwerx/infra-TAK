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
"""TAK Server Update on RHEL, two-server and the 5.8 migrations (ops #1336).

One proof per item of the stack audit. Each test cuts the real function out of app.py and
runs it with the system calls faked, so what is asserted is what the Update button does:

1. A package of an older major.minor is refused on EVERY branch (RHEL, container too).
2. RHEL says "update complete" only when rpm reports the package that was uploaded.
3. A two-server update takes a verified dump on Server One BEFORE it stops TAK, and refuses a
   core and a database package of different releases.
4. The 5.8 split migration compares with the package's own major.minor (a 5.9 core is fine),
   and a split box already on PostgreSQL 18 takes the ordinary two-server update.
5. The split migration puts the keepalive settings on the NEW PostgreSQL 18 cluster, and a box
   marked done by an older release is converged once more.
6. A container migration that stopped after the old volume was removed resumes from its saved
   export instead of saying "nothing to migrate from".
"""

import datetime
import json
import os
import pathlib
import re
import shlex
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    """The function's source, or None when app.py has no such function (so the same tests can
    run against the base branch and fail on behaviour, not on a missing helper)."""
    m = re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M)
    return m.group(0) if m else None


def _const(name):
    return re.search(rf'^{name} = .*?(?=^\S)', APP, re.S | re.M).group(0)


class _Time:
    """time module stand-in: sleeping is instant and moves the clock."""

    def __init__(self):
        self.now = 1000.0

    def time(self):
        return self.now

    def sleep(self, s):
        self.now += s

    def strftime(self, fmt):
        return '20261127-040000'

    monotonic = time


class _Run:
    """subprocess.run stand-in: `handler(argv_or_str)` decides; every call is recorded."""

    def __init__(self, handler):
        self.handler, self.calls = handler, []

    def __call__(self, cmd, *a, **kw):
        self.calls.append(cmd)
        out = self.handler(cmd)
        rc, so = out if isinstance(out, tuple) else (0, out or '')
        return types.SimpleNamespace(returncode=rc, stdout=so, stderr='')


def _load(names, extra=None, consts=()):
    n = {'os': os, 're': re, 'json': json, 'shlex': shlex, 'datetime': datetime.datetime,
         'time': _Time(), '_sudo_wrap': lambda a: a, 'print': lambda *a, **k: None}
    n.update(extra or {})
    for c in consts:
        m = re.search(rf'^{c} = .*?(?=^\S)', APP, re.S | re.M)
        if m:
            exec(m.group(0), n)
    for fn in names:
        src = _cut(fn)
        if src:
            exec(compile(src, 'app.py:' + fn, 'exec'), n)
    return n


# ── 1. one refusal for every branch ─────────────────────────────────────────────────────────

def _route(tmp_path, files, installed, family='debian', container=False, deployment=None,
           s1_major=None, preflight=None, resume=None):
    for f in files:
        (tmp_path / f).write_bytes(b'x')
    started = []

    class FakeThread:
        def __init__(self, target=None, args=(), kwargs=None, daemon=None):
            self.target = target

        def start(self):
            started.append(self.target)

    n = _load(
        ['_tak_artifact_version', '_tak_target_version_gate', '_tak_already_on_58',
         '_tak_release_key', '_tak_package_downgrade', '_tak_fmt_release',
         '_tak_cross_minor_downgrade_message', '_tak_core_db_mismatch_message',
         '_tak_split_db_already_on_target', '_tak_installed_core_release',
         'takserver_update'],
        consts=('_TAK_VER_RE', '_TAK_RELEASE_RE', 'TAK_GATE_BLOCK_FROM'),
        extra={
            'threading': types.SimpleNamespace(Thread=FakeThread),
            'subprocess': types.SimpleNamespace(run=_Run(lambda c: (1, ''))),
            'jsonify': lambda d: d,
            'UPLOAD_DIR': str(tmp_path),
            'upgrade_status': {'running': False}, 'upgrade_log': [],
            'TAK_PG_MAJOR': 18, 'TAK_GATE_MESSAGE': 'gate',
            'load_settings': lambda: {},
            '_tak_is_container': lambda: container,
            '_distro_family': lambda: family,
            '_get_tak_deployment_config': lambda s: deployment or {},
            '_get_takserver_version_info': lambda: {'version': installed},
            '_tak_58_preflight': lambda: {'ready': True, 'blockers': [],
                                          'facts': preflight or {'pg_running_major': 15}},
            '_tak58_s1_pg_major': lambda s1: s1_major,
            '_tak58_container_resume_find': lambda: resume,
            '_tak_update_job': lambda label, fn, log, status: fn,
            'TAK_DOCKER_ROOT': str(tmp_path),
        })
    for w in ('run_takserver_upgrade', 'run_takserver_upgrade_rhel', 'run_takserver_upgrade_container',
              'run_takserver_upgrade_two_server', 'run_takserver_upgrade_two_server_rhel',
              'run_takserver_58_migration', 'run_takserver_58_container_migration',
              'run_takserver_58_two_server_migration'):
        n[w] = type(w, (), {'__call__': lambda self: None, '__name__': w})()
    real = os.path.exists
    n['os'] = types.SimpleNamespace(
        listdir=os.listdir, path=types.SimpleNamespace(
            exists=lambda p: True if p == '/opt/tak' else real(p),
            join=os.path.join, getmtime=os.path.getmtime, basename=os.path.basename,
            realpath=os.path.realpath, dirname=os.path.dirname))
    resp = n['takserver_update']()
    return resp, [t.__name__ for t in started]


def _refused(resp, needle='major.minor'):
    return isinstance(resp, tuple) and resp[1] == 400 and needle in resp[0]['error']


def test_rhel_single_refuses_a_cross_minor_package(tmp_path):
    resp, started = _route(tmp_path, ['takserver-5.7-RELEASE43.noarch.rpm'], '5.8-RELEASE105',
                           family='rhel')
    assert _refused(resp) and started == []


def test_rhel_two_server_refuses_a_cross_minor_package(tmp_path):
    dep = {'mode': 'two_server', 'server_one': {'host': 'db1'}}
    resp, started = _route(tmp_path, ['takserver-core-5.7-RELEASE43.noarch.rpm',
                                      'takserver-database-5.7-RELEASE43.noarch.rpm'],
                           '5.8-RELEASE105', family='rhel', deployment=dep)
    assert _refused(resp) and started == []


def test_container_refuses_a_cross_minor_bundle(tmp_path):
    resp, started = _route(tmp_path, ['takserver-docker-hardened-5.7-RELEASE-43.zip'],
                           '5.8-RELEASE105', container=True)
    assert _refused(resp) and started == []


def test_rhel_two_server_core_with_no_single_package_still_has_a_version_to_compare(tmp_path):
    # On a RHEL split core host `rpm -q takserver` finds nothing, so the version read blank and
    # the refusal could never fire. The fallback asks rpm for takserver-core.
    dep = {'mode': 'two_server', 'server_one': {'host': 'db1'}}
    resp, started = _route(tmp_path, ['takserver-core-5.7-RELEASE43.noarch.rpm',
                                      'takserver-database-5.7-RELEASE43.noarch.rpm'],
                           '', family='rhel', deployment=dep)
    # no installed version readable anywhere here (rpm is faked to fail): an update still goes
    assert started == ['run_takserver_upgrade_two_server_rhel']


def test_an_older_release_in_the_same_minor_still_updates_everywhere(tmp_path):
    # ops #1218 must keep working: R105 -> R104 is a warned downgrade, not a refusal.
    resp, started = _route(tmp_path, ['takserver-5.8-RELEASE104.noarch.rpm'], '5.8-RELEASE105',
                           family='rhel', preflight={'already_migrated': True, 'pg_running_major': 18})
    assert resp == {'success': True} and started == ['run_takserver_upgrade_rhel']


def test_core_and_database_of_different_releases_are_refused(tmp_path):
    dep = {'mode': 'two_server', 'server_one': {'host': 'db1'}}
    resp, started = _route(tmp_path, ['takserver-core_5.7-RELEASE43_all.deb',
                                      'takserver-database_5.7-RELEASE40_all.deb'],
                           '5.7-RELEASE32', deployment=dep)
    assert _refused(resp, 'SAME release') and started == []
    resp, started = _route(tmp_path, ['takserver-core-5.8-RELEASE105.noarch.rpm',
                                      'takserver-database-5.8-RELEASE104.noarch.rpm'],
                           '5.8-RELEASE90', family='rhel', deployment=dep)
    assert _refused(resp, 'SAME release') and started == []


def test_a_matching_core_and_database_pair_still_updates(tmp_path):
    dep = {'mode': 'two_server', 'server_one': {'host': 'db1'}}
    resp, started = _route(tmp_path, ['takserver-core_5.7-RELEASE43_all.deb',
                                      'takserver-database_5.7-RELEASE43_all.deb'],
                           '5.7-RELEASE32', deployment=dep)
    assert resp == {'success': True} and started == ['run_takserver_upgrade_two_server']


# ── 4b. a split box already on PostgreSQL 18 is not migrated again ──────────────────────────

SPLIT = {'mode': 'two_server', 'server_one': {'host': 'db1'}}
CORE58 = 'takserver-core_5.8-RELEASE105_all.deb'
DB58 = 'takserver-database_5.8-RELEASE105_all.deb'


def test_split_box_with_server_one_on_pg18_takes_the_ordinary_two_server_update(tmp_path):
    resp, started = _route(tmp_path, [CORE58, DB58], '5.8-RELEASE104', deployment=SPLIT,
                           s1_major=18)
    assert resp == {'success': True}
    assert started == ['run_takserver_upgrade_two_server']


def test_split_box_with_server_one_on_pg15_still_gets_the_migration(tmp_path):
    resp, started = _route(tmp_path, [CORE58, DB58], '5.7-RELEASE43', deployment=SPLIT,
                           s1_major=15)
    assert resp.get('migration') is True and started == ['run_takserver_58_two_server_migration']


def test_split_box_with_unreadable_server_one_still_goes_to_the_migration_which_refuses(tmp_path):
    resp, started = _route(tmp_path, [CORE58, DB58], '5.8-RELEASE104', deployment=SPLIT,
                           s1_major=None)
    assert started == ['run_takserver_58_two_server_migration']


# ── 2. RHEL: rpm decides, not the exit code of dnf or the existence of /opt/tak ───────────────

def _rhel_run(installed_after, dnf_rc=0, package='5.7-RELEASE43'):
    """Run run_takserver_upgrade_rhel; return (status dict, log list)."""
    log, status = [], {'running': True, 'complete': False, 'error': False}

    def handler(cmd):
        c = cmd if isinstance(cmd, str) else ' '.join(cmd)
        if c.startswith('rpm -qp --qf'):
            return package
        if c.startswith('rpm -q --qf'):
            return (0, installed_after) if installed_after else (1, 'package takserver is not installed')
        if 'dnf install' in c:
            return (dnf_rc, 'Error: ...' if dnf_rc else 'Complete!')
        if c.startswith('rpm -q takserver'):
            return 'takserver-5.8-RELEASE105.noarch'
        return ''

    real = os.path.exists
    n = _load(
        ['_tak_rpm_installed_matches', 'run_takserver_upgrade_rhel'],
        extra={
            'subprocess': types.SimpleNamespace(run=_Run(handler)),
            'upgrade_log': log, 'upgrade_status': status,
            '_tak_snapshot': lambda label, ulog: (True, {'db_dump': True}),
            'load_settings': lambda: {}, 'save_settings': lambda s: None,
            '_sanitize_coreconfig_name_entries': lambda: (False, ''),
            '_resync_ldap_credential_to_coreconfig': lambda: (False, ''),
            '_get_service_domain': lambda s, k: '', 'install_le_cert_on_8446': lambda *a, **k: True,
            '_tak_systemctl': lambda a: 'true', '_get_authentik_env_content': lambda s: '',
            'generate_caddyfile': lambda s: None, '_caddy_reload': lambda: None,
        })
    n['os'] = types.SimpleNamespace(path=types.SimpleNamespace(
        exists=lambda p: True if p == '/opt/tak' else real(p), basename=os.path.basename))
    n['run_takserver_upgrade_rhel']('/tmp/takserver-5.7-RELEASE43.noarch.rpm')
    return status, log


def test_rhel_update_reports_success_when_the_package_really_installed():
    status, log = _rhel_run(installed_after='5.7-RELEASE43')       # control: a good update
    assert status['complete'] is True and status['error'] is False


def test_rhel_update_fails_when_dnf_left_the_old_package(tmp_path):
    # dnf refuses (5.7 rpm on 5.8) or has nothing to do: rpm still says 5.8-RELEASE105.
    status, log = _rhel_run(installed_after='5.8-RELEASE105')
    text = '\n'.join(log)
    assert status['complete'] is False and status['error'] is True
    assert 'TAK Server update complete' not in text
    assert 'did NOT happen' in text and '5.8-RELEASE105' in text and '5.7-RELEASE43' in text


def test_rhel_update_fails_when_dnf_failed_and_nothing_confirms_the_install():
    status, log = _rhel_run(installed_after='', dnf_rc=1)
    assert status['complete'] is False and status['error'] is True


def test_rhel_update_tolerates_a_non_zero_dnf_exit_when_rpm_confirms_the_package():
    status, log = _rhel_run(installed_after='5.7-RELEASE43', dnf_rc=1)
    assert status['complete'] is True


# ── 3. two-server update: backup first, database version checked ──────────────────────────────

def _split_run(fn, backup_ok=True, db_installed='5.8-RELEASE105', tak_cfg=None):
    events, log = [], []
    status = {'running': True, 'complete': False, 'error': False}
    real = os.path.exists

    def handler(cmd):
        c = cmd if isinstance(cmd, str) else ' '.join(cmd)
        if 'systemctl stop takserver' in c or c.endswith('stop'):
            events.append('stop')
        if c.startswith('rpm -qp --qf'):
            return '5.8-RELEASE105'
        if c.startswith('rpm -q --qf'):
            return '5.8-RELEASE105'
        return ''

    def ssh(cfg, cmd, timeout=15):
        if 'takserver-database' in cmd and ('dpkg-query' in cmd or 'rpm -q' in cmd):
            events.append('db-version-read')
            return True, db_installed
        if 'PG_OK' in cmd:
            return True, 'PG_OK'
        return True, ''

    def backup(s1, say, kind='migration'):
        events.append('backup:' + kind)
        return '/var/lib/postgresql/tak-pre-update-X.dump' if backup_ok else None

    n = _load(
        ['_tak_release_key', '_tak_fmt_release', '_tak_remote_db_pkg_matches', '_tak_rpm_installed_matches',
         fn],
        consts=('_TAK_RELEASE_RE',),
        extra={
            'subprocess': types.SimpleNamespace(run=_Run(handler), TimeoutExpired=TimeoutError),
            'upgrade_log': log, 'upgrade_status': status,
            '_tak58_s1_backup': backup, '_ssh_probe': ssh,
            '_scp_to_host': lambda *a, **k: (True, ''),
            'wait_for_unattended_upgrade_worker': lambda *a: None, 'wait_for_apt_lock': lambda *a: None,
            '_tak_upgrade_dpkg_configure_a': lambda *a, **k: True,
            '_tak_log_if_downgrade': lambda *a, **k: False,
            '_tak_upgrade_apt_install': lambda *a, **k: 0,
            '_tak_systemctl': lambda a: 'systemctl %s takserver' % a,
            '_tak_snapshot': lambda label, ulog: (True, {'db_dump': True}),
            'load_settings': lambda: {}, 'save_settings': lambda s: None,
            '_read_priv': lambda p: '', '_read_coreconfig': lambda: '', '_write_priv': lambda *a, **k: None,
            '_coreconfig_db_tls_converge': lambda cc, *a: cc,
            '_fetch_db_password_from_server_one': lambda s1: ('', None),
            '_verify_server_one_db_password': lambda *a, **k: (True, ''),
            '_sanitize_coreconfig_name_entries': lambda: (False, ''),
            '_resync_ldap_credential_to_coreconfig': lambda: (False, ''),
            '_get_service_domain': lambda s, k: '', 'install_le_cert_on_8446': lambda *a, **k: True,
            '_get_authentik_env_content': lambda s: '', 'generate_caddyfile': lambda s: None,
            '_caddy_reload': lambda: None, '_verify_takserver_dpkg_ok': lambda ulog: True,
            '_broker_shim_env': lambda: {}, '_PG_REMOTE_PGSVC_SH': 'true',
            'isfile': None,
        })
    n['os'] = types.SimpleNamespace(
        path=types.SimpleNamespace(exists=lambda p: True if p == '/opt/tak' else real(p),
                                   basename=os.path.basename, dirname=os.path.dirname,
                                   isfile=lambda p: False))
    n['time'].sleep = lambda s: None
    cfg = tak_cfg or {'database': {'port': 5432, 'password': ''}}
    getattr_fn = n[fn]
    if fn.endswith('_rhel'):
        getattr_fn('/tmp/takserver-core-5.8-RELEASE105.noarch.rpm',
                   '/tmp/takserver-database-5.8-RELEASE105.noarch.rpm', {'host': 'db1'}, cfg)
    else:
        getattr_fn('/tmp/takserver-core_5.8-RELEASE105_all.deb',
                   '/tmp/takserver-database_5.8-RELEASE105_all.deb', {'host': 'db1'}, cfg)
    return events, status, '\n'.join(log)


@pytest.mark.parametrize('fn', ['run_takserver_upgrade_two_server', 'run_takserver_upgrade_two_server_rhel'])
def test_two_server_update_takes_a_verified_backup_before_it_stops_tak(fn):
    events, status, text = _split_run(fn)
    assert events[0] == 'backup:update'
    assert 'stop' in events and events.index('backup:update') < events.index('stop')


@pytest.mark.parametrize('fn', ['run_takserver_upgrade_two_server', 'run_takserver_upgrade_two_server_rhel'])
def test_two_server_update_without_a_backup_changes_nothing(fn):
    events, status, text = _split_run(fn, backup_ok=False)
    assert 'stop' not in events
    assert status['error'] is True and status['complete'] is False
    assert 'TAK Server is still running' in text


@pytest.mark.parametrize('fn', ['run_takserver_upgrade_two_server', 'run_takserver_upgrade_two_server_rhel'])
def test_two_server_update_fails_when_server_one_still_has_the_old_database_package(fn):
    events, status, text = _split_run(fn, db_installed='5.7-RELEASE43')
    assert status['error'] is True and status['complete'] is False
    assert 'still reports takserver-database 5.7-RELEASE43' in text and 'STOPPED' in text


@pytest.mark.parametrize('fn', ['run_takserver_upgrade_two_server', 'run_takserver_upgrade_two_server_rhel'])
def test_two_server_update_completes_when_every_check_passes(fn):
    events, status, text = _split_run(fn)
    assert status['complete'] is True and status['error'] is False, text


def test_backup_helper_keeps_only_the_newest_three_update_dumps():
    calls = []

    def ssh(s1, cmd, timeout=15):
        calls.append(cmd)
        if 'pg_dump' in cmd:
            return True, 'RC=0\nDUMPPATH=/var/lib/pgsql/tak-pre-update-20261127-040000.dump'
        if 'pg_restore' in cmd:
            return True, '4096\nLIST_RC=0'
        return True, ''

    n = _load(['_tak58_s1_backup'], extra={'_ssh_probe': ssh, '_cotdb_fmt_bytes': lambda b: str(b)})
    out = n['_tak58_s1_backup']({'host': 'db1'}, lambda m: None, kind='update')
    assert out == '/var/lib/pgsql/tak-pre-update-20261127-040000.dump'    # RHEL home, not /var/lib/postgresql
    assert 'getent passwd postgres' in calls[0]
    assert any('tail -n +4' in c and 'tak-pre-update-' in c for c in calls)
    # the 5.8 migration's own dump is never pruned
    calls.clear()
    n['_tak58_s1_backup']({'host': 'db1'}, lambda m: None)
    assert not any('tail -n +4' in c for c in calls)


# ── 4. the 5.8 split migration: package's own major.minor ────────────────────────────────────

class _Reached(Exception):
    pass


def _migration(core_pkg, installed_after, ka=('ok', 'APPLIED=60/applied'), stop_at='keepalive'):
    log, order = [], []
    status = {'running': True, 'complete': False, 'error': False}
    settings = {}

    def handler(cmd):
        c = cmd if isinstance(cmd, str) else ' '.join(cmd)
        if 'rpm -q --qf' in c or 'dpkg-query' in c:
            return installed_after
        if 'systemctl start takserver' in c:
            order.append('start-tak')
        return ''

    def carry(s1, say):
        order.append('carry-tls')
        return True

    def converge(s1):
        order.append('keepalives')
        if stop_at == 'keepalive':
            raise _Reached()
        return ka

    n = _load(
        ['_tak_artifact_version', 'run_takserver_58_two_server_migration'],
        consts=('_TAK_VER_RE',),
        extra={
            'subprocess': types.SimpleNamespace(run=_Run(handler)),
            'upgrade_log': log, 'upgrade_status': status, 'TAK_PG_MAJOR': 18,
            '_distro_family': lambda: 'debian',
            '_tak58_s1_preflight': lambda s1, say: (True, {'already': True}),
            '_tak58_s1_sql': lambda *a, **k: '5',
            '_tak58_s1_carry_db_tls': carry, '_split_db_keepalives_converge': converge,
            'SPLIT_DB_KEEPALIVE_FIX_VERSION': 2,
            'load_settings': lambda: settings, 'save_settings': lambda s: settings.update(s),
        })
    n['run_takserver_58_two_server_migration'](core_pkg, '/tmp/takserver-database_5.9-RELEASE1_all.deb',
                                               {'host': 'db1'}, {})
    return status, '\n'.join(log), order, settings


def test_a_core_package_of_another_major_minor_than_5_8_is_not_called_not_installed():
    status, text, order, _ = _migration('/tmp/takserver-core_5.9-RELEASE12_all.deb', '5.9-RELEASE12')
    assert 'did not install' not in text
    assert order[0] == 'carry-tls'            # it went on to the database step


def test_a_core_that_did_not_install_is_still_reported_and_tak_stays_stopped():
    status, text, order, _ = _migration('/tmp/takserver-core_5.9-RELEASE12_all.deb', '5.7-RELEASE43')
    assert status['error'] is True and 'did not install' in text and 'carry-tls' not in order


# ── 5. keepalives on the NEW cluster ─────────────────────────────────────────────────────────

def test_the_migration_converges_keepalives_after_the_tls_carry_and_before_tak_starts():
    status, text, order, settings = _migration('/tmp/takserver-core_5.8-RELEASE105_all.deb',
                                               '5.8-RELEASE105', stop_at='none')
    assert order[:3] == ['carry-tls', 'keepalives', 'start-tak'], order
    assert settings.get('split_db_keepalives_state') == 'done:2'


def test_a_failed_keepalive_step_rearms_the_boot_retrofit_instead_of_hiding_it():
    status, text, order, settings = _migration('/tmp/takserver-core_5.8-RELEASE105_all.deb',
                                               '5.8-RELEASE105', ka=('fail', 'IDLE=0'), stop_at='none')
    assert settings.get('split_db_keepalives_state') == ''
    assert 'retry it by itself' in text


def test_a_box_marked_done_by_the_old_release_is_converged_once_more():
    n = _load(['_split_db_keepalives_state', '_split_db_keepalives_complete'],
              extra={'load_settings': lambda: {'split_db_keepalives_state': 'done:1'}})
    exec(_const('SPLIT_DB_KEEPALIVE_FIX_VERSION'), n)
    assert n['SPLIT_DB_KEEPALIVE_FIX_VERSION'] >= 2
    assert n['_split_db_keepalives_complete']('done:1') is False
    assert n['_split_db_keepalives_complete']('done:%d' % n['SPLIT_DB_KEEPALIVE_FIX_VERSION']) is True


def test_the_converge_script_reads_the_newest_cluster_and_asks_the_running_server():
    seen = {}

    def ssh(s1, cmd, timeout=15):
        seen['cmd'] = cmd
        return True, 'PGCONF=/etc/postgresql/18/main/postgresql.conf\nIDLE=1\nAPPLIED=60/applied'

    n = _load(['_split_db_keepalives_converge'],
              extra={'_ssh_probe': ssh, '_PG_REMOTE_PGDATA_SH': 'true', 'TAK_PG_MAJORS': (15, 18),
                     '_pg_keepalive_sh': lambda c: 'true'})
    st, out = n['_split_db_keepalives_converge']({'host': 'db1'})
    assert st == 'ok'
    assert 'sort -V | tail -1' in seen['cmd']                 # the NEW cluster wins over the old one
    assert 'pg_file_settings' in seen['cmd'] and 'systemctl reload postgresql-18' in seen['cmd']
    assert 'from pg_settings' not in seen['cmd']              # a Unix socket always reads 0 there
    assert 'applied::text' not in seen['cmd'] and 'case when applied' in seen['cmd']   # psql prints true, not t
    assert 'restart' not in seen['cmd']                       # reload only: no connection dropped


# ── 6. container migration: resume from the saved export ────────────────────────────────────

def _container_env(tmp_path, marker=None, export_bytes=11, counts_after=None, pg18=True,
                   zip_path=None):
    root = tmp_path / 'tak-docker'
    exp_dir = root / 'snapshots' / 'pre-58-container-20261127-010000'
    exp_dir.mkdir(parents=True)
    exp = exp_dir / 'cot_data.sql'
    exp.write_bytes(b'x' * export_bytes)
    if marker is not None:
        m = {'phase': 'volume_removed', 'export_path': str(exp), 'export_bytes': 11,
             'old_vol': 'takserver_pgsql_pre58_20261127-010000', 'before': {'cot_router': 5, 'users': 2}}
        m.update(marker)
        (exp_dir / 'RESUME.json').write_text(json.dumps(m))
    log, status = [], {'running': True, 'complete': False, 'error': False}
    imported, rebuilt = [], []
    clock = _Time()

    def handler(cmd):
        c = cmd if isinstance(cmd, str) else ' '.join(cmd)
        if 'grep -c' in c and 'Started TAK Server messaging' in c:
            return '2' if imported else '1'
        return ''

    def pgbin(container, major):
        if major == 15:
            return None
        return '/usr/pgsql-18/bin' if pg18 else None

    def counts(container, pgbin_, pw):
        return counts_after if counts_after is not None else {'cot_router': 5, 'users': 2}

    def do_import(container, path, pw, say):
        imported.append(path)
        return True

    def read_priv(p):
        return pathlib.Path(p).read_text()

    def write_priv(p, content, mode='w', perm=None):
        pathlib.Path(p).write_text(content)

    n = _load(
        ['_tak58_file_size', '_tak58_container_resume_write', '_tak58_container_resume_find',
         '_tak58_container_restore_note', 'run_takserver_58_container_migration'],
        consts=('_TAK58_RESUME_NAME', '_TAK58_EXPORT_NAME', '_TAK58_EXPORT_IN_CONTAINER'),
        extra={
            'time': clock, 'subprocess': types.SimpleNamespace(run=_Run(handler)),
            'upgrade_log': log, 'upgrade_status': status, 'TAK_DOCKER_ROOT': str(root),
            'TAK_DB_VOLUME': 'takserver_pgsql', 'TAK_CONTAINER': 'takserver',
            'TAK_DB_CONTAINER': 'takserver-db', 'TAK_PG_MAJOR': 18, '_TAK58_MIN_SCHEMA_VERSION': 100,
            '_tak_is_container': lambda: True, '_tak58_db_password': lambda: 'pw',
            '_tak58_container_pgbin': pgbin, '_tak58_container_counts': counts,
            '_tak58_container_schema_version': lambda *a: 105,
            '_tak58_container_import': do_import,
            '_tak58_container_export': lambda *a: 0,
            '_tak58_volume_copy': lambda *a: True,
            'run_takserver_upgrade_container': lambda *a, **k: rebuilt.append(a),
            '_read_priv': read_priv, '_write_priv': write_priv,
        })
    n['run_takserver_58_container_migration'](zip_path, log=log, status=status)
    return status, '\n'.join(log), imported, rebuilt, exp_dir


def test_a_stopped_container_migration_resumes_from_its_saved_export(tmp_path):
    status, text, imported, rebuilt, exp_dir = _container_env(tmp_path, marker={})
    assert status['complete'] is True and status['error'] is False, text
    assert len(imported) == 1 and imported[0].endswith('cot_data.sql')
    assert rebuilt == []                                       # the new 5.8 database was already up
    assert json.loads((exp_dir / 'RESUME.json').read_text())['phase'] == 'done'
    assert 'Continuing from its saved export' in text


def test_nothing_waiting_still_says_nothing_to_migrate_from(tmp_path):
    status, text, imported, rebuilt, _ = _container_env(tmp_path, marker=None)
    assert status['error'] is True and 'nothing to migrate' in text and imported == []


def test_a_finished_migration_is_never_resumed(tmp_path):
    status, text, imported, rebuilt, _ = _container_env(tmp_path, marker={'phase': 'done'})
    assert status['error'] is True and imported == []


def test_a_saved_export_of_the_wrong_size_is_refused_not_imported(tmp_path):
    status, text, imported, rebuilt, _ = _container_env(tmp_path, marker={}, export_bytes=7)
    assert status['error'] is True and imported == []
    assert 'will not be imported' in text


def test_resume_needs_the_5_8_bundle_when_the_new_database_is_not_built(tmp_path):
    status, text, imported, rebuilt, _ = _container_env(tmp_path, marker={}, pg18=False)
    assert status['error'] is True and imported == [] and rebuilt == []
    assert 'Upload the same hardened 5.8' in text and 'saved export' in text


def test_a_resumed_import_that_loses_rows_is_not_called_complete(tmp_path):
    status, text, imported, rebuilt, _ = _container_env(tmp_path, marker={},
                                                        counts_after={'cot_router': 3, 'users': 2})
    assert status['complete'] is False and status['error'] is True and 'lost rows' in text
    assert 'Press Update again' in text                        # the exact way forward is named


def test_update_button_resumes_even_though_the_box_reads_5_8_on_postgresql_18(tmp_path):
    # The rebuilt box looks "already on 5.8" and would take the plain container upgrade (which
    # finds no NEW bundle and leaves TAK on an empty database).
    zipf = ['takserver-docker-hardened-5.8-RELEASE-105.zip']
    facts = {'already_migrated': True, 'pg_running_major': 18}
    resp, started = _route(tmp_path, zipf, '5.8-RELEASE105', container=True, preflight=facts,
                           resume={'phase': 'volume_removed', 'export_path': '/x'})
    assert resp.get('resume') is True and started == ['run_takserver_58_container_migration']


def test_resume_needs_no_uploaded_bundle_when_the_new_database_is_already_built(tmp_path):
    facts = {'already_migrated': True, 'pg_running_major': 18}
    resp, started = _route(tmp_path, [], '5.8-RELEASE105', container=True, preflight=facts,
                           resume={'phase': 'rebuilt', 'export_path': '/x'})
    assert resp.get('resume') is True and started == ['run_takserver_58_container_migration']


def test_without_a_waiting_migration_a_box_on_5_8_takes_the_plain_container_upgrade(tmp_path):
    facts = {'already_migrated': True, 'pg_running_major': 18}
    resp, started = _route(tmp_path, ['takserver-docker-hardened-5.8-RELEASE-106.zip'],
                           '5.8-RELEASE105', container=True, preflight=facts)
    assert resp == {'success': True} and started == ['run_takserver_upgrade_container']
