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
"""A split box's PostgreSQL security notice has a way to act on it (ops #766).

Field (Sat Nov 14, 2026, a split box): the console said "PostgreSQL security update pending on your
TAK database (18.6 ...). Update PostgreSQL on that machine." while the database server's own card
said "every available update is installed" and offered only a reboot. Cause (verified on a cloud
split built from the h5 snapshots): the card reads the database server's apt package lists as they
are; a database server that is not on all day keeps lists from before the fix, so apt offers
nothing. After `apt-get update` the PGDG repository offered 18.7.

Promises, each tested with the real code:

  1. The job script refreshes the package lists first, upgrades only the PostgreSQL server packages
     (never PostGIS, never TAK's database package, never `full-upgrade`), restarts a cluster that
     still runs the old build, and says why in plain words when it does not: the repository does
     not offer the fix yet, an operator hold, apt failed, the restart did not take. The script runs
     here against a fake apt/dpkg/systemctl that behaves like the stale-lists database server.
  2. The core's watcher turns the job's status into a plain result, checks TAK reconnects, and reads
     the new version itself before it says done.
  3. The button only works for the machine that holds TAK's database, only below the fix, and a
     managed database (RDS, Azure) is never touched.
  4. The notice names the button when the console can act, and keeps the old wording when it cannot.
"""

import json
import os
import pathlib
import re
import shlex
import shutil
import stat
import socket
import subprocess
import threading
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
CONSOLE = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')
HOST = '10.20.30.40'


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


def _const(name):
    m = re.search(rf'^{name} = .*?\n(?=\n)', APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


def _script_ns():
    ns = {'re': re, 'shlex': shlex}
    src = '\n'.join([_const('POSTGRES_SECURITY_RELEASES'), _const('_PG_UPDATE_FIXED_RE'),
                     _const('_PG_UPDATE_SCRIPT'), _fn('_pg_update_dbserver_script')])
    exec(compile(src, 'app.py:pg-update-script', 'exec'), ns)
    return ns


STATUS = '/var/lib/infratak-pg-update/status'


# ── 1. the job script, run against a fake database server ────────────────────────────

_STUBS = {
    # apt-get update refreshes the lists from the repository; install --only-upgrade installs what
    # the lists offer; a postinst restart is only simulated when the scenario asks for it.
    'apt-get': r'''#!/bin/sh
echo "apt-get $*" >> "$FAKE/calls"
case " $* " in
  *" update "*) [ -f "$FAKE/update_fails" ] && exit 100; cp "$FAKE/repo" "$FAKE/lists"; exit 0;;
  *" install "*) [ -f "$FAKE/install_fails" ] && exit 100
                 cp "$FAKE/lists" "$FAKE/installed"
                 [ -f "$FAKE/autorestart" ] && cp "$FAKE/installed" "$FAKE/running"
                 exit 0;;
esac
exit 0
''',
    'apt-cache': r'''#!/bin/sh
echo "apt-cache $*" >> "$FAKE/calls"
echo "postgresql-$(cat $FAKE/major):"
echo "  Installed: $(cat $FAKE/installed)-1.pgdg22.04+2"
echo "  Candidate: $(cat $FAKE/lists)-1.pgdg22.04+2"
''',
    'apt-mark': r'''#!/bin/sh
[ "$1" = showhold ] && cat "$FAKE/held"
exit 0
''',
    'dpkg-query': r'''#!/bin/sh
M="$(cat $FAKE/major)"
case "$*" in
  *Package*) printf 'postgresql-%s\npostgresql-%s-jit\npostgresql-%s-postgis-3\n' "$M" "$M" "$M";;
  *Version*) printf '%s-1.pgdg22.04+2' "$(cat $FAKE/installed)";;
esac
''',
    'dpkg': r'''#!/bin/sh
case "$1" in
  --compare-versions)  [ "$3" = ge ] || exit 2
                       [ "$(printf '%s\n%s\n' "$2" "$4" | sort -V | tail -1)" = "$2" ];;
  -s) M="$(cat $FAKE/major)"
      case "$2" in postgresql-$M|postgresql-$M-jit|postgresql-client-$M|libpq5|postgresql-common|postgresql-client-common) exit 0;; *) exit 1;; esac;;
esac
''',
    'pg_lsclusters': r'''#!/bin/sh
echo "$(cat $FAKE/major) main 5432 online postgres /var/lib/postgresql/x /var/log/x.log"
''',
    'runuser': r'''#!/bin/sh
shift 3
exec "$@"
''',
    'psql': r'''#!/bin/sh
echo "$(cat $FAKE/running) (Ubuntu $(cat $FAKE/running)-1.pgdg22.04+2)"
''',
    'systemctl': r'''#!/bin/sh
echo "systemctl $*" >> "$FAKE/calls"
[ -f "$FAKE/restart_noop" ] || cp "$FAKE/installed" "$FAKE/running"
exit 0
''',
    'pg_ctlcluster': r'''#!/bin/sh
echo "pg_ctlcluster $*" >> "$FAKE/calls"
[ -f "$FAKE/restart_noop" ] || cp "$FAKE/installed" "$FAKE/running"
exit 0
''',
    'pg_isready': '#!/bin/sh\nexit 0\n',
    'pgrep': '#!/bin/sh\nexit 1\n',
    'sleep': '#!/bin/sh\nexit 0\n',
}


def _run_job(tmp_path, installed='18.6', lists=None, repo='18.7', running=None, held='', major='18',
             flags=()):
    """Run the real job script. `lists` are the package lists before the job's apt-get update
    (default: the installed version, the stale-lists state of the field box); `repo` is what the
    repository offers once the lists are refreshed."""
    fake = tmp_path / 'fake'
    bindir = tmp_path / 'bin'
    fake.mkdir()
    bindir.mkdir()
    for name, body in _STUBS.items():
        p = bindir / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    for name, val in (('installed', installed), ('lists', lists or installed), ('repo', repo),
                      ('running', running or installed), ('held', held), ('major', major)):
        (fake / name).write_text(val)
    (fake / 'calls').write_text('')
    for f in flags:
        (fake / f).write_text('')
    status = tmp_path / 'infratak-pg-update' / 'status'
    script = _script_ns()['_pg_update_dbserver_script'](STATUS).replace(shlex.quote(STATUS), shlex.quote(str(status)))
    sp = tmp_path / 'job.sh'
    sp.write_text(script)
    env = {'PATH': str(bindir) + os.pathsep + '/usr/bin:/bin', 'FAKE': str(fake), 'HOME': str(tmp_path)}
    r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, timeout=60, env=env)
    return types.SimpleNamespace(
        rc=r.returncode, out=r.stdout + r.stderr, status=status.read_text().strip() if status.exists() else '',
        calls=(fake / 'calls').read_text().splitlines(), installed=(fake / 'installed').read_text(),
        running=(fake / 'running').read_text())


def _has_bash():
    return shutil.which('bash') is not None


pytestmark_bash = pytest.mark.skipif(not _has_bash(), reason='no bash')


def test_script_parses_in_bash(tmp_path):
    sp = tmp_path / 'job.sh'
    sp.write_text(_script_ns()['_pg_update_dbserver_script'](STATUS))
    r = subprocess.run(['bash', '-n', str(sp)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_stale_lists_database_server_gets_the_fix_and_a_restart(tmp_path):
    """The field state: 18.6 installed, lists that predate the fix. The job refreshes the lists
    FIRST, then installs, then restarts the cluster that still runs 18.6."""
    r = _run_job(tmp_path)
    assert r.rc == 0 and r.status == 'done', r.out
    assert r.installed == '18.7' and r.running == '18.7'
    upd = [i for i, c in enumerate(r.calls) if ' update' in c]
    ins = [i for i, c in enumerate(r.calls) if ' install ' in c]
    assert upd and ins and upd[0] < ins[0], r.calls
    assert any(c.startswith('systemctl restart postgresql@18-main') for c in r.calls), r.calls


def test_only_postgresql_server_packages_are_upgraded(tmp_path):
    r = _run_job(tmp_path)
    (ins,) = [c for c in r.calls if ' install ' in c]
    assert '--only-upgrade' in ins
    for want in ('postgresql-18', 'postgresql-18-jit', 'postgresql-client-18', 'libpq5'):
        assert want in ins.split(), ins
    assert 'postgis' not in ins and 'takserver' not in ins
    assert not any('full-upgrade' in c or 'dist-upgrade' in c for c in r.calls)


def test_a_postinst_that_already_restarted_postgresql_is_not_restarted_again(tmp_path):
    r = _run_job(tmp_path, flags=('autorestart',))
    assert r.status == 'done' and r.running == '18.7'
    assert not any(c.startswith('systemctl restart') or c.startswith('pg_ctlcluster') for c in r.calls), r.calls


def test_repository_without_the_fix_says_so_and_changes_nothing(tmp_path):
    r = _run_job(tmp_path, repo='18.6')
    assert r.rc != 0 and r.status == 'failed:no-fix', r.out
    assert not any(' install ' in c for c in r.calls)
    assert r.installed == '18.6' and r.running == '18.6'
    assert 'below the fix 18.7' in r.out


def test_an_operator_hold_is_respected(tmp_path):
    r = _run_job(tmp_path, held='postgresql-18\nlinux-image-generic\n')
    assert r.status == 'failed:held' and not any(' install ' in c for c in r.calls), r.out


def test_apt_failure_is_reported_not_swallowed(tmp_path):
    r = _run_job(tmp_path, flags=('install_fails',))
    assert r.status == 'failed:apt', r.out


def test_a_restart_that_does_not_take_is_a_failure(tmp_path):
    r = _run_job(tmp_path, flags=('restart_noop',))
    assert r.status == 'failed:restart', r.out
    assert 'after the restart' in r.out


def test_already_fixed_is_a_clean_no_op(tmp_path):
    r = _run_job(tmp_path, installed='18.7', repo='18.7')
    assert r.status == 'done' and not any(' install ' in c or 'restart' in c for c in r.calls), r.calls


def test_new_build_installed_but_old_build_still_running_gets_only_the_restart(tmp_path):
    r = _run_job(tmp_path, installed='18.7', running='18.6')
    assert r.status == 'done' and r.running == '18.7'
    assert not any(' install ' in c for c in r.calls)
    assert any(c.startswith('systemctl restart') for c in r.calls)


def test_a_dead_third_party_repository_does_not_block_the_fix(tmp_path):
    """apt-get update exits non-zero when ANY source fails (Caddy's Cloudsmith, Docker). The
    decision is the PostgreSQL candidate, not the exit code."""
    r = _run_job(tmp_path, lists='18.7', repo='18.7', flags=('update_fails',))
    assert r.status == 'done' and r.installed == '18.7', r.out
    assert 'WARN: apt-get update reported errors' in r.out


def test_a_major_version_the_release_does_not_list_is_left_alone(tmp_path):
    r = _run_job(tmp_path, installed='13.5', repo='13.5', major='13')
    assert r.status == 'done' and not any(' install ' in c for c in r.calls), r.out
    assert 'does not list this major version' in r.out


def test_script_builder_refuses_a_bad_status_path_or_fix_list():
    build = _script_ns()['_pg_update_dbserver_script']
    for bad in ('/tmp/x', '/var/lib/infratak-x/status; rm -rf /', '', None):
        with pytest.raises(ValueError):
            build(bad)
    for bad in ("18=18.7; rm -rf /", '18=18', 'x=1.2', ''):
        with pytest.raises(ValueError):
            build(STATUS, fixed=bad)


def test_script_carries_the_fix_table_from_the_one_place_it_lives():
    ns = _script_ns()
    s = ns['_pg_update_dbserver_script'](STATUS)
    for major, ver in ns['POSTGRES_SECURITY_RELEASES'][-1]['fixed'].items():
        assert f'{major}={ver}' in s


# ── 2. the watcher: plain results, TAK reconnect, the version read by the console ────

def _tick_ns(confirm=('', 'PostgreSQL now reports 18.7')):
    written = []
    ns = {'re': re, 'json': json, 'shlex': shlex, 'time': time, 'os': os, 'print': lambda *a, **k: None,
          '_PG_REMOTE_CACHE': {'ts': 0.0, 'data': 'old'},
          '_dbserver_record_write': lambda rec: written.append(dict(rec)),
          '_dbserver_standdown_end': lambda *a, **k: None,
          'audit': lambda *a, **k: None, '_ssh_probe': lambda *a, **k: (True, ''),
          '_dbserver_priv': lambda s1: '', '_dbserver_pg_confirm': lambda: confirm,
          '_DBSERVER_POLL_S': 30}
    ns['_written'] = written
    src = APP[APP.index('_DBSERVER_ACK = '):APP.index('_dbserver_start_lock = ')]
    ns.update({'threading': threading, 'socket': socket, 'types': types, 'subprocess': subprocess, 'shutil': shutil,
               'CONFIG_DIR': '/nonexistent', 'secrets': __import__('secrets'), 'hashlib': __import__('hashlib'),
               'tempfile': __import__('tempfile')})
    os_consts = APP[APP.index('_OS_UPGRADE_UNIT = '):APP.index('\n\n\ndef _os_upgrade_unit_state')]
    exec(compile(os_consts, 'app.py:os-consts', 'exec'), ns)
    exec(compile(src, 'app.py:dbs-consts', 'exec'), ns)
    for name in ('_systemctl_show_tuple', '_dbserver_compare', '_dbserver_verify', '_dbserver_finish',
                 '_dbserver_tick'):
        exec(compile(_fn(name), f'app.py:{name}', 'exec'), ns)
    return ns


def _status_probe(raw, unit='inactive', **over):
    d = {'boot_id': 'boot-1', 'clusters': [['18', 'main', '5432', 'online']], 'tak_sessions': 5,
         'tak_sessions_ssl': 5, 'services': {'postgresql@18-main': 'active'}, 'agent': 200,
         'jobs': {'pg-update': {'status': raw, 'show': f'LoadState=loaded\nActiveState={unit}\nSubState=dead\nResult=success\nMainPID=0\n'}}}
    d.update(over)
    return lambda s1, mode: (d, '', '')


def _rec(**over):
    r = {'job': 'pg-update', 'host': HOST, 'started': time.time(), 'boot_id': 'boot-1', 'phase': 'running',
         'step': 'start', 'detail': '', 'notices': [], 'finished': 0, 'reboot_required': False,
         'baseline': {'boot_id': 'boot-1', 'tak_sessions': 5, 'tak_sessions_ssl': 5, 'agent': 200,
                      'services': ['postgresql@18-main']}}
    r.update(over)
    return r


def test_done_with_tak_reconnected_and_the_version_read_is_done():
    ns = _tick_ns()
    rec = ns['_dbserver_tick'](_rec(), {'host': HOST}, probe_fn=_status_probe('done'), sleep=lambda s: None)
    assert rec['phase'] == 'done' and 'now reports 18.7' in rec['detail']
    assert ns['_PG_REMOTE_CACHE']['data'] is None          # the page asks again, not the old 18.6


def test_done_but_the_console_still_reads_the_old_version_is_a_failure():
    ns = _tick_ns(confirm=('PostgreSQL still reports 18.6, below the fix', ''))
    rec = ns['_dbserver_tick'](_rec(), {'host': HOST}, probe_fn=_status_probe('done'), sleep=lambda s: None)
    assert rec['phase'] == 'failed' and rec['step'] == 'verify' and 'still reports 18.6' in rec['detail']


def test_done_but_tak_never_reconnected_is_a_failure():
    ns = _tick_ns()
    t = [1000.0]

    def now():
        t[0] += 400
        return t[0]
    rec = ns['_dbserver_tick'](_rec(), {'host': HOST}, probe_fn=_status_probe('done', tak_sessions=0, tak_sessions_ssl=0),
                               sleep=lambda s: None, now=now)
    assert rec['phase'] == 'failed' and 'tak-not-reconnected' in rec['detail']


@pytest.mark.parametrize('code', ['no-fix', 'held', 'apt', 'restart', 'os', 'none'])
def test_each_failure_code_has_a_plain_sentence(code):
    ns = _tick_ns()
    rec = ns['_dbserver_tick'](_rec(), {'host': HOST}, probe_fn=_status_probe('failed:' + code), sleep=lambda s: None)
    assert rec['phase'] == 'failed' and rec['step'] == 'pg-update'
    assert rec['detail'] == ns['_DBSERVER_PG_FAIL'][code] and len(rec['detail']) > 30


def test_a_job_that_died_without_a_status_is_reported():
    ns = _tick_ns()
    rec = ns['_dbserver_tick'](_rec(), {'host': HOST}, probe_fn=_status_probe('running:pg-update', unit='failed'),
                               sleep=lambda s: None)
    assert rec['phase'] == 'failed' and 'stopped without reporting' in rec['detail']


def test_a_running_job_keeps_running():
    ns = _tick_ns()
    rec = ns['_dbserver_tick'](_rec(), {'host': HOST}, probe_fn=_status_probe('running:pg-update', unit='active'),
                               sleep=lambda s: None)
    assert rec['phase'] == 'running' and rec['step'] == 'pg-update'


# ── 3. the console reads the version itself, and only acts where it should ───────────

def _confirm_ns(status):
    ns = {'_PG_REMOTE_CACHE': {'ts': 0.0, 'data': 'old'}, '_postgres_remote_status': lambda **k: status}
    exec(compile(_fn('_dbserver_pg_confirm'), 'app.py:confirm', 'exec'), ns)
    return ns['_dbserver_pg_confirm']


def test_confirm_reads_the_version_and_clears_the_page_cache():
    c = _confirm_ns({'state': 'ok', 'version': '18.7', 'reason': ''})
    assert c() == ('', 'PostgreSQL now reports 18.7')
    assert _confirm_ns({'state': 'update', 'version': '18.6', 'reason': ''})()[0].startswith('PostgreSQL still reports 18.6')
    assert _confirm_ns({'state': 'unknown', 'version': '', 'reason': 'x'})()[0] == ''   # unreadable: a note, not a verdict


def _start_ns(topology, remote_state, same_host=True):
    started = []
    ns = {'_dbserver_target': lambda: ({'host': HOST, 'ssh_user': 'ubuntu'}, ''),
          '_tak_db_topology': lambda: topology, '_dbserver_same_host': lambda a, b: same_host,
          '_postgres_remote_status': lambda **k: remote_state,
          '_dbserver_probe': lambda s1, mode: ({'boot_id': 'b'}, '', ''),
          '_dbserver_remote_busy': lambda d: [], '_dbserver_baseline': lambda d: {'boot_id': 'b'},
          '_dbserver_begin': lambda job, s1, base, launch: (started.append(job) or (200, {'ok': True})),
          '_dbserver_launch': lambda *a: (True, ''),
          '_pg_update_dbserver_script': lambda f: 'script ' + f,
          '_DBSERVER_JOBS': {'pg-update': {'dir': '/var/lib/infratak-pg-update'}}}
    ns['_started'] = started
    exec(compile(_fn('_dbserver_start_locked'), 'app.py:start', 'exec'), ns)
    return ns


def test_the_button_starts_the_job_on_the_database_server_below_the_fix():
    ns = _start_ns(('remote', HOST, 5432), {'state': 'update', 'version': '18.6'})
    code, payload = ns['_dbserver_start_locked']('pg-update', None)
    assert code == 200 and ns['_started'] == ['pg-update']


@pytest.mark.parametrize('topology,state,same,why', [
    (('local', '127.0.0.1', 5432), {'state': 'update', 'version': '18.6'}, True, 'not on the database server'),
    (('remote', 'other.example.org', 5432), {'state': 'update', 'version': '18.6'}, False, 'not on the database server'),
    (('remote', HOST, 5432), {'state': 'ok', 'version': '18.7'}, True, 'already has the security fix'),
])
def test_the_button_refuses_what_it_must_not_touch(topology, state, same, why):
    ns = _start_ns(topology, state, same_host=same)
    code, payload = ns['_dbserver_start_locked']('pg-update', None)
    assert code == 409 and why in payload['error'] and ns['_started'] == []


def test_an_unreadable_version_still_lets_the_job_run_because_the_job_decides_itself():
    ns = _start_ns(('remote', HOST, 5432), {'state': 'unknown', 'version': '', 'reason': 'x'})
    code, _p = ns['_dbserver_start_locked']('pg-update', None)
    assert code == 200


def _manage_ns(target, same):
    ns = {'_dbserver_target': lambda: target, '_dbserver_same_host': lambda a, b: same}
    exec(compile(_fn('_pg_dbserver_manageable'), 'app.py:manage', 'exec'), ns)
    return ns['_pg_dbserver_manageable']


def test_only_the_machine_the_console_holds_ssh_for_is_manageable():
    assert _manage_ns(({'host': HOST}, ''), True)(HOST) is True
    assert _manage_ns(({'host': HOST}, ''), False)('db.other.example') is False
    assert _manage_ns((None, 'this is not a split install'), True)(HOST) is False
    boom = {'_dbserver_target': lambda: (_ for _ in ()).throw(RuntimeError('x')), '_dbserver_same_host': lambda a, b: True}
    exec(compile(_fn('_pg_dbserver_manageable'), 'app.py:manage', 'exec'), boom)
    assert boom['_pg_dbserver_manageable'](HOST) is False


# ── 4. the notice names the button when the console can act ──────────────────────────

def _notice_ns():
    ns = {'re': re, 'print': lambda *a, **k: None, 'os': types.SimpleNamespace(environ={'PATH': '/bin'}),
          'subprocess': subprocess, 'time': time, '_pg_dbserver_manageable': lambda host: True}
    funcs = ('_pg_version_tuple', '_pg_fixed_tuple', '_pg_releases_missing', '_pg_remote_kind', '_pg_remote_where',
             '_postgres_remote_status', '_postgres_remote_items', '_postgres_remote_panel')
    src = '\n'.join([_const('POSTGRES_SECURITY_RELEASES'), _const('_PG_RDS_HOST_RE'), _const('_PG_AZURE_HOST_RE'),
                     _const('_PG_REMOTE_CACHE'), _const('_PG_REMOTE_TTL')] + [_fn(f) for f in funcs])
    exec(compile(src, 'app.py:notice', 'exec'), ns)
    return ns


def test_split_notice_points_at_the_button_and_says_what_it_does():
    n = _notice_ns()
    st = n['_postgres_remote_status'](('remote', HOST, 5432), reader=lambda: ('18.6', ''))
    assert st['manage'] is True and st['state'] == 'update'
    assert 'Press Update PostgreSQL on the database server card' in st['where']
    assert 'Update PostgreSQL on that machine' not in st['where']
    text = ' '.join(n['_postgres_remote_items'](st)[0]['security'])
    assert 'It reconnects by itself.' in text and 'changes nothing on that database' not in text


def test_panel_offers_the_button_for_update_and_unknown_but_not_for_ok():
    base = _notice_ns()['_postgres_remote_status']
    for ver, reason, want in (('18.6', '', True), ('', 'could not connect to the database', True), ('18.7', '', False)):
        n = _notice_ns()
        n['_postgres_remote_status'] = (lambda v, r: lambda **k: base(('remote', HOST, 5432), reader=lambda: (v, r)))(ver, reason)
        d = n['_postgres_remote_panel'](force=True)
        assert d['manage'] is True and d['can_update'] is want, (ver, d)


def test_rds_and_azure_stay_notice_only():
    n = _notice_ns()
    for host in ('tak-db.abc123.us-east-1.rds.amazonaws.com', 'tak-db.postgres.database.azure.com'):
        st = n['_postgres_remote_status'](('remote', host, 5432), reader=lambda: ('18.6', ''))
        assert st['manage'] is False, host
        assert 'Update PostgreSQL on the database server card' not in st['where']


def test_a_split_host_the_console_has_no_ssh_for_keeps_the_old_wording():
    n = _notice_ns()
    n['_pg_dbserver_manageable'] = lambda host: False
    st = n['_postgres_remote_status'](('remote', HOST, 5432), reader=lambda: ('18.6', ''))
    assert st['manage'] is False and f'Your TAK database runs on {HOST}. Update PostgreSQL on that machine.' in st['where']


# ── 5. wiring ──────────────────────────────────────────────────────────────────────────

def test_route_is_login_required_and_split_gated():
    m = re.search(r"@app\.route\('/api/console/dbserver/pg-update', methods=\['POST'\]\)\n@login_required\n"
                  r"def (\w+)\(\):.*?(?=^@app\.route)", APP, re.S | re.M)
    assert m
    body = m.group(0)
    assert '_dbserver_routes_available()' in body and "_dbserver_start('pg-update')" in body


def test_job_has_its_own_unit_script_dir_and_standdown():
    ns = {'re': re, 'os': os, 'CONFIG_DIR': '/x', 'threading': threading, 'socket': socket, 'time': time}
    src = APP[APP.index('_DBSERVER_ACK = '):APP.index('_dbserver_start_lock = ')]
    exec(compile(src, 'app.py:consts', 'exec'), ns)
    j = ns['_DBSERVER_JOBS']['pg-update']
    assert j['unit'] == 'infratak-pg-update' and j['dir'] == '/var/lib/infratak-pg-update'
    assert j['script'] != ns['_DBSERVER_JOBS']['updates']['script']
    assert ns['_DBSERVER_STANDDOWN_S']['pg-update'] == 1800


def test_the_page_has_the_button_on_the_card_and_in_the_notice():
    card = CONSOLE[CONSOLE.index("{% if host.id == 'tak_db' %}<button"):]
    card = card[:card.index('{% endif %}')]
    assert 'id="dbs-card-pg-btn"' in card and 'dbsUpdatePostgres()' in card
    banner = CONSOLE[CONSOLE.index('id="pg-remote-banner"'):CONSOLE.index('id="kernel-patch-banner"')]
    assert 'id="pg-remote-btn"' in banner and 'dbsUpdatePostgres()' in banner
    assert "'/api/console/dbserver/pg-update'" in CONSOLE
    assert "'pg-update':'database server PostgreSQL update'" in CONSOLE
    assert 'd.can_update' in CONSOLE
    assert "confirm('Update PostgreSQL on the database server" in CONSOLE
