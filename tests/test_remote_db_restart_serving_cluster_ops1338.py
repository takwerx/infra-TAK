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
"""Server One's database restart picks the PostgreSQL that SERVES the port (ops #1338).

After the TAK 5.8 split migration Server One keeps the old PostgreSQL 15 cluster, stopped on
5433, next to PostgreSQL 18 on 5432. Every restart used to be
`pg_ctlcluster 15 main restart || systemctl restart postgresql`. With 18 down, the first half
started the OLD cluster and succeeded, so the half that would have started 18 never ran: 18
stayed down and the watcher reported restart_failed.

The REAL shell text runs here in a sandbox where pg_lsclusters, pg_ctlcluster, systemctl and
sudo are stubs that print what they are asked, so each test sees exactly which cluster a
restart reaches. PATH holds only the stubs and the few plain tools the snippet uses, so a real
pg_lsclusters on a CI machine cannot change an answer.
"""

import ast
import os
import pathlib
import re
import shutil
import stat
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-remotedb-watch.sh').read_text()

# What `pg_lsclusters -h` prints: version cluster port status owner data-dir log-file
MIGRATED_BOTH_DOWN = ('15 main 5433 down postgres /var/lib/postgresql/15/main /var/log/postgresql/postgresql-15-main.log\n'
                      '18 main 5432 down postgres /var/lib/postgresql/18/main /var/log/postgresql/postgresql-18-main.log\n')
MIGRATED_18_UP = MIGRATED_BOTH_DOWN.replace('18 main 5432 down', '18 main 5432 online')
ONLY_15 = '15 main 5432 online postgres /var/lib/postgresql/15/main /var/log/postgresql/postgresql-15-main.log\n'
BOTH_ON_5432 = ('15 main 5432 down postgres /var/lib/postgresql/15/main /x\n'
                '18 main 5432 down postgres /var/lib/postgresql/18/main /x\n')
NEITHER_ON_PORT = ('15 main 5434 down postgres /var/lib/postgresql/15/main /x\n'
                   '18 main 5433 down postgres /var/lib/postgresql/18/main /x\n')
ONLY_18_AFTER_REMOVE = '18 main 5432 down postgres /var/lib/postgresql/18/main /x\n'


def _snippet():
    m = re.search(r'^_PG_CTL_SH = r"""(.*?)"""', APP, re.S | re.M)
    assert m, '_PG_CTL_SH is missing from app.py'
    return m.group(1)


def _pg_ctl_cmd():
    """The real _pg_ctl_cmd() from app.py, with the real _PG_CTL_SH."""
    tree = ast.parse(APP)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_pg_ctl_cmd')
    ns = {'_PG_CTL_SH': _snippet()}
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py:_pg_ctl_cmd', 'exec'), ns)
    return ns['_pg_ctl_cmd']


STUBS = {
    'pg_lsclusters': '#!/bin/sh\ncat "$SANDBOX/lsclusters"\n',
    'pg_ctlcluster': '#!/bin/sh\necho "pg_ctlcluster $*" >> "$SANDBOX/calls"\n'
                     '[ -f "$SANDBOX/ctl_fails" ] && { echo "pg_ctlcluster: failed" >&2; exit 1; }\nexit 0\n',
    'sudo': '#!/bin/sh\n[ "$1" = "-n" ] && shift\nexec "$@"\n',
    'systemctl': r'''#!/bin/sh
case "$1" in
  list-units) cat "$SANDBOX/units" 2>/dev/null ;;
  list-unit-files) cat "$SANDBOX/unit_files" 2>/dev/null ;;
  is-active) shift; [ "$1" = "--quiet" ] && shift; grep -qx "$1" "$SANDBOX/active" 2>/dev/null ;;
  *) echo "systemctl $*" >> "$SANDBOX/calls" ;;
esac
''',
}


@pytest.fixture
def sandbox(tmp_path):
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    for tool in ('awk', 'sort', 'sed', 'tail', 'head', 'tr', 'cut', 'cat', 'grep', 'env'):
        real = shutil.which(tool)
        assert real, tool
        (bindir / tool).symlink_to(real)
    for sh in ('sh', 'bash'):
        (bindir / sh).symlink_to(shutil.which(sh))

    def make(lsclusters=None, units='', unit_files='', active='', ctl_fails=False, ts=None):
        for name, body in STUBS.items():
            if name == 'pg_lsclusters' and lsclusters is None:
                p = bindir / name
                if p.exists():
                    p.unlink()
                continue
            (bindir / name).write_text(body)
            (bindir / name).chmod(0o755)
        if lsclusters is not None:
            (tmp_path / 'lsclusters').write_text(lsclusters)
        (tmp_path / 'units').write_text(units)
        (tmp_path / 'unit_files').write_text(unit_files)
        (tmp_path / 'active').write_text(active)
        (tmp_path / 'calls').write_text('')
        if ctl_fails:
            (tmp_path / 'ctl_fails').write_text('1')

    def run(command, shell='bash'):
        env = {'PATH': str(bindir), 'SANDBOX': str(tmp_path)}
        r = subprocess.run([shell, '-c', command], capture_output=True, text=True, env=env, timeout=60)
        calls = (tmp_path / 'calls').read_text().splitlines()
        return r, calls

    make.run = run
    make.dir = tmp_path
    make.bin = bindir
    return make


def _call(sandbox, action='restart', port=5432, shell='bash'):
    return sandbox.run(_pg_ctl_cmd()(action, port), shell=shell)


# --- the bug: Debian Server One after the 5.8 split migration --------------------------------

@pytest.mark.parametrize('shell', ['bash', 'sh'])
def test_migrated_server_one_with_18_down_restarts_18_never_15(sandbox, shell):
    sandbox(MIGRATED_BOTH_DOWN)
    r, calls = _call(sandbox, shell=shell)
    assert calls == ['pg_ctlcluster 18 main restart'], (calls, r.stderr)
    assert r.returncode == 0


def test_migrated_server_one_with_18_running_restarts_18(sandbox):
    sandbox(MIGRATED_18_UP)
    _, calls = _call(sandbox)
    assert calls == ['pg_ctlcluster 18 main restart']


@pytest.mark.parametrize('action', ['start', 'stop', 'restart', 'reload'])
def test_every_action_reaches_the_serving_cluster(sandbox, action):
    sandbox(MIGRATED_BOTH_DOWN)
    _, calls = _call(sandbox, action)
    assert calls == ['pg_ctlcluster 18 main ' + action]


def test_the_cluster_on_the_database_port_wins_even_when_it_is_not_the_newest(sandbox):
    # an operator moved TAK's database to 15 on 5433 and left 18 on 5432 for something else
    sandbox(MIGRATED_BOTH_DOWN)
    _, calls = _call(sandbox, 'restart', 5433)
    assert calls == ['pg_ctlcluster 15 main restart']


# --- the old behaviour must not change where it was right ------------------------------------

def test_a_box_that_never_migrated_still_restarts_15(sandbox):
    sandbox(ONLY_15)
    _, calls = _call(sandbox)
    assert calls == ['pg_ctlcluster 15 main restart']


def test_two_clusters_configured_on_the_same_port_the_newest_wins(sandbox):
    sandbox(BOTH_ON_5432)
    _, calls = _call(sandbox)
    assert calls == ['pg_ctlcluster 18 main restart']


def test_no_cluster_on_the_port_still_picks_the_newest_not_the_old_one(sandbox):
    sandbox(NEITHER_ON_PORT)
    _, calls = _call(sandbox)
    assert calls == ['pg_ctlcluster 18 main restart']


def test_old_cluster_removed_in_guard_dog_only_18_is_left(sandbox):
    sandbox(ONLY_18_AFTER_REMOVE)
    _, calls = _call(sandbox)
    assert calls == ['pg_ctlcluster 18 main restart']


def test_when_pg_ctlcluster_fails_the_fallback_is_18s_own_unit_never_the_whole_service(sandbox):
    sandbox(MIGRATED_BOTH_DOWN, ctl_fails=True)
    r, calls = _call(sandbox)
    # `systemctl restart postgresql` would restart every auto-start cluster, the old 15 too
    assert calls == ['pg_ctlcluster 18 main restart', 'systemctl restart postgresql@18-main'], calls
    assert r.returncode == 0


# --- RHEL / Rocky Server One: no pg_lsclusters, PGDG units postgresql-N ----------------------

RHEL_UNITS = ('postgresql-15.service loaded inactive dead PostgreSQL 15 database server\n'
              'postgresql-18.service loaded active running PostgreSQL 18 database server\n')
RHEL_FILES = 'postgresql-15.service enabled\npostgresql-18.service enabled\n'


def test_rhel_restarts_the_active_unit(sandbox):
    sandbox(None, units=RHEL_UNITS, unit_files=RHEL_FILES, active='postgresql-18\n')
    r, calls = _call(sandbox)
    assert calls == ['systemctl restart postgresql-18'], (calls, r.stderr)


def test_rhel_with_everything_down_restarts_the_newest_unit(sandbox):
    sandbox(None, units=RHEL_UNITS.replace(' active running', ' inactive dead'), unit_files=RHEL_FILES, active='')
    _, calls = _call(sandbox)
    assert calls == ['systemctl restart postgresql-18']


def test_rhel_unit_numbers_sort_as_numbers_not_text(sandbox):
    files = 'postgresql-9.6.service enabled\npostgresql-18.service enabled\n'
    sandbox(None, unit_files=files)
    _, calls = _call(sandbox)
    assert calls == ['systemctl restart postgresql-18']


def test_a_box_with_only_the_plain_unit_keeps_working(sandbox):
    sandbox(None)
    _, calls = _call(sandbox)
    assert calls == ['systemctl restart postgresql']


# --- nothing a request carries reaches the shell ---------------------------------------------

def test_pg_ctl_cmd_refuses_a_bad_action_and_coerces_a_bad_port():
    f = _pg_ctl_cmd()
    with pytest.raises(ValueError):
        f('restart; rm -rf /', 5432)
    with pytest.raises(ValueError):
        f('status', 5432)
    assert f('restart', '5433').endswith('pgctl restart 5433')
    assert f('restart', None).endswith('pgctl restart 5432')
    assert f('restart', '5432; reboot').endswith('pgctl restart 5432')


# --- the real watcher script, end to end -----------------------------------------------------

WATCH_SSH = r'''#!/bin/bash
# the last argument is what the remote shell would run
cmd="${@: -1}"
case "$cmd" in
  *SSHOK*) echo "SSHOK PR=2 SU=0"; exit 0 ;;
esac
exec bash -c "$cmd"
'''


@pytest.fixture
def watcher(sandbox, tmp_path):
    def build(lsclusters, **kw):
        sandbox(lsclusters, **kw)
        bindir = sandbox.bin
        # the watcher needs ordinary tools too; keep them after the stubs
        gd = tmp_path / 'gd'
        gd.mkdir(exist_ok=True)
        (bindir / 'ssh').write_text(WATCH_SSH)
        (bindir / 'timeout').write_text('#!/bin/sh\nexit 1\n')       # TCP stays down
        (bindir / 'sleep').write_text('#!/bin/sh\nexit 0\n')
        (gd / 'send-alert-email.sh').write_text('#!/bin/sh\nexit 0\n')
        for f in (bindir / 'ssh', bindir / 'timeout', bindir / 'sleep', gd / 'send-alert-email.sh'):
            f.chmod(0o755)
        key = tmp_path / 'key'
        key.write_text('k')
        script = (WATCH.replace('/var/lib/takguard', str(tmp_path / 'state'))
                       .replace('/var/log/takguard', str(tmp_path / 'log'))
                       .replace('/opt/tak-guarddog/', str(gd) + '/')
                       .replace('DB_HOST_PLACEHOLDER', 'db1')
                       .replace('DB_PORT_PLACEHOLDER', '5432')
                       .replace('SSH_KEY_PLACEHOLDER', str(key))
                       .replace('SSH_USER_PLACEHOLDER', 'root')
                       .replace('EXTERNAL_DB_PLACEHOLDER', '')
                       .replace('ALERT_EMAIL_PLACEHOLDER', ''))
        sp = tmp_path / 'tak-remotedb-watch.sh'
        sp.write_text(script)
        env = {'PATH': '%s:/usr/bin:/bin' % bindir, 'SANDBOX': str(tmp_path)}
        for _ in range(3):                      # three failures in a row open the restart gate
            r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=120)
            assert r.returncode == 0, r.stderr
        log = tmp_path / 'log' / 'restarts.log'
        return (tmp_path / 'calls').read_text().splitlines(), (log.read_text() if log.exists() else '')
    return build


def test_watcher_restarts_18_when_18_is_down_on_a_migrated_split_box(watcher):
    calls, log = watcher(MIGRATED_BOTH_DOWN)
    assert calls == ['pg_ctlcluster 18 main restart'], (calls, log)
    assert all(' 15 ' not in c for c in calls)


def test_watcher_on_a_box_that_never_migrated_restarts_15(watcher):
    calls, _ = watcher(ONLY_15)
    assert calls == ['pg_ctlcluster 15 main restart']


# --- the other callers of the same job, and the snippet kept in one piece --------------------

def _fn_source(name):
    tree = ast.parse(APP)
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(APP, node), node


def test_watcher_and_console_carry_the_same_snippet():
    m = re.search(r'^# pgctl-begin\n(.*?)^# pgctl-end\n', WATCH, re.S | re.M)
    assert m, 'tak-remotedb-watch.sh lost its pgctl snippet markers'
    assert m.group(1) == _snippet()


def test_no_start_stop_or_restart_of_a_hardcoded_cluster_15_is_left():
    for name, text in (('app.py', APP), ('tak-remotedb-watch.sh', WATCH)):
        text = '\n'.join(l for l in text.splitlines() if not l.lstrip().startswith('#'))   # comments explain the bug
        bad = re.findall(r'pg_ctlcluster 15 main (?:start|stop|restart)', text)
        assert not bad, '%s still hardcodes PostgreSQL 15: %s' % (name, bad)
    assert 'systemctl restart postgresql 2>' not in WATCH


def test_the_watcher_hint_no_longer_points_at_cluster_15():
    assert 'pg_ctlcluster 15 main status' not in WATCH
    assert 'sudo pg_lsclusters' in WATCH


def test_server_one_setup_picks_the_newest_cluster_dir_not_the_first_find_hit():
    src, _ = _fn_source('_setup_server_one')
    assert 'find /etc/postgresql -type d -name main 2>/dev/null | head -1' not in src
    assert src.count('sort -V | tail -1') >= 2
    assert '_PG_CTL_SH' in src and "_pg_ctl_cmd('start', db_port)" in src
    assert 'pg_ctlcluster 15' not in src


def test_server_one_setup_restart_text_defines_pgctl_before_using_it():
    """The config step is `pgctl restart` inside a long && chain: the function must be
    defined first in the same remote command."""
    calls = []

    class Stop(Exception):
        pass

    def probe(s1, cmd, timeout=0):
        calls.append(cmd)
        if 'listen_addresses' in cmd:
            raise Stop
        if 'grep -ci postgres' in cmd:
            return True, '1'                # PostgreSQL is already installed on Server One
        return True, 'PG_OK'                # also answers the OS-family probe: not RHEL, so Debian

    tree = ast.parse(APP)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_setup_server_one')
    ns = {'TAK_PG_MAJOR': 18, '_PGDG_REMOTE_SETUP_SH': '', '_PG_CTL_SH': _snippet(), '_pg_ctl_cmd': _pg_ctl_cmd(),
          '_pg_keepalive_sh': lambda c: 'true', '_ssh_probe': probe, '_scp_to_host': lambda *a, **k: (True, ''),
          '_valid_core_ip': lambda ip: True, '_setup_server_one_rhel': lambda *a, **k: (True, [], ''),
          '_fetch_db_password_from_server_one': lambda *a, **k: ('', ''),
          '_server_one_tls_step': lambda *a, **k: (True, ''),
          '_verify_server_one_db_password': lambda *a, **k: (True, '')}
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py:_setup_server_one', 'exec'), ns)
    with pytest.raises(Stop):
        ns['_setup_server_one']({'host': 'db1', 'ssh_user': 'root'}, '10.0.0.2', 5432, None, None)
    cfg = [c for c in calls if 'listen_addresses' in c]
    assert cfg, calls
    cmd = cfg[0]
    assert cmd.index('pgctl() {') < cmd.index('pgctl restart 5432')
    assert 'pg_ctlcluster 15' not in cmd


# --- the Start / Stop / Restart database button ----------------------------------------------

def _control(sandbox, action, lsclusters=MIGRATED_BOTH_DOWN, port=5432):
    sandbox(lsclusters)
    tree = ast.parse(APP)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'takserver_control')
    node.decorator_list = []
    sent = []

    try:
        helper = _pg_ctl_cmd()
    except (AssertionError, StopIteration):  # base code: no helper, the button builds its own command
        helper = None

    def probe(s1, cmd, timeout=0):
        if 'pgctl' in cmd or 'pg_ctlcluster' in cmd:
            r, _ = sandbox.run(cmd)
            sent.append(cmd)
            return r.returncode == 0, r.stdout
        return True, 'DB_OK'

    ns = {'request': types.SimpleNamespace(json={'action': action, 'target': 'database'}),
          'jsonify': lambda d, *a: d,
          'load_settings': lambda: {},
          '_get_tak_deployment_config': lambda s: {'mode': 'two_server', 'server_one': {'host': 'db1'},
                                                   'database': {'port': port}},
          '_ssh_probe': probe}
    if helper:
        ns['_pg_ctl_cmd'] = helper
    # ops #1382: the button's readiness check is now the _pg_isready_cmd helper (absent on older code)
    ready = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_pg_isready_cmd'), None)
    if ready:
        exec(compile(ast.Module(body=[ready], type_ignores=[]), 'app.py:_pg_isready_cmd', 'exec'), ns)
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py:takserver_control', 'exec'), ns)
    out = ns['takserver_control']()
    return out, sent


@pytest.mark.parametrize('action', ['start', 'stop', 'restart'])
def test_database_button_reaches_18_on_a_migrated_split_box(sandbox, action):
    out, sent = _control(sandbox, action)
    assert sent and out['success'] is True
    calls = (sandbox.dir / 'calls').read_text().splitlines()
    assert calls == ['pg_ctlcluster 18 main ' + action], calls
