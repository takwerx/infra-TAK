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
"""ops #1337: the TAK Server rollback must not destroy what it cannot put back, and must not
say "restored" for a restore that did not happen.

1. A certificate copy that fails keeps the current certificates (no `rm -rf` first).
2. A dump from a newer PostgreSQL than the one installed is refused before TAK stops.
3. pg_restore exit 1 is not "warnings" when it refused the archive or changed nothing.
4. A safety snapshot of the current state is taken before anything is changed.
5. The half-configured heal does not clear the state while the running TAK Server is the old
   code, and runs TAK's database setup after it does.
6. A downgrade whose snapshot has no database dump does not go ahead.
"""

import ast
import datetime as _dt
import os
import pathlib
import re
import shlex
import subprocess
import types

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _assign(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _load(ns, funcs, globs=(), optional=()):
    """`optional` names are helpers this change adds: when one is missing (the base branch) the
    test still runs, and fails on what the code DOES, not on a missing name."""
    for g in globs:
        try:
            exec(compile(_assign(g), 'app.py', 'exec'), ns)
        except AssertionError:
            if g not in optional:
                raise
    for f in funcs:
        try:
            exec(compile(_func(f), 'app.py', 'exec'), ns)
        except AssertionError:
            if f not in optional:
                raise
    return ns


class _Done(Exception):
    """Ends a long function where the test has seen what it needs."""


# ── a scripted subprocess ───────────────────────────────────────────────────────────────────

class _Sub:
    TimeoutExpired = subprocess.TimeoutExpired
    CompletedProcess = subprocess.CompletedProcess
    CalledProcessError = subprocess.CalledProcessError
    PIPE = subprocess.PIPE
    DEVNULL = subprocess.DEVNULL

    def __init__(self, events=None):
        self.calls = []
        self.rules = []          # (predicate(argv_str) -> bool, returncode, stdout, stderr)
        self.events = events if events is not None else []

    def when(self, needle, rc=0, out='', err=''):
        self.rules.append((needle, rc, out, err))

    def run(self, args, **kw):
        s = args if isinstance(args, str) else ' '.join(map(str, args))
        self.calls.append(s)
        if 'systemctl stop' in s or s.startswith('docker stop'):
            self.events.append('stop')
        rc, out, err = 0, '', ''
        for needle, r, o, e in self.rules:
            if needle in s:
                rc, out, err = r, o, e
                break
        if kw.get('stdin') is not None or 'pg_restore --clean' in s:
            err = err.encode() if isinstance(err, str) else err
            out = out.encode() if isinstance(out, str) else out
        if kw.get('check') and rc != 0:
            raise subprocess.CalledProcessError(rc, args, output=out, stderr=err)
        return subprocess.CompletedProcess(args, rc, out, err)


# ── 1. the certificate swap ────────────────────────────────────────────────────────────────

def _swap_ns(real=True):
    ns = {'subprocess': subprocess, 'os': os, '_sudo_wrap': lambda c: list(c)}
    return _load(ns, ['_tak_swap_certs'])


def test_swap_replaces_the_live_folder_and_leaves_no_scratch_folders(tmp_path):
    src, live = tmp_path / 'snap-certs', tmp_path / 'files'
    src.mkdir(); live.mkdir()
    (src / 'new.pem').write_text('new')
    (live / 'old.pem').write_text('old')
    ok, err = _swap_ns()['_tak_swap_certs'](str(src), str(live))
    assert ok and not err
    assert (live / 'new.pem').read_text() == 'new' and not (live / 'old.pem').exists()
    assert not (tmp_path / 'files.rb-new').exists() and not (tmp_path / 'files.rb-old').exists()


def test_swap_with_a_failing_copy_keeps_the_current_certificates(tmp_path):
    live = tmp_path / 'files'
    live.mkdir()
    (live / 'old.pem').write_text('old')
    ok, err = _swap_ns()['_tak_swap_certs'](str(tmp_path / 'no-such-snapshot-folder'), str(live))
    assert not ok and 'copy' in err
    assert (live / 'old.pem').read_text() == 'old', 'the current certificates were destroyed'
    assert not (tmp_path / 'files.rb-new').exists()


def test_swap_puts_the_old_folder_back_when_the_last_move_fails(tmp_path):
    src, live = tmp_path / 'snap-certs', tmp_path / 'files'
    src.mkdir(); live.mkdir()
    (src / 'new.pem').write_text('new')
    (live / 'old.pem').write_text('old')

    def wrap(argv):                      # the move of the copy into place fails
        argv = list(argv)
        if argv[0] == 'mv' and argv[1].endswith('.rb-new'):
            return ['false']
        return argv

    ns = {'subprocess': subprocess, 'os': os, '_sudo_wrap': wrap}
    _load(ns, ['_tak_swap_certs'])
    ok, err = ns['_tak_swap_certs'](str(src), str(live))
    assert not ok
    assert (live / 'old.pem').read_text() == 'old', 'the old certificates were not put back'


# ── 2-4. the rollback ──────────────────────────────────────────────────────────────────────

def _rollback_ns(tmp_path, *, meta=None, major_here=15, sub=None, oids=(10, 20), sv_after=105,
                 safety=(True, {'db_dump': True}), cert_copy_fails=False, cc_copy_fails=False):
    snaps = tmp_path / 'snapshots'
    snap = snaps / 'snap1'
    (snap / 'certs').mkdir(parents=True)
    (snap / 'cot.pgdump').write_bytes(b'PGDMP')
    (snap / 'CoreConfig.xml').write_text('<x/>')
    events = []
    sub = sub or _Sub(events)
    events = sub.events
    oid_seq = list(oids)
    meta_row = dict(meta or {})
    meta_row['label'] = 'snap1'

    def snapshot(label, plog=None):
        events.append('snapshot ' + label)
        return safety

    ns = {
        'subprocess': sub, 'os': os, 're': re, 'shlex': shlex, 'SNAPSHOT_DIR': str(snaps),
        'datetime': _dt.datetime, 'time': __import__('time'),
        '_sudo_wrap': lambda c: list(c), '_validate_snapshot_label': lambda l: (True, l),
        '_tak_is_container': lambda: False,
        '_tak_systemctl': lambda action: f'systemctl {action} takserver',
        '_tak_container_ids': lambda: ('tak', 'tak'),
        '_tak_ca_private_lockdown': lambda plog=None, **kw: ([], []),
        'load_settings': lambda: {'tak_snapshots': [meta_row]},
        'save_settings': lambda s: None,
        '_get_tak_deployment_config': lambda s: {'mode': 'single_server'},
        '_tak_snapshot': snapshot,
        '_tak_prune_snapshots': lambda source, keep: None,
        '_tak_pg_major_local': lambda: major_here,
        '_tak_rollback_prepare_local_db': lambda plog, who='rollback': True,
        '_tak_cot_table_oid': lambda: oid_seq.pop(0) if oid_seq else None,
        '_tak58_schema_version': lambda: sv_after,
        '_tak58_run_setup_db': lambda timeout_sec=3600: 0,
        '_tak_artifact_version': lambda s: (5, 8, 1),
        '_get_takserver_version_info': lambda: {'version': '5.8-RELEASE-1'},
        'TAK_GATE_BLOCK_FROM': (5, 8, 0), '_TAK58_MIN_SCHEMA_VERSION': 100,
        '_broker_should_route': lambda: False, '_broker_available': lambda: False,
        '_tak_rollback_package_note': lambda label: 'note',
        'TAK_DB_CONTAINER': 'takserver-db',
    }
    _load(ns, ['_tak_swap_certs', '_tak_pg_restore_refused', '_tak_rollback_dump_too_new', '_tak_rollback'],
          globs=['_PG_RESTORE_REFUSED_RE'],
          optional=('_tak_swap_certs', '_tak_pg_restore_refused', '_tak_rollback_dump_too_new',
                    '_PG_RESTORE_REFUSED_RE'))
    if cert_copy_fails:
        sub.when('cp -rp ' + str(snap / 'certs'), rc=1, err='No space left on device')
    if cc_copy_fails:
        sub.when('cp -p ' + str(snap / 'CoreConfig.xml'), rc=1, err='denied')
    return ns, sub, events


def _go(ns):
    lines = []
    res = ns['_tak_rollback']('snap1', lines.append)
    return res, lines


def test_a_dump_from_a_newer_postgresql_is_refused_before_tak_is_stopped(tmp_path):
    ns, sub, events = _rollback_ns(tmp_path, meta={'db_pg_major': 18}, major_here=15)
    (ok, err), lines = _go(ns)
    assert ok is False and 'PostgreSQL 18' in err and 'PostgreSQL 15' in err
    assert 'stop' not in events and not any('pg_restore --clean' in c for c in sub.calls)
    assert not any(e.startswith('snapshot') for e in events), 'nothing should be touched or snapshotted'


def test_an_older_dump_into_a_newer_postgresql_is_still_restored(tmp_path):
    ns, sub, events = _rollback_ns(tmp_path, meta={'db_pg_major': 15, 'db_schema_version': 105}, major_here=18)
    (ok, err), lines = _go(ns)
    assert ok is True, (err, lines)


def test_the_current_state_is_saved_before_tak_is_stopped(tmp_path):
    ns, sub, events = _rollback_ns(tmp_path, meta={'db_schema_version': 105})
    (ok, err), lines = _go(ns)
    assert ok is True, (err, lines)
    assert events and events[0].startswith('snapshot pre-rollback-'), events
    assert events.index('stop') > 0


def test_a_failed_safety_snapshot_does_not_block_the_rollback(tmp_path):
    ns, sub, events = _rollback_ns(tmp_path, meta={'db_schema_version': 105}, safety=(False, 'disk full'))
    (ok, err), lines = _go(ns)
    assert ok is True, (err, lines)
    assert any('could not save the current state' in l for l in lines)


def test_pg_restore_that_refused_the_archive_is_not_reported_as_restored(tmp_path):
    sub = _Sub()
    sub.when('pg_restore --clean', rc=1, err='pg_restore: error: unsupported version (1.16) in file header')
    ns, sub, events = _rollback_ns(tmp_path, sub=sub, meta={'db_schema_version': 105})
    (ok, err), lines = _go(ns)
    assert ok is False and 'refused' in err
    assert not any('configuration, certificates and database restored' in l for l in lines)


def test_pg_restore_exit_1_that_changed_nothing_is_a_failure(tmp_path):
    # same table ids before and after = pg_restore --clean never ran
    sub = _Sub()
    sub.when('pg_restore --clean', rc=1, err='')
    ns, sub, events = _rollback_ns(tmp_path, sub=sub, oids=(77, 77), meta={})
    (ok, err), lines = _go(ns)
    assert ok is False and 'changed nothing' in err, (ok, err)


def test_a_restore_that_left_another_schema_than_the_snapshot_is_a_failure(tmp_path):
    sub = _Sub()
    sub.when('pg_restore --clean', rc=1, err='')
    ns, sub, events = _rollback_ns(tmp_path, sub=sub, meta={'db_schema_version': 99}, sv_after=105)
    (ok, err), lines = _go(ns)
    assert ok is False and '99' in err and '105' in err, (ok, err)


def test_pg_restore_exit_1_with_ignorable_warnings_and_a_real_restore_still_passes(tmp_path):
    sub = _Sub()
    sub.when('pg_restore --clean', rc=1,
             err='pg_restore: error: could not execute query: ERROR: table "x" does not exist')
    ns, sub, events = _rollback_ns(tmp_path, sub=sub, meta={'db_schema_version': 105}, oids=(10, 20))
    (ok, err), lines = _go(ns)
    assert ok is True, (err, lines)


def test_a_failed_certificate_copy_is_reported_and_never_says_restored(tmp_path):
    ns, sub, events = _rollback_ns(tmp_path, meta={'db_schema_version': 105}, cert_copy_fails=True)
    (ok, err), lines = _go(ns)
    assert ok is False and 'certificates' in err, (ok, err)
    assert any('still in place' in l for l in lines)
    assert not any('configuration, certificates and database restored' in l for l in lines)
    # the live folder was never removed first
    assert not any(c.startswith('rm -rf /opt/tak/certs/files ') or c == 'rm -rf /opt/tak/certs/files'
                   for c in sub.calls), sub.calls


def test_a_failed_config_copy_is_reported_too(tmp_path):
    ns, sub, events = _rollback_ns(tmp_path, meta={'db_schema_version': 105}, cc_copy_fails=True)
    (ok, err), lines = _go(ns)
    assert ok is False and 'CoreConfig.xml' in err, (ok, err)


@pytest.mark.parametrize('text,expect', [
    ('pg_restore: error: unsupported version (1.16) in file header', True),
    ('pg_restore: error: input file does not appear to be a valid archive', True),
    ('pg_restore: error: input file is too short (read 0, expected 5)', True),
    ('pg_restore: error: could not execute query: ERROR:  table "x" does not exist', False),
    ('pg_restore: warning: errors ignored on restore: 4', False),
    ('', False),
])
def test_pg_restore_refusal_text(text, expect):
    ns = {'re': re}
    _load(ns, ['_tak_pg_restore_refused'], globs=['_PG_RESTORE_REFUSED_RE'])
    assert ns['_tak_pg_restore_refused'](text) is expect


# ── 5. the half-configured heal ────────────────────────────────────────────────────────────

def _heal_ns(started_before):
    sub = _Sub()
    state = {'s': 'install ok half-configured'}

    def run(args, **kw):
        s = ' '.join(args) if not isinstance(args, str) else args
        sub.calls.append(s)
        if 'dpkg-query' in s:
            return subprocess.CompletedProcess(args, 0, state['s'], '')
        if 'is-active' in s:
            return subprocess.CompletedProcess(args, 0, 'active\n', '')
        if 'dpkg --configure' in s:
            state['s'] = 'install ok installed'
        return subprocess.CompletedProcess(args, 0, '', '')

    sub.run = run
    schema = iter([100, 100, 105])
    setup = []
    fake_os = types.SimpleNamespace(path=types.SimpleNamespace(isfile=lambda p: True))
    ns = {
        'subprocess': sub, 'os': fake_os, '_sudo_wrap': lambda c: list(c),
        '_write_priv': lambda p, c, perm=None: None,
        '_takserver_started_before_package': lambda: started_before,
        '_tak58_schema_version': lambda: next(schema, 105),
        '_tak58_run_setup_db': lambda timeout_sec=3600: setup.append(1) or 0,
    }
    _load(ns, ['_selfheal_takserver_half_configured'])
    return ns, sub, setup


def test_heal_leaves_a_half_configured_package_alone_while_the_old_tak_server_runs():
    ns, sub, setup = _heal_ns(started_before=True)
    log = []
    ns['_selfheal_takserver_half_configured'](log.append)
    assert not any('dpkg --configure' in c for c in sub.calls), 'the state was cleared under an old JVM'
    assert any('Run the TAK Server update again' in l for l in log), log
    assert not setup


def test_heal_clears_the_state_and_runs_the_database_setup_when_tak_started_after_the_unpack():
    ns, sub, setup = _heal_ns(started_before=False)
    log = []
    ns['_selfheal_takserver_half_configured'](log.append)
    assert any('dpkg --configure' in c for c in sub.calls)
    assert setup == [1], 'the postinst database setup was skipped and never replaced'
    assert any('schema_version 100 -> 105' in l for l in log), log


def test_the_start_age_check_compares_the_units_active_time_with_the_unpack_time():
    # the unit has no MainPID (SysV script, Type=forking): its own active-since time is used
    def run_with(unpack_mtime, active_usec=900_000_000):
        sub = _Sub()
        sub.when('ActiveEnterTimestampMonotonic', out=f'{active_usec}\n')

        def fake_open(path, *a, **k):
            import io
            if path == '/proc/uptime':
                return io.StringIO('1000.00 3000.00\n')       # up 1000 s
            raise FileNotFoundError(path)

        # now = 5000; boot = 4000; the unit became active 900 s after boot = 4900
        fake_os = types.SimpleNamespace(path=types.SimpleNamespace(getmtime=lambda p: unpack_mtime))
        ns = {'subprocess': sub, 'os': fake_os, 'open': fake_open,
              'time': types.SimpleNamespace(time=lambda: 5000.0)}
        _load(ns, ['_takserver_started_before_package'])
        return ns['_takserver_started_before_package']()

    assert run_with(4950) is True      # package unpacked after TAK Server started: old code running
    assert run_with(4800) is False     # TAK Server started after the unpack
    assert run_with(4950, active_usec=0) is None      # never started: cannot tell


# ── 6. a downgrade with no database dump ───────────────────────────────────────────────────

def _dg_ns(is_downgrade):
    ns = {'_tak_package_downgrade': lambda f: ({'installed': (5, 8, 5), 'package': (5, 8, 2), 'cross_minor': False}
                                              if is_downgrade else None)}
    _load(ns, ['_tak_downgrade_needs_dump'])
    return ns['_tak_downgrade_needs_dump']


def test_a_downgrade_whose_snapshot_has_no_dump_is_refused():
    msg = _dg_ns(True)('takserver_5.8-RELEASE2_all.deb', {'db_dump': False})
    assert msg and 'OLDER' in msg and 'Nothing was changed' in msg


def test_a_downgrade_with_a_dump_and_a_normal_upgrade_without_one_go_ahead():
    assert _dg_ns(True)('takserver_5.8-RELEASE2_all.deb', {'db_dump': True}) == ''
    assert _dg_ns(False)('takserver_5.8-RELEASE9_all.deb', {'db_dump': False}) == ''


@pytest.mark.parametrize('runner', ['run_takserver_upgrade', 'run_takserver_upgrade_rhel',
                                    'run_takserver_upgrade_two_server_rhel'])
def test_every_update_path_that_takes_a_snapshot_asks_the_downgrade_check(runner):
    src = _func(runner)
    assert '_tak_downgrade_needs_dump(' in src, f'{runner} never checks a downgrade against its snapshot'
    assert src.index('_tak_snapshot(') < src.index('_tak_downgrade_needs_dump(')
