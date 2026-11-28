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
"""CloudTAK Update never rolls the old code back onto a database the new one changed (ops #1325).

CloudTAK 14.1.0's migration 0232 drops the old chat tables as soon as the new api boots. When the
update failed later (`up -d` error, or the 2-minute api watch), the code rolled back and said
"nothing was lost" while the old api ran on a changed database. The update now copies the database
before it restarts anything and reads a schema fingerprint; a failure after the fingerprint moved
is NOT rolled back and the message names the copy.

app.py cannot be imported in a test, so the functions are cut out of it. run_cloudtak_update is run
for real (local and remote branch) with the box stubbed out.
"""

import ast
import builtins
import collections
import datetime
import io
import os
import pathlib
import re
import shlex
import threading
import time as _real_time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_REAL = {
    'run_cloudtak_update', '_cloudtak_psql', '_cloudtak_db_fingerprint', '_cloudtak_update_dumps_prune_local',
    '_cloudtak_update_db_dump', '_cloudtak_update_db_guard', '_cloudtak_update_db_moved',
    '_cloudtak_update_db_moved_lines',
}
_CONSTS = {'_STACK_BACKUP_LABEL_RE', 'STACK_BACKUP_DIR'}
REMOTE = {'host': '203.0.113.7', 'ssh_user': 'root'}
SCHEMA_OLD, SCHEMA_NEW = 'a' * 32, 'b' * 32
DUMP_RE = re.compile(r'/var/lib/infratak-backups/cloudtak-update-\d{8}-\d{6}/cloudtak\.pgdump')


class _Box:
    """The stubbed box: a database whose schema flips when the new api 'boots' (up -d), and a log
    of everything the update did."""

    def __init__(self, tmp, remote=False, migrates=True, up_ok=True, watch_ok=True,
                 dump_error=None, db_readable=True, free=10 * 1024 ** 3, size=50 * 1024 ** 2,
                 fp_after_readable=True):
        self.remote, self.migrates, self.up_ok, self.watch_ok = remote, migrates, up_ok, watch_ok
        self.dump_error, self.db_readable, self.free, self.size = dump_error, db_readable, free, size
        self.fp_after_readable = fp_after_readable
        self.schema, self.mig = SCHEMA_OLD, '240'
        self.up_done = False
        self.log, self.calls, self.dumps, self.ssh = [], [], [], []
        self.status = {'running': True, 'complete': False, 'error': False}
        self.settings = {}
        self.tmp = tmp

    # ---- stubs -------------------------------------------------------------------------------
    def docker(self, argv, remote_cfg=None, timeout=60):
        self.calls.append(('docker', list(argv)))
        if argv[:2] == ['docker', 'exec'] and 'psql' in argv:
            if not self.db_readable or (self.up_done and not self.fp_after_readable):
                return 1, '', 'Error response from daemon: No such container'
            sql = argv[-1]
            if 'pg_database_size' in sql:
                return 0, f'{self.size}\n', ''
            if 'md5(' in sql:
                return 0, self.schema + '\n', ''
            if '__drizzle_migrations' in sql:
                return 0, self.mig + '\n', ''
        return 0, '', ''

    def compose_run(self, cloudtak_dir, args, timeout=600):
        self.calls.append(('compose', list(args)))
        if args[:2] == ['up', '-d']:
            return self._up()
        return 0, ''

    def _up(self):
        self.up_done = True
        if self.migrates:
            self.schema, self.mig = SCHEMA_NEW, '241'
        return (0, '') if self.up_ok else (1, 'Error: port is already allocated')

    def ssh_probe(self, host_cfg, cmd='echo ok', timeout=15):
        assert host_cfg == REMOTE
        self.ssh.append(cmd)
        if 'git rev-parse HEAD' in cmd:
            return True, 'c' * 40
        if 'df -Pk' in cmd:
            return True, str(self.free // 1024)
        if 'pg_dump' in cmd:
            if self.dump_error:
                return False, self.dump_error
            self.dumps.append(cmd)
            return True, ''
        if cmd.endswith(' up -d'):
            return (self._up()[0] == 0), 'Error: port is already allocated'
        if '.docker-store' in cmd:
            return False, ''
        return True, ''

    def pg_dump_priv(self, container, dest_path, timeout=3600):
        assert container == 'cloudtak-postgis-1'
        if self.dump_error:
            raise RuntimeError(self.dump_error)
        self.dumps.append(dest_path)
        return 1234, 'f' * 64

    def rollback(self, *a, **k):
        self.calls.append(('rollback', None))
        return True

    def watch(self, *a, **k):
        self.calls.append(('watch', None))
        return (True, '') if self.watch_ok else (False, 'the CloudTAK API is restarting.')


class _Proc:
    returncode = 0

    def __init__(self, *a, **k):
        self.stdout = io.StringIO('')

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


def _noop(*a, **k):
    return None


class _Globals(dict):
    """Globals for the cut-out function: any app.py name nobody stubbed is a no-op, builtins stay builtins."""

    def __missing__(self, key):
        if hasattr(builtins, key):
            raise KeyError(key)
        return _noop


def _run_update(tmp_path, monkeypatch, **kw):
    box = _Box(tmp_path, **kw)
    home = tmp_path / 'home'
    (home / 'CloudTAK' / '.git').mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv('HOME', str(home))
    fn = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name in _REAL)
    parts = []
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _REAL:
            parts.append(ast.get_source_segment(APP, node))
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and (t.id.startswith('_CT_DB') or t.id.startswith('_CT_UPDATE_DUMP')
                                             or t.id in _CONSTS) for t in node.targets):
            parts.append(ast.get_source_segment(APP, node))
    names = {n.name for n in TREE.body if isinstance(n, ast.FunctionDef)}
    assert _REAL <= names, 'a function under test was renamed or removed'
    top = {n.name for n in TREE.body if isinstance(n, ast.FunctionDef)}

    def _settings():
        return box.settings

    def _save(s):
        box.settings = s

    class _Sub:
        TimeoutExpired = TimeoutError
        PIPE, STDOUT, DEVNULL = -1, -2, -3
        Popen = _Proc

        @staticmethod
        def run(argv, **k):
            box.calls.append(('run', list(argv) if isinstance(argv, list) else argv))
            out = 'c' * 40 if isinstance(argv, list) and 'rev-parse' in argv else ''
            return type('R', (), {'returncode': 0, 'stdout': out, 'stderr': ''})()

    ns = _Globals()
    base = {
        'os': os, 're': re, 'shlex': shlex, 'threading': threading, 'deque': collections.deque,
        'datetime': datetime.datetime, 'subprocess': _Sub,
        'time': type('T', (), {'sleep': staticmethod(lambda s: None), 'time': staticmethod(_real_time.time)}),
        'cloudtak_deploy_log': box.log, 'cloudtak_deploy_status': box.status,
        'load_settings': _settings, 'save_settings': _save,
        'STACK_BACKUP_DIR': '/var/lib/infratak-backups',
        '_get_cloudtak_deployment_config': lambda s: ({'target_mode': 'remote', 'remote': REMOTE}
                                                     if box.remote else {'target_mode': 'local'}),
        '_get_cloudtak_target_release_tag': lambda *a, **k: 'v14.1.1',
        '_cloudtak_running_version': lambda *a, **k: '13.140.0',
        '_cloudtak_update_space_problem': lambda *a, **k: None,
        '_cloudtak_update_space_lines': lambda p: [],
        '_cloudtak_needs_minio_hop': lambda t: False,
        '_cloudtak_carry_plugins': lambda *a, **k: [],
        '_cloudtak_plugins_dir': lambda d: os.path.join(d, 'app', 'plugins'),
        '_cloudtak_server_routes_dir': lambda d: os.path.join(d, 'api', 'routes'),
        'CLOUDTAK_PLUGINS': [],
        '_run_cloudtak_prebuild_hooks': lambda *a, **k: (True, ''),
        '_cloudtak_api_plugin_preflight': lambda *a, **k: True,
        '_cloudtak_prefetch_build_data': lambda *a, **k: (True, False, ''),
        '_cloudtak_snapshot_images': lambda *a, **k: [('cloudtak-api', 'sha256:' + 'a' * 64)],
        '_cloudtak_build_failure_hint': lambda *a, **k: [],
        '_cloudtak_compose_is_garage': lambda d: False,
        '_cloudtak_remote_compose_is_garage': lambda c: False,
        '_cloudtak_remote_legacy_image': lambda c: '',
        '_cloudtak_remote_custom_compose_sh': lambda: 'true',
        '_compose_cmd': lambda remote_cfg=None: 'docker compose',
        '_cloudtak_compose_run': box.compose_run,
        '_cloudtak_docker': box.docker,
        '_ssh_probe': box.ssh_probe,
        '_sudo_wrap': lambda a: a,
        '_update_error_line': lambda t: (t or '').strip().splitlines()[-1] if t else '',
        '_stack_backup_free_bytes': lambda: box.free,
        '_stack_pg_dump_priv': box.pg_dump_priv,
        '_cloudtak_api_stability_watch': box.watch,
        '_cloudtak_rollback_after_failed_up': box.rollback,
        '_cloudtak_restore_images': lambda *a, **k: box.calls.append(('restore_images', None)) or True,
        '_cloudtak_revert_checkout': lambda *a, **k: box.calls.append(('revert_checkout', None)),
        '_cloudtak_drop_rollback_pins': lambda *a, **k: box.calls.append(('drop_pins', None)),
        '_cloudtak_remote_garage_rollback': _noop,
        '_cloudtak_hooks_dir': lambda: str(tmp_path / 'no-hooks'),
        '_remote_cloudtak_port_guard': lambda *a, **k: (True, ''),
        '_CLOUDTAK_REMOTE_MEDIA_PERL': 'true',
        '_CLOUDTAK_REMOTE_TILES_LIVE_PERL': 'true',
    }
    for t in top:
        if t not in _REAL:
            ns.setdefault(t, _noop)
    ns.update(base)
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    box.ns = ns
    ns['run_cloudtak_update']()
    return box


def _text(box):
    return '\n'.join(box.log)


def _did(box, what):
    return any(c[0] == what for c in box.calls)


def _compose_up(box):
    return [c for c in box.calls if c[0] == 'compose' and c[1][:2] == ['up', '-d']]


@pytest.fixture(autouse=True)
def _guard(monkeypatch):
    # a stray real sleep or a real subprocess must not leak out of these tests
    # shared-sleep-ok: a no-op that records nothing, so another thread's sleep cannot land in any list (ops #1444)
    monkeypatch.setattr(_real_time, 'sleep', lambda s: None)


# --------------------------------------------------------------------------- #
# the proof: a failure AFTER the new api changed the database is not rolled back
# --------------------------------------------------------------------------- #

def test_local_watch_fails_after_the_database_moved_no_rollback_and_the_copy_is_named(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, migrates=True, watch_ok=False)
    t = _text(b)
    assert not _did(b, 'rollback'), t
    assert not _did(b, 'revert_checkout'), t           # the new tree stays: the old code cannot use the data
    m = DUMP_RE.search(t)
    assert m and m.group(0) == b.dumps[0]
    assert 'already upgraded its database' in t and 'press Update again' in t
    assert 'the update was undone' not in t and 'nothing was lost' not in t
    assert b.status['error'] is True and b.status['complete'] is False
    assert _did(b, 'drop_pins')


def test_local_up_fails_after_the_database_moved_no_rollback(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, migrates=True, up_ok=False)
    t = _text(b)
    assert not _did(b, 'rollback'), t
    assert 'already upgraded its database' in t and DUMP_RE.search(t)
    assert 'port is already allocated' in t
    assert b.status['error'] is True


def test_remote_watch_fails_after_the_database_moved_no_rollback(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, remote=True, migrates=True, watch_ok=False)
    t = _text(b)
    assert not _did(b, 'rollback'), t
    assert '~/CloudTAK-update-dumps/cloudtak-' in t and 'on the CloudTAK host' in t
    assert 'already upgraded its database' in t
    assert len(b.dumps) == 1 and 'docker exec cloudtak-postgis-1 pg_dump -U docker -Fc gis' in b.dumps[0]
    assert 'umask 077' in b.dumps[0] and 'chmod 700' in b.dumps[0]


def test_remote_up_fails_after_the_database_moved_no_rollback(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, remote=True, migrates=True, up_ok=False)
    assert not _did(b, 'rollback'), _text(b)
    assert 'already upgraded its database' in _text(b)


# --------------------------------------------------------------------------- #
# no regression: a failure that changed nothing is still undone
# --------------------------------------------------------------------------- #

def test_local_watch_fails_with_the_database_unchanged_still_rolls_back(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, migrates=False, watch_ok=False)
    assert _did(b, 'rollback'), _text(b)
    assert 'already upgraded its database' not in _text(b)
    assert b.dumps                                   # the copy was still made first


def test_local_up_fails_with_the_database_unchanged_still_rolls_back(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, migrates=False, up_ok=False)
    assert _did(b, 'rollback'), _text(b)
    assert 'already upgraded its database' not in _text(b)


def test_remote_failures_with_the_database_unchanged_still_roll_back(tmp_path, monkeypatch):
    assert _did(_run_update(tmp_path, monkeypatch, remote=True, migrates=False, watch_ok=False), 'rollback')
    assert _did(_run_update(tmp_path, monkeypatch, remote=True, migrates=False, up_ok=False), 'rollback')


def test_a_good_update_makes_the_copy_and_finishes(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, migrates=True)
    t = _text(b)
    assert b.status['complete'] is True and b.status['error'] is False, t
    assert 'Copied CloudTAK\'s database to' in t and 'already upgraded' not in t
    assert not _did(b, 'rollback')


def test_the_copy_is_taken_after_the_build_and_before_up(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, migrates=False)
    order = [c[0] for c in b.calls]
    assert b.dumps and _compose_up(b)
    # the first psql (fingerprint) precedes the up -d call
    first_psql = next(i for i, c in enumerate(b.calls) if c[0] == 'docker' and 'psql' in c[1])
    assert first_psql < b.calls.index(_compose_up(b)[0])


# --------------------------------------------------------------------------- #
# the copy cannot be made
# --------------------------------------------------------------------------- #

def test_a_real_dump_failure_stops_before_anything_is_restarted(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, dump_error='pg_dump in cloudtak-postgis-1 failed: out of space')
    t = _text(b)
    assert not _compose_up(b), t
    assert 'Update stopped before restarting' in t and 'out of space' in t
    assert _did(b, 'revert_checkout') and _did(b, 'restore_images')
    assert 'nothing was changed' in t and b.status['error'] is True


def test_not_enough_free_disk_stops_the_update_with_numbers(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, free=100 * 1024 ** 2, size=5 * 1024 ** 3)
    t = _text(b)
    assert not _compose_up(b) and not b.dumps
    assert 'not enough free disk space' in t and 'MB free' in t


def test_remote_dump_failure_stops_the_update(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, remote=True, dump_error='no space left on device')
    t = _text(b)
    assert not [c for c in b.ssh if c.endswith(' up -d')]
    assert 'Update stopped before restarting' in t and _did(b, 'revert_checkout')


def test_an_older_root_helper_without_the_dump_op_does_not_lock_the_update(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, dump_error='broker stack_pg_dump failed (cloudtak-postgis-1): unknown op',
                    migrates=False)
    t = _text(b)
    assert b.status['complete'] is True, t
    assert 'No database copy was made' in t


def test_an_older_root_helper_still_gets_the_no_rollback_guard(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, dump_error='broker stack_pg_dump failed (x): unknown op',
                    migrates=True, watch_ok=False)
    t = _text(b)
    assert not _did(b, 'rollback'), t
    assert 'already upgraded its database' in t and 'A copy of the database' not in t


def test_database_container_missing_goes_on_with_the_old_rules(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, db_readable=False, watch_ok=False)
    t = _text(b)
    assert _did(b, 'rollback'), t                      # nothing to compare against: the old behaviour
    assert 'No database copy was made' in t and not b.dumps


def test_unreadable_database_after_the_failure_rolls_back_the_old_way_and_says_so(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, migrates=True, watch_ok=False, fp_after_readable=False)
    t = _text(b)
    assert _did(b, 'rollback')
    assert 'Could not check whether the new CloudTAK changed its database' in t


# --------------------------------------------------------------------------- #
# the helpers on their own
# --------------------------------------------------------------------------- #

def test_fingerprint_changes_with_schema_or_migration_count(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, migrates=False)
    fp = b.ns['_cloudtak_db_fingerprint']
    base = fp()
    assert base == f'{SCHEMA_OLD}:240'
    b.mig = '241'
    assert fp() != base
    b.mig = '240'
    b.schema = SCHEMA_NEW
    assert fp() != base


def test_fingerprint_without_a_migrations_table_uses_the_schema_alone(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, migrates=False)
    orig = b.docker

    def docker(argv, remote_cfg=None, timeout=60):
        if '__drizzle_migrations' in argv[-1]:
            return 1, '', 'ERROR:  relation "drizzle.__drizzle_migrations" does not exist'
        return orig(argv, remote_cfg, timeout)
    b.ns['_cloudtak_docker'] = docker
    assert b.ns['_cloudtak_db_fingerprint']() == f'{SCHEMA_OLD}:-'


def test_fingerprint_is_empty_when_psql_fails_for_another_reason(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, migrates=False)
    b.ns['_cloudtak_docker'] = lambda argv, remote_cfg=None, timeout=60: (1, '', 'connection refused')
    assert b.ns['_cloudtak_db_fingerprint']() == ''


def test_only_the_two_newest_local_copies_are_kept(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, migrates=False)
    removed = []
    b.ns['subprocess'] = type('S', (), {'run': staticmethod(
        lambda argv, **k: removed.append(argv) or type('R', (), {'returncode': 0, 'stdout': '', 'stderr': ''})())})
    b.settings['cloudtak_update_dumps'] = [
        {'label': f'cloudtak-update-2026112{i}-010101', 'created': f'2026-11-2{i}T01:01:01Z'} for i in range(1, 6)]
    b.ns['_cloudtak_update_dumps_prune_local']()
    assert [a[-1] for a in removed] == [f'/var/lib/infratak-backups/cloudtak-update-2026112{i}-010101'
                                        for i in (3, 2, 1)]
    assert sorted(x['label'] for x in b.settings['cloudtak_update_dumps']) == [
        'cloudtak-update-20261124-010101', 'cloudtak-update-20261125-010101']


def test_prune_never_touches_a_label_that_is_not_ours(tmp_path, monkeypatch):
    b = _run_update(tmp_path, monkeypatch, migrates=False)
    removed = []
    b.ns['subprocess'] = type('S', (), {'run': staticmethod(
        lambda argv, **k: removed.append(argv) or type('R', (), {'returncode': 0, 'stdout': '', 'stderr': ''})())})
    b.settings['cloudtak_update_dumps'] = [
        {'label': 'stack-20260101-000000', 'created': '2026-01-01T00:00:00Z'},
        {'label': '../etc', 'created': '2025-01-01T00:00:00Z'},
        {'label': 'cloudtak-update-20261125-000000', 'created': '2026-11-25T00:00:00Z'},
        {'label': 'cloudtak-update-20261126-000000', 'created': '2026-11-26T00:00:00Z'},
        {'label': 'cloudtak-update-20261120-000000', 'created': '2026-11-20T00:00:00Z'}]
    b.ns['_cloudtak_update_dumps_prune_local']()
    assert [a[-1] for a in removed] == ['/var/lib/infratak-backups/cloudtak-update-20261120-000000']


def test_moved_lines_say_what_to_do_in_plain_words():
    ns = {}
    fn = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == '_cloudtak_update_db_moved_lines')
    exec(compile(ast.Module(body=[fn], type_ignores=[]), 'app.py', 'exec'), ns)
    text = '\n'.join(ns['_cloudtak_update_db_moved_lines']({'path': '/x/cloudtak.pgdump', 'remote': False}))
    assert 'Not rolling back' in text and '/x/cloudtak.pgdump' in text and 'press Update again' in text
    assert 'on the CloudTAK host' not in text
    remote = '\n'.join(ns['_cloudtak_update_db_moved_lines']({'path': '~/d/f.pgdump', 'remote': True}))
    assert 'on the CloudTAK host' in remote
    nopath = '\n'.join(ns['_cloudtak_update_db_moved_lines']({'path': ''}))
    assert 'A copy of the database' not in nopath and 'press Update again' in nopath


# --------------------------------------------------------------------------- #
# wiring: where run_cloudtak_update calls the guard
# --------------------------------------------------------------------------- #

def _update_body():
    body = APP[APP.index('def run_cloudtak_update('):]
    return re.sub(r'#.*', '', body[:body.index('\ndef ', 1)])


def test_guard_runs_after_the_build_and_before_the_store_step_in_both_branches():
    b = _update_body()
    assert b.count('_cloudtak_update_db_guard(') == 2
    r_build = b.index('build_cmd = f"cd ~/CloudTAK')
    r_guard = b.index('_cloudtak_update_db_guard(plog, remote_cfg=remote_cfg)')
    r_up = b.index('{dcc} up -d')
    assert r_build < r_guard < r_up
    l_build = b.index("f'{dcc} build --no-cache'")
    l_guard = b.index('_cloudtak_update_db_guard(plog)')
    l_up = b.index("_cloudtak_compose_run(cloudtak_dir, ['up', '-d'], timeout=1800)")
    assert l_build < l_guard < l_up


def test_every_failure_after_up_asks_the_database_before_rolling_back():
    b = _update_body()
    assert b.count('elif _cloudtak_update_db_moved(') == 3
    for m in re.finditer(r'elif _cloudtak_update_db_moved\(', b):
        tail = b[m.end():m.end() + 900]
        assert '_cloudtak_update_db_moved_lines(_db_guard)' in tail
        assert '_cloudtak_rollback_after_failed_up' not in tail[:tail.index('_cloudtak_update_db_moved_lines')]


def test_the_schema_fingerprint_reads_base_tables_only():
    # ops #1325: verified against a real PostGIS 17 (new chat tables made, old ones dropped, a column added:
    # three different fingerprints; no change: the same one). Views belong to extensions (PostGIS upgrades
    # change them), so only base tables count.
    node = next(n for n in TREE.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == '_CT_DB_SCHEMA_SQL' for t in n.targets))
    sql = ''.join(c.value for c in ast.walk(node.value) if isinstance(c, ast.Constant) and isinstance(c.value, str))
    assert "t.table_type = 'BASE TABLE'" in sql
    assert 'information_schema.columns' in sql and "'pg_catalog'" in sql
