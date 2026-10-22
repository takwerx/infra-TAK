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
"""EVERY local Authentik `docker compose` call takes the compose lock (ops #178).

ops #173 locked the console's Start/Stop/Restart/Update/Reconfigure. The other callers
(first Deploy, post-update auto-deploy, LDAP repairs, pgbouncer/gunicorn/pg-tuning
helpers, compose-heal, uninstall) still ran unlocked and could race Guard Dog's watcher
the same way, leaving stray `<hash>_authentik-server-1` containers.

The wiring test below is whole-file: any NEW unlocked Authentik compose call fails it.
"""

import ast
import fcntl
import os
import re
import subprocess
import threading
import types

import pytest

from test_authentik_compose_lock_paths import APP, FUNCS, TREE, _locked_spans, console  # noqa: F401

_MUTATING = {'up', 'down', 'restart', 'stop', 'start', 'rm', 'pull', 'kill', 'create'}
_REMOTE_ONLY = {'_run_authentik_deploy_remote', '_run_authentik_reconfigure_remote',
                '_configure_authentik_smtp_and_recovery_remote'}
_TOP = [n for n in TREE.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _owner(lineno):
    return next(f for f in _TOP if f.lineno <= lineno <= f.end_lineno)


def _is_compose_list(node):
    return (isinstance(node, ast.List) and len(node.elts) >= 3
            and all(isinstance(e, ast.Constant) for e in node.elts[:3])
            and [e.value for e in node.elts[:2]] == ['docker', 'compose']
            and node.elts[2].value in _MUTATING)


def _authentik_compose_lists():
    """(lineno, function) of every mutating compose argv run with cwd= the Authentik dir."""
    out = set()
    for call in ast.walk(TREE):
        if not isinstance(call, ast.Call):
            continue
        cwd = next((k.value for k in call.keywords if k.arg == 'cwd'), None)
        if cwd is None:
            continue
        cwd_src = ast.get_source_segment(APP, cwd)
        if not (cwd_src == 'ak_dir' or '~/authentik' in cwd_src):
            continue
        for node in ast.walk(call):
            if _is_compose_list(node):
                out.add((node.lineno, _owner(node.lineno).name))
    return sorted(out)


def test_every_local_authentik_compose_call_is_locked():
    found = _authentik_compose_lists()
    names = {f for _, f in found}
    # Not vacuous: the callers this issue is about are all seen.
    for fn in ('run_authentik_deploy', '_post_update_auto_deploy', '_ensure_authentik_pgbouncer',
               '_ensure_authentik_pgbouncer_pool_size', '_apply_authentik_ldap_routing_repair',
               '_ensure_authentik_ldap_outpost_on_fqdn', '_ensure_authentik_gunicorn_timeout',
               '_authentik_fix_pg_idle_timeout', '_repair_ldap_outpost_token',
               '_ensure_authentik_ldap_service_account', '_ensure_authentik_webadmin',
               'takserver_connect_ldap', '_startup_migrations', '_startup_authentik_idle_load_converge',
               'authentik_compose_heal', 'authentik_uninstall', 'run_full_uninstall'):
        assert fn in names, fn
    assert len(found) >= 45
    bad = ['%s:%d' % (fn, ln) for ln, fn in found
           if not any(a <= ln <= b for a, b in _locked_spans(FUNCS[fn]))]
    assert bad == [], 'unlocked Authentik compose call(s): %s' % bad


def test_no_local_authentik_compose_string_through_plain_module_run():
    # `_module_run(ak_cfg, 'cd ~/authentik && docker compose up …')` runs on THIS box when
    # Authentik is local; it must go through _ak_module_compose so it is locked there.
    pat = re.compile(r'cd ~/authentik && docker compose (%s)\b' % '|'.join(_MUTATING))
    bad = []
    for call in ast.walk(TREE):
        if (isinstance(call, ast.Call) and getattr(call.func, 'id', '') == '_module_run'
                and len(call.args) >= 2 and isinstance(call.args[1], ast.Constant)
                and isinstance(call.args[1].value, str) and pat.search(call.args[1].value)
                and _owner(call.lineno).name not in _REMOTE_ONLY):
            bad.append('%s:%d' % (_owner(call.lineno).name, call.lineno))
    assert bad == []


def test_multi_step_operations_hold_the_lock_once():
    # A watcher down+up landing BETWEEN two steps is the race, so these hold it across.
    def hold(fn, holder):
        src = ast.get_source_segment(APP, FUNCS[fn])
        i = src.index("_authentik_compose_lock('%s'" % holder)
        return src[i:]
    body = hold('_post_update_auto_deploy', 'post-update-hardening-recreate')
    body = body[:body.index('else:')]
    for piece in ("'worker', 'server'", '_wait_for_authentik_stack_healthy(', "'--no-deps', 'ldap'"):
        assert piece in body
    body = hold('_post_update_auto_deploy', 'post-update-pg-shm-recreate')
    body = body[:body.index('else:')]
    assert "'docker', 'stop', '-t', '30', 'authentik-postgresql-1'" in body
    assert "'up', '-d', 'postgresql'" in body
    body = hold('_authentik_fix_pg_idle_timeout', 'pg-idle-timeout-recreate')
    assert "'--force-recreate', 'postgresql'" in body and "['docker', 'compose', 'up', '-d']" in body
    for fn, holder in (('authentik_uninstall', 'uninstall'), ('run_full_uninstall', 'full-uninstall')):
        body = hold(fn, holder)
        body = body[:body.index("rm -rf {ak_dir}")]
        assert "'down', '-v', '--rmi', 'all'" in body


# ── the helpers ──────────────────────────────────────────────────────────────

def _hold_from_other_thread(lock_path):
    fh = open(lock_path, 'a+')
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fh


def test_subprocess_wrapper_runs_holding_the_lock(console):
    r = console.ns['_ak_compose_subprocess'](['docker', 'compose', 'up', '-d', 'ldap'], 'x', console.plog,
                                             cwd='/ak', text=True)
    assert r.returncode == 0
    assert console.ran == [(['docker', 'compose', 'up', '-d', 'ldap'], '/ak', True)]


def test_subprocess_wrapper_busy_lock_does_not_run_and_fails_like_a_command(console):
    console.lock.write_text('')
    with open(console.lock) as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        r = console.ns['_ak_compose_subprocess'](['docker', 'compose', 'restart'], 'deploy-ldap', console.plog,
                                                 wait=0, cwd='/ak', text=True)
        rb = console.ns['_ak_compose_subprocess'](['docker', 'compose', 'restart'], 'deploy-ldap', console.plog,
                                                  wait=0, cwd='/ak', capture_output=True)
        with pytest.raises(subprocess.CalledProcessError) as ei:
            console.ns['_ak_compose_subprocess'](['docker', 'compose', 'restart'], 'x', console.plog,
                                                 wait=0, check=True)
    assert console.ran == []
    assert r.returncode == 75 and r.stdout.startswith('not run: another Authentik operation held')
    assert 'deploy-ldap' in r.stdout and r.stderr == r.stdout
    assert isinstance(rb.stdout, bytes)               # same type the caller asked for
    assert ei.value.returncode == 75
    assert any('NOT acquired' in m for m in console.logged)


def test_lock_is_reentrant_on_the_same_thread(console):
    lock = console.ns['_authentik_compose_lock']
    with lock('outer', plog=console.plog) as a:
        with lock('inner', plog=console.plog, timeout=0) as b:
            assert a is True and b is True
            assert console.held()
        assert console.held()                         # inner exit did not release it
    assert not console.held()
    assert not any('waiting' in m or 'NOT acquired' in m for m in console.logged)


def test_reentrancy_does_not_leak_to_other_threads(console):
    lock = console.ns['_authentik_compose_lock']
    got = []
    def other():
        with lock('other-thread', plog=console.plog, timeout=0) as ok:
            got.append(ok)
    with lock('outer', plog=console.plog):
        t = threading.Thread(target=other)
        t.start()
        t.join()
    assert got == [False]


def test_depth_resets_after_an_error_inside(console):
    lock = console.ns['_authentik_compose_lock']
    with pytest.raises(RuntimeError):
        with lock('outer', plog=console.plog):
            raise RuntimeError('boom')
    assert console.ns['_AK_COMPOSE_LOCK_HELD'].depth == 0
    fh = _hold_from_other_thread(console.lock)        # released, so another holder can take it
    fh.close()


def test_module_compose_locks_locally_and_leaves_remote_alone(console):
    mc = console.ns['_ak_module_compose']
    assert mc({'target_mode': 'local'}, 'cd ~/authentik && docker compose up -d ldap', 'x') == (True, '')
    assert mc({'target_mode': 'remote'}, 'cd ~/authentik && docker compose up -d ldap', 'x') == (True, '')
    assert [(m, h) for _, m, h in console.ran] == [('local', True), ('remote', False)]
    console.ran.clear()
    console.lock.write_text('')
    with open(console.lock) as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        ok, msg = mc({}, 'cd ~/authentik && docker compose up -d ldap', 'webadmin', wait=0)
    assert ok is False and msg.startswith('not run:') and console.ran == []


# ── a busy lock must not strand a half-applied change ───────────────────────

def test_skipped_pg_shm_recreate_never_kills_the_live_postgres():
    # The orphan-kill takes "UID-70 postgres PIDs from before the stop that are still there".
    # With the stop skipped that is every live postgres, so it may only run after a real stop.
    src = ast.get_source_segment(APP, FUNCS['_post_update_auto_deploy'])
    i = src.index("_authentik_compose_lock('post-update-pg-shm-recreate')")
    tail = src[i:i + 2500]
    assert 'if _locked and _old_pg_pids:' in tail
    assert tail.index('if _locked and _old_pg_pids:') < tail.index("'kill', '-9'")


@pytest.mark.parametrize('fn', ['_apply_authentik_ldap_routing_repair', '_ensure_authentik_ldap_outpost_on_fqdn'])
def test_busy_lock_on_an_ldap_move_is_not_a_failed_move(fn):
    # Not run is not failed: no rollback recreate (an LDAP outage for nothing) and no
    # failure record / back-off. Just put the compose back and return.
    src = ast.get_source_segment(APP, FUNCS[fn])
    busy = src.index('if _r.returncode == _AK_COMPOSE_LOCK_BUSY_RC:')
    failed = src.index('if _r.returncode != 0:', busy)
    branch = src[busy:failed]
    assert '_f.write(compose_text)' in branch and 'return' in branch
    assert '_ak_compose_subprocess' not in branch and '_failed(' not in branch and '_attempt(' not in branch


@pytest.mark.parametrize('fn, restore', [
    ('_repair_ldap_outpost_token', '_f.write(compose_text)'),
    ('takserver_connect_ldap', 'f.write(_bp_orig)'),
    ('_ensure_authentik_pgbouncer_pool_size', 'f.write(raw)'),
])
def test_busy_lock_puts_the_edited_file_back(fn, restore):
    src = ast.get_source_segment(APP, FUNCS[fn])
    busy = src.index('_AK_COMPOSE_LOCK_BUSY_RC:')
    assert restore in src[busy:busy + 700]


def test_pgbouncer_install_rollback_skips_rm_when_nothing_started():
    src = ast.get_source_segment(APP, FUNCS['_ensure_authentik_pgbouncer'])
    assert "_rollback_compose_env('pull-failed', started=_pull_r.returncode != _AK_COMPOSE_LOCK_BUSY_RC)" in src
    assert "_rollback_compose_env('up-failed', started=r.returncode != _AK_COMPOSE_LOCK_BUSY_RC)" in src


def test_no_long_lock_wait_on_paths_that_run_during_console_import():
    # _startup_migrations() runs synchronously at import; a 420 s wait there holds the
    # console down. Its own compose calls and these helpers it calls keep the default.
    for fn in ('_startup_migrations', '_ensure_authentik_pgbouncer', '_apply_authentik_ldap_routing_repair',
               '_ensure_authentik_ldap_outpost_on_fqdn', '_ensure_authentik_gunicorn_timeout',
               '_authentik_fix_pg_idle_timeout', '_ensure_authentik_pgbouncer_pool_size'):
        assert '_AK_COMPOSE_LOCK_WAIT_LONG_S' not in ast.get_source_segment(APP, FUNCS[fn]), fn

def test_gunicorn_timeout_puts_the_env_back_when_the_lock_is_busy(tmp_path, monkeypatch):
    # The .env line is the idempotency marker: leaving it while the server was never
    # recreated would make every later run skip as "already set".
    ak = tmp_path / 'authentik'
    ak.mkdir()
    (ak / '.env').write_text('PG_PASS=x\n')
    (ak / 'docker-compose.yml').write_text('services: {}\n')
    monkeypatch.setenv('HOME', str(tmp_path))
    logged = []
    busy = subprocess.CompletedProcess([], 75, stdout='not run: busy', stderr='not run: busy')
    ns = {'os': os, 'subprocess': subprocess, '_sudo_wrap': list, '_AK_COMPOSE_LOCK_BUSY_RC': 75,
          '_ak_compose_subprocess': lambda *a, **k: busy}
    exec(compile(ast.get_source_segment(APP, FUNCS['_ensure_authentik_gunicorn_timeout']), 'app.py', 'exec'), ns)
    ns['_ensure_authentik_gunicorn_timeout'](logged.append)
    assert (ak / '.env').read_text() == 'PG_PASS=x\n'
    assert any('.env restored, next run retries' in m for m in logged)
