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
"""Operator pre-build hooks for CloudTAK (#150).

CloudTAK Update's `git checkout -f <tag>` wipes any local edit to the source, so an
operator carrying one (a video-service.ts fix) lost it on every Update. Scripts in
.config/cloudtak-hooks/pre-build.d/ run right before every CloudTAK build; a failing,
hung or untrusted one stops the build so the old containers keep serving.
"""

import ast
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _body(name):
    return ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name))


def _load(config_dir, timeout=300):
    src = ''.join(_body(n) + '\n\n' for n in
                  ('_cloudtak_hooks_dir', '_cloudtak_hook_untrusted', '_run_cloudtak_prebuild_hooks'))
    ns = {'os': os, 're': re, 'subprocess': subprocess, 'tempfile': tempfile, '_stat': stat,
          'CONFIG_DIR': str(config_dir), '_CLOUDTAK_HOOK_TIMEOUT': timeout,
          '_CLOUDTAK_HOOK_NAME_RE': re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*')}
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns


def _setup(tmp_path):
    cfg = tmp_path / 'config'
    hooks = cfg / 'cloudtak-hooks' / 'pre-build.d'
    hooks.mkdir(parents=True)
    for d in (cfg, hooks.parent, hooks):
        d.chmod(0o700)
    ct = tmp_path / 'CloudTAK'
    ct.mkdir()
    return cfg, hooks, ct


def _hook(hooks, name, body, mode=0o700):
    p = hooks / name
    p.write_text('#!/bin/sh\n' + body + '\n')
    p.chmod(mode)
    return p


def _run(ns, ct, phase='update', **kw):
    log = []
    ok, name = ns['_run_cloudtak_prebuild_hooks'](str(ct), phase, log.append, **kw)
    return ok, name, log


def test_no_folder_is_a_noop(tmp_path):
    ns = _load(tmp_path / 'config')
    ok, name, log = _run(ns, tmp_path)
    assert (ok, name) == (True, '')
    assert log == ['  no pre-build hooks']


def test_hooks_run_in_name_order_in_the_checkout_with_env(tmp_path):
    cfg, hooks, ct = _setup(tmp_path)
    _hook(hooks, '20-second', 'echo "2 $INFRATAK_HOOK_PHASE" >> order')
    _hook(hooks, '10-first', 'echo "1 $INFRATAK_CLOUDTAK_TAG $INFRATAK_CLOUDTAK_PREV_SHA" >> order')
    _hook(hooks, '30-off', 'echo 3 >> order', mode=0o600)       # chmod -x disables it
    _hook(hooks, '.hidden', 'echo h >> order')
    _hook(hooks, '40-backup~', 'echo b >> order')
    ok, name, log = _run(_load(cfg), ct, tag='v13.109.0', prev_sha='abc')
    assert (ok, name) == (True, '')
    assert (ct / 'order').read_text() == '1 v13.109.0 abc\n2 update\n'
    assert '  skipped pre-build hook 30-off (not executable)' in log
    assert log[-1] == '  ran 2 pre-build hook(s)'


def test_console_secrets_in_env_do_not_reach_hooks(tmp_path, monkeypatch):
    cfg, hooks, ct = _setup(tmp_path)
    monkeypatch.setenv('SOME_SECRET', 'x')
    _hook(hooks, '10-env', 'env > envdump')
    assert _run(_load(cfg), ct)[0]
    dump = (ct / 'envdump').read_text()
    assert 'SOME_SECRET' not in dump and 'INFRATAK_CLOUDTAK_DIR=' + str(ct) in dump


def test_failing_hook_stops_and_names_itself(tmp_path):
    cfg, hooks, ct = _setup(tmp_path)
    _hook(hooks, '10-patch', 'echo "anchor not found in video-service.ts"; exit 3')
    _hook(hooks, '20-later', 'touch later')
    ok, name, log = _run(_load(cfg), ct)
    assert (ok, name) == (False, '10-patch')
    assert '    │ anchor not found in video-service.ts' in log
    assert '✗ Pre-build hook 10-patch failed (exit 3)' in log
    assert not (ct / 'later').exists()


def test_hung_hook_is_killed(tmp_path):
    cfg, hooks, ct = _setup(tmp_path)
    _hook(hooks, '10-hang', '(sleep 60) & sleep 60')
    t0 = time.monotonic()
    ok, name, log = _run(_load(cfg, timeout=1), ct)
    assert time.monotonic() - t0 < 15
    assert (ok, name) == (False, '10-hang')
    assert any('timed out' in l for l in log)


def test_background_child_of_a_passing_hook_does_not_outlive_it(tmp_path):
    cfg, hooks, ct = _setup(tmp_path)
    _hook(hooks, '10-bg', '(sleep 2; touch late) > /dev/null 2>&1 &\nexit 0')
    assert _run(_load(cfg), ct)[0]
    time.sleep(3)
    assert not (ct / 'late').exists()


def test_unreadable_folder_fails_closed_instead_of_raising(tmp_path):
    cfg, hooks, ct = _setup(tmp_path)
    _hook(hooks, '10-ok', 'touch ran')
    hooks.chmod(0o000)
    try:
        if os.access(hooks, os.R_OK):   # root ignores the mode
            return
        ok, name, log = _run(_load(cfg), ct)
    finally:
        hooks.chmod(0o700)
    assert ok is False
    assert not (ct / 'ran').exists()


def test_group_writable_hook_is_refused_not_run(tmp_path):
    cfg, hooks, ct = _setup(tmp_path)
    _hook(hooks, '10-open', 'touch ran', mode=0o772)
    ok, name, log = _run(_load(cfg), ct)
    assert (ok, name) == (False, '10-open')
    assert not (ct / 'ran').exists()
    assert any('writable by group or others' in l for l in log)


def test_world_writable_folder_is_refused(tmp_path):
    cfg, hooks, ct = _setup(tmp_path)
    _hook(hooks, '10-ok', 'touch ran')
    hooks.chmod(0o777)
    ok, name, log = _run(_load(cfg), ct)
    assert (ok, name) == (False, str(hooks))
    assert not (ct / 'ran').exists()


def test_symlinked_hook_is_refused(tmp_path):
    cfg, hooks, ct = _setup(tmp_path)
    target = _hook(tmp_path, 'elsewhere', 'touch ran')
    (hooks / '10-link').symlink_to(target)
    ok, name, log = _run(_load(cfg), ct)
    assert (ok, name) == (False, '10-link')
    assert not (ct / 'ran').exists()


def test_symlinked_folder_is_refused(tmp_path):
    cfg, hooks, ct = _setup(tmp_path)
    real = tmp_path / 'real'
    real.mkdir(mode=0o700)
    _hook(real, '10-ok', 'touch ran')
    hooks.rmdir()
    hooks.symlink_to(real)
    ok, name, log = _run(_load(cfg), ct)
    assert ok is False
    assert not (ct / 'ran').exists()


# ── wiring ──

def test_update_runs_hooks_after_our_patches_and_before_the_build():
    body = _body('run_cloudtak_update')
    i_hooks = body.index("_run_cloudtak_prebuild_hooks(cloudtak_dir, 'update'")
    assert body.index('_patch_cloudtak_compose_ports(cloudtak_dir)') < i_hooks
    assert i_hooks < body.index("f'{dcc} build --no-cache'")
    # a failed hook reverts the tree and stops before anything is rebuilt
    tail = body[i_hooks:body.index('Step 3/3')]
    assert '_cloudtak_revert_checkout(prev_sha, plog, cloudtak_dir=cloudtak_dir)' in tail
    assert '_undo_plugin_moves()' in tail and 'return' in tail


def test_plugin_rebuild_runs_hooks_before_the_api_build_and_rolls_back_on_failure():
    body = _body('_run_cloudtak_plugin_action')
    i_hooks = body.index("_run_cloudtak_prebuild_hooks(ct_dir, 'plugin', plog)")
    i_build = body.index("['docker', 'compose', 'build', '--no-cache', 'api']")
    assert i_hooks < i_build
    assert '_rollback_cloudtak_plugin_state(ct_dir, install_path, snap, plog)' in body[i_hooks:i_build]


def test_revert_reapplies_hooks_locally_only():
    body = _body('_cloudtak_revert_checkout')
    i = body.index('_cloudtak_revert_hooks(cloudtak_dir, prev_sha, plog)')
    assert 'if remote_cfg is None and run_hooks:' in body[:i]
    assert "_run_cloudtak_prebuild_hooks(cloudtak_dir, 'revert'" in _body('_cloudtak_revert_hooks')


def test_garage_rollback_runs_hooks_only_after_cloudtak_is_restarted():
    # The migration stopped the app containers; a 5-minute hook must not extend that outage.
    body = _body('_cloudtak_garage_rollback')
    assert 'run_hooks=False' in body
    assert body.index("['start', 'api', 'events', 'tiles', 'retention']") < \
        body.index('_cloudtak_revert_hooks(cloudtak_dir, prev_sha, plog)')
