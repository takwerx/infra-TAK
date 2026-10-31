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
"""Caddy Update waits for the apt lock instead of failing at once (GH #365, ops #381).

Aust-TAK's Caddy Update died at the first step with "Could not get lock" because another
apt run held it. The broker denies `-o DPkg::Lock::Timeout`, so the wait is done in Python.
The helpers are cut out of app.py and run against stubs: the code under test is the shipped text.
"""

import ast
import pathlib
import subprocess
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _load(held, results):
    """held: list of lock states returned in turn (last one repeats). results: apt outcomes in turn."""
    clock = SimpleNamespace(slept=0, runs=[])
    held = list(held)
    results = list(results)

    def lsof_run(cmd, **kw):
        state = held.pop(0) if len(held) > 1 else held[0]
        return subprocess.CompletedProcess(cmd, 0 if state else 1, 'apt 123 root' if state else '', '')

    def chain(cmds, mode='and', timeout=120, **kw):
        clock.runs.append(cmds[0])
        return results.pop(0) if len(results) > 1 else results[0]

    ns = {
        'subprocess': subprocess,
        'time': SimpleNamespace(sleep=lambda s: setattr(clock, 'slept', clock.slept + s)),
        '_sudo_wrap': lambda c: c,
        '_run_priv_chain': chain,
    }
    real_run = subprocess.run
    ns['subprocess'] = SimpleNamespace(run=lsof_run, CompletedProcess=subprocess.CompletedProcess)
    for name in ('_APT_LOCK_FILES', '_APT_LOCK_MSGS', '_apt_lock_held',
                 '_apt_wait_for_lock', '_apt_run_waiting'):
        exec(_segment(name), ns)
    assert subprocess.run is real_run
    return ns, clock


def _cp(rc, out='', err=''):
    return subprocess.CompletedProcess([], rc, out, err)


def test_waits_for_a_busy_lock_then_runs_apt_once():
    ns, clock = _load(held=[True, True, False], results=[_cp(0, 'ok')])
    r = ns['_apt_run_waiting'](['apt-get', 'update', '-qq'])
    assert r.returncode == 0
    assert clock.slept == 10
    assert len(clock.runs) == 1


def test_gives_up_waiting_after_max_wait_but_still_tries_apt():
    ns, clock = _load(held=[True], results=[_cp(0)])
    assert ns['_apt_wait_for_lock'](max_wait=20) is False
    assert clock.slept == 20
    r = ns['_apt_run_waiting'](['apt-get', 'update'], max_wait=10)
    assert r.returncode == 0 and len(clock.runs) == 1


def test_retries_once_when_apt_loses_the_race_for_the_lock():
    lock_err = _cp(100, '', 'E: Could not get lock /var/lib/apt/lists/lock. It is held by process 99')
    ns, clock = _load(held=[False], results=[lock_err, _cp(0, 'done')])
    r = ns['_apt_run_waiting'](['apt-get', 'install', '-y', 'caddy'])
    assert r.returncode == 0 and r.stdout == 'done'
    assert len(clock.runs) == 2


def test_a_real_apt_failure_is_not_retried():
    ns, clock = _load(held=[False], results=[_cp(100, '', 'E: Unable to locate package caddy')])
    r = ns['_apt_run_waiting'](['apt-get', 'install', '-y', 'caddy'])
    assert r.returncode == 100
    assert len(clock.runs) == 1


def test_lock_check_fails_open_when_lsof_is_missing():
    ns, _ = _load(held=[False], results=[_cp(0)])

    def boom(*a, **k):
        raise FileNotFoundError('lsof')
    ns['subprocess'] = SimpleNamespace(run=boom)
    assert ns['_apt_lock_held']() is False


def test_no_dash_o_options_for_the_broker():
    """The non-root broker denies apt-get -o, so none of the new code may use it."""
    body = _segment('_apt_run_waiting') + _segment('_apt_wait_for_lock') + _segment('_apt_lock_held')
    assert "'-o'" not in body and 'Lock::Timeout' not in body


def test_caddy_update_goes_through_the_waiting_helper():
    body = _segment('caddy_update')
    assert "_apt_run_waiting(['apt-get', 'update', '-qq'])" in body
    assert "_apt_run_waiting(['apt-get', 'install', '-y', 'caddy'])" in body
    assert "_run_priv_chain([['apt-get', 'update'" not in body


def test_repo_refresh_and_github_fallback_wait_too():
    assert '_apt_wait_for_lock(log_fn=log_fn)' in _segment('_caddy_ensure_apt_repo')
    assert '_apt_wait_for_lock(log_fn=log_fn)' in _segment('_caddy_install_github_deb')
