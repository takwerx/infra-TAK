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
"""The Caddy deploy no longer stops at a fixed 2-minute apt limit (ops #605).

Two fresh installs of the 10.3.10 candidate on Ubuntu 22.04 stopped at the first apt line of
run_caddy_deploy, `apt-get install -y debian-keyring ...`, which hit `timeout=120`. A pass takes
30 to 40 seconds, so the box or the mirror was slow; a customer on a slow mirror would get the
same stop and no Caddy. Each apt line now waits for the apt lock right before it runs and has a
limit sized for a slow mirror. The wait is done in Python, not with `-o DPkg::Lock::Timeout`,
because the non-root broker denies every `-o` option.
The helpers are cut out of app.py and run against stubs: the code under test is the shipped text.
"""

import ast
import pathlib
import re
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


def _cp(rc, out='', err=''):
    return subprocess.CompletedProcess([], rc, out, err)


def _load(held, outcomes):
    """held: lock states returned in turn (last one repeats). outcomes: results of the shell
    string in turn (last repeats); an Exception instance is raised instead of returned."""
    rec = SimpleNamespace(slept=0, shell=[], logs=[])
    held = list(held)
    outcomes = list(outcomes)

    def fake_run(cmd, **kw):
        if kw.get('shell'):
            rec.shell.append((cmd, kw))
            out = outcomes.pop(0) if len(outcomes) > 1 else outcomes[0]
            if isinstance(out, Exception):
                raise out
            return out
        state = held.pop(0) if len(held) > 1 else held[0]   # the lsof lock probe
        return subprocess.CompletedProcess(cmd, 0 if state else 1, 'apt 123 root' if state else '', '')

    ns = {
        'os': SimpleNamespace(environ={}),
        'subprocess': SimpleNamespace(run=fake_run, CompletedProcess=subprocess.CompletedProcess,
                                      TimeoutExpired=subprocess.TimeoutExpired),
        'time': SimpleNamespace(sleep=lambda s: setattr(rec, 'slept', rec.slept + s)),
        '_sudo_wrap': lambda c: c,
        '_broker_shim_env': lambda base=None: base,
    }
    for name in ('_APT_LOCK_FILES', '_APT_LOCK_MSGS', '_apt_lock_held', '_apt_wait_for_lock',
                 'CADDY_APT_TIMEOUT', 'CADDY_APT_LOCK_WAIT', '_caddy_apt_shell'):
        exec(_segment(name), ns)
    return ns, rec


APT = 'apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl 2>&1'


def test_apt_line_gets_a_slow_mirror_limit_not_120():
    ns, rec = _load(held=[False], outcomes=[_cp(0)])
    assert ns['CADDY_APT_TIMEOUT'] >= 300
    r = ns['_caddy_apt_shell'](APT, rec.logs.append)
    assert r.returncode == 0
    assert rec.shell[0][1]['timeout'] == ns['CADDY_APT_TIMEOUT']


def test_apt_line_waits_for_the_lock_right_before_it_runs_and_says_so():
    ns, rec = _load(held=[True, True, False], outcomes=[_cp(0)])
    r = ns['_caddy_apt_shell'](APT, rec.logs.append)
    assert r.returncode == 0
    assert rec.slept == 10                          # two busy probes, then free
    assert len(rec.shell) == 1
    assert any('waiting' in m.lower() or 'Running' in m for m in rec.logs)


def test_a_timeout_returns_a_failure_with_the_reason_instead_of_raising():
    ns, rec = _load(held=[False], outcomes=[subprocess.TimeoutExpired(APT, 900)])
    r = ns['_caddy_apt_shell'](APT, rec.logs.append)
    assert r.returncode == 124
    assert 'timed out after 900 seconds' in r.stderr


def test_retries_once_when_apt_loses_the_race_for_the_lock():
    lock_err = _cp(100, '', 'E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 99')
    ns, rec = _load(held=[False], outcomes=[lock_err, _cp(0, 'done')])
    r = ns['_caddy_apt_shell']('apt-get install -y caddy 2>&1', rec.logs.append)
    assert r.returncode == 0 and r.stdout == 'done'
    assert len(rec.shell) == 2


def test_a_real_apt_failure_is_not_retried():
    ns, rec = _load(held=[False], outcomes=[_cp(100, '', 'E: Unable to locate package caddy')])
    r = ns['_caddy_apt_shell']('apt-get install -y caddy 2>&1', rec.logs.append)
    assert r.returncode == 100
    assert len(rec.shell) == 1


def test_curl_lines_keep_the_short_limit_and_skip_the_lock_wait():
    ns, rec = _load(held=[True], outcomes=[_cp(0)])
    r = ns['_caddy_apt_shell']('curl -1sLf "https://example.invalid/gpg.key" | gpg --dearmor -o /x 2>&1',
                               rec.logs.append)
    assert r.returncode == 0
    assert rec.shell[0][1]['timeout'] == 120
    assert rec.slept == 0


def test_run_caddy_deploy_has_no_fixed_120_second_apt_line():
    body = _segment('run_caddy_deploy')
    assert '_caddy_apt_shell(' in body
    for m in re.finditer(r'apt-get[^\n]*', body):
        # every apt-get mention is either a plain log/command string or goes through the helper
        assert 'timeout=120' not in m.group(0)
    assert not re.search(r"subprocess\.run\(\s*install_caddy_cmd", body)
    reinstall = body[body.index('--reinstall') - 200: body.index('--reinstall') + 400]
    assert 'timeout=120' not in reinstall and 'CADDY_APT_TIMEOUT' in reinstall
    assert "'-o'" not in body and 'Lock::Timeout' not in body
