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
"""Update Now and module installs retry a slow fetch or a dropped pull, and say why (ops #489).

Rocky 9 box, Nov 4 2026: Update Now was refused because `git fetch` hit its fixed 60 s limit
and showed Python's raw "Command [...] timed out after 60 seconds"; the same click worked on
retry. Image pulls ended the install at the first registry hiccup. The helpers are cut out of
app.py and run with git and docker faked.
"""

import pathlib
import re
import subprocess
import time
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _block(start, end):
    return APP[APP.index(start):APP.index(end)]


GIT_SRC = _block('_GIT_FETCH_TIMEOUTS_S = ', "@app.route('/api/update/apply'")
PULL_SRC = _block('_PULL_RETRY_PAUSES_S = ', 'def _run_nodered_deploy_remote(')


def _git_ns():
    n = {'re': re, 'subprocess': subprocess, 'time': time, 'print': lambda *a, **k: None}
    exec(compile(GIT_SRC, 'app.py', 'exec'), n)
    return n


def _r(rc, err=''):
    return types.SimpleNamespace(returncode=rc, stdout='', stderr=err)


def _runner(outcomes):
    calls = []

    def run_git(args, timeout=60, isolated_fetch=False):
        calls.append(timeout)
        o = outcomes[min(len(calls) - 1, len(outcomes) - 1)]
        if o == 'timeout':
            raise subprocess.TimeoutExpired(['git'] + args, timeout)
        return o

    return run_git, calls


def test_timeout_then_success_retries_with_longer_limit():
    n = _git_ns()
    run, calls = _runner(['timeout', _r(0)])
    r = n['_git_fetch_retry'](run, ['fetch', 'origin'], sleep=lambda s: None)
    assert r.returncode == 0
    assert calls == [90, 120]  # was one 60 s try, then a refusal


def test_three_timeouts_give_a_plain_message_not_python_text():
    n = _git_ns()
    run, calls = _runner(['timeout'])
    r = n['_git_fetch_retry'](run, ['fetch', 'origin'], sleep=lambda s: None)
    assert calls == [90, 120, 150]
    assert r.returncode != 0
    assert 'GitHub did not answer in time' in r.stderr and 'Click Update Now again' in r.stderr
    assert 'Command' not in r.stderr and 'timed out after' not in r.stderr


def test_network_error_is_retried_but_other_errors_are_not():
    n = _git_ns()
    run, calls = _runner([_r(128, 'fatal: unable to access: Could not resolve host: github.com'), _r(0)])
    assert n['_git_fetch_retry'](run, ['fetch'], sleep=lambda s: None).returncode == 0
    assert len(calls) == 2
    run, calls = _runner([_r(128, 'fatal: detected dubious ownership in repository')])
    r = n['_git_fetch_retry'](run, ['fetch'], sleep=lambda s: None)
    assert len(calls) == 1 and 'dubious ownership' in r.stderr


def test_update_now_uses_the_retry_for_every_fetch():
    body = _block("@app.route('/api/update/apply'", '# Issue #113: the daily restart')
    assert body.count('_git_fetch_retry(_git,') == 3
    assert "timeout=60, isolated_fetch=True" not in body


def _pull_ns(once_results):
    """Load the wrapper; `_docker_compose_pull_once` is faked to replay once_results."""
    seq = list(once_results)
    n = {'re': re, 'time': time, 'calls': []}

    def once(*a, **k):
        n['calls'].append(1)
        return seq.pop(0) if len(seq) > 1 else seq[0]

    n['_docker_compose_pull_once'] = once
    exec(compile(PULL_SRC, 'app.py', 'exec'), n)
    return n


def test_dropped_pull_is_retried_and_succeeds():
    blob = 'failed to copy: httpReadSeeker: failed open: unexpected status from GET request to https://registry-1.docker.io/v2/x/blobs/sha256:1: 502 Bad Gateway'
    n = _pull_ns([(False, 'failed', [blob]), (True, 'ok', [])])
    logs, naps = [], []
    assert n['_docker_compose_pull'](None, '/tmp', logs.append, sleep=naps.append) is True
    assert len(n['calls']) == 2 and naps == [10]
    assert any('trying again' in m for m in logs)


def test_rate_limit_is_not_retried_and_says_docker_hub_is_limiting():
    err = 'toomanyrequests: You have reached your pull rate limit. You may increase the limit by authenticating'
    n = _pull_ns([(False, 'failed', [err])])
    logs = []
    assert n['_docker_compose_pull'](None, '/tmp', logs.append, sleep=lambda s: None) is False
    assert len(n['calls']) == 1
    assert any('Docker Hub is limiting pulls from this server' in m for m in logs)
    assert any('6 hours' in m for m in logs)


def test_missing_image_and_timeout_are_not_retried():
    n = _pull_ns([(False, 'failed', ['manifest unknown: manifest unknown'])])
    assert n['_docker_compose_pull'](None, '/tmp', lambda m: None, sleep=lambda s: None) is False
    assert len(n['calls']) == 1
    n = _pull_ns([(False, 'timeout', [])])
    assert n['_docker_compose_pull'](None, '/tmp', lambda m: None, sleep=lambda s: None) is False
    assert len(n['calls']) == 1


def test_gives_up_after_three_tries_with_a_reason():
    n = _pull_ns([(False, 'failed', ['read tcp: connection reset by peer'])])
    logs = []
    assert n['_docker_compose_pull'](None, '/tmp', logs.append, sleep=lambda s: None) is False
    assert len(n['calls']) == 3
    assert any('kept dropping' in m for m in logs)
