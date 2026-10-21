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
"""TAK Portal and Remote Assist rebuild on a fresh base image (ops #135).

`docker compose up -d --build` never pulls: a `node:22-alpine` already on the box is reused,
so Remote Assist on test6 was still on Node 22.23.0 after Docker Hub had 22.23.4. Every Deploy
and Update of both now runs `docker compose build --pull` first. A failed pull falls back to the
cached base (an unreachable registry must not break a build that worked yesterday); a timeout
does not, because the same build without --pull would only time out again.
"""

import pathlib
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
HELPER = APP[APP.index('def _compose_build_pull('):APP.index('def _remote_assist_compose_files(')]


def _ns(result=None, exc=None):
    calls, logs = [], []

    def run(argv, **kw):
        calls.append((argv, kw))
        if exc:
            raise exc
        return result

    fake = types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired)
    n = {'subprocess': fake, 'print': lambda *a, **k: None}
    exec(compile(HELPER, 'app.py', 'exec'), n)
    return n, calls, logs


def _r(rc, out='', err=''):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def test_a_good_pull_reports_ok():
    n, calls, logs = _ns(_r(0))
    ok, err = n['_compose_build_pull'](['docker', 'compose', 'build', '--pull'], '/x', plog=logs.append)
    assert (ok, err) == (True, '')
    assert calls[0][0] == ['docker', 'compose', 'build', '--pull']
    assert calls[0][1]['cwd'] == '/x' and calls[0][1]['timeout'] == 900
    assert any('Base images current' in m for m in logs)


def test_a_failed_pull_is_logged_and_does_not_raise():
    n, _, logs = _ns(_r(1, err='failed to resolve source metadata for docker.io/library/node:22-alpine'))
    ok, err = n['_compose_build_pull'](['docker', 'compose', 'build', '--pull'], '/x', plog=logs.append)
    assert ok is False and 'node:22-alpine' in err
    assert any('cached base' in m and 'node:22-alpine' in m for m in logs)


def test_a_timeout_is_not_swallowed():
    n, _, _ = _ns(exc=subprocess.TimeoutExpired(['docker'], 900))
    with pytest.raises(subprocess.TimeoutExpired):
        n['_compose_build_pull'](['docker', 'compose', 'build', '--pull'], '/x')


def _body(start, end):
    return APP[APP.index(start):APP.index(end)]


@pytest.mark.parametrize('name,start,end,pull,build', [
    ('remote assist deploy', 'def _run_remote_assist_deploy(', 'def _remote_assist_github_repo_path(',
     "_compose_build_pull(_remote_assist_compose_cmd(ra_dir, 'build', '--pull')",
     "_remote_assist_compose_cmd(ra_dir, 'up', '-d', '--build')"),
    ('remote assist update', 'def _run_remote_assist_update(', "@app.route('/api/remote-assist/version')",
     "_compose_build_pull(_remote_assist_compose_cmd(ra_dir, 'build', '--pull')",
     "_remote_assist_compose_cmd(ra_dir, 'up', '-d', '--build')"),
    ('tak portal update', 'def _takportal_run_update(portal_dir):', "@app.route('/api/takportal/update/status')",
     "_compose_build_pull(_sudo_wrap(['docker', 'compose', 'build', '--pull']), portal_dir",
     "_sudo_wrap(['docker', 'compose', 'up', '-d', '--build'])"),
    ('tak portal deploy', 'def run_takportal_deploy():', '_ensure_infratak_network_for_portal()\n        _ensure_infratak_network_for_authentik()\n\n        # Seed real settings.json',
     "_compose_build_pull(_sudo_wrap(['docker', 'compose', 'build', '--pull']), portal_dir",
     "_sudo_wrap(['docker', 'compose', 'up', '-d', '--build', '--no-start'])"),
])
def test_every_build_pulls_first(name, start, end, pull, build):
    body = _body(start, end)
    assert pull in body, name
    assert build in body, name
    assert body.index(pull) < body.index(build), name


def test_takportal_update_timeout_still_caught():
    body = _body('def _takportal_run_update(portal_dir):', "@app.route('/api/takportal/update/status')")
    i = body.index("_compose_build_pull(_sudo_wrap(['docker', 'compose', 'build', '--pull'])")
    assert body.rfind('    try:\n', 0, i) > body.rfind("_gd_maintenance_begin('takportal', 2 * 900 + 180)", 0, i) > 0
    assert 'except subprocess.TimeoutExpired:' in body[i:]
