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
"""ops #348 — `docker compose --project-directory D` must run with D as its working directory.

Compose resolves RELATIVE COMPOSE_FILE entries (TAK Portal's `docker-compose.marketplace.yml` in
CloudTAK's .env) against the working directory, not --project-directory. The broker-run stop/up
therefore looked in `/`, failed, and the root->non-root re-home aborted at every start. The
helpers are cut out of broker/takwerx_broker.py and app.py and run here (neither can be imported
in a test), so the code under test is the shipped text.

Also: the CloudTAK redeploy paths must `stop`, not `down` — `down` orphans postgis' anonymous
data volume and resets CloudTAK's users (ops #346 box test).
"""

import ast
import os
import pathlib
import re
import shlex
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
BROKER = (REPO / 'broker' / 'takwerx_broker.py').read_text(encoding='utf-8')


def _seg(src, cls, name):
    tree = ast.parse(src)
    node = next(n for n in tree.body if isinstance(n, cls) and (
        n.name == name if cls is ast.FunctionDef else
        any(isinstance(t, ast.Name) and t.id == name for t in n.targets)))
    return ast.get_source_segment(src, node)


def _project_dir_fn():
    ns = {'os': os}
    exec(compile(_seg(BROKER, ast.Assign, '_DOCKER_VALUE_FLAGS') + '\n\n'
                 + _seg(BROKER, ast.FunctionDef, 'compose_project_dir'), 'broker', 'exec'), ns)
    return ns['compose_project_dir']


def test_project_dir_is_read_from_compose_flags(tmp_path):
    f = _project_dir_fn()
    d = str(tmp_path)
    assert f(['docker', 'compose', '--project-directory', d, 'stop']) == d
    assert f(['docker', 'compose', '--project-directory=' + d, 'up', '-d']) == d
    assert f(['/usr/bin/docker', 'compose', '-p', 'x', '--project-directory', d, 'up']) == d
    assert f(['docker', '--context', 'c', 'compose', '--project-directory', d, 'ps']) == d


def test_project_dir_ignored_when_not_a_usable_compose_dir(tmp_path):
    f = _project_dir_fn()
    d = str(tmp_path)
    assert f(['docker', 'compose', 'stop']) is None
    assert f(['docker', 'compose', '--project-directory', d + '/missing', 'stop']) is None
    assert f(['docker', 'compose', '--project-directory', 'relative', 'stop']) is None
    assert f(['docker', 'compose', '--project-directory']) is None
    assert f(['docker', 'ps', '--project-directory', d]) is None
    assert f(['systemctl', 'compose', '--project-directory', d, 'stop']) is None
    assert f([]) is None
    # after the subcommand it belongs to the subcommand (a service's own flag), not to compose
    assert f(['docker', 'compose', 'run', '--project-directory', d, 'svc']) is None
    assert f(['docker', 'compose', 'exec', 'api', '--project-directory', d]) is None


def test_exec_runs_in_the_project_directory():
    body = _seg(BROKER, ast.FunctionDef, '_do_exec')
    assert body.index('compose_project_dir(argv)') < body.index('subprocess.run(argv')
    assert re.search(r"_pd = compose_project_dir\(argv\)\n\s+if _pd:\n\s+cwd = _pd", body)


def test_broker_compose_sets_cwd_when_the_console_can_enter_the_dir(tmp_path):
    calls = []

    class _SP:
        @staticmethod
        def run(argv, **kw):
            calls.append((argv, kw))

    ns = {'os': os, 'shlex': shlex, 'subprocess': _SP, '_sudo_wrap': lambda c: ['broker'] + c}
    exec(compile(_seg(APP, ast.FunctionDef, '_broker_compose'), 'app.py', 'exec'), ns)
    ns['_broker_compose'](str(tmp_path), 'stop')
    assert calls[-1][1]['cwd'] == str(tmp_path)
    assert calls[-1][0] == ['broker', 'docker', 'compose', '--project-directory', str(tmp_path), 'stop']
    # a /root-era dir the console cannot enter: no cwd (the broker supplies it)
    ns['_broker_compose'](str(tmp_path / 'missing'), 'stop')
    assert calls[-1][1]['cwd'] is None


@pytest.mark.skipif(not shutil.which('docker'), reason='docker CLI not installed')
def test_real_compose_needs_the_project_dir_as_cwd(tmp_path):
    """The failure and the fix, with the real compose CLI (`config` needs no daemon)."""
    (tmp_path / 'docker-compose.yml').write_text('services:\n  api:\n    image: alpine\n')
    (tmp_path / 'docker-compose.marketplace.yml').write_text(
        'services:\n  api:\n    environment:\n      - X=1\n')
    (tmp_path / '.env').write_text(
        'COMPOSE_FILE=%s/docker-compose.yml:docker-compose.marketplace.yml\n' % tmp_path)
    argv = ['docker', 'compose', '--project-directory', str(tmp_path), 'config']
    elsewhere = subprocess.run(argv, cwd='/', capture_output=True, text=True)
    assert elsewhere.returncode != 0 and 'docker-compose.marketplace.yml' in elsewhere.stderr
    inside = subprocess.run(argv, cwd=str(tmp_path), capture_output=True, text=True)
    assert inside.returncode == 0 and 'environment' in inside.stdout and 'marketplace' not in inside.stderr


def test_cloudtak_redeploy_paths_stop_instead_of_down():
    remote = _seg(APP, ast.FunctionDef, '_cloudtak_remote_reclone_sh')
    assert 'docker compose stop' in remote and 'compose down' not in remote
    i = APP.index('Cleaning up from previous build attempt')
    window = APP[i:i + 600]
    assert "'docker', 'compose', 'stop'" in window and "'down'" not in window
