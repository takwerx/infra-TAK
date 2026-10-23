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
"""GH #246 — an operator's Node-RED compose override survives every console action.

A user published an extra UDP port (GPS tracker CoT) through
~/node-red/docker-compose.override.yml. Update Now runs a plain `docker compose up -d`
and kept it, but Deploy and Start ran `docker compose -f docker-compose.yml ...`, which
ignores the override, so the container was recreated without the port and ingest
stopped silently.

Deploy and Start now run compose with no `-f` from ~/node-red, and Deploy's
from-scratch rewrite of docker-compose.yml never writes or removes an override file.
The two functions are cut out of app.py and run against stubs (app.py cannot be
imported in a test), so the code under test is the shipped text.
"""

import ast
import datetime
import os
import pathlib
import re
import subprocess
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

OVERRIDES = {
    'docker-compose.override.yml':
        'services:\n  node-red:\n    ports:\n      - "0.0.0.0:5005:5005/udp"\n',
    'compose.override.yaml':
        'services:\n  node-red:\n    ports:\n      - "0.0.0.0:5006:5006/udp"\n',
}


def _fn(name):
    node = next(n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(APP, node)   # body only; the route decorators are not included


class _Result:
    def __init__(self, rc=0, out=''):
        self.returncode, self.stdout, self.stderr = rc, out, ''


class _Recorder:
    """Stands in for subprocess: records every argv + cwd, scripted results for `up -d`."""

    def __init__(self, up_results=()):
        self.calls = []
        self._up = list(up_results)

    def run(self, argv, **kw):
        self.calls.append((list(argv), kw.get('cwd')))
        if argv[:2] == ['docker', 'compose'] and 'up' in argv and self._up:
            return self._up.pop(0)
        return _Result(0, 'Up 2 seconds' if argv[:2] == ['docker', 'ps'] else '')

    def compose_calls(self):
        return [(a, c) for a, c in self.calls if a[:2] == ['docker', 'compose']]


def _sub_ns(rec):
    return type('subprocess', (), {
        'run': staticmethod(rec.run), 'PIPE': subprocess.PIPE, 'STDOUT': subprocess.STDOUT,
        'TimeoutExpired': subprocess.TimeoutExpired})


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    nr = tmp_path / 'node-red'
    nr.mkdir()
    for name, body in OVERRIDES.items():
        (nr / name).write_text(body)
    return tmp_path


def _deploy(home, rec, pulls, exists=False):
    status, log = {'running': True}, []
    ns = {
        'os': os, 're': re, 'time': time, 'datetime': datetime.datetime,
        'subprocess': _sub_ns(rec), '_sudo_wrap': lambda c: list(c),
        'nodered_deploy_status': status, 'nodered_deploy_log': log,
        'load_settings': lambda: {}, '_get_module_deployment_config': lambda s, k: {},
        '_preflight_port_conflicts': lambda m: [], '_ensure_docker_log_limits': lambda plog: None,
        '_docker_compose_pull': lambda yml, cwd, plog, **kw: pulls.append((yml, cwd)) or True,
        '_nodered_container_exists': lambda: exists, '_nodered_container_running': lambda: True,
        'NODERED_IMAGE': 'nodered/node-red:4.1.17-22', 'BASE_DIR': str(home / 'no-repo'),
    }
    exec(compile(_fn('run_nodered_deploy'), 'app.py', 'exec'), ns)
    ns['run_nodered_deploy']()
    assert status.get('error') is False, log
    return log


def _assert_override_aware(calls, nr_dir):
    assert calls, 'no docker compose call recorded'
    for argv, cwd in calls:
        assert '-f' not in argv and '--file' not in argv, argv
        assert cwd == nr_dir, (argv, cwd)


def test_deploy_runs_compose_without_f_and_keeps_override_files(home):
    nr_dir = str(home / 'node-red')
    rec, pulls = _Recorder(), []
    _deploy(home, rec, pulls)
    # the pull loads the same files as `up -d`: None = let compose discover them in cwd
    assert pulls == [(None, nr_dir)]
    _assert_override_aware(rec.compose_calls(), nr_dir)
    assert [a for a, _ in rec.compose_calls()] == [['docker', 'compose', 'up', '-d']]
    # the from-scratch rewrite is docker-compose.yml only; overrides are byte-identical
    for name, body in OVERRIDES.items():
        assert (home / 'node-red' / name).read_text() == body
    assert 'image: nodered/node-red:4.1.17-22' in (home / 'node-red' / 'docker-compose.yml').read_text()


def test_deploy_name_conflict_retry_also_keeps_the_override(home):
    # F2a self-heal: a leftover `nodered` container -> rm -f, then a second `up -d`
    nr_dir = str(home / 'node-red')
    clash = _Result(1, 'Error response from daemon: Conflict. The container name "/nodered" '
                       'is already in use by container "abc"')
    rec = _Recorder(up_results=[clash, _Result(0)])
    _deploy(home, rec, [], exists=True)
    ups = [(a, c) for a, c in rec.compose_calls() if 'up' in a]
    assert len(ups) == 2
    _assert_override_aware(ups, nr_dir)
    assert ['docker', 'rm', '-f', 'nodered'] in [a for a, _ in rec.calls]


@pytest.mark.parametrize('action', ['start', 'stop', 'restart'])
def test_control_runs_in_node_red_dir_and_start_loads_override(home, action):
    nr_dir = str(home / 'node-red')
    (home / 'node-red' / 'docker-compose.yml').write_text('services: {}\n')
    rec = _Recorder()
    ns = {
        'os': os, 'time': type('t', (), {'sleep': staticmethod(lambda s: None)}),
        'subprocess': _sub_ns(rec), '_sudo_wrap': lambda c: list(c),
        'request': type('r', (), {'json': {'action': action}}),
        'jsonify': lambda *a, **k: (a, k),
    }
    exec(compile(_fn('nodered_control'), 'app.py', 'exec'), ns)
    ns['nodered_control']()
    calls = rec.compose_calls()
    assert len(calls) == 1 and calls[0][1] == nr_dir
    if action == 'start':
        # `up -d` (re)creates the container, so it must see the override
        assert calls[0][0] == ['docker', 'compose', 'up', '-d']


def test_update_now_and_remote_deploy_stay_override_aware():
    # the paths that already honoured the override must not grow a `-f`
    upd = APP[APP.index('def _auto_nodered():'):]
    upd = upd[:upd.index('_auto_harden_containers()\n')]
    assert '_docker_compose_pull(None, nr_dir' in upd
    assert not re.search(r"'docker', 'compose', '-f'", upd)
    remote = _fn('_run_nodered_deploy_remote')
    assert not re.search(r'docker compose -f', remote)
