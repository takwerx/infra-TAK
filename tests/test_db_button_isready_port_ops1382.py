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
"""Start / Restart database button on a split box: "running" must not read false after a good start (ops #1382).

Field (real two-VM split pair, Ubuntu 22.04, PostgreSQL 18, non-root SSH user): the button's check
ran `pg_isready -q` with no port. On Debian/Ubuntu `pg_isready` is the pg_wrapper; with no port it
picks the lowest-numbered cluster, which after the 5.8 split migration is the stopped old 15 on
5433. As the SSH user that printed "Invalid data directory for cluster 18 main" and exited 1, so
the button answered `running: false` while PostgreSQL 18 was up. With `-p 5432` it answered
"accepting connections".

The REAL takserver_control runs here. The remote command runs locally against a fake pg_isready that
behaves like that wrapper: no port -> the old stopped cluster -> rc 1; -p PORT -> rc 0 only for the
port the live cluster serves.
"""

import ast
import os
import pathlib
import re
import stat
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

# The wrapper's behaviour on a migrated Server One: 18 is up on SERVING_PORT, 15 is stopped on 5433.
PG_ISREADY_STUB = r'''#!/bin/bash
echo "$*" >> "%(dir)s/calls"
port=
while [ $# -gt 0 ]; do
  case "$1" in -p) port=$2; shift 2 ;; *) shift ;; esac
done
if [ -z "$port" ]; then
  echo "Invalid data directory for cluster 18 main" >&2
  exit 1
fi
if [ "$port" = "$(cat "%(dir)s/serving_port")" ]; then
  echo "/var/run/postgresql:$port - accepting connections"
  exit 0
fi
echo "/var/run/postgresql:$port - no response"
exit 2
'''


@pytest.fixture
def sandbox(tmp_path):
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    stub = bindir / 'pg_isready'
    stub.write_text(PG_ISREADY_STUB % {'dir': str(tmp_path)})
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    (tmp_path / 'serving_port').write_text('5432')
    (tmp_path / 'calls').write_text('')

    def run(cmd):
        env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ['PATH'])
        return subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, env=env, timeout=20)

    return types.SimpleNamespace(dir=tmp_path, run=run)


def _fn(name):
    tree = ast.parse(APP)
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)


def _helper():
    ns = {}
    exec(compile(ast.Module(body=[_fn('_pg_isready_cmd')], type_ignores=[]), 'app.py:_pg_isready_cmd', 'exec'), ns)
    return ns['_pg_isready_cmd']


def _control(sandbox, action='start', port=5432, database=True):
    """Press the real database button. Returns (response, remote commands sent)."""
    node = _fn('takserver_control')
    node.decorator_list = []
    sent = []

    def probe(s1, cmd, timeout=0):
        sent.append(cmd)
        if 'pg_isready' in cmd:
            r = sandbox.run(cmd)
            return r.returncode == 0, (r.stdout + r.stderr).strip()
        return True, ''  # the start/stop/restart command itself worked

    cfg = {'mode': 'two_server', 'server_one': {'host': 'db1'}}
    if database:
        cfg['database'] = {'port': port}
    ns = {'request': types.SimpleNamespace(json={'action': action, 'target': 'database'}),
          'jsonify': lambda d, *a: d,
          'load_settings': lambda: {},
          '_get_tak_deployment_config': lambda s: cfg,
          '_ssh_probe': probe}
    try:
        ns['_pg_isready_cmd'] = _helper()
    except StopIteration:  # base code: no helper, the check is written inline
        pass
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py:takserver_control', 'exec'), ns)
    return ns['takserver_control'](), sent


@pytest.mark.parametrize('action', ['start', 'restart'])
def test_button_says_running_when_18_is_up_on_the_database_port(sandbox, action):
    out, sent = _control(sandbox, action)
    db = out['results']['database']
    assert db['running'] is True, (db, sent)
    assert db['success'] is True


def test_the_check_asks_with_the_configured_database_port(sandbox):
    (sandbox.dir / 'serving_port').write_text('5544')
    out, sent = _control(sandbox, 'restart', port=5544)
    assert out['results']['database']['running'] is True
    assert (sandbox.dir / 'calls').read_text().split() == ['-q', '-p', '5544']


def test_no_database_section_in_the_config_falls_back_to_5432(sandbox):
    out, sent = _control(sandbox, 'start', database=False)
    assert out['results']['database']['running'] is True


def test_button_says_not_running_when_nothing_answers_on_the_port(sandbox):
    (sandbox.dir / 'serving_port').write_text('0')  # PostgreSQL really is down
    out, sent = _control(sandbox, 'stop')
    assert out['results']['database']['running'] is False


def test_the_old_check_really_fails_on_this_layout(sandbox):
    """Guards the stub itself: the bare command the button used to send exits 1 here."""
    r = sandbox.run('pg_isready -q && echo DB_OK')
    assert r.returncode == 1 and 'DB_OK' not in r.stdout


# --- the helper ---------------------------------------------------------------------------------

@pytest.mark.parametrize('given,expected', [
    (5432, 'pg_isready -q -p 5432'),
    ('5433', 'pg_isready -q -p 5433'),
    (None, 'pg_isready -q -p 5432'),
    ('', 'pg_isready -q -p 5432'),
    (0, 'pg_isready -q -p 5432'),
    (70000, 'pg_isready -q -p 5432'),
    ('5432; rm -rf /', 'pg_isready -q -p 5432'),
    ('$(reboot)', 'pg_isready -q -p 5432'),
])
def test_helper_forces_an_int_port_so_nothing_reaches_the_shell(given, expected):
    assert _helper()(given) == expected


# --- the other place that asked the same way ----------------------------------------------------

def test_no_remote_pg_isready_is_left_without_a_port():
    """Every pg_isready sent over SSH to Server One names its port (the helper does it)."""
    # app.py text: only look at strings handed to _ssh_probe / built for it, not the local or
    # container pg_isready calls (those pick their own server and are not this bug).
    fn_src = ast.get_source_segment(APP, _fn('run_takserver_upgrade_two_server'))
    assert 'pg_isready -q &&' not in fn_src
    assert '_pg_isready_cmd(db_port)' in fn_src
    ctl_src = ast.get_source_segment(APP, _fn('takserver_control'))
    assert re.search(r"'pg_isready -q && echo DB_OK'", ctl_src) is None
    assert '_pg_isready_cmd(' in ctl_src
