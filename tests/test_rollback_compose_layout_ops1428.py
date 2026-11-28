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
"""ops #1428: Console Rollback to a release older than 10.4.4 left users in a group with no
missions or data feeds over HTTPS, and Update Now did not fix it.

Cause (run fi-20261127-190409, Ubuntu 22.04, 10.3.12 -> dev -> Rollback): the older console's
compose self-heal treats any difference between ~/authentik/docker-compose.yml and PyYAML's
default layout as damage. It rewrites the file and recreates the LDAP outpost under the running
TAK Server, and TAK's API process keeps a dead LDAP connection. 10.4.4 and newer leave a
formatting-only difference alone (ops #860), so a rollback to them was fine.

The older code cannot be changed. `_authentik_compose_before_rollback` writes the file in the
default layout (same data) before the older console starts, only for a release that lacks the
ops #860 rule.

What runs here for real: PyYAML, git (a throw-away repository with an old and a new release),
and a copy of the old heal's decision. The lock is a stand-in.
"""

import ast
import contextlib
import os
import pathlib
import subprocess

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

NAMES = ('_ROLLBACK_COMPOSE_RULE', '_authentik_compose_before_rollback', '_console_release_app_has',
         '_validate_authentik_compose')


def _src(*names):
    parts = []
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name in names:
            parts.append(ast.get_source_segment(APP, n))
        elif isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in n.targets):
            parts.append(ast.get_source_segment(APP, n))
    return '\n\n'.join(parts)


def _ns(locked=True):
    import re
    import time

    @contextlib.contextmanager
    def lock(holder, plog=None, timeout=1):
        yield locked

    ns = {'os': os, 're': re, 'time': time, 'subprocess': subprocess, '_authentik_compose_lock': lock}
    exec(compile(_src(*NAMES), 'app.py:rollback-compose', 'exec'), ns)
    return ns


# What 10.3.12's `_self_heal_authentik_compose` decided (v10.3.12-alpha app.py, the part after the
# file is read): a file that PyYAML's default dump does not reproduce byte for byte is rewritten,
# and every caller then recreates the LDAP outpost. Copied, not imported: that code is not in this tree.
def _old_heal_would_rewrite(text):
    loaded = yaml.safe_load(text)
    return yaml.safe_dump(loaded, default_flow_style=False, sort_keys=False) != text


LONG = ('python -c "import time; print(\'a long command line that PyYAML default width folds onto '
        'several lines unless it is dumped with width 200\'); time.sleep(1)"')


def _compose_data():
    return {
        'services': {
            'server': {'image': 'ghcr.io/goauthentik/server:2026.8.7', 'command': LONG,
                       'environment': {'AUTHENTIK_POSTGRESQL__HOST': 'pgbouncer'}},
            'ldap': {'image': 'ghcr.io/goauthentik/ldap:2026.8.7', 'restart': 'unless-stopped'},
            'pgbouncer': {'image': 'edoburu/pgbouncer:v1.25.1-p0',
                          'environment': {'DEFAULT_POOL_SIZE': '750'}},
        },
    }


def _newer_layout(data):
    """How the newer writers (pgbouncer install, compose patches, worker direct-pg) dump the file."""
    return yaml.safe_dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True, width=200)


def _default_layout(data):
    return yaml.safe_dump(data, default_flow_style=False, sort_keys=False)


def _git(cwd, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.invalid',
               GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.invalid', GIT_TERMINAL_PROMPT='0')
    return subprocess.run(['git', '-c', 'safe.directory=*'] + list(args), cwd=cwd, env=env,
                          capture_output=True, text=True, check=True)


@pytest.fixture()
def console(tmp_path):
    """A console checkout with two releases (refs v-old and v-new): 10.3.12-like (no ops #860 rule) and 10.4.4-like."""
    d = tmp_path / 'console'
    d.mkdir()
    _git(d, 'init', '-q')
    (d / 'app.py').write_text('# 10.3.12\ndef _self_heal_authentik_compose():\n    return "normalized YAML"\n')
    _git(d, 'add', 'app.py')
    _git(d, 'commit', '-q', '-m', 'old')
    _git(d, 'branch', 'v-old')
    (d / 'app.py').write_text('# 10.4.4\ndef _self_heal_authentik_compose():\n'
                              '    stamp = "no-op: only formatting differs (no duplicate mapping keys)"\n')
    _git(d, 'commit', '-q', '-am', 'new')
    _git(d, 'branch', 'v-new')
    return str(d)


@pytest.fixture()
def compose(tmp_path):
    p = tmp_path / 'authentik' / 'docker-compose.yml'
    p.parent.mkdir()
    p.write_text(_newer_layout(_compose_data()))
    return p


def test_the_layout_a_newer_release_writes_is_what_the_old_heal_rewrites(compose):
    # The premise of the fix: the file as Update Now leaves it is "damage" to the old heal.
    assert _old_heal_would_rewrite(compose.read_text())
    assert not _old_heal_would_rewrite(_default_layout(_compose_data()))


def test_rollback_to_a_release_without_the_rule_writes_the_layout_the_old_heal_leaves_alone(console, compose):
    ns = _ns()
    log = []
    assert ns['_authentik_compose_before_rollback'](console, 'v-old', path=str(compose), plog=log.append) == 'rewritten'
    text = compose.read_text()
    assert not _old_heal_would_rewrite(text)                      # the old console's start finds nothing to heal
    assert yaml.safe_load(text) == _compose_data()                # same data, nothing else changed
    [bak] = [p for p in compose.parent.iterdir() if '.rollback-bak-' in p.name]
    assert yaml.safe_load(bak.read_text()) == _compose_data()     # the old file is kept
    assert any('LDAP outpost' in m for m in log)


def test_rollback_to_a_release_with_the_rule_leaves_the_file_alone(console, compose):
    before = compose.read_text()
    assert _ns()['_authentik_compose_before_rollback'](console, 'v-new', path=str(compose)) == 'none'
    assert compose.read_text() == before
    assert [p.name for p in compose.parent.iterdir()] == ['docker-compose.yml']


def test_a_file_already_in_the_default_layout_is_not_touched_and_leaves_no_backup(console, tmp_path):
    p = tmp_path / 'authentik' / 'docker-compose.yml'
    p.parent.mkdir()
    p.write_text(_default_layout(_compose_data()))
    assert _ns()['_authentik_compose_before_rollback'](console, 'v-old', path=str(p)) == 'none'
    assert [x.name for x in p.parent.iterdir()] == ['docker-compose.yml']


def test_no_compose_file_means_nothing_to_do(console, tmp_path):
    assert _ns()['_authentik_compose_before_rollback'](console, 'v-old', path=str(tmp_path / 'nope.yml')) == 'none'


def test_a_file_that_is_not_a_mapping_is_left_alone(console, tmp_path):
    p = tmp_path / 'docker-compose.yml'
    p.write_text('- just\n- a list\n')
    assert _ns()['_authentik_compose_before_rollback'](console, 'v-old', path=str(p)) == 'none'
    assert p.read_text() == '- just\n- a list\n'


def test_a_lock_held_by_another_job_leaves_the_file_alone_and_the_rollback_goes_on(console, compose):
    before = compose.read_text()
    log = []
    assert _ns(locked=False)['_authentik_compose_before_rollback'](console, 'v-old', path=str(compose), plog=log.append) == 'failed'
    assert compose.read_text() == before
    assert any('lock' in m for m in log)


def test_when_git_cannot_read_the_release_the_file_is_still_prepared(tmp_path, compose):
    # no repository at all: the safe side is to prepare the file (it is the same data)
    empty = tmp_path / 'not-a-repo'
    empty.mkdir()
    assert _ns()['_authentik_compose_before_rollback'](str(empty), 'v-old', path=str(compose)) == 'rewritten'
    assert not _old_heal_would_rewrite(compose.read_text())


def test_a_write_error_never_raises_and_says_failed(console, tmp_path):
    p = tmp_path / 'authentik' / 'docker-compose.yml'
    p.parent.mkdir()
    p.write_text(_newer_layout(_compose_data()))
    os.chmod(str(p), 0o444)
    os.chmod(str(p.parent), 0o555)
    try:
        if os.access(str(p), os.W_OK):
            pytest.skip('running as a user that can write anywhere')
        assert _ns()['_authentik_compose_before_rollback'](console, 'v-old', path=str(p)) == 'failed'
    finally:
        os.chmod(str(p.parent), 0o755)
        os.chmod(str(p), 0o644)


def test_the_rollback_route_prepares_the_file_after_the_checkout_and_before_the_console_restarts():
    route = APP[APP.index('def console_rollback_api('):]
    route = route[:route.index('\n@app.route(', 10)]
    assert '_authentik_compose_before_rollback(console_dir, target)' in route
    checkout = route.index("['checkout', '--force', target]")
    step = route.index('_authentik_compose_before_rollback(console_dir, target)')
    restart = route.index('_detached_console_restart()')
    assert checkout < step < restart
    # a failed step does not stop the rollback and tells the operator what to press
    assert "compose_layout == 'failed'" in route and 'press Update Now again' in route
