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
"""GD_STACK_OWNER is a supported Guard Dog setting (GH #739, ops #1273).

A user whose Docker stacks belong to a regular admin account (not root or takwerx) needs Guard
Dog's boot sequencer to trust those folders. Before: only the GD_STACK_OWNER environment variable
(a systemd drop-in) did that, and the code said it was for tests. Now it is supported, two ways:
the environment variable, or the first line of /etc/takguard/stack_owner (infra-TAK never writes it,
so updates leave it alone). The file counts only when it and its folder are root-owned and not
writable by others, because Guard Dog runs as root: whoever can write that file would choose which
folders root trusts.

The REAL _gd-tak-lib.sh is sourced in a sandbox. The tests run as a plain user, so
GD_ROOT_UID stands in for root's uid (the same way GD_STACK_OWNER=<uid> already does in other tests).
"""

import os
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
LIB = REPO / 'scripts' / 'guarddog' / '_gd-tak-lib.sh'


@pytest.fixture
def sh(tmp_path):
    folder = tmp_path / 'etc-takguard'
    folder.mkdir()
    folder.chmod(0o755)
    owner_file = folder / 'stack_owner'
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    (stubs / 'logger').write_text('#!/bin/sh\necho "$*" >> %s\n' % (tmp_path / 'logger.log'))
    (stubs / 'logger').chmod(0o755)

    def run(script, **extra):
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs,
               'GD_CONF_FILE': str(tmp_path / 'none.conf'),
               'GD_STACK_OWNER_FILE': str(owner_file),
               'GD_ROOT_UID': str(os.getuid())}
        env.update(extra)
        r = subprocess.run(['bash', '-c', 'source %s; %s' % (LIB, script)],
                           capture_output=True, text=True, env=env, timeout=30)
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    run.file = owner_file
    run.folder = folder
    run.tmp = tmp_path
    run.log = tmp_path / 'logger.log'
    return run


def _owner(sh, **extra):
    return sh('echo "$GD_STACK_OWNER"', **extra)


def test_default_is_takwerx(sh):
    assert _owner(sh) == 'takwerx'


def test_file_names_the_stack_owner(sh):
    sh.file.write_text('dfndr13\n')
    sh.file.chmod(0o644)
    assert _owner(sh) == 'dfndr13'


def test_environment_variable_wins_over_the_file(sh):
    sh.file.write_text('dfndr13\n')
    assert _owner(sh, GD_STACK_OWNER='someoneelse') == 'someoneelse'


@pytest.mark.parametrize('mode', [0o666, 0o664, 0o622, 0o646])
def test_file_writable_by_others_is_ignored(sh, mode):
    sh.file.write_text('dfndr13\n')
    sh.file.chmod(mode)
    assert _owner(sh) == 'takwerx'


def test_folder_writable_by_others_is_ignored(sh):
    sh.file.write_text('dfndr13\n')
    sh.file.chmod(0o644)
    sh.folder.chmod(0o777)
    assert _owner(sh) == 'takwerx'


def test_symlinked_file_is_ignored(sh):
    real = sh.tmp / 'real'
    real.write_text('dfndr13\n')
    real.chmod(0o644)
    sh.file.symlink_to(real)
    assert _owner(sh) == 'takwerx'


def test_file_not_owned_by_root_is_ignored(sh):
    sh.file.write_text('dfndr13\n')
    sh.file.chmod(0o644)
    assert _owner(sh, GD_ROOT_UID='4242424') == 'takwerx'


@pytest.mark.parametrize('value', ['', 'x; rm -rf /', '-x', '.hidden', 'a b', '$(id)', '`id`'])
def test_value_that_is_not_an_account_name_is_ignored(sh, value):
    sh.file.write_text(value + '\n')
    sh.file.chmod(0o644)
    assert _owner(sh) == 'takwerx'


def test_only_the_first_line_counts(sh):
    sh.file.write_text('dfndr13\nroot\n')
    sh.file.chmod(0o644)
    assert _owner(sh) == 'dfndr13'


def test_the_file_makes_guard_dog_trust_that_accounts_stack_folder(sh):
    """End to end: a stack folder owned by another account is refused until the file names it."""
    if os.getuid() == 0:
        pytest.skip('root owns everything, so nothing is refused')
    stack = sh.tmp / 'authentik'
    stack.mkdir()
    (stack / 'docker-compose.yml').write_text('services: {}\n')
    uid = str(os.getuid())      # stands in for the admin account (a bare uid is accepted)
    check = 'gd_trusted_stack_dir %s && echo trusted || echo refused' % stack
    assert sh(check) == 'refused'
    sh.file.write_text(uid + '\n')
    sh.file.chmod(0o644)
    assert sh(check) == 'trusted'
