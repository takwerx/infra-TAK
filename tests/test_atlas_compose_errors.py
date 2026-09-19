# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Michael Leckliter
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
"""Saying why compose failed (2026-09-18).

⚠️ **The failure that produced nothing to read.** A deploy on the box failed at
step 4 and logged:

    [atlas] ERROR: docker compose up failed:

— and then nothing. The message interpolated `r.stderr`, compose had written the
reason somewhere else, and the operator was left with a failure that explained
itself to no one. The journal was no better: it carried the same empty line.

A failure an operator cannot read is barely better than one they are not told
about, because it costs them the time to go looking anyway.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402


class Result:
    def __init__(self, returncode=1, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_the_error_from_stderr_is_reported():
    message = atlas.compose_error(
        Result(1, stderr='dependency failed to start: container '
                         'takmdm-corona-init-1 exited (1)'))

    assert 'takmdm-corona-init-1 exited (1)' in message


def test_the_error_from_stdout_is_reported_too():
    """⚠️ **The actual bug.** Reading only `stderr` lost the whole message when
    compose wrote it to stdout — which is what happened on the box."""
    message = atlas.compose_error(
        Result(1, stdout='service "api" failed to build: no such file'))

    assert 'no such file' in message


def test_stderr_wins_when_both_streams_carry_something():
    """Compose puts progress on stdout and diagnostics on stderr when it has
    both, so the diagnostic is the more useful of the two."""
    message = atlas.compose_error(
        Result(1, stdout='Container takmdm-api-1 Creating',
               stderr='Error response from daemon: port is already allocated'))

    assert 'port is already allocated' in message
    assert 'Creating' not in message


def test_the_exit_code_is_always_there():
    assert 'exit 137' in atlas.compose_error(Result(137, stderr='killed'))


def test_silence_is_reported_as_silence():
    """⚠️ Rendering two empty streams as an empty string is what made the
    original message unreadable. Saying so — and saying what usually causes it —
    turns a blank line into a lead."""
    message = atlas.compose_error(Result(1))

    assert 'wrote nothing' in message
    assert 'removed or the console restarted' in message
    assert 'exit 1' in message


def test_a_long_error_keeps_its_tail():
    """The useful part of a build failure is at the end; a head-truncated log
    shows the package manager downloading and stops before the reason."""
    message = atlas.compose_error(
        Result(1, stderr='x' * 4000 + 'THE ACTUAL REASON'))

    assert 'THE ACTUAL REASON' in message
    assert len(message) < 2000


def test_the_command_is_named():
    """So a failure in `up` is not read as a failure in `down`."""
    assert 'docker compose up' in atlas.compose_error(
        Result(1, stderr='boom'), 'docker compose up')


def test_deploy_and_update_both_use_it():
    """⚠️ Both jobs raised the same unreadable string, built two different ways.
    One of them being fixed would leave the other silent, and the one left
    silent would be found the way the first was — by an operator with a failure
    and nothing to read."""
    import re

    text = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    raises = re.findall(r"raise RuntimeError\([^)]*compose up[^)]*\)", text)

    assert len(raises) == 2, raises
    for call in raises:
        assert 'compose_error' in call, call
