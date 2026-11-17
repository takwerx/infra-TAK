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
"""TAK Portal Marketplace "Deploy To Caddy" says failed after it worked (ops #879).

The Portal runs `bash -lc 'set -euo pipefail; ...; exit 0'` over SSH as the console user. A login
shell reads ~/.bash_logout on exit and errexit is still on there. Ubuntu's stock file ends with
`[ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q`, which fails with no terminal, so the
whole command exits 1 after the Caddy helper had already written and reloaded the Caddyfile.

Measured on Ubuntu 22.04 with a real sshd (bash 5.1), `bash -lc 'set -euo pipefail; exit 0'`:
stock file rc 1; stock file plus `true` at the end rc 1 (errexit stops the file first); `set +e`
first rc 0; no file rc 0.

infra-TAK puts a marked `set +e` at the top of the console user's existing ~/.bash_logout.
"""

import ast
import os
import pathlib
import shutil
import stat as stat_mod
import subprocess
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

BASH = shutil.which('bash')

# Ubuntu's /etc/skel/.bash_logout, verbatim, except that the one command that fails with no
# terminal is `false` here (clear_console is not on every machine that runs these tests).
STOCK = '''# ~/.bash_logout: executed by bash(1) when login shell exits.

# when leaving the console clear the screen to increase privacy

if [ "$SHLVL" = 1 ]; then
    [ -x /bin/sh ] && false
fi
'''
UBUNTU_STOCK = STOCK.replace('[ -x /bin/sh ] && false',
                             '[ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q')


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _consts():
    """The two module-level constants the function reads, cut out of app.py."""
    out = {}
    for node in TREE.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and getattr(node.targets[0], 'id', '') in ('TAKPORTAL_LOGOUT_MARKER',
                                                           'TAKPORTAL_LOGOUT_BLOCK'):
            out[node.targets[0].id] = node
    assert set(out) == {'TAKPORTAL_LOGOUT_MARKER', 'TAKPORTAL_LOGOUT_BLOCK'}, \
        'TAKPORTAL_LOGOUT_MARKER / TAKPORTAL_LOGOUT_BLOCK missing from app.py'
    return out


@pytest.fixture()
def harden(tmp_path, monkeypatch):
    """_takportal_harden_logout_file cut out of app.py, run against a temp HOME."""
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setenv('HOME', str(home))
    ns = {'os': os, 'tempfile': tempfile, '_stat': stat_mod}
    for node in _consts().values():
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py:const', 'exec'), ns)
    exec(compile(_segment('_takportal_harden_logout_file'), 'app.py:harden', 'exec'), ns)
    ns['_home'] = home
    ns['_logout'] = home / '.bash_logout'
    return ns


def _exit_code(home):
    """The exit code of the Portal's call shape in a login shell with errexit on, with `home`."""
    r = subprocess.run([BASH, '-lc', 'set -euo pipefail; echo RAN; exit 0'],
                       env={'HOME': str(home), 'PATH': '/usr/bin:/bin'},
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    assert 'RAN' in r.stdout
    return r.returncode


pytestmark = pytest.mark.skipif(BASH is None, reason='needs bash')


# ── the shell behaviour that causes it ───────────────────────────────────────

def test_stock_logout_file_makes_the_portal_command_exit_1(harden):
    harden['_logout'].write_text(STOCK)
    assert _exit_code(harden['_home']) == 1


def test_appending_true_does_not_help(harden):
    """The first idea (ops #879 option 1): errexit stops the file at the failing line."""
    harden['_logout'].write_text(STOCK + '\ntrue\n')
    assert _exit_code(harden['_home']) == 1


# ── the fix ──────────────────────────────────────────────────────────────────

def test_after_the_fix_the_portal_command_exits_0(harden):
    harden['_logout'].write_text(STOCK)
    assert harden['_takportal_harden_logout_file']() == 'changed'
    assert _exit_code(harden['_home']) == 0


def test_the_fix_goes_first_and_keeps_the_rest_byte_for_byte(harden):
    harden['_logout'].write_text(UBUNTU_STOCK)
    harden['_takportal_harden_logout_file']()
    text = harden['_logout'].read_text()
    assert text.endswith(UBUNTU_STOCK)
    head = text[:-len(UBUNTU_STOCK)]
    assert 'infratak-portal-logout' in head
    assert head.rstrip().splitlines()[-1] == 'set +e'


def test_a_user_line_that_exits_a_code_still_decides(harden):
    """We only turn errexit off; an explicit `exit N` of the operator's own is still honoured."""
    harden['_logout'].write_text('echo hi\nexit 5\n')
    harden['_takportal_harden_logout_file']()
    assert _exit_code(harden['_home']) == 5


def test_second_run_changes_nothing(harden):
    harden['_logout'].write_text(STOCK)
    f = harden['_takportal_harden_logout_file']
    assert f() == 'changed'
    once = harden['_logout'].read_text()
    before = harden['_logout'].stat().st_mtime_ns
    assert f() == 'current'
    assert harden['_logout'].read_text() == once
    assert harden['_logout'].stat().st_mtime_ns == before
    assert once.count('set +e') == 1


def test_mode_is_kept_and_no_temp_file_is_left(harden):
    harden['_logout'].write_text(STOCK)
    harden['_logout'].chmod(0o640)
    harden['_takportal_harden_logout_file']()
    assert stat_mod.S_IMODE(harden['_logout'].stat().st_mode) == 0o640
    assert [p.name for p in harden['_home'].iterdir()] == ['.bash_logout']


def test_no_file_is_not_created(harden):
    """An account with no ~/.bash_logout has nothing that can fail, so nothing is written."""
    assert harden['_takportal_harden_logout_file']() == 'absent'
    assert not harden['_logout'].exists()
    assert _exit_code(harden['_home']) == 0


def test_rocky_stock_file_is_harmless_and_stays_harmless(harden):
    """Rocky 9's /etc/skel/.bash_logout is one comment line (probed in rockylinux:9: rc 0 with
    errexit). It gets the same marked line and still exits 0."""
    harden['_logout'].write_text('# ~/.bash_logout\n')
    assert _exit_code(harden['_home']) == 0
    assert harden['_takportal_harden_logout_file']() == 'changed'
    assert _exit_code(harden['_home']) == 0


def test_a_symlinked_file_is_left_alone(harden, tmp_path):
    target = tmp_path / 'elsewhere'
    target.write_text(STOCK)
    harden['_logout'].symlink_to(target)
    assert harden['_takportal_harden_logout_file']() == 'absent'
    assert target.read_text() == STOCK


def test_an_unwritable_home_reports_and_does_not_raise(harden, monkeypatch):
    harden['_logout'].write_text(STOCK)

    def boom(*a, **k):
        raise PermissionError('read-only')
    monkeypatch.setattr(harden['tempfile'], 'mkstemp', boom)
    logs = []
    assert harden['_takportal_harden_logout_file'](logs.append) == 'error'
    assert any('not changed' in m for m in logs)
    assert harden['_logout'].read_text() == STOCK


# ── wiring ───────────────────────────────────────────────────────────────────

def test_hooks_are_wired():
    """Called from the Portal SSH setup (deploy / update / Repair) and from the startup heal,
    which only runs where TAK Portal is installed."""
    assert '_takportal_harden_logout_file(log_fn=log_fn)' in _segment('_takportal_setup_ssh')
    startup = _segment('_startup_migrations')
    assert '_takportal_harden_logout_file(' in startup
    i = startup.index('_takportal_harden_logout_file(')
    assert "os.path.isdir(os.path.expanduser('~/TAK-Portal'))" in startup[max(0, i - 200):i]
