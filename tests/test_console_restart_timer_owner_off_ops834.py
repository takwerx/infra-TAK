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
"""The owner's "nightly console restart is off" survives a console start (ops #834).

Field report (infra-TAK #520, 2026-11-16): an agency that moved its console turned
the nightly restart timer off. Every console start ran
_ensure_console_restart_timer(), which ran `systemctl enable --now` again.

The REAL function is cut out of app.py and run with systemctl, the file helpers and
os.path.exists faked, so what is checked is what a box runs at boot.
"""

import ast
import pathlib
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TIMER = '/etc/systemd/system/takconsolerestart.timer'


def _func_source(name):
    tree = ast.parse(APP)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


FUNC = _func_source('_ensure_console_restart_timer')


class Box:
    """A fake box: files on disk and the timer's systemd state."""

    def __init__(self, files=(), state='not-found'):
        self.files = {p: '' for p in files}
        self.state = state
        self.systemctl = []   # every systemctl verb run, in order

    def run(self, cmd, **kw):
        verb = cmd[1] if cmd[0] == 'systemctl' else cmd[0]
        self.systemctl.append(' '.join(cmd))
        out = ''
        if verb == 'is-enabled':
            out = self.state + '\n'
        elif verb == 'enable':
            self.state = 'enabled'
        return types.SimpleNamespace(stdout=out, stderr='', returncode=0)

    def func(self):
        box = self
        ns = {
            'os': types.SimpleNamespace(path=types.SimpleNamespace(
                exists=lambda p: p in box.files)),
            'subprocess': types.SimpleNamespace(run=box.run),
            '_sudo_wrap': lambda c: list(c),
            '_read_priv': lambda p: box.files.get(p, ''),
            '_write_priv': lambda p, c, perm=None: box.files.__setitem__(p, c),
            '_CONSOLE_RESTART_SCRIPT': '#!/bin/bash\n',
        }
        exec(compile(FUNC, 'app.py:_ensure_console_restart_timer', 'exec'), ns)
        return ns['_ensure_console_restart_timer']

    def ensure(self, settings):
        """One console start. Falls back to the old no-argument call so the test
        also runs (and fails on behavior, not on the signature) against the base."""
        fn = self.func()
        try:
            return fn(settings)
        except TypeError:
            return fn()

    def enabled_calls(self):
        return [c for c in self.systemctl if ' enable' in c]


def test_first_install_arms_the_timer():
    box = Box()
    s = {}
    msg = box.ensure(s)
    assert box.state == 'enabled'
    assert 'armed' in msg
    assert 'console_restart_timer_off' not in s


def test_owner_disabled_timer_stays_off_on_every_boot():
    """The bug: unit files exist, the owner ran `systemctl disable`, boot enables it again."""
    box = Box()
    s = {}
    box.ensure(s)                       # first boot installs and arms it
    box.state = 'disabled'              # the owner turns it off
    box.systemctl.clear()
    for _ in range(3):                  # three more console starts
        box.ensure(s)
    assert box.state == 'disabled'
    assert box.enabled_calls() == []
    assert s['console_restart_timer_off'] is True   # the choice is written down


def test_timer_turned_off_before_this_fix_stays_off():
    """A box that updates to this version already has the timer disabled and no flag."""
    box = Box(files=[TIMER, '/etc/systemd/system/takconsolerestart.service',
                     '/usr/local/sbin/tak-console-restart.sh'], state='disabled')
    s = {}
    msg = box.ensure(s)
    assert box.state == 'disabled'
    assert box.enabled_calls() == []
    assert 'left off' in msg
    assert s['console_restart_timer_off'] is True


def test_masked_timer_is_left_alone():
    box = Box(files=[TIMER], state='masked')
    s = {}
    box.ensure(s)
    assert box.enabled_calls() == []
    assert s['console_restart_timer_off'] is True


def test_flag_keeps_it_off_even_when_systemd_says_not_found():
    box = Box(state='not-found')
    s = {'console_restart_timer_off': True}
    box.ensure(s)
    assert box.state == 'not-found'
    assert box.enabled_calls() == []


def test_owner_arming_it_again_clears_the_flag():
    box = Box(files=[TIMER], state='enabled')
    s = {'console_restart_timer_off': True}
    box.ensure(s)
    assert 'console_restart_timer_off' not in s
    assert box.state == 'enabled'


def test_enabled_timer_with_current_files_does_nothing():
    box = Box()
    s = {}
    box.ensure(s)
    box.systemctl.clear()
    msg = box.ensure(s)
    assert msg == ''
    assert box.enabled_calls() == []


def test_disabled_timer_still_gets_its_script_refreshed():
    """Keeping it off must not freeze the script/unit text at an old version."""
    box = Box(files=[TIMER], state='disabled')
    box.files['/usr/local/sbin/tak-console-restart.sh'] = '#!/bin/bash\n# old\n'
    s = {}
    box.ensure(s)
    assert box.files['/usr/local/sbin/tak-console-restart.sh'] == '#!/bin/bash\n'
    assert box.enabled_calls() == []


def test_boot_code_saves_the_flag():
    """The boot call hands over its own settings dict and marks it dirty on a change."""
    assert '_ensure_console_restart_timer(s)' in APP
    i = APP.index('_crt_before = s.get(')
    assert 'settings_dirty = True' in APP[i:i + 400]
