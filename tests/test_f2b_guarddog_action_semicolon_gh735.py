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
"""Guard Dog ban e-mails go out: the fail2ban `actionban` has no ` ;` in it (gh #735).

v10.4.7-alpha: the Guard Dog actions for the Authentik, takserver and takserver-badcert jails
joined the dashboard log line and the e-mail call with ` ; `. fail2ban's config reader sets
inline_comment_prefixes=';' (fail2ban 0.11.2, fail2ban/client/configparserinc.py), and Python's
configparser treats a prefix that follows a space as the start of a comment. So the parsed
actionban stopped at restarts.log, `infratak-f2b-notify` never ran, and no ban e-mail was sent.
`fail2ban-client -d` showed it.

The test reads each action the way fail2ban does (ConfigParser, BasicInterpolation,
inline_comment_prefixes=';'), then RUNS the parsed command in a shell with the notifier
replaced by a stub, so it fails if the e-mail call is dropped for any reason. The constants and
the hook function come from the shipped app.py text.
"""

import ast
import configparser
import os
import pathlib
import re
import stat
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

ACTIONS = {
    '_F2B_AUTHENTIK_GUARDDOG_ACTION': 'authentik',
    '_F2B_TAK_GUARDDOG_ACTION': 'takserver',
    '_F2B_TAK_BADCERT_GUARDDOG_ACTION': 'takserver-badcert',
}
NOTIFY = '/usr/local/sbin/infratak-f2b-notify'

# What the v10.4.7-alpha Authentik action looked like (gh #735), kept as a control that proves
# the reader below really drops the e-mail call from a ` ; ` action.
OLD_SEMICOLON_ACTION = (
    "[Definition]\n"
    "actionban  = mkdir -p /var/log/takguard"
    " && echo \"`/bin/date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ`"
    " | fail2ban: Banned <ip> (Authentik brute-force)\""
    " >> /var/log/takguard/restarts.log"
    " ; /usr/bin/env python3 /usr/local/sbin/infratak-f2b-notify <ip> authentik\n"
    "actionunban =\n"
)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _const(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            ns = {}
            exec(ast.get_source_segment(APP, n), ns)
            return ns[name]
    raise AssertionError(f'{name} was renamed or removed')


def _fail2ban_parse(text):
    """The action file as fail2ban 0.11.2 reads it: `%%` becomes `%`, ` ;` starts a comment."""
    cp = configparser.ConfigParser(interpolation=configparser.BasicInterpolation(),
                                   inline_comment_prefixes=';')
    cp.read_string(text)
    return cp['Definition']['actionban']


def test_reader_drops_the_email_call_from_a_semicolon_action():
    """Control: this is the bug. Same reader, old text: the parsed actionban ends at the log."""
    parsed = _fail2ban_parse(OLD_SEMICOLON_ACTION)
    assert parsed.endswith('/var/log/takguard/restarts.log')
    assert 'infratak-f2b-notify' not in parsed


@pytest.mark.parametrize('name,tag', sorted(ACTIONS.items()))
def test_parsed_actionban_still_calls_the_notifier(name, tag):
    action = _const(name)
    parsed = _fail2ban_parse(action)
    assert f'{NOTIFY} <ip> {tag}' in parsed, parsed
    assert '/var/log/takguard/restarts.log' in parsed, parsed
    # Nothing after a space may start a comment: ` ;` and ` #` both cut a value short.
    for line in action.splitlines():
        assert ' ;' not in line and ' #' not in line, line


def _run_actionban(tmp_path, action, tag, log_dir_is_a_file=False):
    """Run the parsed actionban in sh with the log dir and the notifier moved into tmp_path."""
    parsed = _fail2ban_parse(action)
    log_dir = tmp_path / 'takguard'
    if log_dir_is_a_file:
        log_dir.write_text('not a directory, so mkdir -p and the log write both fail')
    marker = tmp_path / 'notified'
    stub = tmp_path / 'notify-stub'
    stub.write_text(f'#!/bin/sh\necho "$@" >> {marker}\n')
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    cmd = (parsed.replace('/var/log/takguard', str(log_dir))
                 .replace('/usr/bin/env python3 ' + NOTIFY, str(stub))
                 .replace('<ip>', '203.0.113.9'))
    assert str(stub) in cmd, cmd
    subprocess.run(['/bin/sh', '-c', cmd], check=False, capture_output=True, timeout=30)
    return log_dir / 'restarts.log', marker


@pytest.mark.parametrize('name,tag', sorted(ACTIONS.items()))
def test_a_ban_writes_the_dashboard_line_and_sends_the_notification(tmp_path, name, tag):
    log, marker = _run_actionban(tmp_path, _const(name), tag)
    assert marker.exists(), 'the ban e-mail call never ran'
    assert marker.read_text().split() == ['203.0.113.9', tag]
    line = log.read_text()
    assert re.match(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ \| fail2ban: Banned 203\.0\.113\.9 \(', line), line


@pytest.mark.parametrize('name,tag', sorted(ACTIONS.items()))
def test_the_email_still_goes_when_the_dashboard_log_cannot_be_written(tmp_path, name, tag):
    """The old ` ; ` meant: run the notifier whatever the log write did. Keep that."""
    _log, marker = _run_actionban(tmp_path, _const(name), tag, log_dir_is_a_file=True)
    assert marker.exists() and marker.read_text().split() == ['203.0.113.9', tag]


# ── Existing boxes get the new Authentik action once ─────────────────────────────────

class _Box:
    def __init__(self, marker):
        self.settings = {'fail2ban_setup': {'guarddog_hook': marker}} if marker else {}
        self.files = {}
        self.cmds = []

    def run(self, cmd, **_k):
        self.cmds.append(cmd)


def _hook(box):
    ns = {'os': types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: True)),
          '_F2B_NOTIFY_SCRIPT': '# notifier\n',
          '_F2B_AUTHENTIK_GUARDDOG_ACTION': _const('_F2B_AUTHENTIK_GUARDDOG_ACTION'),
          'load_settings': lambda: box.settings,
          'save_settings': lambda s: setattr(box, 'settings', s),
          '_write_priv': lambda p, c, **k: box.files.__setitem__(p, c),
          '_makedirs_priv': lambda *a, **k: None,
          '_f2b_read_jail_config': lambda: {'maxretry': 5, 'findtime': 600, 'bantime': 3600},
          '_f2b_write_jail_config': lambda *a, **k: None,
          '_sudo_wrap': lambda c: c,
          'subprocess': types.SimpleNamespace(run=box.run)}
    exec(_func('_fail2ban_add_guarddog_hook'), ns)
    return ns['_fail2ban_add_guarddog_hook']


ACTION_PATH = '/etc/fail2ban/action.d/infratak-guarddog.conf'


@pytest.mark.parametrize('old_marker', [None, 'applied_v2', 'applied_v3'])
def test_a_box_that_ran_an_older_hook_gets_the_fixed_action_and_a_reload(old_marker):
    box = _Box(old_marker)
    assert _hook(box)(lambda m: None) is True
    assert box.files[ACTION_PATH] == _const('_F2B_AUTHENTIK_GUARDDOG_ACTION')
    assert ' ;' not in box.files[ACTION_PATH]
    assert box.settings['fail2ban_setup']['guarddog_hook'] == 'applied_v4'
    assert ['fail2ban-client', 'reload'] in box.cmds


def test_the_hook_runs_once_per_box():
    box = _Box('applied_v4')
    assert _hook(box)(lambda m: None) is False
    assert box.files == {} and box.cmds == []
