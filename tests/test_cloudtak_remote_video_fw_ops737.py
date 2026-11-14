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
"""ops #737: video from a remote CloudTAK needs TCP 9997 open on the CONSOLE box.

CloudTAK's video-service.ts puts port 9997 on every media address it builds. A remote CloudTAK's
api container calls https://video.<name>:9997 for each lease, and the HLS address handed to the
player is on 9997 too. That name is the console box, where Caddy listens on :9997. The console
opened 9997 for a local CloudTAK only, so with CloudTAK on a remote host and ufw active on the
console, every video lease timed out ("CloudTAK has no working media server") until the operator
ran `ufw allow 9997/tcp` by hand (found in the 10.3.13 T&E, AWS boxes in one VPC).

The port is opened to everyone, as for a local CloudTAK: players come from anywhere. A first try
that opened it for the remote host only let the lease succeed and still blocked the player (red on
the boxes), so a test below refuses any source-scoped rule.

Deploy, Update config, Update, console start and Remove now open and close the port. The helper
runs for real here (fake ufw / firewalld binaries); the wiring into the five paths is checked on
the source.
"""

import ast
import os
import pathlib
import stat
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _src(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def _assign(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def _ns(**extra):
    """The new helper plus the firewall helpers it sits on, exec'd from app.py."""
    parts = [_assign('CLOUDTAK_FW_WEB'), _src('_fw_allow'), _src('_fw_remove'),
             _src('_cloudtak_console_video_fw')]
    ns = {'subprocess': subprocess, '_sudo_wrap': lambda cmd: list(cmd), '_fw_backend': lambda: 'ufw'}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    ns.update(extra)   # a test's stand-ins win over the real helpers
    return ns


def _fake_fw(tmp_path, monkeypatch):
    """Fake `ufw` and `firewall-cmd` on PATH; every call is appended to calls.log."""
    log = tmp_path / 'calls.log'
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    for name in ('ufw', 'firewall-cmd'):
        p = bindir / name
        p.write_text(f'#!/bin/sh\necho "{name} $*" >> "{log}"\nexit 0\n')
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv('PATH', f'{bindir}{os.pathsep}{os.environ["PATH"]}')
    return log


def _calls(log):
    return log.read_text().splitlines() if log.exists() else []


REMOTE = {'target_mode': 'remote', 'remote': {'host': '10.0.0.77'}}
LOCAL = {'target_mode': 'local'}


# ── the behaviour: open for a remote CloudTAK, close on Remove ──────────────────────────────

def test_a_remote_cloudtak_gets_9997_opened_on_the_console_for_everyone(tmp_path, monkeypatch):
    log = _fake_fw(tmp_path, monkeypatch)
    logs = []
    assert _ns()['_cloudtak_console_video_fw'](REMOTE, 'allow', log_fn=logs.append) is True
    assert _calls(log) == ['ufw allow 9997/tcp']
    text = '\n'.join(logs)
    assert 'Video port 9997 opened' in text
    # the operator is told which CLOUD firewall rules the console box still needs
    assert 'TCP 443 and 9997' in text and 'security group' in text


def test_the_port_is_never_scoped_to_one_source(tmp_path, monkeypatch):
    """A rule for the remote host alone lets the lease succeed but blocks the player: CloudTAK
    hands the browser an HLS address on 9997 (red on two AWS boxes, ops #737)."""
    log = _fake_fw(tmp_path, monkeypatch)
    _ns()['_cloudtak_console_video_fw'](REMOTE, 'allow', log_fn=lambda m: None)
    assert all(' from ' not in c for c in _calls(log))
    src = _src('_cloudtak_console_video_fw')
    assert '_fw_allow_from' not in src and '_fw_allow(port' in src


def test_firewalld_gets_the_port_added(tmp_path, monkeypatch):
    log = _fake_fw(tmp_path, monkeypatch)
    ns = _ns(_fw_backend=lambda: 'firewalld')
    assert ns['_cloudtak_console_video_fw'](REMOTE, 'allow', log_fn=lambda m: None) is True
    assert 'firewall-cmd --zone=public --permanent --add-port=9997/tcp' in _calls(log)
    assert _calls(log)[-1] == 'firewall-cmd --reload'


def test_remove_closes_it(tmp_path, monkeypatch):
    log = _fake_fw(tmp_path, monkeypatch)
    logs = []
    assert _ns()['_cloudtak_console_video_fw'](REMOTE, 'remove', log_fn=logs.append) is True
    assert _calls(log) == ['ufw --force delete allow 9997/tcp']
    assert any('closed' in l for l in logs)


def test_allow_twice_runs_the_same_idempotent_command(tmp_path, monkeypatch):
    log = _fake_fw(tmp_path, monkeypatch)
    ns = _ns()
    ns['_cloudtak_console_video_fw'](REMOTE, 'allow', log_fn=lambda m: None)
    ns['_cloudtak_console_video_fw'](REMOTE, 'allow', log_fn=lambda m: None)
    assert _calls(log) == ['ufw allow 9997/tcp'] * 2


def test_a_local_cloudtak_is_left_to_its_own_deploy(tmp_path, monkeypatch):
    log = _fake_fw(tmp_path, monkeypatch)
    ns = _ns()
    assert ns['_cloudtak_console_video_fw'](LOCAL, 'allow', log_fn=lambda m: None) is True
    assert ns['_cloudtak_console_video_fw'](LOCAL, 'remove', log_fn=lambda m: None) is True
    assert _calls(log) == []


def test_no_firewall_on_the_box_is_fine(tmp_path, monkeypatch):
    _fake_fw(tmp_path, monkeypatch)
    ns = _ns(_fw_backend=lambda: None)
    assert ns['_cloudtak_console_video_fw'](REMOTE, 'allow', log_fn=lambda m: None) is True


def test_a_failed_open_is_reported_not_raised():
    logs = []
    ns = _ns(_fw_allow=lambda port, proto='tcp': (False, 'ERROR: not root'))
    assert ns['_cloudtak_console_video_fw'](REMOTE, 'allow', log_fn=logs.append) is False
    assert any('Could not open video port 9997' in l and 'not root' in l for l in logs)


def test_a_firewall_error_never_raises():
    def boom(*a, **k):
        raise RuntimeError('ufw exploded')
    logs = []
    ns = _ns(_fw_allow=boom, _fw_remove=boom)
    assert ns['_cloudtak_console_video_fw'](REMOTE, 'allow', log_fn=logs.append) is False
    assert ns['_cloudtak_console_video_fw'](REMOTE, 'remove', log_fn=logs.append) is False
    assert sum('skipped' in l for l in logs) == 2


def test_the_port_is_the_one_cloudtak_always_calls():
    assert _ns()['CLOUDTAK_FW_WEB'] == ((9997, 'tcp'),)


# ── the wiring: every path that sets up, changes or removes a remote CloudTAK ───────────────

CALL_ALLOW = "_cloudtak_console_video_fw(cfg, 'allow'"


def test_remote_deploy_opens_the_port_after_the_port_lock_and_before_the_containers_start():
    src = _src('run_cloudtak_deploy')
    guard = src.index('_remote_cloudtak_port_guard(cfg, settings, log_fn=plog)')
    call = src.index(CALL_ALLOW)
    step5 = src.index('Step 5/6: Building/Starting remote containers')
    assert guard < call < step5
    assert src.count(CALL_ALLOW) == 1


def test_update_config_reapplies_it_after_the_port_lock():
    src = _src('run_cloudtak_redeploy')
    guard = src.index('_remote_cloudtak_port_guard(cfg, settings, log_fn=plog)')
    assert guard < src.index(CALL_ALLOW)
    assert src.count(CALL_ALLOW) == 1


def test_update_reapplies_it_after_the_port_lock_in_its_remote_branch():
    src = _src('run_cloudtak_update')
    guard = src.index('_remote_cloudtak_port_guard(cfg, settings, log_fn=plog)')
    call = src.index(CALL_ALLOW)
    assert guard < call
    assert src.count(CALL_ALLOW) == 1
    assert src.rindex('if is_remote:', 0, call) > src.rindex('else:', 0, call) - 4000   # in the remote branch


def test_remove_closes_it_for_a_remote_target():
    src = _src('_cloudtak_close_firewall')
    assert "cfg.get('target_mode') == 'remote'" in src
    assert "_cloudtak_console_video_fw(cfg, 'remove'" in src


def test_console_start_opens_it_for_an_already_deployed_remote_cloudtak():
    src = _src('_startup_cloudtak_remote_video_fw')
    assert "cfg.get('target_mode') != 'remote' or not cfg.get('deployed')" in src
    assert "_cloudtak_console_video_fw(cfg, 'allow'" in src
    assert '\n_startup_cloudtak_remote_video_fw()\n' in APP
