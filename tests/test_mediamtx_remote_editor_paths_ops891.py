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
"""The remote MediaMTX web editor must not crash-loop after a deploy (ops #891).

The editor unit runs as takwerx. Its upstream code calls os.makedirs(
'/usr/local/etc/mediamtx_backups') at import, and `/usr/local/etc` is root:root 755 on a
fresh host, so it died with PermissionError and systemd restarted it forever (port 5080
never listened). The local deploy sets this up (_mediamtx_grant_config_dir_write); the
remote deploy did not, and printed "Services started" without looking.

The shell scripts run for real under `sh` against fake mkdir / chown / chmod / sudo /
systemctl / ss binaries that record what they were asked, so the tests check what the host
would be told to do, not only which strings the code holds.
"""

import ast
import os
import pathlib
import re
import stat
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _src(*names):
    """Top-level defs/assignments from app.py, in file order. A name app.py does not have
    is skipped, so on unfixed code the missing helper fails the test by name."""
    parts = []
    for n in TREE.body:
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names:
            parts.append(ast.get_source_segment(APP, n))
        elif isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in names for t in n.targets):
            parts.append(ast.get_source_segment(APP, n))
    return '\n\n'.join(parts)


def _ns(names, **extra):
    ns = {'re': re, 'os': os}
    ns.update(extra)
    exec(compile(_src(*names), 'app.py', 'exec'), ns)
    return ns


def _func_src(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} not found in app.py')


def _write(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# ── fake remote host ───────────────────────────────────────────────────────────────

_RECORD = '#!/bin/sh\necho "{name} $*" >> "$FAKE/calls"\n[ -f "$FAKE/{name}_fails" ] && exit 1\nexit 0\n'
_SUDO = '#!/bin/sh\n[ -f "$FAKE/sudo_fails" ] && exit 1\n[ "$1" = "-n" ] && shift\nexec "$@"\n'
# is-active reads the state file; journalctl prints what the crash loop printed.
_SYSTEMCTL = ('#!/bin/sh\necho "systemctl $*" >> "$FAKE/calls"\n'
              'if [ "$1" = is-active ]; then cat "$FAKE/editor_state"; exit 0; fi\nexit 0\n')
_SS = '#!/bin/sh\n[ -f "$FAKE/listening" ] && echo "LISTEN 0 128 0.0.0.0:5080 0.0.0.0:*"\nexit 0\n'
_JOURNAL = ('#!/bin/sh\necho "journalctl $*" >> "$FAKE/calls"\n'
            "echo \"PermissionError: [Errno 13] Permission denied: '/usr/local/etc/mediamtx_backups'\"\n")


class Host:
    def __init__(self, tmp, root=True):
        self.d = tmp
        (tmp / 'bin').mkdir()
        (tmp / 'calls').write_text('')
        (tmp / 'editor_state').write_text('active\n')
        for name in ('mkdir', 'chown', 'chmod'):
            _write(tmp / 'bin' / name, _RECORD.format(name=name))
        _write(tmp / 'bin' / 'sudo', _SUDO)
        _write(tmp / 'bin' / 'systemctl', _SYSTEMCTL)
        _write(tmp / 'bin' / 'ss', _SS)
        _write(tmp / 'bin' / 'journalctl', _JOURNAL)
        _write(tmp / 'bin' / 'sleep', '#!/bin/sh\nexit 0\n')
        _write(tmp / 'bin' / 'id', f'#!/bin/sh\necho {0 if root else 1000}\n')
        # `[ -f /usr/local/etc/mediamtx.yml ]` is a shell builtin on the real path: the
        # script is rewritten to look at a file inside the fake root instead.
        (tmp / 'mediamtx.yml').write_text('logLevel: info\n')

    def flag(self, name):
        (self.d / name).write_text('')

    def run(self, script):
        script = script.replace('/usr/local/etc/mediamtx.yml', str(self.d / 'mediamtx.yml'))
        env = {'PATH': f'{self.d / "bin"}:/usr/bin:/bin', 'FAKE': str(self.d)}
        r = subprocess.run(['sh', '-c', script], env=env, capture_output=True, text=True, timeout=30)
        return r.returncode == 0, (r.stdout or '') + (r.stderr or '')

    def calls(self):
        return (self.d / 'calls').read_text().splitlines()


def _prepare_sh():
    ns = _ns(('_REMOTE_SUDO_SH', '_MEDIAMTX_REMOTE_EDITOR_PATHS_SH'))
    return ns['_MEDIAMTX_REMOTE_EDITOR_PATHS_SH']


def _check_sh():
    ns = _ns(('_REMOTE_SUDO_SH', '_MEDIAMTX_REMOTE_EDITOR_CHECK_SH'))
    return ns['_MEDIAMTX_REMOTE_EDITOR_CHECK_SH']


# ── 1. the setup the editor needs before it starts ─────────────────────────────────

def test_remote_setup_makes_the_backup_dir_and_hands_it_to_takwerx(tmp_path):
    """The bug: nothing on the remote host made /usr/local/etc/mediamtx_backups for takwerx."""
    host = Host(tmp_path)
    ok, out = host.run(_prepare_sh())
    calls = host.calls()
    assert ok and 'EDITOR_PATHS_RC=0' in out, out
    assert 'mkdir -p /usr/local/etc/mediamtx_backups' in calls
    assert any(c.startswith('chown -R takwerx:takwerx') and '/usr/local/etc/mediamtx_backups' in c
               and '/opt/mediamtx-webeditor' in c for c in calls), calls
    # The editor saves with `sed -i`, which writes a temp file in the config folder.
    assert 'chown root:takwerx /usr/local/etc' in calls
    assert 'chmod 775 /usr/local/etc' in calls
    assert any(c.startswith('chown -h takwerx:takwerx') and c.endswith('mediamtx.yml') for c in calls), calls


def test_remote_setup_uses_sudo_for_a_non_root_ssh_user(tmp_path):
    """A non-root SSH user (sudo -n) must get the same setup, not a silent skip."""
    host = Host(tmp_path, root=False)
    ok, out = host.run(_prepare_sh())
    assert ok and 'EDITOR_PATHS_RC=0' in out, out
    assert 'mkdir -p /usr/local/etc/mediamtx_backups' in host.calls()


def test_remote_setup_reports_failure_when_a_step_fails(tmp_path):
    """No sudo for the SSH user: say so (RC=1), never print a clean RC=0."""
    host = Host(tmp_path, root=False)
    host.flag('sudo_fails')
    ok, out = host.run(_prepare_sh())
    assert 'EDITOR_PATHS_RC=1' in out, out
    assert 'EDITOR_PATHS_RC=0' not in out


def test_remote_setup_leaves_a_missing_yml_alone(tmp_path):
    """mediamtx.yml is written earlier in the deploy, but never fail the whole step on it."""
    host = Host(tmp_path)
    (tmp_path / 'mediamtx.yml').unlink()
    ok, out = host.run(_prepare_sh())
    assert 'EDITOR_PATHS_RC=0' in out, out
    assert not any(c.startswith('chown -h') for c in host.calls())


# ── 2. "started" is not "up": the check after the start ────────────────────────────

def test_check_passes_for_a_stable_listening_editor(tmp_path):
    host = Host(tmp_path)
    host.flag('listening')
    ok, out = host.run(_check_sh())
    assert 'EDITOR_OK=1' in out, out


def test_check_fails_for_a_crash_loop(tmp_path):
    """systemd shows `activating` between restarts of a crash-looping unit."""
    host = Host(tmp_path)
    (tmp_path / 'editor_state').write_text('activating\n')
    ok, out = host.run(_check_sh())
    assert 'EDITOR_OK=0' in out and 'EDITOR_OK=1' not in out, out
    assert 'mediamtx_backups' in out          # the journal tail reaches the deploy log


def test_check_fails_when_active_but_port_5080_is_not_listening(tmp_path):
    host = Host(tmp_path)          # `listening` flag not set: ss prints nothing
    ok, out = host.run(_check_sh())
    assert 'EDITOR_OK=0' in out, out


def test_check_wrapper_logs_the_truth(tmp_path):
    """The deploy log must say NOT running (with the reason) when the editor is down."""
    host = Host(tmp_path)
    (tmp_path / 'editor_state').write_text('activating\n')
    logs = []
    ns = _ns(('_REMOTE_SUDO_SH', '_MEDIAMTX_REMOTE_EDITOR_CHECK_SH', '_mediamtx_remote_editor_check'),
             _module_run=lambda cfg, cmd, timeout=120, log_fn=None: host.run(cmd))
    assert ns['_mediamtx_remote_editor_check']({}, logs.append) is False
    assert any('NOT running' in m for m in logs), logs
    assert any('PermissionError' in m for m in logs), logs

    (tmp_path / 'ok').mkdir()
    host2 = Host(tmp_path / 'ok')
    host2.flag('listening')
    logs2 = []
    ns2 = _ns(('_REMOTE_SUDO_SH', '_MEDIAMTX_REMOTE_EDITOR_CHECK_SH', '_mediamtx_remote_editor_check'),
              _module_run=lambda cfg, cmd, timeout=120, log_fn=None: host2.run(cmd))
    assert ns2['_mediamtx_remote_editor_check']({}, logs2.append) is True
    assert any('is running' in m for m in logs2), logs2


# ── 3. the remote deploy actually calls them, in the right order ───────────────────

def test_remote_deploy_prepares_before_the_start_and_checks_after_it():
    src = _func_src('_run_mediamtx_deploy_remote')
    prep = src.find('_mediamtx_remote_editor_prepare(')
    start = src.find("systemctl start mediamtx && systemctl start mediamtx-webeditor")
    started = src.find('✓ Services started')
    check = src.find('_mediamtx_remote_editor_check(')
    assert -1 not in (prep, start, started, check), (prep, start, started, check)
    assert prep < start, 'the editor folders must exist before the editor starts'
    assert started < check, 'the check must run after the start, not before it'
