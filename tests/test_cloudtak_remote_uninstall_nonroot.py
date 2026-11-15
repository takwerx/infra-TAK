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
"""Remote CloudTAK Remove works for a non-root SSH user (ops #740).

Field (AWS test boxes, Fri Nov 13, 2026): the Garage store container writes
~/CloudTAK/.docker-garage as root. On a remote host reached as `ubuntu`, the uninstall's last
step `rm -rf ~/CloudTAK` failed with "Permission denied", the uninstall returned early, and the
firewall cleanup and the console's "deployed" flag never ran.

The test takes the shell command that cloudtak_uninstall() really sends over SSH and runs it in
bash with shims for `rm` (refuses unless elevated, like root-owned files), `sudo` and `docker`.
"""

import ast
import os
import pathlib
import stat
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _remote_uninstall_command():
    """The command string passed to _ssh_probe() inside cloudtak_uninstall()'s remote branch."""
    tree = ast.parse(APP)
    consts = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            consts[n.targets[0].id] = n.value
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'cloudtak_uninstall')
    for call in ast.walk(fn):
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                and call.func.id == '_ssh_probe' and len(call.args) >= 2):
            arg = call.args[1]
            if isinstance(arg, ast.Name):
                arg = consts[arg.id]
            return ast.literal_eval(arg)
    raise AssertionError('cloudtak_uninstall() has no remote _ssh_probe call')


def _shim(path, body):
    path.write_text('#!/bin/bash\n' + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _run(tmp_path, sudo_ok=True, root_owned=True):
    """Run the remote uninstall command against a fake ~/CloudTAK. Returns (proc, home, sudo_calls)."""
    home = tmp_path / 'home'
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    (home / 'CloudTAK' / '.docker-garage' / 'data').mkdir(parents=True)
    (home / 'CloudTAK' / '.docker-garage' / 'data' / 'garage-marker').write_text('x')
    log = tmp_path / 'sudo.log'
    # `rm` refuses while "root-owned" files exist unless elevated (sudo sets ELEVATED=1).
    _shim(bindir / 'rm',
          'if [ "$ELEVATED" != 1 ] && [ "%s" = 1 ]; then\n'
          '  echo "rm: cannot remove \'$HOME/CloudTAK/.docker-garage/data/garage-marker\': Permission denied" >&2\n'
          '  exit 1\nfi\nexec /bin/rm "$@"\n' % ('1' if root_owned else '0'))
    if sudo_ok:
        _shim(bindir / 'sudo', 'echo "sudo $*" >> "%s"\nshift  # -n\nELEVATED=1 exec "$@"\n' % log)
    else:
        _shim(bindir / 'sudo', 'echo "sudo $*" >> "%s"\n'
              'echo "sudo: a password is required" >&2\nexit 1\n' % log)
    _shim(bindir / 'docker', 'exit 0\n')
    env = {'HOME': str(home), 'PATH': f'{bindir}:/usr/bin:/bin', 'TERM': 'dumb'}
    proc = subprocess.run(['bash', '-c', _remote_uninstall_command()], env=env,
                          capture_output=True, text=True, timeout=30)
    calls = log.read_text().splitlines() if log.exists() else []
    return proc, home, calls


def test_non_root_user_removes_root_owned_garage_data_with_sudo(tmp_path):
    proc, home, calls = _run(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert not (home / 'CloudTAK').exists()
    assert calls and 'rm -rf' in calls[0]


def test_plain_remove_does_not_need_sudo(tmp_path):
    proc, home, calls = _run(tmp_path, root_owned=False)
    assert proc.returncode == 0, proc.stderr
    assert not (home / 'CloudTAK').exists()
    assert calls == []


def test_no_sudo_fails_with_a_message_that_says_what_to_do(tmp_path):
    proc, home, calls = _run(tmp_path, sudo_ok=False)
    assert proc.returncode != 0
    assert (home / 'CloudTAK').exists()
    assert 'passwordless sudo' in proc.stderr and 'sudo rm -rf ~/CloudTAK' in proc.stderr
