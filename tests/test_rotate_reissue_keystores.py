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
"""Rotate Intermediate CA really rewrites each NAME.p12, and refreshes what caches the cert.

makeCert.sh imports into NAME.jks and then NAME.p12 with `keytool -importkeystore -alias NAME`.
On an existing store keytool asks before overwriting; the single `echo "y"` reaches only the
first one, so NAME.p12 kept the cert from the CA it was first made with (ops #96: test8's
admin.p12 on INT-CA-08 after three rotations, TAK Portal and CloudTAK failing 8089).
"""

import ast
import os
import pathlib
import shlex

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


class FakeBox:
    """The cert dir, plus makeCert.sh's keytool behaviour: an existing store is never overwritten."""

    def __init__(self, cert_dir, makecert_ok=True):
        self.dir = cert_dir
        self.makecert_ok = makecert_ok
        self.cmds = []

    def run(self, cmd):
        self.cmds.append(cmd)
        if 'makeCert.sh' in cmd:
            if not self.makecert_ok:
                return False
            argv = shlex.split(cmd.split('makeCert.sh', 1)[1].split('2>&1')[0])
            name = argv[1]
            (self.dir / f'{name}.pem').write_text('NEW')
            for ext in ('.jks', '.p12'):
                p = self.dir / f'{name}{ext}'
                if not p.exists():          # keytool: "overwrite? [no]" on EOF keeps the old one
                    p.write_text('NEW')
            return True
        argv = shlex.split(cmd)
        if argv[:2] == ['mv', '-f']:
            os.replace(argv[2], argv[3])
            return True
        if argv[:2] == ['rm', '-f']:
            pathlib.Path(argv[2]).unlink(missing_ok=True)
            return True
        raise AssertionError(f'unexpected command {cmd!r}')


def _reissue(box, kind, name):
    ns = {'os': os, 'shlex': shlex, '_exists_priv': os.path.exists}
    exec(compile(_func('_rotate_reissue_cert'), 'app.py', 'exec'), ns)
    return ns['_rotate_reissue_cert'](kind, name, box.run, str(box.dir))


@pytest.fixture
def issued_before(tmp_path):
    for ext in ('.pem', '.jks', '.p12', '.key'):
        (tmp_path / f'admin{ext}').write_text('OLD')
    return tmp_path


def test_the_reissue_rewrites_the_p12_not_just_the_pem(issued_before):
    box = FakeBox(issued_before)
    assert _reissue(box, 'client', 'admin') is True
    for ext in ('.pem', '.jks', '.p12'):
        assert (issued_before / f'admin{ext}').read_text() == 'NEW', ext


def test_without_moving_aside_the_fake_keeps_the_old_p12(issued_before):
    """Guards the fake itself: makeCert alone reproduces the field bug."""
    box = FakeBox(issued_before)
    box.run('cd /opt/tak/certs && echo "y" | runuser -u tak -- /opt/tak/certs/makeCert.sh client admin 2>&1')
    assert (issued_before / 'admin.pem').read_text() == 'NEW'
    assert (issued_before / 'admin.p12').read_text() == 'OLD'


def test_no_reissue_leftovers_on_success(issued_before):
    _reissue(FakeBox(issued_before), 'client', 'admin')
    assert not [f for f in os.listdir(issued_before) if f.endswith('.reissue')]


def test_a_failed_makecert_puts_the_old_keystores_back(issued_before):
    box = FakeBox(issued_before, makecert_ok=False)
    assert _reissue(box, 'client', 'admin') is False
    assert (issued_before / 'admin.p12').read_text() == 'OLD'
    assert (issued_before / 'admin.jks').read_text() == 'OLD'
    assert not [f for f in os.listdir(issued_before) if f.endswith('.reissue')]


def test_a_first_issue_with_no_keystores_moves_nothing(tmp_path):
    box = FakeBox(tmp_path)
    assert _reissue(box, 'client', 'newbie') is True
    assert not any(c.startswith('mv') for c in box.cmds)
    assert (tmp_path / 'newbie.p12').read_text() == 'NEW'


def test_the_keystores_are_moved_before_makecert_runs(issued_before):
    box = FakeBox(issued_before)
    _reissue(box, 'server', 'takserver')  # no takserver files: nothing to move
    box.cmds.clear()
    _reissue(box, 'client', 'admin')
    mk = next(i for i, c in enumerate(box.cmds) if 'makeCert.sh' in c)
    assert [c for c in box.cmds[:mk] if c.startswith('mv')] and 'makeCert.sh client admin' in box.cmds[mk]


def test_a_cert_name_is_shell_quoted(tmp_path):
    box = FakeBox(tmp_path)
    _reissue(box, 'client', 'odd name')
    assert "makeCert.sh client 'odd name'" in ''.join(box.cmds)


def test_rotate_reissues_server_and_clients_through_the_helper():
    body = _func('takserver_rotate_intca')
    assert "_rotate_reissue_cert('server', 'takserver', run, cert_dir)" in body
    assert "_rotate_reissue_cert('client', name, run, cert_dir)" in body
    assert 'makeCert.sh client' not in body, 'rotate calls makeCert directly again'
    assert 'makeCert.sh server' not in body, 'rotate calls makeCert directly again'


def test_rotate_refreshes_integrations_after_the_tak_restart():
    body = _func('takserver_rotate_intca')
    assert body.index("run('systemctl restart takserver 2>&1')") < body.index('_rotate_refresh_integrations(log)')
    assert body.index('_rotate_refresh_integrations(log)') < body.index('ROTATION COMPLETE')


class _Done:
    def __init__(self, rc=0, out=''):
        self.returncode, self.stdout, self.stderr = rc, out, ''


def _refresh(nodered_running, heal=None):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        if argv[:2] == ['docker', 'ps']:
            return _Done(0, 'abc123\n' if nodered_running else '')
        return _Done(0)

    class _SP:
        run = staticmethod(fake_run)
    healed = []
    ns = {'subprocess': _SP, '_sudo_wrap': lambda a: list(a),
          '_cloudtak_tak_cert_heal': heal or (lambda log=None: healed.append(True))}
    exec(compile(_func('_rotate_refresh_integrations'), 'app.py', 'exec'), ns)
    logs = []
    ns['_rotate_refresh_integrations'](logs.append)
    return calls, healed, logs


def test_a_running_nodered_is_restarted_and_cloudtak_checked():
    calls, healed, logs = _refresh(True)
    assert ['docker', 'restart', 'nodered'] in calls
    assert healed == [True]


def test_no_nodered_no_restart():
    calls, healed, _ = _refresh(False)
    assert ['docker', 'restart', 'nodered'] not in calls
    assert healed == [True]


def test_a_cloudtak_heal_error_does_not_fail_the_rotation():
    def boom(log=None):
        raise RuntimeError('cloudtak down')
    _, _, logs = _refresh(True, heal=boom)
    assert any('CloudTAK cert check skipped' in m for m in logs)
