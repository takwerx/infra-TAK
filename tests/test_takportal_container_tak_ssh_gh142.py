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
"""TAK Portal on a containerized TAK Server reports a known limitation, not a failure (GH #142).

TAK Portal's integration-user certs, TAK Server restart and plugin sync run
`sudo -u tak makeCert.sh` / `systemctl restart takserver` on the host, which only
exist with a native install. The deploy log used to end "SSH auto-setup failed —
configure manually in TAK Portal settings", sending the operator to configure by
hand something that cannot work.
"""

import ast
import os
import pathlib
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TPL = (REPO / 'templates' / 'takportal.html').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _func(name):
    for n in ast.walk(TREE):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _const(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _setup_ssh(monkeypatch, tmp_path, container, probe='direct'):
    home = tmp_path / 'home'
    key_dir = home / 'TAK-Portal' / 'data' / 'ssh'
    key_dir.mkdir(parents=True)
    (key_dir / 'tak_ssh_ed25519').write_text('priv')
    (key_dir / 'tak_ssh_ed25519.pub').write_text('ssh-ed25519 AAAA tak-portal-auto')
    monkeypatch.setenv('HOME', str(home))
    real_isdir = os.path.isdir
    monkeypatch.setattr(os.path, 'isdir', lambda p: p == '/opt/tak' or real_isdir(p))
    calls = {'probe': 0}

    def _probe():
        calls['probe'] += 1
        return probe, ''

    ns = {
        'os': os,
        'subprocess': types.SimpleNamespace(run=lambda *a, **k: types.SimpleNamespace(returncode=0, stdout='', stderr='')),
        '_takportal_ref': lambda: 'tak-portal',
        '_sudo_wrap': lambda c: c,
        '_takportal_push_settings': lambda restart=False: None,
        '_takportal_install_sudoers': lambda log_fn=None: (True, 'skipped'),
        '_takportal_ssh_probe': _probe,
        '_tak_is_container': lambda: container,
    }
    exec(compile(_const('TAKPORTAL_CONTAINER_TAK_NOTE') + '\n\n' + _func('_takportal_setup_ssh'), 'app.py', 'exec'), ns)
    log = []
    ok = ns['_takportal_setup_ssh'](log_fn=log.append)
    return ok, log, calls


@pytest.mark.parametrize('probe', ['direct', 'root'])
def test_container_tak_names_the_missing_extras_instead_of_failing(monkeypatch, tmp_path, probe):
    ok, log, _ = _setup_ssh(monkeypatch, tmp_path, container=True, probe=probe)
    text = '\n'.join(log)
    assert ok is False, 'even a root console cannot make the native-only commands exist'
    for feature in ('integration-user certs', 'restart TAK Server', 'sync plugins'):
        assert feature in text
    assert 'Users and QR' in text
    assert 'TAK-Portal/issues/61' in text
    assert '⚠' not in text and '✗' not in text and 'Verified end-to-end' not in text


def test_native_tak_still_verifies_and_warns(monkeypatch, tmp_path):
    ok, log, _ = _setup_ssh(monkeypatch, tmp_path, container=False, probe='nopasswd')
    assert ok is True and any('Verified end-to-end' in m for m in log)
    ok, log, _ = _setup_ssh(monkeypatch, tmp_path / 'b', container=False, probe='direct')
    assert ok is False and any('cannot issue integration-user certs' in m for m in log)
    assert not any('Docker' in m for m in log)


def test_deploy_log_does_not_say_failed_on_container_tak():
    src = APP[APP.index('Setting up SSH (container'):]
    src = src[:src.index('_takportal_restart()')]
    branch = src.index('_tak_is_container()')
    assert branch < src.index('SSH auto-setup failed'), 'container check must come before the failed line'


def test_status_card_and_repair_show_the_note():
    assert 'TAKPORTAL_CONTAINER_TAK_NOTE' in _func('takportal_ssh_status')
    repair = _func('takportal_ssh_repair')
    assert 'TAKPORTAL_CONTAINER_TAK_NOTE' in repair and "'note'" in repair
    assert 'd.note' in TPL
