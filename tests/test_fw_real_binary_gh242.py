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
"""Firewall detection sees the real ufw, not the broker shim; a missing ufw is installed (GH #242).

Field, Armbian 26.8 (ARM64): no ufw on the box, yet the non-root console's .shims dir — first
on PATH — holds a ufw shim on every box, so `command -v ufw` said yes. The Firewall page drove
the shim and the broker failed `FileNotFoundError: 'ufw'`; Cyber Controls showed "UFW installed
but not enabled". Nothing on the Debian path ever installed ufw.
"""

import ast
import importlib.util
import os
import pathlib
import re
import shutil
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(APP)


def _fn(name):
    for n in _TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} not found in app.py')


def _ns(*names, **extra):
    ns = {'os': os, 'shutil': shutil, 'subprocess': types.SimpleNamespace(
        run=lambda *a, **k: (_ for _ in ()).throw(AssertionError(f'unexpected subprocess {a}')))}
    ns.update(extra)
    exec(compile('\n\n'.join(_fn(n) for n in names), 'app.py', 'exec'), ns)
    return ns


FAKE = 'takwerx-gh242-fake-fw'


def _exe(d, name):
    p = d / name
    p.write_text('#!/bin/sh\nexit 0\n')
    p.chmod(0o755)


def test_a_shim_alone_is_not_the_real_binary(tmp_path, monkeypatch):
    shims = tmp_path / '.shims'
    shims.mkdir()
    _exe(shims, FAKE)
    monkeypatch.setenv('PATH', f'{shims}{os.pathsep}/usr/bin{os.pathsep}/bin')
    ns = _ns('_host_has_bin', _BROKER_SHIM_DIR=str(shims))
    assert shutil.which(FAKE) is not None          # what `command -v` saw
    assert ns['_host_has_bin'](FAKE) is False


def test_the_real_binary_behind_the_shim_is_found(tmp_path, monkeypatch):
    shims, real = tmp_path / '.shims', tmp_path / 'sbin'
    shims.mkdir(); real.mkdir()
    _exe(shims, FAKE); _exe(real, FAKE)
    monkeypatch.setenv('PATH', f'{shims}{os.pathsep}{real}')
    ns = _ns('_host_has_bin', _BROKER_SHIM_DIR=str(shims))
    assert ns['_host_has_bin'](FAKE) is True


def _backend(family, have):
    return _ns('_fw_backend', _host_has_bin=lambda b: b in have,
               _distro_family=lambda: family)['_fw_backend']()


@pytest.mark.parametrize('family,have,want', [
    ('debian', set(), None),                       # Armbian: nothing installed
    ('debian', {'ufw'}, 'ufw'),
    ('debian', {'ufw', 'firewall-cmd'}, 'ufw'),
    ('rhel', {'firewall-cmd'}, 'firewalld'),
    ('rhel', set(), None),
])
def test_backend_follows_real_binaries(family, have, want):
    assert _backend(family, have) == want


def test_no_backend_reports_unsupported_without_running_ufw():
    st = _ns('_firewall_status_local', _fw_backend=lambda: None)['_firewall_status_local']()
    assert st['supported'] is False and 'No supported firewall' in st['error']


def test_firewall_detection_no_longer_uses_command_v():
    for name in ('_fw_backend', '_firewall_status_local', '_fw_ensure_installed'):
        assert 'command -v' not in re.sub(r'#.*', '', _fn(name)), name


def _ensure(family, have):
    calls = []
    installed = set(have)

    def pkg_install(pkgs, log_fn=None, timeout=None, **k):
        calls.append(list(pkgs))
        installed.add('ufw')
        return True, ''
    ns = _ns('_fw_ensure_installed', _host_has_bin=lambda b: b in installed,
             _distro_family=lambda: family, _pkg_install=pkg_install,
             _pkg_lock_wait=lambda **k: True, _fw_backend=lambda: 'ufw' if 'ufw' in installed else None,
             _sudo_wrap=lambda c: (_ for _ in ()).throw(AssertionError(f'unexpected priv op {c}')))
    logs = []
    be = ns['_fw_ensure_installed'](log=logs.append)
    return be, calls, logs


def test_debian_without_ufw_installs_it_without_removing_anything_or_enabling():
    be, calls, logs = _ensure('debian', set())
    assert calls == [['--no-remove', 'ufw']]
    assert be == 'ufw'
    assert any('not enabled' in l for l in logs)


def test_debian_with_ufw_installs_nothing():
    assert _ensure('debian', {'ufw'})[1] == []


def test_debian_on_firewalld_is_left_alone():
    assert _ensure('debian', {'firewall-cmd'})[1] == []


def test_broker_allows_the_no_remove_install():
    spec = importlib.util.spec_from_file_location('takwerx_broker_gh242_test',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    broker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(broker)
    broker._check_pkgmgr(['apt-get', 'install', '-y', '--no-remove', 'ufw'])


def test_startup_and_both_tak_deploys_ensure_ufw():
    assert 'threading.Thread(target=_startup_ensure_debian_ufw, daemon=True).start()' in APP
    assert APP.count("_fw_ensure_installed(log=log_step)   # GH #242") == 2
    for m in re.finditer(r"_fw_ensure_installed\(log=log_step\)", APP):
        assert "ufw --force enable" in APP[m.end():m.end() + 400]


def test_start_sh_installs_missing_ufw_on_apt():
    sh = (REPO / 'start.sh').read_text(encoding='utf-8')
    assert 'apt-get install -y --no-remove ufw' in sh
