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
"""Fail2ban Install works on a RHEL-family console box with no EPEL (ops #1006).

fail2ban is in EPEL on Rocky/RHEL 9. Only the TAK Server database step added EPEL, so on
a console-only box (no TAK Server yet) the Fail2ban page's Install failed with
"Unable to find a match: fail2ban". The install step now enables EPEL first.

The shipped functions run from app.py text against a fake system whose dnf has no
fail2ban until EPEL is installed.
"""

import ast
import io
import os as _real_os
import pathlib
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

EPEL_URL = 'https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm'
EPEL_URL_10 = 'https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm'


def _func(name, required=True):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    if required:
        raise AssertionError(f'{name} was renamed or removed')
    return None


class FakeBox:
    """A box whose package manager only knows fail2ban once EPEL is installed."""

    def __init__(self, family, epel=False, epel_release_pkg=True, version_id='9.4'):
        self.family = family            # 'rhel' | 'debian'
        self.version_id = version_id    # what this box's /etc/os-release says
        self.epel = epel
        self.epel_release_pkg = epel_release_pkg   # False = genuine RHEL (URL only)
        self.fail2ban = False
        self.cmds = []

    def run(self, cmd, **kw):
        cmd = list(cmd)
        self.cmds.append(cmd)
        out = lambda rc, err='': types.SimpleNamespace(returncode=rc, stdout='', stderr=err)
        if cmd[:3] == ['rpm', '-q', 'epel-release']:
            return out(0 if self.epel else 1)
        if cmd[0] in ('dnf', 'yum') and cmd[1] == 'install':
            args = [a for a in cmd[2:] if not a.startswith('-')]
            if self.family != 'rhel':
                return out(1, 'dnf: command not found')
            ok = True
            for a in args:
                if a == 'epel-release':
                    if not self.epel_release_pkg:
                        return out(1, 'Error: Unable to find a match: epel-release')
                    self.epel = True
                elif a in (EPEL_URL, EPEL_URL_10):
                    self.epel = True
                elif a == 'fail2ban':
                    if self.epel:
                        self.fail2ban = True
                    else:
                        return out(1, 'Error: Unable to find a match: fail2ban')
                else:
                    ok = False
            return out(0 if ok else 1)
        if cmd[0] == 'apt-get' and cmd[1] == 'install':
            if self.family != 'debian':
                return out(1, 'apt-get: command not found')
            if 'fail2ban' in cmd:
                self.fail2ban = True
            return out(0)
        return out(1, 'not faked')


def _ns(box):
    settings = {
        'pkg_mgr': 'dnf' if box.family == 'rhel' else 'apt',
        'os_type': 'rocky-9' if box.family == 'rhel' else 'ubuntu-22.04',
        'authentik_trusted_proxy_cidrs_fix': {'last_outcome': 'applied'},
    }

    class _Path:
        @staticmethod
        def exists(p):
            return True          # ~/authentik/.env is there

        def __getattr__(self, name):
            return getattr(_real_os.path, name)

    class _Os:
        path = _Path()

        def __getattr__(self, name):
            return getattr(_real_os, name)

    def fake_open(path, *a, **kw):
        # The code reads /etc/os-release for the EL major version. CI runs on Ubuntu
        # (VERSION_ID 24.04), so without this the test would ask for epel-...-24.
        if path == '/etc/os-release':
            return io.StringIO(f'ID=rocky\nVERSION_ID="{box.version_id}"\n')
        return open(path, *a, **kw)

    fake_subprocess = types.SimpleNamespace(run=box.run, TimeoutExpired=Exception)
    ns = {'os': _Os(), 'subprocess': fake_subprocess, 'open': fake_open,
          'load_settings': lambda: settings, 'save_settings': lambda s: None,
          '_sudo_wrap': lambda cmd: list(cmd)}
    for name in ('_distro_family', '_pkg_mgr', '_pkg_install', '_pkg_ensure_epel',
                 '_fail2ban_install_and_configure'):
        src = _func(name, required=(name != '_pkg_ensure_epel'))
        if src:
            exec(src, ns)
    return ns


def _run_install(box):
    ns = _ns(box)
    log = []
    try:
        ns['_fail2ban_install_and_configure'](log.append)
    except Exception:
        pass    # the later steps (jails, services) are not faked; only the package step matters
    return log


def test_rocky_console_only_box_installs_fail2ban_by_enabling_epel():
    """The reported case: Rocky 9, no EPEL. Red on base: dnf has no fail2ban."""
    box = FakeBox('rhel', epel=False)
    log = _run_install(box)
    assert box.fail2ban, f'fail2ban was not installed; log: {log}'
    assert box.epel
    assert not any('FAILED' in l for l in log), log


def test_genuine_rhel_without_epel_release_package_uses_the_fedora_rpm():
    box = FakeBox('rhel', epel=False, epel_release_pkg=False)
    log = _run_install(box)
    assert box.fail2ban, f'fail2ban was not installed; log: {log}'
    assert ['dnf', 'install', '-y', EPEL_URL] in box.cmds, box.cmds


def test_genuine_rhel_10_asks_for_the_el10_epel_rpm():
    """The EPEL rpm URL follows this box's major version, not a fixed 9."""
    box = FakeBox('rhel', epel=False, epel_release_pkg=False, version_id='10.0')
    _run_install(box)
    assert box.fail2ban
    assert ['dnf', 'install', '-y', EPEL_URL_10] in box.cmds, box.cmds


def test_epel_already_present_is_left_alone():
    box = FakeBox('rhel', epel=True)
    _run_install(box)
    assert box.fail2ban
    assert not any('epel-release' in ' '.join(c) and c[0] != 'rpm' for c in box.cmds), box.cmds


def test_ubuntu_box_never_touches_epel():
    box = FakeBox('debian')
    _run_install(box)
    assert box.fail2ban
    assert not any('epel' in ' '.join(c) for c in box.cmds), box.cmds
    assert not any(c[0] in ('dnf', 'yum', 'rpm') for c in box.cmds), box.cmds


def test_a_failed_install_is_reported_not_hidden():
    """If EPEL cannot be reached the install still says why it failed."""
    box = FakeBox('rhel', epel=False, epel_release_pkg=False)
    box.run_orig = box.run

    def no_url(cmd, **kw):
        if EPEL_URL in cmd:
            box.cmds.append(list(cmd))
            return types.SimpleNamespace(returncode=1, stdout='', stderr='network down')
        return box.run_orig(cmd, **kw)

    box.run = no_url
    log = _run_install(box)
    assert not box.fail2ban
    assert any('FAILED' in l for l in log), log
