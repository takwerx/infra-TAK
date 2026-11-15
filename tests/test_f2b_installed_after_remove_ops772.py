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
"""Fail2ban must read "not installed" after the Remove button (ops #772).

On the non-root console a fail2ban-client shim sits first on PATH whether or not the package
exists, so `which fail2ban-client` always succeeds. `apt-get remove` / `yum remove` also keep
/etc/fail2ban. The old check (`/etc/fail2ban` exists AND `which` succeeds) therefore kept
saying "installed" after Remove, and Install then refused with "already installed".
The functions run from the shipped app.py text.
"""

import ast
import os
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _seg(node):
    return ast.get_source_segment(APP, node)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return _seg(n)
    raise AssertionError(f'{name} was renamed or removed')


def _const(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return _seg(n)
    raise AssertionError(f'{name} was renamed or removed')


def _ns(fake_fs):
    """Namespace with the shipped helper and a fake filesystem.

    fake_fs maps path -> 'dir' or 'file'. Anything else does not exist."""
    class _Path:
        @staticmethod
        def isdir(p):
            return fake_fs.get(p) == 'dir'

        @staticmethod
        def isfile(p):
            return fake_fs.get(p) == 'file'

        @staticmethod
        def exists(p):
            return p in fake_fs

    fake_os = type('os', (), {'path': _Path})
    ns = {'os': fake_os}
    exec(_const('_F2B_REAL_CLIENT_PATHS'), ns)
    exec(_func('_f2b_installed'), ns)
    exec(_func('_f2b_is_available'), ns)
    return ns


SHIM = '/opt/infratak/.shims/fail2ban-client'


def test_removed_package_with_shim_and_kept_config_is_not_installed():
    """The #772 box: package gone (dpkg state rc), /etc/fail2ban kept, shim still there."""
    ns = _ns({'/etc/fail2ban': 'dir', SHIM: 'file'})
    assert ns['_f2b_installed']() is False
    assert ns['_f2b_is_available']() is False


def test_installed_package_is_installed():
    for client in ('/usr/bin/fail2ban-client', '/usr/sbin/fail2ban-client'):
        ns = _ns({'/etc/fail2ban': 'dir', client: 'file', SHIM: 'file'})
        assert ns['_f2b_installed']() is True, client
        assert ns['_f2b_is_available']() is True, client


def test_never_installed_is_not_installed():
    ns = _ns({SHIM: 'file'})
    assert ns['_f2b_installed']() is False


def test_binary_without_config_dir_is_not_installed():
    ns = _ns({'/usr/bin/fail2ban-client': 'file'})
    assert ns['_f2b_installed']() is False


def test_the_shim_folder_is_never_a_real_client_path():
    ns = _ns({})
    assert not any('.shims' in p for p in ns['_F2B_REAL_CLIENT_PATHS'])


def test_every_installed_check_uses_the_helper():
    """The card, the sidebar, the page, the Cyber Controls row and the Install guard all
    ask the helper. None may go back to `which` or to the bare config directory."""
    detect = _func('_detect_modules_uncached')
    assert "which', 'fail2ban-client'" not in detect
    assert '_f2b_installed()' in detect
    assert "os.path.exists('/etc/fail2ban')" not in _func('fail2ban_page')
    assert '_f2b_installed()' in _func('fail2ban_page')
    assert 'return _f2b_installed()' in _func('_f2b_is_available')
    # sidebar and Cyber Controls: no function should gate on the bare directory any more,
    # except the two post-install steps that run after the package is already in place.
    bare = [n.name for n in TREE.body if isinstance(n, ast.FunctionDef)
            and "os.path.exists('/etc/fail2ban')" in _seg(n)]
    assert sorted(bare) == ['_fail2ban_add_guarddog_hook', '_fail2ban_takserver_filter'], bare
