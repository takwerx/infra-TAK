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
"""The console asks for a restart when a fixed kernel is installed but not running.

Field (test12, 2026-10-21): unattended-upgrades installed 5.15.0-198 on Oct 6,
nothing was left to download, so the OS-updates panel hid itself and the box ran
5.15.0-190 for 54 days with no prompt. `kernel-patch-status` called it patched.

app.py cannot be imported in a test, so the helper is cut out by its markers and
run against a faked /boot; the panel itself is driven by
scripts/check_kernel_reboot_banner.js.
"""

import os
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
START = '# --- ops #154: installed-but-not-running kernel'
END = '# --- end ops #154'
BLOCK = APP[APP.index(START):APP.index(END)]
FLAG = '/var/run/reboot-required'


@pytest.fixture
def box(monkeypatch):
    """Fake running kernel, /boot contents and reboot-required flag."""
    state = {'running': '', 'boot': [], 'flag': False, 'mtime': 1760000000}

    class _U:
        @property
        def release(self):
            return state['running']

    import glob as _glob
    monkeypatch.setattr(os, 'uname', lambda: _U())
    monkeypatch.setattr(_glob, 'glob', lambda pat: ['/boot/vmlinuz-' + v for v in state['boot']]
                        if pat == '/boot/vmlinuz-*' else [])
    real_exists, real_mtime = os.path.exists, os.path.getmtime
    monkeypatch.setattr(os.path, 'exists', lambda p: state['flag'] if p == FLAG else real_exists(p))
    monkeypatch.setattr(os.path, 'getmtime', lambda p: state['mtime'] if p == FLAG else real_mtime(p))
    ns = {'os': os, 're': re}
    exec(compile(BLOCK, 'app.py:ops154', 'exec'), ns)
    state['fn'] = ns['_kernel_reboot_state']
    state['key'] = ns['_kernel_version_key']
    return state


def test_test12_installed_198_running_190_needs_restart(box):
    box['running'] = '5.15.0-190-generic'
    box['boot'] = ['5.15.0-190-generic', '5.15.0-198-generic']
    box['flag'] = True
    st = box['fn']()
    assert st['pending'] and st['kernel']
    assert st['staged'] == '5.15.0-198-generic'
    assert st['sig'] == 'reboot@5.15.0-198-generic'


def test_box_on_newest_kernel_has_no_prompt(box):
    box['running'] = '5.15.0-198-generic'
    box['boot'] = ['5.15.0-190-generic', '5.15.0-198-generic']
    st = box['fn']()
    assert not st['pending'] and not st['kernel']
    assert st['sig'] == ''


def test_numeric_not_lexical_order(box):
    # Lexically "99" > "198"; a restart prompt keyed to that would never clear.
    box['running'] = '5.15.0-198-generic'
    box['boot'] = ['5.15.0-99-generic', '5.15.0-198-generic']
    assert not box['fn']()['pending']


def test_rhel_newer_kernel_staged(box):
    box['running'] = '5.14.0-687.39.1.el9_7.x86_64'
    box['boot'] = ['0-rescue-0123456789abcdef', '5.14.0-687.39.1.el9_7.x86_64',
                   '5.14.0-687.57.1.el9_7.x86_64']
    st = box['fn']()
    assert st['kernel'] and st['staged'] == '5.14.0-687.57.1.el9_7.x86_64'


def test_rhel_rescue_image_is_never_the_staged_kernel(box):
    box['running'] = '5.14.0-687.57.1.el9_7.x86_64'
    box['boot'] = ['0-rescue-0123456789abcdef', '5.14.0-687.57.1.el9_7.x86_64']
    st = box['fn']()
    assert not st['pending']
    assert 'rescue' not in st['staged']


def test_running_kernel_newer_than_boot_is_not_a_prompt(box):
    # Containers / hand-booted kernels: restarting would not change anything.
    box['running'] = '6.8.0-45-generic'
    box['boot'] = ['5.15.0-198-generic']
    assert not box['fn']()['pending']


def test_empty_boot_is_quiet(box):
    box['running'] = '5.15.0-190-generic'
    box['boot'] = []
    assert not box['fn']()['pending']


def test_ubuntu_flag_alone_still_prompts(box):
    box['running'] = '5.15.0-198-generic'
    box['boot'] = ['5.15.0-198-generic']
    box['flag'] = True
    st = box['fn']()
    assert st['pending'] and not st['kernel'] and st['flag']
    assert st['sig'] == 'reboot@flag-1760000000'


def test_kernel_reboot_pending_uses_the_same_answer():
    body = APP[APP.index('def _kernel_reboot_pending():'):]
    body = body[:body.index('\ndef ')]
    assert "_kernel_reboot_state()['kernel']" in body


# -- CVE label ---------------------------------------------------------------

def _cve_ns(codename):
    blk = APP[APP.index('_KERNEL_CVE_FIXES = {'):APP.index('_kernel_patch_cache = ')]

    class _F:
        def __init__(self, *_a, **_k):
            self._lines = ['NAME="Ubuntu"\n', 'VERSION_CODENAME=%s\n' % codename]

        def __enter__(self):
            return iter(self._lines)

        def __exit__(self, *a):
            return False

    ns = {'re': re, 'open': _F}
    exec(compile(blk, 'app.py:cve', 'exec'), ns)
    return ns['_kernel_cve_banner']


def test_cve_label_while_running_kernel_predates_fix():
    assert _cve_ns('jammy')('5.15.0-190-generic') == 'CVE-2026-53266'


def test_no_cve_label_once_on_fixed_kernel():
    assert _cve_ns('jammy')('5.15.0-198-generic') is None


def test_no_cve_label_on_unknown_distro():
    assert _cve_ns('')('5.15.0-190-generic') is None


# -- API contracts -----------------------------------------------------------

def _func(name):
    body = APP[APP.index('def %s(' % name):]
    ends = [i for i in (body.find('\n@app.route'), body.find('\ndef ', 1)) if i > 0]
    return body[:min(ends)]


def test_kernel_patch_status_not_patched_while_restart_pending():
    body = _func('kernel_patch_status_api')
    assert "'patched': upgradable_count == 0 and not reboot_pending" in body
    assert 'upgradable_count > 0 or reboot_pending' in body


def test_os_updates_api_reads_reboot_state_outside_the_cache():
    body = _func('os_updates_api')
    assert '_kernel_reboot_state()' in body
    assert "data['reboot'] = rb" in body
    # never mutate the cached dict
    assert 'dict(_os_updates_summary(' in body


def test_remote_hosts_carry_the_restart_signal():
    probe = _func('_get_unattended_upgrades_status_remote')
    assert '/boot/vmlinuz-' in probe and 'reboot-required' in probe
    assert "'reboot_required':" in probe
    hosts = _func('_build_uu_hosts')
    assert hosts.count("'reboot_required':") == 3  # this host, TAK DB, Fed Hub


def test_the_panel_behaves():
    """Driven, not matched: see scripts/check_kernel_reboot_banner.js."""
    node = shutil.which('node')
    if node is None:
        pytest.skip('no node on PATH, so the OS-updates panel is unexercised')
    r = subprocess.run([node, str(ROOT / 'scripts' / 'check_kernel_reboot_banner.js')],
                       cwd=str(ROOT), capture_output=True, text=True, timeout=120)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert 'all kernel-reboot banner checks passed' in out, out
