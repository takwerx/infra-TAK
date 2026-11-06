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
"""A failed Install-updates run can be dismissed for good (GH #416).

Field (Nov 5-6, 2026): the run failed on Microsoft's 22.04 list after the OS
went to 24.04. The operator fixed apt by hand and rebooted, but the FATAL line
stayed the last word in kernel-patch.log, so the console showed "Update install
FAILED" on every load and Dismiss did not stick. job-status now names the
failed run (`error_at`) so the panel can key a dismissal to it; the panel side
is driven by scripts/check_kernel_reboot_banner.js (section 9).

app.py cannot be imported in a test, so the function is cut out and run with
its collaborators stubbed.
"""

import hashlib
import pathlib
import re
import shutil
import subprocess
from datetime import datetime

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / 'app.py').read_text(encoding='utf-8')


def _job_state(log, unit=('not-found', 'inactive', 'dead', '', 0)):
    body = APP[APP.index('def _kernel_patch_job_state():'):]
    body = body[:body.index('\n@app.route')]

    def _read_priv(_path):
        if log is None:
            raise FileNotFoundError(_path)
        return log

    class _P:
        @staticmethod
        def boot_time():
            return 0

    ns = {
        're': re, 'hashlib': hashlib, 'datetime': datetime, 'psutil': _P,
        '_read_priv': _read_priv, '_KERNEL_PATCH_LOGFILE': '/var/log/takguard/kernel-patch.log',
        '_kernel_patch_unit_state': lambda: unit,
        '_kernel_reboot_state': lambda: {'pending': False, 'sig': ''},
        '_kernel_patch_cache': {},
    }
    exec(compile(body, 'app.py:_kernel_patch_job_state', 'exec'), ns)
    return ns['_kernel_patch_job_state']()


FIELD_LOG = (
    '[2026-11-05T21:13:58Z] === Install updates started ===\n'
    'E: The repository \'https://packages.microsoft.com/ubuntu/22.04/prod noble Release\' '
    'does not have a Release file.\n'
    '[2026-11-05T21:14:03Z] FATAL: apt-get update failed (exit 100)\n'
)


def test_field_log_after_reboot_names_the_failed_run():
    st = _job_state(FIELD_LOG)
    assert st['error'] is True
    assert st['error_at'] == '2026-11-05T21:14:03'


def test_loaded_unit_path_names_it_too():
    st = _job_state(FIELD_LOG, unit=('loaded', 'failed', 'failed', 'exit-code', 0))
    assert st['error'] is True
    assert st['error_at'] == '2026-11-05T21:14:03'


def test_later_failure_gets_a_new_key():
    later = FIELD_LOG + '[2026-11-06T09:00:00Z] FATAL: apt-get full-upgrade failed (exit 100)\n'
    assert _job_state(later)['error_at'] == '2026-11-06T09:00:00'


def test_unstamped_fatal_still_gets_a_stable_key():
    log = 'something went wrong\nFATAL: no stamp here\n'
    a, b = _job_state(log)['error_at'], _job_state(log)['error_at']
    assert a and a == b and a.startswith('h')
    assert _job_state(log.replace('no stamp', 'other'))['error_at'] != a


def test_success_after_failure_has_no_error_key():
    ok = FIELD_LOG + '[2026-11-06T09:00:00Z] === DONE — safe to reboot ===\n'
    st = _job_state(ok)
    assert st['error'] is False and st['error_at'] == ''


def test_no_log_has_no_error_key():
    st = _job_state(None)
    assert st['error'] is False and st['error_at'] == ''


def test_panel_dismissal_sticks():
    """Driven, not matched: section 9 of scripts/check_kernel_reboot_banner.js."""
    node = shutil.which('node')
    if node is None:
        pytest.skip('no node on PATH, so the OS-updates panel is unexercised')
    r = subprocess.run([node, str(ROOT / 'scripts' / 'check_kernel_reboot_banner.js')],
                       cwd=str(ROOT), capture_output=True, text=True, timeout=120)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert 'ok   dismissed failed run stays closed on reload' in out, out
    assert 'ok   dismissed failed run stays closed days later' in out, out
