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
"""Linux kernel CVE-2026-98432 (ops #1084): tell the operator to install the OS update and
RESTART, by Guard Dog email and by the console banner.

The fix is an OS package that only works after a restart, so the test is about who gets
told: a box on an old running kernel (fix installed or not) gets the urgent mail with the
exact steps, a restarted box gets none. The data under test is the REAL
security/patch-now.json and the REAL _KERNEL_CVE_FIXES row in app.py, run through the real
decision functions cut out of app.py, with only the package manager and the clock faked.
Fixed kernels: https://ubuntu.com/security/CVE-2026-98432 and the Red Hat CVE page.
"""

import json
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import test_patch_now_ops377 as pn  # noqa: E402  (shared harness: _ns, _sweep)

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
CVE = 'CVE-2026-98432'
DOC = json.loads((REPO / 'security' / 'patch-now.json').read_text())
ADV = pn._ns()['_patch_now_parse'](DOC)

# first fixed kernel per OS key, as published (Ubuntu `linux` rows, Rocky 9.8)
FIXED = {
    'ubuntu-22.04': '5.15.0-203', 'ubuntu-22.04/aws': '5.15.0-1120', 'ubuntu-22.04/azure': '5.15.0-1126',
    'ubuntu-24.04': '6.8.0-149', 'ubuntu-24.04/aws': '6.8.0-1069', 'ubuntu-24.04/azure': '6.8.0-1073',
    'rocky-9': '5.14.0-687.64.1',
}


def _rb(running, staged=None):
    return {'running': running, 'staged': staged or running}


def _items(os_type, rb):
    pkg_mgr = 'dnf' if os_type.startswith('rocky') else 'apt'
    return pn._ns()['_patch_now_feed_items'](ADV, {}, os_type, rb, pkg_mgr)


# ── the shipped list ──────────────────────────────────────────────────────────

def test_shipped_list_names_the_cve_for_every_supported_os_and_cloud():
    assert [a['id'] for a in ADV] == [CVE]
    assert ADV[0]['packages'] == {'kernel': FIXED}


def test_wording_is_plain_and_not_cut_short_by_the_parser():
    raw = DOC['advisories'][0]
    assert ADV[0]['what'] == raw['what'] and len(raw['what']) <= 240
    assert ADV[0]['why'] == raw['why'] and len(raw['why']) <= 160
    assert 'restart' in raw['why']        # the one thing the operator has to do


# ── before / after: who is told ───────────────────────────────────────────────

@pytest.mark.parametrize('os_type, fix_key, old, fixed_run', [
    ('ubuntu-22.04', 'ubuntu-22.04', '5.15.0-198-generic', '5.15.0-203-generic'),
    ('ubuntu-22.04', 'ubuntu-22.04/aws', '5.15.0-1100-aws', '5.15.0-1120-aws'),
    ('ubuntu-22.04', 'ubuntu-22.04/azure', '5.15.0-1125-azure', '5.15.0-1126-azure'),
    ('ubuntu-24.04', 'ubuntu-24.04', '6.8.0-148-generic', '6.8.0-149-generic'),
    ('ubuntu-24.04', 'ubuntu-24.04/aws', '6.8.0-1068-aws', '6.8.0-1069-aws'),
    ('ubuntu-24.04', 'ubuntu-24.04/azure', '6.8.0-1072-azure', '6.8.0-1073-azure'),
    ('rocky-9', 'rocky-9', '5.14.0-687.63.1.el9_8.x86_64', '5.14.0-687.64.1.el9_8.x86_64'),
    ('rocky-9', 'rocky-9', '5.14.0-611.5.1.el9_7.x86_64', '5.14.0-700.1.1.el9_8.x86_64'),
])
def test_old_running_kernel_is_told_to_install_and_restart_fixed_one_is_not(os_type, fix_key, old, fixed_run):
    # no automatic updates: fix not installed yet -> install, then restart
    it, = _items(os_type, _rb(old))
    assert it['key'] == 'pn:feed:' + CVE and it['patch_now'] is True
    assert f'(fixed in {FIXED[fix_key]})' in it['security'][-1]
    assert it['how'].startswith('Console page → "Operating system updates available" → Install updates.')
    assert 'Then reboot to finish: Console page → Reboot now' in it['how']
    # automatic updates installed it but nobody restarted -> just restart
    it, = _items(os_type, _rb(old, staged=fixed_run))
    assert it['how'].startswith('The fix is already installed; reboot to finish: Console page → Reboot now')
    # restarted: nothing, so the daily reminders stop
    assert _items(os_type, _rb(fixed_run)) == []


@pytest.mark.parametrize('os_type, running', [
    ('ubuntu-22.04', '5.15.0-1100-gcp'),            # a cloud with no published row: no guess
    ('ubuntu-24.04', '6.8.0-100-lowlatency'),
    ('ubuntu-22.04', '6.8.0-100-generic'),          # 22.04 on the 6.8 HWE kernel: other numbering
])
def test_a_kernel_with_no_published_fix_row_is_never_claimed_exposed(os_type, running):
    assert _items(os_type, _rb(running)) == []


# ── the whole path: collect -> mail, with the package manager faked ───────────

def _collect(os_type, rb):
    n = pn._ns(_patch_now_advisories=lambda feed, now: (ADV, feed, True),
               _kernel_reboot_state=lambda: rb, _read_os_release=lambda: (os_type, ''),
               _installed_pkg_versions=lambda names: {}, _pending_os_updates=lambda: [],
               _pkg_mgr=lambda: 'dnf' if os_type.startswith('rocky') else 'apt',
               _dnf_security_advisories=lambda: [])
    items, _feed = n['_collect_patch_now_items'](None, set(), now=pn.T0)
    return items


def test_old_box_gets_the_urgent_mail_with_steps_then_a_daily_reminder_restarted_box_gets_none():
    items = _collect('ubuntu-22.04', _rb('5.15.0-198-generic', staged='5.15.0-203-generic'))
    r, sent, saved, _ = pn._sweep(items, {}, pn.T0)
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '🔒 Security update pending on tak-prod-1 — patch now'
    assert body.startswith('URGENT SECURITY UPDATE: install this now on tak-prod-1.')
    assert f'Urgent security fix {CVE}' in body
    assert 'with no login' in body and 'only works after the server restarts' in body
    assert 'Still exposed here: Linux kernel 5.15.0-198-generic (fixed in 5.15.0-203)' in body
    assert ('Fix it from the infra-TAK console: The fix is already installed; reboot to finish: '
            'Console page → Reboot now (the box is back in 1-3 minutes).') in body
    # same box, 23 h later: nothing; 24 h later: reminder, until it restarts
    _, again, _, _ = pn._sweep(items, saved[-1], pn.T0 + 23 * 3600)
    assert again == []
    _, rem, saved2, _ = pn._sweep(items, saved[-1], pn.T0 + pn.DAY)
    assert rem[0][0].endswith('patch now (reminder)')
    # the operator restarts: the next check finds nothing and the reminders stop
    done = _collect('ubuntu-22.04', _rb('5.15.0-203-generic'))
    assert done == []
    _, after, saved3, _ = pn._sweep(done, saved2[-1], pn.T0 + 2 * pn.DAY)
    assert after == [] and '_patch_now_sent' not in saved3[-1]


def test_box_with_no_automatic_updates_is_told_to_install_first():
    items = _collect('ubuntu-24.04', _rb('6.8.0-148-generic'))
    _, sent, _, _ = pn._sweep(items, {}, pn.T0)
    body = sent[0][1]
    assert ('Fix it from the infra-TAK console: Console page → "Operating system updates available" '
            '→ Install updates. Then reboot to finish: Console page → Reboot now') in body


def test_rocky_box_is_told_too():
    items = _collect('rocky-9', _rb('5.14.0-687.63.1.el9_8.x86_64'))
    assert [i['key'] for i in items] == ['pn:feed:' + CVE]
    assert _collect('rocky-9', _rb('5.14.0-687.64.1.el9_8.x86_64')) == []


# ── console banner ────────────────────────────────────────────────────────────

def _banner_ns(codename):
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


@pytest.mark.parametrize('codename, running, want', [
    ('jammy', '5.15.0-198-generic', CVE), ('jammy', '5.15.0-203-generic', None),
    ('noble', '6.8.0-148-generic', CVE), ('noble', '6.8.0-149-generic', None),
    ('noble', '6.8.0-160-generic', None),
    ('jammy', '5.15.0-1119-aws', CVE), ('jammy', '5.15.0-1120-aws', None),
    ('jammy', '5.15.0-1125-azure', CVE), ('jammy', '5.15.0-1126-azure', None),
    ('noble', '6.8.0-1068-aws', CVE), ('noble', '6.8.0-1069-aws', None),
    ('noble', '6.8.0-1072-azure', CVE), ('noble', '6.8.0-1073-azure', None),
    # no row for this flavour: never claim exposure we cannot verify
    ('jammy', '5.15.0-1100-gcp', None), ('noble', '6.8.0-1000-gcp', None),
    ('bookworm', '6.1.0-10-amd64', None),
    # -lowlatency numbers like generic and was judged that way before: unchanged
    ('noble', '6.8.0-100-lowlatency', 'CVE-2026-31431 (Copy Fail)'),
])
def test_banner_names_the_cve_only_while_the_running_kernel_predates_the_fix(codename, running, want):
    assert _banner_ns(codename)(running) == want


def test_cloud_kernel_is_not_judged_against_the_generic_number():
    # 5.15.0-1050-aws is far older than the AWS fix 1120, yet 1050 > 203: the old lookup
    # compared the two scales and called every cloud box fixed
    assert _banner_ns('jammy')('5.15.0-1050-aws') == CVE


# ── guard: the checks that carry this cannot drop out unseen ──────────────────

def test_the_update_sweep_still_runs_the_patch_now_check_every_hour():
    sweep = APP[APP.index('def _update_notify_check_once('):]
    sweep = sweep[:sweep.index('\ndef ')]
    assert '_collect_patch_now_items(feed, unknown, now)' in sweep
    loop = APP[APP.index('def _update_notify_loop('):]
    loop = loop[:loop.index('\ndef ')]
    assert 'fast=True' in loop or 'fast=' in loop


def test_banner_and_mail_both_read_the_running_kernel_not_the_package_list():
    assert "_kernel_cve_banner(running_kernel) if (upgradable_count > 0 or reboot_pending)" in APP
    assert "'patched': upgradable_count == 0 and not check_err and not reboot_pending" in APP
