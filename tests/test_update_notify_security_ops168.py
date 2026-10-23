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
"""Guard Dog's update email flags security updates (ops #168).

Two cases: OS security patches the console can install (and a security kernel
that is installed but not running), and an infra-TAK / CloudTAK release that is
a security release. A security claim needs positive evidence; "could not check"
is never reported as security, and never prunes what was already mailed. The
functions are cut out of app.py and run with the package manager / GitHub faked.
"""

import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import subprocess as _real_subprocess
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
BROKER_PY = REPO / 'broker' / 'takwerx_broker.py'


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?(?=^\S)', APP, re.S | re.M).group(0)


def _exec(n, *names, consts=()):
    src = '\n'.join([_const(c) for c in consts] + [_cut(x) for x in names])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


OS_CONSTS = ('_DNF_CHECK_OK_RC', '_DNF_CHECK_UPDATE_ARGS', '_DNF_ROW_RE',
             '_APT_SECURITY_SUITE_RE', '_DNF_SEC_ADVISORY_RE', '_DNF_SEVERITY_RANK')
OS_FUNCS = ('_parse_dnf_check_update', '_dnf_error_tail', '_dnf_ignored_repos',
            '_dnf_check_update_run', '_dnf_readonly_run', '_parse_apt_simulation',
            '_pending_os_updates', '_parse_apt_security',
            '_parse_dnf_security_advisories', '_dnf_security_advisories',
            '_pending_security_os_updates', '_apt_policy_installed_from_security',
            '_staged_kernel_security')

APT_SIM = (
    'NOTE: This is only a simulation!\n'
    'Inst libssl3 [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates, '
    'Ubuntu:22.04/jammy-security [amd64])\n'
    'Inst openssl [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates, '
    'Ubuntu:22.04/jammy-security [amd64])\n'
    'Inst tzdata [2024a-0ubuntu0.22.04] (2024b-0ubuntu0.22.04 Ubuntu:22.04/jammy-updates [all])\n'
    'Inst docker-ce [5:27.3.1-1~ubuntu.22.04~jammy] (5:27.4.0-1~ubuntu.22.04~jammy '
    'Docker CE:jammy [amd64])\n'
    'Inst libexpat1 [2.4.7-1ubuntu0.3] (2.4.7-1ubuntu0.4 UbuntuESM:22.04/jammy-infra-security [amd64])\n'
    'Conf libssl3 (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])\n'
)
DNF_SEC_ROWS = (
    'openssl-libs.x86_64    1:3.2.2-6.el9_5.1       baseos\n'
    'kernel-core.x86_64     5.14.0-687.57.1.el9_8   baseos\n'
)
DNF_ADVISORIES = (
    'RLSA-2026:1234 Important/Sec. kernel-core-5.14.0-687.57.1.el9_8.x86_64\n'
    'RLSA-2026:1240 Moderate/Sec.  openssl-libs-1:3.2.2-6.el9_5.1.x86_64\n'
    'RLSA-2026:1240 Moderate/Sec.  openssl-1:3.2.2-6.el9_5.1.x86_64\n'
    'RLSA-2026:1301 Critical/Sec.  sudo-1.9.17p2-3.el9_8.3.x86_64\n'
)
POLICY_SECURITY = (
    'linux-image-5.15.0-198-generic:\n'
    '  Installed: 5.15.0-198.208\n'
    '  Candidate: 5.15.0-198.208\n'
    '  Version table:\n'
    ' *** 5.15.0-198.208 500\n'
    '        500 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages\n'
    '        500 http://security.ubuntu.com/ubuntu jammy-security/main amd64 Packages\n'
    '        100 /var/lib/dpkg/status\n'
)
POLICY_UPDATES_ONLY = (
    'linux-image-5.15.0-198-generic:\n'
    '  Installed: 5.15.0-198.208\n'
    '  Version table:\n'
    '     5.15.0-199.209 500\n'
    '        500 http://security.ubuntu.com/ubuntu jammy-security/main amd64 Packages\n'
    ' *** 5.15.0-198.208 500\n'
    '        500 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages\n'
    '        100 /var/lib/dpkg/status\n'
)


def _os_ns(answers, pkg_mgr='apt', uid=1001, cve=lambda k: None):
    """answers: list of (match, rc, stdout, stderr) — first whose `match` is in argv wins."""
    calls = []

    def fake_run(argv, *a, **k):
        calls.append(list(argv))
        for match, rc, out, err in answers:
            if match in argv:
                if isinstance(rc, BaseException):
                    raise rc
                return _real_subprocess.CompletedProcess(argv, rc, out, err)
        return _real_subprocess.CompletedProcess(argv, 0, '', '')

    n = {
        're': re,
        'os': types.SimpleNamespace(getuid=lambda: uid, path=os.path),
        'subprocess': types.SimpleNamespace(run=fake_run, DEVNULL=_real_subprocess.DEVNULL),
        '_pkg_mgr': lambda: pkg_mgr,
        '_real_bin': lambda name: '/usr/bin/' + name,
        '_sudo_wrap': lambda argv: ['BROKER'] + list(argv),
        '_kernel_cve_banner': cve,
    }
    return _exec(n, *OS_FUNCS, consts=OS_CONSTS), calls


# ── apt: the -security pocket is the evidence ─────────────────────────────────

def test_apt_security_parse_picks_only_security_pockets():
    n, _ = _os_ns([])
    names = [p['name'] for p in n['_parse_apt_security'](APT_SIM)]
    # jammy-updates-only tzdata and third-party docker-ce are NOT security; the Conf
    # line is not a second row; Ubuntu Pro's infra-security pocket is.
    assert names == ['libssl3', 'openssl', 'libexpat1']


def test_apt_pending_security_and_failure_raises():
    n, calls = _os_ns([('full-upgrade', 0, APT_SIM, '')])
    d = n['_pending_security_os_updates']()
    assert [p['name'] for p in d['packages']] == ['libssl3', 'openssl', 'libexpat1']
    assert d['advisories'] == []
    assert calls[0] == ['/usr/bin/apt-get', '-s', 'full-upgrade']
    n, _ = _os_ns([('full-upgrade', 100, '', 'E: Unable to correct problems')])
    with pytest.raises(RuntimeError):
        n['_pending_security_os_updates']()


def test_apt_nothing_security_is_a_real_empty():
    n, _ = _os_ns([('full-upgrade', 0, 'Inst tzdata [a] (b Ubuntu:22.04/jammy-updates [all])\n', '')])
    assert n['_pending_security_os_updates']()['packages'] == []


# ── dnf: dnf's own --security filter, advisory ids as an extra ────────────────

def test_dnf_security_uses_check_update_security_through_broker():
    n, calls = _os_ns([('check-update', 100, DNF_SEC_ROWS, ''), ('updateinfo', 0, DNF_ADVISORIES, '')],
                      pkg_mgr='dnf')
    d = n['_pending_security_os_updates']()
    assert [p['name'] for p in d['packages']] == ['openssl-libs', 'kernel-core']
    # deduped by id, worst severity first
    assert d['advisories'] == [{'id': 'RLSA-2026:1301', 'severity': 'Critical'},
                               {'id': 'RLSA-2026:1234', 'severity': 'Important'},
                               {'id': 'RLSA-2026:1240', 'severity': 'Moderate'}]
    cu = next(c for c in calls if 'check-update' in c)
    assert cu[:2] == ['BROKER', 'dnf'] and '--security' in cu and '-C' in cu
    assert cu.index('--security') < cu.index('check-update')
    ui = next(c for c in calls if 'updateinfo' in c)
    assert ui[:2] == ['BROKER', 'dnf'] and ui[-3:] == ['updateinfo', 'list', '--security']


def test_dnf_advisory_failure_keeps_packages():
    n, _ = _os_ns([('check-update', 100, DNF_SEC_ROWS, ''), ('updateinfo', 1, '', 'Error: x')],
                  pkg_mgr='dnf')
    d = n['_pending_security_os_updates']()
    assert len(d['packages']) == 2 and d['advisories'] == []


def test_dnf_check_failure_is_unknown_not_none():
    n, _ = _os_ns([('check-update', 1, '', "Error: Cache-only enabled but no cache for 'baseos'")],
                  pkg_mgr='dnf')
    with pytest.raises(RuntimeError) as e:
        n['_pending_security_os_updates']()
    assert 'rc=1' in str(e.value)
    skipped = "Ignoring repositories: baseos\n"
    n, _ = _os_ns([('check-update', 0, '', skipped)], pkg_mgr='dnf')
    with pytest.raises(RuntimeError):
        n['_pending_security_os_updates']()


def test_dnf_rc0_no_security_is_a_real_empty():
    n, _ = _os_ns([('check-update', 0, '', '')], pkg_mgr='dnf')
    assert n['_pending_security_os_updates']() == {'packages': [], 'advisories': []}


# ── staged kernel: verified security or nothing ───────────────────────────────

RB_UBU = {'kernel': True, 'running': '5.15.0-190-generic', 'staged': '5.15.0-198-generic',
          'sig': 'reboot@5.15.0-198-generic'}
RB_EL = {'kernel': True, 'running': '5.14.0-687.39.1.el9_8.x86_64',
         'staged': '5.14.0-687.57.1.el9_8.x86_64', 'sig': 'reboot@5.14.0-687.57.1.el9_8.x86_64'}


def test_kernel_ubuntu_installed_from_security_pocket():
    n, calls = _os_ns([('policy', 0, POLICY_SECURITY, '')])
    assert n['_staged_kernel_security'](RB_UBU) == 'Ubuntu security update'
    assert calls[-1] == ['/usr/bin/apt-cache', 'policy', 'linux-image-5.15.0-198-generic']


def test_kernel_ubuntu_only_the_installed_rows_count():
    # a NEWER version in -security must not make the installed (-updates) one security
    n, _ = _os_ns([('policy', 0, POLICY_UPDATES_ONLY, '')])
    assert n['_staged_kernel_security'](RB_UBU) is None


def test_kernel_ubuntu_policy_failure_raises():
    n, _ = _os_ns([('policy', 100, '', 'E: x')])
    with pytest.raises(RuntimeError):
        n['_staged_kernel_security'](RB_UBU)


def test_kernel_cve_table_wins_only_when_staged_fixes_it():
    banners = {'5.15.0-190-generic': 'CVE-2026-53266', '5.15.0-198-generic': None}
    n, calls = _os_ns([], cve=lambda k: banners.get(k))
    assert n['_staged_kernel_security'](RB_UBU) == 'CVE-2026-53266'
    assert calls == []
    # staged kernel still exposed to the same CVE -> the table says nothing; ask apt
    n, _ = _os_ns([('policy', 0, POLICY_UPDATES_ONLY, '')], cve=lambda k: 'CVE-2026-53266')
    assert n['_staged_kernel_security'](RB_UBU) is None


def test_kernel_dnf_advisory_for_the_staged_kernel():
    n, calls = _os_ns([('updateinfo', 0, DNF_ADVISORIES, '')], pkg_mgr='dnf')
    assert n['_staged_kernel_security'](RB_EL) == 'RLSA-2026:1234 (Important)'
    ui = next(c for c in calls if 'updateinfo' in c)
    assert ui[-2:] == ['--installed', 'kernel-core']
    other = dict(RB_EL, staged='5.14.0-700.1.1.el9_8.x86_64')
    assert n['_staged_kernel_security'](other) is None


def test_kernel_not_staged_is_none_without_asking():
    n, calls = _os_ns([])
    assert n['_staged_kernel_security']({'kernel': False, 'staged': 'x', 'running': 'y'}) is None
    assert calls == []


# ── infra-TAK security release: the ship skill's headline ─────────────────────

def _rel_ns():
    return _exec({'re': re}, '_release_security_summary',
                 consts=('_SECURITY_RELEASE_HEADLINE_RE',))


@pytest.mark.parametrize('body, want', [
    ('## Security release: CloudTAK PostgreSQL 17.11 + PostGIS 3.6\n\nThis release ...',
     'CloudTAK PostgreSQL 17.11 + PostGIS 3.6'),
    ('## Security: TAK Portal and Remote Assist on the newest Node 22\n',
     'TAK Portal and Remote Assist on the newest Node 22'),
    ('\n\n### **Security release:** fixes GHSA-abcd-efgh-ijkl\n', 'fixes GHSA-abcd-efgh-ijkl'),
    ('## Hotfix: Node-RED feeds get their groups back\n\nmoves Node-RED onto the Node.js 22 security release', None),
    ('## Guard Dog frees disk\n\n## Security: not the headline\n', None),
    ('Security release notes are below\n', None),
    ('', None),
    (None, None),
])
def test_release_security_headline(body, want):
    assert _rel_ns()['_release_security_summary'](body) == want


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_urllib(routes):
    """routes: {url-substring: python object | Exception}"""
    def urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, 'full_url') else req
        for k, v in routes.items():
            if k in url:
                if isinstance(v, BaseException):
                    raise v
                return _Resp(json.dumps(v).encode())
        raise AssertionError('unexpected url ' + url)
    import urllib.request as _ur
    return types.SimpleNamespace(Request=_ur.Request, urlopen=urlopen)


RELEASES = [
    {'tag_name': 'v10.2.27-alpha', 'body': '## Fixes for Guard Dog\n'},
    {'tag_name': 'v10.2.26-alpha', 'body': '## Security: Authentik 2026.8.4 (CVE-2026-11111)\n'},
    {'tag_name': 'v10.2.25-alpha', 'body': '## Hotfix: Node-RED feeds\n'},
    {'tag_name': 'v10.2.24-alpha', 'body': '## Security: TAK Portal on the newest Node 22\n'},
    {'tag_name': 'v10.2.22-alpha', 'body': '## Security release: CloudTAK PostgreSQL 17.11\n'},
    {'tag_name': 'v10.2.28-alpha', 'body': '## Security release: draft\n', 'draft': True},
]


def _console(routes, version='10.2.23-alpha'):
    import sys
    fake = _fake_urllib(routes)
    n = {'json': json, 'subprocess': _real_subprocess, 'os': os, 're': re, 'VERSION': version,
         'GITHUB_REPO': 'takwerx/infra-TAK'}
    _exec(n, '_console_pending_update', '_release_security_summary',
          consts=('_SECURITY_RELEASE_HEADLINE_RE',))
    real = sys.modules['urllib.request']
    sys.modules['urllib.request'] = fake
    try:
        import urllib
        old_attr = urllib.request
        urllib.request = fake
        try:
            return n['_console_pending_update']({'update_channel': 'main'})
        finally:
            urllib.request = old_attr
    finally:
        sys.modules['urllib.request'] = real


def test_console_names_every_security_release_since_installed():
    item = _console({'/releases/latest': {'tag_name': 'v10.2.27-alpha'}, '/releases?': RELEASES})
    assert item['target'] == 'v10.2.27-alpha' and item['how'] == 'Console page → Update Now.'
    # .22 is older than what runs (.23); the draft is past the target; oldest first
    assert item['security'] == [
        'v10.2.24-alpha is a security release: TAK Portal on the newest Node 22',
        'v10.2.26-alpha is a security release: Authentik 2026.8.4 (CVE-2026-11111)']
    assert 'security_unknown' not in item


def test_console_plain_release_has_empty_security():
    item = _console({'/releases/latest': {'tag_name': 'v10.2.27-alpha'}, '/releases?': RELEASES},
                    version='10.2.26-alpha')
    assert item['security'] == []


def test_console_release_list_unreadable_is_unknown_not_security():
    item = _console({'/releases/latest': {'tag_name': 'v10.2.27-alpha'},
                     '/releases?': OSError('rate limited')})
    assert item['identity'] == 'v10.2.27-alpha'
    assert item.get('security_unknown') is True and not item.get('security')


# ── CloudTAK: GitHub advisories with version ranges ───────────────────────────

CT_ADVISORIES = [
    {'ghsa_id': 'GHSA-rm89-4h58-wv8j', 'cve_id': None, 'severity': 'medium', 'state': 'published',
     'summary': 'Missing connection authorization on POST /api/template',
     'vulnerabilities': [{'patched_versions': '', 'vulnerable_version_range': '<= 13.49.0'}]},
    {'ghsa_id': 'GHSA-r95q-fp26-h3hc', 'cve_id': 'CVE-2026-55177', 'severity': 'high',
     'state': 'published', 'summary': 'Authenticated full-read SSRF in /api/esri*',
     'vulnerabilities': [{'patched_versions': '>= v13.10.0', 'vulnerable_version_range': '<= 13.7.0'}]},
    {'ghsa_id': 'GHSA-xxxx', 'cve_id': None, 'severity': 'low', 'state': 'published',
     'summary': 'unparseable range', 'vulnerabilities': [{'vulnerable_version_range': 'all versions'}]},
    {'ghsa_id': 'GHSA-wdrn', 'cve_id': None, 'severity': 'high', 'state': 'published',
     'withdrawn_at': '2026-09-01T00:00:00Z', 'summary': 'withdrawn',
     'vulnerabilities': [{'vulnerable_version_range': '<= 99.0.0'}]},
]


def _adv_ns(advs):
    import urllib as _u
    n = {'json': json, 're': re}
    _exec(n, '_semver_tuple', '_version_in_range', '_gh_advisories_fixed_by')
    fake = _fake_urllib({'security-advisories': advs})

    def run(*a):
        old = _u.request
        _u.request = fake
        import sys
        real = sys.modules['urllib.request']
        sys.modules['urllib.request'] = fake
        try:
            return n['_gh_advisories_fixed_by'](*a)
        finally:
            _u.request = old
            sys.modules['urllib.request'] = real
    return n, run


@pytest.mark.parametrize('ver, spec, want', [
    ('13.49.0', '<= 13.49.0', True), ('13.50.0', '<= 13.49.0', False),
    ('1.1.0', '>= 1.0, < 1.2.3', True), ('1.2.3', '>= 1.0, < 1.2.3', False),
    ('v13.10.0', '>= v13.10.0', True), ('13.8', '>= v13.10.0', False),
    ('13.49.0-beta', '<= 13.49.0', None), ('13.49.0', 'all versions', None), ('13.49.0', '', None),
])
def test_version_in_range(ver, spec, want):
    n, _ = _adv_ns([])
    assert n['_version_in_range'](ver, spec) is want


def test_cloudtak_advisories_fixed_by_the_target():
    _, run = _adv_ns(CT_ADVISORIES)
    got = run('dfpc-coe/CloudTAK', '13.5.0', '13.50.0')
    assert got == ['GHSA-rm89-4h58-wv8j (medium): Missing connection authorization on POST /api/template',
                   'CVE-2026-55177 (high): Authenticated full-read SSRF in /api/esri*']
    # 13.8 is out of the vulnerable range but not yet patched (>= 13.10.0): not claimed
    got = run('dfpc-coe/CloudTAK', '13.5.0', '13.8.0')
    assert [g.split(' ')[0] for g in got] == []
    # already past every range: nothing
    assert run('dfpc-coe/CloudTAK', '13.50.0', '13.51.0') == []


# ── OS items: grace while automatic updates are applying ──────────────────────

def _items_ns(sec, posture, rb=None, kernel=None):
    n = {'time': time, 'hashlib': hashlib, 'OS_SECURITY_AUTO_GRACE_S': 36 * 3600,
         '_auto_update_posture': lambda: posture,
         '_kernel_reboot_state': lambda: rb or {'kernel': False}}

    def pso():
        if isinstance(sec, BaseException):
            raise sec
        return sec
    n['_pending_security_os_updates'] = pso

    def sks(r):
        if isinstance(kernel, BaseException):
            raise kernel
        return kernel
    n['_staged_kernel_security'] = sks
    return _exec(n, '_os_security_items')


SEC = {'packages': [{'name': 'openssl', 'old': '1', 'new': '2'},
                    {'name': 'libssl3', 'old': '1', 'new': '2'}],
       'advisories': [{'id': 'RLSA-2026:1240', 'severity': 'Moderate'}]}


def test_os_items_no_auto_updates_reports_now():
    n = _items_ns(SEC, {'applies': False})
    seen, unknown = {}, set()
    items = n['_os_security_items'](seen, unknown, now=1000.0)
    assert len(items) == 1 and items[0]['key'] == 'os-security'
    it = items[0]
    assert it['summary'] == 'Operating system: 2 security patches pending'
    assert it['security'][0] == 'Packages: libssl3, openssl'
    assert it['security'][1] == 'Advisories: RLSA-2026:1240 (Moderate)'
    assert 'Install updates' in it['how']
    assert seen == {'openssl=2': 1000.0, 'libssl3=2': 1000.0} and not unknown


def test_os_items_auto_updates_wait_out_the_grace():
    n = _items_ns(SEC, {'applies': True, 'mechanism': 'unattended-upgrades'})
    seen = {}
    assert n['_os_security_items'](seen, set(), now=1000.0) == []
    assert n['_os_security_items'](seen, set(), now=1000.0 + 35 * 3600) == []
    items = n['_os_security_items'](seen, set(), now=1000.0 + 36 * 3600)
    assert items and 'unattended-upgrades' in items[0]['security'][-1]


def test_os_items_identity_tracks_the_set_and_prunes_installed():
    n = _items_ns(SEC, {'applies': False})
    seen = {'gone=1': 5.0}
    a = n['_os_security_items'](seen, set(), now=10.0)[0]['identity']
    assert 'gone=1' not in seen
    n2 = _items_ns({'packages': SEC['packages'] + [{'name': 'sudo', 'old': '1', 'new': '2'}],
                    'advisories': []}, {'applies': False})
    b = n2['_os_security_items'](seen, set(), now=20.0)[0]['identity']
    assert a != b and seen['openssl=2'] == 10.0


def test_os_items_check_failure_is_unknown_and_keeps_seen():
    n = _items_ns(RuntimeError('apt-get simulation failed'), {'applies': False})
    seen, unknown = {'openssl=2': 5.0}, set()
    assert n['_os_security_items'](seen, unknown, now=10.0) == []
    assert unknown == {'os-security'} and seen == {'openssl=2': 5.0}


def test_os_items_security_kernel_and_unknown_kernel():
    rb = dict(RB_UBU, pending=True)
    n = _items_ns({'packages': [], 'advisories': []}, {}, rb=rb, kernel='CVE-2026-53266')
    items = n['_os_security_items']({}, set(), now=1.0)
    assert [i['key'] for i in items] == ['kernel-security']
    assert items[0]['identity'] == 'reboot@5.15.0-198-generic'
    assert 'CVE-2026-53266' in items[0]['security'][0] and 'Reboot now' in items[0]['how']
    n = _items_ns({'packages': [], 'advisories': []}, {}, rb=rb, kernel=None)
    assert n['_os_security_items']({}, set(), now=1.0) == []
    n = _items_ns({'packages': [], 'advisories': []}, {}, rb=rb, kernel=RuntimeError('x'))
    unknown = set()
    assert n['_os_security_items']({}, unknown, now=1.0) == [] and unknown == {'kernel-security'}


# ── the sweep: email body, subject, once-per-change ───────────────────────────

def _sweep(pending, state, unknown_keys=()):
    sent, saved = [], []
    n = {
        'socket': types.SimpleNamespace(gethostname=lambda: 'box'),
        'load_settings': lambda: {'guarddog_alert_email': 'ops@example.com', 'fqdn': 'tak.example.com',
                                  'console_port': 5001, 'update_channel': 'main'},
        '_safe_alert_email_list': lambda v: v,
        '_guarddog_server_identifier': lambda s: 'tak-prod-1',
        '_update_notify_state_load': lambda: json.loads(json.dumps(state)),
        '_update_notify_state_save': lambda s: saved.append(s),
        '_guarddog_send_alert_email_via_relay': lambda to, subj, body: sent.append((subj, body)),
        'print': lambda *a, **k: None,
    }

    def collect(settings, seen=None, unknown=None):
        unknown.update(unknown_keys)
        seen['openssl=2'] = 1.0
        return json.loads(json.dumps(pending))
    n['_collect_pending_updates'] = collect
    _exec(n, '_update_notify_check_once')
    return n['_update_notify_check_once'](), sent, saved


CONSOLE_SEC = {'key': 'console', 'label': 'infra-TAK console', 'installed': 'v10.2.23-alpha',
               'target': 'v10.2.27-alpha', 'identity': 'v10.2.27-alpha+security',
               'how': 'Console page → Update Now.',
               'security': ['v10.2.24-alpha is a security release: TAK Portal on the newest Node 22']}
OS_SEC = {'key': 'os-security', 'label': 'Operating system', 'installed': '2 packages',
          'target': 'security patches', 'summary': 'Operating system: 2 security patches pending',
          'identity': 'abc123', 'security': ['Packages: libssl3, openssl'],
          'how': 'Console page → "Operating system updates available" → Install updates.'}
PLUGIN = {'key': 'plugin:x', 'label': 'CloudTAK plugin “x”', 'installed': 'aaa',
          'target': 'bbb (main channel)', 'identity': 'bbb'}


def test_security_email_says_update_what_it_fixes_and_where():
    r, sent, saved = _sweep([CONSOLE_SEC, OS_SEC, PLUGIN], {})
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '🔒 Security update pending on tak-prod-1 — update this machine'
    assert body.startswith('SECURITY UPDATE: you should update this machine (tak-prod-1).')
    assert '  • infra-TAK console: v10.2.23-alpha → v10.2.27-alpha' in body
    assert '      v10.2.24-alpha is a security release: TAK Portal on the newest Node 22' in body
    assert '      Fix it from the infra-TAK console: Console page → Update Now.' in body
    assert '  • Operating system: 2 security patches pending' in body
    assert 'Install updates.' in body
    assert 'Other pending updates:\n  • CloudTAK plugin “x”: aaa → bbb (main channel)' in body
    assert saved[-1]['os-security'] == 'abc123' and saved[-1]['_os_security_seen'] == {'openssl=2': 1.0}


def test_plain_updates_keep_the_old_email():
    plain = dict(CONSOLE_SEC, identity='v10.2.27-alpha', security=[])
    _, sent, _ = _sweep([plain, PLUGIN], {})
    subj, body = sent[0]
    assert subj == '⬆ 2 updates pending on tak-prod-1'
    assert body.startswith('The following updates are pending on tak-prod-1:')
    assert 'SECURITY' not in body


def test_same_pending_security_does_not_mail_again():
    state = {'console': 'v10.2.27-alpha+security', 'os-security': 'abc123'}
    r, sent, _ = _sweep([CONSOLE_SEC, OS_SEC], state)
    assert sent == [] and r['emailed'] is False
    # a NEW security patch set mails again
    r, sent, _ = _sweep([CONSOLE_SEC, dict(OS_SEC, identity='def456')], state)
    assert len(sent) == 1


def test_release_turning_out_security_mails_once_more():
    r, sent, _ = _sweep([CONSOLE_SEC], {'console': 'v10.2.27-alpha'})
    assert len(sent) == 1 and sent[0][0].startswith('🔒')


def test_unknown_security_state_neither_remails_nor_prunes():
    unknown_console = dict(CONSOLE_SEC, identity='v10.2.27-alpha', security=None,
                           security_unknown=True,
                           seen_ok=['v10.2.27-alpha', 'v10.2.27-alpha+security'])
    state = {'console': 'v10.2.27-alpha+security', 'os-security': 'abc123',
             '_os_security_seen': {'openssl=2': 1.0}}
    r, sent, saved = _sweep([unknown_console], state, unknown_keys={'os-security'})
    assert sent == []
    # nothing changed, so nothing to save — and in particular the mailed state survives
    assert saved == [] or (saved[-1]['console'] == 'v10.2.27-alpha+security'
                           and saved[-1]['os-security'] == 'abc123')


def test_unknown_os_check_carries_state_even_when_something_else_is_new():
    state = {'os-security': 'abc123'}
    r, sent, saved = _sweep([PLUGIN], state, unknown_keys={'os-security'})
    assert len(sent) == 1 and 'SECURITY' not in sent[0][1]
    assert saved[-1]['os-security'] == 'abc123' and saved[-1]['plugin:x'] == 'bbb'


def test_resolved_security_is_pruned_so_it_can_mail_again():
    r, sent, saved = _sweep([], {'os-security': 'abc123'})
    assert sent == [] and 'os-security' not in saved[-1]


# ── broker: updateinfo is a query, the setopt gate is unchanged ───────────────

@pytest.fixture(scope='module')
def broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops168_test', BROKER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_broker_allows_the_security_queries(broker):
    broker._check_pkgmgr(['dnf', '-C', '-q', '--assumeno', '--setopt=skip_if_unavailable=True',
                          '--security', 'check-update'])
    broker._check_pkgmgr(['dnf', '-C', '-q', '--assumeno', '--setopt=skip_if_unavailable=True',
                          'updateinfo', 'list', '--security'])
    broker._check_pkgmgr(['dnf', '-C', '-q', '--assumeno', '--setopt=skip_if_unavailable=True',
                          'updateinfo', 'list', '--security', '--installed', 'kernel-core'])


@pytest.mark.parametrize('opt', ['--setopt=pluginpath=/tmp/x', '-oAPT::Update::Pre-Invoke::=x'])
def test_broker_updateinfo_still_denies_setopt(broker, opt):
    with pytest.raises(broker.Denied):
        broker._check_pkgmgr(['dnf', opt, 'updateinfo', 'list'])
