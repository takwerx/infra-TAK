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
"""Patch-now security fixes (ops #377).

A fix that is a really big deal must reach the customer within the hour (no 36 h grace,
no 6 h wait) and be mailed again every 24 h until it is installed — and the reminders
must stop once the package manager shows the fix. Patch-now comes from evidence only:
the takwerx patch-now list (checked against the box's own installed versions), a dnf
advisory rated Critical, or a critical GitHub advisory for Docker / containerd / Caddy /
NetBird. The functions are cut out of app.py and run with the package manager faked.
"""

import io
import json
import pathlib
import re
import subprocess as _real_subprocess
import time
import types
import urllib.error
import urllib.request

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    # a closing bracket at column 0 still belongs to the constant
    return re.search(rf'^{name} = .*?(?=^[^\s)\]}}])', APP, re.S | re.M).group(0)


def _exec(n, *names, consts=()):
    src = '\n'.join([_const(c) for c in consts] + [_cut(x) for x in names])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


PN_CONSTS = ('PATCH_NOW_FEED_URL', 'PATCH_NOW_CHECK_INTERVAL_S', 'PATCH_NOW_REPEAT_S',
             'PATCH_NOW_FEED_MAX_AGE_S', 'PATCH_NOW_BUILTIN', '_PN_ID_RE', '_PN_PKG_RE',
             '_PN_VER_RE', '_PN_OS_RE', 'THIRD_PARTY_ADVISORY_REPOS',
             'THIRD_PARTY_ADVISORY_CACHE_S', '_third_party_adv_cache', '_OS_INSTALL_HOW',
             '_OS_REBOOT_HOW')
PN_FUNCS = ('_vercmp_segment_deb', '_vercmp_segment_rpm', '_pkg_vercmp', '_upstream_version',
            '_pkg_restart_impact', '_patch_now_parse', '_patch_now_advisories',
            '_installed_pkg_versions', '_patch_now_feed_items', '_nevra_name',
            '_dnf_critical_items', '_third_party_security_items', '_collect_patch_now_items',
            '_kernel_version_key', '_dnf_error_tail')


def _impact():
    src = re.search(r'^_MANAGED_PKG_IMPACT = \[\n.*?^\]\n_MANAGED_PKG_IMPACT = .*?\n', APP,
                    re.S | re.M).group(0)
    n = {'re': re}
    exec(src, n)
    return n['_MANAGED_PKG_IMPACT']


def _ns(**extra):
    n = {'re': re, 'json': json, 'time': time, 'print': lambda *a, **k: None,
         '_MANAGED_PKG_IMPACT': _impact(), '_pkg_mgr': lambda: 'apt',
         '_real_bin': lambda name: '/usr/bin/' + name}
    n.update(extra)
    _exec(n, *PN_FUNCS, consts=PN_CONSTS)
    n.update(extra)          # fakes win over the real functions cut above
    return n


# ── version comparison: dpkg and rpm rules ────────────────────────────────────

@pytest.mark.parametrize('a, b, want', [
    ('1.0', '1.0.1', -1), ('1.0a', '1.0', 1), ('1.0~rc1', '1.0', -1), ('1.0+b1', '1.0', 1),
    ('0ubuntu1.16', '0ubuntu1.15', 1), ('0ubuntu1.9', '0ubuntu1.10', -1), ('2.4', '2.4', 0),
    ('1~~', '1~', -1),
])
def test_deb_segment(a, b, want):
    assert _ns()['_vercmp_segment_deb'](a, b) == want


@pytest.mark.parametrize('a, b, want', [
    ('1.0', '1.0.1', -1), ('1.0~rc1', '1.0', -1), ('1.0^git1', '1.0', 1), ('1.0^git1', '1.0.1', -1),
    ('1.0a', '1.0', 1), ('2.el9', '2.el9_5', -1), ('6.el9_5.1', '6.el9_5', 1),
    ('1.9.17p2', '1.9.17p10', -1), ('1.0.1', '1.0.a', 1), ('5.14.0', '5.14.0', 0),
])
def test_rpm_segment(a, b, want):
    assert _ns()['_vercmp_segment_rpm'](a, b) == want


@pytest.mark.parametrize('installed, fixed, mgr, want', [
    ('5:28.5.1-1~ubuntu.22.04~jammy', '28.5.2', 'apt', -1),    # epoch ignored when fixed has none
    ('5:28.5.2-1~ubuntu.22.04~jammy', '28.5.2', 'apt', 0),     # any build of the fixed version
    ('5:29.0.0-1~ubuntu.22.04~jammy', '28.5.2', 'apt', 1),
    ('3.0.2-0ubuntu1.15', '3.0.2-0ubuntu1.20', 'apt', -1),     # the fix is in the revision
    ('3.0.2-0ubuntu1.20', '3.0.2-0ubuntu1.20', 'apt', 0),
    ('1:3.0.2-1', '2:1.0', 'apt', -1),                         # epoch counts when fixed names it
    ('0:3.2.2-6.el9_5', '3.2.2-6.el9_5.1', 'dnf', -1),
    ('1:3.2.2-6.el9_5.1', '3.2.2-6.el9_5.1', 'dnf', 0),
    ('0:1.9.17p2-3.el9_8.3', '1.9.17p2-3.el9_8.4', 'dnf', -1),
])
def test_pkg_vercmp(installed, fixed, mgr, want):
    assert _ns()['_pkg_vercmp'](installed, fixed, mgr) == want


@pytest.mark.parametrize('v, want', [
    ('5:28.5.1-1~ubuntu.22.04~jammy', '28.5.1'), ('3:28.5.1-1.el9', '28.5.1'),
    ('1.7.28-1', '1.7.28'), ('2.10.2', '2.10.2'), ('', None), ('git-abc', None),
])
def test_upstream_version(v, want):
    assert _ns()['_upstream_version'](v) == want


# ── the patch-now list: shape is validated, a bad entry is dropped whole ──────

GOOD = {'id': 'CVE-2026-12345', 'what': 'A Docker bug that lets a container take over the server.',
        'why': 'It is being actively attacked.',
        'packages': {'docker-ce': '28.5.2',
                     'openssl': {'ubuntu-22.04': '3.0.2-0ubuntu1.20', 'rocky-9': '3.2.2-6.el9_5.1'},
                     'kernel': {'ubuntu-22.04': '5.15.0-198', 'ubuntu-22.04/aws': '6.8.0-1030'}}}


def test_parse_keeps_good_and_drops_bad_whole():
    bad = [
        dict(GOOD, id='CVE 2026; rm -rf /'),
        dict(GOOD, what=''),
        dict(GOOD, packages={}),
        dict(GOOD, packages={'docker-ce': '28.5.2', 'Bad Name': '1'}),
        dict(GOOD, packages={'docker-ce': '28.5.2 && reboot'}),
        dict(GOOD, packages={'openssl': {'ubuntu': '1'}}),
        'not a dict',
    ]
    got = _ns()['_patch_now_parse']({'advisories': [GOOD] + bad})
    assert [a['id'] for a in got] == ['CVE-2026-12345']
    assert got[0]['packages']['docker-ce'] == {'*': '28.5.2'}
    assert _ns()['_patch_now_parse'](None) == [] and _ns()['_patch_now_parse']({'advisories': 'x'}) == []


def test_repo_patch_now_file_is_valid_and_empty():
    doc = json.loads((REPO / 'security' / 'patch-now.json').read_text())
    assert doc == {'advisories': []}
    assert _const('PATCH_NOW_FEED_URL').strip().endswith(
        "'https://raw.githubusercontent.com/takwerx/infra-TAK/main/security/patch-now.json'")


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fetch(monkeypatch, answer, feed, now=1000.0):
    def urlopen(req, timeout=None):
        assert req.full_url.endswith('/security/patch-now.json')
        if isinstance(answer, BaseException):
            raise answer
        return _Resp(json.dumps(answer).encode())
    monkeypatch.setattr(urllib.request, 'urlopen', urlopen)
    return _ns()['_patch_now_advisories'](feed, now)


def test_feed_fetched_and_cached(monkeypatch):
    advs, feed, ok = _fetch(monkeypatch, {'advisories': [GOOD]}, None)
    assert ok and [a['id'] for a in advs] == ['CVE-2026-12345'] and feed['at'] == 1000.0


def test_feed_404_is_a_real_empty(monkeypatch):
    err = urllib.error.HTTPError('u', 404, 'Not Found', {}, None)
    advs, feed, ok = _fetch(monkeypatch, err, {'at': 900.0, 'advisories': [GOOD]})
    assert ok and advs == [] and feed == {'at': 1000.0, 'advisories': []}


def test_feed_outage_uses_last_good_copy_then_goes_unknown(monkeypatch):
    cached = {'at': 1000.0, 'advisories': [GOOD]}
    advs, feed, ok = _fetch(monkeypatch, OSError('timed out'), cached, now=1000.0 + 6 * 86400)
    assert ok and [a['id'] for a in advs] == ['CVE-2026-12345'] and feed is cached
    advs, feed, ok = _fetch(monkeypatch, urllib.error.HTTPError('u', 503, 'x', {}, None), cached,
                            now=1000.0 + 8 * 86400)
    assert not ok and advs == []


# ── installed versions come from the package database ─────────────────────────

def _run_ns(rc, out, err='', mgr='apt'):
    calls = []

    def run(argv, *a, **k):
        calls.append(list(argv))
        return _real_subprocess.CompletedProcess(argv, rc, out, err)
    return _ns(subprocess=types.SimpleNamespace(run=run), _pkg_mgr=lambda: mgr), calls


def test_installed_versions_dpkg():
    out = ('docker-ce\t5:28.5.1-1~ubuntu.22.04~jammy\tinstalled\n'
           'caddy\t2.10.2\tconfig-files\n')
    n, calls = _run_ns(1, out, 'dpkg-query: no packages found matching netbird\n')
    assert n['_installed_pkg_versions'](['docker-ce', 'caddy', 'netbird']) == {
        'docker-ce': '5:28.5.1-1~ubuntu.22.04~jammy'}
    assert calls[0][:2] == ['/usr/bin/dpkg-query', '-W'] and calls[0][-3:] == ['caddy', 'docker-ce', 'netbird']
    n, _ = _run_ns(2, '', 'dpkg-query: error: parsing file')
    with pytest.raises(RuntimeError):
        n['_installed_pkg_versions'](['docker-ce'])


def test_installed_versions_rpm_takes_highest():
    out = ('openssl-libs\t1:3.2.2-6.el9_5\tinstalled\n'
           'openssl-libs\t1:3.2.2-6.el9_5.1\tinstalled\n'
           'package caddy is not installed\n')
    n, calls = _run_ns(1, out, mgr='dnf')
    assert n['_installed_pkg_versions'](['openssl-libs', 'caddy']) == {'openssl-libs': '1:3.2.2-6.el9_5.1'}
    assert calls[0][:2] == ['/usr/bin/rpm', '-q']
    n, _ = _run_ns(1, '', 'error: rpmdb open failed', mgr='dnf')
    with pytest.raises(RuntimeError):
        n['_installed_pkg_versions'](['openssl-libs'])


def test_installed_versions_never_passes_a_bad_name():
    n, calls = _run_ns(0, '')
    assert n['_installed_pkg_versions'](['--admindir=/tmp', 'Bad Name']) == {} and calls == []


# ── which listed advisories still apply to this box ───────────────────────────

ADV = _ns()['_patch_now_parse']({'advisories': [GOOD]})
RB_OLD = {'running': '5.15.0-190-generic', 'staged': '5.15.0-190-generic'}
RB_STAGED = {'running': '5.15.0-190-generic', 'staged': '5.15.0-198-generic'}
RB_NEW = {'running': '5.15.0-198-generic', 'staged': '5.15.0-198-generic'}


def test_feed_item_for_an_exposed_package():
    items = _ns()['_patch_now_feed_items'](ADV, {'docker-ce': '5:28.5.1-1~ubuntu.22.04~jammy'},
                                           'ubuntu-22.04', RB_NEW, 'apt')
    assert len(items) == 1
    it = items[0]
    assert it['key'] == 'pn:feed:CVE-2026-12345' and it['identity'] == 'CVE-2026-12345'
    assert it['patch_now'] is True
    assert it['security'][0] == 'What it fixes: A Docker bug that lets a container take over the server.'
    assert it['security'][1] == 'Why it is urgent: It is being actively attacked.'
    assert 'docker-ce 5:28.5.1-1~ubuntu.22.04~jammy (fixed in 28.5.2)' in it['security'][2]
    assert any(s.startswith('Installing it restarts every container') for s in it['security'])
    assert it['how'] == 'Console page → "Operating system updates available" → Install updates.'


def test_feed_item_gone_once_fixed_or_not_installed():
    n = _ns()
    fixed = {'docker-ce': '5:28.5.2-1~ubuntu.22.04~jammy', 'openssl': '3.0.2-0ubuntu1.20'}
    assert n['_patch_now_feed_items'](ADV, fixed, 'ubuntu-22.04', RB_NEW, 'apt') == []
    assert n['_patch_now_feed_items'](ADV, {}, 'ubuntu-22.04', RB_NEW, 'apt') == []
    # an OS the entry does not list claims nothing for its OS-keyed packages
    assert n['_patch_now_feed_items'](ADV, {'openssl': '1.0'}, 'ubuntu-24.04', RB_NEW, 'apt') == []


def test_feed_kernel_running_old_says_install_then_reboot():
    it = _ns()['_patch_now_feed_items'](ADV, {}, 'ubuntu-22.04', RB_OLD, 'apt')[0]
    assert 'Linux kernel 5.15.0-190-generic (fixed in 5.15.0-198)' in it['security'][2]
    assert it['how'].startswith('Console page → "Operating system updates available" → Install updates.')
    assert 'Then reboot to finish: Console page → Reboot now' in it['how']


def test_feed_kernel_staged_says_reboot_to_finish_and_stops_when_running():
    n = _ns()
    it = n['_patch_now_feed_items'](ADV, {}, 'ubuntu-22.04', RB_STAGED, 'apt')[0]
    assert it['how'].startswith('The fix is already installed; reboot to finish: Console page → Reboot now')
    assert n['_patch_now_feed_items'](ADV, {}, 'ubuntu-22.04', RB_NEW, 'apt') == []


def test_feed_kernel_cloud_flavour_needs_its_own_key():
    n = _ns()
    aws_old = {'running': '6.8.0-1021-aws', 'staged': '6.8.0-1021-aws'}
    assert n['_patch_now_feed_items'](ADV, {}, 'ubuntu-22.04', aws_old, 'apt')[0]['key'] == 'pn:feed:CVE-2026-12345'
    azure = {'running': '6.8.0-1021-azure', 'staged': '6.8.0-1021-azure'}
    assert n['_patch_now_feed_items'](ADV, {}, 'ubuntu-22.04', azure, 'apt') == []


# ── dnf Critical advisories ───────────────────────────────────────────────────

DNF_ADVISORIES = [
    {'id': 'RLSA-2026:1234', 'severity': 'Important', 'nevra': 'kernel-core-5.14.0-687.57.1.el9_8.x86_64'},
    {'id': 'RLSA-2026:1301', 'severity': 'Critical', 'nevra': 'sudo-1.9.17p2-3.el9_8.3.x86_64'},
    {'id': 'RLSA-2026:1310', 'severity': 'Critical', 'nevra': 'kernel-core-5.14.0-687.60.1.el9_8.x86_64'},
    {'id': 'RLSA-2026:1310', 'severity': 'Critical', 'nevra': 'kernel-5.14.0-687.60.1.el9_8.x86_64'},
]


def test_dnf_critical_only_and_kernel_says_reboot():
    n = _ns(_pkg_mgr=lambda: 'dnf', _dnf_security_advisories=lambda: DNF_ADVISORIES)
    items = n['_dnf_critical_items']()
    assert [i['key'] for i in items] == ['pn:os:RLSA-2026:1301', 'pn:os:RLSA-2026:1310']
    assert all(i['patch_now'] for i in items)
    assert items[0]['security'][0] == 'Fixes: sudo' and 'Reboot' not in items[0]['how']
    assert items[1]['security'][0] == 'Fixes: kernel, kernel-core'
    assert 'Then reboot to finish' in items[1]['how']
    assert _ns(_pkg_mgr=lambda: 'apt')['_dnf_critical_items']() == []


def test_nevra_name():
    n = _ns()
    assert n['_nevra_name']('openssl-libs-1:3.2.2-6.el9_5.1.x86_64') == 'openssl-libs'
    assert n['_nevra_name']('tzdata-2026a-1.el9.noarch') == 'tzdata'


# ── Docker / containerd / Caddy / NetBird: GitHub advisories ───────────────────

PENDING = [
    {'name': 'docker-ce', 'old': '5:28.5.1-1~ubuntu.22.04~jammy', 'new': '5:29.8.2-1~ubuntu.22.04~jammy'},
    {'name': 'caddy', 'old': '2.11.3', 'new': '2.11.5'},
    {'name': 'netbird', 'old': '0.76.1', 'new': '0.76.2'},
    {'name': 'tzdata', 'old': 'a', 'new': 'b'},
]


def _tp(answers):
    calls = []

    def adv(repo, inst, tgt, packages=None):
        calls.append((repo, inst, tgt, packages))
        a = answers[repo]
        if isinstance(a, BaseException):
            raise a
        return a
    n = _ns(_gh_advisories=adv)
    n['_third_party_adv_cache'].clear()
    return n, calls


def test_third_party_critical_is_patch_now_high_is_security():
    n, calls = _tp({
        'moby/moby': [{'id': 'CVE-2026-1', 'severity': 'critical', 'summary': 'container escape'}],
        'caddyserver/caddy': [{'id': 'GHSA-x', 'severity': 'high', 'summary': 'path traversal'}],
        'netbirdio/netbird': []})
    unknown = set()
    items = n['_third_party_security_items'](PENDING, unknown, now=100.0)
    assert [(i['key'], i['patch_now']) for i in items] == [('pn:3p:docker-ce', True), ('3p:caddy', False)]
    assert calls[0] == ('moby/moby', '28.5.1', '29.8.2', ('Docker Engine',))
    d = items[0]
    assert d['summary'] == 'Docker: security update 28.5.1 → 29.8.2' and d['identity'] == '29.8.2+security'
    assert d['security'][0] == 'Fixes CVE-2026-1 (critical): container escape'
    assert 'rated critical' in d['security'][1] and d['security'][2].startswith('Installing it restarts')
    assert not unknown
    # second call inside the cache window does not ask GitHub again
    n['_third_party_security_items'](PENDING, set(), now=200.0)
    assert len(calls) == 3


def test_third_party_github_down_is_unknown_not_safe():
    n, _ = _tp({'moby/moby': OSError('rate limited'), 'caddyserver/caddy': [], 'netbirdio/netbird': []})
    unknown = set()
    assert n['_third_party_security_items'](PENDING, unknown, now=1.0) == []
    assert unknown == {'3p:docker-ce', 'pn:3p:docker-ce'}


def test_gh_advisories_package_filter(monkeypatch):
    advs = [{'ghsa_id': 'GHSA-a', 'severity': 'critical', 'state': 'published', 'summary': 'engine bug',
             'vulnerabilities': [
                 {'package': {'name': 'github.com/docker/docker/daemon'},
                  'vulnerable_version_range': '<= v28.5.2', 'patched_versions': ''},
                 {'package': {'name': 'Docker Engine'},
                  'vulnerable_version_range': '< 29.5.1', 'patched_versions': '29.5.1'}]},
            {'ghsa_id': 'GHSA-b', 'severity': 'high', 'state': 'published', 'summary': 'module only',
             'vulnerabilities': [{'package': {'name': 'github.com/docker/docker/daemon'},
                                  'vulnerable_version_range': '<= v28.5.2', 'patched_versions': ''}]}]
    monkeypatch.setattr(urllib.request, 'urlopen', lambda req, timeout=None: _Resp(json.dumps(advs).encode()))
    n = _exec({'json': json, 're': re}, '_semver_tuple', '_version_in_range', '_gh_advisories')
    got = n['_gh_advisories']('moby/moby', '28.5.1', '29.8.2', packages=('Docker Engine',))
    assert got == [{'id': 'GHSA-a', 'severity': 'critical', 'summary': 'engine bug'}]
    assert len(n['_gh_advisories']('moby/moby', '28.5.1', '29.8.2')) == 2
    # a bare patched version is the first fixed one, not the only one; a target below it
    # is still exposed and claims nothing
    assert n['_gh_advisories']('moby/moby', '28.5.1', '29.5.0', packages=('Docker Engine',)) == []


# ── collecting: each source shielded, failures become unknown ─────────────────

def test_collect_marks_failed_sources_unknown():
    def boom(*a, **k):
        raise RuntimeError('x')
    n = _ns(_patch_now_advisories=lambda feed, now: (ADV, feed, True),
            _installed_pkg_versions=boom, _read_os_release=lambda: ('ubuntu-22.04', ''),
            _kernel_reboot_state=lambda: RB_NEW, _dnf_critical_items=boom, _pending_os_updates=boom)
    unknown = set()
    items, feed = n['_collect_patch_now_items']({'at': 1}, unknown, now=5.0)
    assert items == [] and feed == {'at': 1}
    assert unknown == {'pn:feed', 'pn:os', '3p', 'pn:3p'}


def test_collect_no_list_is_unknown_for_the_list_only():
    n = _ns(_patch_now_advisories=lambda feed, now: ([], {}, False),
            _dnf_critical_items=lambda: [], _pending_os_updates=lambda: [])
    unknown = set()
    assert n['_collect_patch_now_items'](None, unknown, now=5.0) == ([], {})
    assert unknown == {'pn:feed'}


# ── the sweep: mail now, repeat every 24 h, stop once fixed ───────────────────

PN = {'key': 'pn:feed:CVE-2026-12345', 'label': 'Urgent security fix CVE-2026-12345',
      'installed': 'docker-ce 5:28.5.1', 'target': 'the fixed version',
      'summary': 'Urgent security fix CVE-2026-12345', 'identity': 'CVE-2026-12345', 'patch_now': True,
      'security': ['What it fixes: A Docker bug.', 'Why it is urgent: It is being actively attacked.'],
      'how': 'Console page → "Operating system updates available" → Install updates.'}
TP_HIGH = {'key': '3p:caddy', 'label': 'Caddy (HTTPS)', 'installed': '2.11.3', 'target': '2.11.5',
           'summary': 'Caddy (HTTPS): security update 2.11.3 → 2.11.5', 'identity': '2.11.5+security',
           'patch_now': False, 'security': ['Fixes GHSA-x (high): path traversal'],
           'how': 'Console page → "Operating system updates available" → Install updates.'}
PLUGIN = {'key': 'plugin:x', 'label': 'CloudTAK plugin “x”', 'installed': 'aaa',
          'target': 'bbb (main channel)', 'identity': 'bbb'}


def _sweep(pn_items, state, now, fast=True, normal=(), unknown_keys=(), send_fails=False):
    sent, saved, collected = [], [], []

    def send(to, subj, body):
        if send_fails:
            raise OSError('relay down')
        sent.append((subj, body))

    def collect(settings, seen=None, unknown=None):
        collected.append(1)
        return json.loads(json.dumps(list(normal)))

    def pn(feed, unknown, now=None):
        unknown.update(unknown_keys)
        return json.loads(json.dumps(list(pn_items))), {'at': now, 'advisories': []}

    n = {
        'time': types.SimpleNamespace(time=lambda: now),
        'socket': types.SimpleNamespace(gethostname=lambda: 'box'),
        'load_settings': lambda: {'guarddog_alert_email': 'ops@example.com', 'fqdn': 'tak.example.com',
                                  'console_port': 5001, 'update_channel': 'main'},
        '_safe_alert_email_list': lambda v: v,
        '_gd_quiet_state': lambda: (False, 0, ''),
        '_guarddog_server_identifier': lambda s: 'tak-prod-1',
        '_update_notify_state_load': lambda: json.loads(json.dumps(state)),
        '_update_notify_state_save': lambda s: saved.append(json.loads(json.dumps(s))),
        '_guarddog_send_alert_email_via_relay': send,
        '_collect_pending_updates': collect,
        '_collect_patch_now_items': pn,
        'print': lambda *a, **k: None,
    }
    _exec(n, '_carried_by_unknown', '_update_notify_check_once', consts=('PATCH_NOW_REPEAT_S',))
    r = n['_update_notify_check_once'](fast=fast)
    return r, sent, saved, collected


T0 = 1_800_000_000.0
DAY = 24 * 3600


def test_fast_check_mails_patch_now_at_once_and_leaves_other_state_alone():
    state = {'os-security': 'abc123', 'plugin:x': 'bbb', '_os_security_seen': {'openssl=2': 1.0}}
    r, sent, saved, collected = _sweep([PN, TP_HIGH], state, T0)
    assert collected == []                          # fast: no console/CloudTAK/plugin lookups
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '🔒 Security update pending on tak-prod-1 — patch now'
    assert body.startswith('URGENT SECURITY UPDATE: install this now on tak-prod-1.')
    assert '  • Urgent security fix CVE-2026-12345' in body
    assert '      What it fixes: A Docker bug.' in body
    assert '      Why it is urgent: It is being actively attacked.' in body
    assert ('      Fix it from the infra-TAK console: Console page → "Operating system updates '
            'available" → Install updates.') in body
    assert 'Reminder' not in body and 'Caddy' not in body      # non-urgent waits for the full sweep
    assert 'you get a reminder every 24 hours until they are installed' in body
    st = saved[-1]
    assert st['os-security'] == 'abc123' and st['plugin:x'] == 'bbb'
    assert st['_os_security_seen'] == {'openssl=2': 1.0}
    assert st['_patch_now_sent'] == {'pn:feed:CVE-2026-12345': {
        'identity': 'CVE-2026-12345', 'first': T0, 'last': T0, 'count': 1}}
    assert '3p:caddy' not in st


def test_no_repeat_inside_24h_then_reminder_after():
    _, _, saved, _ = _sweep([PN], {}, T0)
    st = saved[-1]
    r, sent, _, _ = _sweep([PN], st, T0 + 23 * 3600)
    assert sent == [] and r['emailed'] is False
    r, sent, saved, _ = _sweep([PN], st, T0 + DAY)
    assert len(sent) == 1
    subj, body = sent[0]
    assert subj == '🔒 Security update pending on tak-prod-1 — patch now (reminder)'
    assert 'Reminder: this is still not installed. We first emailed about it 1 day ago.' in body
    assert saved[-1]['_patch_now_sent']['pn:feed:CVE-2026-12345'] == {
        'identity': 'CVE-2026-12345', 'first': T0, 'last': T0 + DAY, 'count': 2}
    _, sent, _, _ = _sweep([PN], saved[-1], T0 + 3 * DAY)
    assert 'We first emailed about it 3 days ago.' in sent[0][1]


def test_reminders_survive_a_restart_because_they_live_in_the_state_file():
    # a restarted console starts from the saved file, nothing in memory
    _, _, saved, _ = _sweep([PN], {}, T0)
    on_disk = json.loads(json.dumps(saved[-1]))
    _, sent, _, _ = _sweep([PN], on_disk, T0 + 2 * 3600)
    assert sent == []


def test_fixed_stops_the_reminders():
    _, _, saved, _ = _sweep([PN], {}, T0)
    r, sent, saved2, _ = _sweep([], saved[-1], T0 + DAY)
    assert sent == [] and '_patch_now_sent' not in saved2[-1]
    # and if it ever comes back it mails at once, as new
    _, sent, _, _ = _sweep([PN], saved2[-1], T0 + DAY + 60)
    assert len(sent) == 1 and '(reminder)' not in sent[0][0]


def test_unreadable_source_neither_mails_nor_forgets():
    _, _, saved, _ = _sweep([PN], {}, T0)
    r, sent, saved2, _ = _sweep([], saved[-1], T0 + DAY, unknown_keys={'pn:feed'})
    assert sent == []
    st = saved2[-1] if saved2 else saved[-1]
    assert st['_patch_now_sent']['pn:feed:CVE-2026-12345']['last'] == T0


def test_failed_send_retries_next_hour():
    r, sent, saved, _ = _sweep([PN], {}, T0, send_fails=True)
    assert sent == [] and saved == []
    _, sent, _, _ = _sweep([PN], {}, T0 + 3600)
    assert len(sent) == 1


def test_full_sweep_mails_urgent_plus_ordinary_security_and_plain_updates():
    r, sent, saved, collected = _sweep([PN, TP_HIGH], {}, T0, fast=False, normal=[PLUGIN])
    assert collected == [1] and len(sent) == 1
    subj, body = sent[0]
    assert subj == '🔒 Security update pending on tak-prod-1 — patch now'
    i_urgent = body.index('URGENT SECURITY UPDATE')
    i_sec = body.index('SECURITY UPDATE: you should update this machine')
    i_other = body.index('Other pending updates:\n  • CloudTAK plugin “x”: aaa → bbb (main channel)')
    assert i_urgent < i_sec < i_other
    assert '  • Caddy (HTTPS): security update 2.11.3 → 2.11.5' in body
    st = saved[-1]
    assert st['3p:caddy'] == '2.11.5+security' and st['plugin:x'] == 'bbb'
    assert 'pn:feed:CVE-2026-12345' not in st and 'pn:feed:CVE-2026-12345' in st['_patch_now_sent']
    # the next full sweep inside 24 h mails nothing; the ordinary items are not repeated
    _, sent, _, _ = _sweep([PN, TP_HIGH], st, T0 + 6 * 3600, fast=False, normal=[PLUGIN])
    assert sent == []


def test_full_sweep_carries_unknown_third_party_state():
    state = {'3p:caddy': '2.11.5+security'}
    _, sent, saved, _ = _sweep([], state, T0, fast=False, normal=[PLUGIN], unknown_keys={'3p'})
    assert saved[-1]['3p:caddy'] == '2.11.5+security'


def test_ordinary_security_patches_still_wait_for_the_grace():
    # the 36 h grace for patches unattended-upgrades installs on its own is untouched
    src = _cut('_os_security_items')
    assert 'OS_SECURITY_AUTO_GRACE_S' in src and 'patch_now' not in src


def test_loop_runs_hourly_fast_checks_between_full_sweeps():
    loop = _cut('_update_notify_loop')
    assert 'wait = PATCH_NOW_CHECK_INTERVAL_S' in loop
    assert '_update_notify_check_once(fast=not full)' in loop
    assert 'next_full = time.time() + UPDATE_NOTIFY_INTERVAL_S' in loop
    assert _const('PATCH_NOW_CHECK_INTERVAL_S').strip() == 'PATCH_NOW_CHECK_INTERVAL_S = 3600'
    assert _const('PATCH_NOW_REPEAT_S').strip() == 'PATCH_NOW_REPEAT_S = 24 * 3600'
