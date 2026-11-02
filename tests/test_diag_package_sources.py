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
"""Diagnostics: Ubuntu Pro, package sources and pins, the last failed install (ops #353).

infra-TAK #352: a TAK Server install on an Ubuntu Pro box stopped at the package step because
Ubuntu Pro's apt pins (510) outranked the PostgreSQL repo (500). The Diagnostics report said only
"TAK Server not installed": it showed neither the pins nor why the install had stopped.
"""

import json
import os
import pathlib
import re
import shutil
import threading
import types
from collections import deque
from datetime import datetime

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

# The Pro/ESM case from #352, as `apt-cache policy` prints it: Ubuntu's ESM copy of gdal-data at
# 510 beside PGDG's newer libgdal at 500.
POLICY_ESM = """\
postgresql:
  Installed: (none)
  Candidate: 16+257build1.1
  Version table:
     16+257build1.1 500
        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages
gdal-data:
  Installed: (none)
  Candidate: 3.8.4+dfsg-3ubuntu3+esm1
  Version table:
     3.8.4+dfsg-3ubuntu3+esm1 510
        510 https://esm.ubuntu.com/apps/ubuntu noble-apps-security/main amd64 Packages
     3.13.3+dfsg-1~noble 500
        500 https://apt.postgresql.org/pub/repos/apt noble-pgdg/main amd64 Packages
     3.8.4+dfsg-3ubuntu3 500
        500 http://archive.ubuntu.com/ubuntu noble/universe amd64 Packages
libpq5:
  Installed: 16.4-0ubuntu0.24.04.1
  Candidate: 17.2-1.pgdg24.04+1
  Version table:
     17.2-1.pgdg24.04+1 500
        500 https://apt.postgresql.org/pub/repos/apt noble-pgdg/main amd64 Packages
 *** 16.4-0ubuntu0.24.04.1 500
        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
        100 /var/lib/dpkg/status
"""

POLICY_ALL = """\
Package files:
 100 /var/lib/dpkg/status
     release a=now
 510 https://user:s3cr3t@esm.ubuntu.com/apps/ubuntu noble-apps-security/main amd64 Packages
     release o=UbuntuESMApps,a=noble-apps-security,n=noble,l=UbuntuESMApps,c=main,b=amd64
     origin esm.ubuntu.com
 500 https://apt.postgresql.org/pub/repos/apt noble-pgdg/main amd64 Packages
     release o=apt.postgresql.org,a=noble-pgdg,n=noble-pgdg,l=PostgreSQL for Debian/Ubuntu repository,c=main,b=amd64
     origin apt.postgresql.org
Pinned packages:
     gdal-data -> 3.13.3+dfsg-1~noble with priority 600
"""

PRO_ATTACHED = json.dumps({
    'attached': True, 'machine_id': 'MACHINE-ID-SECRET-1234', 'account': {'name': 'ACCOUNT-NAME-SECRET'},
    'contract': {'id': 'CONTRACT-ID-SECRET', 'name': 'x'}, 'token': 'TOKEN-SECRET-VALUE',
    'services': [{'name': 'esm-apps', 'status': 'enabled', 'entitled': 'yes'},
                 {'name': 'esm-infra', 'status': 'enabled', 'entitled': 'yes'},
                 {'name': 'livepatch', 'status': 'enabled', 'entitled': 'yes'},
                 {'name': 'fips', 'status': 'disabled', 'entitled': 'yes'}]})


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


CONSTANTS = APP[APP.index('_DIAG_SRC_PKGS = '):APP.index('def _diag_read(')]


def _read(path):
    with open(path) as f:
        return f.read()


def _ns(tmp_path=None, **extra):
    ns = {'os': os, 're': re, 'json': json, 'shutil': shutil,
          '_diag_cmd': lambda *a, **k: '',
          '_read_own_or_priv': _read}
    exec(CONSTANTS, ns)
    ns.update(extra)
    for n in ('_diag_read', '_diag_os_id', '_diag_ubuntu_pro', '_diag_apt_pins', '_diag_apt_sources',
              '_diag_apt_policy_parse', '_diag_apt_candidates', '_diag_apt_priorities', '_diag_rpm_sources',
              '_diag_section_package_sources'):
        src = _cut(n)
        if tmp_path is not None:
            src = (src.replace('/etc/apt/', str(tmp_path) + '/apt/')
                      .replace('/etc/yum.repos.d', str(tmp_path) + '/yum.repos.d')
                      .replace('/etc/dnf/', str(tmp_path) + '/dnf/')
                      .replace('/etc/os-release', str(tmp_path) + '/os-release'))
        exec(compile(src, 'app.py:' + n, 'exec'), ns)
    return ns


@pytest.fixture
def root(tmp_path):
    (tmp_path / 'apt' / 'preferences.d').mkdir(parents=True)
    (tmp_path / 'apt' / 'sources.list.d').mkdir()
    return tmp_path


# --------------------------------------------------------------------------- #
# 1. Ubuntu Pro / ESM
# --------------------------------------------------------------------------- #

def test_pro_attached_reports_esm_services_and_leaks_no_account_details(root):
    (root / 'apt' / 'sources.list.d' / 'ubuntu-esm-apps.sources').write_text('Types: deb\n')
    ns = _ns(root, _diag_cmd=lambda argv, **k: PRO_ATTACHED, shutil=types.SimpleNamespace(which=lambda n: '/usr/bin/pro'))
    out = '\n'.join(ns['_diag_ubuntu_pro']())
    assert 'Ubuntu Pro: ATTACHED' in out
    assert 'esm-apps: enabled' in out and 'esm-infra: enabled' in out
    assert 'livepatch' in out and 'fips' not in out        # other services: enabled ones only
    assert 'ubuntu-esm-apps.sources' in out
    for secret in ('MACHINE-ID', 'ACCOUNT-NAME', 'CONTRACT-ID', 'TOKEN-SECRET'):
        assert secret not in out


def test_pro_not_attached_and_missing_client_and_garbage_output(root):
    st = json.dumps({'attached': False, 'services': [{'name': 'esm-apps', 'status': 'disabled', 'entitled': 'no'}]})
    ns = _ns(root, _diag_cmd=lambda argv, **k: 'warning line\n' + st,
             shutil=types.SimpleNamespace(which=lambda n: '/usr/bin/pro'))
    out = '\n'.join(ns['_diag_ubuntu_pro']())
    assert 'not attached' in out and 'esm-apps: disabled' in out and 'esm-infra: not listed' in out
    ns = _ns(root, shutil=types.SimpleNamespace(which=lambda n: None))
    assert 'pro client is not installed' in ns['_diag_ubuntu_pro']()[0]
    ns = _ns(root, _diag_cmd=lambda argv, **k: 'Traceback boom', shutil=types.SimpleNamespace(which=lambda n: '/usr/bin/pro'))
    assert 'no usable answer' in ns['_diag_ubuntu_pro']()[0]


def test_pro_unattached_box_lists_services_with_only_available(root):
    # the shape ubuntu-pro-client 37 prints on a stock, unattached Ubuntu 24.04 (Azure, 2026-10-30)
    st = json.dumps({'attached': False, 'services': [{'name': 'esm-apps', 'available': 'yes'},
                                                    {'name': 'esm-infra', 'available': 'yes'}]})
    ns = _ns(root, _diag_cmd=lambda argv, **k: st, shutil=types.SimpleNamespace(which=lambda n: '/usr/bin/pro'))
    out = '\n'.join(ns['_diag_ubuntu_pro']())
    assert 'esm-apps: not enabled (available: yes)' in out and 'None' not in out


def test_priorities_fold_components_into_one_line_per_suite():
    raw = ('Package files:\n'
           ' 500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n     release o=Ubuntu,a=noble,l=Ubuntu\n'
           ' 500 http://archive.ubuntu.com/ubuntu noble/universe amd64 Packages\n     release o=Ubuntu,a=noble,l=Ubuntu\n'
           ' 100 http://archive.ubuntu.com/ubuntu noble-backports/main amd64 Packages\n     release o=Ubuntu,a=noble-backports,l=Ubuntu\n')
    out = _ns(_diag_cmd=lambda *a, **k: raw)['_diag_apt_priorities']()
    assert out[0] == 'package sources by priority (2):'
    assert out[1].strip().startswith('500 http://archive.ubuntu.com/ubuntu noble (main, universe)')
    assert out[2].strip().startswith('100 http://archive.ubuntu.com/ubuntu noble-backports (main)')


# --------------------------------------------------------------------------- #
# 2. apt pins, sources, candidates
# --------------------------------------------------------------------------- #

def test_pins_are_listed_with_priorities_and_bad_extensions_flagged(root):
    pd = root / 'apt' / 'preferences.d'
    (pd / 'ubuntu-pro-esm-apps').write_text('# generated\nPackage: *\nPin: release o=UbuntuESMApps\nPin-Priority: 510\n')
    (pd / 'infratak-pgdg-gis').write_text('Package: gdal-data\nPin: origin apt.postgresql.org\nPin-Priority: 600\n')
    (pd / 'old.disabled').write_text('Package: *\nPin-Priority: 1\n')
    out = '\n'.join(_ns(root)['_diag_apt_pins']())
    assert 'pin files' in out and ': 3' in out.splitlines()[0]
    assert 'Pin-Priority: 510' in out and 'Pin: release o=UbuntuESMApps' in out and 'Pin-Priority: 600' in out
    assert '# generated' not in out                                  # comments dropped
    assert re.search(r'old\.disabled  \(ignored by apt', out)
    assert 'ubuntu-pro-esm-apps  (ignored' not in out


def test_no_pin_files_says_zero(root):
    assert _ns(root)['_diag_apt_pins']()[0].endswith(': 0')


def test_sources_list_active_lines_only_and_url_credentials_removed(root):
    (root / 'apt' / 'sources.list').write_text('# comment\n\ndeb http://archive.ubuntu.com/ubuntu noble main\n')
    (root / 'apt' / 'sources.list.d' / 'pgdg.list').write_text(
        'deb [signed-by=/usr/share/keyrings/pgdg.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main\n')
    (root / 'apt' / 'sources.list.d' / 'priv.sources').write_text(
        'Types: deb\nURIs: https://bob:hunter22@private.example/repo\nSuites: noble\n')
    (root / 'apt' / 'sources.list.d' / 'readme.txt').write_text('deb http://not-a-source.example x y\n')
    out = '\n'.join(_ns(root)['_diag_apt_sources']())
    assert 'archive.ubuntu.com' in out and 'apt.postgresql.org' in out and 'noble-pgdg' in out
    assert 'hunter22' not in out and 'bob:' not in out and 'private.example/repo' in out
    assert 'not-a-source' not in out and '# comment' not in out


def test_policy_parse_finds_candidate_priority_and_competing_sources():
    ns = _ns()
    pk = ns['_diag_apt_policy_parse'](POLICY_ESM)
    assert pk['gdal-data']['candidate'] == '3.8.4+dfsg-3ubuntu3+esm1'
    assert [(v[0], v[1]) for v in pk['gdal-data']['versions']][:2] == [('3.8.4+dfsg-3ubuntu3+esm1', 510), ('3.13.3+dfsg-1~noble', 500)]
    assert pk['gdal-data']['versions'][0][2].startswith('https://esm.ubuntu.com/apps/ubuntu')
    assert pk['libpq5']['installed'] == '16.4-0ubuntu0.24.04.1'
    # the installed marker and the dpkg status line do not confuse the parser
    assert [v[0] for v in pk['libpq5']['versions']] == ['17.2-1.pgdg24.04+1', '16.4-0ubuntu0.24.04.1']
    assert pk['libpq5']['versions'][1][2].startswith('http://archive.ubuntu.com')


def test_candidates_show_the_pro_pin_beating_the_postgresql_repo():
    calls = []

    def cmd(argv, **k):
        calls.append(argv)
        return 'libgdal34t64\nlibgdal39\nlibgdal-dev\nlibgdal-grass\n' if argv[1] == 'pkgnames' else POLICY_ESM
    out = '\n'.join(_ns(_diag_cmd=cmd)['_diag_apt_candidates']())
    # libgdal packages are looked up by name and passed to apt-cache policy
    assert calls[1][:2] == ['apt-cache', 'policy'] and 'libgdal39' in calls[1] and 'libgdal34t64' in calls[1]
    assert 'libgdal-dev' not in calls[1]
    assert 'gdal-data: installed (none), candidate 3.8.4+dfsg-3ubuntu3+esm1 at priority 510 from https://esm.ubuntu.com' in out
    assert 'also offered: 3.13.3+dfsg-1~noble at priority 500 from https://apt.postgresql.org' in out
    assert 'postgis: not known to apt' in out
    # versions from the candidate's own source are not repeated; only competing sources are
    assert out.count('also offered') == 3
    assert 'libpq5: installed 16.4-0ubuntu0.24.04.1, candidate 17.2-1.pgdg24.04+1 at priority 500' in out


def test_priorities_list_each_source_with_origin_and_pinned_packages_without_credentials():
    out = '\n'.join(_ns(_diag_cmd=lambda *a, **k: POLICY_ALL)['_diag_apt_priorities']())
    assert '510 https://esm.ubuntu.com/apps/ubuntu noble-apps-security (main)' in out and 'o=UbuntuESMApps' in out
    assert '500 https://apt.postgresql.org/pub/repos/apt noble-pgdg (main)' in out and 'o=apt.postgresql.org' in out
    assert 's3cr3t' not in out and 'user:' not in out
    assert '/var/lib/dpkg/status' not in out
    assert 'packages with an individual pin (1): gdal-data (600)' in out


# --------------------------------------------------------------------------- #
# RHEL family
# --------------------------------------------------------------------------- #

def test_rhel_repos_modules_and_package_sources(root):
    (root / 'yum.repos.d').mkdir()
    (root / 'dnf').mkdir()
    (root / 'yum.repos.d' / 'pgdg-redhat-all.repo').write_text(
        '[pgdg16]\nname=PostgreSQL 16\nbaseurl=https://u:pw1234@download.postgresql.org/pub/repos/yum/16/redhat/rhel-$releasever-$basearch\n'
        'enabled=1\ngpgcheck=1\nmodule_hotfixes=1\npriority=10\n'
        '[pgdg15]\nname=PostgreSQL 15\nbaseurl=https://download.postgresql.org/pub/repos/yum/15/\nenabled=0\n')
    (root / 'yum.repos.d' / 'rocky.repo').write_text('[baseos]\nname=BaseOS\nmetalink=https://mirrors.rockylinux.org/metalink?repo=BaseOS\nexclude=postgresql*\n')
    (root / 'dnf' / 'dnf.conf').write_text('[main]\ngpgcheck=1\nexclude=kernel*\nbest=True\n')

    def cmd(argv, **k):
        if 'module' in argv:
            return 'Rocky Linux 9 - AppStream\nName   Stream  Profiles  Summary\npostgresql [d][e]  15  server  PostgreSQL server\n'
        if '--installed' in argv:
            return 'Installed Packages\npostgresql16-server.x86_64  16.4-1PGDG.rhel9  @pgdg16\n'
        return ('Available Packages\npostgis34_16.x86_64  3.4.3-1PGDG.rhel9  pgdg16\n'
                'gdal313-devel.aarch64  3.13.3-9PGDG.rhel9.8  pgdg-common\ngdal313-libs.aarch64  3.13.3-9PGDG.rhel9.8  pgdg-common\n'
                'postgresql16-server-debuginfo.x86_64 16.4 pgdg16\n')
    out = '\n'.join(_ns(root, _diag_cmd=cmd)['_diag_rpm_sources']())
    assert 'pgdg16 (pgdg-redhat-all.repo): https://download.postgresql.org/pub/repos/yum/16/redhat' in out
    assert 'priority=10' in out and 'module_hotfixes=1' in out
    assert 'pw1234' not in out and 'u:' not in out
    assert 'pgdg15' not in out                                        # enabled=0
    assert 'baseos (rocky.repo): https://mirrors.rockylinux.org/metalink' in out and 'exclude=postgresql*' in out
    assert 'dnf.conf: exclude=kernel*; best=True' in out
    assert 'postgresql [d][e]  15  server' in out
    assert 'postgresql16-server.x86_64  16.4-1PGDG.rhel9  @pgdg16' in out
    assert 'postgis34_16.x86_64  3.4.3-1PGDG.rhel9  pgdg16' in out
    assert 'Installed Packages' not in out and 'Available Packages' not in out
    assert 'gdal313-libs.aarch64' in out and 'gdal313-devel' not in out and 'debuginfo' not in out


def test_rhel_without_repo_files_does_not_raise(root):
    out = '\n'.join(_ns(root)['_diag_rpm_sources']())
    assert '(none found)' in out


def test_section_picks_apt_or_dnf_and_never_needs_tak_to_be_installed(root, monkeypatch):
    (root / 'os-release').write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    monkeypatch.setattr(shutil, 'which', lambda n: '/usr/bin/' + n if n in ('apt-cache', 'pro') else None)
    ns = _ns(root, _diag_cmd=lambda argv, **k: PRO_ATTACHED if argv[0].endswith('pro') else POLICY_ESM)
    out = '\n'.join(ns['_diag_section_package_sources']({}))
    assert 'Ubuntu Pro: ATTACHED' in out and 'candidate versions' in out and 'pin files' in out
    (root / 'os-release').write_text('ID=debian\n')
    assert 'not applicable (this is not Ubuntu)' in '\n'.join(ns['_diag_section_package_sources']({}))
    monkeypatch.setattr(shutil, 'which', lambda n: '/usr/bin/dnf' if n == 'dnf' else None)
    assert 'RHEL family' in ns['_diag_section_package_sources']({})[0]
    monkeypatch.setattr(shutil, 'which', lambda n: None)
    assert ns['_diag_section_package_sources']({}) == ['no apt or dnf found on this box']
    body = _cut('_diag_section_package_sources')
    assert '/opt/tak' not in body and '_tak_is_container' not in body       # the #352 box had no TAK Server


# --------------------------------------------------------------------------- #
# 3. last failed install or deploy
# --------------------------------------------------------------------------- #

MODULE_START = '# v10.2.8 W10: a failed module update records its own reason'
MODULE_BLOCK = APP[APP.index(MODULE_START):APP.index('def load_auth():')]


@pytest.fixture
def h(tmp_path):
    import secrets
    from functools import wraps
    ns = {'os': os, 're': re, 'json': json, 'threading': threading, 'datetime': datetime, 'secrets': secrets,
          'wraps': wraps, 'deque': deque, 'CONFIG_DIR': str(tmp_path),
          'app': types.SimpleNamespace(jinja_env=types.SimpleNamespace(globals={}))}
    exec(compile(MODULE_BLOCK, 'app.py', 'exec'), ns)
    ns.update(deploy_status={'error': False}, deploy_log=[], _tak_is_container=lambda: False)
    exec(compile(_cut('_diag_section_failed_install'), 'app.py:fi', 'exec'), ns)
    ns['_tmp'] = tmp_path
    return ns


APT_FAIL = ['[13:01:02] ━━━ Step 3/9: PostgreSQL ━━━', '[13:01:09] Installing PostgreSQL 15 + PostGIS...',
            '  The following packages have unmet dependencies:',
            '   libgdal39 : Depends: gdal-data (= 3.13.3+dfsg-1~noble) but 3.8.4+dfsg-3ubuntu3+esm1 is to be installed',
            '  E: Unable to correct problems, you have held broken packages.',
            '[13:01:30] ✗ Command failed (exit 100)']


def test_failed_deploy_keeps_the_end_of_its_log_and_scrubs_secrets(h):
    h['_mod_result_start']('takserver', 'deploy')
    h['_tracked_finish']('takserver', {'error': True}, APT_FAIL + ['  password=hunter2hunter2 https://u:pw9999@x.example/'], kind='deploy')
    last = json.loads((h['_tmp'] / 'module-results.json').read_text())['takserver']['last']
    assert last['outcome'] == 'failed' and last['kind'] == 'deploy'
    assert last['step'] == 'Step 3/9: PostgreSQL' or 'PostgreSQL' in last['step']
    blob = json.dumps(last['log_tail'])
    assert 'E: Unable to correct problems' in blob and 'hunter2hunter2' not in blob and 'pw9999' not in blob


def test_log_tail_is_capped_and_a_later_success_clears_it(h):
    h['_mod_result_start']('takserver', 'deploy')
    h['_tracked_finish']('takserver', {'error': True}, [f'line {i} ' + 'x' * 400 for i in range(200)], kind='deploy')
    tail = h['_mod_results_load']()['takserver']['last']['log_tail']
    assert len(tail) == 40 and tail[-1].startswith('line 199') and all(len(l) <= 240 for l in tail)
    h['_mod_result_start']('takserver', 'deploy')
    h['_tracked_finish']('takserver', {'error': False}, ['fine'], kind='deploy')
    assert 'log_tail' not in h['_mod_results_load']()['takserver']['last']


def test_a_successful_run_stores_no_log(h):
    h['_mod_result_start']('caddy', 'update')
    h['_mod_result_finish']('caddy', True)
    assert 'log_tail' not in h['_mod_results_load']()['caddy']['last']


def test_report_shows_the_failed_install_when_tak_server_is_not_installed(h, monkeypatch):
    monkeypatch.setattr(os.path, 'exists', lambda p: False)
    h['_mod_result_start']('takserver', 'deploy')
    h['_tracked_finish']('takserver', {'error': True}, APT_FAIL, kind='deploy')
    out = '\n'.join(h['_diag_section_failed_install']({}))
    assert 'TAK Server on this box: NOT installed' in out
    assert 'takserver: last deploy FAILED' in out and 'Step 3/9' in out
    assert 'gdal-data (= 3.13.3+dfsg-1~noble) but 3.8.4+dfsg-3ubuntu3+esm1 is to be installed' in out
    assert 'E: Unable to correct problems' in out and 'exit 100' in out


def test_interrupted_attempt_without_log_says_why_and_a_newer_success_hides_old_failure(h, monkeypatch):
    monkeypatch.setattr(os.path, 'exists', lambda p: p == '/opt/tak')
    h['_mod_result_start']('takserver', 'deploy')
    h['_mod_results_mark_interrupted']()
    out = '\n'.join(h['_diag_section_failed_install']({}))
    assert 'TAK Server on this box: installed' in out and 'INTERRUPTED' in out and 'cut off by a console restart' in out
    h['_mod_result_start']('takserver', 'deploy')
    h['_tracked_finish']('takserver', {'error': False}, [], kind='deploy')
    out = '\n'.join(h['_diag_section_failed_install']({}))
    assert 'no failed or cut-off install, deploy or update is recorded' in out and 'INTERRUPTED' not in out


def test_nothing_recorded_on_a_box_without_tak_says_no_attempt_reached_deploy(h, monkeypatch):
    monkeypatch.setattr(os.path, 'exists', lambda p: False)
    out = '\n'.join(h['_diag_section_failed_install']({}))
    assert 'TAK Server is not installed, so no install attempt reached the deploy step' in out


def test_deploy_that_failed_before_recording_is_read_from_the_session_log(h, monkeypatch):
    monkeypatch.setattr(os.path, 'exists', lambda p: False)
    h['deploy_status']['error'] = True
    h['deploy_log'].extend(APT_FAIL)
    out = '\n'.join(h['_diag_section_failed_install']({}))
    assert 'deploy log of this console session' in out and 'E: Unable to correct problems' in out


def test_other_modules_failures_are_shown_too_and_capped_at_four(h):
    for n in ('a', 'b', 'c', 'd', 'e', 'f'):
        h['_mod_result_start'](n, 'update')
        h['_tracked_finish'](n, {'error': True}, [f'{n} boom'], kind='update')
    out = '\n'.join(h['_diag_section_failed_install']({}))
    assert sum(l.endswith(('step: ?')) or '| step:' in l for l in out.splitlines()) == 4


# --------------------------------------------------------------------------- #
# wiring
# --------------------------------------------------------------------------- #

def test_sections_are_registered_in_the_report():
    reg = APP[APP.index('_DIAG_SECTIONS = ('):APP.index('def _diag_collect')]
    assert '_diag_section_package_sources' in reg and '_diag_section_failed_install' in reg


def test_every_tak_server_deploy_thread_is_recorded_as_a_deploy():
    assert 'target=run_takserver_deploy' not in APP
    starts = re.findall(r"target=_run_tracked, daemon=True,[^\n]*\n\s+args=\('takserver', deploy_status, deploy_log, "
                        r"run_takserver_deploy, \w+\),\n\s+kwargs=\{'kind': 'deploy'\}", APP)
    assert len(starts) == 2


def test_new_sections_only_read():
    body = '\n'.join(_cut(n) for n in ('_diag_ubuntu_pro', '_diag_apt_pins', '_diag_apt_sources', '_diag_apt_candidates',
                                       '_diag_apt_priorities', '_diag_rpm_sources', '_diag_section_package_sources',
                                       '_diag_section_failed_install'))
    code = re.sub(r'#.*|""".*?"""', '', body, flags=re.S)
    assert not re.search(r"'(install|remove|purge|update|upgrade|enable|attach|detach|refresh)'", code)
    assert not re.search(r'\b(write|unlink|rmtree|chmod)\(', code)
    assert "'pro', 'status'" not in code and "[pro, 'status', '--format', 'json']" in code
