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
"""A package-manager error is "could not check", never "nothing pending" (ops #152).

Field: on a Rocky 9 box the console user's `dnf -C -q check-update` exited 1
(PGDG repo_gpgcheck key it could not import, so "no cache for 'pgdg-common'").
stdout was empty, the parser returned [], and the OS-updates panel said nothing
was pending while ~190 updates (a kernel among them) were. The kernel
and Caddy checks had the same rc=1 = "current" shape. The functions are cut out
of app.py and run with the package manager faked.
"""

import hashlib
import importlib.util
import os
import pathlib
import re
import subprocess as _real_subprocess
import time
import types
from datetime import datetime

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
BROKER_PY = REPO / 'broker' / 'takwerx_broker.py'

DNF_ROWS = (
    'kernel.x86_64          5.14.0-687.57.1.el9_8   baseos\n'
    'kernel-core.x86_64     5.14.0-687.57.1.el9_8   baseos\n'
    'openssh.x86_64         9.9p1-12.el9_8          baseos\n'
    'sudo.x86_64            1.9.17p2-3.el9_8.3      baseos\n'
)
PGDG_ERR = ('Importing GPG key 0x08B40D20:\n'
            "Error: Cache-only enabled but no cache for 'pgdg-common'\n")


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _src(*names):
    consts = [re.search(rf'^{c} = .*?(?=^\S)', APP, re.S | re.M).group(0)
              for c in ('_DNF_CHECK_OK_RC', '_DNF_CHECK_UPDATE_ARGS', '_DNF_ROW_RE')]
    return '\n'.join(consts + [_cut(n) for n in names])


def _ns(answers, pkg_mgr='dnf', uid=1001):
    """answers: list of (match, rc, stdout, stderr) — first whose `match` is in argv wins."""
    calls = []

    def fake_run(argv, *a, **k):
        calls.append((list(argv), k))
        for match, rc, out, err in answers:
            if match in argv:
                if isinstance(rc, BaseException):
                    raise rc
                return _real_subprocess.CompletedProcess(argv, rc, out, err)
        return _real_subprocess.CompletedProcess(argv, 0, '', '')

    sub = types.SimpleNamespace(run=fake_run, DEVNULL=_real_subprocess.DEVNULL,
                                TimeoutExpired=_real_subprocess.TimeoutExpired)
    fake_os = types.SimpleNamespace(getuid=lambda: uid, path=os.path)
    n = {
        're': re, 'os': fake_os, 'subprocess': sub,
        '_pkg_mgr': lambda: pkg_mgr,
        '_real_bin': lambda name: '/usr/bin/' + name,
        # the broker path: tag the argv so a test can tell the two attempts apart
        '_sudo_wrap': lambda argv: ['BROKER'] + list(argv),
    }
    exec(compile(_src('_parse_dnf_check_update', '_parse_apt_simulation', '_dnf_error_tail',
                      '_dnf_ignored_repos', '_dnf_check_update_run', '_pending_os_updates'),
                 'app.py', 'exec'), n)
    return n, calls


# ── _pending_os_updates: dnf ───────────────────────────────────────────────────

def test_dnf_rc1_raises_instead_of_returning_empty():
    n, calls = _ns([('check-update', 1, '', PGDG_ERR)])
    with pytest.raises(RuntimeError) as e:
        n['_pending_os_updates']()
    assert 'rc=1' in str(e.value)
    assert "no cache for 'pgdg-common'" in str(e.value)
    # both the broker (root cache) and the console-user path were tried
    assert len(calls) == 2 and calls[0][0][0] == 'BROKER' and calls[1][0][0] == '/usr/bin/dnf'


def test_dnf_reads_root_cache_through_broker_first():
    n, calls = _ns([('check-update', 100, DNF_ROWS, '')])
    pend = n['_pending_os_updates']()
    assert [p['name'] for p in pend] == ['kernel', 'kernel-core', 'openssh', 'sudo']
    argv, kw = calls[0]
    assert argv[:2] == ['BROKER', 'dnf']
    # cacheonly, never answers a GPG prompt yes, one dead repo does not blank the list
    for flag in ('-C', '--assumeno', '--setopt=skip_if_unavailable=True', 'check-update'):
        assert flag in argv
    assert '-y' not in argv and '--assumeyes' not in argv
    assert kw.get('stdin') == _real_subprocess.DEVNULL


def test_dnf_falls_back_to_console_user_when_broker_path_fails():
    answers = [('BROKER', 1, '', 'Error: denied'), ('/usr/bin/dnf', 100, DNF_ROWS, '')]
    n, calls = _ns(answers)
    pend = n['_pending_os_updates']()
    assert 'kernel' in [p['name'] for p in pend]
    assert len(calls) >= 2


def test_dnf_rc0_is_genuinely_up_to_date():
    n, _ = _ns([('check-update', 0, '', '')])
    assert n['_pending_os_updates']() == []


def test_dnf_skipped_repo_is_reported_and_never_reads_as_current():
    skipped = "Error: Cache-only enabled but no cache for 'pgdg-common'\nIgnoring repositories: pgdg-common\n"
    # some updates listed: returned, with the skipped repo noted
    n, _ = _ns([('check-update', 100, DNF_ROWS, skipped)])
    notes = {}
    assert len(n['_pending_os_updates'](notes)) == 4
    assert notes['skipped_repos'] == ['pgdg-common']
    # nothing listed AND a repo skipped: that is not "up to date"
    n, _ = _ns([('check-update', 0, '', skipped)])
    with pytest.raises(RuntimeError) as e:
        n['_pending_os_updates']({})
    assert 'pgdg-common' in str(e.value)


def test_dnf_timeout_raises():
    n, _ = _ns([('check-update', _real_subprocess.TimeoutExpired('dnf', 60), '', '')])
    with pytest.raises(RuntimeError):
        n['_pending_os_updates']()


def test_root_console_does_not_run_the_same_check_twice():
    n, calls = _ns([('check-update', 1, '', 'Error: x')], uid=0)
    with pytest.raises(RuntimeError):
        n['_pending_os_updates']()
    assert len(calls) == 1


# ── _pending_os_updates: apt ───────────────────────────────────────────────────

def test_apt_error_raises():
    n, _ = _ns([('full-upgrade', 100, '', 'E: Unable to correct problems, you have held broken packages.')],
               pkg_mgr='apt')
    with pytest.raises(RuntimeError) as e:
        n['_pending_os_updates']()
    assert 'rc=100' in str(e.value)


def test_apt_success_unchanged():
    out = ('NOTE: This is only a simulation!\n'
           'Inst linux-image-generic [5.15.0.177] (5.15.0.180 Ubuntu:22.04/jammy-security [amd64])\n')
    n, calls = _ns([('full-upgrade', 0, out, '')], pkg_mgr='apt')
    assert n['_pending_os_updates']() == [{'name': 'linux-image-generic', 'old': '5.15.0.177',
                                           'new': '5.15.0.180'}]
    assert calls[0][0] == ['/usr/bin/apt-get', '-s', 'full-upgrade']


# ── _os_updates_summary: the panel's view ──────────────────────────────────────

def test_summary_carries_the_error_not_an_empty_list():
    n, _ = _ns([('check-update', 1, '', PGDG_ERR)])
    n.update({
        'time': time, 'hashlib': hashlib, 'datetime': datetime,
        'os': types.SimpleNamespace(getuid=lambda: 1001,
                                    path=types.SimpleNamespace(exists=lambda p: False)),
        '_OS_UPDATES_CACHE': {'ts': 0.0, 'data': None}, '_OS_UPDATES_TTL': 300,
        '_classify_os_updates': lambda p: ([], list(p)),
        '_auto_update_posture': lambda: {},
    })
    exec(compile(_cut('_os_updates_summary'), 'app.py', 'exec'), n)
    d = n['_os_updates_summary'](force=True)
    assert d['error'] and 'rc=1' in d['error']
    assert d['total'] == 0 and d['skipped_repos'] == []


# ── kernel-only check ──────────────────────────────────────────────────────────

def _kernel(answers, pkg_mgr='dnf', reboot_pending=False):
    calls = []

    def fake_run(argv, *a, **k):
        calls.append(list(argv))
        if argv[:1] == ['uname']:
            return _real_subprocess.CompletedProcess(argv, 0, '5.14.0-687.39.1.el9_8.x86_64\n', '')
        rc, out, err = answers
        if isinstance(rc, BaseException):
            raise rc
        return _real_subprocess.CompletedProcess(argv, rc, out, err)

    n = {
        're': re, 'subprocess': types.SimpleNamespace(run=fake_run, DEVNULL=_real_subprocess.DEVNULL),
        'jsonify': lambda d: d, 'load_settings': lambda: {'pkg_mgr': pkg_mgr},
        '_sudo_wrap': lambda argv: list(argv),
        '_kernel_patch_cache': {'ts': 0, 'data': None},
        '_kernel_cve_banner': lambda k: None,
        '_kernel_reboot_pending': lambda: reboot_pending,
    }
    exec(compile(_cut('_dnf_error_tail') + '\n' + _cut('kernel_patch_status_api'), 'app.py', 'exec'), n)
    return n['kernel_patch_status_api'](), calls


def test_kernel_check_rc1_is_an_error_not_patched():
    d, calls = _kernel((1, '', PGDG_ERR))
    assert d['patched'] is False and d['upgradable'] is False
    assert 'rc=1' in d['error']
    assert '--assumeno' in calls[-1]


def test_kernel_check_rc100_and_rc0():
    d, _ = _kernel((100, 'kernel.x86_64 5.14.0-687.57.1.el9_8 baseos\n', ''))
    assert d['upgradable'] is True and d['patched'] is False and not d['error']
    d, _ = _kernel((0, '', ''))
    assert d['patched'] is True and not d['error']


def test_kernel_check_apt():
    d, calls = _kernel((0, 'linux-image-generic/jammy-security 5.15.0.180 amd64 [upgradable from: 5.15.0.177]\n', ''),
                       pkg_mgr='apt')
    assert d['upgradable'] is True and not d['error']
    assert calls[-1] == ['apt', 'list', '--upgradable']
    d, _ = _kernel((0, 'Listing...\n', ''), pkg_mgr='apt')
    assert d['patched'] is True
    d, _ = _kernel((100, '', 'E: boom'), pkg_mgr='apt')
    assert d['patched'] is False and d['error']


def test_kernel_check_installed_but_not_running_is_not_patched():
    # ops #154: nothing left to download, but the new kernel is not booted yet.
    d, _ = _kernel((0, '', ''), reboot_pending=True)
    assert d['patched'] is False and d['reboot_pending'] is True and not d['error']


# ── Caddy check ────────────────────────────────────────────────────────────────

def _caddy(family, rc, out=''):
    def fake_run(argv, *a, **k):
        if k.get('shell'):
            return _real_subprocess.CompletedProcess(argv, 0, 'v2.10.2 h1:abc\n', '')
        if isinstance(rc, BaseException):
            raise rc
        return _real_subprocess.CompletedProcess(argv, rc, out, 'Error: x')

    n = {
        'subprocess': types.SimpleNamespace(run=fake_run, DEVNULL=_real_subprocess.DEVNULL,
                                            TimeoutExpired=_real_subprocess.TimeoutExpired),
        '_distro_family': lambda: family, '_sudo_wrap': lambda argv: list(argv),
        '_DNF_CHECK_OK_RC': (0, 100),
    }
    exec(compile(_cut('_get_caddy_version_info'), 'app.py', 'exec'), n)
    return n['_get_caddy_version_info']()


def test_caddy_dnf_rc1_is_check_failed_not_current():
    d = _caddy('rhel', 1)
    assert d['update_check_failed'] is True and d['update_available'] is False


def test_caddy_dnf_rc100_and_rc0():
    assert _caddy('rhel', 100, 'caddy.x86_64 2.10.3-1 copr:caddy\n')['update_available'] is True
    d = _caddy('rhel', 0)
    assert d['update_available'] is False and d['update_check_failed'] is False


def test_caddy_apt():
    d = _caddy('debian', 0, 'caddy/any-version 2.10.3 amd64 [upgradable from: 2.10.2]\n')
    assert d['update_available'] is True and d['update_check_failed'] is False
    assert _caddy('debian', 0, 'Listing...\n')['update_available'] is False
    assert _caddy('debian', 100)['update_check_failed'] is True
    assert _caddy('debian', _real_subprocess.TimeoutExpired('apt', 10))['update_check_failed'] is True


# ── broker: exactly one more --setopt ──────────────────────────────────────────

@pytest.fixture(scope='module')
def broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops152_test', BROKER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_broker_allows_the_os_updates_check(broker):
    broker._check_pkgmgr(['dnf', '-C', '-q', '--assumeno', '--setopt=skip_if_unavailable=True',
                          'check-update'])
    broker._check_pkgmgr(['dnf', '-q', '--assumeno', 'check-update', 'caddy'])


@pytest.mark.parametrize('opt', [
    '--setopt=skip_if_unavailable=False',
    '--setopt=skip_if_unavailable=True,pluginpath=/tmp',
    '--setopt=pgdg-common.skip_if_unavailable=True',
    '--setopt=pluginpath=/tmp/x',
    '--setopt=reposdir=/tmp',
])
def test_broker_still_denies_every_other_setopt(broker, opt):
    with pytest.raises(broker.Denied):
        broker._check_pkgmgr(['dnf', '-C', opt, 'check-update'])


# ── the dnf Install updates job ────────────────────────────────────────────────

def _dnf_job_script():
    """The `script = (...)` literal inside `if pkg_mgr == 'dnf':` of the job."""
    import ast
    fn = ast.parse(_cut('_kernel_patch_start_job')).body[0]
    for node in ast.walk(fn):
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and getattr(node.test.left, 'id', '') == 'pkg_mgr'
                and getattr(node.test.comparators[0], 'value', '') == 'dnf'):
            for st in node.body:
                if isinstance(st, ast.Assign) and getattr(st.targets[0], 'id', '') == 'script':
                    return ast.literal_eval(st.value)
    raise AssertionError('dnf job script not found')


def test_dnf_install_job_skips_and_names_an_unreachable_repo(tmp_path):
    script = _dnf_job_script()
    assert "dnf -y upgrade --setopt=skip_if_unavailable=True --exclude='takserver*'" in script
    assert 'WARNING: could not reach $SKIPPED' in script
    f = tmp_path / 'job.sh'
    f.write_text(script)
    assert _real_subprocess.run(['bash', '-n', str(f)]).returncode == 0
    # the SKIPPED= line pulls the repo ids out of dnf's own summary line
    skipped_line = next(ln for ln in script.splitlines() if ln.startswith('SKIPPED='))
    log = tmp_path / 'upg.log'
    log.write_text("Error: Failed to download metadata for repo 'epel'\n"
                   'Ignoring repositories: epel, pgdg-common\n')
    r = _real_subprocess.run(['bash', '-c', skipped_line + '\necho "$SKIPPED"'],
                             env={'UPGLOG': str(log), 'PATH': os.environ['PATH']},
                             capture_output=True, text=True, timeout=10)
    assert r.stdout.strip() == 'epel, pgdg-common'
