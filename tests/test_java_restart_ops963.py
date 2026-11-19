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
"""Java security update that TAK Server has not restarted onto (ops #963).

Promises, each tested with the real functions cut out of app.py:

  1. A TAK Server JVM that started BEFORE its JDK was last written to disk is "on the old Java";
     one that started after is not. A JVM whose JDK folder is gone is on the old Java.
  2. The Guard Dog update email names it only on positive evidence (Ubuntu's -security pocket,
     or a dnf advisory that lists the installed build); "could not tell" is carried, never mailed.
  3. The wiring cannot silently disappear: the email sweep collects the item, /api/os-updates
     returns `java_restart`, the console has its banner, and the TAK Server image builds pull a
     fresh base so a newer Temurin build is taken once it is out.
"""

import os
import pathlib
import re
import shutil
import subprocess as _real_subprocess
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
CONSOLE = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?\n(?=\n)', APP, re.S | re.M).group(0)


STATE_FUNCS = ('_java_proc_start_epoch', '_java_is_tak_cmdline', '_tak_native_java_procs',
               '_java_installed_at', '_java_stale_procs', '_java_restart_state')
SEC_FUNCS = ('_java_package_candidates', '_java_update_security', '_java_restart_items')

POLICY_SECURITY = """openjdk-17-jre-headless:
  Installed: 17.0.21.1+1-1ubuntu1~22.04
  Candidate: 17.0.21.1+1-1ubuntu1~22.04
  Version table:
 *** 17.0.21.1+1-1ubuntu1~22.04 500
        500 http://security.ubuntu.com/ubuntu jammy-security/main amd64 Packages
        100 /var/lib/dpkg/status
     17.0.18+8-1~22.04 500
        500 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages
"""
POLICY_UPDATES = """openjdk-17-jre-headless:
  Installed: 17.0.18+8-1~22.04
  Version table:
 *** 17.0.18+8-1~22.04 500
        500 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages
        100 /var/lib/dpkg/status
"""


def _ns(extra=None):
    n = {'re': re, 'os': os, 'shutil': shutil, 'time': time, 'subprocess': _real_subprocess,
         'print': lambda *a, **k: None, '_tak_is_container': lambda: False}
    src = '\n'.join([_const('_JAVA_PKG_MAJOR_RE'), _const('_JAVA_RESTART_HOW'),
                     _cut('_apt_policy_installed_from_security')]
                    + [_cut(f) for f in STATE_FUNCS + SEC_FUNCS])
    src = src.replace('_APT_SECURITY_SUITE_RE', '_SEC_RX')
    n['_SEC_RX'] = re.compile(r'[\w.+~]+-security(?=[/,\s\])]|$)')
    exec(compile(src, 'app.py', 'exec'), n)
    n.update(extra or {})
    return n


# ── fake /proc ────────────────────────────────────────────────────────────────

def _stat_line(pid, comm, start_ticks):
    # pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime
    # cutime cstime priority nice threads itrealvalue starttime ...   (starttime is field 22)
    rest = ['S', '1', '1', '1', '0', '-1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '20', '0', '1', '0',
            str(start_ticks), '0']
    return f'{pid} ({comm}) ' + ' '.join(rest) + '\n'


def _fake_proc(tmp_path, procs, btime=1_000_000):
    root = tmp_path / 'proc'
    root.mkdir()
    (root / 'stat').write_text(f'cpu  1 2 3\nbtime {btime}\nprocesses 9\n')
    for pid, argv, comm, ticks in procs:
        d = root / str(pid)
        d.mkdir()
        (d / 'cmdline').write_bytes(b'\0'.join(a.encode() for a in argv) + b'\0')
        (d / 'stat').write_text(_stat_line(pid, comm, ticks))
    (root / 'self').mkdir()          # non-numeric entries are skipped
    return str(root)


TAK_ARGV = ['/usr/bin/java', '-Dspring.profiles.active=messaging', '-jar', '/opt/tak/takserver.war']
OTHER_ARGV = ['/usr/bin/java', '-jar', '/opt/other/app.jar']


# ── 1. what runs vs what is installed ─────────────────────────────────────────

def test_start_time_is_read_from_the_stat_line_even_with_a_hard_command_name():
    n = _ns()
    line = _stat_line(42, 'java) (x', 500)
    assert n['_java_proc_start_epoch'](line, 1000, 100) == 1005.0
    assert n['_java_proc_start_epoch']('garbage', 1000, 100) is None
    assert n['_java_proc_start_epoch'](line, 1000, 0) is None


def test_only_takservers_own_java_processes_are_looked_at(tmp_path):
    n = _ns()
    root = _fake_proc(tmp_path, [(100, TAK_ARGV, 'java', 6000),
                                 (101, OTHER_ARGV, 'java', 6000),
                                 (102, ['/usr/sbin/sshd', '-D', '/opt/tak/x'], 'sshd', 6000)])
    got = n['_tak_native_java_procs'](root)
    assert [p['pid'] for p in got] == [100]
    assert got[0]['java'] == '/usr/bin/java'
    assert got[0]['start'] == 1_000_000 + 6000 / os.sysconf('SC_CLK_TCK')


def test_a_docker_install_reports_nothing_because_its_java_is_in_the_image(tmp_path):
    n = _ns({'_tak_is_container': lambda: True})
    root = _fake_proc(tmp_path, [(100, TAK_ARGV, 'java', 6000)])
    assert n['_tak_native_java_procs'](root) == []


def test_unreadable_proc_is_not_an_alarm(tmp_path):
    assert _ns()['_tak_native_java_procs'](str(tmp_path / 'nope')) == []


def test_a_process_started_before_the_jdk_changed_is_on_the_old_java():
    n = _ns()
    procs = [{'pid': 1, 'start': 100.0, 'java': '/usr/bin/java'},
             {'pid': 2, 'start': 300.0, 'java': '/usr/bin/java'}]
    stale, newest, real = n['_java_stale_procs'](procs, lambda j: (200.0, '/usr/lib/jvm/java-17-openjdk-amd64/bin/java'))
    assert [p['pid'] for p in stale] == [1]          # 2 started after the install
    assert newest == 200.0
    assert real.endswith('java-17-openjdk-amd64/bin/java')


def test_a_jdk_that_could_not_be_read_claims_nothing():
    n = _ns()
    stale, newest, _ = n['_java_stale_procs']([{'pid': 1, 'start': 1.0, 'java': 'java'}], lambda j: (None, ''))
    assert stale == [] and newest == 0.0


def test_a_jvm_whose_folder_was_removed_by_the_update_is_on_the_old_java(tmp_path):
    n = _ns()
    gone = str(tmp_path / 'java-17-openjdk-17.0.19.0.10-1.el9' / 'bin' / 'java')   # not on disk
    when, real = n['_java_installed_at'](gone)
    assert when == float('inf') and real == gone
    stale, newest, _ = n['_java_stale_procs']([{'pid': 1, 'start': 5.0, 'java': gone}], n['_java_installed_at'])
    assert [p['pid'] for p in stale] == [1] and newest == 0.0


def test_install_time_is_the_newest_change_time_of_java_and_libjvm(tmp_path):
    n = _ns()
    home = tmp_path / 'jvm'
    (home / 'bin').mkdir(parents=True)
    (home / 'lib' / 'server').mkdir(parents=True)
    (home / 'bin' / 'java').write_text('x')
    (home / 'lib' / 'server' / 'libjvm.so').write_text('x')
    when, real = n['_java_installed_at'](str(home / 'bin' / 'java'))
    assert abs(when - time.time()) < 60 and real == str(home / 'bin' / 'java')


def test_end_to_end_the_proof_started_before_the_update_flagged_after_a_restart_clear(tmp_path):
    """The real chain on a fake /proc and a real JDK folder: running since long before the JDK
    was written -> flagged; a process that started after the JDK was written -> clear."""
    home = tmp_path / 'jvm'
    (home / 'bin').mkdir(parents=True)
    (home / 'lib' / 'server').mkdir(parents=True)
    (home / 'bin' / 'java').write_text('x')
    (home / 'lib' / 'server' / 'libjvm.so').write_text('x')
    java = str(home / 'bin' / 'java')
    hz = os.sysconf('SC_CLK_TCK')
    btime = int(time.time()) - 1000
    old_ticks = 10 * hz                       # up 10 s after boot: 990 s ago, before the JDK file
    new_ticks = 2000 * hz                     # "started" 1000 s after boot: in the future, after it
    argv = [java] + TAK_ARGV[1:]
    n = _ns()
    (tmp_path / 'a').mkdir()
    (tmp_path / 'b').mkdir()
    old = _fake_proc(tmp_path / 'a', [(100, argv, 'java', old_ticks)], btime)
    new = _fake_proc(tmp_path / 'b', [(100, argv, 'java', new_ticks)], btime)
    read_procs = n['_tak_native_java_procs']
    n['_tak_native_java_procs'] = lambda: read_procs(old)
    st = n['_java_restart_state']()
    assert st['stale'] == [100] and st['sig'].startswith('java@') and st['java'] == java
    n['_tak_native_java_procs'] = lambda: read_procs(new)
    assert n['_java_restart_state']()['stale'] == []


# ── 2. the email item needs positive evidence ─────────────────────────────────

def _run_fake(stdout, rc=0):
    def run(cmd, **kw):
        return types.SimpleNamespace(returncode=rc, stdout=stdout, stderr='')
    return types.SimpleNamespace(run=run)


def _sec_ns(mgr='apt', versions=None, policy=POLICY_SECURITY, policy_rc=0, advisories=None, stale=True):
    state = ({'stale': [100], 'installed_at': 5.0, 'java': '/usr/lib/jvm/java-17-openjdk-amd64/bin/java',
              'sig': 'java@5'} if stale else {'stale': [], 'installed_at': 0.0, 'java': '', 'sig': ''})
    return _ns({'_pkg_mgr': lambda: mgr,
                '_installed_pkg_versions': lambda names: {k: v for k, v in (versions or {
                    'openjdk-17-jre-headless': '17.0.21.1+1-1ubuntu1~22.04'}).items() if k in names},
                '_real_bin': lambda name: name,
                'subprocess': _run_fake(policy, policy_rc),
                '_dnf_security_advisories': lambda extra=(): advisories or [],
                '_java_restart_state': lambda: state})


def test_a_security_pocket_build_is_named_as_a_security_update():
    n = _sec_ns()
    (item,) = n['_java_restart_items'](set())
    assert item['key'] == 'java-restart' and item['identity'] == 'java@5'
    assert 'restart TAK Server' in item['summary'] and item['security'] and not item.get('patch_now')
    assert 'Restart TAK Server' in item['how']
    assert 'openjdk-17-jre-headless' in item['target']


def test_a_plain_updates_pocket_build_is_not_called_security():
    assert _sec_ns(policy=POLICY_UPDATES)['_java_restart_items'](set()) == []


def test_a_jdk_that_is_not_a_distro_package_claims_nothing():
    assert _sec_ns(versions={'something-else': '1'})['_java_restart_items'](set()) == []


def test_no_stale_process_means_no_mail():
    assert _sec_ns(stale=False)['_java_restart_items'](set()) == []


def test_could_not_tell_is_carried_not_mailed():
    unknown = set()
    assert _sec_ns(policy_rc=100)['_java_restart_items'](unknown) == []
    assert unknown == {'java-restart'}


def test_dnf_needs_an_advisory_that_lists_the_installed_build():
    ver = '1:17.0.21.0.10-1.el9'
    jdk = '/usr/lib/jvm/java-17-openjdk-17.0.21.0.10-1.el9.x86_64/bin/java'
    adv = [{'id': 'RHSA-2026:9999', 'severity': 'Important', 'nevra': 'java-17-openjdk-headless-1:17.0.21.0.10-1.el9.x86_64'}]
    n = _sec_ns(mgr='dnf', versions={'java-17-openjdk-headless': ver}, advisories=adv)
    n['_java_restart_state'] = lambda: {'stale': [1], 'installed_at': 5.0, 'java': jdk, 'sig': 'java@5'}
    (item,) = n['_java_restart_items'](set())
    assert 'RHSA-2026:9999' in ' '.join(item['security'])
    other = _sec_ns(mgr='dnf', versions={'java-17-openjdk-headless': ver},
                    advisories=[dict(adv[0], nevra='java-17-openjdk-headless-1:17.0.12.0.7-1.el9.x86_64')])
    other['_java_restart_state'] = n['_java_restart_state']
    assert other['_java_restart_items'](set()) == []


def test_package_names_follow_the_java_major_in_the_path():
    n = _ns()
    f = n['_java_package_candidates']
    assert f('/usr/lib/jvm/java-21-openjdk-amd64/bin/java', 'apt')[0] == 'openjdk-21-jre-headless'
    assert f('/usr/lib/jvm/java-17-openjdk-17.0.21/bin/java', 'dnf')[0] == 'java-17-openjdk-headless'
    assert f('', 'apt')[0] == 'openjdk-17-jre-headless'


# ── 3. the wiring ─────────────────────────────────────────────────────────────

def test_the_email_sweep_collects_the_java_item():
    sweep = _cut('_collect_pending_updates')
    assert 'pending.extend(_java_restart_items(unknown))' in sweep


def test_os_updates_api_returns_java_restart():
    assert "data['java_restart'] = _java_restart_state()" in _cut('os_updates_api')


def test_the_console_has_the_banner_and_the_restart_button():
    assert 'id="java-restart-banner"' in CONSOLE
    assert '_javaRestartRender(ud)' in CONSOLE
    assert "/api/takserver/control" in CONSOLE and "action:'restart',target:'core'" in CONSOLE
    # a banner that never shows is no banner: it is shown from java_restart.stale
    assert 'j.stale.length' in CONSOLE


def test_tak_server_image_builds_pull_a_fresh_base():
    # deploy and update both build the takserver image; a cached old Temurin must not survive
    assert APP.count('docker build --pull -t {TAK_CONTAINER}') == 2
    assert 'docker build -t {TAK_CONTAINER}' not in APP
