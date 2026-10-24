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
"""Guard Dog's JVM watch never mistakes another pgrep for the TAK JVM (ops #191).

Field box, 2026-10-23 09:31:50Z, a healthy TAK on Java 17 emailed:

    TAK Server is running on the WRONG JVM
    TAK API PID: 221445
    JVM in use: /usr/bin/pgrep
    Reported as: /usr/bin/pgrep: invalid option -- 'e'

tak-jvm-watch.sh took `pgrep -f -- '-Dspring.profiles.active=api' | head -1`. pgrep skips only
itself, so the console's identical pgrep (TAK Server card, Guard Dog `jvm` monitor) running at
the same second was listed too, and after a PID wrap it sorted ahead of the JVM. /usr/bin/pgrep
is root-owned under /usr/bin, so it cleared the trust gate, and `pgrep -version` has no "17".

Now the script takes the first PID whose exe is `java`, and output with no `version "` string
is unknown, never an alert. The REAL script runs with pgrep / readlink / stat stubbed and its
trusted prefixes and state paths pointed into a sandbox.
"""

import ast
import os
import pathlib
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-jvm-watch.sh').read_text()
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TOP = ast.parse(APP).body

PGREP_PID, JVM_PID = '1187', '221445'          # wrapped counter: the pgrep sorts first
J17 = 'openjdk version "17.0.11" 2024-04-16\nOpenJDK Runtime Environment (build 17.0.11+9)\n'
J21 = 'openjdk version "21.0.2" 2024-01-16\nOpenJDK Runtime Environment (build 21.0.2+13)\n'
PGREP_OUT = "/usr/bin/pgrep: invalid option -- 'e'\nUsage:\n pgrep [options] <pattern>\n"


@pytest.fixture
def box(tmp_path):
    stubs, gd, state = (tmp_path / n for n in ('bin', 'gd', 'state'))
    for d in (stubs, gd):
        d.mkdir()
    java = tmp_path / 'usr/lib/jvm/java-17-openjdk-amd64/bin/java'
    pgrep = tmp_path / 'usr/bin/pgrep'
    for f in (java, pgrep):
        f.parent.mkdir(parents=True)
    pgrep.write_text('#!/bin/sh\nprintf "%%s" "$(cat %s)" >&2\nexit 2\n' % (tmp_path / 'pgrep.out'))
    (tmp_path / 'pgrep.out').write_text(PGREP_OUT)
    mails = tmp_path / 'mails'
    alert = gd / 'send-alert-email.sh'
    alert.write_text('#!/bin/sh\n{ echo "SUBJECT $1"; cat; echo; } >> %s\n' % mails)
    # pgrep: the PID list in $tmp/pids, ascending, as the real one prints it
    (stubs / 'pgrep').write_text('#!/bin/sh\ncat %s\n' % (tmp_path / 'pids'))
    # readlink -f /proc/N/exe -> $tmp/exe/N; a missing entry is a process that has exited
    (stubs / 'readlink').write_text(
        '#!/bin/sh\nn=${2#/proc/}; n=${n%%/exe}\n[ -f %s/exe/$n ] || exit 1\ncat %s/exe/$n\n'
        % (tmp_path, tmp_path))
    (stubs / 'stat').write_text('#!/bin/sh\ncase "$2" in %u) echo 0 ;; %a) echo 755 ;; esac\n')
    (tmp_path / 'exe').mkdir()
    for f in (alert, pgrep, *stubs.iterdir()):
        f.chmod(0o755)
    script = (WATCH.replace('/opt/tak-guarddog/', str(gd) + '/')
                   .replace('/var/lib/takguard', str(state))
                   .replace('/tmp/', str(tmp_path) + '/')
                   .replace('  /usr/lib/jvm/*|', '  %s/usr/lib/jvm/*|' % tmp_path)
                   .replace('|/usr/bin/*|', '|%s/usr/bin/*|' % tmp_path))
    assert script.count(str(tmp_path) + '/usr/') == 2, 'trusted-prefix case line changed'
    sp = tmp_path / 'watch.sh'
    sp.write_text(script)

    def run(pids, exes, java_out=J17):
        (tmp_path / 'pids').write_text(''.join(p + '\n' for p in pids))
        for f in (tmp_path / 'exe').iterdir():
            f.unlink()
        for pid, which in exes.items():
            (tmp_path / 'exe' / pid).write_text(str(java if which == 'java' else pgrep))
        java.write_text('#!/bin/sh\nprintf "%%s" "$(cat %s)" >&2\n' % (tmp_path / 'java.out'))
        java.chmod(0o755)
        (tmp_path / 'java.out').write_text(java_out)
        if mails.exists():
            mails.unlink()
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        status = (state / 'jvm_status').read_text()
        kv = dict(l.split('=', 1) for l in status.splitlines() if '=' in l)
        return (mails.read_text() if mails.exists() else ''), kv

    run.java = str(java)
    run.alert_sent = state / 'jvm_alert_sent'
    return run


def test_ops191_other_pgrep_listed_first_is_skipped_and_the_jvm_recorded(box):
    mail, kv = box([PGREP_PID, JVM_PID], {PGREP_PID: 'pgrep', JVM_PID: 'java'})
    assert mail == ''
    assert kv['pid'] == JVM_PID and kv['exe'] == box.java
    assert 'version "17.0.11"' in kv['version']
    assert not box.alert_sent.exists()


def test_ops191_only_a_pgrep_in_the_list_is_unknown_not_an_alert(box):
    mail, kv = box([PGREP_PID], {PGREP_PID: 'pgrep'})
    assert mail == '' and kv == {'unknown': '1'}
    assert not box.alert_sent.exists()


def test_ops191_pgrep_already_exited_still_finds_the_jvm(box):
    mail, kv = box([PGREP_PID, JVM_PID], {JVM_PID: 'java'})
    assert mail == '' and kv['pid'] == JVM_PID


def test_ops191_no_java_version_string_is_unknown_not_wrong(box):
    mail, kv = box([JVM_PID], {JVM_PID: 'java'}, java_out=PGREP_OUT)
    assert mail == ''
    assert kv['unknown'] == '1' and kv['pid'] == JVM_PID and 'version' not in kv
    assert not box.alert_sent.exists()


def test_java_tool_options_banner_first_is_not_an_alert(box):
    out = 'Picked up JAVA_TOOL_OPTIONS: -Xss2m\n' + J17
    mail, kv = box([JVM_PID], {JVM_PID: 'java'}, java_out=out)
    assert mail == '' and 'version "17.0.11"' in kv['version']


def test_a_real_wrong_jvm_still_alerts_with_the_jvm_pid(box):
    mail, kv = box([PGREP_PID, JVM_PID], {PGREP_PID: 'pgrep', JVM_PID: 'java'}, java_out=J21)
    assert mail.startswith('SUBJECT TAK Server is running on the WRONG JVM on ')
    assert 'TAK API PID: %s' % JVM_PID in mail and 'JVM in use: %s' % box.java in mail
    assert 'version "21.0.2"' in mail and 'pgrep' not in mail
    assert box.alert_sent.exists()


# ── console side ──────────────────────────────────────────────────────────────

def _load(names, ns):
    parts = [ast.get_source_segment(APP, n) for n in TOP
             if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(parts) == len(names), 'a function under test was renamed or removed'
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


def _api_pid(pids, exe=None, comm=None):
    """_tak_api_pid() against a fake /proc: exe/comm map pid -> name, or an exception."""
    def _readlink(p):
        v = (exe or {}).get(p.split('/')[2], FileNotFoundError)
        if isinstance(v, type):
            raise v(p)
        return v

    def _open(p, *a, **kw):
        v = (comm or {}).get(p.split('/')[2], FileNotFoundError)
        if isinstance(v, type):
            raise v(p)
        return __import__('io').StringIO(v + '\n')

    ns = {'subprocess': types.SimpleNamespace(run=lambda *a, **kw: types.SimpleNamespace(
              returncode=0, stdout=''.join(p + '\n' for p in pids), stderr='')),
          'os': types.SimpleNamespace(readlink=_readlink, path=os.path), 'open': _open}
    return _load(['_tak_api_pid'], ns)['_tak_api_pid']()


def test_ops191_console_root_skips_the_other_pgrep():
    assert _api_pid([PGREP_PID, JVM_PID], exe={PGREP_PID: '/usr/bin/pgrep',
                                               JVM_PID: '/usr/lib/jvm/x/bin/java'}) == JVM_PID


def test_ops191_console_nonroot_uses_comm_to_skip_the_other_pgrep():
    perm = PermissionError
    assert _api_pid([PGREP_PID, JVM_PID], exe={PGREP_PID: perm, JVM_PID: perm},
                    comm={PGREP_PID: 'pgrep', JVM_PID: 'java'}) == JVM_PID


def test_console_exited_pid_is_skipped_and_unclassifiable_is_kept():
    assert _api_pid([PGREP_PID, JVM_PID], exe={JVM_PID: '/usr/lib/jvm/x/bin/java'}) == JVM_PID
    perm = PermissionError
    assert _api_pid([JVM_PID], exe={JVM_PID: perm}, comm={JVM_PID: perm}) == JVM_PID


def test_console_jvm_replaced_on_disk_is_still_the_jvm():
    assert _api_pid([JVM_PID], exe={JVM_PID: '/usr/lib/jvm/x/bin/java (deleted)'}) == JVM_PID


def test_console_nothing_but_pgrep_is_none():
    assert _api_pid([PGREP_PID], exe={PGREP_PID: '/usr/bin/pgrep'}) is None
    assert _api_pid([]) is None


def _jvm_monitor(version):
    ns = {'_tak_is_container': lambda: False, '_tak_api_pid': lambda: JVM_PID,
          '_trusted_java_exe': lambda pid: None,
          '_jvm_status_from_guarddog': lambda pid: {'pid': pid, 'version': version}}
    return _load(['_monitor_health_check'], ns)['_monitor_health_check']('jvm')


def test_ops191_jvm_monitor_greys_on_output_with_no_java_version():
    assert _jvm_monitor("/usr/bin/pgrep: invalid option -- 'e'") is None
    assert _jvm_monitor('') is None
    assert _jvm_monitor('openjdk version "17.0.11" 2024-04-16') is True
    assert _jvm_monitor('openjdk version "21.0.2" 2024-01-16') is False


# ── delivery ─────────────────────────────────────────────────────────────────

def test_ops191_watch_script_rides_both_redeploy_paths():
    deploy = APP[APP.index('def run_guarddog_deploy(alert_email):'):]
    assert "'tak-jvm-watch.sh'" in deploy[:deploy.index('# Optional: monitors')]
    # The startup copy takes every script in scripts/guarddog/ and rewrites any that differ.
    auto = ast.get_source_segment(APP, next(n for n in TOP
                                            if isinstance(n, ast.FunctionDef)
                                            and n.name == '_auto_update_guarddog'))
    assert "os.listdir(scripts_dir) if f.endswith(('.sh', '.py'))" in auto
    assert '_read_priv(dest) == content' in auto and '_write_priv(dest, content, perm=0o755)' in auto
