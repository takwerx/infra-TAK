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
"""The console reads /proc/<pid>/exe with readlink only, never lstat (ops #1298).

Rocky 9, SELinux Enforcing, confined console (takwerx_console_t). The journal got about 1,800
priority-err lines in 3 hours from setroubleshoot, one per SELinux denial:

    SELinux is preventing /usr/bin/python3.9 from getattr access on the lnk_file /proc/<pid>/exe

The policy lets the console `read` another domain's lnk_file (readlink) but not `getattr`
(lstat). `_trusted_java_exe()` called os.path.realpath('/proc/<pid>/exe'), and realpath does an
lstat on every path part. On the nuc (Rocky 9.8) that was 477 denials in 3 hours. The kernel
already returns the resolved path from readlink, so realpath added nothing.

These tests fail if any console code takes a metadata call (lstat, realpath, islink, resolve)
on /proc/<pid>/exe, and prove the helper still returns the same answer for every case it had.
"""

import ast
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TOP = ast.parse(APP).body

JVM = '/usr/lib/jvm/java-17-openjdk-amd64/bin/java'


def _load(names, ns):
    parts = [ast.get_source_segment(APP, n) for n in TOP
             if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(parts) == len(names), 'a function under test was renamed or removed'
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


def _trusted(links, files=None, uid=0, mode=0o100755):
    """_trusted_java_exe(pid) against a fake /proc that, like the confined console, allows
    readlink on /proc/<pid>/exe and refuses any metadata call on it.

    links: pid -> link target, or an exception class to raise from readlink.
    files: paths that exist as regular files. Returns (result, calls made on the proc link).
    """
    files = set(files if files is not None else [JVM])
    seen = []

    def _denied(p):
        if str(p).startswith('/proc/'):
            seen.append(str(p))
            raise PermissionError(13, 'SELinux: getattr on lnk_file denied', str(p))

    def _readlink(p):
        v = links.get(p.split('/')[2], FileNotFoundError)
        if isinstance(v, type):
            raise v(p)
        return v

    def _realpath(p, *a, **kw):
        _denied(p)                      # real realpath lstat()s every part
        return p

    def _isfile(p):
        _denied(p)
        return p in files

    path = types.SimpleNamespace(realpath=_realpath, isfile=_isfile, basename=__import__('os').path.basename)
    fake_os = types.SimpleNamespace(readlink=_readlink, path=path,
                                    stat=lambda p: types.SimpleNamespace(st_uid=uid, st_mode=mode))
    ns = _load(['_trusted_java_exe'], {'os': fake_os})
    return ns['_trusted_java_exe']('4242'), seen


def test_ops1298_resolving_the_jvm_takes_no_metadata_call_on_the_proc_link():
    exe, seen = _trusted({'4242': JVM})
    assert exe == JVM
    assert seen == [], f'metadata call on /proc/<pid>/exe (SELinux getattr denial): {seen}'


def test_ops1298_unreadable_proc_link_is_unknown_not_an_error():
    """The non-root console cannot readlink a TAK-owned process: still None, no lstat."""
    exe, seen = _trusted({'4242': PermissionError})
    assert exe is None and seen == []


def test_ops1298_exited_process_is_unknown():
    exe, seen = _trusted({})
    assert exe is None and seen == []


def test_ops1298_same_trust_gates_as_before():
    """Only a root-owned, not group/world-writable `java` under a system prefix is trusted."""
    assert _trusted({'4242': '/usr/bin/dash'}, files=['/usr/bin/dash'])[0] is None
    assert _trusted({'4242': '/tmp/evil/java'}, files=['/tmp/evil/java'])[0] is None
    assert _trusted({'4242': JVM}, uid=1000)[0] is None
    assert _trusted({'4242': JVM}, mode=0o100777)[0] is None
    assert _trusted({'4242': JVM + ' (deleted)'})[0] is None     # JDK replaced under the JVM
    assert _trusted({'4242': JVM})[0] == JVM


def test_ops1298_no_console_code_stats_a_proc_pid_link():
    """lstat, realpath, islink, resolve or stat on /proc/<pid>/exe (or cwd, root) is a
    getattr on another domain's lnk_file, which takwerx_console_t is not allowed. readlink is."""
    bad = re.compile(r"""(os\.path\.(realpath|islink|lexists|exists|isfile|isdir)|os\.(lstat|stat)|\.resolve|\.exists|\.is_symlink)"""
                     r"""\(\s*(f?['"]/proc/(\{[^}]*\}|%s|%d|<pid>)/(exe|cwd|root)['"]|Path\(f?['"]/proc/\{[^}]*\}/(exe|cwd|root)['"]\))""")
    hits = []
    for rel in ('app.py', *sorted(p.name for p in (REPO / 'modules').glob('*.py'))):
        src = APP if rel == 'app.py' else (REPO / 'modules' / rel).read_text(encoding='utf-8')
        for n, line in enumerate(src.splitlines(), 1):
            if line.lstrip().startswith('#'):
                continue
            if bad.search(line):
                hits.append(f'{rel}:{n}: {line.strip()[:120]}')
    assert not hits, 'metadata call on a /proc link:\n' + '\n'.join(hits)
