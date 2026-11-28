#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Fail a PR that makes a test patch time.sleep on the shared `time` module (ops #1446).

Why: `time` is one module for the whole pytest process. A patch of `time.sleep` is seen by every thread, not
only by the test. A thread left over from an earlier test (a watcher, a retry loop) that sleeps while the
patch is on writes its own sleep into the test's list, and a test that counts or checks the sleeps fails at
random. infra-TAK dev went red this way twice (test_ldap_outpost_token_missing_provider_ops663: ops #1172 and
ops #1444). A flaky test is a bug in the check, not in the product.

What is caught, in any file under tests/ (found by reading the code, not by running it):
    patch('time.sleep'), mock.patch('app.time.sleep', ...)       a string target that ends in time.sleep
    patch.object(time, 'sleep', ...), patch.multiple(time, sleep=...)
    monkeypatch.setattr(time, 'sleep', ...), monkeypatch.setattr('time.sleep', ...), setattr(time, 'sleep', f)
    time.sleep = f
where `time` is the stdlib module under any name (`import time as _t`) or `<module>.time` (`app.time`).

What is fine, and what to do instead:
    * give the code under test its own time stand-in: monkeypatch.setattr(module, 'time', fake_time).
      This changes the name `time` inside that one module only; no other thread is touched.
    * keep a patch of the shared module only when it records nothing and cannot hide a bug, or when it
      ignores sleeps made by other threads. Say so on the same line or the line above:
          # shared-sleep-ok: <why this cannot see another thread's sleep>
      A marker with no reason does not count.

Files that already did it when this check was added are in .github/ci/shared-sleep-baseline.txt (path and
count). A file may keep what it has, never add one; a new file may not have any. When you fix a file,
delete its line from the baseline (a line the file no longer needs is reported but does not fail, so two
PRs never wait for each other).

    python3 -I .github/ci/shared_sleep_check.py             # check tests/ against the baseline
    python3 -I .github/ci/shared_sleep_check.py --list      # every finding, to write the baseline
"""
import ast
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DEFAULT_ROOT = os.path.join(REPO, 'tests')
DEFAULT_BASELINE = os.path.join(HERE, 'shared-sleep-baseline.txt')

MARKER = re.compile(r'#\s*shared-sleep-ok:\s*\S')
STRING_TARGET = re.compile(r'(^|\.)time\.sleep$')


def _dotted(node):
    """a.b.c for a Name/Attribute chain, else ''."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return '.'.join(reversed(parts))
    return ''


def _time_module_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == 'time':
                    names.add(alias.asname or 'time')
    return names


def _is_time_module(node, names):
    if isinstance(node, ast.Name):
        return node.id in names
    # app.time, atlas.time, drive.time: the module's own reference to the shared stdlib module.
    return isinstance(node, ast.Attribute) and node.attr == 'time'


def _is_str(node, value=None):
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and (value is None or node.value == value)


def _patch_kind(call):
    """'patch', 'object', 'multiple', 'setattr' or '' for the call's function."""
    name = _dotted(call.func)
    if not name:
        return ''
    last = name.rsplit('.', 1)[-1]
    before = name.rsplit('.', 1)[0].rsplit('.', 1)[-1] if '.' in name else ''
    if last == 'patch':
        return 'patch'
    if last in ('object', 'multiple') and before == 'patch':
        return last
    if last == 'setattr':
        return 'setattr'
    return ''


def _call_hits(call, names):
    kind = _patch_kind(call)
    if not kind:
        return False
    args = call.args
    if kind in ('patch', 'setattr') and args and _is_str(args[0]) and STRING_TARGET.search(args[0].value):
        return True
    if kind in ('object', 'setattr') and len(args) >= 2 and _is_time_module(args[0], names) and _is_str(args[1], 'sleep'):
        return True
    if kind == 'multiple' and args and _is_time_module(args[0], names) and any(k.arg == 'sleep' for k in call.keywords):
        return True
    return False


def _assign_hits(node, names):
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return any(isinstance(t, ast.Attribute) and t.attr == 'sleep' and _is_time_module(t.value, names) for t in targets)


def scan_source(source, filename='<test>'):
    """Return [(line, text)] of shared time.sleep patches in one file's source that carry no marker."""
    tree = ast.parse(source, filename)
    lines = source.splitlines()
    names = _time_module_names(tree)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            hit = _call_hits(node, names)
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            hit = _assign_hits(node, names)
        else:
            continue
        if not hit:
            continue
        first = node.lineno
        last = getattr(node, 'end_lineno', None) or first
        window = lines[max(first - 2, 0):last]  # the line above, the call, and any lines it spans
        if any(MARKER.search(w) for w in window):
            continue
        found.append((first, lines[first - 1].strip()))
    return sorted(set(found))


def scan_tree(root):
    """{relative path: [(line, text), ...]} for every .py file under root that has a hit."""
    result = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ('__pycache__', 'fixtures')]
        for fn in sorted(filenames):
            if not fn.endswith('.py'):
                continue
            path = os.path.join(dirpath, fn)
            with open(path, encoding='utf-8') as fh:
                source = fh.read()
            try:
                hits = scan_source(source, path)
            except SyntaxError:
                continue  # compile_check.py is the check that reports a file that does not compile
            if hits:
                result[os.path.relpath(path, root).replace(os.sep, '/')] = hits
    return result


def load_baseline(path):
    baseline = {}
    if not os.path.exists(path):
        return baseline
    with open(path, encoding='utf-8') as fh:
        for raw in fh:
            line = raw.split('#', 1)[0].strip()
            if not line:
                continue
            name, count = line.rsplit(None, 1)
            baseline[name] = int(count)
    return baseline


def compare(found, baseline):
    """Return (new, stale): new = [(file, line, text)] over the baseline, stale = [(file, now, allowed)]."""
    new, stale = [], []
    for name, hits in sorted(found.items()):
        allowed = baseline.get(name, 0)
        if len(hits) > allowed:
            new.extend((name, ln, text) for ln, text in hits)
    for name, allowed in sorted(baseline.items()):
        now = len(found.get(name, []))
        if now < allowed:
            stale.append((name, now, allowed))
    return new, stale


def main(argv):
    root = DEFAULT_ROOT
    baseline_path = DEFAULT_BASELINE
    if '--root' in argv:
        root = argv[argv.index('--root') + 1]
    if '--baseline' in argv:
        baseline_path = argv[argv.index('--baseline') + 1]
    found = scan_tree(root)
    if '--list' in argv:
        for name, hits in sorted(found.items()):
            for ln, text in hits:
                print('%s:%d: %s' % (name, ln, text))
        return 0
    new, stale = compare(found, load_baseline(baseline_path))
    for name, now, allowed in stale:
        print('note: %s now has %d (baseline %d): lower its line in %s' % (name, now, allowed, os.path.basename(baseline_path)))
    if not new:
        print('shared time.sleep patches: none new (%d files in the baseline)' % len(load_baseline(baseline_path)))
        return 0
    print('FAIL: a test patches time.sleep on the shared time module (ops #1446).')
    print('A patch of time.sleep is seen by every thread in the pytest process, so a thread left over from an')
    print('earlier test can write its own sleep into your list and fail the test at random.')
    for name, ln, text in new:
        print('  tests/%s:%d: %s' % (name, ln, text))
    print('Fix: give the code under test its own time stand-in, monkeypatch.setattr(module, "time", fake_time).')
    print('Or, if the patch cannot see another thread, add  # shared-sleep-ok: <why>  on that line or the line above.')
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
