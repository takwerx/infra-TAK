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
"""TAK Server deploy on Rocky/RHEL 9: every dnf call must pass the broker rulebook (ops #852).

On a non-root console every `dnf` goes through the broker. Two calls in the TAK Server
deploy used shapes the rulebook refuses:

* `dnf repolist --all`          -> "dnf subcommand not allowed: repolist"
* `dnf -qy module disable ...`  -> "dnf: option not allowed: -qy" (the bundled short
                                   option form is only allowed for apt)

A broker that does not enforce yet logs WOULD-DENY (and the 72-hour clean clock restarts
each time). A broker that enforces refuses them: the PostgreSQL module stays enabled and
the CRB repo is not found.

The fix is on the console side (the broker rulebook is not widened): `-q -y`, and the CRB
repo id is read from the repo files instead of `dnf repolist`.

The proof test runs the real dnf command strings found in app.py through the broker's own
checker (`check_exec`, the same function `_evaluate` calls for an `exec` request).
"""

import ast
import importlib.util
import pathlib
import re
import shlex

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
H = '/home/takwerx'


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops852', REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()
APP_SRC = (REPO / 'app.py').read_text()
APP_TREE = ast.parse(APP_SRC)


def _placeholder(expr):
    """A realistic value for an f-string field, judged by the variable's name."""
    e = expr.lower()
    if 'pkg' in e or 'rpm' in e or 'name' in e:
        return 'takserver-core-5.8-RELEASE84.noarch.rpm'
    if 'arch' in e:
        return 'x86_64'
    if 'ver' in e:
        return '9'
    return 'x'


def _const_text(node):
    """Source text of a string literal or f-string; {placeholders} become a plain word."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        out = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                out.append(str(part.value))
            else:
                out.append(_placeholder(ast.unparse(part.value)))
        return ''.join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _const_text(node.left), _const_text(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _string_literals():
    """(lineno, text) for every string literal in app.py, adjacent literals joined."""
    seen = set()
    out = []
    # pieces of an f-string or of a `'a' + 'b'` are read through their parent, not alone
    inner = set()
    for node in ast.walk(APP_TREE):
        if isinstance(node, ast.JoinedStr):
            inner.update(id(v) for v in node.values)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            inner.update((id(node.left), id(node.right)))
    for node in ast.walk(APP_TREE):
        if id(node) in inner:
            continue
        if isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp)):
            t = _const_text(node)
            if t is None or 'dnf' not in t:
                continue
            key = (node.lineno, t)
            if key not in seen:
                seen.add(key)
                out.append((node.lineno, t))
    return out


_SPLIT = re.compile(r'\s*(?:\|\||&&|;|\||\n)\s*')


def _dnf_argvs(text):
    """Every `dnf ...` command inside one shell string, as an argv list.

    Redirections (`2>&1`, `2>/dev/null`) and a leading `sudo` are shell business, not
    arguments of dnf, so they are dropped, the way the broker shim sees them."""
    argvs = []
    for seg in _SPLIT.split(text):
        seg = seg.strip().lstrip('(').rstrip(')').strip()
        if seg.startswith('sudo '):
            seg = seg[5:]
        if not re.match(r'dnf\s', seg):
            continue
        seg = re.sub(r'\s+\d*>&?\S*', '', seg)       # 2>&1, 2>/dev/null, >/dev/null
        seg = re.sub(r'\s+>\s*\S+', '', seg)
        try:
            argv = shlex.split(seg)
        except ValueError:
            continue
        argvs.append(argv)
    return argvs


def _calls_in_function(name):
    """dnf argvs (with line numbers) found in the string literals inside function `name`."""
    fn = next(n for n in ast.walk(APP_TREE) if isinstance(n, ast.FunctionDef) and n.name == name)
    lo, hi = fn.lineno, fn.end_lineno
    calls = []
    for lineno, text in _string_literals():
        if lo <= lineno <= hi:
            for argv in _dnf_argvs(text):
                calls.append((lineno, argv))
    return calls


def _all_rhel_deploy_functions():
    """Functions that run the TAK Server deploy or upgrade on the RHEL family."""
    names = []
    for n in ast.walk(APP_TREE):
        if not isinstance(n, ast.FunctionDef):
            continue
        body = ast.get_source_segment(APP_SRC, n) or ''
        if 'module disable postgresql' in body or 'dnf repolist' in body:
            names.append(n.name)
    return sorted(set(names))


def _fmt(call):
    lineno, argv = call
    return f'app.py:{lineno}: {" ".join(argv)}'


# --- the proof: the real call strings pass the rulebook ---------------------------------

def test_the_scan_finds_the_deploy_functions():
    """Guard against the scan silently seeing nothing."""
    names = _all_rhel_deploy_functions()
    assert len(names) >= 3, names
    total = sum(len(_calls_in_function(n)) for n in names)
    assert total >= 6, total


def test_every_dnf_call_in_the_takserver_deploy_passes_the_broker_rulebook():
    refused = []
    for name in _all_rhel_deploy_functions():
        for call in _calls_in_function(name):
            lineno, argv = call
            if argv[:3] == ['dnf', 'config-manager', '--add-repo']:
                continue
            try:
                B.check_exec(argv, H)
            except B.Denied as e:
                refused.append(f'{name}: {_fmt(call)}  ->  {e}')
    assert not refused, 'broker refuses these dnf calls:\n' + '\n'.join(refused)


def test_no_dnf_repolist_call_is_left_in_app():
    # string literals only: a comment may name the old call
    left = [f'app.py:{n}' for n, t in _string_literals()
            if re.search(r'dnf\s+(-\S+\s+)*repolist', t)]
    assert not left, left


def test_module_disable_uses_separate_short_options():
    texts = [(n, t) for n, t in _string_literals() if 'module disable' in t]
    assert len(texts) >= 5, texts
    bundled = [f'app.py:{n}' for n, t in texts if re.search(r'dnf\s+-[a-zA-Z]{2,}\s+module\s+disable', t)]
    assert not bundled, bundled
    assert all('dnf -q -y module disable postgresql' in t for _, t in texts)


# --- the broker rulebook itself stays as it was (the fix is not a widening) -------------

@pytest.mark.parametrize('argv', [
    ['dnf', 'repolist', '--all'],
    ['dnf', '-qy', 'module', 'disable', 'postgresql'],
    ['dnf', '--setopt=reposdir=/tmp/x', 'module', 'disable', 'postgresql'],
], ids=lambda a: ' '.join(a))
def test_rulebook_still_refuses_these_shapes(argv):
    with pytest.raises(B.Denied):
        B.check_exec(argv, H)


def test_rulebook_allows_the_replacement_shape():
    B.check_exec(['dnf', '-q', '-y', 'module', 'disable', 'postgresql'], H)
    B.check_exec(['dnf', 'config-manager', '--set-enabled', 'codeready-builder-for-rhel-9-rhui-rpms'], H)
    B.check_exec(['dnf', 'config-manager', '--set-enabled', 'crb'], H)


# --- the CRB repo id comes from the repo files ------------------------------------------

def _crb_helper():
    fn = next((n for n in ast.walk(APP_TREE)
               if isinstance(n, ast.FunctionDef) and n.name == '_find_crb_repo_id'), None)
    assert fn is not None, '_find_crb_repo_id() is missing from app.py'
    ns = {'os': __import__('os'), 're': re, 'glob': __import__('glob')}
    src = ast.get_source_segment(APP_SRC, fn)
    # the module-level regex the helper uses
    for n in APP_TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', '') == '_CRB_REPO_ID_RE' for t in n.targets):
            exec(ast.get_source_segment(APP_SRC, n), ns)
    exec(src, ns)
    return ns['_find_crb_repo_id']


@pytest.mark.parametrize('files,want', [
    ({'rocky.repo': '[baseos]\nname=x\n[crb]\nname=CRB\n[crb-source]\nname=s\n'}, 'crb'),
    ({'redhat-rhui.repo': '[rhui-client-config-server-9]\n'
                           '[codeready-builder-for-rhel-9-rhui-rpms]\nname=CRB\n'
                           '[codeready-builder-for-rhel-9-rhui-source-rpms]\n'
                           '[codeready-builder-for-rhel-9-rhui-debug-rpms]\n'},
     'codeready-builder-for-rhel-9-rhui-rpms'),
    ({'redhat.repo': '[codeready-builder-for-rhel-9-x86_64-source-rpms]\n'
                     '[codeready-builder-for-rhel-9-x86_64-debug-rpms]\n'
                     '[codeready-builder-for-rhel-9-x86_64-rpms]\n'},
     'codeready-builder-for-rhel-9-x86_64-rpms'),
    ({'almalinux-crb.repo': '[crb]\nname=AlmaLinux CRB\n'}, 'crb'),
    ({'rocky.repo': '[baseos]\n[appstream]\n'}, ''),
    ({}, ''),
])
def test_find_crb_repo_id(tmp_path, files, want):
    for name, body in files.items():
        (tmp_path / name).write_text(body)
    assert _crb_helper()(str(tmp_path)) == want
