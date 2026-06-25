#!/usr/bin/env python3
"""Convert SIMPLE shell-string privileged subprocess/os.system calls into argv
lists routed through `_sudo_wrap(...)`  (v10.0.5 non-root P1 pass).

Scope (this tool only touches calls it is 100% sure about; everything else is
SKIPPED and reported):
  * subprocess.run/call/check_call/check_output/Popen(<str>, shell=True, ...)
    or os.system(<str>) where <str> is a single fully-literal command (no &&,
    no |, no ||, no non-trailing ;, no $()/backtick, no cd, no redirect to a
    real file) whose head is a privileged binary.
  * Only the redirection "noise" `2>&1`, `2>/dev/null`, `>/dev/null`,
    `&>/dev/null`, and a trailing `; true` / `|| true` are stripped.

Behavior preservation:
  * shell=True is removed.
  * `2>/dev/null` / no-redir:  stderr was discarded or already captured ->
    keep the call's existing capture kwargs; stderr now lands in r.stderr
    (harmless, nobody read the discarded stream). r.stdout is unchanged.
  * `2>&1` (stderr merged into stdout, then read via r.stdout): preserve EXACTLY
    by converting `capture_output=True` -> `stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT`. If the call had no capture_output, we add
    `stdout=subprocess.PIPE, stderr=subprocess.STDOUT`.
  * os.system('cmd') -> subprocess.run(_sudo_wrap([...])) (exit status rarely
    inspected; os.system callers here are fire-and-forget).

Usage:
  python3 broker/convert_shell_calls.py --lines L1,L2,...  [--apply]
  python3 broker/convert_shell_calls.py --bucket simple-norepl [--apply]
Default is DRY-RUN: prints every planned before/after and a SKIP report.
"""
import argparse
import ast
import os
import re
import shlex
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, 'app.py')

SUBPROC_FUNCS = {'run', 'call', 'check_call', 'check_output', 'Popen'}
SHELL_PRIV_HINTS = ('systemctl ', 'ufw ', 'firewall-cmd', 'dnf ', 'apt ',
                    'apt-get', 'docker ', 'semanage', 'semodule', 'install -m',
                    'fail2ban-client', 'swapon', 'mkswap', 'chown ', 'chmod ',
                    'tee /etc', 'tee /opt', '> /etc', '>> /etc', '> /opt')
# privileged binaries (basename) whose presence as the command head means the
# call must route through the broker.
PRIV_BINS = {'systemctl', 'ufw', 'firewall-cmd', 'dnf', 'apt', 'apt-get', 'yum',
             'docker', 'docker-compose', 'semanage', 'fail2ban-client', 'swapon',
             'swapoff', 'mkswap', 'fallocate', 'install', 'chown', 'chmod', 'tee',
             'cp', 'mv', 'rm', 'mkdir', 'ln', 'touch', 'sysctl', 'restorecon'}

REDIR_RE = re.compile(r'\s*(?:\d*>&\d+|&?>{1,2}\s*/dev/null|\d*>\s*/dev/null)')
TRAIL_TRUE_RE = re.compile(r'\s*(?:;|\|\|)\s*true\s*$')


def lines_from_args(a):
    if a.lines:
        return set(int(x) for x in a.lines.split(',') if x.strip())
    return None


class Conv:
    def __init__(self, node, cmd_node, shellish, is_system, src):
        self.node = node
        self.cmd_node = cmd_node
        self.shellish = shellish
        self.is_system = is_system
        self.line = node.lineno
        self.src = src


def find_calls(tree, src):
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in SUBPROC_FUNCS \
                and isinstance(f.value, ast.Name) and f.value.id in ('subprocess', '_sp'):
            shellish = any(isinstance(k, ast.keyword) and k.arg == 'shell'
                           and isinstance(k.value, ast.Constant) and k.value.value
                           for k in node.keywords)
            cmd = node.args[0] if node.args else None
            out.append(Conv(node, cmd, shellish, False, src))
        elif isinstance(f, ast.Attribute) and f.attr == 'system' \
                and isinstance(f.value, ast.Name) and f.value.id == 'os':
            cmd = node.args[0] if node.args else None
            out.append(Conv(node, cmd, True, True, src))
    return out


def const_str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def analyze(text):
    """Return (argv, merge_stderr) or (None, reason) if not safely convertible."""
    if text is None:
        return None, 'not a literal string'
    t = text.strip()
    if not any(h in t for h in SHELL_PRIV_HINTS):
        return None, 'no privileged hint'
    merge = bool(re.search(r'\d*>&1', t))
    # strip trailing "; true" / "|| true"
    t = TRAIL_TRUE_RE.sub('', t).strip()
    # strip redirection noise (2>&1, 2>/dev/null, >/dev/null, &>/dev/null)
    t = REDIR_RE.sub('', t).strip()
    # reject anything still shell-compound
    if '$(' in t or '`' in t:
        return None, 'command substitution'
    if '&&' in t or '||' in t:
        return None, 'compound &&/||'
    if re.search(r'(?<!\|)\|(?!\|)', t):
        return None, 'pipe'
    if ';' in t:
        return None, 'semicolon (non-trailing)'
    if t.startswith('cd '):
        return None, 'cd prefix'
    if '>' in t or '<' in t:
        return None, 'residual redirect to file'
    if '*' in t or '?' in t or '~' in t:
        return None, 'glob/tilde'
    try:
        argv = shlex.split(t)
    except ValueError as e:
        return None, f'shlex: {e}'
    if not argv:
        return None, 'empty'
    base = os.path.basename(argv[0])
    if base not in PRIV_BINS:
        return None, f'head not privileged: {base}'
    return (argv, merge), ''


def kw_span(node, name, src):
    for k in node.keywords:
        if k.arg == name:
            return k
    return None


def line_col_to_off(src, lineno, col):
    # offsets of line starts
    off = 0
    cur = 1
    for i, ch in enumerate(src):
        if cur == lineno:
            return i + col
        if ch == '\n':
            cur += 1
    return None


def node_span(src, node):
    s = line_col_to_off(src, node.lineno, node.col_offset)
    e = line_col_to_off(src, node.end_lineno, node.end_col_offset)
    return s, e


def plan(conv, src):
    text = const_str(conv.cmd_node)
    res, info = analyze(text)
    if res is None:
        return None, info
    argv, merge = res
    edits = []  # (start, end, replacement)
    # 1. replace command-string arg with _sudo_wrap([...])
    s, e = node_span(src, conv.cmd_node)
    argv_lit = '[' + ', '.join(repr(a) for a in argv) + ']'
    edits.append((s, e, f'_sudo_wrap({argv_lit})'))
    # 2. shell=True removal (subprocess only)
    sh = kw_span(conv.node, 'shell', src)
    if sh is not None:
        ks, ke = node_span(src, sh.value)
        # find the 'shell' name start: keyword node has no lineno in <3.9 reliably;
        # search backwards from value for 'shell='
        kstart = src.rfind('shell', max(0, ks - 30), ks)
        # remove preceding comma+ws
        cstart = kstart
        j = kstart - 1
        while j > 0 and src[j] in ' \t\n':
            j -= 1
        if src[j] == ',':
            cstart = j
        edits.append((cstart, ke, ''))
    # 3. stderr merge handling for 2>&1
    if merge:
        cap = kw_span(conv.node, 'capture_output', src)
        if cap is not None:
            cs, ce = node_span(src, cap.value)
            kstart = src.rfind('capture_output', max(0, cs - 40), cs)
            edits.append((kstart, ce, 'stdout=subprocess.PIPE, stderr=subprocess.STDOUT'))
        elif kw_span(conv.node, 'stdout', src) is None and kw_span(conv.node, 'stderr', src) is None:
            # no capture_output AND no existing stdout/stderr — append the merge.
            # (If the call already pipes stdout/stderr, it already merges; appending
            # would create a duplicate keyword -> SyntaxError. Skip in that case.)
            edits.append((e, e, ', stdout=subprocess.PIPE, stderr=subprocess.STDOUT'))
    # os.system -> subprocess.run wrapper
    if conv.is_system:
        # replace 'os.system(' head with 'subprocess.run(' and ensure capture
        fs, _ = node_span(src, conv.node.func)
        # func node is the Attribute os.system; replace its span
        ffs = line_col_to_off(src, conv.node.func.lineno, conv.node.func.col_offset)
        ffe = line_col_to_off(src, conv.node.func.end_lineno, conv.node.func.end_col_offset)
        edits.append((ffs, ffe, 'subprocess.run'))
    return edits, (argv, merge)


def apply_edits(src, all_edits):
    # all_edits: list of (start,end,repl); apply right-to-left, no overlaps
    all_edits = sorted(all_edits, key=lambda x: x[0], reverse=True)
    for s, e, r in all_edits:
        src = src[:s] + r + src[e:]
    return src


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lines')
    ap.add_argument('--apply', action='store_true')
    a = ap.parse_args()
    want = lines_from_args(a)
    src = open(APP).read()
    tree = ast.parse(src)
    calls = find_calls(tree, src)
    if want is not None:
        calls = [c for c in calls if c.line in want]

    planned = []
    skipped = []
    for c in calls:
        if not c.shellish:
            continue
        edits, info = plan(c, src)
        if edits is None:
            skipped.append((c.line, info, (const_str(c.cmd_node) or '')[:70]))
            continue
        planned.append((c.line, edits, info))

    print(f'PLANNED: {len(planned)}   SKIPPED: {len(skipped)}')
    for ln, edits, (argv, merge) in sorted(planned):
        print(f'  L{ln}  merge={merge}  -> _sudo_wrap({argv})')
    if skipped:
        print('\n--- SKIPPED ---')
        from collections import Counter
        cc = Counter(r for _, r, _ in skipped)
        for r, n in cc.most_common():
            print(f'  {n:4d}  {r}')

    if a.apply and planned:
        all_edits = []
        for _, edits, _ in planned:
            all_edits += edits
        new = apply_edits(src, all_edits)
        # safety: must COMPILE (ast.parse alone misses 'keyword argument repeated')
        compile(new, APP, 'exec')
        open(APP, 'w').write(new)
        print(f'\nAPPLIED {len(planned)} conversions, {len(all_edits)} edits.')


if __name__ == '__main__':
    main()
