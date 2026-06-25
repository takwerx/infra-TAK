#!/usr/bin/env python3
"""Convert single-command privileged shell calls whose shell metacharacters live
INSIDE quoted arguments (e.g. `docker exec X sh -c "a || b"`, `docker exec X psql
-c "SELECT …;"`, `docker exec X sed -i "s|a|b|g" f`)  (v10.0.5 non-root P1 pass).

These were false-positive "compound"/"pipe" skips in the other converters because
they string-match `&&`/`|`/`;` before tokenising. Here we shlex.split FIRST: a
shell operator is a STANDALONE token only when UNQUOTED, so an operator inside a
quoted in-container arg never appears standalone. If any standalone operator
token (&&, ||, |, ;, >, >>, <, &) survives, the call is genuinely host-level
compound and is SKIPPED; otherwise it's a single command and we convert it to
`_sudo_wrap([...])`, preserving input=/2>&1.

Const + f-string. shlex.quote unwrapped. DRY-RUN default; --apply gates compile().
"""
import argparse
import ast
import os
import re
import shlex
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, 'app.py')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import takwerx_broker as _B  # noqa: E402


def _broker_denies(argv_src):
    """True if the broker would DENY this argv (so converting it would gap, OR —
    for a coreutil on a takwerx-owned /home path — the original direct call already
    works and must stay unwrapped). Variable args -> neutral token."""
    argv = []
    for a in argv_src:
        try:
            v = ast.literal_eval(a)
            argv.append(v if isinstance(v, str) else 'X')
        except Exception:
            argv.append('PLACEHOLDERTOKEN')
    try:
        _B.check_exec(argv)
        return False
    except _B.Denied:
        return True
SUBPROC_FUNCS = {'run', 'call', 'check_call', 'check_output', 'Popen'}
PRIV_BINS = {'systemctl', 'ufw', 'firewall-cmd', 'dnf', 'apt', 'apt-get', 'yum',
             'docker', 'docker-compose', 'semanage', 'fail2ban-client', 'swapon',
             'swapoff', 'mkswap', 'fallocate', 'install', 'chown', 'chmod', 'tee',
             'cp', 'mv', 'rm', 'mkdir', 'ln', 'touch', 'sysctl', 'restorecon', 'semodule', 'chcon'}
OPERATORS = {'&&', '||', '|', ';', '>', '>>', '<', '&', '2>'}
REDIR_RE = re.compile(r'\s*(?:\d*>&\d+|&?>{1,2}\s*/dev/null|\d*>\s*/dev/null)')
TRAIL_TRUE_RE = re.compile(r'\s*(?:;|\|\|)\s*true\s*$')
SENT = '\x00%d\x00'
SENT_RE = re.compile('\x00(\\d+)\x00')


def line_col_to_off(src, lineno, col):
    cur, i = 1, 0
    for ch in src:
        if cur == lineno:
            return i + col
        if ch == '\n':
            cur += 1
        i += 1
    return None


def node_span(src, node):
    return (line_col_to_off(src, node.lineno, node.col_offset),
            line_col_to_off(src, node.end_lineno, node.end_col_offset))


def kw(node, name):
    for k in node.keywords:
        if k.arg == name:
            return k
    return None


def _unwrap_quote(expr):
    if (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == 'quote' and len(expr.args) == 1
            and isinstance(expr.func.value, ast.Name)
            and expr.func.value.id in ('shlex', 'pipes')):
        return expr.args[0]
    return expr


def build_template(cmd_node, src):
    if isinstance(cmd_node, ast.Constant) and isinstance(cmd_node.value, str):
        return cmd_node.value, []
    if not isinstance(cmd_node, ast.JoinedStr):
        return None, None
    parts, exprs = [], []
    for v in cmd_node.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            parts.append(v.value)
        elif isinstance(v, ast.FormattedValue):
            if v.conversion not in (-1, None) or v.format_spec is not None:
                return None, None
            esrc = ast.get_source_segment(src, _unwrap_quote(v.value))
            if esrc is None:
                return None, None
            parts.append(SENT % len(exprs))
            exprs.append(esrc)
        else:
            return None, None
    return ''.join(parts), exprs


def find_calls(tree):
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
            if shellish and node.args:
                out.append(node)
    return out


def tokens_to_argv(toks, exprs):
    out = []
    for tok in toks:
        m = list(SENT_RE.finditer(tok))
        if not m:
            out.append(repr(tok))
        elif len(m) == 1 and m[0].group(0) == tok:
            out.append(exprs[int(m[0].group(1))])
        else:
            out.append('f' + repr(SENT_RE.sub(lambda x: '{' + exprs[int(x.group(1))] + '}', tok)))
    return out


def plan(node, src):
    tmpl, exprs = build_template(node.args[0], src)
    if tmpl is None:
        return None, 'not literal/f-string'
    merge = bool(re.search(r'\d*>&1', tmpl))
    t = TRAIL_TRUE_RE.sub('', tmpl).strip()
    t = REDIR_RE.sub('', t).strip()
    # Punctuation-aware tokeniser: separates UNQUOTED shell operators into their
    # own tokens even when attached (e.g. `live/;` -> `live/`, `;`), while keeping
    # operators INSIDE quotes within their token (`"SELECT 1;"` -> `SELECT 1;`).
    # This is the discriminator: a standalone operator token = real host-level
    # compound (skip); an operator inside a token = in-container/in-arg (convert).
    try:
        lex = shlex.shlex(t, posix=True, punctuation_chars=';&|<>')
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError as e:
        return None, f'shlex: {e}'
    if not toks:
        return None, 'empty'
    # strip leading VAR=value env-assignments (e.g. DEBIAN_FRONTEND=noninteractive);
    # the broker sets apt's non-interactive env itself.
    while toks and re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', toks[0]):
        toks.pop(0)
    if not toks:
        return None, 'empty after env-strip'
    # standalone operator token => genuine host-level compound => skip
    for tk in toks:
        if tk in OPERATORS or tk in (';', '&', '|', '<', '>', '&&', '||', '>>', '2>'):
            return None, 'host-level operator (compound)'
    if SENT_RE.search(toks[0]):
        return None, 'dynamic head'
    base = os.path.basename(toks[0])
    if base not in PRIV_BINS:
        return None, f'head not privileged: {base}'
    argv = tokens_to_argv(toks, exprs)
    if _broker_denies(argv):
        # Either a real gap, OR a coreutil on a takwerx-owned /home path whose
        # direct call already works — leave it unwrapped either way.
        return None, 'broker DENY (gap, or takwerx-owned path that works direct)'
    return {'argv': argv, 'merge': merge, 'node': node}, ''


def make_edit(p, src):
    node = p['node']
    edits = []
    s, e = node_span(src, node.args[0])
    edits.append((s, e, '_sudo_wrap([' + ', '.join(p['argv']) + '])'))
    sh = kw(node, 'shell')
    if sh is not None:
        ks, ke = node_span(src, sh.value)
        kstart = src.rfind('shell', max(0, ks - 30), ks)
        j = kstart - 1
        while j > 0 and src[j] in ' \t\n':
            j -= 1
        cstart = j if src[j] == ',' else kstart
        edits.append((cstart, ke, ''))
    if p['merge']:
        cap = kw(node, 'capture_output')
        if cap is not None:
            cs, ce = node_span(src, cap.value)
            kstart = src.rfind('capture_output', max(0, cs - 40), cs)
            edits.append((kstart, ce, 'stdout=subprocess.PIPE, stderr=subprocess.STDOUT'))
        elif kw(node, 'stdout') is None and kw(node, 'stderr') is None:
            _, ae = node_span(src, node.args[0])
            edits.append((ae, ae, ', stdout=subprocess.PIPE, stderr=subprocess.STDOUT'))
    return edits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true')
    ap.add_argument('--exclude', default='')
    a = ap.parse_args()
    excl = set(int(x) for x in a.exclude.split(',') if x.strip())
    src = open(APP).read()
    tree = ast.parse(src)
    planned, skipped = [], []
    for node in find_calls(tree):
        if node.lineno in excl:
            continue
        p, info = plan(node, src)
        if p is None:
            skipped.append((node.lineno, info))
            continue
        planned.append(p)
    print(f'PLANNED: {len(planned)}   SKIPPED: {len(skipped)}')
    for p in sorted(planned, key=lambda x: x['node'].lineno):
        print(f"  L{p['node'].lineno}  _sudo_wrap([{', '.join(p['argv'])[:95]}])")
    if a.apply and planned:
        edits = []
        for p in planned:
            edits += make_edit(p, src)
        edits.sort(key=lambda x: x[0], reverse=True)
        new = src
        for s, e, r in edits:
            new = new[:s] + r + new[e:]
        compile(new, APP, 'exec')
        open(APP, 'w').write(new)
        print(f'\nAPPLIED {len(planned)} conversions.')


if __name__ == '__main__':
    main()
