#!/usr/bin/env python3
"""Convert single-pipe privileged shell calls `PRIV_CMD | FILTER` into
`_priv_pipe([priv argv], [filter argv])`  (v10.0.5 non-root P1 pass).

The privileged head runs via the broker; the filter (grep/tail/wc/head/sed/awk —
NOT privileged) runs as the console user on the broker'd output. _priv_pipe returns
the FILTER's CompletedProcess, so `grep -q`/returncode/stdout callers are unchanged.

Uses the punctuation-aware tokeniser to find the STANDALONE `|` (a `|` inside a
quoted arg, or `||`, is not a split point). Single pipe only; multi-pipe / pipe-
with-host-compound is skipped. Strips leading sudo/env on the head, trailing
redirect/true noise on the filter. Broker-gap self-skip. DRY-RUN; --apply gates compile.
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

SUBPROC_FUNCS = {'run', 'call', 'check_call', 'check_output', 'Popen'}
PRIV_BINS = {'systemctl', 'ufw', 'firewall-cmd', 'dnf', 'apt', 'apt-get', 'yum',
             'docker', 'docker-compose', 'semanage', 'fail2ban-client', 'swapon',
             'swapoff', 'mkswap', 'fallocate', 'install', 'chown', 'chmod', 'tee',
             'cp', 'mv', 'rm', 'mkdir', 'ln', 'touch', 'sysctl', 'restorecon',
             'journalctl', 'loginctl', 'semodule'}
REDIR_RE = re.compile(r'\s*(?:\d*>&\d+|&?>{1,2}\s*/dev/null|\d*>\s*/dev/null)')
TRAIL_TRUE_RE = re.compile(r'\s*(?:;|\|\|)\s*true\s*$')
SENT = '\x00%d\x00'
SENT_RE = re.compile('\x00(\\d+)\x00')
OPS = {';', '&', '<', '>', '&&', '||', '>>', '2>', '(', ')'}


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


def tok_argv(toks, exprs):
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


def _broker_denies(argv_src):
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


def find_calls(tree):
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in SUBPROC_FUNCS \
                and isinstance(f.value, ast.Name) and f.value.id in ('subprocess', '_sp'):
            if any(isinstance(k, ast.keyword) and k.arg == 'shell'
                   and isinstance(k.value, ast.Constant) and k.value.value
                   for k in node.keywords) and node.args:
                out.append(node)
    return out


def plan(node, src):
    tmpl, exprs = build_template(node.args[0], src)
    if tmpl is None:
        return None, 'not literal/f-string'
    t = TRAIL_TRUE_RE.sub('', tmpl).strip()
    t = REDIR_RE.sub('', t).strip()
    if t.startswith('('):
        return None, 'subshell'
    try:
        lex = shlex.shlex(t, posix=True, punctuation_chars=';&|<>')
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError as e:
        return None, f'shlex: {e}'
    # locate standalone '|' tokens
    pipe_idx = [i for i, tk in enumerate(toks) if tk == '|']
    if len(pipe_idx) != 1:
        return None, f'{len(pipe_idx)} pipes (need exactly 1)'
    i = pipe_idx[0]
    left, right = toks[:i], toks[i + 1:]
    # any other host operator => skip
    for tk in left + right:
        if tk in OPS or tk in ('&&', '||', ';'):
            return None, 'extra host operator'
    # strip leading sudo / env on the privileged head
    while left and (left[0] == 'sudo' or re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', left[0])):
        left.pop(0)
    if not left or not right:
        return None, 'empty side'
    if SENT_RE.search(left[0]):
        return None, 'dynamic head'
    base = os.path.basename(left[0])
    if base not in PRIV_BINS:
        return None, f'head not privileged: {base}'
    left_argv = tok_argv(left, exprs)
    if _broker_denies(left_argv):
        return None, 'broker DENY head'
    right_argv = tok_argv(right, exprs)
    return {'left': left_argv, 'right': right_argv, 'node': node}, ''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true')
    a = ap.parse_args()
    src = open(APP).read()
    tree = ast.parse(src)
    planned, skipped = [], []
    for node in find_calls(tree):
        p, info = plan(node, src)
        if p is None:
            skipped.append((node.lineno, info))
        else:
            planned.append(p)
    print(f'PLANNED: {len(planned)}   SKIPPED: {len(skipped)}')
    for p in sorted(planned, key=lambda x: x['node'].lineno):
        print(f"  L{p['node'].lineno}  _priv_pipe([{', '.join(p['left'])}], [{', '.join(p['right'])}])")
    if a.apply and planned:
        edits = []
        for p in planned:
            node = p['node']
            extra = ''
            to = kw(node, 'timeout')
            if to is not None:
                extra = ', timeout=' + ast.get_source_segment(src, to.value)
            repl = f"_priv_pipe([{', '.join(p['left'])}], [{', '.join(p['right'])}]{extra})"
            ws, we = node_span(src, node)
            edits.append((ws, we, repl))
        edits.sort(key=lambda x: x[0], reverse=True)
        new = src
        for s, e, r in edits:
            new = new[:s] + r + new[e:]
        compile(new, APP, 'exec')
        open(APP, 'w').write(new)
        print(f'\nAPPLIED {len(planned)} conversions.')


if __name__ == '__main__':
    main()
