#!/usr/bin/env python3
"""Convert compound shell-string privileged calls (A && B / A || B / A; B) into
`_run_priv_chain([...], mode)`  (v10.0.5 non-root P1 pass, compound variant).

  subprocess.run('systemctl reload caddy 2>&1 || systemctl restart caddy 2>&1',
                 shell=True, capture_output=True, text=True, timeout=90)
    -> _run_priv_chain([['systemctl','reload','caddy'],['systemctl','restart','caddy']],
                       'or', timeout=90)

Handles `subprocess.<fn>` AND aliased `_sp.<fn>` (an alias the unwrapped scanner
misses). Single operator type only (all && => 'and', all || => 'or', all ; =>
'seq'). SKIPS (for hand conversion): mixed operators, `cd ` prefix, `sudo `,
subshell `$()`/backticks, pipes, and any segment whose head is a NON-privileged
binary the broker denies (e.g. `sleep`, `which`) — those must be restructured by
hand (e.g. sleep -> time.sleep).

Const and f-string commands both handled (placeholders -> arg expressions,
shlex.quote unwrapped). Redirection noise + trailing true stripped per segment.
DRY-RUN default; --apply gates on compile().
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


def _broker_denies(argv_lists):
    """True if the broker rulebook would DENY any segment (so converting it would
    create a coverage gap). Variable args are filled with a neutral token."""
    for av in argv_lists:
        argv = []
        for a in av:
            try:
                v = ast.literal_eval(a)
                argv.append(v if isinstance(v, str) else 'X')
            except Exception:
                argv.append('PLACEHOLDERTOKEN')
        try:
            _B.check_exec(argv)
        except _B.Denied:
            return True
    return False
SUBPROC_FUNCS = {'run', 'call', 'check_call', 'check_output', 'Popen'}
PRIV_BINS = {'systemctl', 'ufw', 'firewall-cmd', 'dnf', 'apt', 'apt-get', 'yum',
             'docker', 'docker-compose', 'semanage', 'fail2ban-client', 'swapon',
             'swapoff', 'mkswap', 'fallocate', 'install', 'chown', 'chmod', 'tee',
             'cp', 'mv', 'rm', 'mkdir', 'ln', 'touch', 'sysctl', 'restorecon',
             'journalctl', 'loginctl', 'semodule', 'chcon'}
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


def plan(node, src):
    tmpl, exprs = build_template(node.args[0], src)
    if tmpl is None:
        return None, 'not a literal/f-string'
    t = TRAIL_TRUE_RE.sub('', tmpl).strip()
    # which operator? require a single type
    has_and = '&&' in t
    has_or = '||' in t
    if has_and and has_or:
        return None, 'mixed && and ||'
    if has_and:
        mode, segs = 'and', t.split('&&')
    elif has_or:
        mode, segs = 'or', t.split('||')
    elif ';' in t:
        mode, segs = 'seq', t.split(';')
    else:
        return None, 'not compound'
    # A leading `cd DIR` segment -> extract it as cwd= and chain the rest.
    cwd_src = None
    seg0 = REDIR_RE.sub('', segs[0]).strip()
    if seg0.startswith('cd '):
        cdtgt = seg0[3:].strip()
        mall = list(SENT_RE.finditer(cdtgt))
        if len(mall) == 1 and mall[0].group(0) == cdtgt:
            cwd_src = exprs[int(mall[0].group(1))]
        elif not mall and cdtgt.startswith('~'):
            cwd_src = f'os.path.expanduser({cdtgt!r})'
        elif not mall and cdtgt.startswith('/'):
            cwd_src = repr(cdtgt)
        else:
            return None, f'unhandled cd target: {cdtgt!r}'
        segs = segs[1:]
        if not segs:
            return None, 'cd with no command'
    argv_lists = []
    for seg in segs:
        seg = REDIR_RE.sub('', seg).strip()
        if not seg:
            return None, 'empty segment'
        if seg.startswith('cd ') or '$(' in seg or '`' in seg or '(' in seg.split()[0]:
            return None, 'cd/subshell segment'
        if re.search(r'(?<!\|)\|(?!\|)', seg):
            return None, 'pipe in segment'
        try:
            toks = shlex.split(seg)
        except ValueError as e:
            return None, f'shlex: {e}'
        while toks and (toks[0] == 'sudo' or re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', toks[0])):
            toks.pop(0)   # strip leading sudo + VAR=value (broker runs as root,
                          # and sets apt env itself)
        if not toks or SENT_RE.search(toks[0]):
            return None, 'dynamic/empty head'
        base = os.path.basename(toks[0])
        if base not in PRIV_BINS:
            return None, f'non-privileged segment head: {base}'
        argv_lists.append(tokens_to_argv(toks, exprs))
    if _broker_denies(argv_lists):
        return None, 'broker would DENY a segment (gap) — needs rulebook/hand fix'
    return {'mode': mode, 'argv_lists': argv_lists, 'node': node, 'cwd_src': cwd_src}, ''


def make_edit(p, src):
    node = p['node']
    s, e = node_span(src, node)
    inner = ', '.join('[' + ', '.join(a) + ']' for a in p['argv_lists'])
    extra = ''
    to = kw(node, 'timeout')
    if to is not None:
        extra += ', timeout=' + ast.get_source_segment(src, to.value)
    cw = kw(node, 'cwd')
    if cw is not None:
        extra += ', cwd=' + ast.get_source_segment(src, cw.value)
    elif p.get('cwd_src'):
        extra += ', cwd=' + p['cwd_src']
    repl = f"_run_priv_chain([{inner}], {p['mode']!r}{extra})"
    return (s, e, repl)


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
        inner = ' / '.join(' '.join(a) for a in p['argv_lists'])
        print(f"  L{p['node'].lineno}  [{p['mode']}]  {inner[:90]}")
    if skipped:
        from collections import Counter
        print('\n--- SKIPPED ---')
        for r, n in Counter(i for _, i in skipped).most_common():
            print(f'  {n:3d}  {r}')
    if a.apply and planned:
        edits = [make_edit(p, src) for p in planned]
        edits.sort(key=lambda x: x[0], reverse=True)
        new = src
        for s, e, r in edits:
            new = new[:s] + r + new[e:]
        compile(new, APP, 'exec')
        open(APP, 'w').write(new)
        print(f'\nAPPLIED {len(planned)} conversions.')


if __name__ == '__main__':
    main()
