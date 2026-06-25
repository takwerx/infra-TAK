#!/usr/bin/env python3
"""Convert `cd DIR && <one privileged command>` shell calls into a single argv
call routed through `_sudo_wrap(...)` with `cwd=DIR`  (v10.0.5 non-root P1 pass).

  f'cd {cloudtak_dir} && docker compose up -d 2>&1'
    -> subprocess.run(_sudo_wrap(['docker','compose','up','-d']),
                      cwd=cloudtak_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, ...)

The broker's exec proxy forwards the caller's cwd to the daemon, so cwd= reaches
the real command. Only the SINGLE-command form is handled here; `cd X && a && b`
(multiple commands) is SKIPPED for hand conversion (it must become >1 statement).

cwd source:
  * `cd {expr} && ...`        -> cwd=<expr>  (shlex.quote unwrapped)
  * `cd ~/authentik && ...`   -> cwd=os.path.expanduser('~/authentik')
  * `cd /abs/path && ...`     -> cwd='/abs/path'

Default DRY-RUN. --apply gates on compile().
"""
import argparse
import ast
import os
import re
import shlex

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, 'app.py')
SUBPROC_FUNCS = {'run', 'call', 'check_call', 'check_output', 'Popen'}
PRIV_BINS = {'systemctl', 'ufw', 'firewall-cmd', 'dnf', 'apt', 'apt-get', 'yum',
             'docker', 'docker-compose', 'semanage', 'fail2ban-client', 'swapon',
             'swapoff', 'mkswap', 'fallocate', 'install', 'chown', 'chmod', 'tee',
             'cp', 'mv', 'rm', 'mkdir', 'ln', 'touch', 'sysctl', 'restorecon'}
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


def find_calls(tree):
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in SUBPROC_FUNCS \
                and isinstance(f.value, ast.Name) and f.value.id in ('subprocess', '_sp'):
            out.append((node, node.args[0] if node.args else None, False))
        elif isinstance(f, ast.Attribute) and f.attr == 'system' \
                and isinstance(f.value, ast.Name) and f.value.id == 'os':
            out.append((node, node.args[0] if node.args else None, True))
    return out


def _unwrap_quote(expr):
    if (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == 'quote' and len(expr.args) == 1
            and isinstance(expr.func.value, ast.Name)
            and expr.func.value.id in ('shlex', 'pipes')):
        return expr.args[0]
    return expr


def build_template(joined, src):
    parts, exprs = [], []
    for v in joined.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            parts.append(v.value)
        elif isinstance(v, ast.FormattedValue):
            if v.conversion not in (-1, None) or v.format_spec is not None:
                return None, 'conversion/format_spec'
            esrc = ast.get_source_segment(src, _unwrap_quote(v.value))
            if esrc is None:
                return None, 'no source segment'
            parts.append(SENT % len(exprs))
            exprs.append(esrc)
        else:
            return None, 'unexpected node'
    return ''.join(parts), exprs


def tokens_to_argv(toks, exprs):
    argv_src = []
    for tok in toks:
        m = list(SENT_RE.finditer(tok))
        if not m:
            argv_src.append(repr(tok))
        elif len(m) == 1 and m[0].group(0) == tok:
            argv_src.append(exprs[int(m[0].group(1))])
        else:
            argv_src.append('f' + repr(SENT_RE.sub(lambda x: '{' + exprs[int(x.group(1))] + '}', tok)))
    return argv_src


def plan_one(node, cmd_node, is_system, src):
    if isinstance(cmd_node, ast.Constant) and isinstance(cmd_node.value, str):
        tmpl, exprs = cmd_node.value, []   # const cd-string (no placeholders)
    elif isinstance(cmd_node, ast.JoinedStr):
        tmpl, exprs = build_template(cmd_node, src)
        if tmpl is None:
            return None, exprs
    else:
        return None, 'not a cd string'
    merge = bool(re.search(r'\d*>&1', tmpl))
    t = TRAIL_TRUE_RE.sub('', tmpl).strip()
    t = REDIR_RE.sub('', t).strip()
    if not t.startswith('cd '):
        return None, 'not cd-prefixed'
    if '$(' in t or '`' in t or '|' in t:
        return None, 'subshell/pipe'
    parts = t.split(' && ')
    if len(parts) != 2:
        return None, f'{len(parts)-1} commands after cd (need exactly 1)'
    cdpart, cmdpart = parts[0].strip(), parts[1].strip()
    if ';' in cmdpart:
        return None, 'semicolon in command'
    # cwd from cd target
    cdtgt = cdpart[3:].strip()
    mall = list(SENT_RE.finditer(cdtgt))
    if len(mall) == 1 and mall[0].group(0) == cdtgt:
        cwd_src = exprs[int(mall[0].group(1))]
    elif not mall and cdtgt.startswith('~'):
        cwd_src = f'os.path.expanduser({cdtgt!r})'
    elif not mall and cdtgt.startswith('/'):
        cwd_src = repr(cdtgt)
    else:
        return None, f'unhandled cd target: {cdtgt!r}'
    # command argv
    try:
        toks = shlex.split(cmdpart)
    except ValueError as e:
        return None, f'shlex: {e}'
    if not toks or SENT_RE.search(toks[0]):
        return None, 'dynamic/empty command head'
    base = os.path.basename(toks[0])
    if base not in PRIV_BINS:
        return None, f'head not privileged: {base}'
    argv_src = tokens_to_argv(toks, exprs)
    return {'merge': merge, 'argv_src': argv_src, 'cwd_src': cwd_src,
            'node': node, 'cmd_node': cmd_node, 'is_system': is_system}, ''


def make_edits(p, src):
    node, cmd_node = p['node'], p['cmd_node']
    edits = []
    s, e = node_span(src, cmd_node)
    argv_lit = '[' + ', '.join(p['argv_src']) + ']'
    edits.append((s, e, f'_sudo_wrap({argv_lit})'))
    # remove shell=True
    sh = kw(node, 'shell')
    if sh is not None:
        ks, ke = node_span(src, sh.value)
        kstart = src.rfind('shell', max(0, ks - 30), ks)
        j = kstart - 1
        while j > 0 and src[j] in ' \t\n':
            j -= 1
        cstart = j if src[j] == ',' else kstart
        edits.append((cstart, ke, ''))
    # append cwd (+ merge) right after the command arg
    tail = f", cwd={p['cwd_src']}"
    if p['merge'] and kw(node, 'capture_output') is None \
            and kw(node, 'stdout') is None and kw(node, 'stderr') is None:
        tail += ', stdout=subprocess.PIPE, stderr=subprocess.STDOUT'
    elif p['merge']:
        cap = kw(node, 'capture_output')
        if cap is not None:
            cs, ce = node_span(src, cap.value)
            kstart = src.rfind('capture_output', max(0, cs - 40), cs)
            edits.append((kstart, ce, 'stdout=subprocess.PIPE, stderr=subprocess.STDOUT'))
    edits.append((e, e, tail))
    if p['is_system']:
        ffs = line_col_to_off(src, node.func.lineno, node.func.col_offset)
        ffe = line_col_to_off(src, node.func.end_lineno, node.func.end_col_offset)
        edits.append((ffs, ffe, 'subprocess.run'))
    return edits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lines')
    ap.add_argument('--exclude', default='')
    ap.add_argument('--apply', action='store_true')
    a = ap.parse_args()
    want = set(int(x) for x in a.lines.split(',') if x.strip()) if a.lines else None
    excl = set(int(x) for x in a.exclude.split(',') if x.strip())
    src = open(APP).read()
    tree = ast.parse(src)
    planned, skipped = [], []
    for node, cmd_node, is_sys in find_calls(tree):
        if want is not None and node.lineno not in want:
            continue
        if node.lineno in excl or cmd_node is None:
            continue
        p, info = plan_one(node, cmd_node, is_sys, src)
        if p is None:
            if isinstance(cmd_node, ast.JoinedStr):
                seg = (ast.get_source_segment(src, cmd_node) or '')
                if 'cd ' in seg:
                    skipped.append((node.lineno, info))
            continue
        planned.append(p)

    print(f'PLANNED: {len(planned)}   SKIPPED(cd): {len(skipped)}')
    for p in sorted(planned, key=lambda x: x['node'].lineno):
        print(f"  L{p['node'].lineno}  merge={p['merge']}  cwd={p['cwd_src']}")
        print(f"     _sudo_wrap([{', '.join(p['argv_src'])}])")
    if skipped:
        from collections import Counter
        print('\n--- SKIPPED ---')
        for r, n in Counter(i for _, i in skipped).most_common():
            print(f'  {n:4d}  {r}')
        for ln, r in sorted(skipped):
            print(f'    L{ln}: {r}')

    if a.apply and planned:
        all_edits = []
        for p in planned:
            all_edits += make_edits(p, src)
        all_edits.sort(key=lambda x: x[0], reverse=True)
        new = src
        for s, e, r in all_edits:
            new = new[:s] + r + new[e:]
        compile(new, APP, 'exec')
        open(APP, 'w').write(new)
        print(f'\nAPPLIED {len(planned)} conversions, {len(all_edits)} edits.')


if __name__ == '__main__':
    main()
