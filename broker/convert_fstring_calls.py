#!/usr/bin/env python3
"""Convert SINGLE-command f-string privileged shell calls into argv lists routed
through `_sudo_wrap(...)`  (v10.0.5 non-root P1 pass, f-string variant).

Harder than the const path: an f-string `f'docker logs {cid} --tail 200 2>&1'`
becomes `_sudo_wrap(['docker','logs', cid, '--tail','200'])`. We:
  1. Build a template, replacing each {expr} with a NUL-delimited sentinel.
  2. Strip redirection noise + trailing `; true`/`|| true`; reject compound
     (&&, |, ||, non-trailing ;, cd, $()/backtick).
  3. shlex.split the template, then map each token back to argv source:
       * pure literal           -> repr(token)
       * exactly one sentinel   -> the placeholder's source expression
       * mixed literal+sentinel -> a rebuilt f-string  f'lit{expr}lit'
  4. Remove shell=True; preserve 2>&1 via stdout=PIPE/stderr=STDOUT (only if the
     call has neither capture_output nor an existing stdout/stderr).

SAFETY — word-split risk: if a token is a BARE placeholder used where the value
might contain spaces (e.g. `f'systemctl restart {units}'`), shell would split it
into multiple args but argv keeps it as one. We cannot know runtime values, so
every conversion is printed for review and any with a bare-placeholder argv token
is tagged [REVIEW]. Use --exclude to drop risky lines; default DRY-RUN.

Usage:
  python3 broker/convert_fstring_calls.py --lines L1,L2 [--exclude L3,L4] [--apply]
"""
import argparse
import ast
import os
import re
import shlex

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, 'app.py')
SUBPROC_FUNCS = {'run', 'call', 'check_call', 'check_output', 'Popen'}
SHELL_PRIV_HINTS = ('systemctl ', 'ufw ', 'firewall-cmd', 'dnf ', 'apt ',
                    'apt-get', 'docker ', 'semanage', 'fail2ban-client', 'swapon',
                    'mkswap', 'chown ', 'chmod ', 'tee /etc', 'tee /opt')
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


def build_template(joined, src):
    """Return (template_text, [expr_src,...]) for a JoinedStr, or (None, reason)."""
    parts = []
    exprs = []
    for v in joined.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            parts.append(v.value)
        elif isinstance(v, ast.FormattedValue):
            if v.conversion not in (-1, None) or v.format_spec is not None:
                return None, 'f-string conversion/format_spec'
            expr = v.value
            # Unwrap shlex.quote(X) -> X: it shell-escapes a value for a shell
            # command line; in a direct argv (no shell) it would inject literal
            # quote chars into the argument. argv is inherently injection-safe.
            if (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
                    and expr.func.attr == 'quote' and len(expr.args) == 1):
                fv = expr.func.value
                if isinstance(fv, ast.Name) and fv.id in ('shlex', 'pipes'):
                    expr = expr.args[0]
            esrc = ast.get_source_segment(src, expr)
            if esrc is None:
                return None, 'no source segment'
            parts.append(SENT % len(exprs))
            exprs.append(esrc)
        else:
            return None, 'unexpected f-string node'
    return ''.join(parts), exprs


def plan_one(node, cmd_node, is_system, src):
    if not isinstance(cmd_node, ast.JoinedStr):
        return None, 'not f-string'
    tmpl, exprs = build_template(cmd_node, src)
    if tmpl is None:
        return None, exprs
    # privileged hint check on literal skeleton
    if not any(h in tmpl for h in SHELL_PRIV_HINTS):
        return None, 'no privileged hint'
    merge = bool(re.search(r'\d*>&1', tmpl))
    t = TRAIL_TRUE_RE.sub('', tmpl).strip()
    t = REDIR_RE.sub('', t).strip()
    if '$(' in t or '`' in t:
        return None, 'command substitution'
    if '&&' in t or '||' in t or re.search(r'(?<!\|)\|(?!\|)', t):
        return None, 'compound &&/|/||'
    if ';' in t:
        return None, 'semicolon (non-trailing)'
    if t.startswith('cd '):
        return None, 'cd prefix'
    if '>' in t or '<' in t:
        return None, 'residual redirect'
    try:
        toks = shlex.split(t)
    except ValueError as e:
        return None, f'shlex: {e}'
    if not toks:
        return None, 'empty'
    # head must be a privileged binary (head token must be a literal)
    if SENT_RE.search(toks[0]):
        return None, 'dynamic command head'
    base = os.path.basename(toks[0])
    if base not in PRIV_BINS:
        return None, f'head not privileged: {base}'
    # map tokens -> argv element source
    argv_src = []
    review = False
    for tok in toks:
        matches = list(SENT_RE.finditer(tok))
        if not matches:
            argv_src.append(repr(tok))
        elif len(matches) == 1 and matches[0].group(0) == tok:
            argv_src.append(exprs[int(matches[0].group(1))])
            review = True  # bare placeholder: possible word-split at runtime
        else:
            # mixed literal + placeholder(s) -> rebuild as f-string
            fs = SENT_RE.sub(lambda m: '{' + exprs[int(m.group(1))] + '}', tok)
            # escape braces that were literal? unlikely in these commands; flag if any stray { }
            argv_src.append('f' + repr(fs))
    return {
        'merge': merge, 'argv_src': argv_src, 'review': review,
        'node': node, 'cmd_node': cmd_node, 'is_system': is_system,
    }, ''


def make_edits(p, src):
    node, cmd_node = p['node'], p['cmd_node']
    edits = []
    s, e = node_span(src, cmd_node)
    argv_lit = '[' + ', '.join(p['argv_src']) + ']'
    edits.append((s, e, f'_sudo_wrap({argv_lit})'))
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
            edits.append((e, e, ', stdout=subprocess.PIPE, stderr=subprocess.STDOUT'))
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
        if node.lineno in excl:
            continue
        if cmd_node is None:
            continue
        p, info = plan_one(node, cmd_node, is_sys, src)
        if p is None:
            if isinstance(cmd_node, ast.JoinedStr):
                skipped.append((node.lineno, info))
            continue
        planned.append(p)

    print(f'PLANNED: {len(planned)}   SKIPPED(f-str): {len(skipped)}')
    for p in sorted(planned, key=lambda x: x['node'].lineno):
        tag = ' [REVIEW: bare placeholder]' if p['review'] else ''
        print(f"  L{p['node'].lineno}  merge={p['merge']}{tag}")
        print(f"     _sudo_wrap([{', '.join(p['argv_src'])}])")
    if skipped:
        from collections import Counter
        print('\n--- SKIPPED ---')
        for r, n in Counter(i for _, i in skipped).most_common():
            print(f'  {n:4d}  {r}')

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
