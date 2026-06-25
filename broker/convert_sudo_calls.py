#!/usr/bin/env python3
"""Convert `sudo …` shell-string privileged calls to broker-mediated `_sudo_wrap`
(v10.0.5).  The console-as-takwerx has NO sudoers, so `sudo X` fails; the broker
runs X as root instead.

Handles the common idioms:
  f'sudo ufw allow {port}/tcp'                          -> _sudo_wrap(['ufw','allow', f'{port}/tcp'])
  'sudo systemctl restart takserver'                   -> _sudo_wrap(['systemctl','restart','takserver'])
  '(sudo ufw deny 9997/tcp || ufw deny 9997/tcp) >/dev/null 2>&1 || true'
                                                        -> _sudo_wrap(['ufw','deny','9997/tcp'])
  'sudo ufw status verbose 2>/dev/null || ufw … || true'-> _sudo_wrap(['ufw','status','verbose'])

The `(sudo X || X) … || true` fallback idiom means "run X once, ignore errors" —
so we take the LEAD command (up to the first standalone operator), strip the
leading `(` and `sudo`, drop redirect noise, and wrap it. PIPES (`sudo X | grep`)
are SKIPPED — the filter changes the result, needs hand conversion. Self-excludes
broker-denied argv. DRY-RUN default; --apply gates compile().
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
             'cp', 'mv', 'rm', 'mkdir', 'ln', 'touch', 'sysctl', 'restorecon', 'semodule', 'chcon'}
REDIR_RE = re.compile(r'\s*(?:\d*>&\d+|&?>{1,2}\s*/dev/null|\d*>\s*/dev/null)')
SENT = '\x00%d\x00'
SENT_RE = re.compile('\x00(\\d+)\x00')
OPS = {';', '&', '|', '<', '>', '&&', '||', '>>', '2>', '(', ')'}


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
    t = tmpl.strip()
    if t.startswith('('):
        t = t[1:].strip()
    if not t.startswith('sudo '):
        return None, 'not sudo-prefixed'
    t = REDIR_RE.sub('', t).strip()
    try:
        lex = shlex.shlex(t, posix=True, punctuation_chars=';&|<>')
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError as e:
        return None, f'shlex: {e}'
    # take the lead command up to the first standalone operator
    lead, op = [], None
    for tk in toks:
        if tk in OPS:
            op = tk
            break
        lead.append(tk)
    if op == '|':
        return None, 'pipe (filter changes result) — hand convert'
    # strip leading 'sudo' (and a possible 'sudo' again / env assignment)
    while lead and (lead[0] == 'sudo' or '=' in lead[0] and not lead[0].startswith('-')):
        lead.pop(0)
    if not lead or SENT_RE.search(lead[0]):
        return None, 'empty/dynamic head'
    base = os.path.basename(lead[0])
    if base not in PRIV_BINS:
        return None, f'head not privileged: {base}'
    argv = tok_argv(lead, exprs)
    if _broker_denies(argv):
        return None, 'broker DENY'
    return {'argv': argv, 'node': node}, ''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true')
    a = ap.parse_args()
    src = open(APP).read()
    tree = ast.parse(src)
    planned, skipped = [], []
    for node in find_calls(tree):
        p, info = plan(node, src)
        (planned if p else skipped).append((node.lineno, p, info))
    planned = [(ln, p) for ln, p, _ in planned if p]
    print(f'PLANNED: {len(planned)}   SKIPPED: {len(skipped) - len(planned)}')
    for ln, p in sorted(planned):
        print(f"  L{ln}  _sudo_wrap([{', '.join(p['argv'])}])")
    if a.apply and planned:
        edits = []
        for ln, p in planned:
            node = p['node']
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
        edits.sort(key=lambda x: x[0], reverse=True)
        new = src
        for s, e, r in edits:
            new = new[:s] + r + new[e:]
        compile(new, APP, 'exec')
        open(APP, 'w').write(new)
        print(f'\nAPPLIED {len(planned)} conversions.')


if __name__ == '__main__':
    main()
