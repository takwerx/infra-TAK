#!/usr/bin/env python3
"""Wrap raw `subprocess.<fn>([argv])` / `_sp.<fn>([argv])` privileged calls in
`_sudo_wrap(...)`  (v10.0.5 — catches the `_sp` alias the first wrap pass missed).

Finds list/tuple-argv subprocess calls whose head basename is a privileged binary
(systemctl write-verb, MUST_WRAP set, or a coreutil targeting a privileged path)
and whose first arg is NOT already `_sudo_wrap(...)`, and wraps the argv. Byte-
identical as root; broker-mediated non-root. DRY-RUN default; --apply gates on
compile().
"""
import argparse
import ast
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, 'app.py')
SUBPROC_FUNCS = {'run', 'call', 'check_call', 'check_output', 'Popen'}
SYSTEMCTL_WRITE = {'start', 'stop', 'restart', 'reload', 'try-restart',
                   'reload-or-restart', 'enable', 'disable', 'mask', 'unmask',
                   'daemon-reload', 'set-property', 'set-environment', 'link',
                   'edit', 'kill', 'reset-failed', 'isolate', 'revert'}
MUST_WRAP = {'ufw', 'firewall-cmd', 'dnf', 'apt', 'apt-get', 'yum', 'docker',
             'docker-compose', 'semanage', 'semodule', 'setsebool', 'restorecon',
             'setcap', 'fail2ban-client', 'swapon', 'swapoff', 'mkswap',
             'fallocate', 'useradd', 'usermod', 'groupadd', 'chpasswd', 'install',
             'mount', 'umount', 'sysctl'}
COREUTILS = {'tee', 'cp', 'mv', 'rm', 'mkdir', 'rmdir', 'chmod', 'chown',
             'touch', 'ln', 'dd', 'sed'}
PRIV_PREFIXES = ('/etc/', '/opt/', '/usr/', '/var/', '/root/', '/run/',
                 '/swapfile', '/boot/', '/sys/', '/proc/sys/')


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


def _list_head_and_args(node):
    """(head_basename or None, [literal-or-None args])."""
    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return None, []
    vals = [e.value if isinstance(e, ast.Constant) and isinstance(e.value, str) else None
            for e in node.elts]
    return (os.path.basename(vals[0]) if vals[0] else None), vals


def needs_wrap(node):
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if not (isinstance(f, ast.Attribute) and f.attr in SUBPROC_FUNCS
            and isinstance(f.value, ast.Name) and f.value.id in ('subprocess', '_sp')):
        return False
    if not node.args:
        return False
    arg = node.args[0]
    # already wrapped?
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id == '_sudo_wrap':
        return False
    base, vals = _list_head_and_args(arg)
    if base is None:
        return False
    if base == 'systemctl':
        verb = next((a for a in vals[1:] if a and not a.startswith('-')), None)
        return verb in SYSTEMCTL_WRITE
    if base in MUST_WRAP:
        return True
    if base in COREUTILS:
        return any(isinstance(a, str) and a.startswith(PRIV_PREFIXES) for a in vals[1:])
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true')
    a = ap.parse_args()
    src = open(APP).read()
    tree = ast.parse(src)
    edits = []
    for node in ast.walk(tree):
        if needs_wrap(node):
            arg = node.args[0]
            s, e = node_span(src, arg)
            edits.append((s, e, node.lineno, src[s:e]))
    print(f'WRAP sites: {len(edits)}')
    for s, e, ln, txt in sorted(edits, key=lambda x: x[2]):
        print(f'  L{ln}  {txt[:80]}')
    if a.apply and edits:
        for s, e, ln, txt in sorted(edits, key=lambda x: x[0], reverse=True):
            src = src[:s] + f'_sudo_wrap({txt})' + src[e:]
        compile(src, APP, 'exec')
        open(APP, 'w').write(src)
        print(f'\nAPPLIED {len(edits)} wraps.')


if __name__ == '__main__':
    main()
