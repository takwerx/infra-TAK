#!/usr/bin/env python3
"""Find RAW / unwrapped privileged calls that bypass the broker and will FAIL
when the console runs as non-root (`takwerx`).  (v10.0.5 non-root migration)

Two classes:
  1. subprocess(...) / os.system(...) whose command is a privileged binary
     (systemctl write-verbs, ufw, firewall-cmd, dnf/apt, docker, semanage,
     install, file-mutating coreutils on privileged paths, ...) and is NOT
     wrapped in `_sudo_wrap(...)`.
  2. open(privileged_path, <write/append>) NOT routed through `_write_priv`.

These are the P1 "wrap pass" — the work between "broker proven" and "console
actually runs non-root." Output is grouped + line-anchored so we can convert in
batches. `os.system` and `shell=True` string commands are flagged as SHELL
(need manual conversion). Variable commands are DYNAMIC (verify at runtime).

Usage: python3 broker/scan_unwrapped_privileged.py [files...]   (default app.py)
"""
import ast
import os
import re
import sys

SUBPROCESS_FUNCS = {'run', 'call', 'check_call', 'check_output', 'Popen'}
# systemctl verbs that REQUIRE root (write/control). Read verbs work fine non-root.
SYSTEMCTL_WRITE = {
    'start', 'stop', 'restart', 'reload', 'try-restart', 'reload-or-restart',
    'enable', 'disable', 'mask', 'unmask', 'daemon-reload', 'set-property',
    'set-environment', 'link', 'edit', 'kill', 'reset-failed', 'isolate', 'revert',
}
# binaries that fail outright as non-root (root, or a group takwerx isn't in)
MUST_WRAP = {
    'ufw', 'firewall-cmd', 'dnf', 'apt', 'apt-get', 'yum', 'docker',
    'docker-compose', 'semanage', 'semodule', 'setsebool', 'restorecon', 'setcap',
    'fail2ban-client', 'swapon', 'swapoff', 'mkswap', 'fallocate', 'useradd',
    'usermod', 'groupadd', 'chpasswd', 'install', 'mount', 'umount', 'sysctl',
    'systemctl-write',  # synthetic, see below
}
COREUTILS = {'tee', 'cp', 'mv', 'rm', 'mkdir', 'rmdir', 'chmod', 'chown',
             'touch', 'ln', 'dd', 'sed'}
PRIV_PREFIXES = ('/etc/', '/opt/', '/usr/', '/var/', '/root/', '/run/',
                 '/swapfile', '/boot/', '/sys/', '/proc/sys/')
WRITE_MODES = {'w', 'a', 'w+', 'r+', 'wb', 'ab', 'wb+', 'x'}
SHELL_PRIV_HINTS = ('systemctl ', 'ufw ', 'firewall-cmd', 'dnf ', 'apt ',
                    'apt-get', 'docker ', 'semanage', 'semodule', 'install -m',
                    'fail2ban-client', 'swapon', 'mkswap', 'chown ', 'chmod ',
                    'tee /etc', 'tee /opt', '> /etc', '>> /etc', '> /opt')


def _is_sudo_wrap(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == '_sudo_wrap')


def _list_strs(node):
    """('binary', [literal-or-None args], has_dynamic) from a list/concat node."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _list_strs(node.left)
    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return None, [], True
    out = []
    for e in node.elts:
        out.append(e.value if isinstance(e, ast.Constant) and isinstance(e.value, str) else None)
    return out[0], out, (None in out)


def _const_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):  # f-string: stitch the literal parts
        return ''.join(v.value for v in node.values
                       if isinstance(v, ast.Constant) and isinstance(v.value, str))
    return None


def _priv_path(p):
    return isinstance(p, str) and p.startswith(PRIV_PREFIXES)


def scan(path):
    tree = ast.parse(open(path).read(), filename=path)
    findings = []   # (line, kind, detail)

    for node in ast.walk(tree):
        # ---- subprocess.* / os.system ----
        cmd_node = None
        shellish = False
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in SUBPROCESS_FUNCS \
               and isinstance(f.value, ast.Name) and f.value.id in ('subprocess', '_sp'):
                cmd_node = node.args[0] if node.args else None
                # shell=True ?
                shellish = any(isinstance(k, ast.keyword) and k.arg == 'shell'
                               and isinstance(k.value, ast.Constant) and k.value.value
                               for k in node.keywords)
            elif isinstance(f, ast.Attribute) and f.attr == 'system' \
                    and isinstance(f.value, ast.Name) and f.value.id == 'os':
                cmd_node = node.args[0] if node.args else None
                shellish = True

        if cmd_node is not None:
            if _is_sudo_wrap(cmd_node):
                continue  # already mediated
            if shellish or isinstance(cmd_node, (ast.Constant, ast.JoinedStr)):
                s = _const_str(cmd_node)
                # READ-ONLY shell commands run fine as the non-root console even
                # though a hint substring matches: `which/command -v` probes, and
                # read verbs of systemctl (show/status/is-*/list-*/cat) + apt/dnf
                # `list`. These are not privileged ops, so don't flag them.
                st = (s or '').strip()
                is_probe = (st.startswith(('which ', 'command -v ', 'command -V '))
                            or re.match(r'^systemctl (show|status|is-active|is-enabled|is-failed|list-units|list-timers|list-unit-files|cat)\b', st)
                            or re.match(r'^(apt|apt-get|dnf|yum) list\b', st))
                if s and not is_probe and any(h in s for h in SHELL_PRIV_HINTS):
                    findings.append((node.lineno, 'SHELL', s.strip().replace('\n', ' ')[:90]))
                continue
            binary, elts, dyn = _list_strs(cmd_node)
            if binary is None:
                continue  # variable/dynamic command head
            base = os.path.basename(binary)
            if base == 'systemctl':
                verb = next((a for a in elts[1:] if a and not a.startswith('-')), None)
                if verb in SYSTEMCTL_WRITE:
                    findings.append((node.lineno, 'WRAP', f'systemctl {verb} ...'))
            elif base in MUST_WRAP:
                findings.append((node.lineno, 'WRAP', f'{base} ' + ' '.join(a or '<v>' for a in elts[1:])[:60]))
            elif base in COREUTILS:
                if any(_priv_path(a) for a in elts[1:]):
                    tgt = next((a for a in elts[1:] if _priv_path(a)), '')
                    findings.append((node.lineno, 'WRAP', f'{base} -> {tgt}'))
            continue

        # ---- open(privileged_path, <write>) not via _write_priv ----
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'open':
            p = _const_str(node.args[0]) if node.args else None
            if not _priv_path(p):
                continue
            mode = 'r'
            if len(node.args) > 1:
                mode = _const_str(node.args[1]) or 'r'
            for k in node.keywords:
                if k.arg == 'mode':
                    mode = _const_str(k.value) or mode
            if mode in WRITE_MODES:
                findings.append((node.lineno, 'OPEN-W', f'{p} ({mode})'))

        # ---- raw os.* / shutil.* mutating a privileged path (bypass the broker) ----
        # These fail EPERM under a non-root console and are NOT subprocess/open, so
        # they were a blind spot until a deploy surfaced them. Route through
        # _makedirs_priv/_chmod_priv or _sudo_wrap(['rm'|'mv'|'cp'|'chown'|...]).
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            modname = node.func.value.id if isinstance(node.func.value, ast.Name) else None
            attr = node.func.attr
            os_mut = {'chmod', 'chown', 'makedirs', 'mkdir', 'remove', 'unlink',
                      'rename', 'replace', 'rmdir', 'symlink', 'link', 'truncate'}
            sh_mut = {'copy', 'copy2', 'copyfile', 'move', 'rmtree', 'chown', 'copytree'}
            fn = None
            if modname == 'os' and attr in os_mut:
                fn = f'os.{attr}'
            elif modname == 'shutil' and attr in sh_mut:
                fn = f'shutil.{attr}'
            if fn and node.args:
                p = _const_str(node.args[0])
                if _priv_path(p):
                    findings.append((node.lineno, 'OS-RAW', f'{fn} -> {p}'))
    return findings


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = argv or [os.path.join(root, 'app.py')]
    allf = []
    for fpath in files:
        if os.path.exists(fpath):
            for ln, kind, detail in scan(fpath):
                allf.append((os.path.basename(fpath), ln, kind, detail))
    from collections import Counter
    by = Counter(k for _, _, k, _ in allf)
    print('=' * 70)
    print('UNWRAPPED PRIVILEGED CALLS (will fail when console runs non-root)')
    print('=' * 70)
    print(f'total: {len(allf)}   by kind: {dict(by)}')
    print('  WRAP   = raw subprocess on a privileged binary -> wrap in _sudo_wrap')
    print('  OPEN-W = raw write open on a privileged path    -> use _write_priv')
    print('  SHELL  = shell=True / os.system privileged string -> manual convert')
    print()
    for kind in ('OPEN-W', 'OS-RAW', 'WRAP', 'SHELL'):
        rows = [r for r in allf if r[2] == kind]
        print(f'--- {kind} ({len(rows)}) ---')
        for fn, ln, _, detail in rows:
            print(f'  {fn}:{ln}  {detail}')
        print()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
