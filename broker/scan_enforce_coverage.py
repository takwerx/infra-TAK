#!/usr/bin/env python3
"""Static enforce-list coverage scanner  (v10.0.5)

Reads the console source, extracts EVERY privileged operation the code routes
through the broker — `_sudo_wrap([...])` commands and `_write_priv`/`_read_priv`
file paths — and runs each through the broker's REAL rulebook (check_exec /
_path_allowed). Anything the rulebook would DENY is a GAP that would break strict
(ENFORCE) mode. Covers all code paths at once — single-box, two-server/split,
Federation Hub, remote modules — so we don't have to deploy every topology live
to find holes.

Usage:  python3 broker/scan_enforce_coverage.py [file1.py file2.py ...]
        (defaults to app.py + selfheal_ip.py next to the repo root)

Output: GAPS (fully-literal commands/paths the rulebook denies — must fix before
strict), DYNAMIC (commands/paths with a variable arg we can't resolve statically
— spot-check live), and a coverage summary. Exit code 1 if any GAPS.
"""

import ast
import os
import sys

# import the broker's real policy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import takwerx_broker as B  # noqa: E402

HELPERS = {'_sudo_wrap', '_write_priv', '_read_priv', '_makedirs_priv', '_chmod_priv', '_run_priv_chain', '_priv_pipe'}
# binaries whose *path operand* is a variable we can't resolve statically; these
# were hand-confirmed to resolve into allowlisted dirs (jail_path -> /etc/fail2ban,
# svc_path -> /etc/systemd/system, etc.). Flagged DYNAMIC, not GAP.
PATHISH = set(B.PATH_CHECKED_BINS) | {'install'}


def _elt_candidates(e):
    """Possible constant string values for one list element: [s] for a string
    constant, [s1, s2] for a two-branch string ternary (`a if x else b`),
    [] for fully dynamic (a variable/expression)."""
    if isinstance(e, ast.Constant) and isinstance(e.value, str):
        return [e.value]
    if isinstance(e, ast.IfExp):
        b, o = _elt_candidates(e.body), _elt_candidates(e.orelse)
        if b and o:
            return b + o
    return []


def _list_slots(node):
    """Return (slots, has_dynamic) where slots[i] is a list of candidate strings
    for element i ([] = dynamic). Handles list concat `[...] + list(pkgs)`."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, _ = _list_slots(node.left)
        if left is not None:
            return left + [[]], True          # literal prefix + dynamic tail
        return None, True
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None, True
    slots, dyn = [], False
    for e in node.elts:
        c = _elt_candidates(e)
        slots.append(c)
        if not c:
            dyn = True
    return slots, dyn


def _const_str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def scan_file(path):
    src = open(path).read()
    tree = ast.parse(src, filename=path)
    cmds, writes = [], []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func.id if isinstance(node.func, ast.Name) else None
        if fn not in HELPERS or not node.args:
            continue
        line = node.lineno
        if fn in ('_sudo_wrap', '_priv_pipe'):
            # _priv_pipe's first arg is the privileged command (the filter is not)
            slots, dyn = _list_slots(node.args[0])
            cmds.append((path, line, slots, dyn))
        elif fn == '_run_priv_chain':
            # first arg is a list of argv-lists — check each inner command
            outer = node.args[0]
            if isinstance(outer, (ast.List, ast.Tuple)):
                for inner in outer.elts:
                    slots, dyn = _list_slots(inner)
                    cmds.append((path, line, slots, dyn))
        else:  # _write_priv / _read_priv / _makedirs_priv / _chmod_priv
            writes.append((path, line, _const_str(node.args[0])))
    return cmds, writes


def evaluate_cmd(slots, dyn):
    """-> ('ALLOW'|'DENY'|'DYNAMIC'|'BYPASS', reason). Evaluates every
    combination of conditional/ternary args; a DENY in ANY real combination is a
    gap. BYPASS = sudo-prefixed (runs directly, never hits the broker)."""
    import itertools
    if not slots or not slots[0]:
        return 'DYNAMIC', 'variable binary'
    base = os.path.basename(slots[0][0])
    if base == 'sudo':
        return 'BYPASS', 'sudo-prefixed: runs directly, not via broker'
    if dyn and base in PATHISH:
        return 'DYNAMIC', 'variable path operand (hand-confirmed allowlisted dirs)'
    # fill dynamic slots with a neutral non-flag token; expand ternary slots
    concrete_slots = [s if s else ['PKGorUNIT'] for s in slots]
    for combo in itertools.product(*concrete_slots[:24]):
        try:
            B.check_exec(list(combo))
        except B.Denied as d:
            return 'DENY', str(d)
    return 'ALLOW', ''


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = argv or [os.path.join(root, 'app.py'), os.path.join(root, 'selfheal_ip.py')]
    files = [f for f in files if os.path.exists(f)]

    all_cmds, all_writes = [], []
    for f in files:
        c, w = scan_file(f)
        all_cmds += c
        all_writes += w

    gaps, dynamic, bypass = [], [], []
    bins = {}
    for path, line, slots, dyn in all_cmds:
        verdict, reason = evaluate_cmd(slots, dyn)
        b = os.path.basename(slots[0][0]) if slots and slots[0] else '<var>'
        bins[b] = bins.get(b, 0) + 1
        shown = ' '.join('|'.join(s) if s else '<var>' for s in (slots or []))
        rec = (os.path.basename(path), line, shown, reason)
        if verdict == 'DENY':
            gaps.append(rec)
        elif verdict == 'DYNAMIC':
            dynamic.append(rec)
        elif verdict == 'BYPASS':
            bypass.append(rec)

    path_gaps, path_dyn = [], []
    for path, line, p in all_writes:
        if p is None:
            path_dyn.append((os.path.basename(path), line))
            continue
        try:
            B._path_allowed(p)
        except B.Denied as d:
            path_gaps.append((os.path.basename(path), line, p, str(d)))

    print('=' * 70)
    print('BROKER ENFORCE-LIST COVERAGE SCAN')
    print('=' * 70)
    print(f'scanned: {", ".join(os.path.basename(f) for f in files)}')
    print(f'_sudo_wrap commands: {len(all_cmds)}   '
          f'_write/_read_priv paths: {len(all_writes)}')
    print(f'distinct binaries: {", ".join(f"{k}({v})" for k, v in sorted(bins.items()))}')
    print()

    if gaps:
        print(f'❌ COMMAND GAPS — strict mode WOULD BLOCK these ({len(gaps)}):')
        for f, ln, cmd, why in gaps:
            print(f'   {f}:{ln}  {cmd}\n        -> {why}')
    else:
        print('✅ COMMAND GAPS: none — every fully-literal command is allowed.')
    print()

    if path_gaps:
        print(f'❌ PATH GAPS — strict mode WOULD BLOCK these writes/reads ({len(path_gaps)}):')
        for f, ln, p, why in path_gaps:
            print(f'   {f}:{ln}  {p}\n        -> {why}')
    else:
        print('✅ PATH GAPS: none — every literal privileged path is allowed.')
    print()

    print(f'ℹ️  DYNAMIC (variable arg — spot-check live, not a known gap): '
          f'{len(dynamic)} cmds, {len(path_dyn)} paths')
    print(f'ℹ️  BYPASS (sudo-prefixed, runs directly — not broker-mediated): '
          f'{len(bypass)}')
    if bypass:
        for f, ln, cmd, _ in bypass:
            print(f'      {f}:{ln}  {cmd}')

    total_gaps = len(gaps) + len(path_gaps)
    print()
    print('=' * 70)
    if total_gaps == 0:
        print('RESULT: ✅ CLEAN — no gaps. Strict mode covers every statically-'
              'resolvable privileged op in the codebase.')
    else:
        print(f'RESULT: ❌ {total_gaps} GAP(S) — fix the rulebook before shipping strict.')
    print('=' * 70)
    return 1 if total_gaps else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
