#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Say which test tiers a change must pass before merge (ops #242).

Plain script, no Claude. Reads the path -> tier map in tools/test-tiers.json, looks at what
a branch changed (git diff, or a saved diff) and prints a short checklist for the PR and the
ops issue. The lead merges only when every listed item is green.

    python3 tools/pick-tests.py                    # origin/dev...HEAD
    python3 tools/pick-tests.py --base origin/dev --head claude/issue-12
    python3 tools/pick-tests.py --diff-file my.diff --format json

app.py is one 75,000-line file, so a path alone says nothing about it: rules also match the
changed lines and the function a hunk sits in (the text after the second @@ in git diff).
"""
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MAP = os.path.join(HERE, 'test-tiers.json')
MAX_EVIDENCE = 2


def glob_to_regex(glob):
    """gitignore-ish glob: ** crosses folders, * does not; a bare name matches at any depth."""
    out = []
    i = 0
    while i < len(glob):
        if glob.startswith('**/', i):
            out.append('(?:.*/)?')
            i += 3
        elif glob.startswith('**', i):
            out.append('.*')
            i += 2
        elif glob[i] == '*':
            out.append('[^/]*')
            i += 1
        elif glob[i] == '?':
            out.append('[^/]')
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    body = ''.join(out)
    if '/' not in glob:
        body = '(?:.*/)?' + body
    return re.compile('^' + body + '$')


def path_matches(path, globs):
    return any(glob_to_regex(g).match(path) for g in globs)


def parse_diff(text):
    """Unified diff (-U0 is enough) -> [{'paths': [...], 'lines': [...], 'contexts': [...]}]."""
    files = []
    cur = None
    for raw in text.splitlines():
        if raw.startswith('diff --git '):
            m = re.match(r'diff --git a/(.*) b/(.*)$', raw)
            paths = [m.group(1)] if m else []
            if m and m.group(2) != m.group(1):
                paths.append(m.group(2))
            cur = {'paths': paths, 'lines': [], 'contexts': []}
            files.append(cur)
        elif cur is None:
            continue
        elif raw.startswith('rename from ') or raw.startswith('rename to '):
            p = raw.split(' ', 2)[2]
            if p not in cur['paths']:
                cur['paths'].append(p)
        elif raw.startswith('@@'):
            m = re.match(r'@@ [^@]*@@ ?(.*)$', raw)
            if m and m.group(1):
                cur['contexts'].append(m.group(1))
        elif raw.startswith(('+++', '---')):
            continue
        elif raw.startswith(('+', '-')):
            cur['lines'].append(raw[1:])
    return files


def git_diff(base, head):
    # three-dot: only what the branch added since it left base
    cmd = ['git', 'diff', '-U0', '--no-color', '--find-renames', '--end-of-options',
           '%s...%s' % (base, head), '--']
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        msg = getattr(e, 'stderr', '') or str(e)
        sys.exit('pick-tests: git diff failed: %s' % msg.strip())
    return res.stdout


def compile_all(patterns):
    return [re.compile(p, re.I) for p in patterns]


def pick(changes, tier_map):
    """Return {rule_id: {'rule': rule, 'evidence': [str, ...]}} for every rule that fired."""
    ignore = tier_map.get('ignore_content_paths', [])
    fired = {}
    for rule in tier_map['rules']:
        content = compile_all(rule.get('content', []))
        context = compile_all(rule.get('context', []))
        evidence = []
        for ch in changes:
            main = ch['paths'][-1] if ch['paths'] else '?'
            hit = next((p for p in ch['paths'] if path_matches(p, rule.get('paths', []))), None)
            if hit:
                evidence.append(hit)
                continue
            if all(path_matches(p, ignore) for p in ch['paths']):
                continue
            found = None
            for line in ch['lines']:
                m = next((rx for rx in content if rx.search(line)), None)
                if m:
                    found = '%s: %s' % (main, line.strip()[:45])
                    break
            if not found:
                for ctx in ch['contexts']:
                    if any(rx.search(ctx) for rx in context):
                        found = '%s: in %s' % (main, ctx.strip()[:45])
                        break
            if found:
                evidence.append(found)
        if evidence:
            fired[rule['id']] = {'rule': rule, 'evidence': evidence}
    return fired


def build_result(changes, tier_map):
    fired = pick(changes, tier_map)
    boxes = []
    for hit in fired.values():
        for b in hit['rule'].get('boxes', []):
            if b not in boxes:
                boxes.append(b)
    items = []
    for a in tier_map.get('always', []):
        item = {'id': a['id'], 'label': a['label'], 'why': 'always', 'evidence': []}
        if a['id'] == 'box':
            item['boxes'] = boxes or tier_map.get('default_boxes', [])
        items.append(item)
    for rid, hit in fired.items():
        r = hit['rule']
        items.append({'id': rid, 'label': r['label'], 'why': r.get('why', ''),
                      'evidence': hit['evidence']})
    return {'files_changed': len(changes), 'required': items}


def render_markdown(result):
    lines = ['**Tests required before merge** (picked by `tools/pick-tests.py` from %d changed files)'
             % result['files_changed']]
    for it in result['required']:
        text = '- [ ] %s' % it['label']
        if it.get('boxes'):
            text += ': ' + ', '.join(it['boxes'])
        if it['evidence']:
            shown = it['evidence'][:MAX_EVIDENCE]
            more = len(it['evidence']) - len(shown)
            text += ' — %s (%s%s)' % (it['why'], '; '.join(shown), ', +%d more' % more if more else '')
        lines.append(text)
    lines.append('Lead: do not merge until every box above is green.')
    return '\n'.join(lines)


def load_map(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--base', default='origin/dev', help='branch the PR targets (default origin/dev)')
    ap.add_argument('--head', default='HEAD')
    ap.add_argument('--diff-file', help="read a saved 'git diff -U0' instead of running git ('-' = stdin)")
    ap.add_argument('--map', default=DEFAULT_MAP, help='path -> tier map (default tools/test-tiers.json)')
    ap.add_argument('--format', choices=('md', 'json'), default='md')
    args = ap.parse_args(argv)

    if args.diff_file == '-':
        text = sys.stdin.read()
    elif args.diff_file:
        with open(args.diff_file, encoding='utf-8', errors='replace') as f:
            text = f.read()
    else:
        text = git_diff(args.base, args.head)
    result = build_result(parse_diff(text), load_map(args.map))
    if args.format == 'json':
        print(json.dumps(result, indent=2))
    else:
        print(render_markdown(result))
    return 0


if __name__ == '__main__':
    sys.exit(main())
