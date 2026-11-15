#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Build / refresh the ETL Runner catalog (modules/etlrunner/catalog.json).

Dev-side tool (needs the `gh` CLI, authenticated). It is the "auto-intake" half of W3:
  * every public `dfpc-coe/etl-*` repo (minus the libraries) at its highest semver tag;
  * every community entry in modules/etlrunner/community.json at its pinned ref.

Each entry is pinned to a commit SHA, and its name/description come from the ETL's own
capabilities.json at that SHA — the authors write the "what does it do" text.

It never publishes anything: it rewrites catalog.json and prints what changed (NEW / BUMP /
GONE). A changed entry still goes through /module-scan before the catalog bump lands
(CLAUDE.md: no external repo lands unscanned).

    python3 tools/etl_catalog_sync.py            # rewrite catalog.json, print the diff
    python3 tools/etl_catalog_sync.py --check    # print the diff only, exit 1 if anything changed
"""
import argparse
import base64
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.join(HERE, '..', 'modules', 'etlrunner')
CATALOG = os.path.join(MOD, 'catalog.json')
COMMUNITY = os.path.join(MOD, 'community.json')
COE_ORG = 'dfpc-coe'
NOT_ETLS = {'etl-base', 'etl-template'}          # libraries, not runnable ETLs
HIDDEN = {'etl-drone-tag'}                       # operator 2026-11-08: empty template, posts nothing
SEMVER = re.compile(r'^v?(\d+)\.(\d+)\.(\d+)$')


def gh(path):
    out = subprocess.run(['gh', 'api', '--paginate', path], check=True,
                         capture_output=True, text=True).stdout
    # --paginate concatenates JSON arrays as `][`
    return json.loads(out.replace('][', ','))


def gh_file(owner, repo, path, ref):
    try:
        d = gh(f'repos/{owner}/{repo}/contents/{path}?ref={ref}')
    except subprocess.CalledProcessError:
        return None
    return base64.b64decode(d['content']).decode()


def highest_tag(owner, repo):
    best = None
    for t in gh(f'repos/{owner}/{repo}/tags?per_page=100'):
        m = SEMVER.match(t['name'])
        if m:
            key = tuple(int(x) for x in m.groups())
            if best is None or key > best[0]:
                best = (key, t['name'], t['commit']['sha'])
    return best


def flags(caps):
    inv = caps.get('invocations') or {}
    inc = inv.get('incoming') or {}
    f = {
        'schedule': 'schedule' in inc,
        'webhook': 'webhook' in inc,
        'email': 'email' in inc,
        'outgoing': bool((inv.get('outgoing') or {}).get('types')),
    }
    # what the local runner can host today: scheduled now, webhook with W7, email parked (SES)
    f['installable'] = f['schedule'] or f['webhook']
    return f


def entry(owner, repo, ref, sha, version, prefix, community, author, name_override=None):
    caps_raw = gh_file(owner, repo, 'capabilities.json', sha)
    caps = json.loads(caps_raw) if caps_raw else {}
    names = {x['name'] for x in gh(f'repos/{owner}/{repo}/contents?ref={sha}')}
    logo = next((n for n in ('logo.png', 'logo.svg') if n in names), None)
    raw = f'https://raw.githubusercontent.com/{owner}/{repo}/{sha}'
    return {
        'prefix': prefix,
        'name': name_override or caps.get('name') or repo,
        'description': (caps.get('description') or '').strip(),
        'source': f'{owner}/{repo}',
        'ref': ref,
        'sha': sha,
        'version': version,
        'author': author,
        'community': community,
        'logo': f'{raw}/{logo}' if logo else None,
        'readme': f'{raw}/README.md' if 'README.md' in names else None,
        'repo_url': f'https://github.com/{owner}/{repo}',
        'compute': caps.get('compute') or {},
        'flags': flags(caps),
        'has_capabilities': bool(caps_raw),
    }


def coe_entries():
    repos = [r for r in gh(f'orgs/{COE_ORG}/repos?per_page=100')
             if r['name'].startswith('etl-') and r['name'] not in NOT_ETLS and r['name'] not in HIDDEN
             and not r['archived'] and not r['private']]

    def one(r):
        t = highest_tag(COE_ORG, r['name'])
        if not t:
            return None
        (_, tag, sha) = t
        return entry(COE_ORG, r['name'], tag, sha, tag.lstrip('v'), r['name'], False, 'COE')
    with ThreadPoolExecutor(8) as ex:
        return [e for e in ex.map(one, repos) if e]


def community_entries():
    out = []
    for c in json.load(open(COMMUNITY))['entries']:
        owner, repo = c['source'].split('/')
        sha = c['sha']
        pkg = json.loads(gh_file(owner, repo, 'package.json', sha) or '{}')
        version = c.get('version') or pkg.get('version') or '0.0.0'
        e = entry(owner, repo, c['ref'], sha, version, c['prefix'], True, c['author'],
                  c.get('name'))
        if c.get('note'):
            e['note'] = c['note']
        out.append(e)
    return out


def diff(old, new):
    o = {e['prefix']: e for e in old}
    n = {e['prefix']: e for e in new}
    lines = []
    for p in sorted(n.keys() - o.keys()):
        lines.append(f"NEW   {p} {n[p]['version']}  ({n[p]['name']})")
    for p in sorted(o.keys() - n.keys()):
        lines.append(f"GONE  {p} {o[p]['version']}")
    for p in sorted(n.keys() & o.keys()):
        if n[p]['sha'] != o[p]['sha']:
            lines.append(f"BUMP  {p} {o[p]['version']} -> {n[p]['version']}")
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--check', action='store_true')
    a = ap.parse_args()
    new = sorted(coe_entries() + community_entries(), key=lambda e: (e['community'], e['name'].lower()))
    prefixes = [e['prefix'] for e in new]
    dup = {p for p in prefixes if prefixes.count(p) > 1}
    if dup:
        sys.exit(f'duplicate prefixes (CloudTAK keys integrations by prefix): {sorted(dup)}')
    old = json.load(open(CATALOG))['entries'] if os.path.exists(CATALOG) else []
    # `reviewed` is set by /module-scan, never by this tool: it survives only while the pinned
    # SHA is unchanged, so every NEW or BUMP entry comes in unreviewed and the box won't install it.
    prev = {e['prefix']: e for e in old}
    for e in new:
        p = prev.get(e['prefix'])
        e['reviewed'] = p.get('reviewed') if p and p.get('sha') == e['sha'] else None
    changes = diff(old, new)
    print('\n'.join(changes) if changes else 'catalog unchanged')
    if a.check:
        sys.exit(1 if changes else 0)
    # `serial` is stamped by tools/etl_catalog_publish.py when the catalog is signed; keep it, so
    # the bundled file stays byte-identical to the published one until the next publish.
    serial = json.load(open(CATALOG)).get('serial') if os.path.exists(CATALOG) else None
    doc = {'schema': 1, **({'serial': serial} if serial else {}), 'entries': new}
    with open(CATALOG, 'w') as f:
        json.dump(doc, f, indent=2)
        f.write('\n')
    print(f'{len(new)} entries -> {os.path.relpath(CATALOG)}')


if __name__ == '__main__':
    main()
