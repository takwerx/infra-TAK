#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Is the ETL catalog bundled in infra-TAK behind the signed live one? (ops #977)

A box uses modules/etlrunner/catalog.json when it cannot fetch the live catalog from
takwerx/infratak-etl-catalog. If the bundled copy falls behind, those boxes build old ETL
versions. Before infra-TAK PR 576 it sat 20 hours behind.

This tool fetches the live catalog.json and catalog.json.sig (both at one commit, the way the
console does), checks the signature with modules/etlrunner/catalog_signing.pub, and compares
serials. It runs weekly from .github/workflows/etl-catalog-freshness.yml. It is not a PR check:
the live catalog moves on its own and would turn every open PR red.

    python3 tools/etl_catalog_freshness.py

Exit codes: 0 bundled is current (or ahead), 1 bundled is behind, 2 the live signature does not
verify (never trust that catalog), 3 the live catalog could not be fetched or read.

The fix for exit 1 is the last step of every signed-catalog PR: copy catalog.json from
takwerx/infratak-etl-catalog main into modules/etlrunner/catalog.json, byte for byte.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUNDLED = os.path.join(ROOT, 'modules', 'etlrunner', 'catalog.json')
PUBKEY = os.path.join(ROOT, 'modules', 'etlrunner', 'catalog_signing.pub')
REPO = 'takwerx/infratak-etl-catalog'
BRANCH = 'main'
SHA_RE = re.compile(r'^[0-9a-f]{40}$')

OK, BEHIND, BAD_SIG, NO_FETCH = 0, 1, 2, 3


def _load_etlrunner():
    """modules/etlrunner by path: its parse, serial and signature checks are the ones the
    console uses, so this tool can never accept something the console would refuse."""
    spec = importlib.util.spec_from_file_location(
        'etlrunner_for_freshness', os.path.join(ROOT, 'modules', 'etlrunner', '__init__.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def judge(etl, live_raw, live_sig, bundled_raw, pubkey_path=PUBKEY):
    """(exit_code, message). Signature first: an unsigned live catalog says nothing about
    freshness."""
    try:
        live = etl.parse_catalog(live_raw)
    except ValueError as e:
        return NO_FETCH, f'live catalog is not readable: {e}'
    if not etl.verify_signature(live_raw, live_sig, pubkey_path):
        return BAD_SIG, ('live catalog.json does not match catalog.json.sig for the key in '
                         'modules/etlrunner/catalog_signing.pub. Do not copy it. Tell the catalog owner.')
    try:
        bundled = etl.parse_catalog(bundled_raw)
    except ValueError as e:
        return NO_FETCH, f'bundled catalog is not readable: {e}'
    ls, bs = etl.catalog_serial(live), etl.catalog_serial(bundled)
    if ls > bs:
        return BEHIND, (f'bundled ETL catalog is behind: bundled serial {bs}, live serial {ls}. '
                        f'Copy catalog.json from {REPO} {BRANCH} into modules/etlrunner/catalog.json '
                        f'and open a PR to dev.')
    if ls < bs:
        return OK, f'bundled serial {bs} is ahead of live serial {ls} (a catalog PR is waiting to publish). OK.'
    return OK, f'bundled catalog is current: serial {bs}.'


def _get(url, limit, timeout=20, tries=3):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'infra-tak-catalog-freshness'})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read(limit + 1)
            if len(data) > limit:
                raise ValueError('response is too large')
            return data
        except Exception as e:  # network blips are common on shared runners: retry
            last = e
            if i < tries - 1:
                time.sleep(3 * (i + 1))
    raise RuntimeError(f'could not fetch {url}: {last}')


def _live_commit():
    """The catalog branch's commit, so both files come from one commit."""
    ref = f'refs/heads/{BRANCH}'
    try:
        r = subprocess.run(['git', 'ls-remote', f'https://github.com/{REPO}.git', ref],
                           capture_output=True, text=True, timeout=30,
                           env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'})
        sha = r.stdout.split('\t', 1)[0].strip() if r.returncode == 0 else ''
        if SHA_RE.match(sha):
            return sha
    except (OSError, subprocess.SubprocessError):
        pass
    meta = json.loads(_get(f'https://api.github.com/repos/{REPO}/commits/{BRANCH}', 512 * 1024))
    sha = str(meta.get('sha') or '') if isinstance(meta, dict) else ''
    if not SHA_RE.match(sha):
        raise RuntimeError('GitHub returned no commit for the catalog')
    return sha


def main(argv=None):
    etl = _load_etlrunner()
    try:
        sha = _live_commit()
        base = f'https://raw.githubusercontent.com/{REPO}/{sha}/catalog.json'
        live_raw = _get(base, etl.CATALOG_MAX_BYTES)
        live_sig = _get(base + '.sig', 4096)
    except Exception as e:
        code, msg, sha = NO_FETCH, str(e), ''
    else:
        with open(BUNDLED, 'rb') as f:
            bundled_raw = f.read()
        code, msg = judge(etl, live_raw, live_sig, bundled_raw, PUBKEY)
    line = f'{msg}' + (f' (live commit {sha[:12]})' if sha else '')
    print(line)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as f:
            f.write(('### ETL catalog freshness: ' + ('OK' if code == OK else 'FAILED') + '\n\n' + line + '\n'))
    return code


if __name__ == '__main__':
    sys.exit(main())
