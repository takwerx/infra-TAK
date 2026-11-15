#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Record /module-scan results in modules/etlrunner/catalog.json.

Reads scan result files ({"results": [{"prefix", "sha", "verdict", "head_verified", ...}]}) and
sets `reviewed` on every catalog entry whose scan PASSED at exactly the catalog's pinned SHA.
A FAIL, a SHA mismatch, or an unverified checkout clears `reviewed` — a box then refuses to
install that ETL. tools/etl_catalog_sync.py keeps `reviewed` only while the SHA is unchanged.

    python3 tools/etl_catalog_review.py --date 2026-11-08 scan/batch-*.json
"""
import argparse
import json
import os
import re
import sys

CATALOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'modules', 'etlrunner', 'catalog.json')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--date', required=True)
    ap.add_argument('results', nargs='+')
    a = ap.parse_args()
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', a.date):
        sys.exit('--date must be YYYY-MM-DD')
    scans = {}
    for path in a.results:
        for r in json.load(open(path)).get('results') or []:
            scans[r.get('prefix')] = r
    cat = json.load(open(CATALOG))
    passed, failed, missing = [], [], []
    for e in cat['entries']:
        r = scans.get(e['prefix'])
        if not r:
            missing.append(e['prefix'])
            continue
        ok = r.get('verdict') == 'PASS' and r.get('sha') == e['sha'] and r.get('head_verified') is True
        e['reviewed'] = f"{a.date} /module-scan" if ok else None
        (passed if ok else failed).append(e['prefix'])
    with open(CATALOG, 'w') as f:
        json.dump(cat, f, indent=2)
        f.write('\n')
    print(f"reviewed: {len(passed)}  not reviewed (FAIL or SHA mismatch): {len(failed)} {failed}")
    if missing:
        print(f"no scan result (left as they were): {missing}")


if __name__ == '__main__':
    main()
