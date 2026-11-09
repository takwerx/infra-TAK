#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Sign the ETL catalog for takwerx/infratak-etl-catalog (W3 phase 2).

Dev-side, operator machine only: the private key never leaves it and never goes to CI.

  1. stamps a new `serial` into modules/etlrunner/catalog.json (the bundled copy),
  2. signs those exact bytes with the offline Ed25519 key,
  3. verifies the signature with the public key that ships in infra-TAK,
  4. writes catalog.json + catalog.json.sig into a checkout of the public repo.

It never commits and never pushes. The bundled and published files are byte-identical, so a box
on this infra-TAK release and a box that fetched the catalog see the same thing.

    python3 tools/etl_catalog_publish.py --out ~/GitHub/infratak-etl-catalog
"""
import argparse
import base64
import datetime
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
from modules import etlrunner as etl  # noqa: E402

DEFAULT_KEY = os.path.expanduser('~/.config/infratak/etl-catalog-ed25519.pem')


def sign(raw, key):
    with tempfile.TemporaryDirectory() as d:
        msg, sig = os.path.join(d, 'msg'), os.path.join(d, 'sig')
        with open(msg, 'wb') as f:
            f.write(raw)
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', key, '-in', msg, '-out', sig],
                       check=True, capture_output=True)
        return base64.b64encode(open(sig, 'rb').read()).decode() + '\n'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True, help='checkout of takwerx/infratak-etl-catalog')
    ap.add_argument('--key', default=DEFAULT_KEY)
    a = ap.parse_args()
    if not os.path.isfile(a.key) or os.stat(a.key).st_mode & 0o077:
        sys.exit(f'{a.key}: missing, or readable by others (must be 0600)')
    if not os.path.isdir(os.path.join(a.out, '.git')):
        sys.exit(f'{a.out}: not a git checkout')

    d = etl.bundled_catalog()
    ents = d.get('entries') or []
    bad = [e.get('prefix') for e in ents if not etl.valid_entry(e)]
    prefixes = [e['prefix'] for e in ents]
    dup = sorted({p for p in prefixes if prefixes.count(p) > 1})
    if bad or dup:
        sys.exit(f'refusing to sign: invalid entries {bad}, duplicate prefixes {dup}')
    stamp = int(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M'))
    d = {'schema': etl.CATALOG_SCHEMA, 'serial': max(stamp, etl.catalog_serial(d) + 1), 'entries': ents}
    raw = (json.dumps(d, indent=2) + '\n').encode()
    etl.parse_catalog(raw)
    sig = sign(raw, a.key)
    if not etl.verify_signature(raw, sig):
        sys.exit('signature does not verify with modules/etlrunner/catalog_signing.pub — wrong key?')

    with open(etl.CATALOG, 'wb') as f:
        f.write(raw)
    with open(os.path.join(a.out, etl.CATALOG_FILE), 'wb') as f:
        f.write(raw)
    with open(os.path.join(a.out, etl.CATALOG_FILE + '.sig'), 'w') as f:
        f.write(sig)
    rev = sum(1 for e in ents if e.get('reviewed'))
    print(f"serial {d['serial']}: {len(ents)} entries ({rev} reviewed), signed and verified")
    print(f'  bundled:   {os.path.relpath(etl.CATALOG)}')
    print(f'  published: {a.out}/{etl.CATALOG_FILE} (+ .sig) — commit and push both repos yourself')


if __name__ == '__main__':
    main()
