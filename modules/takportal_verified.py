# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""The TAK Portal release that passed our Marketplace test (ops #1042).

infra-TAK used to take TAK Portal's newest GitHub release the day it came out. TAK Portal 2.0.38
broke every Marketplace plugin install (ops #1037) and we cannot control what TAK Portal's
maintainers ship, so a release now reaches users only after it passes our gate.

The version that passed lives in a small signed file in takwerx/infratak-etl-catalog
(takportal-verified.json + takportal-verified.json.sig), signed with the same offline Ed25519 key
as the ETL catalog. It names a tag AND the commit that tag must point to. It moves without an
infra-TAK release. This file is data that picks which pinned tag we build; it never runs code.

Pure helpers only: no network, no app.py import (the Dependency Rule boundary). app.py fetches the
two files and calls accept_fetched(); everything that reads the result calls resolve().

Rules, in one place:
  * a fetched file is used only when its signature verifies against the pinned public key;
  * its serial must never go down (a replayed older file is a rollback and is refused);
  * serial rules apply to the FILE, not to the version: moving the verified version back to an
    earlier tag (a version that passed and later turned out bad) is a new file with a higher serial;
  * with no valid file, the answer is the bundled floor (TAKPORTAL_REF_FALLBACK), never GitHub.
"""
import json as _json
import os
import re as _re

from . import etlrunner as _etl

VERIFIED_REPO = _etl.CATALOG_REPO            # takwerx/infratak-etl-catalog
VERIFIED_BRANCH = _etl.CATALOG_BRANCH
VERIFIED_FILE = 'takportal-verified.json'
VERIFIED_SCHEMA = 1
VERIFIED_MAX_BYTES = 64 * 1024
VERIFIED_CHECK_SEC = 1800                    # same cadence as the update badge cache
TAG_RE = _re.compile(r'^v?\d+(\.\d+){1,3}$')   # same shape the readers have always accepted
COMMIT_RE = _etl.SHA_RE
HELD_MAX = 200


def parse(raw):
    """bytes -> dict, or ValueError. Checks shape only; the signature is checked apart."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > VERIFIED_MAX_BYTES:
        raise ValueError('verified-version file is too large')
    try:
        d = _json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise ValueError('verified-version file is not JSON')
    if not isinstance(d, dict) or d.get('schema') != VERIFIED_SCHEMA:
        raise ValueError('verified-version file schema is not supported')
    serial = d.get('serial')
    if not isinstance(serial, int) or isinstance(serial, bool) or serial <= 0:
        raise ValueError('verified-version file has no serial')
    tag = d.get('tag')
    if not isinstance(tag, str) or not TAG_RE.fullmatch(tag):
        raise ValueError('verified-version file has no valid tag')
    commit = d.get('commit')
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise ValueError('verified-version file has no valid commit')
    held = d.get('held', [])
    if not isinstance(held, list) or len(held) > HELD_MAX:
        raise ValueError('verified-version file has a bad held list')
    for h in held:
        if not isinstance(h, dict) or not isinstance(h.get('tag'), str) or not TAG_RE.fullmatch(h['tag']):
            raise ValueError('verified-version file has a bad held entry')
    return d


def serial_of(d):
    s = d.get('serial') if isinstance(d, dict) else None
    return s if isinstance(s, int) and not isinstance(s, bool) and s > 0 else 0


def accept_fetched(raw, sig, floor, pubkey_path=_etl.CATALOG_PUBKEY):
    """(dict, '') when a fetched file may replace the cache, else (None, reason). `floor` is the
    highest serial this box has accepted: anything lower is a rollback."""
    try:
        d = parse(raw)
    except ValueError as e:
        return None, str(e)
    if not _etl.verify_signature(raw, sig, pubkey_path):
        return None, 'signature does not verify'
    if serial_of(d) < floor:
        return None, f'serial {serial_of(d)} is older than {floor} (rollback refused)'
    return d, ''


def cached(cache_dir, pubkey_path=_etl.CATALOG_PUBKEY):
    """The cached file in `cache_dir`, or None unless its signature still verifies. Verified again
    on every read, so a file edited on disk after it was cached is never trusted."""
    if not cache_dir:
        return None
    cp = os.path.join(cache_dir, VERIFIED_FILE)
    try:
        with open(cp, 'rb') as f:
            raw = f.read(VERIFIED_MAX_BYTES + 1)
        with open(cp + '.sig', 'rb') as f:
            sig = f.read(4096)
        d = parse(raw)
    except (OSError, ValueError):
        return None
    return d if _etl.verify_signature(raw, sig, pubkey_path) else None


def resolve(record, fallback_tag):
    """(tag, commit, source). `record` is a verified dict or None. source is 'signed' or 'floor'.
    The floor has no commit to check (it is trusted like code, as it always was)."""
    if isinstance(record, dict) and record.get('tag'):
        return record['tag'], record['commit'], 'signed'
    return fallback_tag, None, 'floor'


def is_held(record, tag):
    """True when the signed file lists `tag` as held (failed the gate)."""
    if not isinstance(record, dict):
        return False
    want = str(tag or '').lstrip('vV')
    return any(str(h.get('tag', '')).lstrip('vV') == want for h in record.get('held', []))
