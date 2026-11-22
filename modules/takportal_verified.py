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
  * it must say `"kind": "takportal-verified"`, so a file signed with the same key for something
    else (the ETL catalog) is never taken for it;
  * it carries an `expires` date (UTC, YYYY-MM-DD, good through that day). A fetched file past its
    date is refused, so an old signed file replayed to a brand-new box (serial floor 0) goes
    stale. A file a box already accepted keeps working after its date: a missed renewal must not
    push every box back to the floor. The daily sweep (`pipeline/takportal-verify check`) warns
    while there is time to re-sign;
  * serial rules apply to the FILE, not to the version: moving the verified version back to an
    earlier tag (a version that passed and later turned out bad) is a new file with a higher serial;
  * with no valid file, the answer is the bundled floor (TAKPORTAL_REF_FALLBACK), never GitHub.
"""
import datetime as _dt
import json as _json
import os
import re as _re

from . import etlrunner as _etl

VERIFIED_REPO = _etl.CATALOG_REPO            # takwerx/infratak-etl-catalog
VERIFIED_BRANCH = _etl.CATALOG_BRANCH
VERIFIED_FILE = 'takportal-verified.json'
VERIFIED_SCHEMA = 1
VERIFIED_KIND = 'takportal-verified'
VERIFIED_MAX_BYTES = 64 * 1024
VERIFIED_CHECK_SEC = 1800                    # same cadence as the update badge cache
TAG_RE = _re.compile(r'^v?\d+(\.\d+){1,3}$')   # same shape the readers have always accepted
COMMIT_RE = _etl.SHA_RE
HELD_MAX = 200
EXPIRES_RE = _re.compile(r'^\d{4}-\d{2}-\d{2}$')


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
    if d.get('kind') != VERIFIED_KIND:
        raise ValueError('verified-version file is not of kind takportal-verified')
    serial = d.get('serial')
    if not isinstance(serial, int) or isinstance(serial, bool) or serial <= 0:
        raise ValueError('verified-version file has no serial')
    if expires_on(d) is None:
        raise ValueError('verified-version file has no valid expires date')
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


def expires_on(d):
    """The `expires` date of a parsed file as a date, or None when it is missing or not a real date."""
    v = d.get('expires') if isinstance(d, dict) else None
    if not isinstance(v, str) or not EXPIRES_RE.fullmatch(v):
        return None
    try:
        return _dt.date.fromisoformat(v)
    except ValueError:
        return None


def is_expired(d, today=None):
    """True when `d` is past its `expires` date (still good all through that day, UTC)."""
    exp = expires_on(d)
    if exp is None:
        return True
    return (today or _dt.datetime.now(_dt.timezone.utc).date()) > exp


def serial_of(d):
    s = d.get('serial') if isinstance(d, dict) else None
    return s if isinstance(s, int) and not isinstance(s, bool) and s > 0 else 0


def accept_fetched(raw, sig, floor, pubkey_path=_etl.CATALOG_PUBKEY, today=None):
    """(dict, '') when a fetched file may replace the cache, else (None, reason). `floor` is the
    highest serial this box has accepted: anything lower is a rollback. A file past its `expires`
    date is refused here (a stale replay); `cached()` does not check the date."""
    try:
        d = parse(raw)
    except ValueError as e:
        return None, str(e)
    if not _etl.verify_signature(raw, sig, pubkey_path):
        return None, 'signature does not verify'
    if serial_of(d) < floor:
        return None, f'serial {serial_of(d)} is older than {floor} (rollback refused)'
    if is_expired(d, today):
        return None, f'expired on {d["expires"]} (an old signed file is not accepted as new)'
    return d, ''


def cached(cache_dir, pubkey_path=_etl.CATALOG_PUBKEY):
    """The cached file in `cache_dir`, or None unless its signature still verifies. Verified again
    on every read, so a file edited on disk after it was cached is never trusted. The `expires`
    date is not checked here on purpose (see the module docstring): it gates what a box newly
    accepts, not what it already accepted."""
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


# --- Vetted vs Available (ops #1065) -----------------------------------------
# The gate decides what Update installs (Vetted). It must not hide that TAK Portal's maintainers
# shipped something newer: the console shows both, and an admin who accepts the risk can install the
# newer one by hand. Nothing below changes what Update, deploy, the badge or Guard Dog use.
REASON_MAX = 160


def version_tuple(tag):
    """(2, 0, 40) for '2.0.40' or 'v2.0.40'; None for anything that is not a plain release tag."""
    t = str(tag or '')
    if not TAG_RE.fullmatch(t):
        return None
    return tuple(int(p) for p in t.lstrip('vV').split('.'))


def clean_reason(text):
    """A held reason as one short plain line. It comes from a signed file, but it ends up in a dialog,
    so control characters and long text never reach the page."""
    s = ' '.join(''.join(ch if ch.isprintable() else ' ' for ch in str(text or '')).split())
    return s[:REASON_MAX]


def held_reason(record, tag):
    """The reason the signed file gives for holding `tag`, or '' (not held, or no reason given)."""
    if not isinstance(record, dict):
        return ''
    want = str(tag or '').lstrip('vV')
    for h in record.get('held', []):
        if str(h.get('tag', '')).lstrip('vV') == want:
            return clean_reason(h.get('reason'))
    return ''


def channel_state(vetted_tag, available_tag, record):
    """What the TAK Portal page shows next to the installed version.

    {vetted, available, state, reason, newer}
      state 'none'    Available is not newer than Vetted (or equal): nothing to say.
      state 'testing' Available is newer, we have not signed it and have not held it: it is in our
                      test queue (the daily sweep opens a gate issue for every new release).
      state 'held'    Available is newer and failed our gate; `reason` says why in a few words.
      state 'unknown' Vetted or Available could not be read (offline, no signed file yet).
    `newer` is True for 'testing' and 'held': the two states that offer the not-vetted install."""
    out = {'vetted': str(vetted_tag or '').lstrip('vV'), 'available': str(available_tag or '').lstrip('vV'),
           'state': 'unknown', 'reason': '', 'newer': False}
    v, a = version_tuple(vetted_tag), version_tuple(available_tag)
    if v is None or a is None:
        return out
    if a <= v:
        out['state'] = 'none'
        return out
    out['newer'] = True
    if is_held(record, available_tag):
        out['state'] = 'held'
        out['reason'] = held_reason(record, available_tag)
    else:
        out['state'] = 'testing'
    return out


def may_install_unvetted(requested_tag, available_tag, vetted_tag, installed=''):
    """(ok, why not). The not-vetted install takes only the release GitHub calls the newest one right
    now, only when it is newer than what we vetted, and never one the box already runs. A branch, a
    commit, an older release or any other tag is refused whatever the caller sends."""
    r, a, v = version_tuple(requested_tag), version_tuple(available_tag), version_tuple(vetted_tag)
    if r is None:
        return False, 'That is not a TAK Portal release tag.'
    if a is None or r != a:
        return False, 'That is not the newest TAK Portal release any more. Reload the page.'
    if v is None:
        return False, 'The console could not read which release we vetted, so it cannot say this one is newer.'
    if r <= v:
        return False, 'That release is not newer than the vetted one. Use Update.'
    cur = version_tuple(installed)
    if cur is not None and cur >= r:
        return False, 'TAK Portal already runs that release or a newer one.'
    return True, ''
