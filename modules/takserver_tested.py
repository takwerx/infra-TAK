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
"""The newest TAK Server version that passed our install and update tests (ops #1119).

tak.gov needs a login, so a box cannot ask it which TAK Server is newest. What we can say, and
what customers want to hear, is "we installed this version and updated to it, and both worked".
That statement lives in a small signed file in takwerx/infratak-etl-catalog
(takserver-tested.json + takserver-tested.json.sig), signed with the same offline Ed25519 key as
the ETL catalog and the TAK Portal verified file. It is written by `pipeline/takserver-tested` in
the ops repo, and only after a passing fresh install and a passing update for that exact version.

It is data, never code. It does not pick what a box installs: TAK Server packages still come from
the operator's own tak.gov download. It only drives two messages: the "Latest we tested" line on
the TAK Server page and one Guard Dog email per tested version.

Pure helpers only: no network, no app.py import. app.py fetches the two files and calls
accept_fetched(); everything that reads the result calls cached().

Rules, in one place (same as modules/takportal_verified.py):
  * a fetched file is used only when its signature verifies against the pinned public key;
  * its serial must never go down (a replayed older file is a rollback and is refused);
  * it must say `"kind": "takserver-tested"`, so a file signed with the same key for something else
    is never taken for it;
  * it carries an `expires` date (UTC, YYYY-MM-DD). A fetched file past its date is refused, so an
    old signed file replayed to a new box goes stale. A file a box already accepted keeps working.
"""
import datetime as _dt
import json as _json
import os
import re as _re

from . import etlrunner as _etl

TESTED_REPO = _etl.CATALOG_REPO              # takwerx/infratak-etl-catalog
TESTED_BRANCH = _etl.CATALOG_BRANCH
TESTED_FILE = 'takserver-tested.json'
TESTED_SCHEMA = 1
TESTED_KIND = 'takserver-tested'
TESTED_MAX_BYTES = 16 * 1024
TESTED_CHECK_SEC = 1800                      # same cadence as the TAK Portal verified file
COMMIT_RE = _etl.SHA_RE
EXPIRES_RE = _re.compile(r'^\d{4}-\d{2}-\d{2}$')
# 5.8-RELEASE104 (what dpkg and rpm show) or 5.8-RELEASE-104 (what tak.gov file names show).
VERSION_RE = _re.compile(r'^(\d+)\.(\d+)-RELEASE-?(\d+)$')
TAK_GOV_URL = 'https://tak.gov/products/tak-server'


def normalize(version):
    """'5.8-RELEASE-104' and '5.8-RELEASE104' both become '5.8-RELEASE104'; '' when it is neither."""
    m = VERSION_RE.fullmatch(str(version or '').strip())
    return f'{m.group(1)}.{m.group(2)}-RELEASE{m.group(3)}' if m else ''


def version_tuple(version):
    """(5, 8, 104) for '5.8-RELEASE104'. Finds the version inside a longer string too (a dpkg
    version can carry a suffix). None when no TAK Server release version is in it."""
    s = str(version or '').strip()
    m = VERSION_RE.fullmatch(s) or _re.search(r'(\d+)\.(\d+)-RELEASE-?(\d+)', s)
    return tuple(int(g) for g in m.groups()) if m else None


def parse(raw):
    """bytes -> dict, or ValueError. Checks shape only; the signature is checked apart."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > TESTED_MAX_BYTES:
        raise ValueError('tested-version file is too large')
    try:
        d = _json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise ValueError('tested-version file is not JSON')
    if not isinstance(d, dict) or d.get('schema') != TESTED_SCHEMA:
        raise ValueError('tested-version file schema is not supported')
    if d.get('kind') != TESTED_KIND:
        raise ValueError('tested-version file is not of kind takserver-tested')
    serial = d.get('serial')
    if not isinstance(serial, int) or isinstance(serial, bool) or serial <= 0:
        raise ValueError('tested-version file has no serial')
    if expires_on(d) is None:
        raise ValueError('tested-version file has no valid expires date')
    v = d.get('version')
    if not isinstance(v, str) or not normalize(v) or normalize(v) != v:
        raise ValueError('tested-version file has no valid version')
    if d.get('installs') is not True or d.get('updates') is not True:
        raise ValueError('tested-version file does not say both the install and the update passed')
    if _date(d.get('tested')) is None:
        raise ValueError('tested-version file has no valid tested date')
    return d


def _date(v):
    if not isinstance(v, str) or not EXPIRES_RE.fullmatch(v):
        return None
    try:
        return _dt.date.fromisoformat(v)
    except ValueError:
        return None


def expires_on(d):
    return _date(d.get('expires')) if isinstance(d, dict) else None


def is_expired(d, today=None):
    exp = expires_on(d)
    if exp is None:
        return True
    return (today or _dt.datetime.now(_dt.timezone.utc).date()) > exp


def serial_of(d):
    s = d.get('serial') if isinstance(d, dict) else None
    return s if isinstance(s, int) and not isinstance(s, bool) and s > 0 else 0


def accept_fetched(raw, sig, floor, pubkey_path=_etl.CATALOG_PUBKEY, today=None):
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
    if is_expired(d, today):
        return None, f'expired on {d["expires"]} (an old signed file is not accepted as new)'
    return d, ''


def cached(cache_dir, pubkey_path=_etl.CATALOG_PUBKEY):
    """The cached file in `cache_dir`, or None unless its signature still verifies (checked again
    on every read, so a file edited on disk after it was cached is never trusted)."""
    if not cache_dir:
        return None
    cp = os.path.join(cache_dir, TESTED_FILE)
    try:
        with open(cp, 'rb') as f:
            raw = f.read(TESTED_MAX_BYTES + 1)
        with open(cp + '.sig', 'rb') as f:
            sig = f.read(4096)
        d = parse(raw)
    except (OSError, ValueError):
        return None
    return d if _etl.verify_signature(raw, sig, pubkey_path) else None


def page_state(installed, record):
    """What the TAK Server page shows next to the installed version.

    {tested, tested_date, state}   state is one of
      'unknown'  no signed file yet, or the installed version cannot be read: say nothing.
      'current'  the box runs the tested version, or a newer one (a newer one is not tested by us).
      'behind'   the box runs an older version than the one we tested.
    A box that runs a NEWER version than the tested one gets state 'newer': the page says we have
    not tested it yet, and never calls it behind."""
    out = {'tested': '', 'tested_date': '', 'state': 'unknown'}
    if not isinstance(record, dict) or not record.get('version'):
        return out
    out['tested'] = record['version']
    out['tested_date'] = record.get('tested') or ''
    have, want = version_tuple(installed), version_tuple(record['version'])
    if have is None or want is None:
        return out
    out['state'] = 'behind' if have < want else ('current' if have == want else 'newer')
    return out


def pending_item(installed, record, how):
    """The Guard Dog "pending update" item for a box that runs an older TAK Server than the one we
    tested, or None. Shape matches app._collect_pending_updates items. The identity is the tested
    version, so the mail goes out once per tested version and never repeats."""
    if page_state(installed, record)['state'] != 'behind':
        return None
    v = record['version']
    return {
        'key': 'takserver-tested', 'label': 'TAK Server', 'installed': str(installed).strip(), 'target': v,
        'identity': v, 'tested_new': True,
        'summary': f'We tested TAK Server {v}. It installs and updates fine.',
        'detail': [f'Tested {record.get("tested")}: a fresh install and an update both worked.',
                   f'Your server runs {str(installed).strip()}.',
                   f'Get the new package from tak.gov ({TAK_GOV_URL}), upload it on the TAK Server page, '
                   'then click Update TAK Server. Read the checks the page shows first.'],
        'how': how,
    }
