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
"""TAK 5.8 upgrade on a ROOT console: the pre-migration backup can be verified (v10.2.7).

Field, lutak2.net 2026-10-03 (root console, broker routing False, native 5.7):

    snapshot: cot pg_dump written (5355 KB)
    verifying the backup is restorable (pg_restore --list)…
    backup verification FAILED — could not read the archive (dump failed authenticity
    check — not a broker-produced snapshot). Do not proceed with the migration.

_tak_58_backup() always asked the broker to read the dump, and the broker only reads dumps
that carry its own HMAC sidecar — which only ITS pg_dump writes. A root console dumps in
_tak_snapshot()'s root branch, so every root console was refused, every time. Now the root
branch proves its own dump reads (pg_restore --list, like the external-DB branch) and
records db_dump_toc; only broker-written dumps go to the broker.
"""

import ast
import os
import pathlib
import re
import stat
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _func(name):
    return re.search(rf'^def {name}\(.*?(?=^def )', APP, re.S | re.M).group(0)


def _code(body):
    return re.sub(r'#.*', '', body)


def _load(names, ns):
    parts = [ast.get_source_segment(APP, n) for n in ast.parse(APP).body
             if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(parts) == len(names), 'a function under test was renamed or removed'
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


class _Broker:
    def __init__(self, reply):
        self.calls, self.reply = [], reply

    def __call__(self, req, timeout=None):
        self.calls.append(req)
        return self.reply


def _backup(meta, broker_reply=None, snap_ok=True):
    broker = _Broker(broker_reply or {'ok': True, 'toc_entries': 42})
    ns = _load({'_tak_58_backup'}, {
        'os': os, 'time': __import__('time'), 'subprocess': subprocess,
        'SNAPSHOT_DIR': '/opt/tak/snapshots',
        '_tak_snapshot': lambda label, plog=None: (snap_ok, dict(meta)),
        '_sudo_wrap': lambda argv: ['true'],          # the stat probe; size comes from meta
        '_broker_request': broker,
        '_cotdb_fmt_bytes': lambda n: '%d B' % n,
    })
    log = []
    out = ns['_tak_58_backup'](plog=log.append)
    return out, broker.calls, log


def test_root_console_dump_verified_locally_never_asks_the_broker():
    out, calls, log = _backup({'db_dump': True, 'db_dump_via': 'root',
                               'db_dump_toc': 311, 'db_dump_bytes': 5483520})
    assert out['ok'] and out['toc_entries'] == 311 and out['error'] is None
    assert calls == []
    assert any('backup verified' in l and '311 objects' in l for l in log)


def test_root_dump_that_did_not_verify_says_why_not_authenticity():
    out, calls, log = _backup({'db_dump': True, 'db_dump_via': 'root',
                               'db_dump_verify_error': 'could not read the archive (truncated)'})
    assert not out['ok'] and calls == []
    assert 'truncated' in out['error'] and 'authenticity' not in out['error']
    assert 'Do not proceed with the migration' in out['error']


def test_broker_dump_still_goes_through_the_broker_hmac_check():
    out, calls, _ = _backup({'db_dump': True, 'db_dump_via': 'broker'})
    assert out['ok'] and out['toc_entries'] == 42
    assert len(calls) == 1 and calls[0]['op'] == 'pg_restore' and calls[0]['list_only'] is True


def test_broker_refusal_is_still_a_hard_stop():
    out, calls, _ = _backup({'db_dump': True, 'db_dump_via': 'broker'},
                            broker_reply={'ok': False, 'error': 'dump failed authenticity check'})
    assert not out['ok'] and len(calls) == 1 and 'authenticity' in out['error']


def test_unverified_non_broker_dump_is_refused_without_the_broker():
    # e.g. the two-server branch: copied in from Server One, never verified
    out, calls, _ = _backup({'db_dump': True, 'db_dump_via': 'remote'})
    assert not out['ok'] and calls == []
    assert 'could not be verified where it was written' in out['error']


def _toc_ns(tmp_path, script):
    fake = tmp_path / 'bin' / 'pg_restore'
    fake.parent.mkdir()
    fake.write_text('#!/bin/sh\n' + script)
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    shutil_stub = type('S', (), {'which': staticmethod(lambda n: str(fake))})
    return _load({'_pg_restore_toc'}, {'os': os, 'subprocess': subprocess, 'shutil': shutil_stub,
                                       '_TAK58_PG_BIN_LAYOUTS': ('/nonexistent-{major}',)})


def test_pg_restore_toc_counts_entries_like_the_broker(tmp_path):
    ns = _toc_ns(tmp_path, 'printf ";\\n; Archive created\\n;\\n3; 2615 2200 SCHEMA - public\\n'
                           '4; 0 0 TABLE public cot_router\\n\\n"\n')
    assert ns['_pg_restore_toc'](str(tmp_path / 'cot.pgdump')) == (2, '')


def test_pg_restore_toc_failure_returns_the_reason(tmp_path):
    ns = _toc_ns(tmp_path, 'echo "pg_restore: error: input file is too short" >&2; exit 1\n')
    n, why = ns['_pg_restore_toc'](str(tmp_path / 'cot.pgdump'))
    assert n == 0 and 'input file is too short' in why


def test_snapshot_branches_record_who_wrote_the_dump():
    body = _code(_func('_tak_snapshot'))
    root = body[body.index("['runuser', '-u', 'postgres', '--', 'pg_dump',"):]
    root = root[:root.index("meta['db_dump_toc'] = _toc_n") + 40]
    assert "meta['db_dump_via'] = 'root'" in root and '_pg_restore_toc(pg_dump_path)' in root
    broker = body[body.index('_pg_dump_priv(pg_dump_path'):]
    broker = broker[:broker.index('else:')]
    assert "meta['db_dump_via'] = 'broker'" in broker
