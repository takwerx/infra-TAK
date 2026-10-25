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
""""Retention is stalled" only for rows retention would actually delete (ops #227).

Found in the 10.2.30 T&E: the CoT Diagnose card said "Retention is stalled",
but every row past the retention window was mission content, which TAK's retention (and our guard, GH #98) keeps on purpose. The same
whole-table min(servertime) drove Guard Dog's "retention is not deleting" email.

Both are run here against a tiny model database: rows with an age, uid and
cot_type, plus the set of uids that belong to a mission.
"""

import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-cotdb-watch.sh').read_text()
GUARD = (REPO / 'scripts' / 'guarddog' / 'tak-retention-guard.sh').read_text()

HOUR = 3600
DAY = 86400

# Answers the handful of statements these code paths send, from a JSON model.
# Shared by the Python harness (imported) and the shell harness (run as a script).
FAKE_PSQL = r'''
import json, os, re, sys

EXPIRABLE = "cr.cot_type <> 'b-t-f' AND NOT EXISTS (SELECT 1 FROM mission_uid mu WHERE mu.uid = cr.uid)"

def answer(sql, model):
    if model.get('fail_expirable') and 'mission_uid' in sql:
        return False, 'ERROR:  canceling statement due to statement timeout'
    rows = model['rows']
    if 'pg_database_size' in sql:
        return True, '0'
    if 'min(cr.servertime)' in sql:
        assert EXPIRABLE in sql, sql
        line = int(re.search(r"interval '(\d+) seconds'", sql).group(1))
        ages = [r['age'] for r in rows if r['age'] > line and r['type'] != 'b-t-f'
                and r['uid'] not in model['missions']]
        # psql 15+ prints the SET tag too; the caller must take the last line.
        return True, 'SET\n%d' % (max(ages) if ages else 0)
    if 'min(servertime)' in sql and 'FROM cot_router;' in sql:
        oldest = max(r['age'] for r in rows) if rows else 0
        if '::text' in sql:
            return True, '2026-01-01 00:00:00+00|2026-10-25 00:00:00+00|%d' % oldest
        return True, 'SET\n%d' % oldest
    return True, ''

if __name__ == '__main__':
    model = json.load(open(os.environ['FAKE_MODEL']))
    with open(os.environ['FAKE_SQL_LOG'], 'a') as fh:
        fh.write(sys.argv[1] + '\n---\n')
    ok, out = answer(sys.argv[1], model)
    print(out)
    sys.exit(0 if ok else 1)
'''

_fake = {}
exec(compile(FAKE_PSQL, 'fake_psql', 'exec'), _fake)


def _model(*extra_rows, fail_expirable=False):
    rows = [{'age': 1 * HOUR, 'uid': 'ANDROID-1', 'type': 'a-f-G-U-C'},
            {'age': 10 * HOUR, 'uid': 'ANDROID-2', 'type': 'a-f-G-U-C'},
            # The field case: shapes in a mission, 30 days old, and an old
            # GeoChat message (aged out on the GeoChat TTL, not the CoT one).
            {'age': 30 * DAY, 'uid': 'shape-1', 'type': 'u-d-f'},
            {'age': 20 * DAY, 'uid': 'chat-1', 'type': 'b-t-f'}]
    rows.extend(extra_rows)
    return {'rows': rows, 'missions': ['shape-1'], 'fail_expirable': fail_expirable}


OLD_POSITION = {'age': 5 * DAY, 'uid': 'ANDROID-3', 'type': 'a-f-G-U-C'}


# ── Diagnose card (app.py) ──────────────────────────────────────────────────────

def _cotdb_ns(model, retention_hours=24):
    start = APP.index('_COTDB_TABLES = (')
    end = APP.index("@app.route('/api/guarddog/cotdb/diagnose')")
    ns = {'re': re, 'time': time, 'os': os, 'shlex': shlex, 'subprocess': subprocess}
    exec(compile(APP[start:end], 'app.py', 'exec'), ns)
    sent = []

    def fake_psql(_cfg, sql, db='cot', timeout=25):
        sent.append(sql)
        return _fake['answer'](sql, model)

    ns.update({
        '_cotdb_psql': fake_psql,
        '_cotdb_df': lambda _cfg, _path: (150 * 1024 ** 3, 200 * 1024 ** 3),
        '_cotdb_retention_hours': lambda: retention_hours,
        '_cotdb_retention_proc_alive': lambda: True,
        '_cotdb_systemctl': lambda _args: 'enabled',
        '_detect_disk_layout': lambda: {},
    })
    ns['sent'] = sent
    return ns


def _diagnose(model, **kw):
    ns = _cotdb_ns(model, **kw)
    facts = ns['_cotdb_facts']({'mode': 'local'})
    verdict, _headline, detail, _rec = ns['_cotdb_verdict'](facts)
    return facts, verdict, detail, ns['sent']


def test_only_mission_and_geochat_rows_old_is_not_stalled():
    facts, verdict, detail, _sent = _diagnose(_model())
    assert facts['oldest_age_secs'] == 30 * DAY        # the tile still shows the real oldest row
    assert facts['retention_stalled'] is False
    assert facts['old_rows_kept'] is True
    assert verdict != 'retention_stalled'
    assert 'retention keeps on purpose' in detail


def test_old_non_mission_row_still_raises_the_alarm():
    facts, verdict, detail, _sent = _diagnose(_model(OLD_POSITION))
    assert facts['retention_stalled'] is True
    assert facts['oldest_expirable_age_secs'] == 5 * DAY
    assert verdict == 'retention_stalled'
    # quotes the row retention should have deleted, not the 30-day mission shape
    assert 'should have deleted is 5 days old' in detail


def test_failed_lookup_keeps_the_alarm_and_says_why():
    facts, verdict, _detail, _sent = _diagnose(_model(fail_expirable=True))
    assert facts['retention_stalled'] is True and verdict == 'retention_stalled'
    assert any(e.startswith('retention-eligible age:') for e in facts['errors'])


def test_young_database_never_sends_the_extra_query():
    model = _model()
    model['rows'] = [r for r in model['rows'] if r['age'] < 48 * HOUR]
    facts, _verdict, _detail, sent = _diagnose(model)
    assert facts['retention_stalled'] is False and facts['old_rows_kept'] is False
    assert not [s for s in sent if 'mission_uid' in s]


def test_no_retention_policy_is_its_own_verdict_not_stalled():
    facts, verdict, _detail, sent = _diagnose(_model(OLD_POSITION), retention_hours=None)
    assert facts['retention_stalled'] is False and verdict == 'no_retention'
    assert not [s for s in sent if 'mission_uid' in s]


# ── Guard Dog email (tak-cotdb-watch.sh) ────────────────────────────────────────

@pytest.fixture
def watch(tmp_path):
    gd = tmp_path / 'gd'
    gd.mkdir()
    (tmp_path / 'state').mkdir()
    (tmp_path / 'fake_psql.py').write_text(FAKE_PSQL)
    (gd / '_gd-tak-lib.sh').write_text(
        'gd_psql_present() { return 0; }\n'
        'gd_psql_scalar() { %s %s "$1"; }\n'
        'gd_db_shell() { return 1; }\n' % (sys.executable, tmp_path / 'fake_psql.py'))
    (gd / 'server_identifier').write_text('box\n')
    (gd / 'send-alert-email.sh').write_text('#!/bin/sh\n{ echo "SUBJECT $1"; cat; } >> %s\n'
                                           % (tmp_path / 'mail'))
    (gd / 'send-alert-email.sh').chmod(0o755)
    policy = tmp_path / 'retention-policy.yml'
    policy.write_text('dataRetentionMap:\n  cot: 86400\n  geochat: null\n')
    script = (WATCH.replace('/opt/tak-guarddog/', str(gd) + '/')
                   .replace('/opt/tak/conf/retention/retention-policy.yml', str(policy))
                   .replace('/var/lib/takguard', str(tmp_path / 'state'))
                   .replace('/var/log/takguard', str(tmp_path / 'log')))
    sp = tmp_path / 'watch.sh'
    sp.write_text(script)

    def run(model):
        (tmp_path / 'model.json').write_text(json.dumps(model))
        (tmp_path / 'sql').write_text('')
        env = {'PATH': '/usr/bin:/bin', 'FAKE_MODEL': str(tmp_path / 'model.json'),
               'FAKE_SQL_LOG': str(tmp_path / 'sql')}
        r = subprocess.run(['bash', str(sp)], env=env, capture_output=True, text=True, timeout=60)
        mail = tmp_path / 'mail'
        return r, mail.read_text() if mail.exists() else '', (tmp_path / 'sql').read_text()
    return run


def test_watch_does_not_email_for_mission_rows(watch):
    r, mail, sql = watch(_model())
    assert r.returncode == 0, r.stderr
    assert 'mission_uid' in sql                       # it did look
    assert 'retention is not deleting' not in mail


def test_watch_still_emails_for_old_non_mission_rows(watch):
    r, mail, _sql = watch(_model(OLD_POSITION))
    assert r.returncode == 0, r.stderr
    assert 'CoT retention is not deleting' in mail
    assert 'should have deleted: 5 days old' in mail


def test_watch_failed_lookup_keeps_the_alert(watch):
    r, mail, _sql = watch(_model(fail_expirable=True))
    assert r.returncode == 0, r.stderr
    assert 'CoT retention is not deleting' in mail


# ── One definition of "expired" ─────────────────────────────────────────────────

def test_all_three_use_the_retention_guards_predicate():
    guard_where = re.search(r'^EXPIRED_WHERE="([^"]+)"', GUARD, re.M).group(1)
    expirable = _fake['EXPIRABLE']
    assert guard_where.endswith(' AND ' + expirable)
    ns = {}
    exec(re.search(r'^_COTDB_EXPIRABLE_WHERE = \(.*?\)\n', APP, re.S | re.M).group(0), ns)
    assert ns['_COTDB_EXPIRABLE_WHERE'] == expirable
    assert expirable in WATCH
