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
"""The retention guard deletes only what TAK Server would, and never reports a
failed lookup as an all-clear (v10.2.10, GH #98).

Field (10.2.6, split install): the guard's batched DELETE had no exclusion for
mission-linked rows — 35,119 of the reporter's 40,026 old rows. It had not fired
there only because local mode ran `sudo -u postgres psql` on an app node with no
postgres user, discarded the error, and logged "~0 expired rows ... nothing to do"
8,824 times in a row.

The REAL script runs here with its absolute paths pointed into a sandbox and
sudo/ssh/docker stubbed; every SQL statement it sends is recorded.
"""

import json
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
GUARD = (REPO / 'scripts' / 'guarddog' / 'tak-retention-guard.sh').read_text()
LIB = (REPO / 'scripts' / 'guarddog' / '_gd-tak-lib.sh').read_text()

# A stand-in for `sudo -u postgres psql -d cot ... -c "<sql>"`. Behaviour is
# driven by FAKE_* env vars; each SQL statement is appended to sql.log.
FAKE_SUDO = r'''#!/usr/bin/env python3
import os, sys
mode = os.environ.get('FAKE_PG', 'ok')
if mode == 'nouser':
    sys.stderr.write('sudo: unknown user postgres\n'); sys.exit(1)
sql = sys.argv[-1]
with open(os.environ['FAKE_SQL_LOG'], 'a') as f:
    f.write(sql + '\n---\n')
if sql == 'SELECT 1;':
    print('1'); sys.exit(0)
if 'count_estimate' in sql:
    sys.stderr.write('ERROR:  function count_estimate(unknown) does not exist\n'); sys.exit(1)
if 'pg_stat_activity' in sql:
    if 'COUNT(*)' in sql:
        print('0')
    sys.exit(0)
if sql.startswith('SELECT COUNT(*) FROM (SELECT 1 FROM cot_router'):
    if mode == 'countfail':
        sys.stderr.write('ERROR:  relation "mission_uid" does not exist\n'); sys.exit(1)
    print(os.environ.get('FAKE_EXPIRED', '5000')); sys.exit(0)
if sql.startswith('DELETE'):
    if mode == 'deletefail':
        sys.stderr.write('ERROR:  canceling statement due to lock timeout\n'); sys.exit(1)
    print('DELETE 5000'); sys.exit(0)
sys.exit(0)
'''


@pytest.fixture
def box(tmp_path):
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    calls = tmp_path / 'calls.log'
    sql_log = tmp_path / 'sql.log'
    sql_log.write_text('')
    (stubs / 'sudo').write_text(FAKE_SUDO)
    for name, body in (('ssh', 'echo "ssh $*" >> %s; exit 1' % calls),
                       ('docker', 'exit 1'),          # no DB container on this box
                       ('ip', 'exit 0'),               # no extra local addresses
                       ('alert', 'cat >/dev/null; echo "alert $*" >> %s' % calls)):
        (stubs / name).write_text('#!/bin/sh\n%s\n' % body)
    for f in stubs.iterdir():
        f.chmod(0o755)

    conf = tmp_path / 'guarddog.conf'
    core = tmp_path / 'CoreConfig.xml'
    policy = tmp_path / 'retention-policy.yml'
    policy.write_text('dataRetentionMap:\n  cot: 172800\n  geochat: null\n')
    core.write_text('<connection url="jdbc:postgresql://127.0.0.1:5432/cot"/>\n')

    lib = tmp_path / '_gd-tak-lib.sh'
    lib.write_text(LIB.replace('/opt/tak/CoreConfig.xml', str(core)))

    def run(script_text=GUARD, conf_obj=None, env=None):
        if conf_obj is not None:
            conf.write_text(json.dumps(conf_obj))
        script = (script_text
                  .replace('/opt/tak-guarddog/_gd-tak-lib.sh', str(lib))
                  .replace('/opt/tak-guarddog/guarddog.conf', str(conf))
                  .replace('/opt/tak-guarddog/server_identifier', str(tmp_path / 'sid'))
                  .replace('/opt/tak-guarddog/send-alert-email.sh', str(stubs / 'alert'))
                  .replace('/opt/tak/conf/retention/retention-policy.yml', str(policy))
                  .replace('/var/log/takguard', str(tmp_path / 'log')))
        path = tmp_path / 'guard.sh'
        path.write_text(script)
        e = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs,
             'GD_CONF_FILE': str(conf), 'FAKE_SQL_LOG': str(sql_log)}
        e.update(env or {})
        r = subprocess.run(['bash', str(path)], env=e, capture_output=True, text=True, timeout=60)
        logf = tmp_path / 'log' / 'restarts.log'
        return {'rc': r.returncode,
                'log': logf.read_text() if logf.exists() else '',
                'sql': [s.strip() for s in sql_log.read_text().split('\n---\n') if s.strip()],
                'calls': calls.read_text() if calls.exists() else ''}

    run.core = core
    return run


def _deletes(res):
    return [s for s in res['sql'] if s.startswith('DELETE')]


def test_delete_keeps_mission_rows_and_geochat_like_tak(box):
    res = box()
    assert res['rc'] == 0, res
    dels = _deletes(res)
    assert dels, res
    for sql in dels:
        # TAK's own LocalQueryService.deleteCotByTtl predicate.
        assert 'NOT EXISTS (SELECT 1 FROM mission_uid mu WHERE mu.uid = cr.uid)' in sql
        assert "cr.cot_type <> 'b-t-f'" in sql
        assert "interval '48 hours'" in sql
    counts = [s for s in res['sql'] if s.startswith('SELECT COUNT(*) FROM (SELECT 1 FROM cot_router')]
    assert counts and 'mission_uid' in counts[0]
    assert 'removed 5000 rows' in res['log']


def test_count_estimate_inner_query_is_quoted_for_sql(box):
    res = box()
    est = [s for s in res['sql'] if 'count_estimate' in s]
    assert est
    # The inner query is a SQL string literal: every quote inside must be doubled.
    assert "interval ''48 hours''" in est[0] and "<> ''b-t-f''" in est[0]
    assert '\\' not in est[0]


def test_unreachable_local_db_fails_loudly_not_zero_rows(box):
    # The reporter's box: no postgres user locally, error used to read as "~0 rows".
    res = box(env={'FAKE_PG': 'nouser'})
    assert res['rc'] != 0
    assert 'ERROR' in res['log'] and 'NOT an all-clear' in res['log']
    assert 'nothing to do' not in res['log']
    assert not _deletes(res)


def test_failed_count_is_an_error_not_zero(box):
    res = box(env={'FAKE_PG': 'countfail'})
    assert res['rc'] != 0
    assert 'count query failed' in res['log']
    assert 'expired rows' not in res['log'].replace('expired-row count', '')
    assert not _deletes(res)


def test_failed_delete_is_reported_as_failure(box):
    res = box(env={'FAKE_PG': 'deletefail'})
    assert res['rc'] != 0
    assert 'batched delete failed' in res['log']
    assert 'batched delete complete' not in res['log']


def test_below_threshold_still_reports_nothing_to_do(box):
    res = box(env={'FAKE_EXPIRED': '12'})
    assert res['rc'] == 0
    assert '~12 expired rows' in res['log'] and 'nothing to do' in res['log']
    assert not _deletes(res)


def test_two_server_with_placeholders_refuses_and_says_so(box):
    res = box(conf_obj={'two_server': True, 'db_host': ''})
    assert res['rc'] == 0
    assert 'NOT RUNNING' in res['log'] and 'placeholders' in res['log']
    assert 'ssh' not in res['calls']
    assert not res['sql']


def test_placeholder_check_survives_deploy_substitution():
    # app.py substitutes these tokens on deploy (run_guarddog_deploy). The guard's
    # own placeholder check must not be rewritten into something that never matches.
    deployed = (GUARD.replace('DB_HOST_PLACEHOLDER', '10.0.0.5')
                     .replace('SSH_KEY_PLACEHOLDER', '/home/takwerx/.ssh/infratak_serverone')
                     .replace('SSH_USER_PLACEHOLDER', 'takwerx')
                     .replace('ALERT_EMAIL_PLACEHOLDER', ''))
    assert '*_PLACEHOLDER*)' in deployed


def test_two_server_without_key_says_not_running(box, tmp_path):
    deployed = (GUARD.replace('DB_HOST_PLACEHOLDER', '10.0.0.5')
                     .replace('SSH_KEY_PLACEHOLDER', str(tmp_path / 'missing-key'))
                     .replace('SSH_USER_PLACEHOLDER', 'takwerx'))
    res = box(script_text=deployed, conf_obj={'two_server': True, 'db_host': '10.0.0.5'})
    assert res['rc'] == 0
    assert 'NOT RUNNING' in res['log'] and '(clean)' not in res['log']
    assert not res['sql']


def _grep_has_pcre():
    return subprocess.run(['grep', '-oP', r'a\Kb'], input='ab', capture_output=True,
                          text=True).stdout.strip() == 'b'


@pytest.mark.skipif(not _grep_has_pcre(), reason='gd_db_host needs GNU grep -P (Linux)')
def test_split_install_unknown_to_console_refuses_instead_of_local_mode(box):
    # No two_server in guarddog.conf, but TAK's CoreConfig points at another host.
    box.core.write_text('<connection url="jdbc:postgresql://10.20.30.40:5432/cot"/>\n')
    res = box(conf_obj={})
    assert res['rc'] == 0
    assert 'NOT RUNNING' in res['log'] and '10.20.30.40' in res['log']
    assert not res['sql']                      # never touched any local postgres
