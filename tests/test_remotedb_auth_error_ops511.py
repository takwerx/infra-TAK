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
"""Guard Dog's "DB Credential Alert" says WHY the database login failed (ops #511).

Field (test8, ops #509): the alert said the martiuser login failed but not whether the password
was wrong, PostgreSQL was restarting, or the connection dropped, because tak-remotedb-auth-watch.sh
threw psql's error text away (2>/dev/null). Now psql's first error line is in the alert email and
in restarts.log, with the passwords masked. The 3-failures-in-a-row rule (ops #488) is unchanged.

The REAL script runs against a stub ssh. The stub only prints psql's error to stdout when the
remote command asked for it (2>&1), exactly like a real shell, so these tests fail on the old
script, which discarded it.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_remotedb_blip_ops488 import AUTH, _alerts, _log, _run, _sandbox  # noqa: E402

PW_LOCAL = 'pw-Local-S3cret'
PW_SERVER = 'pw-Server-Zz9'

SSH = r'''#!/bin/bash
CFG='<connection url="jdbc:postgresql://db1:5432/cot" username="martiuser" password="%s"/>'
case "$*" in
  *__mgmt_ok__*) echo __mgmt_ok__ ;;
  *PGPASSWORD=*)
    mode=$(cat "@DIR@/psql_mode")
    [ "$mode" = ssh_drop ] && exit 255
    pw=$(printf '%s' "$*" | sed -n "s/.*PGPASSWORD='\([^']*\)'.*/\1/p")
    out=""
    if [ "$pw" = "$(cat "@DIR@/db_accepts")" ]; then
      [ "$mode" = warn ] && out="WARNING:  something harmless
"
      out="${out}1"
      err=""
    else
      case "$mode" in
        starting) err='psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  the database system is starting up' ;;
        leaky)    err="psql: error: connection to server failed: FATAL:  password authentication failed for user \"martiuser\" (password was $pw; url postgresql://martiuser:$pw@127.0.0.1:5432/cot; password=$pw)" ;;
        long)     err="psql: error: $(printf 'x%.0s' $(seq 1 900))" ;;
        *)        err='psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  password authentication failed for user "martiuser"' ;;
      esac
    fi
    # Like a real shell: psql's stderr only reaches us if the remote command said 2>&1.
    if printf '%s' "$*" | grep -q '2>&1'; then
      [ -n "$out" ] && printf '%s\n' "$out"
      [ -n "$err" ] && printf '%s\n' "$err"
    else
      [ -n "$out" ] && printf '%s\n' "$out"
      [ -n "$err" ] && printf '%s\n' "$err" >&2
    fi ;;
  *"sudo cat"*) printf "$CFG\n" "$(cat "@DIR@/server_one_pw")" ;;
esac
exit 0
'''


@pytest.fixture
def auth(tmp_path):
    stubs, sp = _sandbox(tmp_path, AUTH, SSH)
    (tmp_path / 'CoreConfig.xml').write_text(
        '<connection url="jdbc:postgresql://db1:5432/cot" username="martiuser" password="%s"/>\n' % PW_LOCAL)

    def run(db_accepts, server_one_pw=PW_LOCAL, psql_mode='wrong', times=1, tcp='up'):
        (tmp_path / 'db_accepts').write_text(db_accepts)
        (tmp_path / 'server_one_pw').write_text(server_one_pw)
        (tmp_path / 'psql_mode').write_text(psql_mode)
        (tmp_path / 'tcp').write_text(tcp)
        for _ in range(times):
            _run(stubs, sp, tmp_path)
        return tmp_path
    return run


WRONG_PW = 'FATAL:  password authentication failed for user "martiuser"'
STARTING = 'FATAL:  the database system is starting up'


def _everything_written(t):
    parts = [_log(t)]
    for name in ('alerts', 'bodies'):
        f = t / name
        parts.append(f.read_text() if f.exists() else '')
    return '\n'.join(parts)


def test_blip_log_line_says_why_the_login_failed(auth):
    t = auth('something-else', times=1)
    assert _alerts(t) == []                                     # still a blip: no email (ops #488)
    assert '1 of 3 in a row, no alert yet) — PostgreSQL said: psql: error:' in _log(t)
    assert WRONG_PW in _log(t)


def test_alert_email_and_log_carry_psqls_error_line(auth):
    t = auth('something-else', times=3)
    assert len(_alerts(t)) == 1 and 'DB Credential Alert' in _alerts(t)[0]
    body = (t / 'bodies').read_text()
    assert 'Why the login failed (PostgreSQL said): psql: error: connection to server at "127.0.0.1"' in body
    assert WRONG_PW in body
    assert 'Check that failed: database login as martiuser to db1:5432 (3 checks in a row' in body
    assert 'auto-resync FAILED' in _log(t) and WRONG_PW in _log(t)


def test_a_restarting_database_reads_differently_from_a_wrong_password(auth):
    t = auth('something-else', psql_mode='starting', times=3)
    body = (t / 'bodies').read_text()
    assert STARTING in body and WRONG_PW not in body


def test_three_in_a_row_rule_is_unchanged(auth):
    assert _alerts(auth('something-else', times=2)) == []
    t = auth('something-else', times=1)                         # the third run, state kept
    assert len(_alerts(t)) == 1


def test_passwords_never_reach_the_alert_or_the_log(auth):
    # psql's error line echoes the password three ways: bare, in a URL, and as password=...
    t = auth('something-else', server_one_pw=PW_SERVER, psql_mode='leaky', times=3)
    text = _everything_written(t)
    assert PW_LOCAL not in text and PW_SERVER not in text
    assert 'password authentication failed' in text             # the useful part survives
    assert '[hidden]' in text


def test_passwords_masked_when_server_ones_password_also_fails(auth):
    t = auth('neither', server_one_pw=PW_SERVER, psql_mode='leaky', times=3)
    body = (t / 'bodies').read_text()
    assert "PostgreSQL's answer to Server One's password:" in body
    assert PW_LOCAL not in _everything_written(t) and PW_SERVER not in _everything_written(t)


def test_auto_resync_email_also_says_what_postgresql_said_before_the_fix(auth):
    t = auth(PW_SERVER, server_one_pw=PW_SERVER, times=1)
    assert 'Auto-Resynced' in _alerts(t)[0]
    assert 'PostgreSQL said before the fix: psql: error:' in (t / 'bodies').read_text()
    assert PW_LOCAL not in _everything_written(t) and PW_SERVER not in _everything_written(t)


def test_a_harmless_warning_next_to_the_answer_is_still_a_successful_login(auth):
    t = auth(PW_LOCAL, psql_mode='warn', times=3)
    assert _alerts(t) == [] and _log(t) == ''
    assert not (t / 'state' / 'remotedb_auth_fail_count').exists()


def test_a_very_long_error_is_cut_to_one_short_line(auth):
    t = auth('something-else', psql_mode='long', times=3)
    line = [ln for ln in (t / 'bodies').read_text().splitlines() if ln.startswith('Why the login failed')][0]
    assert len(line) < 400


def test_a_dropped_ssh_session_is_still_not_a_credential_failure(auth):
    t = auth('whatever', psql_mode='ssh_drop', times=5)
    assert _alerts(t) == [] and 'Credentials were not tested' in _log(t)
