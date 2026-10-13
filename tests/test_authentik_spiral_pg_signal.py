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
"""The spiral detector's Postgres signal sees connections that come through PgBouncer (ops #38).

Authentik's server reaches Postgres through PgBouncer, which leaves application_name blank.
The detector counted idle-in-transaction only `WHERE application_name LIKE '%authentik%'`,
so on every PgBouncer box it matched the worker's one direct connection and read 0 —
test8 had 57 idle-in-transaction sessions mid-storm, every one with a blank name.

_detect_authentik_ldap_spiral() is cut out of app.py and run with docker stubbed.
"""

import pathlib
import re
import subprocess
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _detector(pg_out, ldap_log=''):
    src = re.search(r'^def _detect_authentik_ldap_spiral\(.*?(?=^def )', APP, re.S | re.M).group(0)
    queries = []

    def run(cmd, **kw):
        if cmd[:2] == ['docker', 'logs']:
            return subprocess.CompletedProcess(cmd, 0, stdout=ldap_log)
        sql = cmd[-1]
        queries.append(sql)
        if 'django_channels_postgres_message' in sql:
            return subprocess.CompletedProcess(cmd, 0, stdout='0|0\n')
        return subprocess.CompletedProcess(cmd, 0, stdout=pg_out)

    sub = types.SimpleNamespace(PIPE=subprocess.PIPE, STDOUT=subprocess.STDOUT, run=run)
    ns = {'subprocess': sub, '_sudo_wrap': lambda c: c}
    exec(compile(src, 'app.py:_detect_authentik_ldap_spiral', 'exec'), ns)
    return ns['_detect_authentik_ldap_spiral'], queries


def _idle_in_tx_sql(queries):
    sql = next(q for q in queries if 'idle in transaction' in q)
    return sql.split('),')[0]          # the first sub-select: the idle-in-transaction count


def test_count_does_not_depend_on_application_name():
    detect, queries = _detector('57|117\n')
    detect()
    idle = _idle_in_tx_sql(queries)
    assert 'application_name' not in idle
    assert "datname='authentik'" in idle
    assert 'pg_backend_pid()' in idle  # the probe's own psql session never counts
    assert "LIKE 'idle in transaction%'" in idle  # includes "idle in transaction (aborted)"


def test_test8_storm_trips_the_postgres_signal():
    detect, _ = _detector('57|117\n')
    spiraling, ev = detect()
    assert spiraling and ev['pg_idle_in_trans'] == 57
    assert ev['reason'].startswith('postgres signal: 57 idle-in-trans')


def test_healthy_box_stays_quiet():
    detect, _ = _detector('0|13\n')
    spiraling, ev = detect()
    assert not spiraling and ev['pg_idle_in_trans'] == 0
