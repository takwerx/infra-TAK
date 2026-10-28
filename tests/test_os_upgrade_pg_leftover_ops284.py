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
"""ops #284 — the 22.04 -> 24.04 upgrade stopped at `reassert` on a box carrying the TAK
5.8 migration's stopped PostgreSQL 15 copy (field, 2026-10-27):

    15 main 5434 down   postgres /var/lib/postgresql/15/main ...
    18 main 5432 online postgres /var/lib/postgresql/18/main ...
    FATAL: step reassert failed — expected exactly one PostgreSQL cluster, found 2

The preflight let the box through ("any 18"), the reassert step demanded "exactly one" —
after the flip. Now one rule, in bash (the job) and Python (both preflights): exactly one
cluster online, 18 on 5432; anything else older, stopped, on another port. The bash
fragment is EXECUTED here against a stubbed pg_lsclusters, and its verdict must match the
Python helper's for every layout.
"""

import pathlib
import re
import subprocess

import pytest

from test_os_upgrade import Box, _check, _ns
import test_dbserver_upgrade as dbs

FIELD = ('15 main 5434 down   postgres /var/lib/postgresql/15/main log/postgresql-%a.log\n'
         '18 main 5432 online postgres /var/lib/postgresql/18/main log/postgresql-%a.log')


def _line(v, n, port, st):
    return f'{v} {n} {port} {st} postgres /var/lib/postgresql/{v}/{n} log/postgresql-%a.log'


LAYOUTS = [
    # (label, clusters, safe)
    ('only 18', [('18', 'main', '5432', 'online')], True),
    ('field: 15 stopped on 5434', [('15', 'main', '5434', 'down'), ('18', 'main', '5432', 'online')], True),
    ('15 stopped, binaries gone', [('15', 'main', '5433', 'down,binaries_missing'), ('18', 'main', '5432', 'online')], True),
    ('two old copies stopped', [('14', 'main', '5435', 'down'), ('15', 'main', '5434', 'down'), ('18', 'main', '5432', 'online')], True),
    ('15 still running beside 18', [('15', 'main', '5434', 'online'), ('18', 'main', '5432', 'online')], False),
    ('18 down', [('15', 'main', '5434', 'down'), ('18', 'main', '5432', 'down')], False),
    ('18 not on 5432', [('18', 'main', '5433', 'online')], False),
    ('only 15 running', [('15', 'main', '5432', 'online')], False),
    ('stopped 15 also on 5432', [('15', 'main', '5432', 'down'), ('18', 'main', '5432', 'online')], False),
    ('stopped newer major', [('18', 'main', '5432', 'online'), ('19', 'main', '5433', 'down')], False),
    ('second 18 stopped', [('18', 'main', '5432', 'online'), ('18', 'old', '5433', 'down')], False),
    ('none', [], False),
]


def _run_check(tmp_path, listing, script_fn='core'):
    """Execute the job's real reassert PG fragment with pg_lsclusters / dpkg stubbed."""
    ns = _ns()
    frag = ns['_OS_UPGRADE_SH_PG_CHECK']
    bindir = tmp_path / 'bin'
    bindir.mkdir(exist_ok=True)
    (tmp_path / 'listing').write_text(listing + ('\n' if listing else ''))
    for name, body in (('pg_lsclusters', f'cat {tmp_path}/listing'), ('dpkg', 'exit 0')):
        p = bindir / name
        p.write_text(f'#!/bin/bash\n{body}\n')
        p.chmod(0o755)
    prog = (f'STATUS={tmp_path}/status\nTS() {{ echo T; }}\n'
            'fail() { echo "failed:$1" > "$STATUS"; echo "FATAL $1 — $2"; exit 1; }\n'
            'PG_EXPECT=18\nPG_NEXT="NEXT-STEPS"\n' + frag + 'echo PASSED\n')
    return subprocess.run(['bash', '-c', prog], capture_output=True, text=True,
                          env={'PATH': f'{bindir}:/usr/bin:/bin'})


def test_the_field_layout_now_passes_and_says_what_it_kept(tmp_path):
    r = _run_check(tmp_path, FIELD)
    assert r.returncode == 0 and 'PASSED' in r.stdout, r.stdout + r.stderr
    assert 'kept as it is: stopped PostgreSQL 15/main on 5434' in r.stdout
    assert 'Guard Dog' in r.stdout


@pytest.mark.parametrize('label,clusters,safe', LAYOUTS, ids=[l[0] for l in LAYOUTS])
def test_bash_and_python_agree(tmp_path, label, clusters, safe):
    r = _run_check(tmp_path, '\n'.join(_line(*c) for c in clusters))
    assert (r.returncode == 0) is safe, r.stdout + r.stderr
    if not safe:
        assert (tmp_path / 'status').read_text().strip() == 'failed:reassert'
        assert 'NEXT-STEPS' in r.stdout          # every refusal says how to finish by hand
    ok, detail = _ns()['_os_upgrade_pg_layout'](clusters, '18')
    assert ok is safe, detail


def test_python_detail_tells_the_operator_what_to_do():
    lay = _ns()['_os_upgrade_pg_layout']
    ok, d = lay([('15', 'main', '5434', 'online'), ('18', 'main', '5432', 'online')], '18')
    assert not ok and 'sudo pg_ctlcluster 15 main stop' in d and '/etc/postgresql/15/main/start.conf' in d
    ok, d = lay([('15', 'main', '5434', 'down'), ('18', 'main', '5432', 'online')], '18')
    assert ok and 'Guard Dog' in d and '15/main:5434 down' in d


def test_core_failure_text_names_the_exact_finish_commands():
    sc = _ns()['_os_upgrade_script']('/opt/infratak', 'takwerx', 5001, pg_expect='18')
    s = sc[sc.index('step reassert'):sc.index('step restart-console')]
    assert s.index('PG_NEXT=') < s.index('pg_lsclusters --no-header')
    for want in ('console was NOT restarted and the box was NOT rebooted',
                 'sudo rm -f /etc/apt/apt.conf.d/99infratak-os-upgrade /etc/update-manager/release-upgrades.d/infratak.cfg',
                 'sudo systemctl restart takwerx-broker', 'sudo systemctl restart takwerx-console',
                 'echo rebooting | sudo tee $STATUS', 'sudo reboot'):
        assert want in s, want
    # "rebooting" is exactly what the console's after-boot check looks for
    assert "raw not in ('rebooting', 'running:reboot', 'verifying')" in dbs.APP


def test_dbserver_failure_text_names_its_own_finish():
    sc = dbs._ns()['_os_upgrade_dbserver_script']()
    s = sc[sc.index('step reassert'):sc.index('step reboot')]
    assert s.index('PG_NEXT=') < s.index('pg_lsclusters --no-header')
    assert 'NOT rebooted' in s and '$PRE/pg' in s and 'takwerx-console' not in s
    assert subprocess.run(['bash', '-n'], input=sc, capture_output=True, text=True).returncode == 0


def test_no_old_exactly_one_rule_is_left():
    assert 'expected exactly one PostgreSQL cluster' not in dbs.APP
    assert '[ "$N" -eq 1 ] || fail reassert' not in dbs.APP


# --- preflights: refuse before the flip what reassert would refuse after it -------------
def test_core_preflight_accepts_the_field_box():
    pf = Box(clusters=(('15', 'main', '5434', 'down'), ('18', 'main', '5432', 'online'))).run()
    c = _check(pf, 'takserver_58')
    assert c['pass'] and pf['baseline']['pg_expect'] == '18'
    assert 'Guard Dog' in c['detail']


def test_core_preflight_refuses_a_running_leftover_before_anything_changes():
    pf = Box(clusters=(('15', 'main', '5434', 'online'), ('18', 'main', '5432', 'online'))).run()
    c = _check(pf, 'takserver_58')
    assert not c['pass'] and not pf['ok'] and pf['baseline']['pg_expect'] == ''
    assert 'pg_ctlcluster 15 main stop' in c['detail']
    # 18 present but stopped used to pass ("any 18") and fail after the flip
    assert not _check(Box(clusters=(('18', 'main', '5432', 'down'),)).run(), 'takserver_58')['pass']


def test_dbserver_preflight_accepts_the_leftover_and_refuses_a_running_one():
    ok = dbs._ns()['_dbserver_preflight'](probe=dbs._probe(
        clusters=[['15', 'main', '5434', 'down'], ['18', 'main', '5432', 'online']]))
    assert dbs._checks(ok)['is_tak_db']['pass'], dbs._checks(ok)['is_tak_db']
    bad = dbs._ns()['_dbserver_preflight'](probe=dbs._probe(
        clusters=[['15', 'main', '5434', 'online'], ['18', 'main', '5432', 'online']]))
    c = dbs._checks(bad)['is_tak_db']
    assert not c['pass'] and '5.8 update first' not in c['detail']
