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
"""Diagnostics show TAK Portal's side of every Authentik write (ops #71).

Field report: every TAK Portal group change failed "Authentik operation failed and remains
queued for retry; check sync status." That message hides the real Authentik error, which only
lives in TAK Portal's own `authentik_outbox.last_error`. The diagnostics report showed TAK_URL
but not the Authentik URL, the token state or the outbox, so a separate command had to be sent
to the customer. These tests pin what the report now prints — and that the token never is.
"""

import ast
import hmac
import pathlib
import re
import urllib.parse

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

TOKEN = 'a' * 30 + 'SECRETTOKENVALUE' + 'b' * 18     # 64 chars
TEMPLATE_TOKEN = 'your-real-token-here'


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _consts(*names):
    return '\n'.join(ast.get_source_segment(APP, n) for n in TREE.body
                     if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in names for t in n.targets))


def _ns(env_token=TOKEN, psql=None, containers=None):
    """The two functions under test, with docker/psql and the Authentik .env stubbed."""
    calls = []

    def diag_cmd(argv, timeout=20, priv=True, stdin=None):
        calls.append(list(argv))
        sql = argv[-1]
        return (psql or {}).get(next((k for k in (psql or {}) if k in sql), None), '')

    ns = {
        'hmac': hmac, 're': re, 'urllib': urllib,
        '_diag_cmd': diag_cmd,
        '_takportal_project_containers': lambda: containers if containers is not None else [
            {'name': 'tak-portal', 'service': 'tak-portal'},
            {'name': 'tak-portal-worker', 'service': 'tak-portal-worker'},
            {'name': 'tak-portal-postgres', 'service': 'postgres'}],
        '_get_authentik_env_value': lambda s, k: env_token if k == 'AUTHENTIK_BOOTSTRAP_TOKEN' else '',
    }
    exec(compile(_consts('TAKPORTAL_TEMPLATE_PLACEHOLDERS'), 'app.py', 'exec'), ns)
    exec(compile(_func('_diag_takportal_token_state') + '\n\n' + _func('_diag_takportal_authentik'),
                 'app.py', 'exec'), ns)
    ns['calls'] = calls
    return ns


HEALTHY_PSQL = {'count(*)': '0\n', 'directory_sync': '\n'}


def _run(existing, **kw):
    ns = _ns(**kw)
    return ns, '\n'.join(ns['_diag_takportal_authentik']({}, existing))


def test_healthy_box_reads_clean_and_never_prints_the_token():
    ns, out = _run({'AUTHENTIK_URL': 'http://authentik-server-1:9000', 'AUTHENTIK_TOKEN': TOKEN},
                   psql=HEALTHY_PSQL)
    assert 'AUTHENTIK_URL=http://authentik-server-1:9000' in out
    assert "AUTHENTIK_TOKEN=set (64 chars, same as infra-TAK's Authentik token)" in out
    assert 'authentik_outbox: 0 queued row(s)' in out
    assert 'directory_sync last_error: (none)' in out
    assert 'SECRETTOKENVALUE' not in out


def test_template_reset_is_named_as_such():
    _, out = _run({'AUTHENTIK_URL': 'http://your-authentik-url:9000', 'AUTHENTIK_TOKEN': TEMPLATE_TOKEN},
                  psql=HEALTHY_PSQL)
    assert 'AUTHENTIK_URL=http://your-authentik-url:9000  <-- TAK Portal template placeholder' in out
    assert 'AUTHENTIK_TOKEN=TEMPLATE PLACEHOLDER' in out
    assert TEMPLATE_TOKEN not in out


def test_blank_and_stale_tokens():
    st = _ns()['_diag_takportal_token_state']
    assert st('', TOKEN) == 'BLANK' and st(None, TOKEN) == 'BLANK' and st('   ', TOKEN) == 'BLANK'
    other = 'z' * 40
    assert st(other, TOKEN) == "set (40 chars, DIFFERENT from infra-TAK's Authentik token)"
    assert st(TOKEN, '') == "set (64 chars, infra-TAK's Authentik .env has no token to compare)"
    assert other not in st(other, TOKEN)


def test_url_is_reduced_to_scheme_host_port():
    """A URL can carry credentials or a path; the report needs only where Portal is calling."""
    _, out = _run({'AUTHENTIK_URL': 'https://user:pw@tak.example.org:9443/api/v3/?x=1'}, psql=HEALTHY_PSQL)
    assert 'AUTHENTIK_URL=https://tak.example.org:9443 ' in out
    assert 'user' not in out.split('AUTHENTIK_URL=')[1].split()[0] and 'pw@' not in out
    _, out = _run({}, psql=HEALTHY_PSQL)
    assert 'AUTHENTIK_URL=(unset)' in out and 'AUTHENTIK_TOKEN=BLANK' in out


def test_outbox_rows_show_kind_attempts_and_the_real_error():
    psql = {
        'count(*)': '2\n',
        'ORDER BY id DESC': ('42|set_groups|7|2026-10-17 23:41|Request failed with status code 400 | body x\n'
                             '41|create_group|1|2026-10-17 23:40|\n'),
        'directory_sync': 'Authentik could not apply set_groups for jdoe: Request failed with status code 404\n',
    }
    _, out = _run({'AUTHENTIK_URL': 'http://authentik-server-1:9000', 'AUTHENTIK_TOKEN': TOKEN}, psql=psql)
    assert 'authentik_outbox: 2 queued row(s)' in out
    assert ('  id=42 set_groups attempts=7 queued 2026-10-17 23:41 UTC  '
            'last_error: Request failed with status code 400 | body x') in out
    assert '  id=41 create_group attempts=1 queued 2026-10-17 23:40 UTC  last_error: (none yet)' in out
    assert 'directory_sync last_error: Authentik could not apply set_groups for jdoe' in out


def test_db_unreachable_says_so_instead_of_failing_the_section():
    _, out = _run({}, psql={'count(*)': 'Error response from daemon: No such container: tak-portal-postgres'})
    assert 'authentik_outbox: could not read (Error response from daemon' in out


def test_queries_target_the_portal_db_container_and_are_read_only():
    ns, _ = _run({}, psql=HEALTHY_PSQL, containers=[{'name': 'myproj-postgres-1', 'service': 'postgres'}])
    assert ns['calls'], 'no query ran'
    for argv in ns['calls']:
        assert argv[:3] == ['docker', 'exec', 'myproj-postgres-1']
        assert argv[3:8] == ['psql', '-U', 'takportal', '-d', 'takportal']
        assert argv[-1].lstrip().upper().startswith('SELECT ')
    ns, _ = _run({}, psql=HEALTHY_PSQL, containers=[])
    assert ns['calls'][0][2] == 'tak-portal-postgres'


def test_wired_into_the_takportal_section():
    assert '_diag_takportal_authentik(settings, existing)' in _func('_diag_section_takportal')
