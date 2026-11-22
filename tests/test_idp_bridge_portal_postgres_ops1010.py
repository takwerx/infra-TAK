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
"""Identity Bridge said "TAK Portal is not reachable" while the portal ran (ops #1010).

Field (nuc): the Authentik page banner said "Full stack healthy", and the Identity Bridge
section right under it said "TAK Portal is not reachable ... Install/start TAK Portal first."

Verified on nuc (Fri Nov 20, 2026): the current TAK Portal keeps agencies and agency
templates in its Postgres (tables `agencies`, `agency_templates`). On first boot it imports
the old JSON files and renames them into /usr/src/app/data/migrated/, so
`docker exec tak-portal cat /usr/src/app/data/agencies.json` fails ("No such file"). The
console read only those two files, so every current portal looked unreachable.

app.py cannot be imported in a test, so the functions are cut out of it and run: the code
under test is the shipped text. The fake `docker exec` behaves like nuc: the JSON files do
not exist, and the Postgres container answers the console's SELECTs.
"""

import ast
import json
import pathlib
import subprocess
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(APP)

_FUNCS = {'_idp_bridge_portal_file', '_idp_bridge_portal_db', '_idp_bridge_portal_lists',
          'idp_bridge_status_api', '_idp_agency_token'}
_CONSTS = {'_IDP_PORTAL_AGENCIES_SQL', '_IDP_PORTAL_TEMPLATES_SQL', 'IDP_USERNAME_ALLOWED_RE',
           'IDP_USERNAME_FIELDS', 'IDP_USERNAME_FIELD_DEFAULT'}

AGENCIES = [
    {'suffix': '123', 'name': 'ACME PD', 'type': 'Law Enforcement', 'groupPrefix': 'AC-1',
     'color': 'Blue', 'usernameTokenPlacement': 'suffix', 'isActive': True},
    {'suffix': 'fd9', 'name': 'Ninth Fire', 'type': 'Fire', 'groupPrefix': 'FIRE1',
     'color': 'Red', 'usernameTokenPlacement': 'prefix', 'isActive': True},
]
TEMPLATES = [
    {'name': 'Patrol', 'agencySuffix': '123', 'role': 'Team Member',
     'groups': ['tak_AC-1 Main', 'tak_AC-1 OPS'], 'isDefault': True},
]


def _source():
    parts = []
    for n in _TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name in _FUNCS:
            n.decorator_list = []
            parts.append(ast.unparse(n))
        elif isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in _CONSTS for t in n.targets):
            parts.append(ast.unparse(n))
    return '\n\n'.join(parts)


class FakePortalBox:
    """What `docker ps` and `docker exec` show on a TAK Portal box."""

    def __init__(self, postgres=True, db_rows=(AGENCIES, TEMPLATES), json_files=None,
                 psql_rc=0, psql_timeout=False, psql_out=None):
        self.postgres = postgres
        self.db_rows = db_rows
        self.json_files = json_files or {}
        self.psql_rc = psql_rc
        self.psql_timeout = psql_timeout
        self.psql_out = psql_out
        self.calls = []

    def containers(self, all_states=True):
        out = [{'id': 'ab418a9b664d', 'name': 'tak-portal', 'service': 'tak-portal',
                'status': 'Up 4 days', 'running': True}]
        if self.postgres:
            out.append({'id': '91f4e5f9b4b8', 'name': 'tak-portal-postgres',
                        'service': 'postgres', 'status': 'Up 5 days (healthy)', 'running': True})
        return out

    def run(self, argv, **kw):
        self.calls.append(list(argv))
        assert argv[:2] == ['docker', 'exec'], argv
        target = argv[2]
        if argv[3] == 'cat':
            path = argv[4]
            if target == 'ab418a9b664d' and path in self.json_files:
                return types.SimpleNamespace(returncode=0, stdout=self.json_files[path], stderr='')
            return types.SimpleNamespace(
                returncode=1, stdout='', stderr=f"cat: can't open '{path}': No such file or directory")
        assert target == 'tak-portal-postgres' and argv[3] == 'psql', argv
        if self.psql_timeout:
            raise subprocess.TimeoutExpired(argv, 15)
        if self.psql_rc:
            return types.SimpleNamespace(returncode=self.psql_rc, stdout='', stderr='psql: error')
        sql = argv[argv.index('-c') + 1]
        if self.psql_out is not None:
            return types.SimpleNamespace(returncode=0, stdout=self.psql_out, stderr='')
        if 'FROM agency_templates' in sql:
            rows = self.db_rows[1]
        else:
            assert 'FROM agencies' in sql, sql
            rows = self.db_rows[0]
        return types.SimpleNamespace(returncode=0, stdout=json.dumps(rows) + '\n', stderr='')


def _load(box):
    import re
    sub = types.SimpleNamespace(run=box.run, TimeoutExpired=subprocess.TimeoutExpired)
    ns = {'json': json, 're': re, 'subprocess': sub,
          '_sudo_wrap': lambda cmd: list(cmd),
          '_takportal_project_containers': box.containers,
          '_takportal_ref': lambda all_states=True: 'ab418a9b664d',
          '_idp_bridges_load': lambda: {'bridges': {}},
          '_idp_username_field': lambda b: 'employeeNumber',
          '_idp_username_preview': lambda a, b=None: '',
          '_idp_token_ambiguity': lambda a, al: [],
          'jsonify': lambda d: d}
    exec(compile(_source(), 'app.py', 'exec'), ns)
    return ns


def test_current_portal_without_json_files_is_reachable():
    """The nuc case: JSON files gone, data in Postgres. Must read the data, not say unreachable."""
    box = FakePortalBox()
    agencies, templates = _load(box)['_idp_bridge_portal_lists']()
    assert [a['suffix'] for a in agencies] == ['123', 'fd9']
    assert agencies[0]['groupPrefix'] == 'AC-1' and agencies[1]['usernameTokenPlacement'] == 'prefix'
    assert templates[0]['agencySuffix'] == '123' and templates[0]['groups'] == ['tak_AC-1 Main', 'tak_AC-1 OPS']


def test_status_api_portal_ok_and_lists_agencies_and_templates():
    out = _load(FakePortalBox())['idp_bridge_status_api']()
    assert out['portal_ok'] is True
    assert [a['suffix'] for a in out['agencies']] == ['123', 'fd9']
    assert [a['token'] for a in out['agencies']] == ['123', 'fd9']
    assert [a['placement'] for a in out['agencies']] == ['suffix', 'prefix']
    assert out['templates'] == [{'name': 'Patrol', 'agencySuffix': '123', 'role': 'Team Member', 'groups': 2}]


def test_empty_tables_are_a_true_empty_state_not_unreachable():
    """A healthy portal with no agencies or templates yet: portal_ok stays true, lists are empty."""
    out = _load(FakePortalBox(db_rows=([], [])))['idp_bridge_status_api']()
    assert out['portal_ok'] is True
    assert out['agencies'] == [] and out['templates'] == []


def test_old_portal_with_only_json_files_still_works():
    files = {'/usr/src/app/data/agencies.json': json.dumps(AGENCIES),
             '/usr/src/app/data/agency-templates.json': json.dumps(TEMPLATES)}
    box = FakePortalBox(postgres=False, json_files=files)
    agencies, templates = _load(box)['_idp_bridge_portal_lists']()
    assert [a['suffix'] for a in agencies] == ['123', 'fd9'] and len(templates) == 1


def test_postgres_without_the_tables_falls_back_to_json_files():
    """An older portal that has a Postgres container but has not migrated yet."""
    files = {'/usr/src/app/data/agencies.json': json.dumps(AGENCIES),
             '/usr/src/app/data/agency-templates.json': json.dumps(TEMPLATES)}
    box = FakePortalBox(psql_rc=1, json_files=files)
    agencies, templates = _load(box)['_idp_bridge_portal_lists']()
    assert len(agencies) == 2 and len(templates) == 1


def test_real_exec_failure_is_still_not_reachable():
    """Container exec fails or times out and no JSON files exist: that, and only that, is unreachable."""
    for box in (FakePortalBox(psql_rc=1), FakePortalBox(psql_timeout=True),
                FakePortalBox(psql_out='not json'), FakePortalBox(psql_out='{"a": 1}'),
                FakePortalBox(postgres=False)):
        assert _load(box)['_idp_bridge_portal_lists']() == (None, None)
        assert _load(box)['idp_bridge_status_api']()['portal_ok'] is False


def test_every_reader_goes_through_the_one_helper():
    """The reconcile loop, the status route and the create wizard must not read the JSON files
    themselves: they would again answer wrong on a current portal."""
    helper = next(n for n in _TREE.body
                  if isinstance(n, ast.FunctionDef) and n.name == '_idp_bridge_portal_lists')
    allowed = {id(c) for c in ast.walk(helper)}
    direct = [c.lineno for c in ast.walk(_TREE)
              if isinstance(c, ast.Call) and getattr(c.func, 'id', '') == '_idp_bridge_portal_file'
              and id(c) not in allowed]
    assert not direct, f'_idp_bridge_portal_file called outside _idp_bridge_portal_lists at lines {direct}'


def test_sql_selects_the_columns_the_consumers_read():
    """Keys the console reads from an agency / template must come out of the SELECT."""
    ns = _load(FakePortalBox())
    for key, col in (('suffix', 'suffix'), ('name', 'name'), ('groupPrefix', 'group_prefix'),
                     ('color', 'color'), ('usernameTokenPlacement', 'username_token_placement')):
        assert f"'{key}', {col}" in ns['_IDP_PORTAL_AGENCIES_SQL'], key
    for key, col in (('name', 'name'), ('agencySuffix', 'agency_suffix'), ('role', 'role'),
                     ('groups', 'groups')):
        assert f"'{key}', {col}" in ns['_IDP_PORTAL_TEMPLATES_SQL'], key
    assert ns['_IDP_PORTAL_AGENCIES_SQL'].lstrip().upper().startswith('SELECT')
    assert ns['_IDP_PORTAL_TEMPLATES_SQL'].lstrip().upper().startswith('SELECT')
