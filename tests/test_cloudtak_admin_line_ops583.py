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
"""The CloudTAK page says who CloudTAK's admin user is (ops #583).

The first-time setup asks for a TAK user who becomes CloudTAK's first system admin, and the name
was shown once, in the success message, then never again. The page now reads the admins from
CloudTAK's own profile table (`system_admin`), so boxes set up before this change show them too.
"""

import ast
import pathlib
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (REPO / 'templates' / 'cloudtak.html').read_text(encoding='utf-8')
JS = APP[APP.index("CLOUDTAK_PAGE_JS = r'''"):]


def _ns(srv, admins, local=True):
    """The real state functions, with CloudTAK's API and database faked."""
    sql_seen = []

    def postgis(sql):
        sql_seen.append(sql)
        return admins if 'system_admin' in sql else []
    ns = {'_cloudtak_local_with_local_tak': lambda s: local, '_cloudtak_signing_secret': lambda: 's',
          '_cloudtak_admin_token': lambda s: 'jwt',
          '_cloudtak_request_json': lambda *a, **k: (srv is not None, 200, srv),
          '_cloudtak_postgis_json': postgis, '_tak_live_trust_bundle': lambda: '',
          '_tak_ca_bundle': lambda: '', '_cert_signed_by': lambda c, b: None}
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name in (
                '_cloudtak_untrusted_user_certs', '_cloudtak_admin_users', '_cloudtak_admin_candidates',
                '_cloudtak_connect_state_core', '_cloudtak_connect_state'):
            exec(ast.get_source_segment(APP, n), ns)
    ns['sql_seen'] = sql_seen
    return ns


def test_a_connected_cloudtak_names_its_admin():
    ns = _ns({'status': 'configured', 'connection_status': 'live'}, ['cloudtakadmin-acme'])
    st = ns['_cloudtak_connect_state']({})
    assert st['status'] == 'connected' and st['admins'] == ['cloudtakadmin-acme']


def test_every_configured_state_names_the_admins_in_creation_order():
    for srv in ({'status': 'configured', 'connection_status': 'dead'},
                {'status': 'configured', 'connection_status': 'live'}):
        st = _ns(srv, ['first', 'second'])['_cloudtak_connect_state']({})
        assert st['admins'] == ['first', 'second']
    ns = _ns({'status': 'configured', 'connection_status': 'live'}, ['a'])
    ns['_cloudtak_connect_state']({})
    assert any('order by created, username' in q for q in ns['sql_seen'])


def test_nothing_is_shown_before_setup_on_a_remote_cloudtak_or_when_the_api_is_down():
    # An unconfigured CloudTAK only has a half-finished attempt's leftover rows: not "the admin".
    for srv, local in (({'status': 'unconfigured'}, True), ({'status': 'configured'}, False), (None, True)):
        ns = _ns(srv, ['leftover'], local=local)
        st = ns['_cloudtak_connect_state']({})
        assert 'admins' not in st, (srv, local, st)
        assert not any('system_admin' in q for q in ns['sql_seen'])


def test_an_unreadable_table_adds_no_admin_line_instead_of_a_wrong_one():
    ns = _ns({'status': 'configured', 'connection_status': 'live'}, None)
    st = ns['_cloudtak_connect_state']({})
    assert st['status'] == 'connected' and 'admins' not in st


def test_only_clean_usernames_come_back():
    ns = _ns({'status': 'configured'}, ['ok', '', None, 7, {'x': 1}, 'also-ok'])
    assert ns['_cloudtak_admin_users']() == ['ok', 'also-ok']


def test_the_query_reads_admins_only_and_never_credentials():
    ns = _ns({'status': 'configured'}, [])
    ns['_cloudtak_admin_users']()
    sql = ns['sql_seen'][0]
    assert 'where system_admin' in sql and 'select coalesce(json_agg(username' in sql
    assert 'auth' not in sql and 'password' not in sql.lower() and 'cert' not in sql
    # An older CloudTAK without the `disabled` column must still answer.
    assert "to_jsonb(profile)->>'disabled'" in sql


def test_the_page_has_the_line_and_escapes_the_names():
    assert 'id="ct-connect-admins"' in TEMPLATE
    assert TEMPLATE.index('id="ct-connect-admins"') > TEMPLATE.index('id="ct-connect-state"')
    assert "document.getElementById('ct-connect-admins')" in JS
    assert 'admins.map(esc).join' in JS and 'CloudTAK admin' in JS
    # Hidden again when there are none (unconfigured, remote, unreadable).
    assert "adm.style.display = (admins.length || d.no_admin) ? '' : 'none'" in JS
