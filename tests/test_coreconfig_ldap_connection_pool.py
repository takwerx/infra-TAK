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
"""TAK Server reuses bound LDAP connections (ops #64).

test12, 2026-10-16: TAK bound to LDAP as adm_ldapservice for every API call (~200 binds/min
under a Node-RED feed). When the outpost's cached session expired, every bind in flight ran
its own ldap-authentication-flow until the first one finished (73 s); ~200 flows piled up and
Guard Dog restarted Authentik for the herd. With <ldap enableConnectionPool="true"> binds fell
to ~0/min. These tests pin the attribute on both LDAP writers and the startup heal that adds
it to boxes already wired to LDAP.
"""

import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

LDAP = ('<ldap url="ldap://127.0.0.1:389" userstring="cn={username},ou=users,dc=takldap" '
        'updateinterval="30000" groupprefix="cn=tak_" serviceAccountDN="cn=adm_ldapservice,'
        'ou=users,dc=takldap" serviceAccountCredential="pw" adminGroup="ROLE_ADMIN"/>')
CORE = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Configuration xmlns="http://bbn.com/marti/xml/config">\n'
        '    <auth default="ldap" x509groups="true">\n        %s\n    </auth>\n'
        '    <submission ignoreStaleMessages="false" validateXml="false"/>\n'
        '</Configuration>\n')


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, name
    return m.group(0)


def _heal(content, exists=True, read_error=None):
    writes, logs = [], []

    def read(path):
        assert path == '/opt/tak/CoreConfig.xml'
        if read_error:
            raise read_error
        return content

    fake_os = types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: exists))
    ns = {'os': fake_os, 're': re, 'CORECONFIG_PATH': '/opt/tak/CoreConfig.xml',
          '_read_coreconfig': read, '_write_priv': lambda p, c: writes.append((p, c))}
    exec(compile(_fn('_heal_coreconfig_ldap_connection_pool'), 'app.py', 'exec'), ns)
    out = ns['_heal_coreconfig_ldap_connection_pool'](logs.append)
    return out, writes, logs


def test_heal_adds_the_pool_and_changes_nothing_else():
    before = CORE % LDAP
    out, writes, logs = _heal(before)
    assert out is True and len(writes) == 1
    path, after = writes[0]
    assert path == '/opt/tak/CoreConfig.xml'
    assert after == before.replace('adminGroup="ROLE_ADMIN"/>',
                                   'adminGroup="ROLE_ADMIN" enableConnectionPool="true"/>')
    assert 'NEXT restart; nothing was restarted' in logs[0]


def test_heal_is_idempotent():
    _, writes, _ = _heal(CORE % LDAP)
    out, again, logs = _heal(writes[0][1])
    assert out is False and again == [] and logs == []


def test_heal_leaves_an_explicit_value_alone():
    for val in ('false', 'true', 'FALSE'):
        cc = CORE % LDAP.replace('/>', ' enableConnectionPool="%s"/>' % val)
        out, writes, _ = _heal(cc)
        assert out is False and writes == [], val


def test_heal_handles_an_open_tag_and_a_namespace_prefix():
    cc = CORE % LDAP.replace('/>', '></ldap>').replace('<ldap ', '<ns0:ldap ').replace('</ldap>', '</ns0:ldap>')
    out, writes, _ = _heal(cc)
    assert out is True
    assert 'adminGroup="ROLE_ADMIN" enableConnectionPool="true"></ns0:ldap>' in writes[0][1]


def test_heal_does_not_touch_other_tags_or_a_box_without_ldap():
    cc = CORE % '<ldapish foo="1"/>'
    cc = cc.replace('<auth default="ldap" x509groups="true">', '<auth default="file">')
    out, writes, _ = _heal(cc)
    assert out is False and writes == []
    out, writes, _ = _heal(CORE % LDAP, exists=False)
    assert out is False and writes == []


def test_unreadable_coreconfig_never_blocks_boot():
    out, writes, logs = _heal('', read_error=PermissionError('640 tak:tak'))
    assert out is False and writes == []
    assert 'skipped, will retry next boot' in logs[0]


def test_both_ldap_writers_set_the_pool():
    assert "'enableConnectionPool': 'true'" in _fn('_apply_coreconfig_ldap_auth_et')
    assert 'adminGroup="ROLE_ADMIN" enableConnectionPool="true"/>' in _fn('_apply_coreconfig_ldap_auth_text')


def test_heal_runs_at_startup_and_never_restarts_tak():
    assert APP.count('_heal_coreconfig_ldap_connection_pool(') == 2   # def + startup call
    body = _fn('_heal_coreconfig_ldap_connection_pool')
    assert 'systemctl' not in body and 'restart takserver' not in body
    start = APP.index('_heal_coreconfig_updateinterval_ms(\n')
    assert APP.index('_heal_coreconfig_ldap_connection_pool(\n') > start
