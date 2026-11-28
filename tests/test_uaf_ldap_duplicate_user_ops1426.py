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
"""A TAK user in the flat file AND in LDAP with different groups (ops #1426).

Found with CloudTAK 14.4.2 (ops #1410): with default="ldap" and x509useGroupCache="true" every certificate
login of such a user sets the cached groups twice (flat file, then LDAP), TAK Server sends `t-x-g-c` each
time, and CloudTAK answers each one with a groups call (a new login). The CloudTAK API then logs 30 to 300
"refreshed channels" lines a second and runs hot while a browser session is open. Same groups in both
places, or the user in one place only: 0 lines a second (fresh install, Ubuntu 22.04).

The console checks every 5 minutes. A flat-file `webadmin` whose LDAP twin is ROLE_ADMIN is removed
through TAK's own user-management call (no restart); any other name is only reported (it is the
operator's); nothing is removed when LDAP lacks the user or when LDAP's `webadmin` is not ROLE_ADMIN.
Same fake box idea as test_groupless_client_ops1039: the file, LDAP, the Marti API and the mail are stubs.
"""

import os
import re
import urllib.parse

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(REPO, 'app.py'), encoding='utf-8') as _f:
    APP = _f.read()

NS = 'http://bbn.com/marti/xml/bindings'
T0 = 1_800_000_000.0


def _src(name):
    m = re.search(r'^def %s\(.*?(?=^def |^# |^_[A-Z_]+ = |\Z)' % name, APP, re.S | re.M)
    assert m, f'{name} is not in app.py'
    return m.group(0)


def _const(name):
    return eval(re.search(r'^%s = (.+)$' % name, APP, re.M).group(1))


def uaf(*users):
    """users: (identifier, role, [groups]) -> the XML text TAK keeps."""
    out = [f'<?xml version="1.0"?><UserAuthenticationFile xmlns="{NS}">']
    for ident, role, groups in users:
        out.append(f'<User identifier="{ident}" passwordHash="x" role="{role}">')
        out += [f'<groupList>{g}</groupList>' for g in groups]
        out.append('</User>')
    out.append('</UserAuthenticationFile>')
    return ''.join(out)


class Box:
    """One TAK box: the flat file, what LDAP holds, the TAK delete call and the mail."""

    def __init__(self, file_users, ldap, delete_works=True, ldap_up=True, split=False, update_running=False,
                 mail_to='ops@example.org'):
        self.file = list(file_users)
        self.ldap = ldap                  # {cn: [groups]}
        self.delete_works = delete_works
        self.ldap_up = ldap_up
        self.split = split
        self.update_running = update_running
        self.settings = {'guarddog_alert_email': mail_to} if mail_to else {}
        self.deleted = []
        self.mails = []
        self.log = []
        self.now = T0

    def text(self):
        return uaf(*self.file)

    def ns(self):
        box = self

        def _tak_admin_marti_req(url, timeout=12, method='GET', json_body=None):
            m = re.match(r'https://127\.0\.0\.1:8443/user-management/api/delete-user/(.+)$', url)
            assert method == 'DELETE' and m, (method, url)
            if not box.delete_works:
                return None, 'HTTP 404'
            name = urllib.parse.unquote(m.group(1))
            box.deleted.append(name)
            box.file = [u for u in box.file if u[0] != name]
            return True, None

        def _ldap_users_tak_groups(ldap_pass, cns=None):
            if not box.ldap_up:
                return None
            want = {c.lower() for c in (cns or [])}
            return {cn: list(g) for cn, g in box.ldap.items() if not want or cn.lower() in want}

        def _save(s):
            box.settings.clear()
            box.settings.update(s)

        ns = {
            'os': os, 'time': type('T', (), {'time': staticmethod(lambda: box.now)}), 'urllib': urllib,
            'load_settings': lambda: dict(box.settings),
            'save_settings': _save,
            '_get_tak_deployment_config': lambda s: {'mode': 'two_server' if box.split else 'single'},
            '_coreconfig_has_ldap': lambda: True,
            '_read_priv': lambda p: box.text(),
            '_get_authentik_env_value': lambda s, k: 'ldap-pass',
            '_ensure_ldapsearch': lambda: True,
            '_ldap_users_tak_groups': _ldap_users_tak_groups,
            '_tak_admin_marti_req': _tak_admin_marti_req,
            '_console_update_in_progress': lambda: box.update_running,
            '_guarddog_server_identifier': lambda s: 'box-1',
            '_guarddog_send_alert_email_via_relay': lambda to, subj, body, force=False: box.mails.append((to, subj, body)) or True,
            'socket': type('S', (), {'gethostname': staticmethod(lambda: 'host')}),
        }
        ns['os'] = type('O', (), {'path': type('P', (), {'exists': staticmethod(lambda p: True)})})
        for c in ('_TAK_UAF_CONFLICT_TICK_S', '_TAK_UAF_CONFLICT_REMIND_S', '_TAK_UAF_CONFLICT_REMOVED_MAIL_GAP_S'):
            ns[c] = _const(c)
        ns['_tak_uaf_conflict_last'] = {'at': 0.0}
        for fn in ('_tak_uaf_file_users', '_tak_uaf_ldap_conflicts', '_tak_remove_flatfile_user',
                   '_tak_uaf_conflict_alert', '_tak_uaf_conflict_check'):
            exec(_src(fn), ns)
        return ns

    def check(self, ns, advance=0):
        self.now += advance
        return ns['_tak_uaf_conflict_check'](self.log.append)


# The box of the report: webadmin is local (ZZ-Test) and in LDAP (tak_ROLE_ADMIN), the CloudTAK service users are local only.
def storm_box(**kw):
    return Box([('admin', 'ROLE_ADMIN', ['__ANON__']), ('webadmin', 'ROLE_ADMIN', ['ZZ-Test'])],
               {'webadmin': ['ROLE_ADMIN'], 'alice': ['Fire']}, **kw)


def test_webadmin_with_other_groups_is_removed_without_a_restart():
    box = storm_box()
    out = box.check(box.ns())
    assert box.deleted == ['webadmin']
    assert [u[0] for u in box.file] == ['admin']              # the admin cert user stays
    assert out['removed'] == ['webadmin']


def test_removal_is_reported_in_plain_words_once():
    box = storm_box()
    ns = box.ns()
    box.check(ns)
    assert len(box.mails) == 1
    to, subj, body = box.mails[0]
    assert to == 'ops@example.org' and 'fixed' in subj and "'webadmin'" in body
    assert 'You do not need to do anything' in body
    box.check(ns, advance=600)          # next check: the file is clean now, no second mail
    assert len(box.mails) == 1


def test_a_user_with_another_name_is_reported_and_never_removed():
    box = Box([('admin', 'ROLE_ADMIN', ['__ANON__']), ('bob', 'ROLE_USER', ['Local'])],
              {'bob': ['Fire'], 'webadmin': ['ROLE_ADMIN']})
    out = box.check(box.ns())
    assert box.deleted == [] and [u[0] for u in box.file] == ['admin', 'bob']
    assert [c['name'] for c in out['conflicts']] == ['bob'] and out['removed'] == []
    assert len(box.mails) == 1 and "'bob'" in box.mails[0][2] and 'does not change this user' in box.mails[0][2]
    assert any("user 'bob'" in m and 'Not changed' in m for m in box.log)


def test_the_same_duplicate_gets_one_mail_then_a_reminder_after_a_week():
    box = Box([('bob', 'ROLE_USER', ['Local'])], {'bob': ['Fire']})
    ns = box.ns()
    box.check(ns)
    box.check(ns, advance=3600)
    box.check(ns, advance=86400)
    assert len(box.mails) == 1
    box.check(ns, advance=7 * 86400)
    assert len(box.mails) == 2
    box.ldap['bob'] = ['Fire', 'EMS']           # a different duplicate is news again
    box.check(ns, advance=600)
    assert len(box.mails) == 3


def test_same_groups_in_both_places_is_left_alone():
    box = Box([('webadmin', 'ROLE_ADMIN', ['ROLE_ADMIN'])], {'webadmin': ['ROLE_ADMIN']})
    out = box.check(box.ns())
    assert out == {'conflicts': [], 'removed': []}
    assert box.deleted == [] and box.mails == []


def test_a_user_that_is_only_local_is_left_alone():
    box = Box([('admin', 'ROLE_ADMIN', ['__ANON__']), ('cloudtak-svc-bootstrap', 'ROLE_ADMIN', ['A', 'B'])],
              {'alice': ['Fire']})
    assert box.check(box.ns())['conflicts'] == []
    assert box.deleted == [] and box.mails == []


def test_webadmin_is_kept_when_ldap_does_not_have_it_as_admin():
    """Removing the local copy would take the admin login away."""
    box = Box([('webadmin', 'ROLE_ADMIN', ['ZZ-Test'])], {'webadmin': ['Fire']})
    out = box.check(box.ns())
    assert box.deleted == [] and [u[0] for u in box.file] == ['webadmin']
    assert out['removed'] == []
    assert any('NOT removing' in m for m in box.log)
    box2 = Box([('webadmin', 'ROLE_ADMIN', ['ZZ-Test'])], {'alice': ['Fire']})      # LDAP has no webadmin at all
    assert box2.check(box2.ns())['conflicts'] == [] and box2.deleted == []


def test_when_tak_will_not_delete_it_the_user_is_kept_and_reported():
    box = storm_box(delete_works=False)
    out = box.check(box.ns())
    assert [u[0] for u in box.file] == ['admin', 'webadmin'] and out['removed'] == []
    assert any('did not remove it' in m for m in box.log)
    assert len(box.mails) == 1 and 'does not change this user' in box.mails[0][2]


def test_group_names_compare_by_name_ignoring_case_of_the_user_and_the_direction_lists():
    text = (f'<UserAuthenticationFile xmlns="{NS}"><User identifier="WebAdmin" role="ROLE_ADMIN">'
            '<groupListIN>A</groupListIN><groupListOUT>B</groupListOUT><groupList>C</groupList></User>'
            '<User fingerprint="abc" role="ROLE_ADMIN"><groupList>X</groupList></User></UserAuthenticationFile>')
    users = Box([], {}).ns()['_tak_uaf_file_users'](text)
    assert users == {'webadmin': ('WebAdmin', 'ROLE_ADMIN', {'A', 'B', 'C'})}       # a certificate-only entry has no name
    assert Box([], {}).ns()['_tak_uaf_file_users']('not xml') is None


def test_nothing_happens_when_it_cannot_be_told():
    for kw in ({'ldap_up': False}, {'split': True}, {'update_running': True}):
        box = storm_box(**kw)
        assert box.check(box.ns()) is None
        assert box.deleted == [] and box.mails == []


def test_it_runs_at_most_every_five_minutes():
    box = storm_box()
    ns = box.ns()
    assert box.check(ns) is not None
    box.file.append(('webadmin', 'ROLE_ADMIN', ['ZZ-Test']))        # it comes back (a TAK redeploy)
    assert box.check(ns, advance=60) is None and box.deleted == ['webadmin']
    assert box.check(ns, advance=300) is not None and box.deleted == ['webadmin', 'webadmin']


def test_a_cleared_duplicate_forgets_its_mail_state():
    box = Box([('bob', 'ROLE_USER', ['Local'])], {'bob': ['Fire']})
    ns = box.ns()
    box.check(ns)
    assert box.settings.get('tak_uaf_conflict')
    box.file = []
    box.check(ns, advance=600)
    assert 'tak_uaf_conflict' not in box.settings


def test_no_mail_when_no_recipient_is_set_but_the_fix_still_happens():
    box = storm_box(mail_to='')
    box.check(box.ns())
    assert box.deleted == ['webadmin'] and box.mails == []
    assert any('SUPPRESSED' in m for m in box.log)


def test_the_monitor_loop_runs_the_check():
    loop = _src('_tak_stuck_mass_loop')
    assert '_tak_uaf_conflict_check(log)' in loop
    assert 'duplicate-user check error (non-fatal)' in loop
