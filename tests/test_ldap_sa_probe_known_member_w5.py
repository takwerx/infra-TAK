# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""v10.4.3 W5: "is LDAP good?" asks for a known member, not "the first 500 users".

akres E3: with >500 users the -z 500 page held no tak_ member (sort order), so the probe said
"LDAP has no groups" and the TAK heal refused to run for 25 min while LDAP was fine. Now:
(cn=webadmin) first, then a server-side (memberOf=cn=tak_*) filter, then the old scan.
A failed bind is still a failure; a filter the outpost rejects is skipped, not taken for one.
"""
import re
import subprocess
import types

import pytest

from test_tak_ldap_recycle import APP

SA_PASS = 'sa-secret-do-not-log'


def _ns(answer):
    """answer(flt, size_limit) -> (rc, ldif)"""
    calls = []

    def run(cmd, **kw):
        assert cmd[0] == 'ldapsearch'
        calls.append(cmd)
        flt = [a for a in cmd if a.startswith('(')][0]
        rc, out = answer(flt, int(cmd[cmd.index('-z') + 1]))
        return subprocess.CompletedProcess(cmd, rc, stdout=out,
                                           stderr='' if rc in (0, 4) else f'ldap_search: error ({rc})\n')

    ns = {'subprocess': types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired)}
    src = re.search(r'^def _authentik_ldap_sa_search\(.*?(?=^def _authentik_ldap_sa_groups_settle\()',
                    APP, re.S | re.M).group(0)
    exec(compile(src, 'app.py[W5]', 'exec'), ns)
    return ns['_authentik_ldap_sa_group_probe'], calls


def _user(cn, groups):
    return f'dn: cn={cn},ou=users,dc=takldap\n' + ''.join(
        f'memberOf: cn={g},ou=groups,dc=takldap\n' for g in groups) + '\n'


def test_big_box_whose_first_page_has_no_tak_member_is_good():
    def answer(flt, z):
        if flt == '(cn=webadmin)':
            return 0, _user('webadmin', ['tak_ROLE_ADMIN', 'authentik Admins'])
        return 4, ''.join(_user(f'u{i}', []) for i in range(500))   # the old scan's view
    probe, calls = _ns(answer)
    bound, groups, detail = probe(SA_PASS)
    assert bound and groups == 1 and detail.startswith('webadmin:')
    assert len(calls) == 1 and calls[0][calls[0].index('-z') + 1] == '1'
    assert SA_PASS not in detail


def test_no_webadmin_uses_the_server_side_filter():
    def answer(flt, z):
        if flt == '(memberOf=cn=tak_*)':
            return 0, _user('ops1', ['tak_OPS'])
        return 0, ''
    probe, calls = _ns(answer)
    assert probe(SA_PASS)[:2] == (True, 1)
    assert [c for c in calls if '(memberOf=cn=tak_*)' in c]


def test_outpost_that_rejects_the_filter_falls_back_to_the_scan():
    def answer(flt, z):
        if flt == '(memberOf=cn=tak_*)':
            return 53, ''                    # unwilling to perform: NOT a failed bind
        if flt == '(objectClass=*)':
            return 0, _user('a', []) + _user('b', ['tak_OPS', 'tak_FIRE'])
        return 0, ''
    probe, _ = _ns(answer)
    bound, groups, detail = probe(SA_PASS)
    assert bound and groups == 2 and detail.startswith('first 500 users:')


@pytest.mark.parametrize('rc', [49, 1, 52])
def test_failed_bind_or_search_on_the_first_step_is_ldap_not_good(rc):
    probe, calls = _ns(lambda flt, z: (rc, ''))
    bound, groups, _ = probe(SA_PASS)
    assert (bound, groups) == (False, 0) and len(calls) == 1


def test_bind_failing_later_is_still_a_failure():
    probe, _ = _ns(lambda flt, z: (0, '') if flt == '(cn=webadmin)' else (49, ''))
    assert probe(SA_PASS)[:2] == (False, 0)


def test_ldap_up_but_no_tak_member_anywhere_is_bound_with_no_groups():
    probe, calls = _ns(lambda flt, z: (0, _user('x', ['other'])))
    bound, groups, detail = probe(SA_PASS)
    assert (bound, groups) == (True, 0) and len(calls) == 3
    assert 'webadmin:' in detail and 'first 500 users:' in detail


def test_ldapsearch_missing_is_not_good():
    def run(cmd, **kw):
        raise FileNotFoundError('ldapsearch')
    ns = {'subprocess': types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired)}
    src = re.search(r'^def _authentik_ldap_sa_search\(.*?(?=^def _authentik_ldap_sa_groups_settle\()',
                    APP, re.S | re.M).group(0)
    exec(compile(src, 'app.py[W5]', 'exec'), ns)
    assert ns['_authentik_ldap_sa_group_probe'](SA_PASS) == (False, 0, 'ldapsearch FileNotFoundError')
