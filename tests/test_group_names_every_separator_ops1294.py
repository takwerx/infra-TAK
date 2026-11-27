# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1294: the console lists EVERY Authentik group whose name holds "|", ";" or ",".

TAK Portal 2.0.42 refuses the three characters in NEW group names. It does not clean OLD
ones and still splits the groups header on them, so a group named `x|authentik Admins` is
read as two groups. ops #1082 added a check that listed only some of these names. This
file holds the proof for the rest: `a;b` and `a,b` are listed too, with the exact step.
"""

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
ADMINS = 'authentik Admins'


def _source(name, kind):
    for n in TREE.body:
        if kind == 'func' and isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
        if (kind == 'assign' and isinstance(n, ast.Assign) and len(n.targets) == 1
                and getattr(n.targets[0], 'id', None) == name):
            return ast.get_source_segment(APP, n)
    raise AssertionError('app.py has no %s' % name)


def _finder():
    ns = {'CONSOLE_SSO_ADMIN_GROUP': ADMINS}
    exec(_source('AK_GROUP_NAME_SEPARATORS', 'assign'), ns)
    exec(_source('_ak_group_name_findings', 'func'), ns)
    return ns['_ak_group_name_findings']


def test_every_name_with_a_separator_is_listed():
    got = [f['name'] for f in _finder()(['ok', 'a|b', 'a;b', 'a,b'])]
    assert got == ['a,b', 'a;b', 'a|b']


def test_a_name_that_reads_as_the_admin_group_still_says_so():
    got = {f['name']: f['reads_as'] for f in _finder()(
        [ADMINS, 'ok', 'x|authentik Admins', 'x;authentik Admins', 'x,authentik Admins',
         'plain;name'])}
    assert got == {'x|authentik Admins': [ADMINS], 'x;authentik Admins': [ADMINS],
                   'x,authentik Admins': [ADMINS], 'plain;name': []}


def test_clean_names_are_not_listed():
    assert _finder()(['ok', 'tak_Fire', 'Station 1', ADMINS]) == []


def test_the_page_and_the_log_give_the_exact_step():
    page = (REPO / 'templates' / 'authentik.html').read_text(encoding='utf-8')
    assert 'Authentik Admin → Directory → Groups → rename the group' in page
    assert 'holds a separator (| ; ,)' in page
    log = APP[APP.index('GROUP NAME WARNING'):][:700]
    assert 'Directory, Groups, rename' in log and 'does not rename it' in log
