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
"""New admin accounts get an email that can receive mail (infra-TAK #687, ops #1169).

infra-TAK made webadmin@<TAK FQDN> for new Authentik admin accounts. That domain has no MX,
and TAK Portal mails every admin-group member when a user asks for access, so each of those
notifications bounced. A new account now gets the first Guard Dog alert address when one is
set, and the made-up form only when nothing else exists.
"""

import ast
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
FUNCS = {n.name: n for n in TREE.body if isinstance(n, ast.FunctionDef)}
ASSIGNS = {}
for _n in TREE.body:
    if isinstance(_n, ast.Assign) and len(_n.targets) == 1 and isinstance(_n.targets[0], ast.Name):
        ASSIGNS[_n.targets[0].id] = _n

FQDN = 'tak.example.org'


@pytest.fixture
def g():
    ns = {'re': re}
    ns['load_settings'] = lambda: {'fqdn': FQDN}
    for name in ('_ALERT_EMAIL_RE', '_AUTHENTIK_RECOVERABLE_USERS', '_AK_ADMIN_PLACEHOLDER_EMAILS'):
        exec(ast.get_source_segment(APP, ASSIGNS[name]), ns)
    for name in ('_safe_alert_email', '_safe_alert_emails', '_ak_admin_email_is_placeholder',
                 '_ak_admin_account_email'):
        exec(ast.get_source_segment(APP, FUNCS[name]), ns)
    return ns


def test_new_account_uses_the_guard_dog_alert_address(g):
    s = {'fqdn': FQDN, 'guarddog_alert_email': 'ops@agency.gov'}
    assert g['_ak_admin_account_email']('webadmin', s) == 'ops@agency.gov'
    assert g['_ak_admin_account_email']('akadmin', s) == 'ops@agency.gov'


def test_first_address_wins_when_several_are_set(g):
    s = {'fqdn': FQDN, 'guarddog_alert_email': 'a@agency.gov,b@agency.gov'}
    assert g['_ak_admin_account_email']('webadmin', s) == 'a@agency.gov'


def test_no_alert_address_falls_back_to_the_made_up_form(g):
    assert g['_ak_admin_account_email']('webadmin', {'fqdn': FQDN}) == f'webadmin@{FQDN}'
    assert g['_ak_admin_account_email']('webadmin', {'fqdn': f'{FQDN}:8443'}) == f'webadmin@{FQDN}'
    assert g['_ak_admin_account_email']('webadmin', {}) == 'webadmin@tak.local'


def test_an_alert_address_on_the_tak_domain_is_skipped(g):
    # Mail to webadmin@<FQDN> is what bounces; never hand that back as the "real" address.
    s = {'fqdn': FQDN, 'guarddog_alert_email': f'webadmin@{FQDN},ops@agency.gov'}
    assert g['_ak_admin_account_email']('webadmin', s) == 'ops@agency.gov'


def test_invalid_alert_value_is_ignored(g):
    s = {'fqdn': FQDN, 'guarddog_alert_email': 'x; rm -rf /'}
    assert g['_ak_admin_account_email']('webadmin', s) == f'webadmin@{FQDN}'


def test_akadmin_at_the_tak_domain_counts_as_made_up(g):
    assert g['_ak_admin_email_is_placeholder']('akadmin', f'akadmin@{FQDN}', {'fqdn': FQDN}) is True
    assert g['_ak_admin_email_is_placeholder']('akadmin', 'ops@agency.gov', {'fqdn': FQDN}) is False


def test_every_webadmin_create_site_uses_the_helper():
    # The three places that give webadmin an email must not build webadmin@<fqdn> themselves.
    assert not re.search(r"""f['"]webadmin@\{""", APP), 'a site still builds webadmin@<fqdn> by hand'
    assert APP.count("_ak_admin_account_email('webadmin'") == 3
