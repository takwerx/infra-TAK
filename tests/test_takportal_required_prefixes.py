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
"""TAK Portal hides our admin accounts and groups on every box, fresh or not.

Found on a fresh split install (2026-10-21, TAK Portal 2.0.14): the Users page listed akadmin and
webadmin and Groups listed ROLE_ADMIN. We seed USERS_HIDDEN_PREFIXES / GROUPS_HIDDEN_PREFIXES only
when the portal has no value, and TAK Portal 2.x ships its own (`ak-,adm_,nodered-,ma-`,
`authentik, MA -`), so ours never landed. The admin guardrail then pushed through the same
seed-only writer, changed nothing, restarted the portal, and logged "hidden + action-locked".

Operator decision (option A): our entries are ADDED to whatever list is there and never replace
it. The guardrail runs on every console start, so an infra-TAK update fixes existing boxes.
"""

import ast
import json
import pathlib
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

PORTAL_2X = {'USERS_HIDDEN_PREFIXES': 'ak-,adm_,nodered-,ma-',
             'GROUPS_HIDDEN_PREFIXES': 'authentik, MA -',
             'USERS_ACTIONS_HIDDEN_PREFIXES': 'akadmin,webadmin',
             'GROUPS_ACTIONS_HIDDEN_PREFIXES': '',
             'AUTHENTIK_URL': 'http://authentik-server-1:9000', 'AUTHENTIK_TOKEN': 'tok'}


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _consts(*names):
    return '\n'.join(ast.get_source_segment(APP, n) for n in TREE.body
                     if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in names for t in n.targets))


def _ns(extra=None, funcs=('_takportal_with_required_prefixes',)):
    ns = {'json': json, 'os': __import__('os')}
    ns.update(extra or {})
    exec(compile(_consts('TAKPORTAL_REQUIRED_PREFIXES', 'TAKPORTAL_AUTHORITATIVE_KEYS',
                         'TAKPORTAL_DOMAIN_KEYS', 'TAKPORTAL_AUTH_ADOPT_KEYS', 'EMAIL_TRANSPORT_KEYS',
                         'TAKPORTAL_TEMPLATE_PLACEHOLDERS', 'TAKPORTAL_TEMPLATE_TAK_CONNECTION'),
                 'app.py', 'exec'), ns)
    exec(compile('\n\n'.join(_func(f) for f in funcs), 'app.py', 'exec'), ns)
    return ns


def _with(value, required):
    return _ns()['_takportal_with_required_prefixes'](value, required)


# ── the list helper ──────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('value,required,want', [
    ('ak-,adm_,nodered-,ma-', ('akadmin', 'webadmin'), 'ak-,adm_,nodered-,ma-,akadmin,webadmin'),
    ('authentik, MA -', ('tak_ROLE_', 'vid_'), 'authentik, MA -, tak_ROLE_, vid_'),
    ('', ('akadmin', 'webadmin'), 'akadmin,webadmin'),
    (None, ('akadmin',), 'akadmin'),
    ('ak-,', ('akadmin',), 'ak-,akadmin'),                       # a trailing comma is not an entry
    ('webadmin', ('akadmin', 'webadmin'), 'webadmin,akadmin'),  # only the missing one is added
])
def test_missing_entries_are_appended(value, required, want):
    assert _with(value, required) == want


@pytest.mark.parametrize('value', [
    'akadmin,webadmin,ak-',
    'AKADMIN, WebAdmin',          # TAK Portal matches case-insensitively
    'ak,web',                     # a shorter prefix already hides ours
    'a,w',
])
def test_a_list_that_already_covers_ours_is_returned_unchanged(value):
    assert _with(value, ('akadmin', 'webadmin')) == value


def test_operator_entries_are_never_removed_or_reordered():
    out = _with('zz-ops,ak-,custom_', ('akadmin', 'webadmin'))
    assert out.startswith('zz-ops,ak-,custom_,')


def test_required_set_is_our_accounts_and_groups():
    req = _ns()['TAKPORTAL_REQUIRED_PREFIXES']
    assert set(req) == {'USERS_HIDDEN_PREFIXES', 'USERS_ACTIONS_HIDDEN_PREFIXES', 'GROUPS_HIDDEN_PREFIXES'}
    assert set(req['USERS_HIDDEN_PREFIXES']) == set(req['USERS_ACTIONS_HIDDEN_PREFIXES']) == {'akadmin', 'webadmin'}
    assert 'tak_ROLE_' in req['GROUPS_HIDDEN_PREFIXES']


# ── the single writer ────────────────────────────────────────────────────────────────────────

def _merge(existing):
    ns = _ns({'_takportal_get_existing_settings': lambda: dict(existing),
              '_takportal_build_settings_dict': lambda s: {
                  'USERS_HIDDEN_PREFIXES': 'akadmin,webadmin,ak-,adm_,nodered-,ma-',
                  'GROUPS_HIDDEN_PREFIXES': 'authentik, MA -, vid_, tak_ROLE_',
                  'USERS_ACTIONS_HIDDEN_PREFIXES': 'akadmin,webadmin',
                  'AUTHENTIK_URL': 'http://authentik-server-1:9000', 'AUTHENTIK_TOKEN': 'tok'},
              '_takportal_settings_value_is_blank': lambda v: v is None or (isinstance(v, str) and not v.strip())},
             funcs=('_takportal_with_required_prefixes', '_takportal_template_placeholder_keys',
                    '_takportal_merged_settings_json'))
    return json.loads(ns['_takportal_merged_settings_json']({}))


def test_a_fresh_portal_2x_install_gets_our_entries_added_to_its_own():
    out = _merge(PORTAL_2X)
    assert out['USERS_HIDDEN_PREFIXES'] == 'ak-,adm_,nodered-,ma-,akadmin,webadmin'
    assert out['GROUPS_HIDDEN_PREFIXES'] == 'authentik, MA -, tak_ROLE_, vid_'
    assert out['USERS_ACTIONS_HIDDEN_PREFIXES'] == 'akadmin,webadmin'
    assert out['GROUPS_ACTIONS_HIDDEN_PREFIXES'] == ''              # not ours — untouched


def test_an_operator_list_keeps_everything_and_gains_only_ours():
    out = _merge(dict(PORTAL_2X, USERS_HIDDEN_PREFIXES='svc-,bot_', GROUPS_HIDDEN_PREFIXES='lab-'))
    assert out['USERS_HIDDEN_PREFIXES'] == 'svc-,bot_,akadmin,webadmin'
    assert out['GROUPS_HIDDEN_PREFIXES'] == 'lab-,tak_ROLE_,vid_'


def test_a_healthy_box_is_written_back_byte_identical():
    healthy = dict(PORTAL_2X, USERS_HIDDEN_PREFIXES='akadmin,webadmin,ak-',
                   GROUPS_HIDDEN_PREFIXES='authentik, MA -, vid_, tak_ROLE_')
    out = _merge(healthy)
    for k in ('USERS_HIDDEN_PREFIXES', 'GROUPS_HIDDEN_PREFIXES', 'USERS_ACTIONS_HIDDEN_PREFIXES'):
        assert out[k] == healthy[k], k


# ── the guardrail ────────────────────────────────────────────────────────────────────────────

def _guardrail(states, push_ok=True):
    """Run the guardrail with the portal's settings reading `states` in turn."""
    reads = iter(states)
    logs, pushes = [], []
    ns = _ns({'_takportal_web_running': lambda: True,
              '_takportal_get_existing_settings': lambda: next(reads),
              '_takportal_push_settings': lambda plog=None: pushes.append(1) or push_ok},
             funcs=('_takportal_with_required_prefixes', '_takportal_admin_guardrail'))
    ns['os'] = types.SimpleNamespace(path=types.SimpleNamespace(expanduser=lambda p: p, isdir=lambda p: True))
    ns['_takportal_admin_guardrail'](plog_fn=logs.append)
    return logs, pushes


def test_guardrail_is_silent_on_a_healthy_box():
    healthy = dict(PORTAL_2X, USERS_HIDDEN_PREFIXES='akadmin,webadmin',
                   GROUPS_HIDDEN_PREFIXES='tak_ROLE_, vid_')
    logs, pushes = _guardrail([healthy])
    assert logs == [] and pushes == []


def test_guardrail_reports_success_only_when_the_readback_has_them():
    fixed = dict(PORTAL_2X, USERS_HIDDEN_PREFIXES='ak-,akadmin,webadmin',
                 GROUPS_HIDDEN_PREFIXES='authentik, MA -, tak_ROLE_, vid_')
    logs, pushes = _guardrail([PORTAL_2X, fixed])
    assert pushes == [1]
    assert 'hidden + action-locked' in logs[-1]


def test_guardrail_never_claims_success_after_a_push_that_changed_nothing():
    """The bug: the old guardrail logged success here, on every console start."""
    logs, pushes = _guardrail([PORTAL_2X, PORTAL_2X])
    assert pushes == [1]
    assert 'still missing after the push' in logs[-1]
    assert not any('hidden + action-locked' in l for l in logs)
