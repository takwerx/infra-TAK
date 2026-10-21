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
"""A TAK Portal settings.json left on its own template heals (v10.2.18, ops #71).

Field report, 2026-10-17 (v10.2.17, TAK Portal 2.0.12, Authentik 2026.5.7): every group change
failed "Authentik operation failed and remains queued for retry; check sync status." GH #158 had
reset settings.json to settings.example.json before v10.2.17 shipped. Reproduced on a test box:
the outbox's last_error was `getaddrinfo EAI_AGAIN your-authentik-url`, and the dashboard's TAK
stats failed on the template's `./data/certs/webadmin.p12`.

TAK Portal's fill-in-the-blank sentinels carry no operator intent, so they seed like a blank key.
Real values, including our own defaults and the template's real-looking ones, are never touched.
"""

import ast
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

# The TAK connection / Authentik block of TAK Portal 2.0.12's settings.example.json, verbatim,
# plus two template keys that are real-looking defaults and must survive.
TEMPLATE = {
    'AUTHENTIK_URL': 'http://your-authentik-url:9000',
    'AUTHENTIK_TOKEN': 'your-real-token-here',
    'USERS_HIDDEN_PREFIXES': 'ak-,adm_,nodered-,ma-',
    'TAK_URL': 'https://your-tak-server:8443/Marti',
    'TAK_API_P12_PATH': './data/certs/webadmin.p12',
    'TAK_API_P12_PASSPHRASE': 'atakatak',
    'TAK_CA_PATH': './data/certs/tak-ca.pem',
    'TAK_REVOKE_ON_DISABLE': 'true',
    'BRAND_LOGO_URL': '',
}
BUILT = {
    'AUTHENTIK_URL': 'http://authentik-server-1:9000',
    'AUTHENTIK_TOKEN': 'real-token',
    'USERS_HIDDEN_PREFIXES': 'akadmin,webadmin,ak-,adm_,nodered-,ma-',
    'TAK_URL': 'https://takserver.ops1.example.com:8443/Marti',
    'TAK_API_P12_PATH': 'data/certs/tak-client.p12',
    'TAK_API_P12_PASSPHRASE': 'box-cert-pass',
    'TAK_CA_PATH': 'data/certs/tak-ca.pem',
    'TAK_REVOKE_ON_DISABLE': 'true',
    'BRAND_LOGO_URL': '',
}
HEALTHY = {
    'AUTHENTIK_URL': 'http://authentik-server-1:9000',
    'AUTHENTIK_TOKEN': 'real-token',
    'USERS_HIDDEN_PREFIXES': 'akadmin,webadmin,ak-',
    'TAK_URL': 'https://tak.agency.gov:8443/Marti',
    'TAK_API_P12_PATH': './data/certs/webadmin.p12',   # the operator copied webadmin.p12 in
    'TAK_API_P12_PASSPHRASE': 'atakatak',
    'TAK_CA_PATH': './data/certs/tak-ca.pem',
    'TAK_REVOKE_ON_DISABLE': 'false',
    'BRAND_LOGO_URL': 'https://agency.gov/logo.png',
}
RESEEDED = ('AUTHENTIK_URL', 'AUTHENTIK_TOKEN', 'TAK_URL', 'TAK_API_P12_PATH',
            'TAK_API_P12_PASSPHRASE', 'TAK_CA_PATH')


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _consts(*names):
    return '\n'.join(ast.get_source_segment(APP, n) for n in TREE.body
                     if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in names for t in n.targets))


def _load(names, ns=None):
    ns = {'json': json} if ns is None else dict({'json': json}, **ns)
    exec(compile(_consts('TAKPORTAL_TEMPLATE_PLACEHOLDERS', 'TAKPORTAL_TEMPLATE_TAK_CONNECTION',
                         'TAKPORTAL_AUTHORITATIVE_KEYS', 'TAKPORTAL_DOMAIN_KEYS', 'TAKPORTAL_AUTH_ADOPT_KEYS',
                         'EMAIL_TRANSPORT_KEYS'),
                 'app.py', 'exec'), ns)
    exec(compile('\n\n'.join(_func(n) for n in names), 'app.py', 'exec'), ns)
    return ns


def _keys(existing):
    return _load(['_takportal_template_placeholder_keys'])['_takportal_template_placeholder_keys'](existing)


def _merge(existing):
    ns = _load(['_takportal_settings_value_is_blank', '_takportal_template_placeholder_keys',
                '_takportal_merged_settings_json'],
               {'_takportal_get_existing_settings': lambda: dict(existing),
                '_takportal_build_settings_dict': lambda s: dict(BUILT)})
    return json.loads(ns['_takportal_merged_settings_json']({}))


# ── what counts as a placeholder ─────────────────────────────────────────────────────────────

def test_a_reset_file_reports_the_sentinels_and_the_tak_block_that_came_with_them():
    assert _keys(TEMPLATE) == frozenset(RESEEDED)


def test_a_healthy_file_has_no_placeholders():
    assert _keys(HEALTHY) == frozenset()
    assert _keys({}) == frozenset() and _keys(None) == frozenset()


def test_template_p12_block_alone_is_the_operators_once_tak_url_is_real():
    """`atakatak` / webadmin.p12 are real TAK defaults; with a real TAK_URL they are a choice."""
    assert _keys(dict(TEMPLATE, TAK_URL='https://tak.agency.gov:8443/Marti')) == \
        frozenset({'AUTHENTIK_URL', 'AUTHENTIK_TOKEN'})


@pytest.mark.parametrize('key,value', [
    ('AUTHENTIK_URL', 'http://your-authentik-url.agency.gov:9000'),
    ('AUTHENTIK_URL', 'https://your-authentik-url:9443'),
    ('AUTHENTIK_TOKEN', 'your-real-token-here-not'),
    ('TAK_URL', 'https://your-tak-server.agency.gov:8443/Marti'),
    ('TAK_URL', 'https://your-tak-server:8446/Marti'),
])
def test_only_an_exact_match_counts(key, value):
    assert key not in _keys(dict(TEMPLATE, **{key: value}))


def test_surrounding_whitespace_is_still_the_template():
    assert 'TAK_URL' in _keys(dict(TEMPLATE, TAK_URL='  https://your-tak-server:8443/Marti\n'))


def test_non_string_values_are_never_placeholders():
    assert _keys({'AUTHENTIK_URL': 9000, 'TAK_URL': None, 'AUTHENTIK_TOKEN': ['x']}) == frozenset()


# ── the merge ────────────────────────────────────────────────────────────────────────────────

def test_merge_reseeds_the_placeholders_on_a_reset_file():
    out = _merge(TEMPLATE)
    for k in RESEEDED:
        assert out[k] == BUILT[k], k
    assert out['USERS_HIDDEN_PREFIXES'] == TEMPLATE['USERS_HIDDEN_PREFIXES'], \
        'a real-looking template default is not a placeholder — hands off'


def test_merge_never_touches_a_real_operator_value():
    out = _merge(HEALTHY)
    for k in HEALTHY:
        if k in ('AUTHENTIK_URL', 'AUTHENTIK_TOKEN'):
            continue  # authoritative — infra-TAK always writes these
        assert out[k] == HEALTHY[k], k


def test_merge_keeps_a_template_p12_block_once_the_operator_set_tak_url():
    existing = dict(TEMPLATE, TAK_URL='https://tak.agency.gov:8443/Marti')
    out = _merge(existing)
    assert out['TAK_URL'] == 'https://tak.agency.gov:8443/Marti'
    assert out['TAK_API_P12_PATH'] == './data/certs/webadmin.p12'
    assert out['TAK_API_P12_PASSPHRASE'] == 'atakatak'


def test_preserve_on_empty_never_carries_the_template_token_forward():
    body = _func('_takportal_build_settings_dict')
    assert "TAKPORTAL_TEMPLATE_PLACEHOLDERS['AUTHENTIK_TOKEN']" in body


# ── the console-start heal ───────────────────────────────────────────────────────────────────

class _Box:
    def __init__(self, existing, running=True, token='real-token'):
        self.existing, self.running, self.token = existing, running, token
        self.pushes, self.logs = 0, []

    def heal(self):
        def push(plog=None):
            self.pushes += 1
            return True
        ns = _load(['_takportal_template_placeholder_keys', '_heal_takportal_authentik_token'], {
            '_takportal_web_running': lambda: self.running,
            '_takportal_get_existing_settings': lambda: self.existing,
            'load_settings': lambda: {},
            '_get_authentik_env_value': lambda s, k: self.token,
            '_takportal_push_settings': push,
        })
        return ns['_heal_takportal_authentik_token'](self.logs.append)


def test_heal_pushes_on_a_reset_file():
    box = _Box(dict(TEMPLATE))
    assert box.heal() is True and box.pushes == 1
    assert any('AUTHENTIK_URL' in m and 'TAK_URL' in m for m in box.logs)
    assert not any('real-token' in m for m in box.logs), 'never log the token'


def test_heal_partial_reset_repairs_authentik_and_leaves_real_tak_fields_alone():
    """The field box: Authentik fields on the template, TAK connection real (its stats were fine)."""
    partial = dict(HEALTHY, AUTHENTIK_URL=TEMPLATE['AUTHENTIK_URL'], AUTHENTIK_TOKEN=TEMPLATE['AUTHENTIK_TOKEN'])
    assert _keys(partial) == frozenset({'AUTHENTIK_URL', 'AUTHENTIK_TOKEN'})
    box = _Box(partial)
    assert box.heal() is True and box.pushes == 1
    assert any('(AUTHENTIK_TOKEN, AUTHENTIK_URL)' in m for m in box.logs)
    out = _merge(partial)
    assert out['AUTHENTIK_URL'] == BUILT['AUTHENTIK_URL'] and out['AUTHENTIK_TOKEN'] == BUILT['AUTHENTIK_TOKEN']
    for k in HEALTHY:
        if k not in ('AUTHENTIK_URL', 'AUTHENTIK_TOKEN'):
            assert out[k] == HEALTHY[k], k


def test_heal_leaves_a_healthy_box_alone():
    box = _Box(dict(HEALTHY))
    assert box.heal() is False and box.pushes == 0


def test_heal_still_fixes_a_blank_token():
    box = _Box(dict(HEALTHY, AUTHENTIK_TOKEN=''))
    assert box.heal() is True and box.pushes == 1


def test_heal_skips_a_blank_token_it_cannot_read_yet():
    box = _Box(dict(HEALTHY, AUTHENTIK_TOKEN=''), token='')
    assert box.heal() is False and box.pushes == 0


def test_heal_fixes_tak_url_even_when_the_token_is_not_readable_yet():
    box = _Box(dict(TEMPLATE), token='')
    assert box.heal() is True and box.pushes == 1
    assert any('healing the other keys' in m for m in box.logs)


@pytest.mark.parametrize('existing,running', [({}, True), (None, True), (TEMPLATE, False)])
def test_heal_does_nothing_without_a_readable_file_or_a_running_portal(existing, running):
    """An unreadable file reads as {} — pushing then would rebuild it from seeds alone."""
    box = _Box(existing, running=running)
    assert box.heal() is False and box.pushes == 0


def test_heal_runs_on_console_start():
    i = APP.index('_heal_takportal_authentik_token(\n')
    assert 'Startup migration' in APP[i:i + 200]
