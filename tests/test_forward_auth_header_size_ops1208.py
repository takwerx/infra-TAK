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
"""A person in many Authentik groups must not get HTTP 431 on the console or TAK Portal (ops #1208).

Caddy's forward_auth copied every X-Authentik-* header to the app, and the outpost joins ALL of a
person's group names into X-Authentik-Groups (about 10,600 bytes for 200 groups with TAK-style names)
and puts them again in the signed X-Authentik-Jwt. Measured on a real box (Nov 24, 2026, akadmin in
201 groups): the console (gunicorn, one header over about 8,190 bytes) and TAK Portal (Node, all
headers over 16 KB) both answered 431.

The fix is per site, by what the app reads:
- the console reads X-Authentik-Username only, so only that header is copied;
- the MediaMTX editor overlay reads X-Authentik-Username and X-Authentik-Jwt only;
- TAK Portal reads the groups (who is an admin) and the token, so they stay and its Node server is
  told to take bigger headers (a fleet constant, written into the compose override).
"""
import ast
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
OVERLAY = (REPO / 'mediamtx_ldap_overlay.py').read_text(encoding='utf-8')

GUNICORN_ONE_HEADER_LIMIT = 8190        # limit_request_field_size default
NODE_DEFAULT_HEADER_LIMIT = 16384       # --max-http-header-size default (all headers together)


def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') == name:
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found in app.py')


def _func_src(name):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def _groups_header(n):
    """What the outpost sends for a person in n groups with TAK Portal style names."""
    return '|'.join('TAK-Agency-Group-%03d-County-Fire-and-Rescue-Dispatch' % i for i in range(n))


# --- the console ------------------------------------------------------------------------

def test_console_vhost_copies_only_the_username_header():
    src = _func_src('generate_caddyfile')
    # ops #1081: the block comes from the one writer; the console hands it its header list.
    block = src[src.index('_caddy_forward_auth_lines(ak_up, "        ", _CONSOLE_AK_COPY_HEADERS,'):]
    block = block[:block.index('reverse_proxy 127.0.0.1:5001')]
    assert "matcher='@needs_sso'" in block
    assert _const('_CONSOLE_AK_COPY_HEADERS') == 'X-Authentik-Username'
    for name in ('Groups', 'Email', 'Name', 'Uid', 'Jwt'):
        assert f'X-Authentik-{name}' not in block, f'the console vhost must not copy X-Authentik-{name}'


def test_console_reads_no_authentik_header_but_the_username():
    """If the console starts to read another X-Authentik header, the vhost must copy it too."""
    read = set(re.findall(r"""headers(?:\.get\(|\[)\s*['"]X-Authentik-([A-Za-z-]+)""", APP, re.I))
    assert {h.lower() for h in read} == {'username'}, read


def test_a_person_in_250_groups_gives_the_console_a_small_request():
    groups = _groups_header(250)
    assert len(groups) > GUNICORN_ONE_HEADER_LIMIT          # the header that used to be copied
    copied = _const('_CONSOLE_AK_COPY_HEADERS').split()
    sent = {'X-Authentik-Username': 'akadmin', 'X-Authentik-Groups': groups}
    got = {h: v for h, v in sent.items() if h in copied}
    assert 'X-Authentik-Groups' not in got
    assert max(len(v) for v in got.values()) < GUNICORN_ONE_HEADER_LIMIT


# --- the MediaMTX editor ----------------------------------------------------------------

def test_mediamtx_editor_gets_only_the_headers_its_overlay_reads():
    read = set(re.findall(r"""headers\.get\(\s*['"]X-Authentik-([A-Za-z-]+)""", OVERLAY, re.I))
    assert {h.lower() for h in read} == {'username', 'jwt'}, read
    copied = _const('_MEDIAMTX_AK_COPY_HEADERS')
    assert copied == 'copy_headers X-Authentik-Username X-Authentik-Jwt'


# --- TAK Portal -------------------------------------------------------------------------

def _override_text(tmp_path, monkeypatch):
    portal = tmp_path / 'TAK-Portal'
    portal.mkdir()
    monkeypatch.setenv('HOME', str(tmp_path))
    ns = {
        'os': __import__('os'),
        '_ensure_infratak_docker_network': lambda: None,
        'load_settings': lambda: {},
        '_get_takserver_host': lambda s: '',
        '_takportal_app_services': lambda d=None: ['tak-portal', 'tak-portal-worker'],
        'INFRATAK_DOCKER_NETWORK': 'infratak',
        'TAKPORTAL_MAX_HEADER_BYTES': _const('TAKPORTAL_MAX_HEADER_BYTES'),
    }
    exec(_func_src('_write_takportal_override'), ns)
    assert ns['_write_takportal_override']() is True
    return (portal / 'docker-compose.override.yml').read_text()


def test_takportal_override_raises_the_node_header_limit(tmp_path, monkeypatch):
    yaml = pytest.importorskip('yaml')
    doc = yaml.safe_load(_override_text(tmp_path, monkeypatch))
    want = '--max-http-header-size=%d' % _const('TAKPORTAL_MAX_HEADER_BYTES')
    for svc in ('tak-portal', 'tak-portal-worker'):
        assert doc['services'][svc]['environment']['NODE_OPTIONS'] == want
        # what the override already did stays
        assert 'infratak' in doc['services'][svc]['networks']
        assert doc['services'][svc]['extra_hosts']


def test_takportal_limit_holds_the_groups_and_the_token_of_a_person_in_250_groups():
    groups = _groups_header(250)
    # the signed token carries the same list again as JSON, base64 url encoded
    token = len(groups) * 1.35 + len(groups) * 0.1 + 600
    request = len(groups) + token + 2000                    # cookies, host, the other X-Authentik-*
    limit = _const('TAKPORTAL_MAX_HEADER_BYTES')
    assert request > NODE_DEFAULT_HEADER_LIMIT              # the default is what gave 431
    assert limit > NODE_DEFAULT_HEADER_LIMIT
    assert limit >= 3 * request, 'keep room for several times 250 groups'


def test_takportal_still_gets_the_groups_and_token_headers():
    """It decides who is an admin from the groups and keeps its agreement marker from the token."""
    copied = _const('_TAKPORTAL_AK_COPY_HEADERS').split()
    assert 'X-Authentik-Groups' in copied and 'X-Authentik-Jwt' in copied


def test_the_startup_converge_recreates_takportal_when_the_override_changes():
    """Existing boxes get the new limit: the override is rewritten and the container recreated
    on the next console start (the same path as the network hardening)."""
    src = _func_src('_startup_harden_tak_portal_ports')
    assert '_write_takportal_override()' in src and '--force-recreate' in src
