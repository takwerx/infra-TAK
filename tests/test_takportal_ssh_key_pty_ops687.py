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
"""ops #687: the portal key line must allow a terminal.

10.3.12 wrote `restrict,from="..."`. `restrict` turns off terminal (pty) allocation, and TAK
Portal's plugin worker asks for a terminal, so Marketplace installs ended with
`Unable to request a pseudo-terminal`. The line is now `restrict,pty,from="..."`: forwarding,
agent and X11 stay off, from= still limits who can use the key, and the console-start heal
rewrites the 10.3.12 line so an update alone fixes a box.
"""

import ast
import os
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

PORTAL_PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPortalCurrentKeyBlob0000000000000000000000 tak-portal-auto'
OPERATOR = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOperatorKeyBlob000000000000000000000000000 ops@laptop'
NETS = ['172.19.0.0/16', '172.22.0.0/16']
FROM = 'from="127.0.0.1,::1,172.19.0.0/16,172.22.0.0/16"'
BLOB = PORTAL_PUB.split()[1]


def _src(kind, name):
    for n in ast.walk(TREE):
        if (kind == 'def' and isinstance(n, ast.FunctionDef) and n.name == name) or \
           (kind == 'const' and isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets)):
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} is missing from app.py')


@pytest.fixture()
def kt():
    ns = {'os': os, 're': re}
    src = '\n\n'.join([_src('const', c) for c in ('TAKPORTAL_SSH_KEY_COMMENT', '_AUTHKEY_TYPE_RE')]
                      + [_src('def', f) for f in ('_authorized_keys_split', '_takportal_ssh_key_options',
                                                   '_takportal_authorized_keys_text')])
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns


def _portal_line(text):
    return [l for l in text.splitlines() if BLOB in l]


def _opts(line):
    """The option field of an authorized_keys line (before the key type)."""
    return line.split(' ssh-ed25519 ')[0]


def test_key_options_include_pty_with_and_without_sources(kt):
    opts = kt['_takportal_ssh_key_options']
    assert opts(NETS) == 'restrict,pty,' + FROM
    assert opts([]) == 'restrict,pty'


def test_pty_does_not_open_forwarding_or_wider_access(kt):
    """`restrict` stays first (it turns off port, agent, X11 forwarding and user rc); only pty is
    switched back on, and from= still limits the source."""
    line = kt['_takportal_ssh_key_options'](NETS)
    parts = line.split(',')
    assert parts[0] == 'restrict'
    assert parts[1] == 'pty'
    for banned in ('port-forwarding', 'agent-forwarding', 'X11-forwarding', 'user-rc'):
        assert banned not in line
    assert FROM in line


def test_10_3_12_line_is_rewritten_with_pty_and_other_lines_kept(kt):
    old = f'restrict,{FROM} {PORTAL_PUB}'
    existing = f'{OPERATOR}\n{old}\n'
    text, changed, removed = kt['_takportal_authorized_keys_text'](existing, PORTAL_PUB, NETS)
    assert changed and removed == 0
    assert _portal_line(text) == [f'restrict,pty,{FROM} {PORTAL_PUB}']
    assert OPERATOR in text.splitlines()
    again, changed, _ = kt['_takportal_authorized_keys_text'](text, PORTAL_PUB, NETS)
    assert again == text and changed is False


def test_10_3_12_line_gets_pty_even_when_docker_is_unreadable(kt):
    """No sources: the old from= is kept (never narrowed), and pty is added to it."""
    old = f'restrict,{FROM} {PORTAL_PUB}'
    text, changed, _ = kt['_takportal_authorized_keys_text'](f'{old}\n', PORTAL_PUB, [])
    assert changed
    assert _portal_line(text) == [f'restrict,pty,{FROM} {PORTAL_PUB}']
    again, changed, _ = kt['_takportal_authorized_keys_text'](text, PORTAL_PUB, [])
    assert again == text and changed is False
    bare, _, _ = kt['_takportal_authorized_keys_text'](f'restrict {PORTAL_PUB}\n', PORTAL_PUB, [])
    assert _portal_line(bare) == [f'restrict,pty {PORTAL_PUB}']


def test_heal_rewrites_a_10_3_12_line_on_disk(monkeypatch, tmp_path):
    """The console-start heal, run on a box that holds the 10.3.12 line, writes the pty line."""
    ns = {'os': os, 're': re}
    names = ('_authorized_keys_split', '_takportal_ssh_key_options', '_takportal_authorized_keys_text',
             '_takportal_trust_portal_key', '_heal_takportal_ssh_key')
    import tempfile
    ns['tempfile'] = tempfile
    ns['_takportal_ssh_from_sources'] = lambda: list(NETS)
    ns['_takportal_web_running'] = lambda: True
    src = '\n\n'.join([_src('const', c) for c in ('TAKPORTAL_SSH_KEY_COMMENT', '_AUTHKEY_TYPE_RE')]
                      + [_src('def', f) for f in names])
    exec(compile(src, 'app.py', 'exec'), ns)
    home = tmp_path / 'h'
    (home / '.ssh').mkdir(parents=True)
    (home / 'TAK-Portal' / 'data' / 'ssh').mkdir(parents=True)
    (home / 'TAK-Portal' / 'data' / 'ssh' / 'tak_ssh_ed25519.pub').write_text(PORTAL_PUB + '\n')
    ak = home / '.ssh' / 'authorized_keys'
    ak.write_text(f'{OPERATOR}\nrestrict,{FROM} {PORTAL_PUB}\n')
    monkeypatch.setenv('HOME', str(home))
    real_isdir = os.path.isdir
    monkeypatch.setattr(os.path, 'isdir', lambda p: p == '/opt/tak' or real_isdir(p))
    assert ns['_heal_takportal_ssh_key'](lambda m: None) is True
    assert ak.read_text() == f'{OPERATOR}\nrestrict,pty,{FROM} {PORTAL_PUB}\n'
    assert ns['_heal_takportal_ssh_key'](lambda m: None) is False
