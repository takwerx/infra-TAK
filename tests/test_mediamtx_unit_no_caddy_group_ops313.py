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
"""MediaMTX must start on a box with no Caddy (ops #313).

The unit used to always say `SupplementaryGroups=caddy`. The `caddy` group only exists once
Caddy is installed, and systemd refuses to start a unit naming a missing group
(status=216/GROUP), so MediaMTX crash-looped on a fresh box. The line is now written only
when the group exists, and added later when Caddy shows up and the stream cert is wired.
"""

import ast
import pathlib
import re
import subprocess
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _const(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError(f'{name} was renamed or removed')


def _src(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _ns(group_exists, files=None):
    """The helpers, wired to a fake `caddy` group and an in-memory unit file."""
    files = {} if files is None else files
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        assert cmd == ['getent', 'group', 'caddy']
        return types.SimpleNamespace(returncode=0 if group_exists else 2)

    ns = {'re': re, 'subprocess': types.SimpleNamespace(run=fake_run),
          '_MEDIAMTX_UNIT_TEXT': _const('_MEDIAMTX_UNIT_TEXT'),
          '_read_priv': lambda p: files[p],
          '_write_priv': lambda p, t: files.__setitem__(p, t)}
    for name in ('_caddy_group_exists', '_mediamtx_unit_with_caddy_group',
                 '_mediamtx_unit_text', '_mediamtx_unit_ensure_caddy_group'):
        exec(compile(_src(name), 'app.py', 'exec'), ns)
    ns['_files'], ns['_calls'] = files, calls
    return ns


def test_base_unit_never_names_the_caddy_group():
    assert 'SupplementaryGroups' not in _const('_MEDIAMTX_UNIT_TEXT')


def test_no_caddy_group_means_no_group_line():
    ns = _ns(group_exists=False)
    txt = ns['_mediamtx_unit_text']()
    assert 'SupplementaryGroups' not in txt and 'User=takwerx' in txt


def test_caddy_group_present_adds_the_line_right_after_user():
    txt = _ns(group_exists=True)['_mediamtx_unit_text']()
    lines = txt.split('\n')
    assert lines[lines.index('User=takwerx') + 1] == 'SupplementaryGroups=caddy'
    assert txt.count('SupplementaryGroups=caddy') == 1


def test_adding_the_line_twice_changes_nothing():
    ns = _ns(group_exists=True)
    once = ns['_mediamtx_unit_text']()
    assert ns['_mediamtx_unit_with_caddy_group'](once) == once


def test_ensure_adds_line_to_old_unit_once_caddy_exists():
    path = '/etc/systemd/system/mediamtx.service'
    ns = _ns(group_exists=True, files={path: _const('_MEDIAMTX_UNIT_TEXT')})
    assert ns['_mediamtx_unit_ensure_caddy_group'](path) is True
    assert 'SupplementaryGroups=caddy' in ns['_files'][path]
    assert ns['_mediamtx_unit_ensure_caddy_group'](path) is False      # nothing left to do


def test_ensure_leaves_unit_alone_without_the_group():
    path = '/etc/systemd/system/mediamtx.service'
    base = _const('_MEDIAMTX_UNIT_TEXT')
    ns = _ns(group_exists=False, files={path: base})
    assert ns['_mediamtx_unit_ensure_caddy_group'](path) is False
    assert ns['_files'][path] == base


def test_ensure_never_raises():
    ns = _ns(group_exists=True, files={})                              # unit file missing
    assert ns['_mediamtx_unit_ensure_caddy_group']('/nope') is False


def test_group_lookup_failure_counts_as_no_group():
    def boom(cmd, **kw):
        raise OSError('no getent')
    ns = _ns(group_exists=True)
    ns['subprocess'] = types.SimpleNamespace(run=boom)
    assert ns['_caddy_group_exists']() is False


def test_deploy_step5_unit_literal_has_no_group_line_and_goes_through_the_guard():
    body = APP[APP.index('# Step 5: Create mediamtx systemd service'):]
    body = body[:body.index('Write web editor Python app')]
    literal = body[body.index('mediamtx_svc = """'):body.index('"""\n', body.index('mediamtx_svc = """') + 20)]
    assert 'User=takwerx' in literal and 'SupplementaryGroups' not in literal
    assert '_mediamtx_unit_with_caddy_group(mediamtx_svc) if _caddy_group_exists()' in body


def test_every_reader_of_the_cert_grants_the_group_when_needed():
    for fn in ('_grant_caddy_cert_read',):
        assert '_mediamtx_unit_ensure_caddy_group()' in _src(fn)
