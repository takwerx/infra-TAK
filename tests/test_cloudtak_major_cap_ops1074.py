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
"""infra-TAK never offers a CloudTAK major it has not tested (ops #1074).

CloudTAK 14.0.0 came out Nov 22, 2026 and was tested on Ubuntu 22.04, Rocky 9 and ARM, so the cap
is 14. infra-TAK installs "upstream latest" on every channel, so without a cap the next major (15)
would reach a customer's box the day it is released. CLOUDTAK_MAX_MAJOR caps the lookup.

These tests fail without the cap: the lookup returns v15.0.0. (Until the 10.4.6 candidate the cap
was 13 and held 14 back; the same tests then used v14 where this file uses v15.)

app.py cannot be imported in a test, so the functions are cut out of it.
"""

import ast
import io
import json
import os
import pathlib
import re
import subprocess
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_FUNCS = {'_get_cloudtak_latest_release_tag', '_cloudtak_latest_tag_from_git',
          '_get_cloudtak_target_release_tag', '_cloudtak_newest_allowed_tag'}


def _top_level(name):
    for node in ast.parse(APP).body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found in app.py')


def _ns():
    tree = ast.parse(APP)
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in _FUNCS]
    # Tolerant on purpose: on the base code the helper does not exist, and the tests must then
    # fail on the behaviour (v14 offered), not on a missing name.
    assert {'_get_cloudtak_latest_release_tag', '_cloudtak_latest_tag_from_git',
            '_get_cloudtak_target_release_tag'} <= {n.name for n in body}
    ns = {'re': re, 'subprocess': subprocess, 'json': json, 'os': os,
          'CLOUDTAK_VETTED_RELEASE': _top_level('CLOUDTAK_VETTED_RELEASE'),
          'CLOUDTAK_MAX_MAJOR': _top_level('CLOUDTAK_MAX_MAJOR') if 'CLOUDTAK_MAX_MAJOR' in APP else 13,
          '_cloudtak_release_cache': {'tag': None, 'ts': 0}}
    exec(compile(ast.Module(body=body, type_ignores=[]), 'app.py', 'exec'), ns)
    return ns


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Proc:
    def __init__(self, out, rc=0):
        self.stdout, self.returncode, self.stderr = out, rc, ''


# What GitHub says on Nov 22, 2026: 14.0.0 is the newest, 13.x follows. Newest first, as GitHub sends it.
RELEASES = [
    {'tag_name': 'v15.0.0', 'draft': False, 'prerelease': False},
    {'tag_name': 'v14.1.0-rc.1', 'draft': False, 'prerelease': True},
    {'tag_name': 'v14.0.0', 'draft': False, 'prerelease': False},
    {'tag_name': 'v13.128.0', 'draft': False, 'prerelease': False},
    {'tag_name': 'v14.0.1', 'draft': True, 'prerelease': False},
]

LS_REMOTE = '\n'.join([
    'aaa\trefs/tags/v13.127.0',
    'bbb\trefs/tags/v14.0.0',
    'ccc\trefs/tags/v15.0.0',
    'ddd\trefs/tags/v14.0.1',
    'eee\trefs/tags/v14.1.0-rc.1',
    'fff\trefs/tags/nightly',
])


def _api_returns(monkeypatch, payload):
    seen = []

    def fake(req, timeout=None):
        seen.append(req.full_url)
        return _Resp(json.dumps(payload).encode())
    monkeypatch.setattr(urllib.request, 'urlopen', fake)
    return seen


def test_cap_is_the_last_tested_major():
    assert 'CLOUDTAK_MAX_MAJOR' in APP
    assert _top_level('CLOUDTAK_MAX_MAJOR') == 14
    # the offline pin must sit under the cap, or a fresh offline Deploy would break it
    assert int(_top_level('CLOUDTAK_VETTED_RELEASE').split('.')[0]) <= _top_level('CLOUDTAK_MAX_MAJOR')


def test_release_list_never_gives_15(monkeypatch):
    ns = _ns()
    seen = _api_returns(monkeypatch, RELEASES)
    assert ns['_get_cloudtak_latest_release_tag'](use_cache=False) == 'v14.0.0'
    assert ns['_cloudtak_release_cache']['tag'] == 'v14.0.0'
    # it must read the list: GitHub's "latest" answers 14.0.0 and would be unusable
    assert seen and 'releases/latest' not in seen[0]


def test_git_fallback_never_gives_15(monkeypatch):
    ns = _ns()

    def boom(req, timeout=None):
        raise OSError('HTTP Error 403: rate limit exceeded')
    monkeypatch.setattr(urllib.request, 'urlopen', boom)
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: _Proc(LS_REMOTE))
    assert ns['_cloudtak_latest_tag_from_git']() == 'v14.0.1'
    assert ns['_get_cloudtak_latest_release_tag'](use_cache=False) == 'v14.0.1'


def test_list_with_only_15_falls_through_to_git(monkeypatch):
    ns = _ns()
    _api_returns(monkeypatch, [r for r in RELEASES if r['tag_name'].startswith('v15')])
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: _Proc(LS_REMOTE))
    assert ns['_get_cloudtak_latest_release_tag'](use_cache=False) == 'v14.0.1'


def test_update_and_deploy_targets_stay_on_14(monkeypatch):
    ns = _ns()
    _api_returns(monkeypatch, RELEASES)
    assert ns['_get_cloudtak_target_release_tag'](use_cache=False, allow_fallback=False) == 'v14.0.0'
    assert ns['_get_cloudtak_target_release_tag'](use_cache=False) == 'v14.0.0'


def test_offline_deploy_uses_the_pin(monkeypatch):
    ns = _ns()

    def boom(req, timeout=None):
        raise OSError('offline')
    monkeypatch.setattr(urllib.request, 'urlopen', boom)
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: _Proc('', 128))
    assert ns['_get_cloudtak_target_release_tag'](use_cache=False) == 'v' + _top_level('CLOUDTAK_VETTED_RELEASE')


def test_helper_skips_prereleases_and_odd_names():
    pick = _ns().get('_cloudtak_newest_allowed_tag')
    assert pick, '_cloudtak_newest_allowed_tag is missing from app.py'
    assert pick(['v15.0.0', 'v14.0.0', 'v13.10.0', 'v14.1.0-rc.1', 'nightly', '', None]) == 'v14.0.0'
    assert pick(['v15.0.0']) is None
    assert pick([]) is None
