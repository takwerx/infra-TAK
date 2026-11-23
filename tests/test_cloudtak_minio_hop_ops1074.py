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
"""A box with the old MinIO folder stops at 13.x before CloudTAK 14 (ops #1074).

CloudTAK 14.0.0 removed `cloudtak.sh migrate-store` and the MinIO compose services that infra-TAK's
MinIO -> Garage move runs from the checked-out tree. An Update of a box that still has
~/CloudTAK/.docker-store to 14.0.0 built for about 10 minutes, failed at "Garage store setup failed"
and rolled back (box test, Nov 22). So such a box must go to the newest 13.x first, which moves the
files and archives the folder; the next Update then goes on to 14.

These tests raise the cap to 14 (what the 10.4.6 candidate does) and check the hop. They fail on the
code before this change: the hop helper does not exist, and Update, Deploy and the card ask for 14.

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
          '_cloudtak_newest_allowed_tag', '_cloudtak_tag_major', '_cloudtak_tag_for_minio_store'}


def _ns(cap=14):
    tree = ast.parse(APP)
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in _FUNCS]
    assert '_cloudtak_tag_for_minio_store' in {n.name for n in body}, 'the hop helper is missing from app.py'
    ns = {'re': re, 'subprocess': subprocess, 'json': json, 'os': os,
          'CLOUDTAK_MAX_MAJOR': cap, 'CLOUDTAK_MINIO_HOP_MAJOR': 13,
          '_cloudtak_release_cache': {'tag': None, 'ts': 0}}
    exec(compile(ast.Module(body=body, type_ignores=[]), 'app.py', 'exec'), ns)
    return ns


def _func_src(name):
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found')


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


RELEASES = [
    {'tag_name': 'v14.0.0', 'draft': False, 'prerelease': False},
    {'tag_name': 'v13.128.0', 'draft': False, 'prerelease': False},
    {'tag_name': 'v13.127.0', 'draft': False, 'prerelease': False},
]


def _api(monkeypatch, payload=RELEASES):
    monkeypatch.setattr(urllib.request, 'urlopen', lambda req, timeout=None: _Resp(json.dumps(payload).encode()))


def test_minio_box_stops_at_newest_13(monkeypatch):
    ns = _ns()
    _api(monkeypatch)
    assert ns['_cloudtak_tag_for_minio_store']('v14.0.0', True) == ('v13.128.0', True)


def test_box_without_the_old_folder_goes_straight_to_14(monkeypatch):
    ns = _ns()
    _api(monkeypatch)
    assert ns['_cloudtak_tag_for_minio_store']('v14.0.0', False) == ('v14.0.0', False)


def test_13_target_is_never_changed(monkeypatch):
    ns = _ns()
    _api(monkeypatch)
    assert ns['_cloudtak_tag_for_minio_store']('v13.128.0', True) == ('v13.128.0', False)


def test_unreadable_13_lookup_gives_none_so_the_caller_stops(monkeypatch):
    ns = _ns()

    def boom(req, timeout=None):
        raise OSError('offline')
    monkeypatch.setattr(urllib.request, 'urlopen', boom)
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: type('P', (), {'stdout': '', 'stderr': '', 'returncode': 128})())
    assert ns['_cloudtak_tag_for_minio_store']('v14.0.0', True) == (None, True)


def test_the_13_stop_is_not_cached_as_the_latest(monkeypatch):
    ns = _ns()
    _api(monkeypatch)
    ns['_cloudtak_tag_for_minio_store']('v14.0.0', True)
    assert ns['_cloudtak_release_cache']['tag'] is None
    assert ns['_get_cloudtak_latest_release_tag'](use_cache=False) == 'v14.0.0'


def test_lower_cap_still_wins(monkeypatch):
    # the 13 cap of 10.4.5 is untouched: the hop never lifts it
    ns = _ns(cap=13)
    _api(monkeypatch)
    assert ns['_get_cloudtak_latest_release_tag'](use_cache=False) == 'v13.128.0'
    assert ns['_cloudtak_tag_for_minio_store']('v13.128.0', True) == ('v13.128.0', False)


def _before(src, first, then):
    a, b = src.find(first), src.find(then)
    assert a != -1, f'{first!r} missing'
    assert b != -1, f'{then!r} missing'
    assert a < b, f'{first!r} must come before {then!r}'


def test_update_decides_before_anything_is_checked_out_or_built():
    src = _func_src('run_cloudtak_update')
    _before(src, '_cloudtak_tag_for_minio_store(', 'Step 2/3: Checking out')
    _before(src, '_cloudtak_tag_for_minio_store(', '_mod_result_versions(')
    assert 'newest 13.x release could not be looked up' in src


def test_deploy_local_and_remote_use_the_hop():
    src = _func_src('run_cloudtak_deploy')
    assert src.count('_cloudtak_tag_for_minio_store(') == 2
    first, last = src.find('_cloudtak_tag_for_minio_store('), src.rfind('_cloudtak_tag_for_minio_store(')
    # remote hop comes before the remote checkout; local hop before the local in-place checkout
    assert first < src.find('_cloudtak_remote_reclone_sh(remote_release_tag)')
    assert last < src.find("checkout -f {release_tag}", last)
    assert 'newest 13.x release could not be looked up' in src


def test_card_names_the_13_stop_for_a_minio_box():
    src = _func_src('_get_cloudtak_version_info')
    assert '_cloudtak_tag_for_minio_store(' in src
    _before(src, '_cloudtak_tag_for_minio_store(', "out['latest'] =")
