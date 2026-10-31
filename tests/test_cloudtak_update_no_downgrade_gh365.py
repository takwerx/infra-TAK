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
"""CloudTAK Update never falls back to the old offline pin (gh #365).

Field (ops1, v10.3.3, on-prem): api.github.com answered 403 "rate limit exceeded" and DNS was
flaky, so the release lookup failed. The update then used CLOUDTAK_VETTED_RELEASE (13.54.3),
older than the 13.116.0 running, and the build of that old tag died at `apk add` three times.

Now: the lookup asks `git ls-remote` when the API fails, and Update stops without changing
anything when neither answers. Deploy keeps the offline pin.

app.py cannot be imported in a test, so the functions are cut out of it.
"""

import ast
import pathlib
import re
import subprocess
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_FUNCS = {'_get_cloudtak_latest_release_tag', '_cloudtak_latest_tag_from_git',
          '_get_cloudtak_target_release_tag'}


def _ns(**extra):
    tree = ast.parse(APP)
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in _FUNCS]
    assert {n.name for n in body} == _FUNCS
    import json, os, time
    ns = {'re': re, 'subprocess': subprocess, 'json': json, 'os': os,
          'CLOUDTAK_VETTED_RELEASE': '13.54.3',
          '_cloudtak_release_cache': {'tag': None, 'ts': 0}}
    ns.update(extra)
    exec(compile(ast.Module(body=body, type_ignores=[]), 'app.py', 'exec'), ns)
    return ns


class _Proc:
    def __init__(self, out, rc=0):
        self.stdout, self.returncode, self.stderr = out, rc, ''


LS_REMOTE = '\n'.join([
    'aaa\trefs/tags/v13.9.0',
    'bbb\trefs/tags/v13.117.0',
    'ccc\trefs/tags/v13.116.0',
    'ddd\trefs/tags/v14.0.0-rc.1',
    'eee\trefs/tags/nightly',
])


def _api_down(monkeypatch):
    def boom(req, timeout=None):
        raise OSError('HTTP Error 403: rate limit exceeded')
    monkeypatch.setattr(urllib.request, 'urlopen', boom)


def test_git_lookup_picks_highest_plain_version(monkeypatch):
    ns = _ns()
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: _Proc(LS_REMOTE))
    assert ns['_cloudtak_latest_tag_from_git']() == 'v13.117.0'


def test_git_lookup_failure_is_none(monkeypatch):
    ns = _ns()
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: _Proc('', 128))
    assert ns['_cloudtak_latest_tag_from_git']() is None

    def boom(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 30)
    monkeypatch.setattr(subprocess, 'run', boom)
    assert ns['_cloudtak_latest_tag_from_git']() is None


def test_api_rate_limited_uses_git_tags(monkeypatch):
    ns = _ns()
    _api_down(monkeypatch)
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: _Proc(LS_REMOTE))
    assert ns['_get_cloudtak_latest_release_tag'](use_cache=False) == 'v13.117.0'
    assert ns['_cloudtak_release_cache']['tag'] == 'v13.117.0'


def test_update_gets_none_not_the_old_pin(monkeypatch):
    ns = _ns()
    _api_down(monkeypatch)
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: _Proc('', 128))
    assert ns['_get_cloudtak_target_release_tag'](use_cache=False, allow_fallback=False) is None


def test_deploy_still_falls_back_to_pin_offline(monkeypatch):
    ns = _ns()
    _api_down(monkeypatch)
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: _Proc('', 128))
    assert ns['_get_cloudtak_target_release_tag'](use_cache=False) == 'v13.54.3'


def test_run_cloudtak_update_asks_without_fallback_and_refuses_downgrade():
    src = APP[APP.index('def run_cloudtak_update'):]
    src = src[:src.index('\ndef ', 10)]
    assert 'allow_fallback=False' in src
    assert 'if not release_tag:' in src
    assert 'not downgrading' in src
    # the stop happens before anything touches the tree
    assert src.index('not downgrading') < src.index('Step 2/3')
    assert src.index('if not release_tag:') < src.index('Step 2/3')
