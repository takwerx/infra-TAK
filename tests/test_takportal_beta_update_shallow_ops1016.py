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
"""TAK Portal Update with Beta Features on, on the clone Deploy really makes (ops #1016).

Deploy runs `git clone --depth 1 --branch <release tag>`. That clone only knows its tag
(`remote.origin.fetch = +refs/tags/2.0.14:refs/tags/2.0.14`, no branch ref). The beta branch of
_takportal_update_git ran `git fetch origin main`, which with that refspec only fills FETCH_HEAD
and never creates `origin/main`, so the next line failed with
"fatal: 'origin/main' is not a commit and a branch 'main' cannot be created from it".

These tests run the real function from app.py against a tag-only shallow clone of a real git repo.
"""

import json
import os
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

HELPERS = APP[APP.index('def _takportal_version_tuple(ver):'):APP.index('def _fetch_takportal_latest(')]
GIT = APP[APP.index('def _takportal_git_hint(stderr):'):APP.index('def _takportal_build_settings_dict(')]

_GIT_ENV = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t',
                GIT_COMMITTER_EMAIL='t@t', GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')


def _git(cwd, *args):
    r = subprocess.run(['git', '-C', str(cwd)] + list(args), capture_output=True, text=True, env=_GIT_ENV)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def _pkg(version):
    return json.dumps({'name': 'tak-portal', 'version': version}, indent=2) + '\n'


@pytest.fixture
def upstream(tmp_path):
    """A repo shaped like TAK-Portal: release tag 2.0.14, then main moves on (the beta work)."""
    up = tmp_path / 'upstream'
    up.mkdir()
    _git(up, 'init', '-q', '-b', 'main')
    (up / 'docker-compose.yml').write_text('services:\n  tak-portal:\n    ports:\n      - "3000:3000"\n')
    (up / '.gitignore').write_text('.env\n')
    (up / 'package.json').write_text(_pkg('2.0.14'))
    _git(up, 'add', '-A')
    _git(up, 'commit', '-q', '-m', '2.0.14')
    _git(up, 'tag', '2.0.14')
    (up / 'server.js').write_text('// docker tak server support, unreleased\n')
    _git(up, 'add', '-A')
    _git(up, 'commit', '-q', '-m', 'main work')
    return up


@pytest.fixture
def portal(tmp_path, upstream):
    """~/TAK-Portal exactly as Deploy makes it: shallow, one release tag, no branch ref."""
    pd = tmp_path / 'home' / 'TAK-Portal'
    pd.parent.mkdir()
    subprocess.run(['git', 'clone', '-q', '--depth', '1', '--branch', '2.0.14',
                    'file://' + str(upstream), str(pd)], check=True, env=_GIT_ENV, capture_output=True)
    (pd / '.env').write_text('WEB_UI_PORT=3000\n')
    return pd


def _update_fn(beta=True):
    n = {'os': os, 're': re, 'json': json, 'subprocess': subprocess}
    exec(compile(HELPERS, 'app.py', 'exec'), n)
    n.update(_takportal_beta_mode=lambda: beta,
             _module_checkout_ownership_selfheal=lambda d, plog=None: (False, ''),
             _takportal_release_tag_strict=lambda d, plog=None: '2.0.14')
    exec(compile(GIT, 'app.py', 'exec'), n)
    return n['_takportal_update_git']


def test_fixture_is_the_clone_deploy_makes(portal):
    """Guard the test itself: no branch ref, only the tag refspec (what the box showed)."""
    assert _git(portal, 'config', '--get-all', 'remote.origin.fetch') == '+refs/tags/2.0.14:refs/tags/2.0.14'
    assert _git(portal, 'rev-parse', '--is-shallow-repository') == 'true'
    r = subprocess.run(['git', '-C', str(portal), 'rev-parse', '--verify', '-q', 'origin/main'],
                       capture_output=True, text=True, env=_GIT_ENV)
    assert r.returncode != 0


def test_beta_update_on_a_tag_only_shallow_clone_lands_on_main(portal, upstream):
    r = _update_fn()(str(portal), plog=lambda m: None)
    assert r['ok'] is True, r
    assert r['channel'] == 'beta' and r['ref'] == 'origin/main'
    assert _git(portal, 'rev-parse', 'HEAD') == _git(upstream, 'rev-parse', 'main')
    assert (portal / 'server.js').exists()
    assert (portal / '.env').read_text() == 'WEB_UI_PORT=3000\n'


def test_beta_update_again_follows_main_when_it_moves(portal, upstream):
    fn = _update_fn()
    assert fn(str(portal), plog=lambda m: None)['ok'] is True
    (upstream / 'server.js').write_text('// more beta work\n')
    _git(upstream, 'add', '-A')
    _git(upstream, 'commit', '-q', '-m', 'more main work')
    r = fn(str(portal), plog=lambda m: None)
    assert r['ok'] is True, r
    assert _git(portal, 'rev-parse', 'HEAD') == _git(upstream, 'rev-parse', 'main')


def test_turning_beta_off_goes_back_to_the_release(portal, upstream):
    assert _update_fn(beta=True)(str(portal), plog=lambda m: None)['ok'] is True
    r = _update_fn(beta=False)(str(portal), plog=lambda m: None)
    assert r['ok'] is True, r
    assert _git(portal, 'rev-parse', 'HEAD') == _git(upstream, 'rev-parse', '2.0.14^{commit}')


def test_beta_update_with_unreachable_origin_changes_nothing(portal, tmp_path):
    before = _git(portal, 'rev-parse', 'HEAD')
    _git(portal, 'remote', 'set-url', 'origin', str(tmp_path / 'gone'))
    r = _update_fn()(str(portal), plog=lambda m: None)
    assert r['ok'] is False and 'git fetch origin main failed' in r['error']
    assert _git(portal, 'rev-parse', 'HEAD') == before
