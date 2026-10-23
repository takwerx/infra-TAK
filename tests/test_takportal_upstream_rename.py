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
"""TAK Portal upstream moved AdventureSeeker423 -> ValleyTacticalSolutions (2026-10-22).

New installs clone the new URL; existing clones, whose origin is the old URL, are repointed
before every fetch from origin — Update AND redeploy over an existing checkout. A fork origin
is never touched. The helper runs for real against git repos; the wiring is checked in the
app.py source so a new fetch path can't skip it silently.
"""

import os
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

NEW = 'https://github.com/ValleyTacticalSolutions/TAK-Portal.git'
HELPER = APP[APP.index('def _takportal_repoint_origin('):APP.index('def _takportal_update_git(')]
UPDATE = APP[APP.index('def _takportal_update_git('):APP.index('def _takportal_update_git(') + 12000]
DEPLOY = APP[APP.index('def run_takportal_deploy('):APP.index('def run_takportal_deploy(') + 20000]

_GIT_ENV = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')


def _load():
    ns = {'subprocess': subprocess, 'TAKPORTAL_REPO': NEW}
    exec(HELPER, ns)
    return ns['_takportal_repoint_origin']


def _clone(tmp_path, origin):
    d = tmp_path / 'TAK-Portal'
    subprocess.run(['git', 'init', '-q', str(d)], check=True, env=_GIT_ENV)
    subprocess.run(['git', '-C', str(d), 'remote', 'add', 'origin', origin], check=True, env=_GIT_ENV)
    return d


def _origin(d):
    return subprocess.run(['git', '-C', str(d), 'remote', 'get-url', 'origin'],
                          capture_output=True, text=True, env=_GIT_ENV).stdout.strip()


def test_constant_is_the_new_upstream():
    assert re.search(r'^TAKPORTAL_REPO = "' + re.escape(NEW) + '"$', APP, re.M)


def test_no_old_upstream_url_left():
    # The helper's stock-URL match is the only mention left.
    assert 'github.com/adventureseeker423' not in APP.replace(HELPER, '').lower()


@pytest.mark.parametrize('old', [
    'https://github.com/AdventureSeeker423/TAK-Portal.git',
    'https://github.com/AdventureSeeker423/TAK-Portal',
    'https://github.com/adventureseeker423/tak-portal.git',
    'https://github.com/AdventureSeeker423/TAK-Portal/',
])
def test_stock_old_origin_is_repointed(tmp_path, old):
    d = _clone(tmp_path, old)
    logs = []
    assert _load()(str(d), plog=logs.append) is True
    assert _origin(d) == NEW
    assert any('origin repointed' in m for m in logs)


@pytest.mark.parametrize('origin', [
    NEW,
    'https://github.com/someagency/TAK-Portal.git',
    'git@github.com:someagency/TAK-Portal.git',
    # Contain the old owner/repo path but are not the stock URL: a mirror, another repo.
    'https://git.agency.local/mirrors/AdventureSeeker423/TAK-Portal.git',
    'https://github.com/AdventureSeeker423/TAK-Portal-fork.git',
])
def test_new_or_fork_origin_is_left_alone(tmp_path, origin):
    d = _clone(tmp_path, origin)
    logs = []
    assert _load()(str(d), plog=logs.append) is False
    assert _origin(d) == origin
    assert logs == []


def test_not_a_git_checkout_does_not_raise(tmp_path):
    assert _load()(str(tmp_path / 'missing'), plog=lambda m: None) is False


def test_update_repoints_before_any_fetch_from_origin():
    i = UPDATE.index('_takportal_repoint_origin(portal_dir')
    fetches = [m.start() for m in re.finditer(r"\['fetch', 'origin'", UPDATE)]
    assert fetches and all(i < f for f in fetches)
    # The stable-channel tag pick runs `ls-remote origin`; it is called after the repoint too.
    assert i < UPDATE.index('_takportal_release_tag_strict(portal_dir')


def test_redeploy_over_existing_checkout_repoints_before_fetch():
    i = DEPLOY.index('_takportal_repoint_origin(portal_dir')
    f = DEPLOY.index("'fetch', '--tags', '--force', 'origin'")
    assert DEPLOY.index('if os.path.exists(portal_dir):') < i < f


def test_fresh_install_clones_the_constant():
    assert 'TAKPORTAL_REPO, portal_dir]' in DEPLOY


def test_release_lookups_use_the_new_owner():
    apis = re.findall(r"https://api\.github\.com/repos/([^/]+)/TAK-Portal/releases/latest", APP)
    assert apis and set(apis) == {'ValleyTacticalSolutions'}
