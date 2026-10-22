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
"""TAK Portal Update reports the release it actually installed (GH #214).

Field report (2026-10-21): Update said "Updated from 2.0.14 to GitHub Release 2.0.15. (2.0.14)",
the card kept "v2.0.15 available", and the record read OK 2.0.14 -> 2.0.14. Upstream's 2.0.15
tag ships package.json with `"version": "2.0.14"` and `"beta-version": "2.0.15"` — the checkout
and the rebuild were right, the number was read from a field upstream forgot to bump.

These tests run the real functions from app.py against a real git repo laid out like upstream.
"""

import json
import os
import pathlib
import re
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

HELPERS = APP[APP.index('def _takportal_version_tuple(ver):'):APP.index('def _fetch_takportal_latest(')]
VINFO = APP[APP.index('def _get_takportal_version_info('):APP.index('def _get_takserver_version_info(')]
GIT = APP[APP.index('def _takportal_git_hint(stderr):'):APP.index('def _takportal_build_settings_dict(')]
JOB = APP[APP.index('# ops #72: TAK Portal Update as a background job'):APP.index("@app.route('/api/takportal/deploy'")]

_GIT_ENV = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t',
                GIT_COMMITTER_EMAIL='t@t', GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')


def _git(cwd, *args):
    r = subprocess.run(['git', '-C', str(cwd)] + list(args), capture_output=True, text=True, env=_GIT_ENV)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def _pkg(version, beta):
    return json.dumps({'name': 'tak-portal', 'version': version, 'beta-version': beta}, indent=2) + '\n'


@pytest.fixture
def upstream(tmp_path):
    """A repo shaped like AdventureSeeker423/TAK-Portal around 2.0.14 / 2.0.15."""
    up = tmp_path / 'upstream'
    up.mkdir()
    _git(up, 'init', '-q', '-b', 'main')
    (up / 'docker-compose.yml').write_text('services:\n  tak-portal:\n    ports:\n      - "${WEB_UI_PORT:-3000}:${WEB_UI_PORT:-3000}"\n')
    (up / '.gitignore').write_text('.env\n')
    (up / 'package.json').write_text(_pkg('2.0.14', '2.0.14'))
    _git(up, 'add', '-A')
    _git(up, 'commit', '-q', '-m', '2.0.14')
    _git(up, 'tag', '2.0.14')
    (up / 'package.json').write_text(_pkg('2.0.14', '2.0.15'))   # upstream's real 2.0.15 package.json
    (up / 'server.js').write_text('// 2.0.15\n')
    _git(up, 'add', '-A')
    _git(up, 'commit', '-q', '-m', '2.0.15')
    _git(up, 'tag', '2.0.15')
    return up


@pytest.fixture
def portal(tmp_path, upstream):
    """~/TAK-Portal on 2.0.14, with an operator .env."""
    pd = tmp_path / 'home' / 'TAK-Portal'
    pd.parent.mkdir()
    subprocess.run(['git', 'clone', '-q', str(upstream), str(pd)], check=True, env=_GIT_ENV, capture_output=True)
    _git(pd, 'checkout', '-q', '--force', '2.0.14')
    (pd / '.env').write_text('WEB_UI_PORT=3000\n')
    return pd


def _ns(**extra):
    n = {'os': os, 're': re, 'json': json, 'subprocess': subprocess}
    exec(compile(HELPERS, 'app.py', 'exec'), n)
    n.update(extra)
    return n


def _git_ns(tag='2.0.15', run=None):
    n = _ns(_takportal_beta_mode=lambda: False,
            _module_checkout_ownership_selfheal=lambda d, plog=None: (False, ''),
            _takportal_release_tag_strict=lambda d, plog=None: tag)
    if run is not None:
        n['subprocess'] = types.SimpleNamespace(run=run, CompletedProcess=subprocess.CompletedProcess)
    exec(compile(GIT, 'app.py', 'exec'), n)
    return n


# --------------------------------------------------------------------------- #
# which release is installed
# --------------------------------------------------------------------------- #

def test_the_release_tag_wins_over_a_package_json_upstream_forgot_to_bump(portal):
    n = _ns()
    _git(portal, 'checkout', '-q', '--force', '2.0.15')
    assert json.loads((portal / 'package.json').read_text())['version'] == '2.0.14'
    assert n['_takportal_head_release_tag'](str(portal)) == '2.0.15'
    assert n['_takportal_installed_version'](str(portal)) == '2.0.15'


def test_off_a_release_tag_package_json_is_still_the_answer(portal):
    n = _ns()
    (portal / 'server.js').write_text('// local\n')
    _git(portal, 'add', '-A')
    _git(portal, 'commit', '-q', '-m', 'untagged')
    assert n['_takportal_head_release_tag'](str(portal)) == ''
    assert n['_takportal_installed_version'](str(portal)) == '2.0.14'


def test_no_git_checkout_falls_back_to_package_json(tmp_path):
    pd = tmp_path / 'TAK-Portal'
    pd.mkdir()
    (pd / 'package.json').write_text(_pkg('1.4.9', '2.0.0'))
    n = _ns()
    assert n['_takportal_head_release_tag'](str(pd)) == ''
    assert n['_takportal_installed_version'](str(pd)) == '1.4.9'


def test_non_release_tags_are_ignored(portal):
    _git(portal, 'tag', 'nightly')
    _git(portal, 'tag', 'v2.0.14-rc1')
    assert _ns()['_takportal_head_release_tag'](str(portal)) == '2.0.14'


def _vinfo(monkeypatch, portal, *, channel='release', web=None, latest='2.0.15'):
    monkeypatch.setenv('HOME', str(portal.parent))
    n = _ns(_takportal_web_container=lambda: web, _takportal_beta_channel_state=lambda: channel,
            _sudo_wrap=lambda a: ['true'], _fetch_takportal_latest=lambda fresh=False: latest)
    exec(compile(VINFO, 'app.py', 'exec'), n)
    return n['_get_takportal_version_info']()


def test_the_card_stops_offering_the_release_that_is_already_installed(monkeypatch, portal):
    """ops1's header: '2.0.14 · v2.0.15 available' after a successful update to 2.0.15."""
    _git(portal, 'checkout', '-q', '--force', '2.0.15')
    v = _vinfo(monkeypatch, portal)
    assert v['version'] == '2.0.15' and v['update_available'] is False


def test_a_box_still_on_the_old_release_is_offered_the_new_one(monkeypatch, portal):
    v = _vinfo(monkeypatch, portal)
    assert v['version'] == '2.0.14' and v['update_available'] is True


def test_beta_channel_still_reports_beta_version(monkeypatch, portal):
    _git(portal, 'checkout', '-q', '--force', '2.0.15')
    v = _vinfo(monkeypatch, portal, channel='beta', web={'id': 'abc'})
    assert v['version'] == '2.0.15' and v['channel'] == 'beta'


# --------------------------------------------------------------------------- #
# the update's git step
# --------------------------------------------------------------------------- #

def test_update_moves_to_the_release_and_says_so(portal):
    r = _git_ns()['_takportal_update_git'](str(portal), plog=lambda m: None)
    assert r['ok'] is True, r
    assert (r['from_version'], r['to_version']) == ('2.0.14', '2.0.15')
    assert r['message'] == 'Updated from 2.0.14 to GitHub Release 2.0.15.'
    assert _git(portal, 'rev-parse', 'HEAD') == _git(portal, 'rev-parse', '2.0.15^{commit}')
    assert (portal / '.env').read_text() == 'WEB_UI_PORT=3000\n'


def test_a_second_update_knows_it_is_already_on_the_release(portal):
    n = _git_ns()
    n['_takportal_update_git'](str(portal), plog=lambda m: None)
    r = n['_takportal_update_git'](str(portal), plog=lambda m: None)
    assert r['ok'] is True and r['from_version'] == '2.0.15'
    assert r['message'] == 'Checked out GitHub Release 2.0.15.'


def test_a_failed_tag_fetch_stops_before_anything_moves(portal, tmp_path):
    """The old code ignored the fetch result and checked out whatever local tag had the name."""
    before = _git(portal, 'rev-parse', 'HEAD')
    _git(portal, 'tag', '-d', '2.0.15')
    _git(portal, 'tag', '2.0.15', '2.0.14')                    # a stale local tag of the same name
    _git(portal, 'remote', 'set-url', 'origin', str(tmp_path / 'gone'))
    r = _git_ns()['_takportal_update_git'](str(portal), plog=lambda m: None)
    assert r['ok'] is False
    assert r['error'].startswith('Could not fetch release 2.0.15 from GitHub') and 'Nothing was changed' in r['error']
    assert _git(portal, 'rev-parse', 'HEAD') == before


def test_a_checkout_that_lands_elsewhere_fails_and_puts_the_tree_back(portal):
    before = _git(portal, 'rev-parse', 'HEAD')

    def run(argv, **kw):
        if argv[-3:] == ['checkout', '--force', '2.0.15']:     # "succeeds" without moving HEAD
            return subprocess.CompletedProcess(argv, 0, '', '')
        return subprocess.run(argv, **kw)

    r = _git_ns(run=run)['_takportal_update_git'](str(portal), plog=lambda m: None)
    assert r['ok'] is False and 'did not land on release 2.0.15' in r['error']
    assert 'still running the previous version' in r['error']
    assert _git(portal, 'rev-parse', 'HEAD') == before
    assert (portal / '.env').read_text() == 'WEB_UI_PORT=3000\n'


# --------------------------------------------------------------------------- #
# the update job's verdict
# --------------------------------------------------------------------------- #

def _job(gitr, reported, calls):
    n = {'os': os, 're': re, 'json': json, 'threading': __import__('threading'), 'secrets': __import__('secrets'),
         'time': types.SimpleNamespace(sleep=lambda s: None),
         'app': types.SimpleNamespace(route=lambda *a, **k: (lambda f: f)),
         'login_required': lambda f: f, 'jsonify': lambda d: d,
         '_records_module_update': lambda *a, **k: (lambda f: f),
         '_takportal_update_git': lambda pd: gitr,
         '_patch_takportal_compose_ports': lambda pd=None: calls.append('patch_ports'),
         '_write_takportal_override': lambda: None,
         '_takportal_compose_exposed_ports': lambda pd=None: [],
         'load_settings': lambda: {}, '_takportal_merged_settings_json': lambda s: '{}',
         '_takportal_project_containers': lambda all_states=True: [],
         '_gd_maintenance_begin': lambda *a: None, '_pull_base_images': lambda *a, **k: None,
         '_sudo_wrap': lambda a: a,
         'subprocess': types.SimpleNamespace(
             run=lambda *a, **k: calls.append(a[0]) or subprocess.CompletedProcess(a[0], 0, '', ''),
             TimeoutExpired=subprocess.TimeoutExpired),
         '_ensure_infratak_network_for_portal': lambda: None,
         '_ensure_infratak_network_for_authentik': lambda: None,
         '_takportal_get_existing_settings': lambda: {}, 'TAKPORTAL_AUTHORITATIVE_KEYS': set(),
         '_update_boot_stagger_service': lambda: None,
         '_get_takportal_version_info': lambda: {'version': reported},
         '_takportal_web_running': lambda: True,
         '_mod_result_last': lambda m: None}
    exec(compile(HELPERS, 'app.py', 'exec'), n)
    exec(compile(JOB, 'app.py', 'exec'), n)
    return n['_takportal_run_update']


GITR = {'ok': True, 'channel': 'stable', 'ref': '2.0.15', 'from_version': '2.0.14', 'to_version': '2.0.15',
        'rolled_back': False, 'message': 'Updated from 2.0.14 to GitHub Release 2.0.15.', 'error': ''}


def test_an_update_that_still_reports_the_old_release_is_a_failure():
    """Never OK 2.0.14 -> 2.0.14 when 2.0.15 was the target."""
    body, code = _job(GITR, '2.0.14', [])('/p')
    assert code == 500 and body['success'] is False
    assert body['error'] == 'Update did not reach 2.0.15: TAK Portal reports 2.0.14 after the rebuild.'


def test_an_update_that_reaches_the_release_is_ok():
    body, code = _job(GITR, '2.0.15', [])('/p')
    assert code == 200 and body['success'] is True and body['version'] == '2.0.15'


def test_beta_updates_have_no_release_target_to_check():
    beta = dict(GITR, channel='beta', ref='origin/main', to_version='')
    body, code = _job(beta, '2.0.16', [])('/p')
    assert code == 200 and body['success'] is True


def test_a_git_failure_reapplies_the_loopback_port_patch_and_builds_nothing():
    calls = []
    body, code = _job(dict(GITR, ok=False, error='Could not fetch release 2.0.15 from GitHub: x.'), '2.0.14', calls)('/p')
    assert code == 500 and body['error'].startswith('Could not fetch release')
    assert calls == ['patch_ports']
