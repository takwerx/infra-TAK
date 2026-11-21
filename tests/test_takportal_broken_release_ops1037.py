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
"""ops #1037: infra-TAK never installs or offers TAK Portal 2.0.38.

TAK Portal 2.0.38 removed the marketplace lint skips from CloudTAK's api lint config, so every
Marketplace install, update and uninstall fails at the CloudTAK build when a plugin ships a
route file that starts with `// @ts-nocheck` (d4h does, in its own repo). The release is on a
named list; installs, the update badge and Update Now use the newest release not on it, and a
box already on it is offered the roll back.

These tests run the real functions from app.py with GitHub's releases API faked.
"""

import io
import json
import pathlib
import re
import urllib.request

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

HELPERS = APP[APP.index('def _takportal_version_tuple(ver):'):APP.index('def _takportal_head_release_tag(')]


def _ns():
    ns = {'json': json, 're': re}
    exec(HELPERS, ns)
    return ns


def _rel(tag, **kw):
    return dict({'tag_name': tag, 'draft': False, 'prerelease': False}, **kw)


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def github(monkeypatch):
    """Fake GitHub: `calls` lists the URLs asked; set `latest` and `listing`."""
    state = {'latest': None, 'listing': [], 'calls': [], 'down': False}

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, 'full_url') else str(req)
        state['calls'].append(url)
        if state['down']:
            raise OSError('network down')
        if url.endswith('/releases/latest'):
            return _Resp(json.dumps(_rel(state['latest'])).encode())
        if '/releases?per_page=' in url:
            return _Resp(json.dumps(state['listing']).encode())
        raise AssertionError('unexpected url ' + url)

    monkeypatch.setattr(urllib.request, 'urlopen', fake_urlopen)
    return state


def test_2_0_38_is_on_the_broken_list_with_the_upstream_issue():
    ns = _ns()
    assert ns['_takportal_release_is_broken']('2.0.38')
    assert ns['_takportal_release_is_broken']('v2.0.38')
    assert not ns['_takportal_release_is_broken']('2.0.37')
    assert not ns['_takportal_release_is_broken']('2.0.39')
    assert not ns['_takportal_release_is_broken']('')
    assert 'TAK-Portal#144' in ns['TAKPORTAL_BROKEN_RELEASES']['2.0.38']


def test_newest_release_listed_as_broken_falls_back_to_the_newest_good_one(github):
    github['latest'] = '2.0.38'
    github['listing'] = [_rel('2.0.38'), _rel('2.0.37'), _rel('2.0.36'),
                         _rel('2.0.99', prerelease=True), _rel('2.0.98', draft=True),
                         _rel('not-a-version')]
    assert _ns()['_takportal_newest_good_release']() == '2.0.37'


def test_a_fixed_release_is_picked_up_without_any_code_change(github):
    github['latest'] = '2.0.39'
    github['listing'] = [_rel('2.0.39'), _rel('2.0.38'), _rel('2.0.37')]
    assert _ns()['_takportal_newest_good_release']() == '2.0.39'
    assert github['calls'] == ['https://api.github.com/repos/ValleyTacticalSolutions/TAK-Portal/releases/latest'], \
        'the normal case must stay one API call'


def test_v_prefixed_broken_tag_is_skipped_and_good_tag_keeps_its_spelling(github):
    github['latest'] = 'v2.0.38'
    github['listing'] = [_rel('v2.0.38'), _rel('v2.0.37')]
    assert _ns()['_takportal_newest_good_release']() == 'v2.0.37'


def test_nothing_usable_gives_none_and_network_errors_raise(github):
    github['latest'] = '2.0.38'
    github['listing'] = [_rel('2.0.38')]
    assert _ns()['_takportal_newest_good_release']() is None
    github['down'] = True
    with pytest.raises(OSError):
        _ns()['_takportal_newest_good_release']()


def _func(name, nxt):
    return APP[APP.index(f'def {name}('):APP.index(nxt)]


def test_every_resolver_uses_the_skip_and_none_reads_releases_latest_directly():
    for name, nxt in (('_takportal_latest_tag', 'def _remote_assist_write_env('),
                      ('_fetch_takportal_latest', 'def _get_takportal_version_info('),
                      ('_takportal_release_tag_strict', 'def _takportal_git_hint(')):
        body = _func(name, nxt)
        assert '_takportal_newest_good_release(' in body, name
        assert 'releases/latest' not in body, f'{name} still asks for the newest release directly'
    # the offline git-tags fallback skips it too
    strict = _func('_takportal_release_tag_strict', 'def _takportal_git_hint(')
    assert '_takportal_release_is_broken(name)' in strict


def test_fetch_latest_returns_the_good_release(github):
    github['latest'] = '2.0.38'
    github['listing'] = [_rel('2.0.38'), _rel('2.0.37')]
    ns = _ns()
    ns['_takportal_upstream_cache'] = {'latest': None, 'ts': 0}
    ns['TAKPORTAL_UPSTREAM_CACHE_TTL'] = 1800
    ns['time'] = __import__('time')
    # the real function, with the module-level names it reads
    src = _func('_fetch_takportal_latest', 'def _get_takportal_version_info(')
    exec(src, ns)
    assert ns['_fetch_takportal_latest'](fresh=True) == '2.0.37'


def test_box_on_the_broken_release_is_offered_the_roll_back():
    vinfo = _func('_get_takportal_version_info', 'def _get_takserver_version_info(')
    # installed broken, latest older: still an update (the roll back)
    assert re.search(r"elif out\['version'\] and _takportal_release_is_broken\(out\['version'\]\):\s*\n\s*"
                     r"out\['update_available'\] = True", vinfo)


def test_update_says_why_it_rolls_back():
    upd = _func('_takportal_update_git', 'def _takportal_build_settings_dict(')
    assert 'is known to break Marketplace plugin installs' in upd
    assert "out['rolled_back'] = True" in upd
