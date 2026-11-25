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
"""A box that has used its 60 unauthenticated GitHub API calls an hour still learns the newest
release (ops #1217).

api.github.com answers HTTP 403 for the rest of the hour. Before this, the Guard Dog "Update
pending" mail was skipped for that run and the Authentik / NetBird / Remote Assist lookups saw
nothing new. The newest-release lookup is now one helper: the github.com /releases/latest
redirect, then the API, then the last answer kept on disk. The functions are cut out of app.py
and run with GitHub faked; the Guard Dog script is run in bash with a fake curl.
"""

import json
import os
import pathlib
import re
import stat
import subprocess
import threading
import time
import types
import urllib.error
import urllib.parse
import urllib.request

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
WATCH = REPO / 'scripts' / 'guarddog' / 'tak-updates-watch.sh'


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?(?=^\S)', APP, re.S | re.M).group(0)


HELPER_CONSTS = ('_GH_LATEST_TTL', '_GH_LATEST_RETRY', '_GH_LATEST_FILE', '_GH_REPO_RE', '_GH_TAG_RE',
                 '_gh_latest_mem', '_gh_latest_lock')
HELPER_FUNCS = ('_gh_latest_from_redirect', '_gh_latest_from_api', '_gh_latest_disk_read',
                '_gh_latest_disk_write', '_gh_latest_release_tag')


class _Resp:
    def __init__(self, url='', body=b''):
        self._url, self._body = url, body

    def geturl(self):
        return self._url

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeGitHub:
    """api.github.com and github.com as the test wants them to answer."""

    def __init__(self):
        self.api = {}          # repo -> tag_name, or an Exception
        self.web = {}          # repo -> release page URL it ends on, or an Exception
        self.calls = []

    def urlopen(self, req, timeout=None):
        url = req.full_url if hasattr(req, 'full_url') else req
        self.calls.append(url)
        m = re.match(r'https://api\.github\.com/repos/([^/]+/[^/]+)/releases/latest$', url)
        if m:
            v = self.api.get(m.group(1), urllib.error.HTTPError(url, 403, 'rate limit exceeded', {}, None))
            if isinstance(v, BaseException):
                raise v
            return _Resp(url, json.dumps({'tag_name': v}).encode())
        m = re.match(r'https://github\.com/([^/]+/[^/]+)/releases/latest$', url)
        if m:
            v = self.web.get(m.group(1), urllib.error.URLError('offline'))
            if isinstance(v, BaseException):
                raise v
            return _Resp(v)
        raise AssertionError('unexpected url ' + url)


@pytest.fixture
def gh(monkeypatch):
    g = FakeGitHub()
    monkeypatch.setattr(urllib.request, 'urlopen', g.urlopen)
    return g


def _helper(tmp_path, **extra):
    n = {'json': json, 'os': os, 're': re, 'time': time, 'threading': threading,
         'urllib': urllib, 'CONFIG_DIR': str(tmp_path), 'tempfile': __import__('tempfile')}
    n.update(extra)
    src = '\n'.join([_const(c) for c in HELPER_CONSTS] + [_cut(f) for f in HELPER_FUNCS])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


def _tag_page(repo, tag):
    return f'https://github.com/{repo}/releases/tag/{tag}'


# --- the helper -----------------------------------------------------------------------------

def test_api_refused_still_names_the_newest_tag(gh, tmp_path):
    """The proof case: 60 of 60 used, API says 403, the release page still answers."""
    gh.web['takwerx/infra-TAK'] = _tag_page('takwerx/infra-TAK', 'v10.4.2-alpha')
    n = _helper(tmp_path)
    assert n['_gh_latest_release_tag']('takwerx/infra-TAK') == 'v10.4.2-alpha'
    # the redirect is asked first: the API's hourly budget is not spent at all
    assert 'api.github.com' not in {urllib.parse.urlparse(c).hostname for c in gh.calls}


def test_tag_with_a_slash_is_kept_whole(gh, tmp_path):
    gh.web['goauthentik/authentik'] = _tag_page('goauthentik/authentik', 'version%2F2026.8.5')
    assert _helper(tmp_path)['_gh_latest_release_tag']('goauthentik/authentik') == 'version/2026.8.5'
    gh.web['goauthentik/authentik'] = _tag_page('goauthentik/authentik', 'version/2026.8.6')
    assert _helper(tmp_path)['_gh_latest_release_tag']('goauthentik/authentik') == 'version/2026.8.6'


def test_api_is_the_second_source_when_the_web_page_fails(gh, tmp_path):
    gh.api['netbirdio/netbird'] = 'v0.82.1'
    assert _helper(tmp_path)['_gh_latest_release_tag']('netbirdio/netbird') == 'v0.82.1'


def test_a_redirect_to_another_repo_is_not_taken(gh, tmp_path):
    gh.web['takwerx/infra-TAK'] = _tag_page('someone/else', 'v9.9.9')
    gh.api['takwerx/infra-TAK'] = 'v10.4.2-alpha'
    assert _helper(tmp_path)['_gh_latest_release_tag']('takwerx/infra-TAK') == 'v10.4.2-alpha'
    gh.api['takwerx/infra-TAK'] = urllib.error.HTTPError('u', 403, 'x', {}, None)
    n = _helper(tmp_path / 'fresh')
    assert n['_gh_latest_release_tag']('takwerx/infra-TAK') is None


def test_a_tag_with_shell_or_newline_characters_is_never_returned(gh, tmp_path):
    for bad in ('v1.0;rm -rf /', 'v1.0\nAUTHENTIK_X=1', 'v1.0 $(id)', '../etc'):
        gh.web['a/b'] = _tag_page('a/b', urllib.request.quote(bad, safe='/'))
        assert _helper(tmp_path)['_gh_latest_release_tag']('a/b') is None, bad
    assert _helper(tmp_path)['_gh_latest_release_tag']('not a repo; rm') is None


def test_ten_minute_cache_then_a_fresh_ask(gh, tmp_path):
    gh.web['a/b'] = _tag_page('a/b', 'v1.0.0')
    n = _helper(tmp_path)
    assert n['_gh_latest_release_tag']('a/b') == 'v1.0.0'
    gh.web['a/b'] = _tag_page('a/b', 'v1.0.1')
    assert n['_gh_latest_release_tag']('a/b') == 'v1.0.0'               # inside 10 minutes
    assert n['_gh_latest_release_tag']('a/b', fresh=True) == 'v1.0.1'   # the page asks for fresh
    n['_gh_latest_mem']['a/b']['ok_at'] -= 601
    n['_gh_latest_mem']['a/b']['try_at'] -= 601
    gh.web['a/b'] = _tag_page('a/b', 'v1.0.2')
    assert n['_gh_latest_release_tag']('a/b') == 'v1.0.2'


def test_last_good_answer_survives_a_failure_and_a_restart(gh, tmp_path):
    gh.web['a/b'] = _tag_page('a/b', 'v1.2.0')
    assert _helper(tmp_path)['_gh_latest_release_tag']('a/b') == 'v1.2.0'
    path = tmp_path / 'github-latest-release.json'
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    gh.web['a/b'] = urllib.error.URLError('down')                        # and the API still says 403
    n = _helper(tmp_path)                                                # new process: memory empty
    assert n['_gh_latest_release_tag']('a/b') == 'v1.2.0'
    # a failed run does not hammer GitHub on every page: one try a minute
    gh.calls.clear()
    assert n['_gh_latest_release_tag']('a/b') == 'v1.2.0'
    n['_gh_latest_mem']['a/b']['ok_at'] -= 601
    assert n['_gh_latest_release_tag']('a/b') == 'v1.2.0' and gh.calls == []


def test_never_a_good_answer_gives_none_not_a_guess(gh, tmp_path):
    assert _helper(tmp_path)['_gh_latest_release_tag']('a/b') is None


def test_unreadable_disk_file_is_ignored(gh, tmp_path):
    (tmp_path / 'github-latest-release.json').write_text('{not json')
    gh.web['a/b'] = _tag_page('a/b', 'v3.0.0')
    assert _helper(tmp_path)['_gh_latest_release_tag']('a/b') == 'v3.0.0'


# --- the callers -----------------------------------------------------------------------------

def test_authentik_latest_with_the_api_refused(gh, tmp_path):
    gh.web['goauthentik/authentik'] = _tag_page('goauthentik/authentik', 'version/2026.8.5')
    n = _helper(tmp_path, _authentik_release_cache={'tag': None, 'ts': 0})
    n['_ak_tag_is_sane'] = lambda t: bool(re.match(r'^\d{4}(\.\d{1,3}){1,3}$', t or ''))
    exec(_cut('_get_authentik_latest_release_tag'), n)
    assert n['_get_authentik_latest_release_tag']() == '2026.8.5'
    # a tag that is not Authentik CalVer never becomes the target (the old rule still holds)
    gh.web['goauthentik/authentik'] = _tag_page('goauthentik/authentik', 'version/evil')
    assert n['_get_authentik_latest_release_tag'](use_cache=False) == '2026.8.5'


def test_netbird_latest_with_the_api_refused(gh, tmp_path):
    gh.web['netbirdio/dashboard'] = _tag_page('netbirdio/dashboard', 'v2.96.0')
    n = _helper(tmp_path, _netbird_release_cache={})
    exec(_cut('_get_netbird_github_latest'), n)
    assert n['_get_netbird_github_latest']('dashboard') == 'v2.96.0'
    gh.web['netbirdio/dashboard'] = urllib.error.URLError('down')
    assert n['_get_netbird_github_latest']('dashboard', use_cache=False) == 'v2.96.0'


def _pending(tmp_path, gh, channel='main', version='10.2.23-alpha', ls_remote=None, rels=None):
    n = _helper(tmp_path, VERSION=version, GITHUB_REPO='takwerx/infra-TAK', subprocess=subprocess,
                urllib=urllib, _git_ls_remote=ls_remote or (lambda *a, **k: None))
    n['_gh_json_cached'] = (lambda url, **k: rels) if not isinstance(rels, Exception) else (lambda url, **k: None)
    src = '\n'.join([_const(c) for c in ('_SECURITY_RELEASE_HEADLINE_RE', '_SECURITY_SECTION_HEADING_RE',
                                         '_MD_MARKS_RE')] +
                    [_cut(f) for f in ('_console_pending_update', '_release_security_summary',
                                       '_security_section_summary', '_release_notes_line')])
    exec(compile(src, 'app.py', 'exec'), n)
    return n['_console_pending_update']({'update_channel': channel})


def test_guard_dog_console_mail_still_names_the_new_release_when_the_api_is_refused(gh, tmp_path):
    """The mail that tells customers about an update must not depend on the API's hourly budget."""
    gh.web['takwerx/infra-TAK'] = _tag_page('takwerx/infra-TAK', 'v10.2.27-alpha')
    rels = [{'tag_name': 'v10.2.27-alpha', 'body': '## Security: Authentik 2026.8.4\n'}]
    item = _pending(tmp_path, gh, rels=rels)
    assert item['target'] == 'v10.2.27-alpha' and item['how'] == 'Console page → Update Now.'
    assert item['security'] == ['v10.2.27-alpha is a security release: Authentik 2026.8.4']


def test_unreadable_release_notes_mean_unknown_never_no_security_fix(gh, tmp_path):
    gh.web['takwerx/infra-TAK'] = _tag_page('takwerx/infra-TAK', 'v10.2.27-alpha')
    item = _pending(tmp_path, gh, rels=RuntimeError('403'))
    assert item['target'] == 'v10.2.27-alpha'
    assert item.get('security_unknown') is True and 'security' not in item


def test_console_mail_with_nothing_readable_raises_so_the_caller_keeps_its_state(gh, tmp_path):
    with pytest.raises(RuntimeError):
        _pending(tmp_path, gh, rels=[])


def test_dev_channel_mail_falls_back_to_git_when_the_api_is_refused(gh, tmp_path, monkeypatch):
    def refused(req, timeout=None):
        raise urllib.error.HTTPError('u', 403, 'rate limit exceeded', {}, None)
    monkeypatch.setattr(urllib.request, 'urlopen', refused)
    sha = 'a' * 40
    item = _pending(tmp_path, gh, channel='dev',
                    ls_remote=lambda *a, **k: {'refs/heads/dev': sha})
    assert item['target'] == 'dev@aaaaaaa'
    with pytest.raises(urllib.error.HTTPError):
        _pending(tmp_path, gh, channel='dev')


def test_update_now_resolves_the_newest_tag_when_the_api_is_refused(gh, tmp_path, monkeypatch):
    """Update Now used to fall back to origin/main when this returned None."""
    def refused(req, timeout=None):
        raise urllib.error.HTTPError('u', 403, 'rate limit exceeded', {}, None)
    monkeypatch.setattr(urllib.request, 'urlopen', refused)
    refs = {'refs/tags/v10.4.0-alpha': 'a', 'refs/tags/v10.4.2-alpha': 'b', 'refs/tags/v10.4.2-alpha^{}': 'c',
            'refs/tags/v10.10.0-alpha': 'd', 'refs/tags/not-a-version': 'e'}
    n = {'json': json, 'GITHUB_REPO': 'takwerx/infra-TAK', '_git_ls_remote': lambda *a, **k: refs}
    exec(_cut('_fetch_latest_tag_name') + '\n' + _cut('_fetch_latest_tag_name_from_git'), n)
    assert n['_fetch_latest_tag_name']() == 'v10.10.0-alpha'
    n['_git_ls_remote'] = lambda *a, **k: None
    assert n['_fetch_latest_tag_name']() is None


def test_no_release_lookup_goes_to_the_api_outside_the_helper():
    """New code must use _gh_latest_release_tag, not its own releases/latest call."""
    calls = [m.start() for m in re.finditer(r"api\.github\.com/repos/[^'\"]*releases/latest", APP)]
    helper = APP.index('def _gh_latest_from_api(')
    helper_end = APP.index('\ndef ', helper + 10)
    outside = [APP.count('\n', 0, c) + 1 for c in calls if not helper < c < helper_end]
    # MediaMTX goes through _gh_json_cached (30 minutes, last good answer). Remote Assist keeps
    # its own call: it has its own cache and back-off and checks the tag against the tag's VERSION.
    lines = APP.split('\n')
    assert all('_gh_json_cached(' in lines[ln - 1] or 'REMOTE_ASSIST_API_REPO' in lines[ln - 1]
               for ln in outside), outside


# --- Guard Dog's watcher ----------------------------------------------------------------------

def _watch_functions():
    sh = WATCH.read_text()
    out = []
    for name in ('latest_tag_redirect', 'latest_tag', 'latest_infratak'):
        out.append(re.search(rf'^{name}\(\) \{{\n.*?^\}}\n', sh, re.S | re.M).group(0))
    return '\n'.join(out)


def _run_watch(tmp_path, call, web_location, api_status=22):
    """Run one watcher function with a fake curl: api.github.com is refused, github.com answers."""
    fake = tmp_path / 'bin'
    fake.mkdir(exist_ok=True)
    curl = fake / 'curl'
    curl.write_text(f'''#!/bin/bash
url="${{@: -1}}"
case "$url" in
  https://api.github.com/*) echo '{{"message":"API rate limit exceeded"}}'; exit {api_status} ;;
  https://github.com/*/releases/latest)
    printf 'HTTP/2 302\\r\\n'
    [ -n "{web_location}" ] && printf 'location: {web_location}\\r\\n'
    printf '\\r\\n'; exit 0 ;;
esac
exit 7
''')
    curl.chmod(0o755)
    script = f'CURL_TIMEOUT=5\n{_watch_functions()}\n{call}\n'
    r = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=30,
                       env={**os.environ, 'PATH': f'{fake}:{os.environ["PATH"]}'})
    return r.stdout.strip()


def test_watcher_names_the_newest_release_when_the_api_says_403(tmp_path):
    loc = 'https://github.com/takwerx/infra-TAK/releases/tag/v10.4.2-alpha'
    assert _run_watch(tmp_path, 'latest_infratak', loc) == '10.4.2-alpha'
    loc = 'https://github.com/goauthentik/authentik/releases/tag/version/2026.8.5'
    assert _run_watch(tmp_path, 'latest_tag goauthentik/authentik', loc) == '2026.8.5'
    # a relative Location (GitHub sends both shapes) is read the same way
    assert _run_watch(tmp_path, 'latest_tag bluenviron/mediamtx',
                      '/bluenviron/mediamtx/releases/tag/v1.18.1') == '1.18.1'


def test_watcher_ignores_a_redirect_to_another_repo_or_a_odd_tag(tmp_path):
    assert _run_watch(tmp_path, 'latest_tag bluenviron/mediamtx',
                      'https://github.com/someone/else/releases/tag/v9.9.9') == ''
    assert _run_watch(tmp_path, 'latest_tag bluenviron/mediamtx',
                      'https://github.com/bluenviron/mediamtx/releases/tag/v1;touch$IFS/tmp/x') == ''
    assert _run_watch(tmp_path, 'latest_tag bluenviron/mediamtx', '') == ''


def test_watcher_still_prefers_nothing_over_a_wrong_answer_when_both_fail(tmp_path):
    assert _run_watch(tmp_path, 'latest_infratak', '') == ''
