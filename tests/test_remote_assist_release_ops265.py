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
"""Remote Assist follows upstream's newest verified release, never main (ops #234 / #265).

Deploy and Update used to follow upstream `main`, so whatever upstream published there next was
built and run on every box at its next Update, unreviewed (ops #234 pinned one commit instead).
Now both follow upstream's newest PUBLISHED RELEASE, like TAK Portal, with three guards: the tag
must be a plain version, the tag's own VERSION file must equal it (upstream's eud_3.3.0 and
eud_3.4.0 tags pointed at the v3.1.4 commit on 2026-10-26), and a checkout already newer than
the target is never downgraded. With no verified release (offline, broken tag) the reviewed
floor REMOTE_ASSIST_SHA is installed, and the floor is never an update target.
"""

import builtins
import json
import os
import re
import types
import urllib.request

import pytest

REPO = __import__('pathlib').Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _const(name):
    return re.search(rf'^{name} = "([^"]+)"', APP, re.M).group(1)


FLOOR = _const('REMOTE_ASSIST_SHA')
FLOOR_VERSION = _const('REMOTE_ASSIST_PIN_VERSION')
URL = _const('REMOTE_ASSIST_REPO')
API_REPO = _const('REMOTE_ASSIST_API_REPO')
OTHER = 'a017dbb' + '0' * 33
TAG_SHA = '56815a8' + '0' * 33
REL = {'tag': 'eud_3.4.1', 'version': '3.4.1'}


def _func(name):
    start = APP.index(f'def {name}(')
    m = re.compile(r'^(?:def |@|[A-Za-z_])', re.M).search(APP, APP.index('\n', start) + 1)
    return APP[start:m.start()]


def _r(rc=0, out='', err=''):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


class FakeGit:
    """`git -C <dir> ...` stand-in. `head` is HEAD before the reset. A successful reset moves
    HEAD to the commit it was given (or `lands_on`) and writes `version` into the VERSION file."""

    def __init__(self, ra_dir='', head=OTHER, fetch_ok=True, reset_ok=True, lands_on=None,
                 dirty='', known=(FLOOR, TAG_SHA), version=None, tag_sha=TAG_SHA):
        self.ra_dir, self.head, self.fetch_ok, self.reset_ok = ra_dir, head, fetch_ok, reset_ok
        self.lands_on, self.dirty, self.known, self.version = lands_on, dirty, known, version
        self.tag_sha, self.calls = tag_sha, []

    def run(self, argv, **kw):
        assert argv[:2] == ['git', '-C'], argv
        args = tuple(argv[3:])
        self.calls.append(args)
        if args == ('rev-parse', 'HEAD'):
            return _r(out=self.head + '\n')
        if args[:3] == ('rev-parse', '--verify', '-q'):
            t = args[3]
            sha = self.tag_sha if t.endswith('^{commit}') else t
            return _r(out=sha + '\n') if sha in self.known else _r(1)
        if args[0] == 'remote':
            return _r()
        if args[0] == 'fetch':
            return _r() if self.fetch_ok else _r(128, err='fatal: unable to access github.com')
        if args[0] == 'reset':
            if not self.reset_ok:
                return _r(128, err=f'fatal: Could not parse object {args[-1]}')
            self.head = self.lands_on or args[-1]
            if self.version is not None:
                with open(os.path.join(self.ra_dir, 'VERSION'), 'w') as f:
                    f.write(self.version + '\n')
            return _r(out=f'HEAD is now at {self.head[:7]} Release\n')
        if args[0] == 'status':
            return _r(out=self.dirty)
        raise AssertionError(f'unexpected git call {args}')


def _ns(fake_sp, **extra):
    real_import = builtins.__import__

    def imp(name, *a, **kw):
        return fake_sp if name == 'subprocess' else real_import(name, *a, **kw)

    n = {'__builtins__': dict(vars(builtins), __import__=imp), 'os': os, 're': re, 'json': json,
         'REMOTE_ASSIST_SHA': FLOOR, 'REMOTE_ASSIST_PIN_VERSION': FLOOR_VERSION,
         'REMOTE_ASSIST_REPO': URL, 'REMOTE_ASSIST_API_REPO': API_REPO,
         'TAKPORTAL_UPSTREAM_CACHE_TTL': 600, **extra}
    n['_REMOTE_ASSIST_TAG_RE'] = re.compile(re.search(
        r"^_REMOTE_ASSIST_TAG_RE = re\.compile\((r'[^']+')\)", APP, re.M).group(1)[2:-1])
    n['_remote_assist_upstream_cache'] = {'ts': 0, 'release': None}
    for f in ('_remote_assist_read_version_file', '_remote_assist_version_tuple',
              '_remote_assist_latest_release', '_remote_assist_checkout_release',
              '_get_remote_assist_version_info'):
        if f not in extra:
            exec(compile(_func(f), 'app.py', 'exec'), n)
    return n


def _clone(tmp_path, version=None):
    d = tmp_path / 'eud-remote-assist'
    (d / '.git').mkdir(parents=True)
    if version:
        (d / 'VERSION').write_text(version + '\n')
    return str(d)


# ── the floor itself ────────────────────────────────────────────────────────────────────────

def test_floor_is_a_full_sha_and_a_release():
    assert re.fullmatch(r'[0-9a-f]{40}', FLOOR)
    assert re.fullmatch(r'\d+\.\d+\.\d+', FLOOR_VERSION)
    assert URL == 'https://github.com/cfd2474/EUD_Remote_Assist_Portal.git'
    assert API_REPO == 'cfd2474/EUD_Remote_Assist_Portal'


# ── _remote_assist_latest_release ───────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, body):
        self._b = body.encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return self._b if n < 0 else self._b[:n]


def _upstream(monkeypatch, tag, version_file, calls=None, boom=None):
    def urlopen(req, timeout=None):
        if calls is not None:
            calls.append(req.full_url)
        if boom:
            raise boom
        if req.full_url.endswith('/releases/latest'):
            return _Resp(json.dumps({'tag_name': tag}))
        assert req.full_url.endswith(f'/refs/tags/{tag}/VERSION'), req.full_url
        return _Resp(version_file)

    monkeypatch.setattr(urllib.request, 'urlopen', urlopen)


@pytest.mark.parametrize('tag,ver', [('eud_3.4.1', '3.4.1'), ('v3.5.0', '3.5.0'), ('3.4.2', '3.4.2')])
def test_a_release_whose_tag_holds_its_own_version_is_used(monkeypatch, tag, ver):
    _upstream(monkeypatch, tag, ver + '\n')
    assert _ns(None)['_remote_assist_latest_release'](fresh=True) == {'tag': tag, 'version': ver}


def test_a_tag_that_points_at_the_wrong_commit_is_ignored(monkeypatch):
    # upstream's eud_3.4.0 held the v3.1.4 commit on 2026-10-26
    _upstream(monkeypatch, 'eud_3.4.0', '3.1.4\n')
    assert _ns(None)['_remote_assist_latest_release'](fresh=True) is None


@pytest.mark.parametrize('tag', ['main', 'eud_3.4.1-rc1', 'eud_3.4', '../../x', 'eud_3.4.1; rm -rf /', ''])
def test_a_tag_that_is_not_a_plain_version_is_ignored(monkeypatch, tag):
    calls = []
    _upstream(monkeypatch, tag, '3.4.1\n', calls)
    assert _ns(None)['_remote_assist_latest_release'](fresh=True) is None
    assert len(calls) == 1   # never fetched a VERSION file for a tag that is not a version


def test_unreachable_github_is_none_not_the_floor(monkeypatch):
    _upstream(monkeypatch, 'eud_3.4.1', '3.4.1', boom=OSError('network is unreachable'))
    assert _ns(None)['_remote_assist_latest_release'](fresh=True) is None


def test_the_answer_is_cached_and_fresh_bypasses_it(monkeypatch):
    calls = []
    _upstream(monkeypatch, 'eud_3.4.1', '3.4.1', calls)
    n = _ns(None)
    assert n['_remote_assist_latest_release']() == REL
    assert n['_remote_assist_latest_release']() == REL
    assert len(calls) == 2            # one releases call + one VERSION call, then the cache
    n['_remote_assist_latest_release'](fresh=True)
    assert len(calls) == 4


def test_a_failed_lookup_backs_off_for_the_ttl(monkeypatch):
    calls = []
    _upstream(monkeypatch, 'x', '', calls, boom=OSError('down'))
    n = _ns(None)
    assert n['_remote_assist_latest_release']() is None
    assert n['_remote_assist_latest_release']() is None
    assert len(calls) == 1


# ── _remote_assist_checkout_release ─────────────────────────────────────────────────────────

def _checkout(tmp_path, git, release, installed=None):
    d = _clone(tmp_path, installed)
    git.ra_dir = d
    n = _ns(types.SimpleNamespace(run=git.run), _remote_assist_latest_release=lambda fresh=False: release)
    log = []
    return n['_remote_assist_checkout_release'](d, log.append), log, git


def test_checks_out_the_release_tag_and_verifies_it(tmp_path):
    (head, version), log, g = _checkout(tmp_path, FakeGit(version='3.4.1'), REL)
    assert (head, version) == (TAG_SHA, '3.4.1')
    assert ('remote', 'set-url', 'origin', URL) in g.calls
    assert ('fetch', '-q', '--depth=1', 'origin', '+refs/tags/eud_3.4.1:refs/tags/eud_3.4.1') in g.calls
    assert ('reset', '--hard', TAG_SHA) in g.calls
    assert ('status', '--porcelain', '--untracked-files=no') in g.calls
    assert not any('main' in a or a == 'pull' for c in g.calls for a in c)
    assert any('v3.4.1' in m and 'eud_3.4.1' in m and '✓' in m for m in log)


def test_without_a_verified_release_it_installs_the_floor(tmp_path):
    (head, version), log, g = _checkout(tmp_path, FakeGit(version=FLOOR_VERSION), None)
    assert (head, version) == (FLOOR, FLOOR_VERSION)
    assert ('fetch', '-q', '--depth=1', 'origin', FLOOR) in g.calls
    assert ('reset', '--hard', FLOOR) in g.calls
    assert any('floor' in m for m in log)


def test_offline_box_that_already_holds_the_target_still_lands_on_it(tmp_path):
    (head, _v), log, _g = _checkout(tmp_path, FakeGit(fetch_ok=False, version=FLOOR_VERSION), None)
    assert head == FLOOR
    assert any('⚠ git fetch' in m for m in log)


def test_a_release_the_clone_cannot_resolve_stops_before_anything_is_built(tmp_path):
    with pytest.raises(RuntimeError, match='could not find the release'):
        _checkout(tmp_path, FakeGit(fetch_ok=False, known=()), REL)


def test_a_failed_reset_stops_before_anything_is_built(tmp_path):
    with pytest.raises(RuntimeError, match='could not check out'):
        _checkout(tmp_path, FakeGit(reset_ok=False), REL)


def test_head_must_be_the_target(tmp_path):
    with pytest.raises(RuntimeError, match='expected the release'):
        _checkout(tmp_path, FakeGit(lands_on=OTHER, version='3.4.1'), REL)


def test_the_checked_out_version_file_must_say_the_target_version(tmp_path):
    with pytest.raises(RuntimeError, match=r'holds v3\.1\.4, expected v3\.4\.1'):
        _checkout(tmp_path, FakeGit(version='3.1.4'), REL)


def test_tracked_files_must_match_the_target(tmp_path):
    with pytest.raises(RuntimeError, match='does not match'):
        _checkout(tmp_path, FakeGit(dirty=' M server/src/index.ts\n', version='3.4.1'), REL)


def test_a_newer_checkout_is_not_downgraded_to_a_release(tmp_path):
    g = FakeGit(version='3.4.1')
    with pytest.raises(RuntimeError, match='not downgrading'):
        _checkout(tmp_path, g, {'tag': 'eud_3.4.0', 'version': '3.4.0'}, installed='3.4.1')
    assert not any(c[0] in ('fetch', 'reset') for c in g.calls)


def test_a_newer_checkout_is_not_downgraded_to_the_floor(tmp_path):
    g = FakeGit(version=FLOOR_VERSION)
    with pytest.raises(RuntimeError, match='not downgrading'):
        _checkout(tmp_path, g, None, installed='3.4.1')
    assert not any(c[0] in ('fetch', 'reset') for c in g.calls)


def test_updating_from_the_floor_to_a_newer_release_moves_forward(tmp_path):
    (head, version), _l, _g = _checkout(tmp_path, FakeGit(head=FLOOR, version='3.4.1'), REL, installed=FLOOR_VERSION)
    assert (head, version) == (TAG_SHA, '3.4.1')


# ── wiring: Deploy and Update both follow the release, never main ──────────────────────────

@pytest.mark.parametrize('fn', ['_run_remote_assist_deploy', '_run_remote_assist_update'])
def test_deploy_and_update_follow_the_release(fn):
    body = _func(fn)
    assert '_remote_assist_checkout_release(ra_dir, plog)' in body
    assert '_remote_assist_checkout_pin' not in body
    assert 'origin/main' not in body
    assert "'pull'" not in body
    assert "'fetch', 'origin', 'main'" not in body


def test_fresh_clone_does_not_check_out_main():
    assert "['git', 'clone', '--depth=1', '--no-checkout', REMOTE_ASSIST_REPO, ra_dir]" \
        in _func('_run_remote_assist_deploy')


def test_the_tag_is_validated_before_it_reaches_git():
    body = _func('_remote_assist_latest_release')
    assert body.index('_REMOTE_ASSIST_TAG_RE.match(tag)') < body.index('raw.githubusercontent.com')
    assert re.search(r"^_REMOTE_ASSIST_TAG_RE = re\.compile\(r'\^", APP, re.M)


# ── the update notice compares against the newest verified release ─────────────────────────

def _vinfo(tmp_path, head, version, release, settings=None):
    d = _clone(tmp_path, version)

    def run(argv, **kw):
        assert argv == ['git', 'rev-parse', 'HEAD'] and kw.get('cwd') == d, argv
        return _r(out=head + '\n') if head else _r(128)

    n = _ns(types.SimpleNamespace(run=run), REMOTE_ASSIST_INSTALL_DIR=d,
            load_settings=lambda: dict(settings or {}),
            _remote_assist_latest_release=lambda fresh=False: release,
            _get_remote_assist_running_version=lambda: version or '')
    return n['_get_remote_assist_version_info'](fresh=True)


def test_on_the_newest_release_is_current(tmp_path):
    info = _vinfo(tmp_path, TAG_SHA, '3.4.1', REL)
    assert info['is_current'] and not info['update_available']
    assert info['latest'] == '3.4.1' and info['latest_tag'] == 'eud_3.4.1'


def test_an_older_release_is_offered_the_newest(tmp_path):
    info = _vinfo(tmp_path, OTHER, '3.1.4', REL)
    assert info['update_available'] and not info['is_current']
    assert info['latest'] == '3.4.1'


def test_a_newer_checkout_is_not_offered_a_downgrade(tmp_path):
    info = _vinfo(tmp_path, OTHER, '3.5.0', REL)
    assert not info['update_available'] and not info['is_current']


def test_without_a_verified_release_the_floor_is_never_an_update_target(tmp_path):
    # offline, or the newest tag is broken: a box at or above the floor is not offered anything
    for ver in (FLOOR_VERSION, '3.4.1'):
        info = _vinfo(tmp_path / ver, OTHER, ver, None)
        assert not info['update_available']
        assert info['latest'] == FLOOR_VERSION and info['latest_tag'] is None


def test_a_box_below_the_floor_is_offered_the_floor_when_offline(tmp_path):
    assert _vinfo(tmp_path, OTHER, '3.0.2', None)['update_available']


def test_no_github_call_on_the_page_render():
    # the page renders from the cached lookup; only the Update path forces a fresh one
    assert '_get_remote_assist_version_info(fresh=True) if ra.get' not in APP
