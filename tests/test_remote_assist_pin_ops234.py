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
"""Remote Assist is pinned to a reviewed upstream commit (ops #234).

Deploy and Update used to follow upstream `main` (clone --depth=1 / fetch main + reset --hard
origin/main), so whatever upstream published there next was built and run on every box at its
next Update, unreviewed. Now both check out REMOTE_ASSIST_SHA, verify HEAD and the tracked
files against it, refuse to downgrade a checkout that is already newer, and the update notice
compares against the pin instead of asking GitHub what main is.
"""

import builtins
import os
import re
import types

import pytest

REPO = __import__('pathlib').Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _const(name):
    return re.search(rf'^{name} = "([^"]+)"', APP, re.M).group(1)


PIN = _const('REMOTE_ASSIST_SHA')
PIN_VERSION = _const('REMOTE_ASSIST_PIN_VERSION')
URL = _const('REMOTE_ASSIST_REPO')
OTHER = 'a017dbb' + '0' * 33


def _func(name):
    start = APP.index(f'def {name}(')
    m = re.compile(r'^(?:def |@|[A-Za-z_])', re.M).search(APP, APP.index('\n', start) + 1)
    return APP[start:m.start()]


def _r(rc=0, out='', err=''):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


class FakeGit:
    """`git -C <dir> ...` stand-in. `head` is HEAD before the reset; the reset moves it to the
    pin unless `reset_ok` is False; `lands_on` overrides where a successful reset leaves HEAD."""

    def __init__(self, head=OTHER, fetch_ok=True, reset_ok=True, lands_on=PIN, dirty=''):
        self.head, self.fetch_ok, self.reset_ok = head, fetch_ok, reset_ok
        self.lands_on, self.dirty, self.calls = lands_on, dirty, []

    def run(self, argv, **kw):
        assert argv[:2] == ['git', '-C'], argv
        args = tuple(argv[3:])
        self.calls.append(args)
        if args == ('rev-parse', 'HEAD'):
            return _r(out=self.head + '\n')
        if args[0] == 'remote':
            return _r()
        if args[0] == 'fetch':
            return _r() if self.fetch_ok else _r(128, err='fatal: unable to access github.com')
        if args[0] == 'reset':
            if not self.reset_ok:
                return _r(128, err=f'fatal: Could not parse object {args[-1]}')
            self.head = self.lands_on
            return _r(out=f'HEAD is now at {self.head[:7]} Release v{PIN_VERSION}\n')
        if args[0] == 'status':
            return _r(out=self.dirty)
        raise AssertionError(f'unexpected git call {args}')


def _ns(fake_sp, **extra):
    real_import = builtins.__import__

    def imp(name, *a, **kw):
        return fake_sp if name == 'subprocess' else real_import(name, *a, **kw)

    n = {'__builtins__': dict(vars(builtins), __import__=imp), 'os': os,
         'REMOTE_ASSIST_SHA': PIN, 'REMOTE_ASSIST_PIN_VERSION': PIN_VERSION,
         'REMOTE_ASSIST_REPO': URL, **extra}
    for f in ('_remote_assist_read_version_file', '_remote_assist_version_tuple',
              '_remote_assist_checkout_pin', '_get_remote_assist_version_info'):
        exec(compile(_func(f), 'app.py', 'exec'), n)
    return n


def _clone(tmp_path, version=None):
    d = tmp_path / 'eud-remote-assist'
    (d / '.git').mkdir(parents=True)
    if version:
        (d / 'VERSION').write_text(version + '\n')
    return str(d)


# ── the pin itself ──────────────────────────────────────────────────────────────────────────

def test_pin_is_a_full_sha_and_a_release():
    assert re.fullmatch(r'[0-9a-f]{40}', PIN)
    assert re.fullmatch(r'\d+\.\d+\.\d+', PIN_VERSION)
    assert URL == 'https://github.com/cfd2474/EUD_Remote_Assist_Portal.git'


# ── _remote_assist_checkout_pin ─────────────────────────────────────────────────────────────

def test_checks_out_the_pin_by_sha_and_verifies_it(tmp_path):
    g, log = FakeGit(), []
    n = _ns(types.SimpleNamespace(run=g.run))
    assert n['_remote_assist_checkout_pin'](_clone(tmp_path, PIN_VERSION), log.append) == PIN
    assert ('remote', 'set-url', 'origin', URL) in g.calls
    assert ('fetch', '-q', '--depth=1', 'origin', PIN) in g.calls
    assert ('reset', '--hard', PIN) in g.calls
    assert ('status', '--porcelain', '--untracked-files=no') in g.calls
    assert not any('main' in a or 'origin/main' in a or a == 'pull' for c in g.calls for a in c)
    assert any(PIN[:7] in m and '✓' in m for m in log)


def test_offline_box_that_already_holds_the_pin_still_lands_on_it(tmp_path):
    g, log = FakeGit(fetch_ok=False), []
    n = _ns(types.SimpleNamespace(run=g.run))
    assert n['_remote_assist_checkout_pin'](_clone(tmp_path), log.append) == PIN
    assert any('⚠ git fetch' in m for m in log)


def test_a_failed_checkout_stops_before_anything_is_built(tmp_path):
    n = _ns(types.SimpleNamespace(run=FakeGit(fetch_ok=False, reset_ok=False).run))
    with pytest.raises(RuntimeError, match='could not check out pinned commit'):
        n['_remote_assist_checkout_pin'](_clone(tmp_path), lambda m: None)


def test_head_must_be_the_pin(tmp_path):
    n = _ns(types.SimpleNamespace(run=FakeGit(lands_on=OTHER).run))
    with pytest.raises(RuntimeError, match='expected pinned commit'):
        n['_remote_assist_checkout_pin'](_clone(tmp_path), lambda m: None)


def test_tracked_files_must_match_the_pin(tmp_path):
    n = _ns(types.SimpleNamespace(run=FakeGit(dirty=' M server/src/index.ts\n').run))
    with pytest.raises(RuntimeError, match='does not match pinned commit'):
        n['_remote_assist_checkout_pin'](_clone(tmp_path), lambda m: None)


def test_a_newer_checkout_is_not_downgraded(tmp_path):
    g = FakeGit()
    n = _ns(types.SimpleNamespace(run=g.run))
    with pytest.raises(RuntimeError, match='not downgrading'):
        n['_remote_assist_checkout_pin'](_clone(tmp_path, '3.2.5'), lambda m: None)
    assert not any(c[0] in ('fetch', 'reset') for c in g.calls)


def test_already_on_the_pin_is_a_clean_reset(tmp_path):
    g = FakeGit(head=PIN)
    n = _ns(types.SimpleNamespace(run=g.run))
    assert n['_remote_assist_checkout_pin'](_clone(tmp_path, PIN_VERSION), lambda m: None) == PIN


# ── wiring: Deploy and Update both go through the pin, never main ──────────────────────────

@pytest.mark.parametrize('fn', ['_run_remote_assist_deploy', '_run_remote_assist_update'])
def test_deploy_and_update_use_the_pin(fn):
    body = _func(fn)
    assert '_remote_assist_checkout_pin(ra_dir, plog)' in body
    assert 'origin/main' not in body
    assert "'pull'" not in body
    assert "'fetch', 'origin', 'main'" not in body


def test_fresh_clone_does_not_check_out_main():
    assert "['git', 'clone', '--depth=1', '--no-checkout', REMOTE_ASSIST_REPO, ra_dir]" \
        in _func('_run_remote_assist_deploy')


# ── the update notice compares against the pin ─────────────────────────────────────────────

def _vinfo(tmp_path, head, version, settings=None):
    d = _clone(tmp_path, version)

    def run(argv, **kw):
        assert argv == ['git', 'rev-parse', 'HEAD'] and kw.get('cwd') == d, argv
        return _r(out=head + '\n') if head else _r(128)

    n = _ns(types.SimpleNamespace(run=run), REMOTE_ASSIST_INSTALL_DIR=d,
            load_settings=lambda: dict(settings or {}),
            _get_remote_assist_running_version=lambda: version or '')
    return n['_get_remote_assist_version_info'](fresh=True)


def test_on_the_pin_is_current(tmp_path):
    info = _vinfo(tmp_path, PIN, PIN_VERSION)
    assert info['is_current'] and not info['update_available']
    assert info['latest'] == info['latest_tag'] == PIN_VERSION


def test_any_other_commit_is_offered_the_pin(tmp_path):
    # e.g. the pre-rewrite a017dbb checkout: same VERSION, different commit
    info = _vinfo(tmp_path, OTHER, PIN_VERSION)
    assert info['update_available'] and not info['is_current']
    assert info['latest'] == PIN_VERSION


def test_an_older_release_is_offered_the_pin(tmp_path):
    assert _vinfo(tmp_path, OTHER, '3.0.2')['update_available']


def test_a_newer_checkout_is_not_offered_a_downgrade(tmp_path):
    info = _vinfo(tmp_path, OTHER, '3.2.5')
    assert not info['update_available'] and not info['is_current']


def test_no_github_lookup_any_more():
    body = _func('_get_remote_assist_version_info')
    assert 'api.github.com' not in body and 'urllib' not in body
    assert '_fetch_remote_assist_upstream' not in APP
