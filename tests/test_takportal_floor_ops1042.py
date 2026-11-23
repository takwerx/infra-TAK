# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""TAK Portal deploy floor and redeploy never go back (ops #1042, finding from ops #1046).

While no signed verified-version file is on main, a deploy installs TAKPORTAL_REF_FALLBACK. That was
2.0.30, which cannot run Marketplace jobs on CloudTAK 13.124+ for a plugin whose route files carry
`// @ts-nocheck` (D4H): every install after it failed, and a "TAK Portal redeploy" moved a live
2.0.39 checkout back to 2.0.30 (test12, Sat Nov 21).

Pins, each red on the code before this change and green with it:
  * the floor is a release that passed the Marketplace gate (2.0.39 or newer) and ships a pinned helper;
  * deploy over an existing checkout that is on a newer release keeps it (real git, real tags);
  * an older or equal checkout still moves to the target; a checkout on no release tag still does too;
  * run_takportal_deploy goes through that function, not an inline checkout.
"""
import ast
import importlib.util
import os
import pathlib
import re
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
_FNS = {n.name: n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef)}

GATE_PASSED = (2, 0, 39)       # pipeline/takportal-gate.md, verdict on ops #1042


def _floor():
    m = re.search(r'^TAKPORTAL_REF_FALLBACK\s*=\s*"(\d+(?:\.\d+){1,3})"', APP, re.M)
    assert m, 'TAKPORTAL_REF_FALLBACK not found in app.py'
    return tuple(int(x) for x in m.group(1).split('.'))


# ---------------------------------------------------------------- the floor

def test_the_floor_is_a_release_that_passed_the_marketplace_gate():
    assert _floor() >= GATE_PASSED, (
        'a fresh deploy with no signed file installs the floor; 2.0.30 fails every D4H install')


def test_the_floor_ships_a_helper_the_broker_pins():
    spec = importlib.util.spec_from_file_location('takwerx_broker_t1042', ROOT / 'broker' / 'takwerx_broker.py')
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    # 2.0.39's marketplace helper (ops #1043); a floor on an unpinned helper shows "not reviewed yet"
    assert '11b953ada3cfe5dad8c37ec599fa759449841e8afef9ff7de7aeef025e00bd30' in b.TAKPORTAL_HELPER_SHA256
    assert _floor() >= tuple(b.TAKPORTAL_HARDENED_MIN_VERSION)


# ---------------------------------------------------------------- redeploy never goes back

def _git(cwd, *args, check=True):
    env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.com',
               GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.com', GIT_CONFIG_GLOBAL='/dev/null')
    return subprocess.run(['git', *args], cwd=str(cwd), env=env, check=check,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    """An upstream with releases 2.0.30, 2.0.39 and v2.0.40 (a 'v' tag), plus a main past 2.0.40."""
    up = tmp_path / 'upstream'
    up.mkdir()
    _git(up, 'init', '-q', '-b', 'main')
    shas = {}
    for tag in ('2.0.30', '2.0.39', 'v2.0.40'):
        (up / 'VERSION').write_text(tag + '\n')
        _git(up, 'add', '-A')
        _git(up, 'commit', '-q', '-m', tag)
        _git(up, 'tag', tag)
        shas[tag] = _git(up, 'rev-parse', 'HEAD')
    (up / 'VERSION').write_text('main\n')
    _git(up, 'add', '-A')
    _git(up, 'commit', '-q', '-m', 'main moves on')
    shas['main'] = _git(up, 'rev-parse', 'HEAD')
    return up, shas


class Deploy:
    NAMES = ('_takportal_version_tuple', '_takportal_head_release_tag', '_takportal_checkout_existing')

    def __init__(self, up, tmp_path, on):
        self.dir = tmp_path / 'TAK-Portal'
        _git(tmp_path, 'clone', '-q', str(up), str(self.dir))
        _git(self.dir, 'checkout', '-q', '--force', on)
        self.log = []
        self.ns = {'os': os, 're': re, 'subprocess': subprocess,
                   '_module_checkout_ownership_selfheal': lambda d, plog=None, prune=(): (False, ''),
                   '_takportal_repoint_origin': lambda d, plog=None: None}
        for n in self.NAMES:
            assert n in _FNS, f'{n} is missing from app.py'
            exec(compile(ast.get_source_segment(APP, _FNS[n]), 'app.py', 'exec'), self.ns)

    def head(self):
        return _git(self.dir, 'rev-parse', 'HEAD')

    def run(self, target):
        return self.ns['_takportal_checkout_existing'](str(self.dir), target, plog=self.log.append)


def test_a_redeploy_of_a_2_0_39_box_with_the_floor_at_2_0_30_stays_on_2_0_39(repo, tmp_path):
    """The bug: test12 was on 2.0.39, 'TAK Portal redeploy' took the floor and went back to 2.0.30."""
    up, shas = repo
    d = Deploy(up, tmp_path, on='2.0.39')
    assert d.run('2.0.30') == '2.0.39'
    assert d.head() == shas['2.0.39']
    assert (d.dir / 'VERSION').read_text().strip() == '2.0.39'
    assert any('never installs an older release' in m for m in d.log)


def test_a_redeploy_of_a_v_prefixed_newer_tag_stays_too(repo, tmp_path):
    up, shas = repo
    d = Deploy(up, tmp_path, on='v2.0.40')
    d.run('2.0.39')
    assert d.head() == shas['v2.0.40']


def test_a_redeploy_on_the_same_release_stays(repo, tmp_path):
    up, shas = repo
    d = Deploy(up, tmp_path, on='2.0.39')
    assert d.run('2.0.39') == '2.0.39'
    assert d.head() == shas['2.0.39']


def test_an_older_checkout_still_moves_up_to_the_target(repo, tmp_path):
    up, shas = repo
    d = Deploy(up, tmp_path, on='2.0.30')
    assert d.run('2.0.39') == '2.0.39'
    assert d.head() == shas['2.0.39']


def test_a_checkout_on_no_release_tag_still_goes_to_the_target(repo, tmp_path):
    """Beta Mode / a pre-tag clone sits on main: deploy converges it to the target, as before."""
    up, shas = repo
    d = Deploy(up, tmp_path, on='main')
    assert d.run('2.0.39') == '2.0.39'
    assert d.head() == shas['2.0.39']


def test_the_kept_checkout_is_reset_like_the_tag_checkout_was(repo, tmp_path):
    up, shas = repo
    d = Deploy(up, tmp_path, on='2.0.39')
    (d.dir / 'VERSION').write_text('hand edit\n')
    d.run('2.0.30')
    assert (d.dir / 'VERSION').read_text().strip() == '2.0.39'


def test_a_tag_that_is_new_upstream_is_fetched_before_the_decision(repo, tmp_path):
    """Upstream publishes 2.0.41 after the clone; the target 2.0.41 must be fetched, then checked out."""
    up, shas = repo
    d = Deploy(up, tmp_path, on='2.0.30')
    (up / 'VERSION').write_text('2.0.41\n')
    _git(up, 'add', '-A')
    _git(up, 'commit', '-q', '-m', '2.0.41')
    _git(up, 'tag', '2.0.41')
    assert d.run('2.0.41') == '2.0.41'
    assert (d.dir / 'VERSION').read_text().strip() == '2.0.41'


# ---------------------------------------------------------------- the deploy uses it

def test_run_takportal_deploy_goes_through_the_no_downgrade_checkout():
    body = ast.get_source_segment(APP, _FNS['run_takportal_deploy'])
    assert '_takportal_checkout_existing(portal_dir, _tp_tag' in body
    # no inline checkout of the target over an existing clone any more
    assert "'checkout', '--force', _tp_tag" not in body
