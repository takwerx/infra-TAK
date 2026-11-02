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
"""Release hygiene (ops #354): the version in app.py, the newest tag and the release notes agree.

The console shows `VERSION` in app.py and the Update card reads the README changelog, so a release
whose number or notes lag behind the tag tells operators the wrong thing.

`dev` runs ahead of the last tag while the next release is being built (VERSION 10.3.4-alpha, newest
tag v10.3.3-alpha), so the rule is not "VERSION equals the newest tag". It is:

  * VERSION is never behind the newest tag.
  * Once VERSION equals the newest tag (a released tree), the newest changelog section and the README
    "Current release" line are that version.
  * While VERSION is ahead, the newest changelog section and "Current release" are either the last
    release or the one being prepared. Anything else is a typo or a skipped release.
  * The newest section is written for users: it opens with a Headline and carries no commit hashes
    or branch names.

A PR into `dev` is only held to the newest release that `dev` itself already acknowledges (ops #435).
Release tags land on `main`, so for a while after a release the tag is newer than anything `dev` knows
about; a good PR must not turn red in that window. A PR into `main`, or a run with no base branch
(a local run, a release branch), is held to the newest tag, so a release whose notes lag still fails.

CI checks out without tags, so its pytest job fetches them (and the PR's base branch); with `CI` set
and no tags the test fails instead of skipping, so a broken checkout cannot turn the check off.
"""

import os
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent

_VERSION_RE = re.compile(r'^(\d+(?:\.\d+)+)(-[A-Za-z0-9.]+)?$')
_HEADING_RE = re.compile(r'^### v(\d+(?:\.\d+)+(?:-[A-Za-z0-9.]+)?) — (\d{4}-\d{2}-\d{2}) — (\S.*)$', re.M)
_CURRENT_RE = re.compile(r'^\*\*Current release: \[v([^\]]+)\]\(([^)]+)\)\*\*', re.M)


def _key(version):
    """(numbers, suffix) for ordering. '10.3.4-alpha' > '10.3.3-alpha'. Raises ValueError if malformed."""
    m = _VERSION_RE.match(version)
    if not m:
        raise ValueError(f'not a version: {version!r}')
    return tuple(int(p) for p in m.group(1).split('.')), m.group(2) or ''


def _app_version():
    text = (REPO / 'app.py').read_text(encoding='utf-8')
    m = re.search(r'^VERSION = "([^"]+)"', text, re.M)
    assert m, 'app.py has no top-level VERSION = "..." line'
    return m.group(1)


def _readme():
    return (REPO / 'README.md').read_text(encoding='utf-8')


def _newest_section(readme):
    """(version, date, title, body) of the first changelog section after '## Changelog'."""
    head = readme.index('\n## Changelog')
    sections = list(_HEADING_RE.finditer(readme, head))
    assert sections, 'README.md has no "### vX.Y.Z-alpha — date — summary" changelog section'
    first = sections[0]
    end = sections[1].start() if len(sections) > 1 else len(readme)
    return first.group(1), first.group(2), first.group(3), readme[first.end():end]


def _tags():
    """Every `v*` tag as a version string (no leading v); empty when the checkout has no tags."""
    out = subprocess.run(
        ['git', 'for-each-ref', '--format=%(refname:short)', 'refs/tags/v*'],
        cwd=REPO, capture_output=True, text=True, check=False,
    ).stdout.split()
    versions = []
    for tag in out:
        try:
            _key(tag[1:])
        except ValueError:
            continue
        versions.append(tag[1:])
    return versions


def _newest_tag():
    """Newest `v*` tag by version number (not by date), or None when the checkout has no tags."""
    versions = _tags()
    return max(versions, key=_key) if versions else None


def _base_current_release(base_ref, repo=REPO):
    """The "Current release" version in README.md on origin/<base_ref>, or None if it can't be read."""
    out = subprocess.run(
        ['git', 'show', f'origin/{base_ref}:README.md'],
        cwd=repo, capture_output=True, text=True, check=False,
    )
    if out.returncode != 0:
        return None
    m = _CURRENT_RE.search(out.stdout)
    return m.group(1) if m else None


def baseline_tag(newest, tags, base_ref, base_current):
    """The tag a tree is held to. Strict (the newest tag) unless this is a PR into dev whose base README
    names a release: then the newest tag that is not newer than that release, so a release tagged on
    main after the PR's base was cut can't fail a good PR."""
    if base_ref in (None, '', 'main') or base_current is None:
        return newest
    try:
        limit = _key(base_current)
    except ValueError:
        return newest
    older = [t for t in tags if _key(t) <= limit]
    return max(older, key=_key) if older else newest


def release_problems(version, tag, notes_version, current_release):
    """Everything wrong with how these four version strings relate; empty list means consistent."""
    try:
        v, t = _key(version), _key(tag)
    except ValueError as e:
        return [str(e)]
    if v < t:
        return [f'app.py VERSION {version} is behind the newest tag v{tag}']
    allowed = {tag, version}
    if v == t:
        allowed = {version}
    problems = []
    if notes_version not in allowed:
        problems.append(
            f'newest changelog section is v{notes_version}; expected '
            + (f'v{version}' if v == t else f'v{tag} or v{version}'))
    if current_release not in allowed:
        problems.append(
            f'README "Current release" is v{current_release}; expected '
            + (f'v{version}' if v == t else f'v{tag} or v{version}'))
    return problems


# ---- the rule itself --------------------------------------------------------------------------

def test_released_tree_must_match_everywhere():
    assert release_problems('10.3.3-alpha', '10.3.3-alpha', '10.3.3-alpha', '10.3.3-alpha') == []


def test_dev_ahead_of_last_tag_is_fine():
    # notes not started yet, notes in progress, and notes + README bumped for the release being cut
    assert release_problems('10.3.4-alpha', '10.3.3-alpha', '10.3.3-alpha', '10.3.3-alpha') == []
    assert release_problems('10.3.4-alpha', '10.3.3-alpha', '10.3.4-alpha', '10.3.3-alpha') == []
    assert release_problems('10.3.4-alpha', '10.3.3-alpha', '10.3.4-alpha', '10.3.4-alpha') == []


def test_version_behind_tag_fails():
    assert release_problems('10.3.2-alpha', '10.3.3-alpha', '10.3.3-alpha', '10.3.3-alpha')


def test_released_tree_with_stale_notes_fails():
    assert release_problems('10.3.3-alpha', '10.3.3-alpha', '10.3.2-alpha', '10.3.3-alpha')
    assert release_problems('10.3.3-alpha', '10.3.3-alpha', '10.3.3-alpha', '10.3.2-alpha')


def test_notes_for_a_skipped_release_fail():
    assert release_problems('10.3.4-alpha', '10.3.3-alpha', '10.3.5-alpha', '10.3.3-alpha')
    assert release_problems('10.3.4-alpha', '10.3.3-alpha', '10.3.2-alpha', '10.3.3-alpha')


def test_ten_sorts_after_nine():
    assert _key('10.3.0-alpha') > _key('9.9.9-alpha')
    assert release_problems('10.0.0-alpha', '9.9.9-alpha', '10.0.0-alpha', '9.9.9-alpha') == []


def test_malformed_version_is_reported():
    assert release_problems('ten', '10.3.3-alpha', '10.3.3-alpha', '10.3.3-alpha')


# ---- a release tagged on main must not turn good PRs into dev red (ops #435) --------------------

TAGS = ['10.3.2-alpha', '10.3.3-alpha', '10.3.4-alpha']


def test_pr_into_dev_is_held_to_the_release_dev_already_has():
    # 10.3.4-alpha was just tagged on main; dev's README still says 10.3.3-alpha. A PR branched from
    # that dev (VERSION 10.3.4-alpha, notes not yet bumped) is fine.
    tag = baseline_tag('10.3.4-alpha', TAGS, 'dev', '10.3.3-alpha')
    assert tag == '10.3.3-alpha'
    assert release_problems('10.3.4-alpha', tag, '10.3.3-alpha', '10.3.3-alpha') == []
    # Without the base rule, the same tree is red: this is the bug.
    assert release_problems('10.3.4-alpha', '10.3.4-alpha', '10.3.3-alpha', '10.3.3-alpha')


def test_release_branch_into_main_must_still_match_the_new_tag():
    tag = baseline_tag('10.3.4-alpha', TAGS, 'main', '10.3.3-alpha')
    assert tag == '10.3.4-alpha'
    assert release_problems('10.3.4-alpha', tag, '10.3.3-alpha', '10.3.3-alpha')
    assert release_problems('10.3.4-alpha', tag, '10.3.4-alpha', '10.3.4-alpha') == []


def test_no_base_branch_means_strict():
    assert baseline_tag('10.3.4-alpha', TAGS, None, None) == '10.3.4-alpha'
    assert baseline_tag('10.3.4-alpha', TAGS, '', '10.3.3-alpha') == '10.3.4-alpha'


def test_unreadable_base_falls_back_to_strict():
    assert baseline_tag('10.3.4-alpha', TAGS, 'dev', None) == '10.3.4-alpha'
    assert baseline_tag('10.3.4-alpha', TAGS, 'dev', 'garbage') == '10.3.4-alpha'


def test_dev_ahead_of_every_tag_uses_the_newest_tag():
    # dev already announced 10.3.5-alpha as current (tag not cut yet): newest tag it has is 10.3.4-alpha
    assert baseline_tag('10.3.4-alpha', TAGS, 'dev', '10.3.5-alpha') == '10.3.4-alpha'


def test_a_pr_still_fails_when_it_is_behind_what_dev_has():
    tag = baseline_tag('10.3.4-alpha', TAGS, 'dev', '10.3.4-alpha')
    assert tag == '10.3.4-alpha'
    assert release_problems('10.3.3-alpha', tag, '10.3.3-alpha', '10.3.3-alpha')


def test_base_current_release_is_read_from_origin_branch(tmp_path):
    def git(*a):
        subprocess.run(['git', *a], cwd=tmp_path, check=True, capture_output=True)
    git('init', '-q')
    (tmp_path / 'README.md').write_text(
        '**Current release: [v10.3.3-alpha](https://github.com/x/y/releases/tag/v10.3.3-alpha)**\n')
    git('add', 'README.md')
    git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'x')
    git('update-ref', 'refs/remotes/origin/dev', 'HEAD')
    assert _base_current_release('dev', tmp_path) == '10.3.3-alpha'
    assert _base_current_release('nope', tmp_path) is None


# ---- this tree -------------------------------------------------------------------------------

def test_this_tree_is_consistent_with_the_newest_tag():
    tag = _newest_tag()
    if tag is None:
        if os.environ.get('CI'):
            pytest.fail('CI checkout has no v* tags; the pytest job must fetch them (see pr-checks.yml)')
        pytest.skip('no v* tags in this checkout')
    base_ref = os.environ.get('GITHUB_BASE_REF')
    tag = baseline_tag(tag, _tags(), base_ref, _base_current_release(base_ref) if base_ref else None)
    readme = _readme()
    notes_version = _newest_section(readme)[0]
    current = _CURRENT_RE.search(readme)
    assert current, 'README.md lost its "**Current release: [vX.Y.Z-alpha](...)**" line'
    assert release_problems(_app_version(), tag, notes_version, current.group(1)) == []


def test_current_release_link_points_at_its_own_tag():
    current = _CURRENT_RE.search(_readme())
    assert current, 'README.md lost its "**Current release: [vX.Y.Z-alpha](...)**" line'
    assert current.group(2).endswith(f'/releases/tag/v{current.group(1)}')


def test_newest_notes_are_written_for_users():
    version, _date, _title, body = _newest_section(_readme())
    assert re.match(r'\s*\*\*Headline:', body), (
        f'v{version} notes must open with a "**Headline: ...**" paragraph a customer can read')
    assert not re.search(r'\b[0-9a-f]{40}\b', body), f'v{version} notes contain a full commit hash'
    assert 'claude/issue-' not in body, f'v{version} notes mention an internal branch name'
