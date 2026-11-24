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
"""README shape (GitHub #683, ops #1164).

A reporter who uses a screen reader found the README too long to move around in: 2,380 lines, of which
1,900 were the release history. The history now lives in CHANGELOG.md and the README opens with a
table of contents. These checks keep it that way:

  * every README heading is in the table of contents, and every table-of-contents link lands on a
    real heading (a dead anchor does nothing in a screen reader and nothing on GitHub);
  * release entries stay out of the README, so it does not grow back into a wall of text;
  * CHANGELOG.md keeps a clean heading outline (one title, releases one level below it, no skipped
    level) and still holds the whole history.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
README = (REPO / 'README.md').read_text(encoding='utf-8')



def _changelog():
    path = REPO / 'CHANGELOG.md'
    assert path.exists(), 'CHANGELOG.md is missing: the release history belongs there (GitHub #683)'
    return path.read_text(encoding='utf-8')


_RELEASE_HEADING = re.compile(r'^#{1,6} v\d+\.\d+', re.M)


def _slug(title):
    """GitHub's heading anchor: lower case, drop everything but letters, digits, '_', '-' and spaces,
    then spaces become hyphens."""
    t = re.sub(r'[`*]', '', title).strip().lower()
    t = re.sub(r'[^\w\- ]', '', t)
    return t.replace(' ', '-')


def _headings(text):
    """(level, title) for every heading outside a fenced code block."""
    out, fence = [], False
    for line in text.split('\n'):
        if line.startswith('```'):
            fence = not fence
            continue
        m = None if fence else re.match(r'^(#{1,6}) (.+)$', line)
        if m:
            out.append((len(m.group(1)), m.group(2)))
    return out


def _anchors(text):
    """Every anchor GitHub gives the headings of `text`; a repeated title gets -1, -2, ..."""
    seen, anchors = {}, set()
    for _level, title in _headings(text):
        s = _slug(title)
        n = seen.get(s, 0)
        seen[s] = n + 1
        anchors.add(s if n == 0 else f'{s}-{n}')
    return anchors


def _toc_block():
    m = re.search(r'^## Contents\n\n((?:[ ]*- \[.*\]\(#.*\)\n)+)', README, re.M)
    assert m, 'README.md has lost its "## Contents" table of contents (a list of "- [title](#anchor)" links)'
    return m.group(1)


def test_readme_opens_with_a_table_of_contents():
    first_h2 = README.index('\n## ')
    assert README[first_h2:].startswith('\n## Contents\n'), (
        'the table of contents ("## Contents") must be the first section of the README')
    assert _toc_block().count('\n') >= 10


def test_every_toc_link_lands_on_a_heading():
    anchors = _anchors(README)
    dead = [a for a in re.findall(r'\]\(#([^)]+)\)', _toc_block()) if a not in anchors]
    assert not dead, f'table-of-contents links with no heading behind them: {dead}'


def test_every_readme_section_is_in_the_toc():
    toc_anchors = set(re.findall(r'\]\(#([^)]+)\)', _toc_block()))
    seen, missing = {}, []
    for level, title in _headings(README):
        s = _slug(title)
        n = seen.get(s, 0)
        seen[s] = n + 1
        anchor = s if n == 0 else f'{s}-{n}'
        if level in (2, 3) and title != 'Contents' and anchor not in toc_anchors:
            missing.append(title)
    assert not missing, f'README sections missing from the table of contents: {missing}'


def test_readme_has_no_release_entries_and_points_at_the_changelog():
    assert not _RELEASE_HEADING.search(README), (
        'release entries belong in CHANGELOG.md, not in README.md (GitHub #683)')
    assert '(CHANGELOG.md)' in README
    assert len(README.split('\n')) < 800, 'README.md is growing back into a wall of text; split a section out'


def test_changelog_keeps_a_clean_heading_outline():
    levels = [level for level, _t in _headings(_changelog())]
    assert levels and levels[0] == 1 and levels.count(1) == 1, 'CHANGELOG.md needs exactly one "# " title, first'
    assert set(levels) == {1, 2}, 'release entries are "## vX.Y.Z-alpha — date — summary", directly under the title'
    releases = [t for level, t in _headings(_changelog()) if level == 2]
    assert all(re.match(r'v\d+\.\d+', t) for t in releases)


def test_changelog_still_holds_the_whole_history():
    releases = [t for level, t in _headings(_changelog()) if level == 2]
    assert len(releases) >= 160, f'only {len(releases)} releases left in CHANGELOG.md; history was lost'
    assert any(t.startswith('v0.9.40-alpha') for t in releases), 'the oldest entries are gone from CHANGELOG.md'
    assert releases[0].startswith('v10.'), 'newest release must come first'
