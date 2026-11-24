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

Round two (the reporter asked for it on the public issue): install, recovery, ports and the button
reference moved out of the README into docs/INSTALL.md, docs/RECOVERY.md, docs/PORTS.md and
docs/CONSOLE-ACTIONS.md, so the README is a short landing page that links to them. The checks at the
bottom keep those pages linked, their links alive and their heading outlines clean.

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


# ---- round two: the README is a landing page, the detail lives in docs/ -------------------------------

DOC_PAGES = ['docs/INSTALL.md', 'docs/RECOVERY.md', 'docs/PORTS.md', 'docs/CONSOLE-ACTIONS.md']


def _read(rel):
    path = REPO / rel
    assert path.exists(), f'{rel} is missing: the README sends readers there (GitHub #683)'
    return path.read_text(encoding='utf-8')


def _strip_fences(text):
    out, fence = [], False
    for line in text.split('\n'):
        if line.startswith('```'):
            fence = not fence
            continue
        if not fence:
            out.append(line)
    return '\n'.join(out)


def test_readme_is_a_short_landing_page_that_links_every_docs_page():
    assert len(README.split('\n')) < 300, 'README.md should stay a landing page: move detail into docs/'
    for rel in DOC_PAGES:
        assert f']({rel})' in README, f'README.md does not link to {rel}'


def test_docs_pages_hold_the_moved_sections():
    assert 'sudo ./start.sh' in _read('docs/INSTALL.md')
    assert '## Deployment Order' in _read('docs/INSTALL.md')
    assert '## Universal recovery (SSH)' in _read('docs/RECOVERY.md')
    assert '## Tier 1' in _read('docs/PORTS.md')
    assert '**Update Config**' in _read('docs/CONSOLE-ACTIONS.md')
    for heading in ('## Universal recovery (SSH)', '## Deployment Order', '## Actions Reference', '### Tier 1'):
        assert heading not in README, f'"{heading}" moved to docs/; do not paste it back into the README'


def test_docs_pages_have_a_clean_heading_outline():
    for rel in DOC_PAGES:
        levels = [level for level, _t in _headings(_read(rel))]
        assert levels and levels[0] == 1 and levels.count(1) == 1, f'{rel} needs exactly one "# " title, first'
        for prev, cur in zip(levels, levels[1:]):
            assert cur <= prev + 1, f'{rel} skips a heading level (h{prev} then h{cur})'


def test_every_relative_link_lands_on_a_file_and_a_heading():
    broken = []
    for rel in ['README.md'] + DOC_PAGES:
        base = (REPO / rel).parent
        for target in re.findall(r'\]\(([^)\s]+)\)', _strip_fences(_read(rel))):
            if re.match(r'^[a-z][a-z0-9+.-]*:', target):
                continue
            path, _, anchor = target.partition('#')
            dest = (base / path).resolve() if path else (REPO / rel)
            if not dest.exists():
                broken.append(f'{rel} -> {target} (no such file)')
            elif anchor and dest.suffix == '.md' and anchor not in _anchors(dest.read_text(encoding='utf-8')):
                broken.append(f'{rel} -> {target} (no such heading)')
    assert not broken, 'dead links: ' + '; '.join(broken)


def test_new_docs_pages_are_not_gitignored():
    """docs/* is ignored by default in this repo; a page not on the allow-list never reaches GitHub."""
    ignore = (REPO / '.gitignore').read_text(encoding='utf-8').split('\n')
    for rel in DOC_PAGES:
        assert f'!{rel}' in ignore, f'{rel} is not on the docs/ allow-list in .gitignore'
