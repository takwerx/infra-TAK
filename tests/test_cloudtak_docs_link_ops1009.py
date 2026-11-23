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
"""The CloudTAK page links to the official CloudTAK documentation (AJ, Fri Nov 20, 2026, ops #1009).

The link sits in the page header, outside every {% if %} block, so it shows whether or not
CloudTAK is installed. It opens in a new tab and carries rel="noopener"."""

import pathlib
import re

T = (pathlib.Path(__file__).resolve().parent.parent / 'templates' / 'cloudtak.html').read_text()


def _link_tag():
    m = re.search(r'<a\b[^>]*id="ct-docs-link"[^>]*>.*?</a>', T, re.S)
    assert m, 'CloudTAK page has no documentation link (id="ct-docs-link")'
    return m.group(0)


def test_docs_link_points_to_official_cloudtak_docs():
    tag = _link_tag()
    assert 'href="https://docs.cloudtak.io/"' in tag
    assert 'CloudTAK documentation' in tag


def test_docs_link_opens_in_new_tab_safely():
    tag = _link_tag()
    assert 'target="_blank"' in tag
    assert 'noopener' in tag


def test_docs_link_is_in_header_and_always_visible():
    start = T.index('<div class="page-header">')
    end = T.index('</div>', start)
    assert 'id="ct-docs-link"' in T[start:end]
    # every {% if %} opened before the link is closed before it, so no condition hides the link
    before = T[T.index('{% block content %}'):T.index('id="ct-docs-link"')]
    assert len(re.findall(r'\{%-?\s*if\b', before)) == len(re.findall(r'\{%-?\s*endif\b', before))
