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
"""Security reports go by email only (ops #625).

Vulnerabilities, CVEs and leaked keys must not be reported in public, and the
GitHub "Report a vulnerability" form is no longer a way in. SECURITY.md,
CONTRIBUTING.md and the new-issue screen must all point at the one email address.
"""

import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
EMAIL = 'takwerx@gmail.com'


def _read(*parts):
    return (REPO.joinpath(*parts)).read_text(encoding='utf-8')


def test_security_md_says_email_only():
    text = _read('SECURITY.md')
    assert EMAIL in text
    assert 'public issues, discussions or pull requests' in text
    assert 'security/advisories' not in text
    assert 'Report a vulnerability' not in text


def test_security_md_keeps_supported_versions_and_scope():
    text = _read('SECURITY.md')
    assert '## Supported versions' in text
    assert '## Scope' in text


def test_contributing_points_to_email_not_the_form():
    text = _read('CONTRIBUTING.md')
    assert EMAIL in text
    assert 'Report a vulnerability' not in text
    assert 'security/advisories' not in text


def test_new_issue_screen_has_security_link_to_email():
    text = _read('.github', 'ISSUE_TEMPLATE', 'config.yml')
    assert 'blank_issues_enabled: true' in text
    assert 'name: Report a security problem' in text
    assert 'blob/main/SECURITY.md' in text
    assert EMAIL in text
    assert 'security/advisories' not in text
