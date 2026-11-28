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
"""The agency security paper is public and follows the email-only rule (ops #1131).

docs/SECURITY-PRACTICES.md and its PDF are linked from README.md and SECURITY.md.
The paper must not say DRAFT, must send vulnerability reports to the one email
address, and must not point at the GitHub "Report a vulnerability" form (ops #625).
"""

import pathlib
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
EMAIL = 'takwerx@gmail.com'
PAPER = REPO / 'docs' / 'SECURITY-PRACTICES.md'
PDF = REPO / 'docs' / 'infra-TAK-security-practices.pdf'


def _read(*parts):
    return REPO.joinpath(*parts).read_text(encoding='utf-8')


def test_paper_and_pdf_exist():
    assert PAPER.is_file()
    assert PDF.is_file()
    assert PDF.read_bytes()[:5] == b'%PDF-'


def test_paper_is_not_a_draft():
    text = PAPER.read_text(encoding='utf-8')
    assert 'DRAFT' not in text
    assert 'not approved' not in text


def test_paper_reports_by_email_only():
    text = PAPER.read_text(encoding='utf-8')
    assert EMAIL in text
    assert 'Report a vulnerability' not in text
    assert 'private vulnerability reporting' not in text.lower()
    assert 'security/advisories' not in text


def test_paper_keeps_its_ten_sections_and_open_gaps():
    text = PAPER.read_text(encoding='utf-8')
    for n in range(1, 11):
        assert '\n## %d. ' % n in text
    assert 'What is still open' in text
    assert 'We hold no certification' in text


def test_paper_lists_have_a_blank_line_before_them():
    # A list straight after a text line is read as one paragraph by pandoc
    # (the PDF of Nov 23 lost its bullets that way).
    lines = PAPER.read_text(encoding='utf-8').split('\n')
    for i, line in enumerate(lines):
        if line.startswith('- ') and i > 0 and lines[i - 1].strip():
            assert lines[i - 1].startswith('- ') or lines[i - 1].startswith('  '), \
                'list item without a blank line before it: %r' % line


def test_readme_and_security_md_link_the_paper_and_pdf():
    for name in ('README.md', 'SECURITY.md'):
        text = _read(name)
        assert 'docs/SECURITY-PRACTICES.md' in text, name
        assert 'docs/infra-TAK-security-practices.pdf' in text, name


def test_security_md_still_email_only():
    text = _read('SECURITY.md')
    assert EMAIL in text
    assert 'Report a vulnerability' not in text


def test_docs_are_not_ignored_by_git():
    gi = _read('.gitignore')
    assert '!docs/SECURITY-PRACTICES.md' in gi
    assert '!docs/infra-TAK-security-practices.pdf' in gi
    try:
        r = subprocess.run(['git', 'check-ignore', str(PAPER), str(PDF)],
                           cwd=REPO, capture_output=True)
    except OSError:
        return
    assert r.returncode == 1 and not r.stdout, 'paper or PDF is ignored by git'
