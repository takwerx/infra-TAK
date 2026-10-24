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
"""Help → Report an issue (ops #199).

A card above Diagnostics whose button opens the public repo's bug_report form with
the console version (and OS/arch, in the "what happened" skeleton) filled in. The
link lands on a public site, so the one thing that must never happen is a setting
like the FQDN, server IP or Email Relay login leaking into it.

These render the real template, with autoescape on as Flask does, because what is
asserted is the href a user's browser actually follows.
"""

import html
import pathlib
import re
from urllib.parse import parse_qs, urlsplit

import pytest

jinja2 = pytest.importorskip("jinja2", reason="jinja2 not installed")

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

SENSITIVE = {
    'fqdn': 'tak.secret-agency.example.org',
    'server_ip': '203.0.113.77',
    'install_dir': '/home/takwerx/infra-TAK',
    'email_relay': {'relay_host': 'smtp.relay-secret.example.net',
                    'smtp_user': 'dispatch@secret-agency.example.org',
                    'smtp_pass': 'hunter2-relay-password',
                    'from_addr': 'noreply@secret-agency.example.org'},
    'guarddog_alert_email': 'oncall@secret-agency.example.org',
}


def render(settings, version='10.2.29-alpha'):
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(REPO / 'templates')),
        undefined=jinja2.ChainableUndefined,
        autoescape=True,
    )
    return env.get_template('help.html').render(
        settings=settings, version=version, current_ssh_port=22,
        diag_support_email='', diag_email_ready=False)


def card_titles(page):
    return re.findall(r'class="help-card-header"[^>]*><h2>([^<]+)</h2>', page)


def issue_link(page):
    m = re.search(r'<a [^>]*id="report-issue-link"[^>]*>', page)
    assert m, 'Report an issue button missing'
    tag = m.group(0)
    href = html.unescape(re.search(r'href="([^"]*)"', tag).group(1))
    return tag, href


def full_settings():
    return dict(SENSITIVE, os_name='Ubuntu 22.04.5 LTS', os_type='debian', arch='amd64')


def test_report_card_sits_directly_above_diagnostics():
    titles = card_titles(render(full_settings()))
    assert titles[0] == 'Report an issue'
    assert titles[1].startswith('Diagnostics')


def test_link_opens_bug_report_form_on_public_repo_in_new_tab():
    tag, href = issue_link(render(full_settings()))
    url = urlsplit(href)
    assert (url.scheme, url.netloc, url.path) == ('https', 'github.com', '/takwerx/infra-TAK/issues/new')
    assert 'target="_blank"' in tag
    assert 'rel="noopener noreferrer"' in tag
    q = parse_qs(url.query)
    assert q['template'] == ['bug_report.yml']
    # Field ids must exist in the form, or GitHub silently drops the pre-fill.
    form = (REPO / '.github' / 'ISSUE_TEMPLATE' / 'bug_report.yml').read_text(encoding='utf-8')
    for field in set(q) - {'template'}:
        assert re.search(rf'^\s+id: {field}$', form, re.M), field
    assert q['version'] == ['v10.2.29-alpha']
    what = q['what'][0]
    assert 'What happened:' in what and 'What I expected:' in what
    assert 'Console: v10.2.29-alpha · Ubuntu 22.04.5 LTS · amd64' in what


def test_nothing_sensitive_ends_up_in_the_link():
    _, href = issue_link(render(full_settings()))
    q = parse_qs(urlsplit(href).query)
    assert set(q) == {'template', 'version', 'what'}
    blob = href + ' ' + ' '.join(v for vs in q.values() for v in vs)
    for needle in ('secret-agency', '203.0.113.77', 'relay-secret', 'hunter2', '@',
                   '/home/takwerx'):
        assert needle not in blob, needle


def test_missing_os_and_arch_still_render_a_clean_link():
    _, href = issue_link(render({'fqdn': 'tak.example.org'}))
    what = parse_qs(urlsplit(href).query)['what'][0]
    assert 'Console: v10.2.29-alpha\n' in what
    assert 'None' not in what and 'tak.example.org' not in href


def test_card_tells_user_issues_are_public_and_not_to_attach_the_report():
    page = render(full_settings())
    card = page[page.index('id="report-issue-card"'):page.index('id="diag-card"')]
    assert 'GitHub issues are public' in card
    assert "don't attach it to the issue" in card
    assert 'material-symbols-outlined' in card and 'btn btn-primary' in card


def test_every_help_page_icon_is_in_the_subset_icon_font():
    # The icon font ships as a subset; a ligature missing from it paints as the raw
    # word ("BUG_REPORT" on this very button, caught in the PR screenshot).
    script = (REPO / 'tools' / 'build-icon-font.sh').read_text(encoding='utf-8')
    ligs = set(re.search(r'^LIGS="([^"]*)"', script, re.M).group(1).split())
    page = render(full_settings())
    icons = set(re.findall(r'class="material-symbols-outlined"[^>]*>([a-z0-9_]+)<', page))
    assert icons, 'no icons found on the Help page'
    assert icons <= ligs, sorted(icons - ligs)


def test_help_page_still_passes_settings_and_version_to_the_template():
    body = re.search(r'^def help_page\(.*?(?=^\S)', APP, re.S | re.M).group(0)
    assert "render_template('help.html', settings=settings, version=VERSION" in body
