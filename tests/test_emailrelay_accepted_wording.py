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
"""A test email says it was ACCEPTED, not delivered (v10.2.8 W6, GH #87).

Reporter: "The console reports it was sent successfully, but still no luck." The relay only
knows the provider took the message; Brevo then drops mail silently for an unauthorized IP, an
unverified sender, or a domain without DKIM/DMARC.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.emailrelay as er  # noqa: E402

APP = (ROOT / 'app.py').read_text(encoding='utf-8')


def test_brevo_names_the_provider_and_where_its_log_is():
    said = er.accepted_message({'email_relay': {'provider': 'brevo'}}, 'a@b.org')
    assert 'Brevo' in said and 'a@b.org' in said
    assert 'Transactional' in said and 'Logs' in said
    assert 'not that it was delivered' in said
    assert 'sent' not in said.lower()


def test_other_known_provider_is_named_without_a_made_up_menu_path():
    said = er.accepted_message({'email_relay': {'provider': 'smtp2go'}}, 'a@b.org')
    assert 'SMTP2GO' in said and 'Transactional' not in said


def test_custom_or_missing_provider_is_generic():
    for settings in ({'email_relay': {'provider': 'custom'}}, {}, None):
        said = er.accepted_message(settings, 'a@b.org')
        assert "email provider's sending log" in said


def test_both_test_sends_use_it():
    src = (ROOT / 'modules' / 'emailrelay.py').read_text(encoding='utf-8')
    assert "'output': accepted_message(settings, to_addr)" in src
    assert "f'Test email sent to {to_addr}'" not in src
    assert 'mod_registry.emailrelay.accepted_message(settings, to_addr)' in APP
