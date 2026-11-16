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
"""ETL card: the pressed Install / Uninstall / Update button shows a spinner until its job
ends (operator, v10.4.0 T&E on test12: a dimmed "Install" during a minutes-long build looked stuck)."""

import pathlib

T = (pathlib.Path(__file__).resolve().parent.parent / 'templates' / 'cloudtak.html').read_text()


def test_each_etl_action_button_goes_through_the_spinner():
    for action in ('install', 'remove', 'update'):
        assert "spin(%s, e, '%s')" % ({'install': 'i', 'remove': 'r', 'update': 'u'}[action], action) in T
    assert "Installing…" in T and "Uninstalling…" in T and "Updating…" in T
    assert "className = 'ct-btn-spinner'" in T and '.ct-btn-spinner{' in T


def test_the_spinner_is_set_when_the_job_starts_and_cleared_when_it_ends():
    assert "working = {prefix: e.prefix, action: action}; follow(" in T
    assert "busy = false; working = null; load();" in T
