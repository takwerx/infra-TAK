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
"""TAK Simulator engine (infra-TAK v10.1.61, PLAN §4.2–§4.3).

Streams scripted, synthetic Cursor on Target into TAK Server over 8089 on the channel(s)
the operator picked — one enrolled identity ("lane") per channel. Standard library only:
no pip, no lockfile, multi-arch by construction. Runs inside the `tak-simulator` container
as a non-root user; the console (modules/simulator.py) drives it over a loopback-only
bearer-token control API and reuses `scenario.py` to validate uploads.
"""
