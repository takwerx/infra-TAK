# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Michael Leckliter
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
"""Comparing the install pin against the release a feature needs (W234).

⚠️ **Three guards used to assert `ATLAS_TAG == 'v1.49.0'`, and none of them
meant it.** Two meant *at least* that release — a fresh install must land on
something that understands the admin-group list, and on something that
renders the agency name — and equality is a stronger claim than either. The
cost showed up on the next promotion: the pin moved forward, correctly, and
three tests failed for no reason anybody reading them could act on. A guard
that has to be hand-edited every release is a guard that gets hand-edited
without being read.

So the two that mean "at least" now say so, and the one that really is an
equality — the pin names whatever was last promoted — is the single place a
promotion touches.
"""

import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402

#: The release `main` currently points at. ⚠️ **The one line a promotion
#: changes**, and it is deliberately not derived from `ATLAS_TAG`: a test that
#: computes its expectation from the value under test passes for every value.
PROMOTED = 'v1.51.0'

#: The **mirror's** commit for that tag, which is what a clone's HEAD will be.
#: ⚠️ Not this repository's commit: every release has two, and recording
#: the private one pins a hash the clone can never produce -- the install then
#: refuses itself with "refusing to install a tag that has moved", which reads
#: as tampering rather than as bookkeeping. Take it from the mirror:
#:
#:     git ls-remote https://github.com/cfd2474/TAK-MDM.git refs/tags/v1.51.0
PROMOTED_SHA = 'd2419ee63c37c48c85687b457127815312e51ff5'


def _parts(tag):
    found = re.match(r'^v(\d+)\.(\d+)\.(\d+)$', tag)
    assert found, 'not a release tag: %r' % (tag,)
    return tuple(int(g) for g in found.groups())


def pin_at_least(version):
    """`(ok, message)` — is the install pin at or past `version`?

    `version` is the release that first had whatever the caller depends on.
    """
    pin = _parts(atlas.ATLAS_TAG)
    want = _parts(version)
    return pin >= want, (
        'the install pin is %s; a fresh install needs at least %s'
        % (atlas.ATLAS_TAG, version))
