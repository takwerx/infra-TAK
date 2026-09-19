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
"""Fixed and dynamic sizing (W216, chunk 2).

Two modes with one code path and a handful of differences, each of which is the
difference between a reservation and a ceiling:

* `fallocate` vs `truncate` when the image is created;
* `-E nodiscard` present or absent, so `mkfs` either keeps the blocks or hands
  them back;
* `discard` in the mount options, without which a dynamic store can only grow;
* `_reserve_blocks` running or not, because running it on a dynamic store would
  silently convert it into a fixed one;
* and **the second gauge**, without which a dynamic store reports free space the
  host may be unable to deliver.

⚠️ The last is the one that must not ship missing. A filesystem that is only a
ceiling will say "3.3 GB available" with an empty box underneath it, which is
exactly the class of authoritative-looking wrong number W213 removed.

Pure: the argv, the options and the arithmetic. The behaviour they produce was
measured on a real box and the numbers live in the docstrings.
"""

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules.atlas_instances import MODE_DYNAMIC, MODE_FIXED  # noqa: E402

GIB = 1024 ** 3


# --------------------------------------------------------------------------- #
# mkfs: keep the blocks, or hand them back
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Mount options: the half that makes shrink work
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# The second gauge
# --------------------------------------------------------------------------- #


def test_a_fixed_store_trusts_its_own_filesystem():
    """The blocks are already allocated, so the filesystem's answer *is* the
    truth and the host's free space cannot reduce it."""
    assert atlas.deliverable_free(50 * GIB, 1 * GIB, MODE_FIXED) == 50 * GIB


def test_a_dynamic_store_reports_the_smaller_of_the_two():
    """⚠️ **The number that would otherwise lie.** The agency's filesystem says
    50 GB free; the box has 8 GB to give. 8 is the honest answer."""
    assert atlas.deliverable_free(50 * GIB, 8 * GIB, MODE_DYNAMIC) == 8 * GIB


def test_a_dynamic_store_is_still_capped_by_its_own_ceiling():
    """The other direction: the box is roomy, the agency is nearly full."""
    assert atlas.deliverable_free(2 * GIB, 200 * GIB, MODE_DYNAMIC) == 2 * GIB


def test_neither_gauge_goes_negative():
    """A negative remainder would draw a bar pointing the wrong way — the same
    guard the ATLAS-side meter already carries."""
    assert atlas.deliverable_free(-5, 10, MODE_DYNAMIC) == 0
    assert atlas.deliverable_free(10, -5, MODE_DYNAMIC) == 0
    assert atlas.deliverable_free(-5, -5, MODE_FIXED) == 0


def test_the_facts_carry_the_mode_and_say_whether_space_is_held():
    """⚠️ `size_is_reserved` exists so no caller can render a ceiling as though
    it were held space. One field, two meanings, was the W213 shape of bug."""
    facts = atlas.store_facts(None, mode=MODE_DYNAMIC)

    assert facts['mode'] == MODE_DYNAMIC
    assert facts['size_is_reserved'] is False


def test_the_facts_default_to_fixed():
    facts = atlas.store_facts(None)

    assert facts['mode'] == MODE_FIXED
    assert facts['size_is_reserved'] is True


def test_the_facts_always_offer_the_deliverable_figure(monkeypatch):
    """Present in both modes, so the page never has to ask which one it is
    looking at before it can draw a bar."""
    monkeypatch.setattr(atlas, '_disk_free', lambda _p: (500 * GIB, 400 * GIB))

    for mode in (MODE_FIXED, MODE_DYNAMIC):
        assert 'deliverable_gb' in atlas.store_facts(None, mode=mode)


# --------------------------------------------------------------------------- #
# ensure_store: what each mode actually runs
# --------------------------------------------------------------------------- #


class Runner:
    """Records the root commands, and pretends they all succeed."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, timeout=120):
        self.calls.append(list(argv))
        if argv[0] == 'systemd-escape':
            return 0, 'root-atlas-store.mount'
        return 0, ''

    def ran(self, *fragments):
        return [c for c in self.calls
                if all(f in ' '.join(c) for f in fragments)]


@pytest.fixture
def store(monkeypatch, tmp_path):
    """`ensure_store` against a temporary image, with root commands recorded."""
    base = tmp_path / 'atlas'
    (base / 'store').mkdir(parents=True)
    image = tmp_path / 'var' / 'store.img'
    image.parent.mkdir(parents=True)
    # ⚠️ POSIX-shaped, because these fixtures simulate a Linux box and the
    # module now builds box paths with `posixpath`. A Windows temp path here
    # produces mixed separators that exist nowhere in production.
    posix_base = str(base).replace(chr(92), '/')

    runner = Runner()
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(image).replace(chr(92), '/'))
    monkeypatch.setattr(atlas, 'atlas_dir', lambda _c=None: posix_base)
    monkeypatch.setattr(atlas, '_run_root', runner)
    monkeypatch.setattr(atlas, '_bind_unit', lambda *a, **k: None)
    monkeypatch.setattr(atlas, '_bind_pg_volume', lambda *a, **k: None)
    monkeypatch.setattr(atlas.os, 'chown', lambda *a: None, raising=False)
    monkeypatch.setattr(atlas.os, 'chmod', lambda *a: None)
    monkeypatch.setattr(atlas.os.path, 'ismount', lambda _p: True)
    return runner
