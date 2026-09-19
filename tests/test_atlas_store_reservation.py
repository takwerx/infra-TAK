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
"""Whether the reservation actually reserves (W213).

⚠️ **The bug these exist for, and why the existing tests missed it.** W205 built
the store with `fallocate` — deliberately, over `truncate`, with a comment saying
*"a sparse file reserves nothing"* — and then ran `mkfs.ext4`, which discards its
target. On a regular file on ext4 a discard is `FALLOC_FL_PUNCH_HOLE`, so `mkfs`
handed every reserved block straight back. The reservation reserved nothing for
its whole first release while the console reported that it had.

`test_atlas_store_sizing.py` says in its own docstring that it excludes
"creating the image, making the filesystem, mounting it" — which is precisely
where this lived. So the point of this file is to pull the decidable parts *out*
of that gap: the command that gets run, and the arithmetic that judges the
result. Both are checkable without a disk.

⚠️ What still cannot be checked here: that `-E nodiscard` has the effect claimed.
That needs a real ext4, and it is measured on the box instead — 5 GB fallocated
then `mkfs.ext4` → 67 MiB of real blocks, with `-E nodiscard` → 5121 MiB. The
numbers are recorded in `mkfs_argv`'s docstring so the next person does not have
to rediscover them.

⚠️ `os.stat_result` has no `st_blocks` on Windows, where these run. That is why
the arithmetic takes plain numbers and `allocated_bytes` returns `None` rather
than `0` when it cannot tell — otherwise this file could not exist on the
development machine at all.
"""

import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load_module():
    sys.path.insert(0, str(ROOT))
    import modules.atlas as module

    return module


atlas = _load_module()

GIB = 1024 ** 3


# --------------------------------------------------------------------------- #
# The command that was wrong
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Judging the result
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Measuring it
# --------------------------------------------------------------------------- #


def test_a_missing_image_measures_as_unknown_not_as_empty(tmp_path):
    """⚠️ Unknown, not zero — and the distinction matters, because `0` would
    send the repair path into declaring a real failure."""
    assert atlas.allocated_bytes(str(tmp_path / "absent.img")) is None


def test_an_unreadable_path_measures_as_unknown():
    """`os.stat` raises `ValueError`, not `OSError`, on an embedded NUL — found
    the hard way twice on this project."""
    assert atlas.allocated_bytes("\x00") is None


#: Whether this platform can answer the question at all. Windows cannot.
HAS_ST_BLOCKS = hasattr(os.stat(__file__), "st_blocks")


@pytest.mark.skipif(not HAS_ST_BLOCKS, reason="no st_blocks on this platform")
def test_a_real_file_measures_its_own_blocks(tmp_path):
    """Only where the platform can answer. On Windows this is skipped rather
    than faked, because a faked measurement is what this whole item is about."""
    target = tmp_path / "some.bin"
    target.write_bytes(b"x" * 200_000)

    measured = atlas.allocated_bytes(str(target))

    assert measured is not None
    assert measured >= 200_000


# --------------------------------------------------------------------------- #
# What the console is told
# --------------------------------------------------------------------------- #


class FakeStat:
    """Only the field `store_facts` reads."""

    def __init__(self, size):
        self.st_size = size


@pytest.fixture
def facts(monkeypatch, tmp_path):
    """`store_facts` against an image whose apparent and real sizes we set.

    ⚠️ **No real image is created here, and that is not laziness.** The first
    version did `truncate(100 * GIB)` to fake a sparse file — which is sparse on
    ext4 and *fully allocated* on NTFS, where these tests run. It wrote 145 GB
    into pytest's temp directory before the run was killed. `store_facts` only
    ever reads `os.path.exists` and `st_size`, so those are what get faked;
    inventing a real 100 GB file to test a size calculation was never necessary.

    Both fakes delegate for every other path, because patching `os.stat`
    wholesale would break pytest's own bookkeeping mid-test.
    """
    image = str(tmp_path / "store.img")
    monkeypatch.setattr(atlas, "STORE_IMAGE", image)
    monkeypatch.setattr(atlas, "_disk_free", lambda _p: (500 * GIB, 400 * GIB))
    real_stat, real_exists = os.stat, os.path.exists

    def build(apparent, allocated):
        monkeypatch.setattr(
            atlas.os, "stat",
            lambda p, *a, **k: (FakeStat(apparent) if str(p) == image
                                else real_stat(p, *a, **k)),
        )
        monkeypatch.setattr(
            atlas.os.path, "exists",
            lambda p: True if str(p) == image else real_exists(p),
        )
        monkeypatch.setattr(atlas, "allocated_bytes", lambda _p: allocated)
        return atlas.store_facts(None)

    return build


def test_no_image_reports_nothing_reserved(monkeypatch, tmp_path):
    monkeypatch.setattr(atlas, "STORE_IMAGE", str(tmp_path / "absent.img"))
    monkeypatch.setattr(atlas, "_disk_free", lambda _p: (500 * GIB, 400 * GIB))

    f = atlas.store_facts(None)

    assert f["reserved_gb"] == 0
    assert f["allocated_gb"] == 0
    assert f["fully_reserved"] is False


# --------------------------------------------------------------------------- #
# The repair path
# --------------------------------------------------------------------------- #


class Fallocate:
    """Records `fallocate` calls and can pretend the image fills up."""

    def __init__(self, after=None, rc=0):
        self.calls = []
        self.after = after
        self.rc = rc

    def __call__(self, argv, timeout=120):
        self.calls.append(list(argv))
        return self.rc, "" if self.rc == 0 else "pretend fallocate failure"


@pytest.fixture
def repair(monkeypatch):
    """`_reserve_blocks` with a controllable allocation reading."""
    def run(size, before, after, rc=0):
        runner = Fallocate(rc=rc)
        readings = iter([before, after])
        monkeypatch.setattr(atlas, "_run_root", runner)
        monkeypatch.setattr(
            atlas, "allocated_bytes",
            lambda _p: next(readings, after),
        )
        err = atlas._reserve_blocks(size, lambda *_: None)
        return err, runner

    return run

