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
"""Taking the ATLAS store back down again (W212).

⚠️ **The bug these exist for.** W205 added the reserved store — a loop-backed
ext4 image and three systemd mount units — and never wrote the counterpart in
`uninstall`. Three mount points live *inside* the install directory, and
`shutil.rmtree` cannot delete through a mount, so the uninstall removed the
containers and then left the device CA, every private key, the Postgres data
directory and `.env` on disk **while reporting that it had succeeded**. It was
found by auditing a box by hand after the operator ran it.

⚠️ What is *not* here: real mounts, a real loop device, a real `systemctl`.
Those need a kernel. What is checked is the part that was actually wrong — the
*order* of the teardown, and the reporting contract that hid the failure. Both
are decidable without a disk, which is the point of keeping them decidable.
"""

import importlib.util
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

from atlas_layout import deployment_dir  # noqa: E402


# --------------------------------------------------------------------------- #
# A fake root shell that records what it was asked to do
# --------------------------------------------------------------------------- #


class Recorder:
    """Stands in for `_run_root`, remembering the order of the calls.

    ⚠️ Order is what this file is about, so the recorder keeps a list and never
    a set.
    """

    def __init__(self, fail=(), escape=True):
        self.calls: list[list[str]] = []
        self.fail = fail
        self.escape = escape

    def __call__(self, argv, timeout=120):
        self.calls.append(list(argv))
        if argv[0] == "systemd-escape":
            if not self.escape:
                return 1, ""
            # What the real one returns: the path with slashes as dashes.
            return 0, _escape(argv[-1])
        for pattern in self.fail:
            if pattern in " ".join(argv):
                return 1, f"pretend failure: {pattern}"
        if argv[:2] == ["losetup", "-j"]:
            return 0, f"/dev/loop8: [2050]:1 ({atlas.STORE_IMAGE})"
        return 0, ""

    def ran(self, *fragments: str) -> list[list[str]]:
        return [c for c in self.calls
                if all(f in " ".join(c) for f in fragments)]

    def index_of(self, *fragments: str) -> int:
        for i, c in enumerate(self.calls):
            if all(f in " ".join(c) for f in fragments):
                return i
        raise AssertionError(f"never ran anything matching {fragments}")


def _posix(path) -> str:
    """Box-shaped. The module builds paths with `posixpath`."""
    return str(path).replace(chr(92), "/")


def _escape(path: str) -> str:
    return path.strip("/").replace("-", "\\x2d").replace("/", "-") + ".mount"


@pytest.fixture
def box(monkeypatch, tmp_path):
    """A pretend box: an install directory, and nothing actually mounted.

    ⚠️ **It redirects `install_base`, not `atlas_dir` (W233).**
    `instance_paths` used to be *rebased on* `atlas_dir`, deliberately, so
    that a fixture patching that one function moved every deployment with it.
    Nesting ended that: the root now holds the plain deployment rather than
    being it, so `instance_paths` asks `install_base` and `atlas_dir` is
    derived from the answer instead of deciding it.

    That is a better seam -- one function decides the layout instead of the
    plain deployment's path implying it -- but it is a **silent** break for
    any fixture still patching the old pivot: the module goes on resolving
    the real home, the directory does not exist, `remove_instance` skips it,
    and a test asserting on a *failed* teardown passes against a no-op.
    """
    monkeypatch.setattr(atlas, "install_base",
                        lambda ctx=None: str(tmp_path).replace(chr(92), '/'))
    base = deployment_dir("atlas")
    (base / "store").mkdir(parents=True)
    (base / "artifacts").mkdir()
    (base / "cache").mkdir()
    image = tmp_path / "var" / "store.img"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"not really an ext4 image")

    # ⚠️ POSIX-shaped: the module builds box paths with `posixpath`, and a
    # Windows temp path would produce separators that exist nowhere on a box.
    monkeypatch.setattr(atlas, "STORE_IMAGE", str(image).replace(chr(92), '/'))
    # Nothing is a mount point unless a test says so.
    monkeypatch.setattr(os.path, "ismount", lambda _p: False)
    return base


@pytest.fixture
def rec(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(atlas, "_run_root", recorder)
    return recorder


# --------------------------------------------------------------------------- #
# The order, which is the whole function
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# What it removes
# --------------------------------------------------------------------------- #


def test_a_parent_holding_someone_else_s_file_is_left_alone(box, rec):
    parent = pathlib.Path(os.path.dirname(atlas.STORE_IMAGE))
    (parent / "somebody-elses.conf").write_text("keep me", encoding="utf-8")

    atlas.remove_store({}, lambda *_: None)

    assert parent.is_dir(), "removed a directory that still had a file in it"
    assert (parent / "somebody-elses.conf").exists()


# --------------------------------------------------------------------------- #
# Unmounting what systemd will not
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Idempotence
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# The reporting contract that hid the bug
# --------------------------------------------------------------------------- #


class FakeCtx(dict):
    """Just enough console for `uninstall` to run.

    ⚠️ **`save_settings` replaces; it must not merge.** Written as
    `self.settings.update(s)` this fake could not express a *deletion* — and
    `uninstall` clears keys by popping them from the copy it loaded, so the
    assertion that a failed uninstall keeps `atlas_pg_password` held no matter
    what the code did. A mutation caught it: the test passed with the guard
    removed. The harness lied before the code did, which is the second time
    that has happened on this project.
    """

    def __init__(self):
        super().__init__()
        self.settings = {"atlas_pg_password": "x", "atlas_enabled": True}
        self.update({
            "_module_git": lambda *a, **k: None,
            "_sudo_wrap": lambda argv: argv,
            "_fw_remove": lambda *a: None,
            "load_settings": lambda: dict(self.settings),
            "save_settings": self._save,
            "generate_caddyfile": lambda _s: None,
            "_caddy_reload": lambda: None,
            "_deregister_authentik_proxy_app": lambda *a: None,
        })

    def _save(self, s):
        self.settings = dict(s)


@pytest.fixture
def uninstallable(box, monkeypatch):
    monkeypatch.setattr(atlas, "_compose", lambda *a, **k: None)
    monkeypatch.setattr(atlas, "_run", lambda *a: True)
    monkeypatch.setattr(atlas, "_caddy_ca_dir", lambda inst=None: None)
    monkeypatch.setattr(atlas, "_stale_deploy_key", lambda _d: [])
    return FakeCtx()


def test_uninstall_stops_and_reports_failure_when_the_store_will_not_go(
    uninstallable, box, monkeypatch
):
    """⚠️ **The contract that was missing.** The store failing means the mounts
    are still inside the install directory, so deleting it would half-succeed.
    Stop, say so, and leave the box re-runnable."""
    # ⚠️ The mechanism changed and the property did not. There is nothing to
    # unmount now; what fails instead is deleting a tree the containers own --
    # `pgdata` is uid 70, `artifacts` and `cache` are the application's uid --
    # which is exactly what the operator hit on the first real teardown.
    monkeypatch.setattr(
        atlas, "_rm_priv",
        lambda path, inside: "could not remove %s: Permission denied" % path)

    result = atlas.uninstall(uninstallable, None, {})

    assert result["success"] is False
    assert "store could not be removed" in result["error"]
    assert box.exists(), "deleted the install directory after the store failed"


def test_uninstall_reports_failure_when_the_directory_will_not_go(
    uninstallable, box, rec, monkeypatch
):
    """⚠️ The exact bug. This used to append "NOT removed: …" to the steps and
    return success anyway, which is why a box with the device CA, every private
    key, the database and `.env` still on it was reported as clean."""
    def refuse(path):
        raise OSError(16, "Device or resource busy")

    monkeypatch.setattr(atlas.shutil, "rmtree", refuse)
    # ⚠️ The brokered fallback has to fail too, or `_rm_priv` succeeds and
    # there is nothing to report. Without this the test would assert on a
    # failure path it had just repaired.
    monkeypatch.setattr(atlas, "_broker_script", lambda: None)

    result = atlas.uninstall(uninstallable, None, {})

    assert result["success"] is False
    assert "could not be removed" in result["error"]


def test_a_failed_uninstall_does_not_clear_the_settings(
    uninstallable, box, rec, monkeypatch
):
    """⚠️ Clearing `atlas_pg_password` while the database survives is what arms
    the next install to fail: deploy generates a new password, Postgres keeps the
    old one on a non-empty data directory, and the API cannot authenticate."""
    monkeypatch.setattr(
        atlas.shutil, "rmtree",
        lambda _p: (_ for _ in ()).throw(OSError(16, "Device or resource busy")),
    )
    monkeypatch.setattr(atlas, "_broker_script", lambda: None)

    atlas.uninstall(uninstallable, None, {})

    assert uninstallable.settings.get("atlas_pg_password") == "x", (
        "cleared the database password while the database was still on disk"
    )

