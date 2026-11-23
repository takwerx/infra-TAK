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
"""TAK Portal 2.0.39 marketplace helper (version 5) is pinned (ops #1043).

The broker grants root only to a marketplace helper whose sha256 it has reviewed. TAK Portal
2.0.39 ships helper version 5: one new function, require_checkout_package_json(), replaces the
four `[ -d "$ct" ]` checks and refuses a CloudTAK folder that has no api/package.json. It only
refuses more. Until its hash is pinned, a box on 2.0.39 keeps the older helper and shows
"newer version not reviewed yet".

The fixture is the exact file from the upstream tag (AGPL-3.0, same as this repo):
tests/fixtures/takportal-marketplace-helper-2.0.39.
"""

import hashlib
import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
FIX = REPO / 'tests' / 'fixtures'

SHA_2039 = '11b953ada3cfe5dad8c37ec599fa759449841e8afef9ff7de7aeef025e00bd30'
OLDER_PINNED = (
    'c240a12aa8978e106c94c0303a0e116f3e08dff0ba7c6a9273c0422ad92e3bb4',   # 2.0.19-2.0.22
    '4d093f4b834bda8ad712c5df4155929dd9b40f4d14ecded0cdd01b84d14c4559',   # 2.0.29/2.0.30
    '0eb07556d0d3618574ce4b135bf8866fca269c053c67f61c8e0ad97defa26cb6',   # 2.0.31
    '5996839d6d663e3f1c6230a7d64c8f2580e8776b6be1ee708e9f02eec8b86d58',   # 2.0.32
    'd6e9238bbc09f6dda594f5e365b3daaf32a225a42f1bf0ad46201a4dc794ac04',   # 2.0.33
    '4dfeacd03abfb6c3b41add51936255e48fdf370988891d0b65f66ac5db4234e3',   # 2.0.34 to 2.0.38
)


@pytest.fixture()
def b():
    spec = importlib.util.spec_from_file_location('takwerx_broker_t1043', REPO / 'broker' / 'takwerx_broker.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _helper(ver='2.0.39'):
    return (FIX / f'takportal-marketplace-helper-{ver}').read_bytes()


def _portal(tmp_path, monkeypatch, b, version, helper):
    home = tmp_path / 'home'
    d = home / 'TAK-Portal'
    (d / 'host-helpers').mkdir(parents=True, exist_ok=True)
    (d / 'package.json').write_text(json.dumps({'version': version}))
    (d / 'host-helpers' / 'marketplace-helper').write_bytes(helper)
    monkeypatch.setattr(b.pwd, 'getpwnam', lambda u: type('P', (), {'pw_dir': str(home)})())


def test_fixture_is_the_upstream_file():
    assert hashlib.sha256(_helper()).hexdigest() == SHA_2039


def test_2_0_39_helper_hash_is_pinned(b):
    assert SHA_2039 in b.TAKPORTAL_HELPER_SHA256


def test_older_reviewed_hashes_stay_pinned(b):
    for h in OLDER_PINNED:
        assert h in b.TAKPORTAL_HELPER_SHA256


def test_unreviewed_older_helpers_stay_unpinned(b):
    # 2.0.23-2.0.28 ran `caddy validate` as root on caller text (ops #295, #340).
    assert 'e05feed906832e649b5257caf840c19044aeac45352952b268e547117dc4c7f2' not in b.TAKPORTAL_HELPER_SHA256
    assert 'ba749885c92e9ea097012438a98cc0b45f3fabf4d46252d1bac54ef1720123cd' not in b.TAKPORTAL_HELPER_SHA256


def test_nothing_else_got_pinned(b):
    assert set(b.TAKPORTAL_HELPER_SHA256) == set(OLDER_PINNED) | {SHA_2039}


def test_portal_2_0_39_with_the_real_helper_gets_the_grant(b, tmp_path, monkeypatch):
    helper = _helper()
    _portal(tmp_path, monkeypatch, b, '2.0.39', helper)
    d = b._takportal_decide()
    assert d['variant'] == 'hardened'
    assert d['helper_bytes'] == helper
    assert d['helper_unreviewed'] is False and d['helper_reason'] == ''


def test_any_other_bytes_are_still_refused(b, tmp_path, monkeypatch):
    for tampered in (_helper() + b'\n# extra\n', _helper().replace(b'package.json', b'package.jsom', 1),
                     b'#!/bin/bash\nrm -rf /\n'):
        _portal(tmp_path, monkeypatch, b, '2.0.39', tampered)
        d = b._takportal_decide()
        assert d['helper_bytes'] is None
        assert d['helper_unreviewed'] is True and 'not reviewed' in d['helper_reason']


def test_installed_2_0_38_helper_is_replaced_by_the_portals_new_one(b, monkeypatch):
    # A box on 2.0.38 holds the 4dfeacd0 helper; after the Portal update to 2.0.39 the grant must
    # move to the 2.0.39 bytes, not stay on "some pinned helper".
    on_disk = {'data': _helper('2.0.34')}   # 2.0.34 to 2.0.38 are the same file

    def fake_root_file_ok(path, want_sha256=None, want_bytes=None):
        if want_bytes is not None:
            return on_disk['data'] == want_bytes
        return hashlib.sha256(on_disk['data']).hexdigest() in (want_sha256 or ())

    monkeypatch.setattr(b, '_root_file_ok', fake_root_file_ok)
    assert b._takportal_helper_ok()
    assert not b._takportal_helper_current({'helper_bytes': _helper()})
    on_disk['data'] = _helper()
    assert b._takportal_helper_current({'helper_bytes': _helper()})


def test_the_only_change_from_2_0_38_is_a_stricter_check():
    # Reads the two fixtures: every changed line is the version, the new function, or a call to it.
    old = _helper('2.0.34').decode().splitlines()
    new = _helper().decode().splitlines()
    added = [ln for ln in new if ln not in old]
    allowed = ('HELPER_VERSION=5', 'require_checkout_package_json')
    for ln in added:
        s = ln.strip()
        assert (s.startswith('#') or s in ('}', '') or any(a in s for a in allowed)
                or s.startswith(('local ct=', '[ -n "$ct" ]', '[ -d "$ct" ]', '[ -f "$ct/api/package.json" ]'))), ln
    assert 'HELPER_VERSION=5' in new


def test_console_note_names_2_0_39_as_the_newest_pinned():
    src = (REPO / 'app.py').read_text()
    assert 'On a Portal newer than 2.0.39 they wait' in src
