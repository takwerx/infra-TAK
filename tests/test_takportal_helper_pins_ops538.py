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
"""TAK Portal 2.0.31 / 2.0.32 marketplace helpers are pinned (ops #538).

The broker grants root only to a marketplace helper whose sha256 it has reviewed.
Security reviewed the helpers shipped in TAK Portal 2.0.31 (version 4, tighter
`caddy validate` permission-denied test) and 2.0.32 (adds a bounded Docker pull
retry), diffed against the already-pinned 2.0.29/2.0.30 helper. Until both hashes
were pinned, a box that updated TAK Portal to 2.0.31 or 2.0.32 got no helper grant.

The fixtures are the exact files from the upstream tags (AGPL-3.0, same as this
repo): tests/fixtures/takportal-marketplace-helper-<version>.
"""

import hashlib
import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
FIX = REPO / 'tests' / 'fixtures'

SHA = {
    '2.0.30': '4d093f4b834bda8ad712c5df4155929dd9b40f4d14ecded0cdd01b84d14c4559',
    '2.0.31': '0eb07556d0d3618574ce4b135bf8866fca269c053c67f61c8e0ad97defa26cb6',
    '2.0.32': '5996839d6d663e3f1c6230a7d64c8f2580e8776b6be1ee708e9f02eec8b86d58',
}
OLDER_PINNED = (
    'c240a12aa8978e106c94c0303a0e116f3e08dff0ba7c6a9273c0422ad92e3bb4',   # 2.0.19-2.0.22
    SHA['2.0.30'],                                                        # 2.0.29/2.0.30
)


@pytest.fixture()
def b():
    spec = importlib.util.spec_from_file_location('takwerx_broker_t538', REPO / 'broker' / 'takwerx_broker.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _helper(ver):
    return (FIX / f'takportal-marketplace-helper-{ver}').read_bytes()


def _portal(tmp_path, monkeypatch, b, version, helper):
    home = tmp_path / 'home'
    d = home / 'TAK-Portal'
    (d / 'host-helpers').mkdir(parents=True, exist_ok=True)
    (d / 'package.json').write_text(json.dumps({'version': version}))
    (d / 'host-helpers' / 'marketplace-helper').write_bytes(helper)
    monkeypatch.setattr(b.pwd, 'getpwnam', lambda u: type('P', (), {'pw_dir': str(home)})())


@pytest.mark.parametrize('ver', sorted(SHA))
def test_fixture_is_the_reviewed_upstream_file(ver):
    assert hashlib.sha256(_helper(ver)).hexdigest() == SHA[ver]


@pytest.mark.parametrize('ver', ['2.0.31', '2.0.32'])
def test_new_helper_hash_is_pinned(b, ver):
    assert SHA[ver] in b.TAKPORTAL_HELPER_SHA256


def test_older_reviewed_hashes_stay_pinned(b):
    for h in OLDER_PINNED:
        assert h in b.TAKPORTAL_HELPER_SHA256


def test_unreviewed_older_helpers_stay_unpinned(b):
    # 2.0.23-2.0.28 ran `caddy validate` as root on caller text (ops #295, #340).
    assert 'e05feed906832e649b5257caf840c19044aeac45352952b268e547117dc4c7f2' not in b.TAKPORTAL_HELPER_SHA256
    assert 'ba749885c92e9ea097012438a98cc0b45f3fabf4d46252d1bac54ef1720123cd' not in b.TAKPORTAL_HELPER_SHA256


@pytest.mark.parametrize('ver', ['2.0.30', '2.0.31', '2.0.32'])
def test_portal_with_the_real_helper_gets_the_grant(b, tmp_path, monkeypatch, ver):
    helper = _helper(ver)
    _portal(tmp_path, monkeypatch, b, ver, helper)
    d = b._takportal_decide()
    assert d['variant'] == 'hardened'
    assert d['helper_bytes'] == helper
    assert d['helper_unreviewed'] is False and d['helper_reason'] == ''


@pytest.mark.parametrize('ver', ['2.0.31', '2.0.32'])
def test_any_other_bytes_are_still_refused(b, tmp_path, monkeypatch, ver):
    for tampered in (_helper(ver) + b'\n# extra\n', _helper(ver).replace(b'caddy', b'cadd1', 1),
                     b'#!/bin/bash\nrm -rf /\n'):
        _portal(tmp_path, monkeypatch, b, ver, tampered)
        d = b._takportal_decide()
        assert d['helper_bytes'] is None
        assert d['helper_unreviewed'] is True and 'not reviewed' in d['helper_reason']


def test_installed_older_helper_is_replaced_by_the_portals_new_one(b, monkeypatch):
    # A box on 2.0.30 holds the 4d093f4b helper; after the Portal update to 2.0.32 the grant must
    # move to the 2.0.32 bytes, not stay on "some pinned helper".
    on_disk = {'data': _helper('2.0.30')}

    def fake_root_file_ok(path, want_sha256=None, want_bytes=None):
        if want_bytes is not None:
            return on_disk['data'] == want_bytes
        return hashlib.sha256(on_disk['data']).hexdigest() in (want_sha256 or ())

    monkeypatch.setattr(b, '_root_file_ok', fake_root_file_ok)
    assert b._takportal_helper_ok()
    assert not b._takportal_helper_current({'helper_bytes': _helper('2.0.32')})
    on_disk['data'] = _helper('2.0.32')
    assert b._takportal_helper_current({'helper_bytes': _helper('2.0.32')})
