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
"""An ETL on hold stays uninstallable (operator, v10.4.0 T&E, 2026-11-15).

etl-arcgis: a security report sent to the COE on 2026-11-09 (ticket #979) held it. The COE fixed
the problem in v7.34.0 (newest v7.35.1), the diff was reviewed and the ETL ran on a box
(ops #899, 2026-11-17), so the hold is lifted and the catalog pins v7.35.1. It must never go
back to a version before 7.34.0.

etl-cotrip-signs and etl-cotrip-weather (ops #833, 2026-11-16): their Dockerfile security report
went to the COE the same day and is still open, so they stay held."""

import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from modules import etlrunner as etl  # noqa: E402

HOLDS = json.loads((REPO / 'modules' / 'etlrunner' / 'holds.json').read_text())['holds']
HOLDS_FILE = REPO / 'modules' / 'etlrunner' / 'holds.json'
# Every ETL still held for the COE security report of 2026-11-09. Each must stay in holds.json.
COE_HELD = ['etl-cotrip-signs', 'etl-cotrip-weather']
# etl-arcgis was held too until the COE fixed it upstream (v7.34.0 and later; ops #899).
ARCGIS_FIXED_SHA = '7c99969125671cef4256e98100a614fc841a3c59'     # v7.35.1 (annotated tag peeled)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, REPO / 'tools' / f'{name}.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _semver(v):
    return tuple(int(x) for x in v.split('.'))


def test_arcgis_is_not_held_and_the_catalog_offers_the_fixed_release():
    assert 'etl-arcgis' not in HOLDS
    e = next(x for x in etl.bundled_catalog()['entries'] if x['prefix'] == 'etl-arcgis')
    assert e['reviewed'] and 'note' not in e
    assert etl.installable(e) == (True, '')
    assert (e['ref'], e['version'], e['sha']) == ('v7.35.1', '7.35.1', ARCGIS_FIXED_SHA)
    assert ARCGIS_FIXED_SHA in e['logo'] and ARCGIS_FIXED_SHA in e['readme']


def test_arcgis_pin_is_never_older_than_the_security_fix():
    e = next(x for x in etl.bundled_catalog()['entries'] if x['prefix'] == 'etl-arcgis')
    assert _semver(e['version']) >= (7, 34, 0)


def test_every_held_entry_in_the_bundle_is_unreviewed():
    for e in etl.bundled_catalog()['entries']:
        if e['prefix'] in HOLDS:
            assert e['reviewed'] is None


def test_sync_keeps_a_held_entry_unreviewed(tmp_path):
    sync = _load('etl_catalog_sync')
    ents = [{'prefix': 'etl-cotrip-signs', 'reviewed': '2026-11-09 /module-scan'},
            {'prefix': 'etl-geojson', 'reviewed': '2026-11-09 /module-scan'}]
    sync.apply_holds(ents)
    assert ents[0]['reviewed'] is None and ents[0]['note'] == HOLDS['etl-cotrip-signs']
    assert ents[1]['reviewed'] == '2026-11-09 /module-scan' and 'note' not in ents[1]


def test_review_tool_does_not_mark_a_held_entry_reviewed_on_a_pass(tmp_path, monkeypatch):
    rev = _load('etl_catalog_review')
    cat = tmp_path / 'catalog.json'
    (tmp_path / 'holds.json').write_text(json.dumps({'holds': {'etl-arcgis': 'held'}}))
    cat.write_text(json.dumps({'schema': 1, 'serial': 1, 'entries': [
        {'prefix': 'etl-arcgis', 'sha': 'a' * 40, 'reviewed': None},
        {'prefix': 'etl-geojson', 'sha': 'b' * 40, 'reviewed': None}]}))
    res = tmp_path / 'scan.json'
    res.write_text(json.dumps({'results': [
        {'prefix': 'etl-arcgis', 'verdict': 'PASS', 'sha': 'a' * 40, 'head_verified': True},
        {'prefix': 'etl-geojson', 'verdict': 'PASS', 'sha': 'b' * 40, 'head_verified': True}]}))
    monkeypatch.setattr(rev, 'CATALOG', str(cat))
    monkeypatch.setattr(sys, 'argv', ['x', '--date', '2026-11-16', str(res)])
    rev.main()
    out = {e['prefix']: e for e in json.loads(cat.read_text())['entries']}
    assert out['etl-arcgis']['reviewed'] is None and out['etl-arcgis']['note'] == 'held'
    assert out['etl-geojson']['reviewed'] == '2026-11-16 /module-scan'


# ── ops #833: etl-cotrip-signs and etl-cotrip-weather ───────────────────────────────────

def test_every_coe_held_etl_is_in_holds_json_with_the_standard_reason():
    for prefix in COE_HELD:
        assert prefix in HOLDS, f'{prefix} must stay on hold'
        assert HOLDS[prefix] == HOLDS['etl-cotrip-signs']
        assert 'security report sent to the COE on 2026-11-09 is still open' in HOLDS[prefix]


@pytest.mark.parametrize('prefix', ['etl-cotrip-signs', 'etl-cotrip-weather'])
def test_cotrip_signs_and_weather_are_in_the_bundle_and_not_installable(prefix):
    e = next(x for x in etl.bundled_catalog()['entries'] if x['prefix'] == prefix)
    assert prefix in HOLDS
    assert e['reviewed'] is None
    assert etl.installable(e) == (False, 'Waiting for security review')


def test_the_other_cotrip_etls_and_arcgis_are_not_held():
    for prefix in ('etl-arcgis', 'etl-cotrip-incidents', 'etl-cotrip-plows', 'etl-cotrip-cameras'):
        assert prefix not in HOLDS


def test_sync_keeps_the_cotrip_etls_unreviewed_using_the_real_holds_file():
    sync = _load('etl_catalog_sync')
    reviewed = '2026-11-09 /module-scan'
    ents = [{'prefix': p, 'reviewed': reviewed} for p in COE_HELD + ['etl-arcgis', 'etl-cotrip-incidents']]
    sync.apply_holds(ents, path=str(HOLDS_FILE))
    for e in ents[:len(COE_HELD)]:
        assert e['reviewed'] is None and e['note'] == HOLDS[e['prefix']]
    for e in ents[len(COE_HELD):]:
        assert e['reviewed'] == reviewed and 'note' not in e


def test_review_tool_does_not_mark_the_cotrip_etls_reviewed_on_a_pass(tmp_path, monkeypatch):
    rev = _load('etl_catalog_review')
    prefixes = COE_HELD + ['etl-arcgis', 'etl-cotrip-incidents']
    shutil.copy(HOLDS_FILE, tmp_path / 'holds.json')           # the real list, not a stand-in
    cat = tmp_path / 'catalog.json'
    cat.write_text(json.dumps({'schema': 1, 'serial': 1, 'entries': [
        {'prefix': p, 'sha': 'a' * 40, 'reviewed': None} for p in prefixes]}))
    res = tmp_path / 'scan.json'
    res.write_text(json.dumps({'results': [
        {'prefix': p, 'verdict': 'PASS', 'sha': 'a' * 40, 'head_verified': True} for p in prefixes]}))
    monkeypatch.setattr(rev, 'CATALOG', str(cat))
    monkeypatch.setattr(sys, 'argv', ['x', '--date', '2026-11-16', str(res)])
    rev.main()
    out = {e['prefix']: e for e in json.loads(cat.read_text())['entries']}
    for p in COE_HELD:
        assert out[p]['reviewed'] is None and out[p]['note'] == HOLDS[p]
    for p in ('etl-arcgis', 'etl-cotrip-incidents'):
        assert out[p]['reviewed'] == '2026-11-16 /module-scan' and 'note' not in out[p]


# ── ops #899: an operator who has the old etl-arcgis installed hears about the new one ────────

def test_guard_dog_tells_an_operator_with_the_old_arcgis_to_update():
    catalog = etl.load_catalog()
    items, _known = etl.notify_items(catalog, {'etl-arcgis': ['7.33.0']}, {'etl-arcgis'})
    mine = [i for i in items if i['key'] == 'etl:etl-arcgis']
    assert len(mine) == 1
    assert mine[0]['installed'] == 'v7.33.0' and mine[0]['target'] == 'v7.35.1'
    assert mine[0]['identity'] == ARCGIS_FIXED_SHA
    assert 'Update' in mine[0]['how']


def test_guard_dog_stays_quiet_about_the_held_cotrip_etls():
    catalog = etl.load_catalog()
    installed = {p: ['0.0.1'] for p in COE_HELD}
    items, _known = etl.notify_items(catalog, installed, set(COE_HELD))
    assert not [i for i in items if i['key'] in {f'etl:{p}' for p in COE_HELD}]
