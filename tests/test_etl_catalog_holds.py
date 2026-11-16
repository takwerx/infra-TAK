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

etl-arcgis: a security report sent to the COE on 2026-11-09 (ticket #979) is still open and
7.33.0 only bumped dependencies. Held until fixed. A later sync or scan must not re-offer it."""

import importlib.util
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from modules import etlrunner as etl  # noqa: E402

HOLDS = json.loads((REPO / 'modules' / 'etlrunner' / 'holds.json').read_text())['holds']


def _load(name):
    spec = importlib.util.spec_from_file_location(name, REPO / 'tools' / f'{name}.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_arcgis_is_held_and_the_bundled_catalog_refuses_it():
    assert 'etl-arcgis' in HOLDS
    e = next(x for x in etl.bundled_catalog()['entries'] if x['prefix'] == 'etl-arcgis')
    assert e['reviewed'] is None and e['note'] == HOLDS['etl-arcgis']
    assert etl.installable(e) == (False, 'Waiting for security review')


def test_every_held_entry_in_the_bundle_is_unreviewed():
    for e in etl.bundled_catalog()['entries']:
        if e['prefix'] in HOLDS:
            assert e['reviewed'] is None


def test_sync_keeps_a_held_entry_unreviewed(tmp_path):
    sync = _load('etl_catalog_sync')
    ents = [{'prefix': 'etl-arcgis', 'reviewed': '2026-11-09 /module-scan'},
            {'prefix': 'etl-geojson', 'reviewed': '2026-11-09 /module-scan'}]
    sync.apply_holds(ents)
    assert ents[0]['reviewed'] is None and ents[0]['note'] == HOLDS['etl-arcgis']
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
