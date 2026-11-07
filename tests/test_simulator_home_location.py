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
"""A scenario with a home location runs there (TAK Simulator).

A scenario written around a real place (a creek mouth, a stadium) carried its location in
`center`, but nothing used it: the scenario list dropped it, the console's Start sent the
typed center (default Nashville) and the CloudTAK panel sent the map center, so every unit
landed somewhere else. The operator had to type coordinates the file already held.

Also: `sensor.aim: orbit_center` keeps an orbiting unit's cone on the orbit's center (a
helicopter circling a scene with its FLIR on it) instead of along its heading.
"""

import json
import os
import pathlib
import sys
import tempfile
import time
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / 'simulator'))

from engine import core, geo, scenario as sc, sim  # noqa: E402

HOME = {'lat': 38.433496, 'lon': -81.853940}


def _doc(center=HOME):
    d = {
        'title': 'Home test', 'version': 1, 'duration_s': 60, 'loop': False,
        'defaults': {'lane': '1'},
        'entities': [{'id': 'u1', 'callsign': 'U1', 'type': 'a-f-G-E-V-C',
                      'path': {'kind': 'static', 'at': [0, 0]}}],
        'events': [],
    }
    if center is not None:
        d['center'] = center
    return d


def _engine(tmp, docs):
    scen = os.path.join(tmp, 'scenarios')
    certs = os.path.join(tmp, 'certs')
    os.makedirs(scen)
    os.makedirs(certs)
    for name, doc in docs.items():
        with open(os.path.join(scen, f'{name}.json'), 'w') as f:
            json.dump(doc, f)
    open(os.path.join(certs, 'lane-1.pem'), 'w').close()
    with open(os.path.join(certs, core.LANES_FILE), 'w') as f:
        json.dump({'1': 'tak_simulation'}, f)
    cfg = core.config_from_env({'SIM_DRY_RUN': '1', 'SIM_CERT_DIR': certs,
                                'SIM_SCENARIO_DIR': scen, 'SIM_ACTIVATE_GROUPS': '0',
                                'SIM_CONNECT_WAIT_S': '5'})
    return core.Engine(cfg)


def _stop(eng):
    if eng.run is not None:
        eng.run.stop()
        deadline = time.monotonic() + 5
        while eng.run.state != 'stopped' and time.monotonic() < deadline:
            time.sleep(0.05)


def test_summary_carries_the_home_location():
    assert sc.summarize(sc.validate(_doc(), 'site'))['center'] == HOME
    assert sc.summarize(sc.validate(_doc(center=None), 'preset'))['center'] is None


def test_run_without_center_uses_the_home_location():
    with tempfile.TemporaryDirectory() as tmp:
        eng = _engine(tmp, {'site': _doc()})
        try:
            res = eng.start_run({'scenario': 'site'})
            assert res['center'] == HOME
        finally:
            _stop(eng)


def test_an_explicit_center_still_moves_it():
    with tempfile.TemporaryDirectory() as tmp:
        eng = _engine(tmp, {'site': _doc()})
        try:
            res = eng.start_run({'scenario': 'site', 'center': {'lat': 36.16, 'lon': -86.78}})
            assert res['center'] == {'lat': 36.16, 'lon': -86.78}
        finally:
            _stop(eng)


def test_a_preset_without_a_home_still_needs_a_center():
    with tempfile.TemporaryDirectory() as tmp:
        eng = _engine(tmp, {'preset': _doc(center=None)})
        try:
            eng.start_run({'scenario': 'preset'})
        except sc.ScenarioError as e:
            assert any('center' in m for m in e.errors)
        else:
            raise AssertionError('a run with no center and no home location must be rejected')
        finally:
            _stop(eng)


def test_open_for_editing_reopens_at_the_home_location_by_default():
    with tempfile.TemporaryDirectory() as tmp:
        eng = _engine(tmp, {'site': _doc()})
        try:
            res = eng.start_live({'from': 'site', 'center': {'lat': 1.0, 'lon': 1.0}})
            assert res['center'] == HOME
        finally:
            _stop(eng)


def test_open_for_editing_a_preset_uses_the_request_center():
    with tempfile.TemporaryDirectory() as tmp:
        eng = _engine(tmp, {'preset': _doc(center=None)})
        try:
            res = eng.start_live({'from': 'preset', 'center': {'lat': 1.0, 'lon': 2.0}})
            assert res['center'] == {'lat': 1.0, 'lon': 2.0}
        finally:
            _stop(eng)


def test_sensor_aim_defaults_to_heading_and_validates():
    d = _doc()
    d['entities'][0]['sensor'] = {'fov': 20}
    assert sc.validate(d, 'x')['entities'][0]['sensor']['aim'] == 'heading'
    d['entities'][0]['sensor'] = {'fov': 20, 'aim': 'sideways'}
    try:
        sc.validate(d, 'x')
    except sc.ScenarioError as e:
        assert any('aim' in m for m in e.errors)
    else:
        raise AssertionError('an unknown sensor aim must be rejected')


def test_orbit_center_aim_points_the_cone_at_the_center():
    unit = types.SimpleNamespace(
        spec={'sensor': {'aim': 'orbit_center'},
              'path': {'kind': 'orbit', 'center': [0.0, 0.0], 'radius_m': 1000.0}},
        pos=(1000.0, 0.0), heading=180.0, orbit_entry=None)
    assert round(sim.Run._sensor_base(unit)) == 270          # east of center -> looks west
    unit.orbit_entry = (900.0, 0.0)                          # still flying in to the ring
    assert sim.Run._sensor_base(unit) == 180.0
    unit.orbit_entry = None
    unit.spec['sensor']['aim'] = 'heading'
    assert sim.Run._sensor_base(unit) == 180.0
    unit.spec['sensor']['aim'] = 'orbit_center'
    unit.spec['path'] = {'kind': 'waypoints'}
    assert sim.Run._sensor_base(unit) == 180.0               # only meaningful on an orbit


def test_a_saved_aim_survives_revalidation():
    d = _doc()
    d['entities'][0]['sensor'] = {'fov': 20, 'aim': 'orbit_center'}
    once = sc.validate(d, 'x')
    again = sc.validate(json.loads(json.dumps(once)), 'x')
    assert again['entities'][0]['sensor']['aim'] == 'orbit_center'
    assert geo.heading_deg(-1, 0) == 270.0
