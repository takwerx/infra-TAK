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
"""Scenario document schema + validator for the TAK Simulator (PLAN v10.1.61 §4.3, §4.9).

A scenario is JSON, never code. This validator is hand-rolled on the standard library and
deliberately strict: unknown keys are rejected at every level, every string is length-capped,
every number is range-capped, entity/event/point counts are capped, and no key anywhere
accepts a file path. Rejecting unknown keys is what keeps the format from growing into an
eval surface later. The console (modules/simulator.py) imports this same module for uploads,
so there is exactly one validator.

Coordinates are plane offsets in meters `[east, north]` from the run's AO center (§4.3).
"""
import json
import re

SCHEMA_VERSION = 1

# ── caps (fleet constants; a run parameter may raise the message rate, nothing else) ──
MAX_DOC_BYTES = 1_000_000
MAX_ENTITIES = 2500
MAX_EVENTS = 500
MAX_POINTS = 500
MAX_AREAS = 50
MAX_STR = 200
MAX_TEXT = 500
MAX_OFFSET_M = 200_000.0        # ±200 km from center
MAX_DURATION_S = 86_400
MAX_SPEED_MPS = 400.0
MIN_INTERVAL_S, MAX_INTERVAL_S = 0.5, 600.0
MIN_STALE_S, MAX_STALE_S = 5.0, 86_400.0
MAX_RADIUS_M = 100_000.0
MAX_HAE_M = 30_000.0
MAX_GENERATE = 2500
TEMPOS = (1, 2, 4, 10)
DEFAULT_MAX_MSGS_PER_SEC = 200    # per lane — fleet constant (§4.3 rate governor)
MAX_MSGS_PER_SEC_CEILING = 5000   # what a load run may ask for, never persisted

ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}')
NAME_RE = re.compile(r'[a-z0-9][a-z0-9-]{0,40}')
LANE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,15}')
COT_TYPE_RE = re.compile(r'[a-zA-Z][a-zA-Z0-9.-]{0,39}')
CHANNEL_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}')
COLOR_RE = re.compile(r'#[0-9a-fA-F]{6}')
STREAM_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}')
PRINTABLE_RE = re.compile(r'^[\x20-\x7e -￿]*$')

TEAMS = ('White', 'Yellow', 'Orange', 'Magenta', 'Red', 'Maroon', 'Purple', 'Dark Blue',
         'Blue', 'Cyan', 'Teal', 'Green', 'Dark Green', 'Brown')
ROLES = ('Team Member', 'Team Lead', 'HQ', 'Sniper', 'Medic', 'Forward Observer', 'RTO', 'K9')
EMERGENCIES = ('911 Alert', 'Ring The Bell', 'In Contact', 'Geo-fence Breached')

PATH_KINDS = ('waypoints', 'random_walk', 'orbit', 'static')
EVENT_KINDS = ('chat', 'casevac', 'emergency', 'emergency_cancel', 'marker', 'route', 'polygon',
               'circle', 'spawn', 'despawn', 'callsign', 'team', 'remove')


class ScenarioError(ValueError):
    """Raised with a list of human-readable problems (never a traceback for the operator)."""
    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__('; '.join(self.errors[:5]) + (' …' if len(self.errors) > 5 else ''))


class _V:
    """Tiny validation context: collects errors with a JSON-path prefix."""
    def __init__(self):
        self.errors = []

    def err(self, path, msg):
        self.errors.append(f'{path}: {msg}')

    def obj(self, v, path, allowed, required=()):
        if not isinstance(v, dict):
            self.err(path, 'must be an object')
            return None
        for k in v:
            if k not in allowed:
                self.err(f'{path}.{k}', 'unknown key')
        for k in required:
            if k not in v:
                self.err(f'{path}.{k}', 'required')
        return v

    def string(self, v, path, max_len=MAX_STR, regex=None, allow_empty=False):
        if not isinstance(v, str):
            self.err(path, 'must be a string')
            return None
        if not allow_empty and not v:
            self.err(path, 'must not be empty')
            return None
        if len(v) > max_len:
            self.err(path, f'longer than {max_len} characters')
            return None
        if not PRINTABLE_RE.fullmatch(v):
            self.err(path, 'contains control characters')
            return None
        if regex and not regex.fullmatch(v):
            self.err(path, 'has an invalid format')
            return None
        return v

    def number(self, v, path, lo, hi, integer=False):
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            self.err(path, 'must be a number')
            return None
        if integer and int(v) != v:
            self.err(path, 'must be an integer')
            return None
        if not (lo <= v <= hi):
            self.err(path, f'must be between {lo} and {hi}')
            return None
        return int(v) if integer else float(v)

    def boolean(self, v, path):
        if not isinstance(v, bool):
            self.err(path, 'must be true or false')
            return None
        return v

    def choice(self, v, path, choices):
        if v not in choices:
            self.err(path, f'must be one of {", ".join(choices)}')
            return None
        return v

    def point(self, v, path):
        if (not isinstance(v, list) or len(v) != 2
                or any(isinstance(c, bool) or not isinstance(c, (int, float)) for c in v)):
            self.err(path, 'must be [east_m, north_m]')
            return None
        if any(abs(c) > MAX_OFFSET_M for c in v):
            self.err(path, f'offset beyond ±{int(MAX_OFFSET_M)} m')
            return None
        return (float(v[0]), float(v[1]))

    def points(self, v, path, min_n=1, max_n=MAX_POINTS):
        if not isinstance(v, list):
            self.err(path, 'must be a list of points')
            return None
        if not (min_n <= len(v) <= max_n):
            self.err(path, f'needs between {min_n} and {max_n} points')
            return None
        out = [self.point(p, f'{path}[{i}]') for i, p in enumerate(v)]
        return None if any(p is None for p in out) else out


def _validate_path(v, path, areas, spec):
    p = v.obj(spec, path, allowed=('kind', 'points', 'speed_mps', 'loop', 'pause_s', 'area',
                                   'polygon', 'radius_m', 'start', 'center', 'clockwise',
                                   'turn_deg_s', 'at'), required=('kind',))
    if p is None:
        return None
    kind = v.choice(p.get('kind'), f'{path}.kind', PATH_KINDS)
    if kind is None:
        return None
    out = {'kind': kind}
    if kind == 'waypoints':
        if 'points' not in p:
            v.err(f'{path}.points', 'required for waypoints')
            return None
        out['points'] = v.points(p['points'], f'{path}.points', 2)
        out['speed_mps'] = v.number(p.get('speed_mps', 1.5), f'{path}.speed_mps', 0.0, MAX_SPEED_MPS)
        out['loop'] = v.boolean(p.get('loop', True), f'{path}.loop')
        out['pause_s'] = v.number(p.get('pause_s', 0), f'{path}.pause_s', 0, 3600)
    elif kind == 'random_walk':
        out['speed_mps'] = v.number(p.get('speed_mps', 1.5), f'{path}.speed_mps', 0.0, MAX_SPEED_MPS)
        out['turn_deg_s'] = v.number(p.get('turn_deg_s', 30), f'{path}.turn_deg_s', 0, 360)
        if 'area' in p:
            name = v.string(p['area'], f'{path}.area', regex=ID_RE)
            if name is not None and name not in areas:
                v.err(f'{path}.area', f'no area named {name!r}')
            out['area'] = name
        elif 'polygon' in p:
            out['polygon'] = v.points(p['polygon'], f'{path}.polygon', 3)
        else:
            out['start'] = v.point(p.get('start', [0, 0]), f'{path}.start')
            out['radius_m'] = v.number(p.get('radius_m', 500), f'{path}.radius_m', 1, MAX_RADIUS_M)
    elif kind == 'orbit':
        out['center'] = v.point(p.get('center', [0, 0]), f'{path}.center')
        out['radius_m'] = v.number(p.get('radius_m', 1000), f'{path}.radius_m', 1, MAX_RADIUS_M)
        out['speed_mps'] = v.number(p.get('speed_mps', 40), f'{path}.speed_mps', 0.0, MAX_SPEED_MPS)
        out['clockwise'] = v.boolean(p.get('clockwise', True), f'{path}.clockwise')
    elif kind == 'static':
        out['at'] = v.point(p.get('at', [0, 0]), f'{path}.at')
    return out


def _validate_entity(v, e, path, areas, defaults):
    o = v.obj(e, path, allowed=('id', 'callsign', 'type', 'team', 'role', 'lane', 'path',
                                'interval_s', 'stale_s', 'hae_m', 'spawn_at_s', 'despawn_at_s',
                                'sensor', 'video', 'remarks'),
              required=('id', 'callsign', 'type', 'path'))
    if o is None:
        return None
    out = {
        'id': v.string(o.get('id'), f'{path}.id', 32, ID_RE),
        'callsign': v.string(o.get('callsign'), f'{path}.callsign', 32),
        'type': v.string(o.get('type'), f'{path}.type', 40, COT_TYPE_RE),
        'team': v.choice(o.get('team', defaults['team']), f'{path}.team', TEAMS),
        'role': v.choice(o.get('role', defaults['role']), f'{path}.role', ROLES),
        'lane': v.string(o.get('lane', defaults['lane']), f'{path}.lane', 16, LANE_RE),
        'path': _validate_path(v, f'{path}.path', areas, o.get('path')),
        'interval_s': v.number(o.get('interval_s', defaults['interval_s']), f'{path}.interval_s',
                               MIN_INTERVAL_S, MAX_INTERVAL_S),
        'stale_s': v.number(o.get('stale_s', defaults['stale_s']), f'{path}.stale_s',
                            MIN_STALE_S, MAX_STALE_S),
        'hae_m': v.number(o.get('hae_m', 0), f'{path}.hae_m', -500, MAX_HAE_M),
        'spawn_at_s': v.number(o.get('spawn_at_s', 0), f'{path}.spawn_at_s', 0, MAX_DURATION_S),
        'despawn_at_s': (None if o.get('despawn_at_s') is None
                         else v.number(o.get('despawn_at_s'), f'{path}.despawn_at_s', 0, MAX_DURATION_S)),
        'remarks': (None if o.get('remarks') is None
                    else v.string(o.get('remarks'), f'{path}.remarks', MAX_TEXT)),
        'sensor': None, 'video': None,
    }
    if 'sensor' in o:
        s = v.obj(o['sensor'], f'{path}.sensor', allowed=('fov', 'range_m', 'vfov', 'elevation'))
        if s is not None:
            out['sensor'] = {
                'fov': v.number(s.get('fov', 60), f'{path}.sensor.fov', 1, 360),
                'range_m': v.number(s.get('range_m', 1000), f'{path}.sensor.range_m', 1, MAX_RADIUS_M),
                'vfov': v.number(s.get('vfov', 45), f'{path}.sensor.vfov', 1, 180),
                'elevation': v.number(s.get('elevation', 0), f'{path}.sensor.elevation', -90, 90),
            }
    if 'video' in o:
        vd = v.obj(o['video'], f'{path}.video', allowed=('stream',), required=('stream',))
        if vd is not None:
            out['video'] = {'stream': v.string(vd.get('stream'), f'{path}.video.stream', 64, STREAM_RE)}
    return out


def _validate_event(v, ev, path, entity_ids, defaults):
    common = ('at_s', 'kind', 'lane')
    o = v.obj(ev, path, allowed=common + ('from', 'text', 'room', 'id', 'at', 'title', 'urgent',
                                          'priority', 'routine', 'litter', 'ambulatory', 'remarks',
                                          'alert', 'callsign', 'type', 'points', 'color', 'stroke',
                                          'fill', 'fill_alpha', 'radius_m', 'entity', 'team', 'role',
                                          'stale_s'),
              required=('at_s', 'kind'))
    if o is None:
        return None
    kind = v.choice(o.get('kind'), f'{path}.kind', EVENT_KINDS)
    if kind is None:
        return None
    out = {'kind': kind, 'at_s': v.number(o.get('at_s'), f'{path}.at_s', 0, MAX_DURATION_S)}
    if 'lane' in o:
        out['lane'] = v.string(o['lane'], f'{path}.lane', 16, LANE_RE)

    def ref(key):
        eid = v.string(o.get(key), f'{path}.{key}', 32, ID_RE)
        if eid is not None and eid not in entity_ids:
            v.err(f'{path}.{key}', f'no entity with id {eid!r}')
        return eid

    def color(key, default):
        c = o.get(key, default)
        return v.string(c, f'{path}.{key}', 7, COLOR_RE)

    def stale(default):
        return v.number(o.get('stale_s', default), f'{path}.stale_s', MIN_STALE_S, MAX_STALE_S)

    if kind == 'chat':
        out['from'] = ref('from')
        out['text'] = v.string(o.get('text'), f'{path}.text', MAX_TEXT)
        out['room'] = v.string(o.get('room', 'All Chat Rooms'), f'{path}.room', 64)
    elif kind == 'casevac':
        out['id'] = v.string(o.get('id'), f'{path}.id', 32, ID_RE)
        out['at'] = v.point(o.get('at', [0, 0]), f'{path}.at')
        out['title'] = v.string(o.get('title', 'CASEVAC'), f'{path}.title', 64)
        for k in ('urgent', 'priority', 'routine', 'litter', 'ambulatory'):
            out[k] = v.number(o.get(k, 1 if k in ('urgent', 'litter') else 0), f'{path}.{k}', 0, 99, True)
        out['remarks'] = None if o.get('remarks') is None else v.string(o['remarks'], f'{path}.remarks', MAX_TEXT)
        out['stale_s'] = stale(300)
    elif kind in ('emergency', 'emergency_cancel'):
        out['from'] = ref('from')
        out['alert'] = v.choice(o.get('alert', '911 Alert'), f'{path}.alert', EMERGENCIES)
    elif kind == 'marker':
        out['id'] = v.string(o.get('id'), f'{path}.id', 32, ID_RE)
        out['callsign'] = v.string(o.get('callsign'), f'{path}.callsign', 32)
        out['type'] = v.string(o.get('type', 'a-h-G'), f'{path}.type', 40, COT_TYPE_RE)
        out['at'] = v.point(o.get('at', [0, 0]), f'{path}.at')
        out['remarks'] = None if o.get('remarks') is None else v.string(o['remarks'], f'{path}.remarks', MAX_TEXT)
        out['stale_s'] = stale(300)
    elif kind == 'route':
        out['id'] = v.string(o.get('id'), f'{path}.id', 32, ID_RE)
        out['callsign'] = v.string(o.get('callsign', 'Route'), f'{path}.callsign', 32)
        out['points'] = v.points(o.get('points'), f'{path}.points', 2)
        out['color'] = color('color', '#ffffff')
        out['stale_s'] = stale(300)
    elif kind == 'polygon':
        out['id'] = v.string(o.get('id'), f'{path}.id', 32, ID_RE)
        out['callsign'] = v.string(o.get('callsign', 'Area'), f'{path}.callsign', 32)
        out['points'] = v.points(o.get('points'), f'{path}.points', 3)
        out['stroke'] = color('stroke', '#ff0000')
        out['fill'] = color('fill', out['stroke'] or '#ff0000')
        out['fill_alpha'] = v.number(o.get('fill_alpha', 64), f'{path}.fill_alpha', 0, 255, True)
        out['remarks'] = None if o.get('remarks') is None else v.string(o['remarks'], f'{path}.remarks', MAX_TEXT)
        out['stale_s'] = stale(300)
    elif kind == 'circle':
        out['id'] = v.string(o.get('id'), f'{path}.id', 32, ID_RE)
        out['callsign'] = v.string(o.get('callsign', 'Circle'), f'{path}.callsign', 32)
        out['at'] = v.point(o.get('at', [0, 0]), f'{path}.at')
        out['radius_m'] = v.number(o.get('radius_m', 100), f'{path}.radius_m', 1, MAX_RADIUS_M)
        out['stroke'] = color('stroke', '#ffff00')
        out['fill'] = color('fill', out['stroke'] or '#ffff00')
        out['fill_alpha'] = v.number(o.get('fill_alpha', 64), f'{path}.fill_alpha', 0, 255, True)
        out['remarks'] = None if o.get('remarks') is None else v.string(o['remarks'], f'{path}.remarks', MAX_TEXT)
        out['stale_s'] = stale(300)
    elif kind in ('spawn', 'despawn'):
        out['entity'] = ref('entity')
    elif kind == 'callsign':
        out['entity'] = ref('entity')
        out['callsign'] = v.string(o.get('callsign'), f'{path}.callsign', 32)
    elif kind == 'team':
        out['entity'] = ref('entity')
        out['team'] = v.choice(o.get('team', defaults['team']), f'{path}.team', TEAMS)
        out['role'] = None if o.get('role') is None else v.choice(o.get('role'), f'{path}.role', ROLES)
    elif kind == 'remove':
        out['id'] = v.string(o.get('id'), f'{path}.id', 32, ID_RE)
    return out


def _validate_generate(v, g, path, defaults):
    o = v.obj(g, path, allowed=('count', 'count_min', 'count_max', 'callsign_prefix', 'type',
                                'team', 'role', 'lane', 'radius_m', 'interval_s', 'stale_s',
                                'speed_mps'))
    if o is None:
        return None
    out = {
        'count': v.number(o.get('count', 100), f'{path}.count', 1, MAX_GENERATE, True),
        'count_min': v.number(o.get('count_min', 1), f'{path}.count_min', 1, MAX_GENERATE, True),
        'count_max': v.number(o.get('count_max', MAX_GENERATE), f'{path}.count_max', 1, MAX_GENERATE, True),
        'callsign_prefix': v.string(o.get('callsign_prefix', 'LOAD'), f'{path}.callsign_prefix', 12),
        'type': v.string(o.get('type', 'a-f-G-U-C'), f'{path}.type', 40, COT_TYPE_RE),
        'team': v.choice(o.get('team', defaults['team']), f'{path}.team', TEAMS),
        'role': v.choice(o.get('role', defaults['role']), f'{path}.role', ROLES),
        'lane': v.string(o.get('lane', defaults['lane']), f'{path}.lane', 16, LANE_RE),
        'radius_m': v.number(o.get('radius_m', 5000), f'{path}.radius_m', 10, MAX_RADIUS_M),
        'interval_s': v.number(o.get('interval_s', 2), f'{path}.interval_s', MIN_INTERVAL_S, MAX_INTERVAL_S),
        'stale_s': v.number(o.get('stale_s', 30), f'{path}.stale_s', MIN_STALE_S, MAX_STALE_S),
        'speed_mps': v.number(o.get('speed_mps', 2), f'{path}.speed_mps', 0, MAX_SPEED_MPS),
    }
    return out


def validate(doc, name=None):
    """Validate a scenario document. Returns the normalized document (all defaults filled)
    or raises ScenarioError with every problem found."""
    v = _V()
    o = v.obj(doc, '$', allowed=('name', 'title', 'story', 'version', 'duration_s', 'loop',
                                 'defaults', 'areas', 'entities', 'events', 'generate', 'warn',
                                 'default_tempo'),
              required=('title', 'duration_s'))
    if o is None:
        raise ScenarioError(v.errors)
    out = {
        'name': v.string(o.get('name', name or 'scenario'), '$.name', 41, NAME_RE),
        'title': v.string(o.get('title'), '$.title', 80),
        'story': v.string(o.get('story', ''), '$.story', MAX_TEXT, allow_empty=True),
        'version': v.number(o.get('version', SCHEMA_VERSION), '$.version', 1, SCHEMA_VERSION, True),
        'duration_s': v.number(o.get('duration_s'), '$.duration_s', 10, MAX_DURATION_S),
        'loop': v.boolean(o.get('loop', False), '$.loop'),
        'warn': (None if o.get('warn') is None else v.string(o['warn'], '$.warn', MAX_TEXT)),
        'default_tempo': v.choice(o.get('default_tempo', 1), '$.default_tempo', TEMPOS),
    }
    d = v.obj(o.get('defaults', {}), '$.defaults', allowed=('interval_s', 'stale_s', 'team', 'role', 'lane')) or {}
    defaults = {
        'interval_s': v.number(d.get('interval_s', 5), '$.defaults.interval_s', MIN_INTERVAL_S, MAX_INTERVAL_S),
        'stale_s': v.number(d.get('stale_s', 60), '$.defaults.stale_s', MIN_STALE_S, MAX_STALE_S),
        'team': v.choice(d.get('team', 'Cyan'), '$.defaults.team', TEAMS),
        'role': v.choice(d.get('role', 'Team Member'), '$.defaults.role', ROLES),
        'lane': v.string(d.get('lane', '1'), '$.defaults.lane', 16, LANE_RE),
    }
    out['defaults'] = defaults

    areas_in = o.get('areas', {})
    areas = {}
    if not isinstance(areas_in, dict):
        v.err('$.areas', 'must be an object of name -> points')
    else:
        if len(areas_in) > MAX_AREAS:
            v.err('$.areas', f'more than {MAX_AREAS} areas')
        for k, pts in areas_in.items():
            kn = v.string(k, f'$.areas.{k}', 32, ID_RE)
            p = v.points(pts, f'$.areas.{k}', 3)
            if kn is not None and p is not None:
                areas[kn] = p
    out['areas'] = areas

    ents_in = o.get('entities', [])
    if not isinstance(ents_in, list):
        v.err('$.entities', 'must be a list')
        ents_in = []
    if len(ents_in) > MAX_ENTITIES:
        v.err('$.entities', f'more than {MAX_ENTITIES} entities')
        ents_in = ents_in[:MAX_ENTITIES]
    entities = []
    ids = set()
    for i, e in enumerate(ents_in):
        ne = _validate_entity(v, e, f'$.entities[{i}]', areas, defaults)
        if ne is None:
            continue
        if ne['id'] in ids:
            v.err(f'$.entities[{i}].id', f'duplicate id {ne["id"]!r}')
        ids.add(ne['id'])
        entities.append(ne)
    out['entities'] = entities

    evs_in = o.get('events', [])
    if not isinstance(evs_in, list):
        v.err('$.events', 'must be a list')
        evs_in = []
    if len(evs_in) > MAX_EVENTS:
        v.err('$.events', f'more than {MAX_EVENTS} events')
        evs_in = evs_in[:MAX_EVENTS]
    events = []
    for i, ev in enumerate(evs_in):
        ne = _validate_event(v, ev, f'$.events[{i}]', ids, defaults)
        if ne is not None:
            events.append(ne)
    events.sort(key=lambda e: (e['at_s'] if e['at_s'] is not None else 0))
    out['events'] = events

    out['generate'] = _validate_generate(v, o['generate'], '$.generate', defaults) if 'generate' in o else None
    if not entities and not out['generate']:
        v.err('$.entities', 'a scenario needs at least one entity or a generate block')

    if v.errors:
        raise ScenarioError(v.errors)
    return out


def validate_bytes(raw, name=None):
    """Validate a raw upload (bytes). Size cap first, then JSON, then schema."""
    if len(raw) > MAX_DOC_BYTES:
        raise ScenarioError([f'document larger than {MAX_DOC_BYTES // 1000} kB'])
    try:
        doc = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as e:
        raise ScenarioError([f'not valid JSON: {str(e)[:120]}'])
    return validate(doc, name)


def validate_run_params(p, lane_ids_available):
    """Validate the parameters of one run (§4.4 /run). Certificates are never taken from
    the request: the engine maps a lane id to /certs/lane-<id>.pem itself."""
    v = _V()
    o = v.obj(p, 'run', allowed=('scenario', 'center', 'tempo', 'loop', 'lanes', 'exercise',
                                 'params', 'default_channel'),
              required=('scenario', 'center', 'lanes'))
    if o is None:
        raise ScenarioError(v.errors)
    out = {}
    sc = o.get('scenario')
    if isinstance(sc, str):
        out['scenario'] = v.string(sc, 'run.scenario', 41, NAME_RE)
    elif isinstance(sc, dict):
        out['scenario'] = sc          # validated by validate() at run start
    else:
        v.err('run.scenario', 'must be a preset name or a scenario object')
    c = v.obj(o.get('center'), 'run.center', allowed=('lat', 'lon'), required=('lat', 'lon')) or {}
    out['center'] = (v.number(c.get('lat'), 'run.center.lat', -90, 90),
                     v.number(c.get('lon'), 'run.center.lon', -180, 180))
    out['tempo'] = v.choice(o.get('tempo', 1), 'run.tempo', TEMPOS)
    out['loop'] = None if o.get('loop') is None else v.boolean(o.get('loop'), 'run.loop')
    out['exercise'] = v.boolean(o.get('exercise', False), 'run.exercise')
    out['default_channel'] = v.string(o.get('default_channel', 'tak_simulation'), 'run.default_channel', 64, CHANNEL_RE)
    lanes = {}
    lo = o.get('lanes')
    if not isinstance(lo, dict) or not lo:
        v.err('run.lanes', 'must map at least one lane id to {channel}')
    else:
        for lid, spec in lo.items():
            lk = v.string(lid, f'run.lanes.{lid}', 16, LANE_RE)
            s = v.obj(spec, f'run.lanes.{lid}', allowed=('channel', 'exercise'), required=('channel',))
            if lk is None or s is None:
                continue
            if lk not in lane_ids_available:
                v.err(f'run.lanes.{lid}', 'no enrolled certificate for this lane')
                continue
            lanes[lk] = {
                'channel': v.string(s.get('channel'), f'run.lanes.{lid}.channel', 64, CHANNEL_RE),
                'exercise': v.boolean(s.get('exercise', False), f'run.lanes.{lid}.exercise'),
            }
    out['lanes'] = lanes
    pr = v.obj(o.get('params', {}), 'run.params', allowed=('count', 'interval_s', 'max_msgs_per_sec')) or {}
    out['params'] = {
        'count': None if pr.get('count') is None else v.number(pr['count'], 'run.params.count', 1, MAX_GENERATE, True),
        'interval_s': None if pr.get('interval_s') is None else v.number(pr['interval_s'], 'run.params.interval_s', MIN_INTERVAL_S, MAX_INTERVAL_S),
        'max_msgs_per_sec': v.number(pr.get('max_msgs_per_sec', DEFAULT_MAX_MSGS_PER_SEC), 'run.params.max_msgs_per_sec', 1, MAX_MSGS_PER_SEC_CEILING, True),
    }
    if v.errors:
        raise ScenarioError(v.errors)
    return out


def summarize(doc):
    """Counts for the scenario picker (§4.6): entities, events, duration, lanes used."""
    lanes = sorted({e['lane'] for e in doc['entities']} | ({doc['generate']['lane']} if doc['generate'] else set()))
    return {
        'name': doc['name'], 'title': doc['title'], 'story': doc['story'],
        'duration_s': doc['duration_s'], 'loop': doc['loop'], 'warn': doc['warn'],
        'default_tempo': doc['default_tempo'],
        'entities': len(doc['entities']) + (doc['generate']['count'] if doc['generate'] else 0),
        'events': len(doc['events']), 'lanes': lanes,
        'generate': ({'count': doc['generate']['count'], 'count_min': doc['generate']['count_min'],
                      'count_max': doc['generate']['count_max']} if doc['generate'] else None),
        'video': any(e['video'] for e in doc['entities']),
    }
