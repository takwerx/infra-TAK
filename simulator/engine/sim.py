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
"""The run loop: entities, timeline, tempo, rate governor, and clean stop (PLAN v10.1.61 §4.3).

One Run = one validated scenario + one set of run parameters + the lanes it sends on.
A simulated clock advances `tempo` times faster than wall time (1x/2x/4x/10x) and drives
both movement and the timeline; pause freezes it. Every UID the run ever emitted is
remembered so that stop — operator Stop, natural end, SIGTERM, or the container dying —
sends a `t-x-d-d` delete for each one and closes the lanes. Short `stale_s` covers the
crash case the delete cannot.

Director commands (companion PLAN, W9): the control thread validates a command and puts it
on a queue; the loop thread drains the queue at the top of every tick and applies it. The
control thread never touches an entity — it waits for the loop's answer.

Detection (PLAN v10.1.62 W2): a sensor with a `detect` block *looks* — a fixed cone once
per its report interval, a sweeping beam whenever its center crosses a target's bearing
during the tick — and every silent target inside the footprint (range, kinds, altitude
band) becomes a track: one track per (sensor, target), its own uid, named by the sensor,
re-reported while the target stays inside, deleted once it has been outside longer than
the track stale. Two sensors on one target are two tracks — no fusion, by requirement.
"""
import math
import queue
import random
import threading
import time

from . import cot, geo
from . import scenario as sc

CMD_TIMEOUT_S = 10.0
HEADING_LIMIT_M = 2 * sc.MAX_OFFSET_M      # a `heading` path holds at 400 km from center
_DOMAIN_WORD = {'sea': 'vessel', 'air': 'aircraft', 'ground': 'unit'}


class Governor:
    """Token bucket: at most `rate` messages per second per lane (fleet constant 200;
    a load run may raise it for that run only)."""
    def __init__(self, rate):
        self.rate = float(rate)
        self.tokens = float(rate)
        self.last = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self):
        now = time.monotonic()
        self.tokens = min(self.rate, self.tokens + (now - self.last) * self.rate)
        self.last = now

    def take(self):
        with self._lock:
            self._refill()
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

    def wait(self):
        while not self.take():
            time.sleep(1.0 / self.rate)


class _Target:
    """What a sensor evaluates on a look (W2): a silent entity now; a real observed track
    joins the same list in W4. `key` is what the track uid is built from."""
    __slots__ = ('key', 'pos', 'hae', 'heading', 'speed', 'domain', 'dtype', 'dcallsign', 'real', 'label')

    def __init__(self, key, pos, hae, heading, speed, domain, dtype, dcallsign, real, label):
        self.key, self.pos, self.hae, self.heading, self.speed = key, pos, hae, heading, speed
        self.domain, self.dtype, self.dcallsign, self.real, self.label = domain, dtype, dcallsign, real, label


class Entity:
    __slots__ = ('spec', 'uid', 'callsign', 'team', 'role', 'lane', 'type', 'pos', 'heading',
                 'speed', 'alive', 'next_emit', 'wp_idx', 'wp_pause_until', 'angle', 'walk_area',
                 'walk_center', 'walk_radius', 'start_pos', 'emitted', 'lostlink', 'orbit_entry',
                 'silent', 'detected_type', 'detected_callsign', 'domain', 'trk_n', 'next_look',
                 'sweep_prev')

    def __init__(self, spec, uid, rng, areas):
        self.spec = spec
        self.uid = uid
        self.callsign = spec['callsign']
        self.team = spec['team']
        self.role = spec['role']
        self.lane = spec['lane']
        self.type = spec['type']
        self.emitted = False
        self.lostlink = False       # director "lost link": stop reporting, no delete (W9)
        self.orbit_entry = None     # plane point to fly to before an orbit begins (W9)
        # v2 (W2): a silent entity moves but never reports itself; sensors report it
        self.silent = bool(spec.get('silent'))
        self.detected_type = spec.get('detected_type') or sc.default_detected_type(self.type)
        self.detected_callsign = spec.get('detected_callsign')
        self.domain = sc.domain_of(self.type)
        p = spec['path']
        self.walk_area = None
        self.walk_center = None
        self.walk_radius = None
        if p['kind'] == 'waypoints':
            self.start_pos = tuple(p['points'][0])
        elif p['kind'] == 'orbit':
            self.start_pos = geo.orbit_point(p['center'], p['radius_m'], 0.0)
        elif p['kind'] == 'random_walk':
            if p.get('area'):
                self.walk_area = areas[p['area']]
                self.start_pos = geo.random_point_in_polygon(self.walk_area, rng)
            elif p.get('polygon'):
                self.walk_area = p['polygon']
                self.start_pos = geo.random_point_in_polygon(self.walk_area, rng)
            else:
                self.walk_center = tuple(p['start'])
                self.walk_radius = p['radius_m']
                self.start_pos = geo.random_point_in_circle(self.walk_center, self.walk_radius, rng)
        else:
            self.start_pos = tuple(p['at'])
        self.reset(rng)

    def reset(self, rng):
        self.pos = self.start_pos
        self.heading = rng.uniform(0.0, 360.0)
        self.speed = 0.0
        self.alive = False
        self.next_emit = self.spec['spawn_at_s'] + rng.uniform(0.0, self.spec['interval_s'])
        self.wp_idx = 1 if self.spec['path']['kind'] == 'waypoints' else 0
        self.wp_pause_until = 0.0
        self.angle = 0.0
        self.orbit_entry = None
        self.trk_n = 0              # acquisitions this sensor has made (names its tracks T1, T2, …)
        self.next_look = self.spec['spawn_at_s']
        self.sweep_prev = None      # beam azimuth at the previous tick (sweeping sensor)

    def set_path(self, path):
        """Live re-path (director command): keep the position, pick the new path up from
        here. An orbit is entered smoothly, never by teleporting onto the ring: a unit
        already on the circle (an "orbit here" built tangentially by the director) starts
        circling at once; otherwise it flies to the nearest point on the circle (straight
        ahead by `radius_m` when it sits at the center) and then circles."""
        self.spec['path'] = path
        kind = path['kind']
        self.wp_idx = 1 if kind == 'waypoints' else 0
        self.wp_pause_until = 0.0
        self.orbit_entry = None
        if kind == 'orbit':
            c = path['center']
            d = geo.dist(self.pos, c)
            if abs(d - path['radius_m']) < 1.0:
                self.angle = geo.heading_deg(self.pos[0] - c[0], self.pos[1] - c[1])
            else:
                ang = self.heading if d < 1.0 else geo.heading_deg(self.pos[0] - c[0], self.pos[1] - c[1])
                self.angle = ang
                self.orbit_entry = geo.orbit_point(c, path['radius_m'], ang)

    def advance(self, sim_dt, sim_t, rng):
        p = self.spec['path']
        kind = p['kind']
        if kind == 'static' or sim_dt <= 0:
            self.speed = 0.0
            return
        if kind == 'heading':
            self.heading = p['heading_deg']
            step = p['speed_mps'] * sim_dt
            h = math.radians(self.heading)
            cand = (self.pos[0] + step * math.sin(h), self.pos[1] + step * math.cos(h))
            if abs(cand[0]) > HEADING_LIMIT_M or abs(cand[1]) > HEADING_LIMIT_M:
                self.speed = 0.0            # off the plane's edge: hold rather than wrap the globe
                return
            self.pos = cand
            self.speed = p['speed_mps']
            return
        if kind == 'waypoints':
            pts = p['points']
            if sim_t < self.wp_pause_until:
                self.speed = 0.0
                return
            if self.wp_idx >= len(pts):
                self.speed = 0.0
                return
            target = pts[self.wp_idx]
            step = p['speed_mps'] * sim_dt
            new_pos, arrived = geo.step_toward(self.pos, target, step)
            self.heading = geo.heading_deg(target[0] - self.pos[0], target[1] - self.pos[1]) if not arrived or target != self.pos else self.heading
            self.pos = new_pos
            self.speed = p['speed_mps']
            if arrived:
                self.wp_idx += 1
                if self.wp_idx >= len(pts) and p['loop']:
                    self.wp_idx = 0
                if p['pause_s'] > 0:
                    self.wp_pause_until = sim_t + p['pause_s']
        elif kind == 'orbit':
            if self.orbit_entry is not None:
                step = p['speed_mps'] * sim_dt
                tgt = self.orbit_entry
                new_pos, arrived = geo.step_toward(self.pos, tgt, step)
                if not arrived:
                    self.heading = geo.heading_deg(tgt[0] - self.pos[0], tgt[1] - self.pos[1])
                self.pos = new_pos
                self.speed = p['speed_mps']
                if arrived:
                    self.orbit_entry = None
                    c = p['center']
                    self.angle = geo.heading_deg(self.pos[0] - c[0], self.pos[1] - c[1])
                return
            omega = math.degrees(p['speed_mps'] / p['radius_m']) * sim_dt
            self.angle = (self.angle + (omega if p['clockwise'] else -omega)) % 360.0
            self.pos = geo.orbit_point(p['center'], p['radius_m'], self.angle)
            self.heading = (self.angle + (90.0 if p['clockwise'] else -90.0)) % 360.0
            self.speed = p['speed_mps']
        elif kind == 'random_walk':
            self.heading = (self.heading + rng.uniform(-p['turn_deg_s'], p['turn_deg_s']) * sim_dt) % 360.0
            step = p['speed_mps'] * sim_dt
            h = math.radians(self.heading)
            cand = (self.pos[0] + step * math.sin(h), self.pos[1] + step * math.cos(h))
            inside = (geo.point_in_polygon(cand, self.walk_area) if self.walk_area is not None
                      else geo.dist(cand, self.walk_center) <= self.walk_radius)
            if not inside:
                # bounce: turn back toward the middle of the area
                mid = geo.polygon_centroid(self.walk_area) if self.walk_area is not None else self.walk_center
                self.heading = geo.heading_deg(mid[0] - self.pos[0], mid[1] - self.pos[1])
                h = math.radians(self.heading)
                cand = (self.pos[0] + step * math.sin(h), self.pos[1] + step * math.cos(h))
            self.pos = cand
            self.speed = p['speed_mps']


class Run:
    def __init__(self, doc, params, lanes, log, video_base=None, default_channel='tak_simulation',
                 live=False):
        self.doc = doc
        self.params = params
        self.lanes = lanes                      # lane_id -> Lane
        self.log = log
        self.video_base = (video_base or '').rstrip('/') or None
        self.default_channel = default_channel
        self.live = bool(live)                  # director session: empty doc, units via /cmd
        self._cmdq = queue.Queue()
        self._spawn_seq = 0
        self.center = params['center']
        self.tempo = float(params['tempo'])
        self.loop = doc['loop'] if params.get('loop') is None else bool(params['loop'])
        self.duration = float(doc['duration_s'])
        self.rng = random.Random(doc['name'])   # presets replay identically; load runs too
        self.name = doc['name']
        self.max_mps = params['params']['max_msgs_per_sec']
        self.governors = {lid: Governor(self.max_mps) for lid in lanes}

        self.entities = []
        self.by_id = {}
        for spec in doc['entities']:
            e = Entity(spec, f'SIM-{self.name}-{spec["id"]}', self.rng, doc['areas'])
            self.entities.append(e)
            self.by_id[spec['id']] = e
        g = doc.get('generate')
        if g:
            count = params['params'].get('count') or g['count']
            count = max(g['count_min'], min(g['count_max'], int(count)))
            interval = params['params'].get('interval_s') or g['interval_s']
            width = len(str(count))
            for i in range(1, count + 1):
                spec = {
                    'id': f'gen{i}', 'callsign': f'{g["callsign_prefix"]}-{i:0{width}d}', 'type': g['type'],
                    'team': g['team'], 'role': g['role'], 'lane': g['lane'],
                    'path': {'kind': 'random_walk', 'speed_mps': g['speed_mps'], 'turn_deg_s': 45.0,
                             'start': (0.0, 0.0), 'radius_m': g['radius_m']},
                    'interval_s': float(interval), 'stale_s': g['stale_s'], 'hae_m': 0.0,
                    'spawn_at_s': 0.0, 'despawn_at_s': None, 'remarks': None, 'sensor': None, 'video': None,
                    'silent': False, 'detected_type': sc.default_detected_type(g['type']), 'detected_callsign': None,
                }
                e = Entity(spec, f'SIM-{self.name}-gen{i}', self.rng, doc['areas'])
                self.entities.append(e)
                self.by_id[spec['id']] = e
        self.events = list(doc['events'])
        self.ev_idx = 0
        self.persistent = {}        # uid -> {'lane','type','build','refresh','next'}
        self.emitted = {}           # uid -> (lane_id, type) — for the stop deletes
        self.tracks = {}            # (sensor id, target key) -> track (W2); runtime only, never saved
        self.tracks_total = 0
        self.sim_t = 0.0
        self.loops_done = 0
        self.events_fired = 0
        self.state = 'idle'
        self.started_at = None
        self.ended_at = None
        self.ended_reason = None
        self._stop_evt = threading.Event()
        self._cleanup_done = False
        self._cleanup_lock = threading.Lock()
        self._thread = None

    # ── helpers ─────────────────────────────────────────────────────────────
    def _lane(self, lane_id):
        return self.lanes[lane_id]

    def _callsign(self, lane_id, callsign):
        return f'EX-{callsign}' if self.lanes[lane_id].exercise else callsign

    def _latlon(self, pos):
        return geo.to_latlon(self.center, pos[0], pos[1])

    def _plane(self, lat, lon):
        return geo.from_latlon(self.center, lat, lon)

    def _send(self, lane_id, uid, etype, xml, block=False):
        lane = self.lanes[lane_id]
        if uid is not None:
            self.emitted[uid] = (lane_id, etype)
        return lane.send(xml, block=block)

    def _video_url(self, ent):
        v = ent.spec.get('video')
        if not v or not self.video_base:
            return None
        return f'{self.video_base}/{v["stream"]}'

    # ── lifecycle ───────────────────────────────────────────────────────────
    def start(self):
        self.state = 'running'
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._loop, name=f'run-{self.name}', daemon=True)
        self._thread.start()

    def pause(self):
        if self.state == 'running':
            self.state = 'paused'
            self.log(f'run {self.name}: paused at t+{self.sim_t:.0f}s')

    def resume(self):
        if self.state == 'paused':
            self.state = 'running'
            self.log(f'run {self.name}: resumed at t+{self.sim_t:.0f}s')

    def stop(self, reason='stopped by operator'):
        if self.state in ('stopping', 'stopped'):
            return
        self.state = 'stopping'
        self._stop_evt.set()
        if self._thread is not None and threading.current_thread() is not self._thread:
            self._thread.join(timeout=30)
        self._cleanup(reason)

    def _cleanup(self, reason):
        with self._cleanup_lock:
            if self._cleanup_done:
                return
            self._cleanup_done = True
        self.state = 'stopping'
        n = 0
        for uid, (lane_id, etype) in list(self.emitted.items()):
            lane = self.lanes.get(lane_id)
            if lane is None:
                continue
            self.governors[lane_id].wait()
            lane.send(cot.delete_event(uid, etype), block=True)
            self.log(f't-x-d-d {uid}')
            n += 1
        for lane in self.lanes.values():
            lane.flush(timeout=10.0)
            lane.stop()
        self.ended_at = time.time()
        self.ended_reason = reason
        self.state = 'stopped'
        self.log(f'run {self.name}: {reason}; sent {n} delete(s), lanes closed')

    # ── the loop ────────────────────────────────────────────────────────────
    def _loop(self):
        tick = 0.1
        last = time.monotonic()
        n_silent = sum(1 for e in self.entities if e.silent)
        n_detect = sum(1 for e in self.entities if e.spec['sensor'] and e.spec['sensor']['detect'])
        self.log(f'run {self.name}: started — {len(self.entities)} entities'
                 f'{f" ({n_silent} silent, {n_detect} detecting)" if n_silent or n_detect else ""}, '
                 f'{len(self.events)} events, tempo {self.tempo:g}x, loop={self.loop}, '
                 f'duration {self.duration:.0f}s, governor {self.max_mps:g} msg/s/lane')
        while not self._stop_evt.is_set():
            now = time.monotonic()
            dt = now - last
            last = now
            self._drain_commands()
            if self.state != 'running':
                time.sleep(tick)
                continue
            sim_dt = dt * self.tempo
            self.sim_t += sim_dt
            self._advance(sim_dt)
            self._detect(sim_dt)
            self._emit_due()
            self._fire_events()
            self._refresh_persistent()
            if self.sim_t >= self.duration:
                if self.loop:
                    self._reset_loop()
                else:
                    break
            time.sleep(tick)
        self._drain_commands(fail=RuntimeError('run has ended'))
        if not self._stop_evt.is_set():
            self._cleanup('completed')

    def _advance(self, sim_dt):
        for e in self.entities:
            spec = e.spec
            if not e.alive:
                if self.sim_t >= spec['spawn_at_s'] and (spec['despawn_at_s'] is None or self.sim_t < spec['despawn_at_s']):
                    e.alive = True
                else:
                    continue
            elif spec['despawn_at_s'] is not None and self.sim_t >= spec['despawn_at_s']:
                self._despawn(e)
                continue
            e.advance(sim_dt, self.sim_t, self.rng)

    def _emit_due(self):
        for e in self.entities:
            if not e.alive or e.silent or e.lostlink or self.sim_t < e.next_emit:
                continue
            gov = self.governors.get(e.lane)
            if gov is None or not gov.take():
                continue            # backpressure: try again next tick
            self._emit_pli(e)
            e.next_emit = self.sim_t + e.spec['interval_s']

    def _emit_pli(self, e):
        lat, lon = self._latlon(e.pos)
        sensor = e.spec.get('sensor')
        azimuth = None
        if sensor and sensor.get('sweep_deg_s'):
            # radar sweep: the cone rotates at sweep_deg_s on top of the heading (W9)
            azimuth = (e.heading + self.sim_t * sensor['sweep_deg_s']) % 360.0
        xml = cot.pli_event(e.uid, e.type, self._callsign(e.lane, e.callsign), lat, lon,
                            e.spec['hae_m'], e.speed, e.heading, e.team, e.role, e.spec['stale_s'],
                            sensor=sensor, video=self._video_url(e),
                            remarks=e.spec.get('remarks'), sensor_azimuth=azimuth)
        e.emitted = True
        self._send(e.lane, e.uid, e.type, xml)

    def _despawn(self, e):
        e.alive = False
        if e.emitted:
            gov = self.governors.get(e.lane)
            if gov:
                gov.wait()
            self.lanes[e.lane].send(cot.delete_event(e.uid, e.type), block=True)
            self.emitted.pop(e.uid, None)
            e.emitted = False
            self.log(f't-x-d-d {e.uid} (despawn)')
        if self.tracks:
            self._drop_tracks_for(e, 'despawn')     # as a sensor and as a target (W2)

    def _reset_loop(self):
        self.loops_done += 1
        self.sim_t = 0.0
        self.ev_idx = 0
        for key in list(self.tracks):
            self._drop_track(key, 'loop reset')     # targets jump back to their start
        for e in self.entities:
            e.reset(self.rng)
        self.log(f'run {self.name}: loop {self.loops_done} complete, restarting timeline')

    def _refresh_persistent(self):
        for uid, p in list(self.persistent.items()):
            if self.sim_t < p['next']:
                continue
            gov = self.governors[p['lane']]
            if not gov.take():
                continue
            self._send(p['lane'], uid, p['type'], p['build']())
            p['next'] = self.sim_t + p['refresh']

    def _add_persistent(self, uid, lane_id, etype, build, stale_s, meta=None):
        self.persistent[uid] = {'lane': lane_id, 'type': etype, 'build': build,
                                'refresh': max(5.0, stale_s / 2.0), 'next': self.sim_t + max(5.0, stale_s / 2.0),
                                **(meta or {})}
        self.governors[lane_id].wait()
        self._send(lane_id, uid, etype, build())

    def _remove_persistent(self, uid):
        p = self.persistent.pop(uid, None)
        if p is None:
            return
        self.governors[p['lane']].wait()
        self.lanes[p['lane']].send(cot.delete_event(uid, p['type']), block=True)
        self.emitted.pop(uid, None)
        self.log(f't-x-d-d {uid} (removed)')

    # ── detection (W2) ──────────────────────────────────────────────────────
    def _targets(self):
        """Everything a sensor may detect this tick: every alive silent entity. (W4 adds
        each lane's observed real tracks here for sensors that `observe`.)"""
        return [_Target(e.spec['id'], e.pos, e.spec['hae_m'], e.heading, e.speed, e.domain,
                        e.detected_type, e.detected_callsign, False, e.callsign)
                for e in self.entities if e.alive and e.silent]

    def _detect(self, sim_dt):
        """Every detecting sensor looks; every track is acquired, held, or aged out.
        A *look* is once per report interval for a fixed cone, and — for a sweeping beam —
        the tick in which the beam center crossed the target's bearing (computed from the
        azimuth before and after the tick, never by stepping degrees), so `p_detect` is
        per look and a sweep sees a bearing once per revolution. Cheap range gate first;
        the wedge math only runs for targets already inside the range circle."""
        targets = None
        for s in self.entities:
            sensor = s.spec['sensor']
            if not s.alive or s.lostlink or not sensor or not sensor['detect']:
                continue
            det = sensor['detect']
            sweep = sensor['sweep_deg_s']
            if sweep > 0:
                az_now = (s.heading + self.sim_t * sweep) % 360.0     # same azimuth the PLI's cone shows
                az_prev, s.sweep_prev = s.sweep_prev, az_now
                if az_prev is None:
                    continue
                delta, half_fov = sweep * sim_dt, None
            else:
                if self.sim_t < s.next_look:
                    continue
                s.next_look = self.sim_t + s.spec['interval_s']
                az_prev, delta, half_fov = s.heading, 0.0, sensor['fov'] / 2.0
            if targets is None:
                targets = self._targets()
            range_m = sensor['range_m']
            sid = s.spec['id']
            for t in targets:
                if t.key == sid:
                    continue
                d = geo.dist(s.pos, t.pos)
                if d > range_m:
                    continue
                if t.domain not in det['kinds'] or not (det['alt_min_m'] <= t.hae <= det['alt_max_m']):
                    continue
                bearing = geo.heading_deg(t.pos[0] - s.pos[0], t.pos[1] - s.pos[1])
                if half_fov is None:
                    if delta < 360.0 and (bearing - az_prev) % 360.0 >= delta:
                        continue                                   # the beam did not cross it this tick
                elif half_fov < 180.0 and abs((bearing - az_prev + 180.0) % 360.0 - 180.0) > half_fov:
                    continue                                       # outside the fixed cone
                self._look(s, t, d)
        if self.tracks:
            self._age_tracks()

    def _look(self, s, t, d):
        det = s.spec['sensor']['detect']
        key = (s.spec['id'], t.key)
        tr = self.tracks.get(key)
        if tr is None:
            if det['p_detect'] < 1.0 and self.rng.random() >= det['p_detect']:
                return
            s.trk_n += 1
            tr = {'uid': f'{s.uid}-trk-{t.key}', 'sensor': s, 'target': t.key, 'n': s.trk_n,
                  'lane': s.lane, 'type': t.dtype, 'callsign': t.dcallsign, 'real': t.real,
                  'since': self.sim_t, 'last_seen': self.sim_t, 'next_emit': self.sim_t, 'pending': False,
                  'pos': t.pos, 'hae': t.hae, 'heading': t.heading, 'speed': t.speed}
            self.tracks[key] = tr
            self.tracks_total += 1
            # the engine log keeps the correlation the wire deliberately lacks
            self.log(f'{s.callsign} acquired {self._track_label(tr)} '
                     f'({"real" if t.real else "silent"} {_DOMAIN_WORD[t.domain]} {t.label}) at {d / 1000.0:.1f} km')
        else:
            tr['last_seen'] = self.sim_t
            tr['pos'], tr['hae'], tr['heading'], tr['speed'] = t.pos, t.hae, t.heading, t.speed
        if self.sim_t >= tr['next_emit']:
            tr['pending'] = True
            self._emit_track_pending(tr)

    def _age_tracks(self):
        for key, tr in list(self.tracks.items()):
            if self.sim_t - tr['last_seen'] > self._track_stale(tr['sensor']):
                self._drop_track(key, 'lost')
            elif tr['pending']:
                self._emit_track_pending(tr)           # governor had no token earlier this tick

    def _track_stale(self, s):
        sensor = s.spec['sensor']
        stale = sensor['detect']['track_stale_s']
        if sensor['sweep_deg_s'] > 0:
            # a sweeping beam looks at a bearing once per revolution: a track must outlive
            # two missed revolutions or it would flicker between looks
            stale = max(stale, 2.0 * 360.0 / sensor['sweep_deg_s'])
        return stale

    def _track_label(self, tr):
        return tr['callsign'] or f'T{tr["n"]}'

    def _track_callsign(self, tr):
        return tr['callsign'] or f'{tr["sensor"].callsign} T{tr["n"]}'

    def _emit_track_pending(self, tr):
        gov = self.governors.get(tr['lane'])
        if gov is None or not gov.take():
            return False                                # backpressure: retried every tick
        self._emit_track(tr)
        tr['pending'] = False
        tr['next_emit'] = self.sim_t + tr['sensor'].spec['interval_s']
        return True

    def _emit_track(self, tr):
        s = tr['sensor']
        err = s.spec['sensor']['detect']['error_m']
        pos = tr['pos']
        if err > 0:
            pos = (pos[0] + self.rng.gauss(0.0, err), pos[1] + self.rng.gauss(0.0, err))
        lat, lon = self._latlon(pos)
        xml = cot.track_event(tr['uid'], tr['type'], self._callsign(s.lane, self._track_callsign(tr)),
                              lat, lon, tr['hae'], tr['speed'], tr['heading'],
                              s.uid, s.type, self._callsign(s.lane, s.callsign),
                              stale_s=self._track_stale(s), ce=err if err > 0 else 50.0)
        self._send(s.lane, tr['uid'], tr['type'], xml)

    def _drop_track(self, key, why):
        tr = self.tracks.pop(key, None)
        if tr is None:
            return
        if tr['uid'] in self.emitted:
            gov = self.governors.get(tr['lane'])
            if gov:
                gov.wait()
            self.lanes[tr['lane']].send(cot.delete_event(tr['uid'], tr['type']), block=True)
            self.emitted.pop(tr['uid'], None)
            self.log(f't-x-d-d {tr["uid"]} ({why})')
        self.log(f'{tr["sensor"].callsign} lost {self._track_label(tr)}' + ('' if why == 'lost' else f' ({why})'))

    def _drop_tracks_for(self, e, why):
        """Every track this entity is a side of — the sensor that holds it, or the silent
        target it is — goes with a delete, like any other emitted uid."""
        eid = e.spec['id']
        for key in [k for k, tr in self.tracks.items() if tr['sensor'] is e or (not tr['real'] and tr['target'] == eid)]:
            self._drop_track(key, why)

    def _check_caps(self, silent=False, detect=False):
        if silent and sum(1 for x in self.entities if x.silent) >= sc.MAX_DETECTABLE:
            raise sc.ScenarioError([f'cmd: this run already has {sc.MAX_DETECTABLE} silent targets'])
        if detect and sum(1 for x in self.entities if x.spec['sensor'] and x.spec['sensor']['detect']) >= sc.MAX_DETECT_SENSORS:
            raise sc.ScenarioError([f'cmd: this run already has {sc.MAX_DETECT_SENSORS} detecting sensors'])

    # ── timeline ────────────────────────────────────────────────────────────
    def _fire_events(self):
        while self.ev_idx < len(self.events) and self.events[self.ev_idx]['at_s'] <= self.sim_t:
            ev = self.events[self.ev_idx]
            self.ev_idx += 1
            try:
                self._fire(ev)
                self.events_fired += 1
            except Exception as ex:          # a bad event must never kill the run
                self.log(f'event {ev["kind"]} at t+{ev["at_s"]:.0f}s failed: {str(ex)[:160]}')

    def _fire(self, ev):
        kind = ev['kind']
        lane_id = ev.get('lane') or self.doc['defaults']['lane']
        if kind == 'chat':
            e = self.by_id[ev['from']]
            lat, lon = self._latlon(e.pos)
            xml = cot.chat_event(e.uid, e.type, self._callsign(e.lane, e.callsign), ev['text'], lat, lon, ev['room'])
            self._send(e.lane, None, 'b-t-f', xml)
            self.log(f't+{ev["at_s"]:.0f}s chat [{ev["room"]}] {e.callsign}: {ev["text"][:60]}')
        elif kind == 'casevac':
            uid = f'SIM-{self.name}-{ev["id"]}'
            lat, lon = self._latlon(ev['at'])
            title = self._callsign(lane_id, ev['title'])
            build = lambda: cot.casevac_event(uid, title, lat, lon, ev['urgent'], ev['priority'], ev['routine'],
                                              ev['litter'], ev['ambulatory'], ev['remarks'], stale_s=ev['stale_s'])
            self._add_persistent(uid, lane_id, 'b-r-f-h-c', build, ev['stale_s'],
                                 {'id': ev['id'], 'kind': 'casevac', 'callsign': ev['title'], 'ev': ev})
            self.log(f't+{ev["at_s"]:.0f}s CASEVAC {ev["title"]}')
        elif kind in ('emergency', 'emergency_cancel'):
            e = self.by_id[ev['from']]
            cancel = kind == 'emergency_cancel'
            uid = f'{e.uid}-9-1-1'
            cs = self._callsign(e.lane, e.callsign)
            if cancel:
                self._remove_persistent(uid)
                lat, lon = self._latlon(e.pos)
                self._send(e.lane, None, 'b-a-o-can', cot.emergency_event(e.uid, e.type, cs, lat, lon, ev['alert'], True))
                self.log(f't+{ev["at_s"]:.0f}s emergency CANCEL {e.callsign}')
            else:
                def build(e=e, cs=cs, alert=ev['alert']):
                    lat, lon = self._latlon(e.pos)
                    return cot.emergency_event(e.uid, e.type, cs, lat, lon, alert, False)
                self._add_persistent(uid, e.lane, cot.EMERGENCY_TYPES.get(ev['alert'], 'b-a-o-tbl'), build, 90.0,
                                     {'id': f'{ev["from"]}-911', 'kind': 'emergency', 'callsign': e.callsign,
                                      'ev': {'kind': 'emergency', 'at_s': 0, 'from': ev['from'], 'alert': ev['alert']}})
                self.log(f't+{ev["at_s"]:.0f}s EMERGENCY {ev["alert"]} from {e.callsign}')
        elif kind == 'marker':
            uid = f'SIM-{self.name}-{ev["id"]}'
            lat, lon = self._latlon(ev['at'])
            cs = self._callsign(lane_id, ev['callsign'])
            build = lambda: cot.marker_event(uid, ev['type'], cs, lat, lon, ev['remarks'], stale_s=ev['stale_s'])
            self._add_persistent(uid, lane_id, ev['type'], build, ev['stale_s'],
                                 {'id': ev['id'], 'kind': 'marker', 'callsign': ev['callsign'], 'ev': ev})
            self.log(f't+{ev["at_s"]:.0f}s marker {ev["callsign"]} ({ev["type"]})')
        elif kind == 'route':
            uid = f'SIM-{self.name}-{ev["id"]}'
            pts = [self._latlon(p) for p in ev['points']]
            cs = self._callsign(lane_id, ev['callsign'])
            color = cot.argb(ev['color'])
            build = lambda: cot.route_event(uid, cs, pts, color, stale_s=ev['stale_s'])
            self._add_persistent(uid, lane_id, 'b-m-r', build, ev['stale_s'],
                                 {'id': ev['id'], 'kind': 'route', 'callsign': ev['callsign'], 'ev': ev})
            self.log(f't+{ev["at_s"]:.0f}s route {ev["callsign"]} ({len(pts)} points)')
        elif kind == 'polygon':
            uid = f'SIM-{self.name}-{ev["id"]}'
            pts = [self._latlon(p) for p in ev['points']]
            cs = self._callsign(lane_id, ev['callsign'])
            stroke, fill = cot.argb(ev['stroke']), cot.argb(ev['fill'], ev['fill_alpha'])
            build = lambda: cot.polygon_event(uid, cs, pts, stroke, fill, stale_s=ev['stale_s'], remarks=ev['remarks'])
            self._add_persistent(uid, lane_id, 'u-d-f', build, ev['stale_s'],
                                 {'id': ev['id'], 'kind': 'polygon', 'callsign': ev['callsign'], 'ev': ev})
            self.log(f't+{ev["at_s"]:.0f}s polygon {ev["callsign"]} ({len(pts)} vertices)')
        elif kind == 'circle':
            uid = f'SIM-{self.name}-{ev["id"]}'
            lat, lon = self._latlon(ev['at'])
            cs = self._callsign(lane_id, ev['callsign'])
            stroke, fill = cot.argb(ev['stroke']), cot.argb(ev['fill'], ev['fill_alpha'])
            build = lambda: cot.circle_event(uid, cs, lat, lon, ev['radius_m'], stroke, fill, stale_s=ev['stale_s'], remarks=ev['remarks'])
            self._add_persistent(uid, lane_id, 'u-d-c-c', build, ev['stale_s'],
                                 {'id': ev['id'], 'kind': 'circle', 'callsign': ev['callsign'], 'ev': ev})
            self.log(f't+{ev["at_s"]:.0f}s circle {ev["callsign"]} r={ev["radius_m"]:.0f}m')
        elif kind == 'spawn':
            e = self.by_id[ev['entity']]
            e.spec['spawn_at_s'] = min(e.spec['spawn_at_s'], self.sim_t)
            e.alive = True
            e.next_emit = self.sim_t
            self.log(f't+{ev["at_s"]:.0f}s spawn {e.callsign}')
        elif kind == 'despawn':
            e = self.by_id[ev['entity']]
            self._despawn(e)
            e.spec['despawn_at_s'] = self.sim_t if e.spec['despawn_at_s'] is None else e.spec['despawn_at_s']
            self.log(f't+{ev["at_s"]:.0f}s despawn {e.callsign}')
        elif kind == 'callsign':
            e = self.by_id[ev['entity']]
            self.log(f't+{ev["at_s"]:.0f}s callsign {e.callsign} -> {ev["callsign"]}')
            e.callsign = ev['callsign']
            e.next_emit = self.sim_t
        elif kind == 'team':
            e = self.by_id[ev['entity']]
            e.team = ev['team']
            if ev.get('role'):
                e.role = ev['role']
            e.next_emit = self.sim_t
            self.log(f't+{ev["at_s"]:.0f}s team {e.callsign} -> {e.team}')
        elif kind == 'remove':
            self._remove_persistent(f'SIM-{self.name}-{ev["id"]}')
            self.log(f't+{ev["at_s"]:.0f}s remove {ev["id"]}')

    # ── stats ───────────────────────────────────────────────────────────────
    def stats(self):
        alive = sum(1 for e in self.entities if e.alive)
        return {
            'scenario': self.name, 'title': self.doc['title'], 'state': self.state, 'live': self.live,
            'started_at': self.started_at, 'ended_at': self.ended_at, 'ended_reason': self.ended_reason,
            'uptime_s': (round(time.time() - self.started_at) if self.started_at and not self.ended_at
                         else (round(self.ended_at - self.started_at) if self.started_at else 0)),
            'sim_t': round(self.sim_t, 1), 'duration_s': self.duration, 'tempo': self.tempo,
            'loop': self.loop, 'loops_done': self.loops_done,
            'entities_alive': alive, 'entities_total': len(self.entities),
            'events_fired': self.events_fired, 'events_total': len(self.events),
            'persistent_objects': len(self.persistent), 'uids_emitted': len(self.emitted),
            'tracks_live': len(self.tracks), 'tracks_total': self.tracks_total,
            'max_msgs_per_sec': self.max_mps,
            'lanes': [ln.stats() for ln in self.lanes.values()],
        }

    # ── director (W9): commands, state, layout ──────────────────────────────
    def _object_ids(self):
        return {p['id'] for p in self.persistent.values() if p.get('id')}

    def _new_id(self):
        while True:
            self._spawn_seq += 1
            cand = f'u{self._spawn_seq}'
            if cand not in self.by_id:
                return cand

    def command(self, raw):
        """Validate a director command on the caller's thread, queue it, and wait for the
        loop thread to apply it. Returns the state after the change. Raises ScenarioError
        (bad command), LookupError (no such unit/object) or RuntimeError (run not live)."""
        if self.state not in ('running', 'paused'):
            raise RuntimeError('no run in progress — start a live session or a scenario first')
        if isinstance(raw, dict) and raw.get('op') == 'spawn' and not raw.get('id'):
            raw = dict(raw, id=self._new_id())
        if (isinstance(raw, dict) and raw.get('op') == 'detect' and isinstance(raw.get('detect'), dict)
                and 'track_stale_s' not in raw['detect']):
            # the default track stale is twice the SENSOR's own interval (schema v2)
            e = self.by_id.get(raw.get('id'))
            if e is not None:
                raw = dict(raw, detect=dict(raw['detect'], track_stale_s=max(10.0, 2.0 * e.spec['interval_s'])))
        cmd = sc.validate_cmd(raw, self._plane, set(self.by_id), self._object_ids(),
                              set(self.lanes), self.doc['defaults'])
        fut = {'done': threading.Event()}
        self._cmdq.put((cmd, fut))
        if not fut['done'].wait(CMD_TIMEOUT_S):
            raise RuntimeError('the engine did not apply the command in time')
        if 'error' in fut:
            raise fut['error']
        return fut['result']

    def _drain_commands(self, fail=None):
        while True:
            try:
                cmd, fut = self._cmdq.get_nowait()
            except queue.Empty:
                return
            try:
                if fail is not None:
                    raise fail
                fut['result'] = self._apply(cmd)
            except Exception as ex:      # the answer travels back to the control thread
                fut['error'] = ex
            finally:
                fut['done'].set()

    def _apply(self, cmd):
        op = cmd['op']
        if op == 'spawn':
            spec = cmd['entity']
            if spec['id'] in self.by_id:
                raise sc.ScenarioError([f'cmd.id: an entity with id {spec["id"]!r} already exists'])
            if spec['lane'] not in self.lanes:
                raise sc.ScenarioError([f'cmd.lane: this run is not connected on lane {spec["lane"]!r}'])
            self._check_caps(silent=spec['silent'], detect=bool(spec['sensor'] and spec['sensor']['detect']))
            e = Entity(spec, f'SIM-{self.name}-{spec["id"]}', self.rng, self.doc['areas'])
            e.alive = True
            e.next_emit = self.sim_t
            e.next_look = self.sim_t
            self.entities.append(e)
            self.by_id[spec['id']] = e
            self.log(f'director: spawn {e.callsign} ({e.type}{", silent as " + e.detected_type if e.silent else ""}) '
                     f'at t+{self.sim_t:.0f}s on lane {e.lane}'
                     f'{" path=" + spec["path"]["kind"] if spec["path"]["kind"] != "static" else ""}')
            return self._entity_state(e)
        if op == 'tempo':
            self.tempo = float(cmd['tempo'])
            self.log(f'director: tempo {self.tempo:g}x')
            return {'tempo': self.tempo}
        if op == 'event':
            ev = dict(cmd['event'], at_s=self.sim_t)
            self._fire(ev)
            self.events_fired += 1
            uid = f'SIM-{self.name}-{ev["id"]}' if ev.get('id') else None
            if uid and uid in self.persistent:
                return self._object_state(uid)
            return {'fired': ev['kind']}
        if op == 'remove':
            e = self.by_id.get(cmd['id'])
            if e is not None:
                self._remove_entity(e)
                self.log(f'director: remove {e.callsign}')
                return {'removed': cmd['id'], 'entity': True}
            uid = f'SIM-{self.name}-{cmd["id"]}'
            if uid in self.persistent:
                self._remove_persistent(uid)
                self.log(f'director: remove object {cmd["id"]}')
                return {'removed': cmd['id'], 'object': True}
            raise LookupError(f'nothing with id {cmd["id"]!r} to remove')
        e = self.by_id.get(cmd['id'])
        if e is None:
            raise LookupError(f'no entity with id {cmd["id"]!r}')
        if op == 'goto':
            e.set_path({'kind': 'waypoints', 'points': [e.pos, tuple(cmd['to'])],
                        'speed_mps': cmd['speed_mps'], 'loop': False, 'pause_s': 0.0})
        elif op == 'route':
            e.set_path({'kind': 'waypoints', 'points': [e.pos] + [tuple(p) for p in cmd['points']],
                        'speed_mps': cmd['speed_mps'], 'loop': cmd['loop'], 'pause_s': 0.0})
        elif op == 'orbit':
            if cmd['center'] is not None:
                center = tuple(cmd['center'])
            else:
                # "orbit here": a circle THROUGH the current position, entered tangentially —
                # the center sits one radius to the side of the current heading, so the
                # unit starts turning right now (no entry leg, no teleport).
                r = cmd['radius_m']
                h = math.radians(e.heading + (90.0 if cmd['clockwise'] else -90.0))
                center = (e.pos[0] + r * math.sin(h), e.pos[1] + r * math.cos(h))
            e.set_path({'kind': 'orbit', 'center': center, 'radius_m': cmd['radius_m'],
                        'speed_mps': cmd['speed_mps'], 'clockwise': cmd['clockwise']})
        elif op == 'heading':
            e.set_path({'kind': 'heading', 'at': e.pos, 'heading_deg': cmd['heading_deg'],
                        'speed_mps': cmd['speed_mps']})
            if cmd['hae_m'] is not None:
                e.spec['hae_m'] = cmd['hae_m']
        elif op == 'hold':
            e.set_path({'kind': 'static', 'at': e.pos})
        elif op == 'alt':
            e.spec['hae_m'] = cmd['hae_m']
        elif op == 'lostlink':
            e.lostlink = cmd['on']
        elif op == 'rename':
            e.callsign = cmd['callsign']
        elif op == 'team':
            e.team = cmd['team']
            if cmd['role']:
                e.role = cmd['role']
        elif op == 'detect':
            if not e.spec['sensor']:
                raise sc.ScenarioError([f'cmd.id: {e.callsign} has no sensor to detect with'])
            if cmd['detect'] is not None and not e.spec['sensor']['detect']:
                self._check_caps(detect=True)
            e.spec['sensor']['detect'] = cmd['detect']
            if cmd['detect'] is None:
                self._drop_tracks_for(e, 'detection off')
            e.next_look = self.sim_t
            e.sweep_prev = None
        if not e.alive:
            e.alive = True
        if not e.lostlink:
            e.next_emit = self.sim_t           # show the change on the next tick
        self.log(f'director: {op} {e.callsign}'
                 + (f' -> {cmd["heading_deg"]:.0f}° {cmd["speed_mps"]:g} m/s' if op == 'heading' else '')
                 + (f' r={cmd["radius_m"]:.0f}m {cmd["speed_mps"]:g} m/s' if op == 'orbit' else '')
                 + (f' {cmd["speed_mps"]:g} m/s' if op in ('goto', 'route') else '')
                 + (f' {cmd["hae_m"]:.0f} m' if op == 'alt' else '')
                 + (f' {"ON" if cmd["on"] else "off"}' if op == 'lostlink' else '')
                 + ((' ' + (f'{"/".join(cmd["detect"]["kinds"])} to {e.spec["sensor"]["range_m"]:.0f} m'
                            if cmd['detect'] else 'off')) if op == 'detect' else ''))
        return self._entity_state(e)

    def _remove_entity(self, e):
        self._remove_persistent(f'{e.uid}-9-1-1')     # its 911 beacon, if one is up
        self._despawn(e)
        self.by_id.pop(e.spec['id'], None)
        try:
            self.entities.remove(e)
        except ValueError:
            pass

    def _seen_by(self):
        """target entity id -> sorted ids of the sensors currently tracking it."""
        seen = {}
        for tr in list(self.tracks.values()):
            if not tr['real']:
                seen.setdefault(tr['target'], []).append(tr['sensor'].spec['id'])
        return {k: sorted(v) for k, v in seen.items()}

    def _entity_state(self, e, seen=None):
        lat, lon = self._latlon(e.pos)
        if seen is None:
            seen = self._seen_by()
        return {
            'id': e.spec['id'], 'uid': e.uid, 'callsign': e.callsign, 'type': e.type,
            'team': e.team, 'role': e.role, 'lane': e.lane,
            'lat': round(lat, 7), 'lon': round(lon, 7), 'hae_m': e.spec['hae_m'],
            'heading': round(e.heading, 1), 'speed_mps': round(e.speed, 2),
            'alive': e.alive, 'lostlink': e.lostlink, 'emitted': e.emitted,
            'path_kind': e.spec['path']['kind'],
            'sensor': e.spec.get('sensor'), 'video': bool(e.spec.get('video')),
            'silent': e.silent, 'detected_type': e.detected_type, 'detected_callsign': e.detected_callsign,
            'seen_by': seen.get(e.spec['id'], []),
        }

    def _detection_state(self, tr):
        return {'sensor': tr['sensor'].spec['id'], 'target': tr['target'], 'uid': tr['uid'],
                'callsign': self._track_callsign(tr), 'type': tr['type'], 'lane': tr['lane'],
                'since_s': round(self.sim_t - tr['since'], 1), 'real': tr['real']}

    def _object_state(self, uid, p=None):
        p = self.persistent[uid] if p is None else p
        return {'uid': uid, 'id': p.get('id'), 'kind': p.get('kind'), 'callsign': p.get('callsign'),
                'type': p['type'], 'lane': p['lane']}

    def snapshot(self):
        """GET /state: everything a map front end needs to draw its unit list (2 s poll)."""
        seen = self._seen_by()
        return {
            'state': self.state, 'run': self.stats(),
            'entities': [self._entity_state(e, seen) for e in list(self.entities)],
            'objects': [self._object_state(uid, p) for uid, p in list(self.persistent.items())],
            'detections': [self._detection_state(tr) for tr in list(self.tracks.values())],
        }

    def _layout_path(self, e):
        p = e.spec['path']
        kind = p['kind']
        if kind == 'static':
            return {'kind': 'static', 'at': list(e.pos)}
        if kind == 'heading':
            return {'kind': 'heading', 'at': list(e.pos), 'heading_deg': p['heading_deg'], 'speed_mps': p['speed_mps']}
        if kind == 'orbit':
            return {'kind': 'orbit', 'center': list(p['center']), 'radius_m': p['radius_m'],
                    'speed_mps': p['speed_mps'], 'clockwise': p['clockwise']}
        if kind == 'waypoints':
            return {'kind': 'waypoints', 'points': [list(q) for q in p['points']], 'speed_mps': p['speed_mps'],
                    'loop': p['loop'], 'pause_s': p['pause_s']}
        out = {'kind': 'random_walk', 'speed_mps': p['speed_mps'], 'turn_deg_s': p['turn_deg_s']}
        if p.get('area'):
            out['area'] = p['area']
        elif p.get('polygon'):
            out['polygon'] = [list(q) for q in p['polygon']]
        else:
            out['start'] = list(p['start'])
            out['radius_m'] = p['radius_m']
        return out

    def layout_doc(self, title, name):
        """POST /save: the live layout as a scenario document — every live unit at its
        current position (paths preserved), every persistent object as an `at_s: 0`
        event — validated, so what is written always loads again."""
        ents = []
        for e in list(self.entities):
            if not e.alive:
                continue
            spec = e.spec
            ent = {'id': spec['id'], 'callsign': e.callsign, 'type': e.type, 'team': e.team,
                   'role': e.role, 'lane': e.lane, 'path': self._layout_path(e),
                   'interval_s': spec['interval_s'], 'stale_s': spec['stale_s'], 'hae_m': spec['hae_m']}
            for k in ('remarks', 'sensor', 'video'):
                if spec.get(k):
                    ent[k] = spec[k] if isinstance(spec[k], str) else dict(spec[k])
            if e.silent:
                ent['silent'] = True
                ent['detected_type'] = e.detected_type
                if e.detected_callsign:
                    ent['detected_callsign'] = e.detected_callsign
            ents.append(ent)
        events = [_plain(dict(p['ev'], at_s=0)) for p in list(self.persistent.values()) if p.get('ev')]
        doc = {
            'name': name, 'title': title,
            'story': f'Layout saved from a live session: {len(ents)} unit(s), {len(events)} object(s).',
            'version': sc.SCHEMA_VERSION, 'duration_s': 3600, 'loop': True, 'default_tempo': 1,
            'defaults': dict(self.doc['defaults']),
            'areas': {k: [list(q) for q in v] for k, v in self.doc['areas'].items()},
            'entities': ents, 'events': events,
            # where it was laid out, so W3 can reopen it there (`recenter: false`)
            'center': {'lat': self.center[0], 'lon': self.center[1]},
        }
        return sc.validate(_plain(doc), name)


def _plain(obj):
    """Tuples -> lists, recursively, so a normalized event serializes as the schema reads it."""
    if isinstance(obj, tuple):
        return [_plain(x) for x in obj]
    if isinstance(obj, list):
        return [_plain(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _plain(v) for k, v in obj.items()}
    return obj
