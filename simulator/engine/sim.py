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
"""
import math
import random
import threading
import time

from . import cot, geo


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


class Entity:
    __slots__ = ('spec', 'uid', 'callsign', 'team', 'role', 'lane', 'type', 'pos', 'heading',
                 'speed', 'alive', 'next_emit', 'wp_idx', 'wp_pause_until', 'angle', 'walk_area',
                 'walk_center', 'walk_radius', 'start_pos', 'emitted')

    def __init__(self, spec, uid, rng, areas):
        self.spec = spec
        self.uid = uid
        self.callsign = spec['callsign']
        self.team = spec['team']
        self.role = spec['role']
        self.lane = spec['lane']
        self.type = spec['type']
        self.emitted = False
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

    def advance(self, sim_dt, sim_t, rng):
        p = self.spec['path']
        kind = p['kind']
        if kind == 'static' or sim_dt <= 0:
            self.speed = 0.0
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
    def __init__(self, doc, params, lanes, log, video_base=None, default_channel='tak_simulation'):
        self.doc = doc
        self.params = params
        self.lanes = lanes                      # lane_id -> Lane
        self.log = log
        self.video_base = (video_base or '').rstrip('/') or None
        self.default_channel = default_channel
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
                }
                e = Entity(spec, f'SIM-{self.name}-gen{i}', self.rng, doc['areas'])
                self.entities.append(e)
                self.by_id[spec['id']] = e
        self.events = list(doc['events'])
        self.ev_idx = 0
        self.persistent = {}        # uid -> {'lane','type','build','refresh','next'}
        self.emitted = {}           # uid -> (lane_id, type) — for the stop deletes
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
        self.log(f'run {self.name}: started — {len(self.entities)} entities, {len(self.events)} events, '
                 f'tempo {self.tempo:g}x, loop={self.loop}, duration {self.duration:.0f}s, '
                 f'governor {self.max_mps:g} msg/s/lane')
        while not self._stop_evt.is_set():
            now = time.monotonic()
            dt = now - last
            last = now
            if self.state != 'running':
                time.sleep(tick)
                continue
            sim_dt = dt * self.tempo
            self.sim_t += sim_dt
            self._advance(sim_dt)
            self._emit_due()
            self._fire_events()
            self._refresh_persistent()
            if self.sim_t >= self.duration:
                if self.loop:
                    self._reset_loop()
                else:
                    break
            time.sleep(tick)
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
            if not e.alive or self.sim_t < e.next_emit:
                continue
            gov = self.governors.get(e.lane)
            if gov is None or not gov.take():
                continue            # backpressure: try again next tick
            self._emit_pli(e)
            e.next_emit = self.sim_t + e.spec['interval_s']

    def _emit_pli(self, e):
        lat, lon = self._latlon(e.pos)
        xml = cot.pli_event(e.uid, e.type, self._callsign(e.lane, e.callsign), lat, lon,
                            e.spec['hae_m'], e.speed, e.heading, e.team, e.role, e.spec['stale_s'],
                            sensor=e.spec.get('sensor'), video=self._video_url(e),
                            remarks=e.spec.get('remarks'))
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

    def _reset_loop(self):
        self.loops_done += 1
        self.sim_t = 0.0
        self.ev_idx = 0
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

    def _add_persistent(self, uid, lane_id, etype, build, stale_s):
        self.persistent[uid] = {'lane': lane_id, 'type': etype, 'build': build,
                                'refresh': max(5.0, stale_s / 2.0), 'next': self.sim_t + max(5.0, stale_s / 2.0)}
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
            self._add_persistent(uid, lane_id, 'b-r-f-h-c', build, ev['stale_s'])
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
                self._add_persistent(uid, e.lane, cot.EMERGENCY_TYPES.get(ev['alert'], 'b-a-o-tbl'), build, 90.0)
                self.log(f't+{ev["at_s"]:.0f}s EMERGENCY {ev["alert"]} from {e.callsign}')
        elif kind == 'marker':
            uid = f'SIM-{self.name}-{ev["id"]}'
            lat, lon = self._latlon(ev['at'])
            cs = self._callsign(lane_id, ev['callsign'])
            build = lambda: cot.marker_event(uid, ev['type'], cs, lat, lon, ev['remarks'], stale_s=ev['stale_s'])
            self._add_persistent(uid, lane_id, ev['type'], build, ev['stale_s'])
            self.log(f't+{ev["at_s"]:.0f}s marker {ev["callsign"]} ({ev["type"]})')
        elif kind == 'route':
            uid = f'SIM-{self.name}-{ev["id"]}'
            pts = [self._latlon(p) for p in ev['points']]
            cs = self._callsign(lane_id, ev['callsign'])
            color = cot.argb(ev['color'])
            build = lambda: cot.route_event(uid, cs, pts, color, stale_s=ev['stale_s'])
            self._add_persistent(uid, lane_id, 'b-m-r', build, ev['stale_s'])
            self.log(f't+{ev["at_s"]:.0f}s route {ev["callsign"]} ({len(pts)} points)')
        elif kind == 'polygon':
            uid = f'SIM-{self.name}-{ev["id"]}'
            pts = [self._latlon(p) for p in ev['points']]
            cs = self._callsign(lane_id, ev['callsign'])
            stroke, fill = cot.argb(ev['stroke']), cot.argb(ev['fill'], ev['fill_alpha'])
            build = lambda: cot.polygon_event(uid, cs, pts, stroke, fill, stale_s=ev['stale_s'], remarks=ev['remarks'])
            self._add_persistent(uid, lane_id, 'u-d-f', build, ev['stale_s'])
            self.log(f't+{ev["at_s"]:.0f}s polygon {ev["callsign"]} ({len(pts)} vertices)')
        elif kind == 'circle':
            uid = f'SIM-{self.name}-{ev["id"]}'
            lat, lon = self._latlon(ev['at'])
            cs = self._callsign(lane_id, ev['callsign'])
            stroke, fill = cot.argb(ev['stroke']), cot.argb(ev['fill'], ev['fill_alpha'])
            build = lambda: cot.circle_event(uid, cs, lat, lon, ev['radius_m'], stroke, fill, stale_s=ev['stale_s'], remarks=ev['remarks'])
            self._add_persistent(uid, lane_id, 'u-d-c-c', build, ev['stale_s'])
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
            'scenario': self.name, 'title': self.doc['title'], 'state': self.state,
            'started_at': self.started_at, 'ended_at': self.ended_at, 'ended_reason': self.ended_reason,
            'uptime_s': (round(time.time() - self.started_at) if self.started_at and not self.ended_at
                         else (round(self.ended_at - self.started_at) if self.started_at else 0)),
            'sim_t': round(self.sim_t, 1), 'duration_s': self.duration, 'tempo': self.tempo,
            'loop': self.loop, 'loops_done': self.loops_done,
            'entities_alive': alive, 'entities_total': len(self.entities),
            'events_fired': self.events_fired, 'events_total': len(self.events),
            'persistent_objects': len(self.persistent), 'uids_emitted': len(self.emitted),
            'max_msgs_per_sec': self.max_mps,
            'lanes': [ln.stats() for ln in self.lanes.values()],
        }
