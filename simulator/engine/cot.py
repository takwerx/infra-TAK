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
"""Cursor on Target builders for the TAK Simulator engine.

Every event goes out as XML CoT 2.0 (TAK Server negotiates protobuf only when the client
asks for it; we never do). Every builder here is a pure function of its arguments so the
run loop stays testable, and every event carries the EXERCISE remark (PLAN v10.1.61
§4.3) — there is deliberately no way to build one without it.

Detail shapes follow what ATAK itself puts on the wire (contact / __group / track / takv
for a PLI; __chat + chatgrp + link + remarks for GeoChat; _medevac_ for a CASEVAC;
emergency + link for a 911 beacon; link points for routes and shapes; link + __forcedelete
for a delete) so ATAK, iTAK, WinTAK, WebTAK, CloudTAK and TAK Portal all render them.
"""
import os
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urlsplit

EXERCISE_REMARK = 'EXERCISE EXERCISE EXERCISE'
ENGINE_VERSION = os.environ.get('SIM_VERSION', 'dev')
# `how` for a sensor's track of a detected target (PLAN v10.1.62 W2). The CoT spec's
# machine-derived codes (MITRE, "Cursor-on-Target Message Router User's Guide", the `how`
# field) are: m-i mensurated (a measured position), m-g GPS, m-m magnetic, m-s simulated,
# m-f fused (corroborated from several sources), m-c configured, m-p predicted, m-r relayed.
# There is no dedicated "sensor track" code; a single sensor's own measurement is `m-i` —
# `m-f` would claim a fusion this engine deliberately does not do. Fallback: `m-g`.
TRACK_HOW = 'm-i'
XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'

# ATAK team colors and roles (validated by scenario.py; used here only for defaults)
TEAMS = ('White', 'Yellow', 'Orange', 'Magenta', 'Red', 'Maroon', 'Purple', 'Dark Blue',
         'Blue', 'Cyan', 'Teal', 'Green', 'Dark Green', 'Brown')
ROLES = ('Team Member', 'Team Lead', 'HQ', 'Sniper', 'Medic', 'Forward Observer', 'RTO', 'K9')

EMERGENCY_TYPES = {
    '911 Alert': 'b-a-o-tbl',
    'Ring The Bell': 'b-a-o-pan',
    'In Contact': 'b-a-o-opn',
    'Geo-fence Breached': 'b-a-g',
}


def cot_time(t=None):
    """ISO-8601 UTC with milliseconds, the way ATAK writes it."""
    dt = datetime.fromtimestamp(time.time() if t is None else t, tz=timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond // 1000:03d}Z'


def argb(hex_rgb, alpha=255):
    """'#RRGGBB' + alpha -> the signed 32-bit ARGB int ATAK uses for colors."""
    h = (hex_rgb or '#ffffff').lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    v = (int(alpha) << 24) | (r << 16) | (g << 8) | b
    return v - (1 << 32) if v >= (1 << 31) else v


def build_event(uid, etype, lat, lon, hae=0.0, how='m-g', stale_s=60, now=None,
                ce=9999999.0, le=9999999.0, details=()):
    """Serialize one <event>. `details` is an iterable of Elements (None entries skipped).
    The EXERCISE remark is appended unless the caller already supplied a <remarks>."""
    now = time.time() if now is None else now
    ev = ET.Element('event', version='2.0', uid=uid, type=etype, how=how,
                    time=cot_time(now), start=cot_time(now), stale=cot_time(now + stale_s))
    ET.SubElement(ev, 'point', lat=f'{lat:.7f}', lon=f'{lon:.7f}', hae=f'{hae:.1f}',
                  ce=f'{ce:.1f}', le=f'{le:.1f}')
    det = ET.SubElement(ev, 'detail')
    has_remarks = False
    for d in details:
        if d is None:
            continue
        if d.tag == 'remarks':
            has_remarks = True
            if EXERCISE_REMARK not in (d.text or ''):
                d.text = f'{EXERCISE_REMARK} {d.text or ""}'.strip()
        det.append(d)
    if not has_remarks:
        det.append(d_remarks(EXERCISE_REMARK))
    return XML_DECL + ET.tostring(ev, encoding='unicode')


# ── detail fragments ─────────────────────────────────────────────────────────

def d_contact(callsign, endpoint=None):
    el = ET.Element('contact', callsign=callsign)
    if endpoint:
        el.set('endpoint', endpoint)
    return el


def d_group(team, role):
    return ET.Element('__group', name=team, role=role)


def d_track(speed_mps, course_deg):
    return ET.Element('track', speed=f'{speed_mps:.2f}', course=f'{course_deg:.1f}')


def d_takv():
    return ET.Element('takv', device='TAK Simulator', platform='infra-TAK', os='linux',
                      version=ENGINE_VERSION)


def d_uid(callsign):
    return ET.Element('uid', Droid=callsign)


def d_status(battery=100):
    return ET.Element('status', battery=str(int(battery)))


def d_precision():
    return ET.Element('precisionlocation', geopointsrc='GPS', altsrc='GPS')


def d_remarks(text, **attrs):
    el = ET.Element('remarks', **attrs)
    el.text = text
    return el


def d_sensor(azimuth_deg, fov_deg=60.0, range_m=1000.0, vfov_deg=45.0, elevation_deg=0.0,
             model='Simulated EO'):
    return ET.Element('sensor', azimuth=f'{azimuth_deg:.1f}', fov=f'{fov_deg:.1f}',
                      range=f'{range_m:.0f}', vfov=f'{vfov_deg:.1f}',
                      elevation=f'{elevation_deg:.1f}', roll='0', fovRed='1.0',
                      fovGreen='1.0', fovBlue='1.0', fovAlpha='0.3',
                      displayMagneticReference='0', hideFov='false', type='r-e', model=model)


def d_video(alias, url, uid):
    """ATAK/CloudTAK video link. `url` is a full rtsp:// (or rtsps://) URL."""
    u = urlsplit(url)
    port = u.port or (8554 if u.scheme == 'rtsp' else 8555)
    v = ET.Element('__video', uid=uid, url=url)
    ET.SubElement(v, 'ConnectionEntry', networkTimeout='12000', uid=uid, path=u.path or '/',
                  protocol=u.scheme, bufferTime='-1', address=u.hostname or '', port=str(port),
                  roverPort='-1', rtspReliable='1', ignoreEmbeddedKLV='false', alias=alias)
    return v


def d_link(uid, etype, relation='p-p', **extra):
    return ET.Element('link', uid=uid, type=etype, relation=relation, **extra)


def d_color(value):
    return ET.Element('color', value=str(value))


def d_stroke(color, weight=3.0):
    a = ET.Element('strokeColor', value=str(color))
    b = ET.Element('strokeWeight', value=f'{weight:.1f}')
    return a, b


def d_fill(color):
    return ET.Element('fillColor', value=str(color))


def d_labels(on=True):
    return ET.Element('labels_on', value='true' if on else 'false')


def d_archive():
    return ET.Element('archive')


# ── whole events ─────────────────────────────────────────────────────────────

def pli_event(uid, etype, callsign, lat, lon, hae, speed_mps, course_deg, team, role,
              stale_s, now=None, sensor=None, video=None, remarks=None, sensor_azimuth=None):
    """A unit's position report (what ATAK calls SA / PLI). `sensor_azimuth` overrides the
    cone's look direction (a sweeping radar); it defaults to the course."""
    details = [d_contact(callsign), d_group(team, role), d_track(speed_mps, course_deg),
               d_takv(), d_uid(callsign), d_status(), d_precision()]
    if sensor:
        az = course_deg if sensor_azimuth is None else sensor_azimuth
        details.append(d_sensor(az, sensor.get('fov', 60.0), sensor.get('range_m', 1000.0),
                                sensor.get('vfov', 45.0), sensor.get('elevation', 0.0)))
    if video:
        details.append(d_video(callsign, video, f'{uid}-video'))
    details.append(d_remarks(remarks or EXERCISE_REMARK))
    return build_event(uid, etype, lat, lon, hae, how='m-g', stale_s=stale_s, now=now,
                       ce=10.0, le=10.0, details=details)


def track_event(uid, etype, callsign, lat, lon, hae, speed_mps, course_deg, sensor_uid, sensor_type,
                sensor_callsign, stale_s, ce=50.0, now=None):
    """A sensor's track of a target it detected (PLAN v10.1.62 W2): an unknown-domain atom
    (`a-u-S` / `a-u-A` / `a-u-G` unless the scenario says otherwise) named by the sensor,
    linked to the SENSOR as its parent so a client can show who saw it, with the reported
    position error as `ce`. Deliberately nothing of the target's own identity — no link to
    its uid, no name, no MMSI: the point of the drill is that the sensor does not know
    who it is looking at."""
    details = [d_contact(callsign), d_track(speed_mps, course_deg),
               d_link(sensor_uid, sensor_type, 'p-p'),
               d_remarks(f'Detected by {sensor_callsign} — {EXERCISE_REMARK}')]
    return build_event(uid, etype, lat, lon, hae, how=TRACK_HOW, stale_s=stale_s, now=now,
                       ce=ce, le=9999999.0, details=details)


def chat_event(sender_uid, sender_type, sender_callsign, text, lat, lon, room='All Chat Rooms',
               now=None, stale_s=3600):
    """GeoChat to a room. `room` = 'All Chat Rooms' broadcasts to the lane's channel."""
    now = time.time() if now is None else now
    msg_id = str(uuid.uuid4())
    uid = f'GeoChat.{sender_uid}.{room}.{msg_id}'
    chat = ET.Element('__chat', parent='RootContactGroup', groupOwner='false', messageId=msg_id,
                      chatroom=room, id=room, senderCallsign=sender_callsign)
    ET.SubElement(chat, 'chatgrp', uid0=sender_uid, uid1=room, id=room)
    details = [chat, d_link(sender_uid, sender_type, 'p-p'),
               d_remarks(text, source=f'BAO.F.ATAK.{sender_uid}', to=room, time=cot_time(now))]
    return build_event(uid, 'b-t-f', lat, lon, 0.0, how='h-g-i-g-o', stale_s=stale_s, now=now,
                       details=details)


def casevac_event(uid, title, lat, lon, urgent=1, priority=0, routine=0, litter=1, ambulatory=0,
                  remarks=None, now=None, stale_s=300):
    med = ET.Element('_medevac_', title=title, casevac='true', freq='0.0', equipment_none='true',
                     security='0', hlz_marking='0', terrain_none='true', zone_prot_selection='0',
                     urgent=str(int(urgent)), priority=str(int(priority)), routine=str(int(routine)),
                     litter=str(int(litter)), ambulatory=str(int(ambulatory)),
                     medline_remarks=remarks or EXERCISE_REMARK)
    details = [med, d_contact(title), d_archive(), d_remarks(remarks or EXERCISE_REMARK)]
    return build_event(uid, 'b-r-f-h-c', lat, lon, 0.0, how='h-g-i-g-o', stale_s=stale_s, now=now,
                       details=details)


def emergency_event(entity_uid, entity_type, callsign, lat, lon, alert='911 Alert', cancel=False,
                    now=None, stale_s=90):
    uid = f'{entity_uid}-9-1-1'
    etype = 'b-a-o-can' if cancel else EMERGENCY_TYPES.get(alert, 'b-a-o-tbl')
    em = ET.Element('emergency', type=alert, cancel='true' if cancel else 'false')
    em.text = callsign
    details = [em, d_link(entity_uid, entity_type, 'p-p'), d_contact(callsign)]
    return build_event(uid, etype, lat, lon, 0.0, how='h-e', stale_s=stale_s, now=now,
                       details=details)


def marker_event(uid, etype, callsign, lat, lon, remarks=None, now=None, stale_s=300,
                 color=None):
    details = [d_contact(callsign), d_archive()]
    if color is not None:
        details.append(d_color(color))
    details.append(d_remarks(remarks or EXERCISE_REMARK))
    return build_event(uid, etype, lat, lon, 0.0, how='h-g-i-g-o', stale_s=stale_s, now=now,
                       details=details)


def route_event(uid, callsign, points_latlon, color=-1, now=None, stale_s=300, remarks=None):
    """ATAK route: one <link> per checkpoint, drawn in `color`."""
    details = []
    for i, (lat, lon) in enumerate(points_latlon):
        details.append(ET.Element('link', uid=f'{uid}-cp{i}', callsign=f'CP{i + 1}',
                                  type='b-m-p-c' if i in (0, len(points_latlon) - 1) else 'b-m-p-w',
                                  point=f'{lat:.7f},{lon:.7f},0.0', relation='c'))
    ri = ET.Element('__routeinfo')
    ET.SubElement(ri, '__navcues')
    details.append(ri)
    details.append(d_contact(callsign))
    details.extend(d_stroke(color, 3.0))
    details.append(d_color(color))
    details.append(d_labels(False))
    details.append(d_archive())
    details.append(d_remarks(remarks or EXERCISE_REMARK))
    lat0, lon0 = points_latlon[0]
    return build_event(uid, 'b-m-r', lat0, lon0, 0.0, how='h-e', stale_s=stale_s, now=now,
                       details=details)


def polygon_event(uid, callsign, points_latlon, stroke=-65536, fill=1140850688, now=None,
                  stale_s=300, remarks=None):
    """ATAK freeform drawing (u-d-f) — closed polygon, point list repeats the first vertex."""
    pts = list(points_latlon)
    if pts[0] != pts[-1]:
        pts.append(pts[0])
    details = [ET.Element('link', point=f'{lat:.7f},{lon:.7f},0.0') for lat, lon in pts]
    details.extend(d_stroke(stroke, 3.0))
    details.append(d_fill(fill))
    details.append(d_contact(callsign))
    details.append(d_labels(True))
    details.append(d_archive())
    details.append(d_remarks(remarks or EXERCISE_REMARK))
    clat = sum(p[0] for p in pts[:-1]) / (len(pts) - 1)
    clon = sum(p[1] for p in pts[:-1]) / (len(pts) - 1)
    return build_event(uid, 'u-d-f', clat, clon, 0.0, how='h-e', stale_s=stale_s, now=now,
                       details=details)


def circle_event(uid, callsign, lat, lon, radius_m, stroke=-65536, fill=1140850688, now=None,
                 stale_s=300, remarks=None):
    shape = ET.Element('shape')
    ET.SubElement(shape, 'ellipse', major=f'{radius_m:.1f}', minor=f'{radius_m:.1f}', angle='360')
    details = [shape]
    details.extend(d_stroke(stroke, 3.0))
    details.append(d_fill(fill))
    details.append(d_contact(callsign))
    details.append(d_labels(True))
    details.append(d_archive())
    details.append(d_remarks(remarks or EXERCISE_REMARK))
    return build_event(uid, 'u-d-c-c', lat, lon, 0.0, how='h-e', stale_s=stale_s, now=now,
                       details=details)


def delete_event(target_uid, target_type, now=None):
    """t-x-d-d: every client that has `target_uid` removes it (PLAN §4.3 'stop = clean')."""
    details = [d_link(target_uid, target_type, 'none'), ET.Element('__forcedelete')]
    return build_event(f'{target_uid}-del-{uuid.uuid4().hex[:8]}', 't-x-d-d', 0.0, 0.0, 0.0,
                       how='m-g', stale_s=60, now=now, details=details)
