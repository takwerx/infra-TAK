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
"""Local-plane geometry for the TAK Simulator engine.

Entities move on an east/north meter plane centered on the run's area-of-operations
center and are converted to lat/lon only when a CoT event is emitted. That keeps every
preset location-independent (PLAN v10.1.61 §4.3): the same scenario runs in Nashville
or Nome, and the math stays well under a meter over the ~20 km an exercise covers.
Standard library only — no numpy, no shapely.
"""
import math

EARTH_RADIUS_M = 6371008.8


def to_latlon(center, east_m, north_m):
    """(lat, lon) for a plane offset from `center` = (lat, lon)."""
    lat0, lon0 = center
    lat = lat0 + math.degrees(north_m / EARTH_RADIUS_M)
    lon = lon0 + math.degrees(east_m / (EARTH_RADIUS_M * math.cos(math.radians(lat0))))
    return lat, lon


def from_latlon(center, lat, lon):
    """(east_m, north_m) plane offset of a lat/lon from `center` — the exact inverse of
    to_latlon, so a director's map click lands where the click was."""
    lat0, lon0 = center
    north = math.radians(lat - lat0) * EARTH_RADIUS_M
    east = math.radians(lon - lon0) * EARTH_RADIUS_M * math.cos(math.radians(lat0))
    return east, north


def heading_deg(dx, dy):
    """Compass heading (0 = north, 90 = east) of a plane vector."""
    return math.degrees(math.atan2(dx, dy)) % 360.0


def dist(a, b):
    return math.hypot(b[0] - a[0], b[1] - a[1])


def step_toward(pos, target, step_m):
    """Move `pos` up to `step_m` toward `target`. Returns (new_pos, arrived)."""
    d = dist(pos, target)
    if d <= step_m or d == 0.0:
        return (target[0], target[1]), True
    f = step_m / d
    return (pos[0] + (target[0] - pos[0]) * f, pos[1] + (target[1] - pos[1]) * f), False


def point_in_polygon(p, poly):
    """Ray-casting point-in-polygon on the plane. `poly` is a list of (e, n)."""
    x, y = p
    inside = False
    n = len(poly)
    j = n - 1
    for i in range(n):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if (yi > y) != (yj > y):
            x_cross = (xj - xi) * (y - yi) / ((yj - yi) or 1e-12) + xi
            if x < x_cross:
                inside = not inside
        j = i
    return inside


def polygon_bbox(poly):
    xs = [p[0] for p in poly]
    ys = [p[1] for p in poly]
    return min(xs), min(ys), max(xs), max(ys)


def polygon_centroid(poly):
    return (sum(p[0] for p in poly) / len(poly), sum(p[1] for p in poly) / len(poly))


def random_point_in_polygon(poly, rng, tries=1000):
    """Uniform-ish random point inside `poly` by bbox rejection sampling. Falls back to
    the centroid for a degenerate polygon so a bad preset never spins forever."""
    x0, y0, x1, y1 = polygon_bbox(poly)
    for _ in range(tries):
        p = (rng.uniform(x0, x1), rng.uniform(y0, y1))
        if point_in_polygon(p, poly):
            return p
    return polygon_centroid(poly)


def random_point_in_circle(center, radius_m, rng):
    r = radius_m * math.sqrt(rng.random())
    a = rng.uniform(0.0, 2.0 * math.pi)
    return (center[0] + r * math.sin(a), center[1] + r * math.cos(a))


def orbit_point(center, radius_m, angle_deg):
    """Point on a circle at compass angle `angle_deg` (0 = due north of center)."""
    a = math.radians(angle_deg)
    return (center[0] + radius_m * math.sin(a), center[1] + radius_m * math.cos(a))
