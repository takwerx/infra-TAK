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
"""Guard Dog's disk I/O email no longer fires on a 1-hour latency average just over
the ceiling (ops #429). Second round after ops #229.

Field (Oct 29 to Nov 2, 2026): 7 `Disk I/O Degradation` emails from test6 and 2 from
garesponder, each tripped by a 1h commit-latency average of 10.2 to 15.3 ms with nothing
down. In every one the individual 4 KB probes swung between 2 and 46 ms.

Verified: the 1h latency average, the current probe, the last 8 throughput readings,
the 24h average and the 1h throughput average are copied from those emails.
Assumed: the three probes before the current one (the email shows only their average)
are spread evenly, and the hours before that are healthy (2.5 ms).

Runs the real script in the sandbox from test_guarddog_diskio_gate_ops229.
"""

import os
import time

import pytest

from test_guarddog_diskio_gate_ops229 import box  # noqa: F401  (fixture)

# name: (throughput readings oldest first with the alert run last, 24h avg MB/s,
#        the 3 earlier probes in the last hour as ms, current probe ms,
#        1h latency avg the email reported)
EMAILS = {
    'test6-oct30-1614': ([81.1, 89.7, 32.9, 18.4, 60.7, 31.3, 136.0, 34.1], 56.2,
                         [5.0, 5.0, 5.06], 46.14, 15.30),
    'test6-oct30-2215': ([48.5, 14.6, 19.7, 31.4, 36.0, 53.2, 53.3, 72.9], 58.1,
                         [11.0, 12.5, 12.27], 5.07, 10.21),
    'test6-oct31-0602': ([31.3, 28.7, 31.3, 34.2, 38.2, 35.7, 17.3, 43.7], 52.0,
                         [11.0, 11.2, 11.38], 11.98, 11.39),
    'test6-oct31-1736': ([58.1, 60.5, 39.6, 51.1, 27.3, 25.9, 104.0, 34.7], 50.0,
                         [7.0, 7.5, 7.5], 20.73, 10.68),
    'test6-nov1-0410':  ([26.1, 64.3, 48.0, 14.5, 30.9, 98.0, 56.1, 51.4], 53.2,
                         [5.0, 6.0, 6.15], 31.01, 12.04),
    'garesponder-nov2': ([82.0, 53.6, 61.3, 131.0, 31.5, 22.9, 60.9, 14.9], 86.3,
                         [12.2, 12.3, 12.29], 17.09, 13.47),
}
HEALTHY = 2.5


def _lat_rows(earlier_hour, older=8):
    rows = [(45, earlier_hour[0]), (30, earlier_hour[1]), (15, earlier_hour[2])]
    return rows + [(60 + 15 * i, HEALTHY) for i in range(older)]


def _kbs(ms):
    return '%.2f kB/s' % (4000 / ms)


@pytest.mark.parametrize('name', sorted(EMAILS))
def test_this_weeks_false_alarms_stay_quiet(box, name):  # noqa: F811
    readings, avg24, prior, current, lat_avg = EMAILS[name]
    box.current = readings[-1]
    box.seed([100.0] * 4 + readings[:-1], avg24, _lat_rows(prior))
    alerts, _, log = box(tp='%s MB/s' % readings[-1], lat=_kbs(current))
    assert '1h avg: %.2f ms/commit' % lat_avg in log      # what tripped the old gate
    assert alerts == ''


def test_real_stall_alerts_within_the_hour(box):  # noqa: F811
    # Healthy for hours, then the disk stalls: the third bad probe (45 min in) alerts.
    box.seed([100.0] * 11, lat=[(m, HEALTHY) for m in range(150, 60, -15)] +
             [(45, 3.0), (30, 120.0), (15, 140.0)])
    alerts, body, _ = box(lat='20 kB/s')                   # 200 ms/commit
    assert alerts.count('Disk I/O Degradation') == 1
    assert 'Disk commit latency is stalling' in body


def test_two_bad_probes_are_not_yet_a_stall(box):  # noqa: F811
    box.seed([100.0] * 11, lat=[(m, HEALTHY) for m in range(150, 45, -15)] + [(30, 3.0), (15, 140.0)])
    assert box(lat='20 kB/s')[0] == ''


def test_three_hours_over_the_ceiling_alerts(box):  # noqa: F811
    box.seed([100.0] * 11, lat=[(15 * i, 16.0) for i in range(1, 12)])
    alerts, body, _ = box(lat='%s' % _kbs(16.0))
    assert alerts.count('Disk I/O Degradation') == 1
    assert 'on every reading for the last 3 hours' in body


def test_one_dip_in_three_hours_keeps_quiet(box):  # noqa: F811
    rows = [(15 * i, 16.0) for i in range(1, 12)]
    rows[5] = (rows[5][0], 9.0)
    box.seed([100.0] * 11, lat=rows)
    assert box(lat=_kbs(16.0))[0] == ''


def test_one_email_a_day_then_again_if_still_degraded(box):  # noqa: F811
    def stall():
        box.seed([100.0] * 11, lat=[(45, 90.0), (30, 90.0), (15, 90.0)])
        return box(lat='40 kB/s')[0].count('Disk I/O Degradation')
    assert stall() == 1
    assert stall() == 1                                     # same day: no second email
    sentinel = box.state / 'diskio_alert_sent'
    for age_h, want in ((20, 1), (25, 2)):
        old = time.time() - age_h * 3600
        os.utime(sentinel, (old, old))
        assert stall() == want


def test_recovered_email_follows_a_sent_alert_once(box):  # noqa: F811
    box.seed([100.0] * 11, lat=[(45, 90.0), (30, 90.0), (15, 90.0)])
    assert 'Disk I/O Degradation' in box(lat='40 kB/s')[0]
    assert (box.state / 'diskio_degraded').exists()
    box.seed([100.0] * 11, lat=[(45, 2.5), (30, 2.4), (15, 2.6)])
    alerts = box(lat='1600 kB/s')[0]
    assert alerts.count('Disk I/O recovered') == 1
    assert not (box.state / 'diskio_degraded').exists()
    assert box(lat='1600 kB/s')[0].count('Disk I/O recovered') == 1   # not repeated


def test_no_recovered_email_when_no_alert_was_sent(box):  # noqa: F811
    box.seed([100.0] * 11, lat=[(45, 2.5), (30, 2.4), (15, 2.6)])
    assert box(lat='1600 kB/s')[0] == ''
