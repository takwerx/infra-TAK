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
"""Guard Dog's disk I/O check reads its history in one pass (ops #467).

It runs every 15 minutes. The three average calculations used to start a `date`
process for every row of the 31-day history, so on test6 (2,900+ rows) one run took
about 3 minutes of CPU and process spawning on a script that exists to watch for slow
disks. The timestamps are fixed-format UTC ISO-8601, which sort as text, so the windows
are now string compares against two cutoffs.

Two proofs:
  - the same readings give the same alert decisions, mail and log lines as the script
    before the change (frozen in tests/fixtures/tak-diskio-watch.before-ops467.sh);
  - on a full 31-day history the script starts a handful of `date` processes, not one
    per row (the old script starts about 9,000 and fails this test).
"""

import datetime as dt
import pathlib
import random
import re
import time

import pytest

from test_guarddog_diskio_gate_ops229 import make_box

REPO = pathlib.Path(__file__).resolve().parent.parent
BEFORE = (pathlib.Path(__file__).resolve().parent / 'fixtures' /
          'tak-diskio-watch.before-ops467.sh').read_text()
AFTER = (REPO / 'scripts' / 'guarddog' / 'tak-diskio-watch.sh').read_text()

ISO = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ')


def _stamp(now, minutes_ago):
    return (now - dt.timedelta(minutes=minutes_ago, seconds=30)).strftime('%Y-%m-%dT%H:%M:%SZ')


def _write(box, now, tp, lat):
    """tp: [(minutes_ago, mb_s)], lat: [(minutes_ago, ms_per_commit)], oldest first."""
    (box.state / 'diskio_history.csv').write_text(
        'timestamp,mb_per_sec\n' + ''.join('%s,%s\n' % (_stamp(now, m), v) for m, v in tp))
    if lat:
        (box.state / 'diskio_latency.csv').write_text(
            'timestamp,kb_per_sec,ms_per_commit\n' + ''.join(
                '%s,%.1f,%.2f\n' % (_stamp(now, m), 4000 / ms, ms) for m, ms in lat))


def _series(rng, days, tp_gen, lat_gen):
    n = days * 96
    tp = [(15 * (n - i), tp_gen(rng, i, n)) for i in range(n)]
    lat = [(15 * (n - i), lat_gen(rng, i, n)) for i in range(n)]
    return tp, lat


def _healthy_tp(rng, i, n):
    return round(rng.uniform(40, 130), 1)


def _healthy_lat(rng, i, n):
    return round(rng.uniform(1.5, 4.0), 2)


def _busy_tp(rng, i, n):
    return round(rng.uniform(6, 48), 1) if i >= n - 14 else _healthy_tp(rng, i, n)


def _busy_lat(rng, i, n):
    return round(rng.uniform(4, 35), 2) if i >= n - 14 else _healthy_lat(rng, i, n)


def _collapse_tp(rng, i, n):
    return round(rng.uniform(5, 20), 1) if i >= n - 12 else _healthy_tp(rng, i, n)


def _stall_lat(rng, i, n):
    return round(rng.uniform(60, 400), 2) if i >= n - 3 else _healthy_lat(rng, i, n)


def _sustained_lat(rng, i, n):
    return round(rng.uniform(11, 25), 2) if i >= n - 12 else _healthy_lat(rng, i, n)


def _low_hour_tp(rng, i, n):
    return round(rng.uniform(20, 45), 1) if i >= n - 4 else _healthy_tp(rng, i, n)


SCENARIOS = {
    'healthy': (_healthy_tp, _healthy_lat, '90 MB/s', 2.6),
    'busy afternoon': (_busy_tp, _busy_lat, '22 MB/s', 10.0),
    'throughput collapse, fast commits': (_collapse_tp, _healthy_lat, '11 MB/s', 2.4),
    'commit stall': (_healthy_tp, _stall_lat, '90 MB/s', 150.0),
    'commits over the ceiling for 3 h': (_healthy_tp, _sustained_lat, '90 MB/s', 16.0),
    'one low hour': (_low_hour_tp, _healthy_lat, '30 MB/s', 3.0),
    'stall and collapse together': (_collapse_tp, _stall_lat, '9 MB/s', 200.0),
}


def _outcome(box, now, tp, lat, current_tp, current_ms, lat_ok=True):
    _write(box, now, tp, lat)
    alerts, body, log = box(tp=current_tp, lat=(('%.2f kB/s' % (4000 / current_ms)) if lat_ok else None))
    csv = lambda n: (box.state / n).read_text() if (box.state / n).exists() else ''
    # The run's own timestamp differs by a second or two between the two scripts.
    strip = lambda t: ISO.sub('T', t)
    return {
        'alerts': alerts,
        'body': strip(body),
        'log': log,
        'history_rows': len(csv('diskio_history.csv').splitlines()),
        'latency_rows': len(csv('diskio_latency.csv').splitlines()),
        'degraded': (box.state / 'diskio_degraded').exists(),
    }


@pytest.mark.parametrize('name', sorted(SCENARIOS))
def test_same_readings_same_decisions_as_before(tmp_path, name):
    tp_gen, lat_gen, current_tp, current_ms = SCENARIOS[name]
    tp, lat = _series(random.Random(name), 3, tp_gen, lat_gen)
    now = dt.datetime.now(dt.timezone.utc)
    results = []
    for tag, script in (('before', BEFORE), ('after', AFTER)):
        d = tmp_path / tag
        d.mkdir()
        box = make_box(d, script)
        box.current = float(current_tp.split()[0])
        results.append(_outcome(box, now, tp, lat, current_tp, current_ms))
    before, after = results
    assert after == before
    assert 'Benchmark:' in after['log']                      # the script ran to the end


def test_decisions_match_when_latency_is_not_measured(tmp_path):
    tp, _ = _series(random.Random('nolat'), 3, _low_hour_tp, _healthy_lat)
    now = dt.datetime.now(dt.timezone.utc)
    results = []
    for tag, script in (('before', BEFORE), ('after', AFTER)):
        d = tmp_path / tag
        d.mkdir()
        box = make_box(d, script)
        box.current = 30.0
        results.append(_outcome(box, now, tp, [], '30 MB/s', 1.0, lat_ok=False))
    assert results[0] == results[1]
    assert results[1]['alerts'].count('Disk I/O Degradation') == 1


def test_decisions_match_across_a_gap_in_the_history(tmp_path):
    # The box was off for a day: old readings must not count toward the last hour or day.
    tp = [(15 * i + 1500, 40.0) for i in range(60, 0, -1)] + [(45, 90.0), (30, 95.0), (15, 92.0)]
    lat = [(15 * i + 1500, 14.0) for i in range(60, 0, -1)] + [(15, 2.5)]
    now = dt.datetime.now(dt.timezone.utc)
    results = []
    for tag, script in (('before', BEFORE), ('after', AFTER)):
        d = tmp_path / tag
        d.mkdir()
        box = make_box(d, script)
        box.current = 90.0
        results.append(_outcome(box, now, tp, lat, '90 MB/s', 2.5))
    assert results[0] == results[1]
    assert 'Disk I/O Degradation' not in results[1]['alerts']


def test_a_full_month_of_history_takes_a_handful_of_date_calls(tmp_path):
    # test6 holds 31 days (RETENTION_HOURS=744) = about 2,976 rows in each file.
    tp, lat = _series(random.Random('month'), 31, _healthy_tp, _healthy_lat)
    box = make_box(tmp_path, AFTER, count_date=True)
    box.current = 90.0
    _write(box, dt.datetime.now(dt.timezone.utc), tp, lat)
    started = time.monotonic()
    alerts, _, log = box(tp='90 MB/s', lat='1500 kB/s')
    elapsed = time.monotonic() - started
    calls = len((tmp_path / 'date_calls').read_text().split())
    assert alerts == ''
    assert re.search(r'Benchmark: 90\.0 MB/s \| 1h avg: [\d.]+ MB/s \| 24h avg: [\d.]+ MB/s \(2976 samples\)', log)    # the trim drops the oldest row
    # The old script made over 9,000 (three per row of the throughput history alone).
    print('date calls: %d, one run: %.2f s' % (calls, elapsed))
    assert calls <= 15, 'date started %d times for a 2,976-row history' % calls
    assert elapsed < 30, 'one run took %.1f s' % elapsed
