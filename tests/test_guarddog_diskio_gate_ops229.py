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
"""Guard Dog disk I/O alert no longer fires on one busy hour of throughput (ops #229).

Field (2026-10-24/25): `⚠ Disk I/O Degradation` on test6, test8 and test12, each
tripped only by the last-hour throughput average (45.8 / 35.1 / 45.5 MB/s) while
the box ran its own heavy I/O (a CloudTAK --no-cache build, a console deploy, a
startup retention DELETE). A customer VPS gets the same email, with "consider
requesting a node migration", every time it updates CloudTAK.

Second bug found on the way: the 4 KB latency probe parsed dd's rate with
`[KMGT]?B/s`, but GNU dd prints rates under 1 MB/s as `kB/s`. Every probe slower
than ~3.9 ms/commit was dropped as "probe failed", so the series held only fast
readings and the 10 ms latency gate could never trip. In test12's alert hour all
four probes were dropped that way.

The REAL script runs here with its absolute paths pointed into a sandbox, dd and
logger stubbed, and a small `grep -oP` shim (macOS grep has no -P).
"""

import datetime as dt
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-diskio-watch.sh').read_text()

GREP_SHIM = '''#!%s
import os, re, sys
a = sys.argv[1:]
if a[:1] != ['-oP']:
    os.execv('/usr/bin/grep', ['grep'] + a)
hits = re.findall(a[1], sys.stdin.read())
sys.stdout.write(''.join(h + '\\n' for h in hits))
sys.exit(0 if hits else 1)
''' % sys.executable

DD = '#!/bin/sh\ncase "$*" in *bs=4k*) f=%(lat)s ;; *) f=%(tp)s ;; esac\ncat "$f" >&2\n'

# Real readings, oldest first, ending with the run that sent the email (MB/s, 15 min
# apart), the box's 24h average at that moment, and the 4 KB latency Guard Dog
# recorded in that hour as (minutes before the run, ms/commit).
REAL = {
    'test6':  ([49.3, 72.3, 73.6, 52.1, 126.0, 97.8, 66.6, 104.0, 88.3, 26.2, 31.9, 36.7],
               79.3, [(45, 2.79), (15, 2.17)]),
    'test8':  ([214.0, 50.9, 59.3, 80.2, 19.8, 116.0, 63.6, 92.6, 62.4, 18.9, 36.6, 22.5],
               82.1, [(45, 2.44)]),
    'test12': ([71.8, 32.2, 106.0, 56.6, 92.3, 84.3, 133.0, 96.1, 53.4, 62.8, 39.1, 26.9],
               78.1, []),
}


def _ts(minutes_ago):
    t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes_ago, seconds=30)
    return t.strftime('%Y-%m-%dT%H:%M:%SZ')


def _dd_line(mb_s, size='10485760 bytes (10 MB, 10 MiB)'):
    return '%s copied, 0.3 s, %s\n' % (size, mb_s)


@pytest.fixture
def box(tmp_path):
    gd, state, stubs = tmp_path / 'gd', tmp_path / 'state', tmp_path / 'bin'
    for d in (gd, state, stubs):
        d.mkdir()
    (gd / 'server_identifier').write_text('box\n')
    alert = gd / 'send-alert-email.sh'
    alert.write_text('#!/bin/sh\necho "$1" >> %s\ncat >> %s\n'
                     % (tmp_path / 'alerts', tmp_path / 'bodies'))
    (stubs / 'grep').write_text(GREP_SHIM)
    (stubs / 'dd').write_text(DD % {'lat': tmp_path / 'dd_lat', 'tp': tmp_path / 'dd_tp'})
    (stubs / 'logger').write_text('#!/bin/sh\nshift 2\necho "$*" >> %s\n' % (tmp_path / 'log'))
    for f in list(stubs.iterdir()) + [alert]:
        f.chmod(0o755)

    script = (WATCH.replace('/opt/tak-guarddog/', str(gd) + '/')
                   .replace('/var/lib/takguard', str(state))
                   .replace('/tmp/', str(tmp_path) + '/'))
    assert '/var/lib/takguard' not in script and '/opt/tak-guarddog' not in script
    sp = tmp_path / 'watch.sh'
    sp.write_text(script)

    def seed(earlier, avg24=None, lat=()):
        """earlier: readings before this run, oldest first, 15 min apart. Pads the
        rest of the 24h window so its average comes out at avg24."""
        rows = list(earlier)
        if avg24 is not None:
            pad = 96 - len(rows) - 1
            rows = [round((avg24 * 96 - sum(rows) - run.current) / pad, 1)] * pad + rows
        n = len(rows)
        (state / 'diskio_history.csv').write_text(
            'timestamp,mb_per_sec\n' + ''.join(
                '%s,%s\n' % (_ts(15 * (n - i)), v) for i, v in enumerate(rows)))
        if lat:
            (state / 'diskio_latency.csv').write_text(
                'timestamp,kb_per_sec,ms_per_commit\n' + ''.join(
                    '%s,%.1f,%.2f\n' % (_ts(m), 4000 / ms, ms) for m, ms in lat))

    def run(tp='100 MB/s', lat='2.6 MB/s'):
        (tmp_path / 'dd_tp').write_text(_dd_line(tp))
        (tmp_path / 'dd_lat').write_text(
            'dd: error writing\n' if lat is None else _dd_line(lat, '1048576 bytes (1.0 MB, 1.0 MiB)'))
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, timeout=120,
                           env={'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs})
        assert r.returncode == 0, r.stderr
        read = lambda n: (tmp_path / n).read_text() if (tmp_path / n).exists() else ''
        return read('alerts'), read('bodies'), read('log')

    run.current = 0
    run.seed, run.state = seed, state
    return run


@pytest.mark.parametrize('name', sorted(REAL))
def test_real_false_positives_stay_quiet(box, name):
    readings, avg24, lat = REAL[name]
    box.current = readings[-1]
    box.seed(readings[:-1], avg24, lat)
    alerts, _, log = box(tp='%s MB/s' % readings[-1])
    hour = sum(readings[-4:]) / 4
    assert hour < 50 and '1h avg: %.1f MB/s' % hour in log          # what tripped the old gate
    assert alerts == ''


def test_kb_per_sec_probe_is_recorded_not_dropped(box):
    box.seed([100.0] * 11, lat=[(45, 3.0), (30, 3.1), (15, 2.9)])
    alerts, _, log = box(lat='271 kB/s')
    assert 'Latency probe failed' not in log
    last = (box.state / 'diskio_latency.csv').read_text().splitlines()[-1]
    assert last.endswith(',271.0,14.76')
    assert alerts == ''                                  # one slow probe: 1h avg 5.94 ms


def test_slow_commits_alert(box):
    box.seed([100.0] * 11, lat=[(45, 14.0), (30, 16.0), (15, 15.0)])
    alerts, body, _ = box(lat='271 kB/s')
    assert alerts.count('Disk I/O Degradation') == 1
    assert 'exceeds 10 ms ceiling' in body and 'Last-hour average (' not in body


def test_slow_commits_and_low_hour_give_both_reasons(box):
    box.seed([100.0] * 8 + [30.0] * 3, lat=[(45, 14.0), (30, 16.0), (15, 15.0)])
    alerts, body, _ = box(tp='30 MB/s', lat='271 kB/s')
    assert alerts.count('Disk I/O Degradation') == 1
    assert 'Last-hour average (30.0 MB/s) is below 50 MB/s' in body
    assert 'exceeds 10 ms ceiling' in body


def test_three_low_hours_alert_with_fast_commits(box):
    box.seed([42.0, 38.0, 45.0, 31.0, 47.0, 36.0, 44.0, 40.0, 33.0, 46.0, 39.0],
             lat=[(45, 2.0), (30, 2.2), (15, 2.1)])
    alerts, body, _ = box(tp='41 MB/s')
    assert alerts.count('Disk I/O Degradation') == 1
    assert 'Every reading for the last 3 hours (best 47.0 MB/s) is below 50 MB/s' in body
    assert 'Last 3 h (best):   47.0 MB/s' in body


def test_one_good_reading_in_three_hours_keeps_quiet(box):
    box.seed([42.0, 38.0, 45.0, 31.0, 61.0, 36.0, 44.0, 40.0, 33.0, 46.0, 39.0],
             lat=[(45, 2.0), (30, 2.2), (15, 2.1)])
    alerts, _, _ = box(tp='41 MB/s')
    assert alerts == ''


def test_unmeasured_latency_keeps_the_one_hour_gate(box):
    box.seed([100.0] * 8 + [30.0] * 3)                   # no latency series, probe fails too
    alerts, body, log = box(tp='30 MB/s', lat=None)
    assert 'Latency probe failed' in log
    assert alerts.count('Disk I/O Degradation') == 1
    assert 'Last-hour average (30.0 MB/s) is below 50 MB/s' in body


def test_stale_readings_are_not_a_sustained_stretch(box):
    # Twelve low readings, but the box was off for most of a day in between.
    (box.state / 'diskio_history.csv').write_text('timestamp,mb_per_sec\n' + ''.join(
        '%s,40.0\n' % _ts(15 * i + 1200) for i in range(11, 0, -1)))
    (box.state / 'diskio_latency.csv').write_text(
        'timestamp,kb_per_sec,ms_per_commit\n%s,1600.0,2.50\n' % _ts(15))
    alerts, _, _ = box(tp='40 MB/s')
    assert alerts == ''


def test_debounce_still_holds_six_hours(box):
    box.seed([42.0] * 11, lat=[(45, 2.0), (30, 2.2), (15, 2.1)])
    assert box(tp='41 MB/s')[0].count('Disk I/O Degradation') == 1
    assert box(tp='41 MB/s')[0].count('Disk I/O Degradation') == 1      # no second email
