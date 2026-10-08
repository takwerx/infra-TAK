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
"""The broker recycles once a day only when idle (v10.2.8 W3), and the 5.8 pre-flight's
cluster listing is an exact-argv allow (W5b).

T&E 2026-10-08, test6:

    takwerx-broker.service: Service reached runtime time limit. Stopping.   01:10:57
    → a brokered CloudTAK `docker compose build` cut 30 s in → exit 125

`RuntimeMaxSec=24h` stopped the unit whatever it was doing, and a stop signals the whole
cgroup — so the build child died too. The unit no longer has a runtime limit; the broker
waits for a moment with nothing in flight, stops accepting, and exits for systemd to restart.
"""

import importlib.util
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_t',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, secs):
        self.t += secs


class _Srv:
    def __init__(self):
        self.shut = 0

    def shutdown(self):
        self.shut += 1


def _watch(b, inflight_by_time, after=100, poll=5, until=10_000):
    """Drive _recycle_watch with a fake clock; `inflight_by_time(t)` sets the counter."""
    clock, srv, logs = _Clock(), _Srv(), []

    def sleep(secs):
        clock.sleep(secs)
        if clock.t > until:
            raise AssertionError('watcher never recycled')
        b._INFLIGHT = inflight_by_time(clock.t)

    b._INFLIGHT = inflight_by_time(0)
    out = b._recycle_watch(srv, after, 0.0, clock=clock, sleep=sleep, poll=poll,
                           note_every=50, log=logs.append)
    return out, clock.t, srv, logs


def test_never_recycles_before_the_threshold():
    b = _broker()
    out, t, srv, logs = _watch(b, lambda t: 0, after=100)
    assert out == 'idle' and srv.shut == 1
    assert t >= 100
    assert logs and logs[-1].startswith('recycle: idle')


def test_defers_while_a_request_is_in_flight_then_recycles_when_idle():
    b = _broker()
    # a long build runs from t=50 to t=400; the threshold is passed at t=100
    out, t, srv, logs = _watch(b, lambda t: 1 if 50 <= t < 400 else 0, after=100)
    assert out == 'idle' and srv.shut == 1
    assert t >= 400, 'recycled while the build was still running'
    assert any(l.startswith('recycle deferred: 1 request') for l in logs)
    # deferred notes are rate-limited, not one per poll
    assert sum(l.startswith('recycle deferred') for l in logs) < (400 - 100) / 5


def test_drain_waits_for_accepted_work():
    b = _broker()
    clock = _Clock()
    b._INFLIGHT = 2

    def sleep(secs):
        clock.sleep(secs)
        if clock.t >= 3:
            b._INFLIGHT = 0
    assert b._drain(max_secs=60, clock=clock, sleep=sleep) is True
    assert clock.t >= 3


def test_drain_is_bounded():
    b = _broker()
    clock = _Clock()
    b._INFLIGHT = 1
    assert b._drain(max_secs=10, clock=clock, sleep=clock.sleep) is False


def test_handler_counts_every_request_even_on_error():
    b = _broker()
    seen = []

    class H(b._Handler):
        def __init__(self):
            pass

        def _handle(self):
            seen.append(b._inflight())
            raise RuntimeError('boom')
    with pytest.raises(RuntimeError):
        H().handle()
    assert seen == [1] and b._inflight() == 0


def test_recycle_threshold_test_hook(monkeypatch):
    b = _broker()
    monkeypatch.delenv('TAKWERX_BROKER_RECYCLE_SECS', raising=False)
    assert b._recycle_after_secs() == 24 * 3600
    monkeypatch.setenv('TAKWERX_BROKER_RECYCLE_SECS', '300')
    assert b._recycle_after_secs() == 300
    monkeypatch.setenv('TAKWERX_BROKER_RECYCLE_SECS', '1')       # floored: no restart loop
    assert b._recycle_after_secs() == 60
    monkeypatch.setenv('TAKWERX_BROKER_RECYCLE_SECS', 'nope')
    assert b._recycle_after_secs() == 24 * 3600


def test_no_runtime_limit_in_either_broker_unit_writer():
    start = (REPO / 'start.sh').read_text()
    unit = re.search(r'cat > /etc/systemd/system/takwerx-broker\.service << EOF\n(.*?)\nEOF',
                     start, re.S).group(1)
    assert 'RuntimeMaxSec' not in unit
    app = (REPO / 'app.py').read_text(encoding='utf-8')
    body = re.search(r'^def _startup_ensure_broker\(.*?(?=^def )', app, re.S | re.M).group(0)
    unit_lines = re.findall(r"^\s*'([A-Za-z]+=[^']*)\\n'", body, re.M)
    assert 'Restart=always' in unit_lines
    assert not any(l.startswith('RuntimeMaxSec') for l in unit_lines)


def test_pg_lsclusters_is_exact_argv_only():
    b = _broker()
    assert b.check_exec(['pg_lsclusters', '--no-header']) == ['pg_lsclusters', '--no-header']
    for bad in (['pg_lsclusters'], ['pg_lsclusters', '-s'],
                ['pg_lsclusters', '--no-header', '--json'],
                ['pg_lsclusters', '--no-header;id']):
        with pytest.raises(b.Denied):
            b.check_exec(bad)
