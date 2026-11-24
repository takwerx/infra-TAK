# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""v10.4.3 W6/W7: the LDAP SA watchdog reads a failed bind as password drift only when
Authentik's core is ready AND the outpost is running, healthy and up >= 60 s.
_authentik_core_ready(): /-/health/ready/ == 200; remote / no local Authentik -> True."""
import re
import subprocess
import types

import pytest

from test_tak_ldap_recycle import APP

NOW = 1_800_000_000.0


def _ns(ready_status=200, inspect='true 2027-01-15T08:00:00Z healthy', local=True):
    import datetime
    seen = []

    class _Resp:
        def __init__(self, st):
            self.status = st

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def urlopen(url, timeout=0):
        seen.append(url)
        if ready_status is None:
            raise OSError('connection refused')
        return _Resp(ready_status)

    ns = {
        'os': types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: local, expanduser=lambda p: p)),
        'time': types.SimpleNamespace(time=lambda: NOW, sleep=lambda s: None),
        'urllib': types.SimpleNamespace(request=types.SimpleNamespace(urlopen=urlopen)),
        'subprocess': types.SimpleNamespace(run=lambda cmd, **k: subprocess.CompletedProcess(cmd, 0, stdout=inspect + '\n')),
        '_sudo_wrap': lambda c: list(c),
        'datetime': datetime.datetime, 're': re,
    }
    for name in ('_epoch_from_rfc3339',):
        exec(re.search(r'^def %s\(.*?(?=^def |^# |^_[A-Z_]+ = |\Z)' % name, APP, re.S | re.M).group(0), ns)
    src = APP[APP.index('_AK_LOCAL_READY_URL = '):APP.index('    return True\n', APP.index('def _ldap_drift_gate_ok')) + len('    return True\n')]
    exec(compile(src, 'app.py[W6]', 'exec'), ns)
    return ns, seen


def _started(ago):
    import datetime
    return datetime.datetime.utcfromtimestamp(NOW - ago).strftime('%Y-%m-%dT%H:%M:%S.123456789Z')


def test_core_ready_uses_the_ready_endpoint():
    ns, seen = _ns()
    assert ns['_authentik_core_ready'](0) is True
    assert seen == ['http://127.0.0.1:9090/-/health/ready/']


@pytest.mark.parametrize('st', [503, None])
def test_core_not_ready(st):
    ns, _ = _ns(ready_status=st)
    assert ns['_authentik_core_ready'](0) is False


def test_remote_or_absent_authentik_is_ready():
    ns, seen = _ns(ready_status=None, local=False)
    assert ns['_authentik_core_ready'](30) is True and seen == []


def test_gate_open_when_core_ready_and_outpost_healthy_and_settled(capsys):
    ns, _ = _ns(inspect=f'true {_started(600)} healthy')
    assert ns['_ldap_drift_gate_ok']() is True
    assert 'not a password drift' not in capsys.readouterr().out


@pytest.mark.parametrize('ready,inspect,why', [
    (503, f'true {_started(600)} healthy', 'core not ready'),
    (200, 'false 0001-01-01T00:00:00Z', 'not running'),
    (200, f'true {_started(600)} starting', 'outpost starting'),
    (200, f'true {_started(600)} unhealthy', 'outpost unhealthy'),
    (200, f'true {_started(20)} healthy', 'LDAP outpost up only '),
    (200, '', 'not running'),
])
def test_gate_closed_is_not_drift(ready, inspect, why, capsys):
    ns, _ = _ns(ready_status=ready, inspect=inspect)
    assert ns['_ldap_drift_gate_ok']() is False
    out = capsys.readouterr().out
    assert 'LDAP not ready — not a password drift' in out and why in out
