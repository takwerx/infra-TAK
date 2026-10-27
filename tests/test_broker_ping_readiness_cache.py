"""v10.3.0: broker `ping` must not scan the whole audit log (216 MB on test6 -> 50 s,
over the OS-upgrade preflight's 45 s timeout). It answers from a background cache."""
import importlib.util
import os
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, '..', 'broker', 'takwerx_broker.py')


def _load():
    spec = importlib.util.spec_from_file_location('tb_cache_test', SRC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_ping_does_not_wait_for_the_scan(monkeypatch):
    m = _load()
    gate = threading.Event()
    calls = []

    def slow_scan(now=None):
        calls.append(1)
        gate.wait(5)
        return True, '', '2026-10-01T00:00:00Z'

    monkeypatch.setattr(m, '_audit_clean_window', slow_scan)
    t0 = time.monotonic()
    rd = m._enforce_readiness(fresh=False)
    assert time.monotonic() - t0 < 1.0
    assert rd['clean'] is False and 'checking' in rd['reason']
    # a second ping while the scan runs does not start another one
    m._enforce_readiness(fresh=False)
    gate.set()
    for _ in range(50):
        if m._READINESS_CACHE['val'] is not None:
            break
        time.sleep(0.05)
    assert len(calls) == 1
    rd = m._enforce_readiness(fresh=False)
    assert rd['clean'] is True and rd['clean_since'] == '2026-10-01T00:00:00Z'


def test_ping_dispatch_uses_the_cache():
    src = open(SRC).read()
    assert "'readiness': _enforce_readiness(fresh=False)," in src


def test_enforce_decisions_still_scan_fresh(monkeypatch):
    m = _load()
    monkeypatch.setattr(m, '_audit_clean_window', lambda now=None: (False, 'WOULD-DENY seen', None))
    m._READINESS_CACHE.update(at=time.time(), val=(True, '', 'x'))
    assert m._enforce_readiness()['clean'] is False
