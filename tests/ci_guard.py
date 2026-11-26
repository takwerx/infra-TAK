# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Memory guard for the pytest job (ops #1152).

Nov 23, 2026: five PR-check pytest jobs sat until GitHub stopped them (35.2 minutes each: the 30-minute
limit plus the 5-minute wait for a runner that no longer answers) and their logs were never saved. A
runner that runs out of memory freezes like that, and the per-test `--timeout 300` cannot help: it runs
inside the frozen process. The job could not say which test was running.

Every pytest process (the controller and each xdist worker) runs a small watcher thread. When the machine
is almost out of memory, or this process grows past its own cap, the watcher prints which test is running
and who holds the memory, then ends the process at once. The job then fails in seconds, with a log, and
xdist names the test the worker was running ("worker 'gw0' crashed while running ...").

The numbers are fleet constants (rule 5), set for the 16 GB hosted runner. They can be changed for a test
run with INFRATAK_GUARD_MIN_AVAIL_MB / INFRATAK_GUARD_MAX_RSS_MB. On a machine with no /proc/meminfo (macOS)
only the per-process cap applies.
"""
import os
import resource
import subprocess
import sys
import threading
import time

MIN_AVAIL_MB = 1200      # machine-wide: less than this free and the runner is about to freeze
MAX_RSS_MB = 6000        # one pytest process; a normal worker stays well under this
INTERVAL_S = 1.0
EXIT_CODE = 86

_state = {'where': 'startup', 'since': time.time(), 'config': None}


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def check(avail_mb, rss_mb, min_avail_mb, max_rss_mb):
    """Return the reason to stop, or None. avail_mb may be None (no /proc/meminfo)."""
    if avail_mb is not None and avail_mb < min_avail_mb:
        return 'machine memory nearly gone: %d MB available, limit %d MB' % (avail_mb, min_avail_mb)
    if rss_mb > max_rss_mb:
        return 'this process holds %d MB, limit %d MB' % (rss_mb, max_rss_mb)
    return None


def available_mb():
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                if line.startswith('MemAvailable:'):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def rss_mb():
    try:
        with open('/proc/self/statm') as f:
            return int(f.read().split()[1]) * resource.getpagesize() // 1048576
    except (OSError, ValueError, IndexError):
        pass
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # peak, not current: only used off Linux
    return peak // 1048576 if sys.platform == 'darwin' else peak // 1024


def _top_processes():
    try:
        out = subprocess.run(['ps', '-eo', 'pid,rss,etime,args', '--sort=-rss'], capture_output=True,
                             text=True, timeout=5).stdout
        return '\n'.join(l[:200] for l in out.splitlines()[:9])
    except Exception as exc:  # the report must never fail
        return 'ps failed: %s' % exc


def _release_capture():
    # pytest captures stderr while a test runs; anything printed now would be lost when we exit.
    try:
        capman = _state['config'].pluginmanager.getplugin('capturemanager')
        if capman is not None:
            capman.suspend_global_capture(in_=False)
    except Exception:  # the report must never fail
        pass


def report(reason, stream=None):
    _release_capture()
    stream = stream or sys.stderr
    where = _state['where']
    lines = [
        '',
        '!!! MEMORY GUARD (ops #1152): %s' % reason,
        '!!! pytest process %d is running: %s (for %.0f s)' % (os.getpid(), where, time.time() - _state['since']),
        '!!! Biggest processes by memory:',
        _top_processes(),
        '!!! Ending this process now so the job fails here, with this log, and not after 35 minutes.',
        '',
    ]
    stream.write('\n'.join(lines))
    stream.flush()


def _watch(min_avail_mb, max_rss_mb, die):
    while True:
        time.sleep(INTERVAL_S)
        reason = check(available_mb(), rss_mb(), min_avail_mb, max_rss_mb)
        if reason:
            report(reason)
            die(EXIT_CODE)
            return


def start(die=os._exit):
    t = threading.Thread(target=_watch, name='ci-memory-guard', daemon=True, args=(
        _env_int('INFRATAK_GUARD_MIN_AVAIL_MB', MIN_AVAIL_MB), _env_int('INFRATAK_GUARD_MAX_RSS_MB', MAX_RSS_MB), die))
    t.start()
    return t


# pytest hooks (conftest.py re-exports these)
def pytest_configure(config):
    _state['config'] = config
    if os.environ.get('INFRATAK_GUARD_OFF') != '1':
        start()


def pytest_collectstart(collector):
    _state.update(where='collecting %s' % getattr(collector, 'nodeid', '?'), since=time.time())


def pytest_runtest_logstart(nodeid, location):
    _state.update(where=nodeid, since=time.time())


def pytest_runtest_logfinish(nodeid, location):
    _state.update(where='between tests (after %s)' % nodeid, since=time.time())
