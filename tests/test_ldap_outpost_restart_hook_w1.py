# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""v10.4.3 W1 (#549): every console path that (re)starts the LDAP outpost runs the TAK check.

akres E3c: an outpost recreate under ~2 TAK auth/s left TAK giving EVERY user no groups until
TAK restarted, 3 times in 5. The heal used to wait for the 10-min monitor tick. Now:
  * the three Authentik compose wrappers put any `up|restart|start|create` under
    _ldap_outpost_restart_watch() (local) or call _after_ldap_outpost_restart() (remote);
  * every raw call that can start the outpost is under the watch or followed by the hook —
    the whole-file guard below fails on a new one that is not;
  * the watch fires only when the outpost's StartedAt moved;
  * the hook's worker is debounced (a deploy recreates the outpost several times in a row)
    and runs again if the outpost restarted while it worked.
"""
import ast
import re
import threading
import time
import types

import pytest

from test_authentik_compose_lock_paths import APP, FUNCS, TREE, console  # noqa: F401

LINES = APP.splitlines(True)


def _seg(node):
    a, b = node.lineno - 1, node.end_lineno - 1
    if a == b:
        return LINES[a].encode()[node.col_offset:node.end_col_offset].decode()
    return (LINES[a].encode()[node.col_offset:].decode() + ''.join(LINES[a + 1:b])
            + LINES[b].encode()[:node.end_col_offset].decode())


# ── the wrappers ─────────────────────────────────────────────────────────────

def test_run_locked_puts_a_start_under_the_watch_inside_the_lock(console):
    console.ns['_ak_compose_run_locked'](['up', '-d', '--force-recreate', 'ldap'], 'h1', console.plog, '/ak')
    assert console.hooks == [('watch', 'h1', True)]


@pytest.mark.parametrize('args', [['ps'], ['logs', 'ldap'], ['stop', 'ldap'], ['config']])
def test_run_locked_leaves_non_start_commands_alone(console, args):
    console.ns['_ak_compose_run_locked'](args, 'h', console.plog, '/ak')
    assert console.hooks == []


def test_subprocess_wrapper_puts_a_start_under_the_watch(console):
    console.ns['_ak_compose_subprocess'](['docker', 'compose', 'restart', 'ldap'], 'h2', cwd='/ak')
    console.ns['_ak_compose_subprocess'](['docker', 'compose', 'ps'], 'h3', cwd='/ak')
    assert console.hooks == [('watch', 'h2', True)]


def test_module_compose_local_watch_and_remote_hook(console):
    mc = console.ns['_ak_module_compose']
    mc({'target_mode': 'local'}, 'cd ~/authentik && docker compose up -d --force-recreate ldap', 'loc')
    mc({'target_mode': 'remote'}, 'cd ~/authentik && docker compose up -d --force-recreate ldap', 'rem')
    mc({'target_mode': 'remote'}, 'cd ~/authentik && docker compose up -d server worker', 'rem2')
    mc({'target_mode': 'remote'}, 'cd ~/authentik && docker compose logs ldap', 'rem3')
    assert console.hooks == [('watch', 'loc', True), ('hook', 'rem (remote Authentik)', None)]


# ── whole-file guard: no outpost start without the hook ──────────────────────

_WRAPPERS = {'_ak_compose_subprocess', '_ak_compose_run_locked', '_ak_module_compose'}
_RUNNERS = {'run', '_run_priv_chain', '_module_run', 'Popen', 'check_output', 'call', '_priv_pipe'}
_START = re.compile(r"""'compose'\s*,\s*(?:'-[^']*'\s*,\s*)*'(?:up|restart|start|create)'"""
                    r"""|docker compose (?:up|restart|start|create)\b""")
_AK_CWD = re.compile(r"\bak_dir\b|~/authentik|'authentik'")
# Only these services named → cannot (re)start the outpost (`up` without --no-deps does not
# restart a running service it does not name; ldap is nobody's dependency).
_NOT_LDAP = {'server', 'worker', 'postgresql', 'pgbouncer', 'redis'}


def _name(f):
    return f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else '')


def _may_start_outpost(seg):
    if not _START.search(seg):
        return False
    if 'ldap' in seg:
        return True
    if not _AK_CWD.search(seg):
        return False
    # the service words after the start verb, in every compose command of the call
    for m in re.finditer(r"(?:'(?:up|restart|start|create)'|(?:up|restart|start|create)\b)([^\]\n]*)", seg):
        words = set(re.findall(r"'([a-z][a-z0-9_-]*)'|\b([a-z][a-z0-9_-]*)\b", m.group(1)))
        svcs = {a or b for a, b in words} - {'d', 'no', 'deps', 'force', 'recreate', 'remove', 'orphans',
                                              'timeout', 'text', 'true', 'cwd', 'capture_output'}
        if not (svcs & _NOT_LDAP):
            return True
    return False


def _sites():
    parent = {}
    for n in ast.walk(TREE):
        for c in ast.iter_child_nodes(n):
            parent[c] = n
    out = []
    for n in ast.walk(TREE):
        if not (isinstance(n, ast.Call) and _name(n.func) in _RUNNERS):
            continue
        seg = _seg(n)
        if not _may_start_outpost(seg):
            continue
        p, how, fn = n, None, None
        while p in parent:
            p = parent[p]
            if isinstance(p, ast.Call) and _name(p.func) in _WRAPPERS:
                how = 'wrapper'
                break
            if isinstance(p, ast.With) and any('_ldap_outpost_restart_watch' in _seg(i.context_expr)
                                               for i in p.items):
                how = 'watch'
                break
            if isinstance(p, ast.FunctionDef):
                fn = p
                break
        while fn is None and p in parent:
            p = parent[p]
            if isinstance(p, ast.FunctionDef):
                fn = p
        if how is None and fn is not None:
            if fn.name in _WRAPPERS:
                how = 'is-wrapper'
            else:
                after = ''.join(LINES[n.end_lineno:fn.end_lineno])
                if '_after_ldap_outpost_restart(' in after:
                    how = 'hook-after'
        out.append((n.lineno, fn.name if fn else '?', how, seg))
    return out


def test_every_outpost_start_runs_the_w1_hook():
    sites = _sites()
    assert len(sites) >= 15, 'the scan stopped finding compose start sites — fix the scan'
    bad = [(ln, fn, seg.replace('\n', ' ')[:140]) for ln, fn, how, seg in sites if how is None]
    assert not bad, ('LDAP outpost (re)start without the W1 hook — wrap it in '
                     '_ldap_outpost_restart_watch(...) or use an Authentik compose wrapper: %s' % bad)


def test_remote_fix_ldap_token_script_route_runs_the_hook():
    # The remote script (`docker compose … up -d ldap` inside a string) runs on the remote
    # host through _module_run; the route calls the hook after it reports OK.
    src = _seg(FUNCS['authentik_fix_ldap_token'])
    i = src.index("python3 /tmp/fix_ldap_token.py")
    assert src.index("_after_ldap_outpost_restart(", i) < src.index("'success': True", i)


# ── the watch and the debounced worker ───────────────────────────────────────

def _w1_ns(starts, recycle=None):
    want = ('_after_ldap_outpost_restart', '_ldap_outpost_hook_worker', '_ldap_outpost_restart_watch')
    consts = ('_LDAP_OUTPOST_HOOK_DEBOUNCE_S', '_ldap_outpost_hook', '_ldap_outpost_hook_lock')
    parts = []
    for node in TREE.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', None) in consts:
            parts.append(_seg(node))
        if isinstance(node, ast.FunctionDef) and node.name in want:
            parts.append(('@contextlib.contextmanager\n' if node.decorator_list else '') + _seg(node))
    assert len(parts) == 6
    import contextlib
    calls = types.SimpleNamespace(requests=[], recycles=[])
    it = iter(starts)
    ns = {'threading': threading, 'time': time, 'contextlib': contextlib,
          '_docker_started_epoch': lambda c: next(it),
          '_tak_ldap_recycle_request': lambda r: calls.requests.append(r),
          '_tak_recycle_after_ldap_outage': recycle or (lambda plog, trig, check_outpost=True: calls.recycles.append(trig))}
    exec(compile('\n\n'.join(parts), 'app.py[W1]', 'exec'), ns)
    ns['_LDAP_OUTPOST_HOOK_DEBOUNCE_S'] = 0.05
    return ns, calls


def _wait_idle(ns, timeout=5):
    t0 = time.time()
    while time.time() - t0 < timeout:
        with ns['_ldap_outpost_hook_lock']:
            if not ns['_ldap_outpost_hook']['running']:
                return
        time.sleep(0.01)
    raise AssertionError('hook worker did not finish')


@pytest.mark.parametrize('before,after,fires', [
    (1000.0, 1000.0, False),     # outpost not restarted (e.g. `up -d` with nothing changed)
    (1000.0, 1060.0, True),      # recreated
    (None, 1060.0, True),        # came up from not running
    (1000.0, None, False),       # left stopped: the later start fires it
])
def test_watch_fires_only_when_the_outpost_started(before, after, fires):
    ns, calls = _w1_ns([before, after])
    with ns['_ldap_outpost_restart_watch']('t', lambda m: None):
        pass
    _wait_idle(ns)
    assert bool(calls.requests) is fires
    assert calls.recycles == (['LDAP outpost restart'] if fires else [])


def test_worker_is_debounced_and_reruns_for_a_restart_during_its_check():
    gate = threading.Event()
    seen = []

    def recycle(plog, trig, check_outpost=True):
        seen.append(time.time())
        if len(seen) == 1:
            ns['_after_ldap_outpost_restart']('during', lambda m: None)   # outpost restarts again
            gate.set()

    ns, calls = _w1_ns([], recycle=recycle)
    for i in range(3):                       # a deploy: three recreates in a row
        ns['_after_ldap_outpost_restart'](f'r{i}', lambda m: None)
        time.sleep(0.01)
    assert gate.wait(3)
    _wait_idle(ns)
    assert len(seen) == 2                    # one for the burst, one for the restart during it
    assert len(calls.requests) == 4          # every restart is persisted


# ── the poller: restarts the console did not make (Guard Dog, docker, OOM, by hand) ──

class _Stop(Exception):
    pass


def _run_poller(starts, gds, seen_start=None):
    parts = [_seg(n) for n in TREE.body
             if isinstance(n, ast.FunctionDef) and n.name == '_ldap_outpost_restart_poller']
    assert len(parts) == 1
    fired = []
    st = iter(starts)
    gi = iter(gds)
    ticks = {'n': 0}

    def sleep(s):
        ticks['n'] += 1
        if ticks['n'] >= len(starts):
            raise _Stop

    ns = {'time': types.SimpleNamespace(sleep=sleep), '_LDAP_OUTPOST_POLL_S': 30,
          '_ldap_outpost_hook': {'last': 0.0, 'running': False, 'seen_start': seen_start, 'seen_gd': None},
          '_ldap_outpost_hook_lock': threading.Lock(),
          '_docker_started_epoch': lambda c: next(st),
          '_guarddog_authentik_restart_epoch': lambda: next(gi),
          '_after_ldap_outpost_restart': lambda r, plog=None: fired.append(r)}
    exec(compile(parts[0], 'app.py[poller]', 'exec'), ns)
    with pytest.raises(_Stop):
        ns['_ldap_outpost_restart_poller']()
    return fired


def test_poller_first_look_only_records():
    assert _run_poller([1000.0, 1000.0, 1000.0], [500.0, 500.0, 500.0]) == []


def test_poller_fires_once_for_an_outpost_restart_it_did_not_make():
    fired = _run_poller([1000.0, 1000.0, 1300.0, 1300.0], [500.0] * 4)
    assert len(fired) == 1 and 'outside the console' in fired[0]


def test_poller_fires_for_a_guard_dog_server_worker_restart():
    fired = _run_poller([1000.0, 1000.0, 1000.0], [500.0, 500.0, 900.0])
    assert fired == ['Guard Dog restarted Authentik']


def test_poller_does_not_refire_for_a_restart_the_watch_already_hooked():
    # the watch set seen_start to the new StartedAt before the poller looked
    assert _run_poller([1000.0, 1300.0, 1300.0], [None] * 3, seen_start=1300.0) == []


def test_poller_ignores_remote_or_absent_outpost():
    assert _run_poller([None, None, None], [None, None, None]) == []
