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
"""detect_modules() cache (v10.2.2 W2).

app.py cannot be imported in a test, so the cache block is cut out of app.py
by its section markers and executed against stubs — the code under test is the
shipped text, not a copy. Static guards cover what has to stay true in the rest
of app.py: detect never deletes anything, and callers that ACT on the answer
keep asking for fresh data.
"""

import pathlib
import re
import threading
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
START = '# v10.2.2 W2: module-status cache'
END = '# Height of the fixed identification bar.'


def _block():
    i = APP.index(START)
    i = APP.rindex('\n# ---', 0, i)          # include the rule line above the title
    return APP[i:APP.index(END, i)]


class Harness:
    def __init__(self):
        self.clock = [1000.0]
        self.calls = 0
        self.result = {'caddy': {'installed': True, 'running': True}}
        self.gate = None            # threading.Event: block computes until set
        self.entered = threading.Event()
        self.fail = False
        self.registry_running = []
        self.method = 'GET'
        ns = {
            '__name__': 'app_cache_under_test',
            'threading': threading,
            'time': types.SimpleNamespace(monotonic=lambda: self.clock[0]),
            'app': types.SimpleNamespace(after_request=lambda f: f),
            'request': self._Request(self),
            'mod_registry': types.SimpleNamespace(running_jobs=lambda: list(self.registry_running)),
            '_detect_modules_uncached': self._compute,
        }
        exec(compile(_block(), 'app.py:W2-cache', 'exec'), ns)
        self.ns = ns

    class _Request:
        def __init__(self, h):
            self._h = h

        @property
        def method(self):
            return self._h.method

    def _compute(self):
        self.calls += 1
        self.entered.set()
        if self.gate is not None:
            assert self.gate.wait(10)
        if self.fail:
            raise RuntimeError('probe exploded')
        return {k: dict(v) for k, v in self.result.items()}

    def __getattr__(self, name):
        return self.ns[name]

    def wait_refresh(self):
        for _ in range(500):
            if not self.ns['_MODULES_CACHE']['refreshing']:
                return
            time.sleep(0.01)
        raise AssertionError('background refresh never finished')


@pytest.fixture
def h():
    return Harness()


def test_first_call_computes_then_fresh_calls_hit_the_cache(h):
    assert h.detect_modules() == h.result
    assert h.calls == 1
    h.clock[0] += 14
    h.detect_modules()
    h.detect_modules()
    assert h.calls == 1


def test_callers_get_private_copies(h):
    for _ in range(2):                    # the computing call, then a cache hit
        a = h.detect_modules()
        a['caddy']['running'] = False
        a['bogus'] = {}
    assert h.detect_modules() == {'caddy': {'installed': True, 'running': True}}
    assert h.calls == 1


def test_stale_serves_old_data_once_and_refreshes_in_background_single_flight(h):
    h.detect_modules()
    h.result = {'caddy': {'installed': True, 'running': False}}
    h.clock[0] += 16
    h.gate = threading.Event()
    got = [h.detect_modules() for _ in range(5)]          # all stale; one refresh
    assert all(g['caddy']['running'] is True for g in got)
    assert h.entered.wait(5)
    assert h.calls == 2
    h.gate.set()
    h.wait_refresh()
    assert h.detect_modules()['caddy']['running'] is False
    assert h.calls == 2


def test_data_older_than_max_stale_is_never_served(h):
    """GH #214: the first page after a quiet spell showed a boot-time "Stopped" 34 min later."""
    h.detect_modules()
    h.result = {'takportal': {'installed': True, 'running': True}}
    h.clock[0] += h._MODULES_CACHE_MAX_STALE_S
    assert h.detect_modules()['takportal']['running'] is True     # computed now, not served stale
    assert h.calls == 2
    assert h._MODULES_CACHE['refreshing'] == 0.0                   # no background refresh needed
    assert h._MODULES_CACHE_MAX_STALE_S > h._MODULES_CACHE_REFRESH_STUCK_S + h._MODULES_CACHE_FRESH_S


def test_invalidate_forces_a_synchronous_compute(h):
    h.detect_modules()
    h.result = {'caddy': {'installed': False, 'running': False}}
    h._invalidate_modules_cache()
    assert h.detect_modules()['caddy']['installed'] is False
    assert h.calls == 2


def test_refresh_in_flight_across_an_invalidate_does_not_store(h):
    # Node-RED Stop lands while a refresh that already probed "running" is finishing:
    # that refresh must not put "running" back over the invalidation.
    h.detect_modules()
    h.clock[0] += 16
    h.gate = threading.Event()
    h.detect_modules()                       # starts the background refresh
    assert h.entered.wait(5)
    h._invalidate_modules_cache()            # the POST /control completes now
    h.gate.set()                             # the old refresh finishes afterwards
    h.wait_refresh()
    assert h._MODULES_CACHE['data'] is None
    h.gate = None
    h.result = {'caddy': {'installed': True, 'running': False}}
    assert h.detect_modules()['caddy']['running'] is False


def test_a_job_starting_or_finishing_invalidates(h):
    h.detect_modules()
    h.ns['nodered_deploy_status'] = {'running': True}
    h.detect_modules()
    assert h.calls == 2                       # job started
    h.detect_modules()
    assert h.calls == 2                       # same job set: cached
    h.ns['nodered_deploy_status']['running'] = False
    h.result = {'nodered': {'installed': True, 'running': True}}
    assert 'nodered' in h.detect_modules()   # job finished: recomputed, no lag
    assert h.calls == 3


def test_registry_jobs_count_too(h):
    h.detect_modules()
    h.registry_running = ['tvr']
    h.detect_modules()
    h.registry_running = []
    h.detect_modules()
    assert h.calls == 3


def test_status_dicts_without_running_and_other_names_are_ignored(h):
    h.ns['_offbox_status'] = {'last_ship_ts': None}
    h.ns['some_cache'] = {'running': True}            # not *_status
    h.detect_modules()
    h.detect_modules()
    assert h.calls == 1
    assert h._modules_running_jobs() == frozenset()


def test_fresh_always_probes_and_warms_the_cache(h):
    h.detect_modules()
    h.result = {'caddy': {'installed': False, 'running': False}}
    assert h.detect_modules(fresh=True)['caddy']['installed'] is False
    assert h.calls == 2
    assert h.detect_modules()['caddy']['installed'] is False
    assert h.calls == 2


def test_a_hung_refresh_does_not_freeze_the_cache_forever(h):
    h.detect_modules()
    h.clock[0] += 16
    h._MODULES_CACHE['refreshing'] = h.clock[0]       # pretend one is running
    h.detect_modules()
    assert h.calls == 1
    h.clock[0] += 121
    h.detect_modules()
    h.wait_refresh()
    assert h.calls == 2


def test_failed_refresh_keeps_serving_and_retries(h):
    h.detect_modules()
    h.clock[0] += 16
    h.fail = True
    assert h.detect_modules() == h.result
    h.wait_refresh()
    h.fail = False
    h.detect_modules()                                 # still stale -> retries
    h.wait_refresh()
    assert h.calls == 3


def test_synchronous_compute_errors_propagate_like_before(h):
    h.fail = True
    with pytest.raises(RuntimeError):
        h.detect_modules()


@pytest.mark.parametrize('method,invalidates', [('POST', True), ('PUT', True), ('PATCH', True),
                                                ('DELETE', True), ('GET', False), ('HEAD', False)])
def test_state_changing_requests_invalidate(h, method, invalidates):
    h.detect_modules()
    h.method = method
    resp = object()
    assert h._modules_cache_after_mutation(resp) is resp
    assert (h._MODULES_CACHE['data'] is None) is invalidates


# ---------------------------------------------------------------------------
# static guards over the rest of app.py / modules
# ---------------------------------------------------------------------------
def _func(src, name):
    m = re.search(rf'^def {name}\(.*?(?=^(?:def |@app\.|# ----)|\Z)', src, re.S | re.M)
    assert m, name
    return m.group(0)


def test_detect_never_deletes_anything():
    body = _func(APP, '_detect_modules_uncached')
    for verb in ("'rm'", "'daemon-reload'", 'os.remove', 'shutil.rmtree', 'unlink('):
        assert verb not in body, verb
    cleanup = _func(APP, '_cleanup_caddy_leftovers')
    assert "'rm', '-f', path" in cleanup and "'rm', '-rf', '/etc/caddy'" in cleanup


def test_cleanup_runs_at_startup_and_after_uninstall_all():
    assert '_cleanup_caddy_leftovers()' in _func(APP, '_startup_migrations')
    assert '_cleanup_caddy_leftovers()' in _func(APP, 'run_full_uninstall')


@pytest.mark.parametrize('fn', [
    'generate_caddyfile', 'caddy_update_domain', '_heal_authentik_proxy_chain_all_services',
    'mediamtx_deploy_api', 'run_mediamtx_deploy', '_sync_webadmin_after_authentik_reconfigure',
    'takserver_update_config', '_deploy_takserver_container', 'run_takserver_deploy',
    '_fedhub_run_remote_package_install', '_startup_migrations'])
def test_decision_callers_ask_for_fresh_data(fn):
    body = re.sub(r'#.*', '', _func(APP, fn))          # prose may name detect_modules()
    assert 'detect_modules(' in body, fn
    assert re.search(r'detect_modules\(\)', body) is None, f'{fn} reads the cache'


@pytest.mark.parametrize('path,fn', [
    ('modules/__init__.py', '_missing_requirement'), ('modules/__init__.py', '_active_conflict'),
    ('modules/simulator.py', '_video_base')])
def test_module_decision_callers_ask_for_fresh_data(path, fn):
    body = _func((REPO / path).read_text(encoding='utf-8'), fn)
    assert "ctx['detect_modules'](fresh=True)" in body
    assert "ctx['detect_modules']()" not in body


def test_sidebar_uses_the_cache():
    body = _func(APP, 'inject_cloudtak_icon')
    assert 'render_sidebar(detect_modules(),' in body


# ---------------------------------------------------------------------------
# W4b: cold computes are single-flight per generation
# ---------------------------------------------------------------------------
def test_concurrent_cold_callers_share_one_compute(h):
    h.gate = threading.Event()
    got = []
    ts = [threading.Thread(target=lambda: got.append(h.detect_modules())) for _ in range(4)]
    for t in ts:
        t.start()
    assert h.entered.wait(5)
    time.sleep(0.2)                       # let the other three reach the wait
    h.gate.set()
    for t in ts:
        t.join(10)
    assert h.calls == 1 and len(got) == 4
    assert all(g == h.result for g in got)


def test_fresh_never_waits_on_another_compute(h):
    h.gate = threading.Event()
    t = threading.Thread(target=h.detect_modules)
    t.start()
    assert h.entered.wait(5)
    done = []
    h.gate.set()                          # fresh caller computes on its own
    done.append(h.detect_modules(fresh=True))
    t.join(10)
    assert h.calls == 2 and done


def test_owner_failure_does_not_strand_waiters(h):
    h.gate = threading.Event()
    h.fail = True
    errs = []

    def call():
        try:
            h.detect_modules()
        except RuntimeError as e:
            errs.append(e)
    ts = [threading.Thread(target=call) for _ in range(3)]
    for t in ts:
        t.start()
    assert h.entered.wait(5)
    time.sleep(0.2)
    h.gate.set()
    for t in ts:
        t.join(10)
    assert not any(t.is_alive() for t in ts)
    assert len(errs) == 3                 # every caller still gets the error, none hangs


def test_detect_body_has_no_shell_strings_or_direct_subprocess():
    body = _func(APP, '_detect_modules_uncached')
    assert 'shell=True' not in body
    assert 'subprocess.run(' not in body and '_sp.run(' not in body
