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
"""Guard Dog's "Update pending" sweep does not go quiet when GitHub does not answer (ops #1305).

Thu Nov 26: infra-TAK 10.4.8 (a security release) came out at 7:22 AM PT. test8 got its mail at
8:30 AM. garesponder, on the same 6 hour cycle, got nothing. Before this fix a full sweep that
could not read the newest console release (a) forgot it had already mailed the console target,
so the next good sweep mailed the SAME release again (test8 got the 10.4.7 mail twice), and
(b) was not repeated for six hours, so a security release could wait most of a day.

The functions are cut out of app.py and run with GitHub, the mail relay and the clock faked.
"""

import json
import pathlib
import re
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    return re.search(rf'^{name} = .*?(?=^\S)', APP, re.S | re.M).group(0)


def _exec(n, *names, consts=()):
    src = '\n'.join([_const(c) for c in consts] + [_cut(x) for x in names])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


CONSOLE_1048 = {'label': 'infra-TAK console', 'installed': 'v10.4.4-alpha', 'target': 'v10.4.8-alpha',
                'identity': 'v10.4.8-alpha', 'how': 'Console page → Update Now.',
                'security': ['v10.4.8-alpha is a security release: Authentik 2026.8.7']}
CONSOLE_1047 = dict(CONSOLE_1048, target='v10.4.7-alpha', identity='v10.4.7-alpha',
                    security=['v10.4.7-alpha is a security release: sign-in checks'])


def _sweep_ns(console, state, relay_fails=False):
    """Run the REAL _collect_pending_updates and _update_notify_check_once together. `console`
    is what _console_pending_update gives: a dict, None (up to date) or an Exception."""
    sent, saved = [], []

    def console_pending(settings):
        if isinstance(console, Exception):
            raise console
        return json.loads(json.dumps(console)) if console else None

    def relay(to, subj, body):
        if relay_fails:
            raise RuntimeError('relay down')
        sent.append((subj, body))

    none = lambda *a, **k: []   # noqa: E731  every other source: nothing pending
    n = {
        'socket': types.SimpleNamespace(gethostname=lambda: 'box'),
        'os': types.SimpleNamespace(path=types.SimpleNamespace(isdir=lambda p: False,
                                                               expanduser=lambda p: p)),
        'load_settings': lambda: {'guarddog_alert_email': 'ops@example.com', 'fqdn': 'tak.example.com',
                                  'console_port': 5001, 'update_channel': 'main'},
        '_safe_alert_email_list': lambda v: v,
        '_gd_quiet_state': lambda: (False, 0, ''),
        '_guarddog_server_identifier': lambda s: 'garesponder',
        '_update_notify_state_load': lambda: json.loads(json.dumps(state)),
        '_update_notify_state_save': lambda s: saved.append(s),
        '_guarddog_send_alert_email_via_relay': relay,
        'print': lambda *a, **k: None,
        'time': time,
        'PATCH_NOW_REPEAT_S': 24 * 3600,
        '_collect_patch_now_items': lambda feed, unknown, now=None: ([], feed),
        '_console_pending_update': console_pending,
        'detect_modules': lambda: {},
        '_takserver_tested_items': none, '_module_update_items': none, '_os_security_items': none,
        '_postgres_security_items': none, '_java_restart_items': none, '_java_image_items': none,
        '_tak_db_refresh_items': none, '_postgres_remote_security_items': none,
        '_node_container_versions': lambda: {}, '_node_security_items': none,
        'NODE_MODULE_CONTAINERS': (), '_detect_cloudtak_plugins': none,
        '_marketplace_plugin_items': none,
    }
    _exec(n, '_apply_security_identity', '_carried_by_unknown', '_collect_pending_updates',
          '_update_notify_check_once')
    return n, sent, saved


def _run(console, state, **kw):
    n, sent, saved = _sweep_ns(console, state, **kw)
    return n['_update_notify_check_once'](), sent, saved


# ── (a) a console check that failed keeps what was already mailed ─────────────

def test_console_check_failure_is_unknown_and_keeps_the_mailed_record():
    state = {'console': 'v10.4.7-alpha+security'}
    r, sent, saved = _run(OSError('HTTP Error 403: rate limit exceeded'), state)
    assert sent == [] and r['emailed'] is False
    # nothing to save, or the mailed record is still there
    assert saved == [] or saved[-1].get('console') == 'v10.4.7-alpha+security'


def test_after_a_failed_check_the_same_release_is_not_mailed_a_second_time():
    # test8, Wed 2:31 PM and Thu 2:30 AM PT: the 10.4.7 mail came twice.
    state = {'console': 'v10.4.7-alpha+security'}
    _, _, saved = _run(OSError('HTTP Error 403'), state)
    after_failure = saved[-1] if saved else state
    r, sent, _ = _run(CONSOLE_1047, after_failure)
    assert sent == [] and r['emailed'] is False


def test_a_console_mailed_for_1047_mails_again_when_the_target_becomes_1048():
    # the question in the ops issue: dedupe is by target, so a NEW release always mails
    state = {'console': 'v10.4.7-alpha+security'}
    r, sent, saved = _run(CONSOLE_1048, state)
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj.startswith('🔒 Security update pending on garesponder')
    assert 'v10.4.4-alpha → v10.4.8-alpha' in body and 'Authentik 2026.8.7' in body
    assert saved[-1]['console'] == 'v10.4.8-alpha+security'


# ── (b) a sweep that could not look, or could not send, is repeated soon ──────

def test_failed_console_check_asks_for_an_early_retry():
    r, _, _ = _run(OSError('HTTP Error 403'), {})
    assert r.get('retry_soon') is True


def test_failed_send_asks_for_an_early_retry_and_is_not_marked_mailed():
    r, sent, saved = _run(CONSOLE_1048, {'console': 'v10.4.7-alpha+security'}, relay_fails=True)
    assert r['emailed'] is False and r.get('retry_soon') is True
    assert saved == []          # a failed send is not recorded as mailed


def test_a_quiet_good_sweep_asks_for_nothing():
    r, sent, _ = _run(None, {})
    assert r == {'pending': [], 'emailed': False}


def test_a_good_sweep_that_mailed_asks_for_nothing():
    r, sent, _ = _run(CONSOLE_1048, {})
    assert r['emailed'] is True and 'retry_soon' not in r


# ── the loop: hourly full retries, then back to the 6 hour rhythm ─────────────

class _Stop(Exception):
    pass


def _loop(results, iterations):
    """Run the real _update_notify_loop on a fake clock. `results` is the list of what each full
    sweep returns (the last one repeats). Returns the list of (hour, 'full'|'fast') calls."""
    clock = {'t': 0.0, 'slept': 0}
    calls = []
    results = list(results)

    def check(fast=False):
        calls.append((round(clock['t'] / 3600.0, 2), 'fast' if fast else 'full'))
        if fast:
            return {'pending': [], 'emailed': False}
        r = results.pop(0) if len(results) > 1 else results[0]
        if isinstance(r, Exception):
            raise r
        return r

    def sleep(sec):
        clock['slept'] += 1
        if clock['slept'] > iterations:
            raise _Stop()
        clock['t'] += sec

    n = {'time': types.SimpleNamespace(time=lambda: clock['t'], sleep=sleep),
         '_update_notify_lock': types.SimpleNamespace(__enter__=lambda s: None, __exit__=lambda s, *a: None),
         '_update_notify_check_once': check, 'print': lambda *a, **k: None}

    class _Lock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    n['_update_notify_lock'] = _Lock()
    consts = ['UPDATE_NOTIFY_FIRST_DELAY_S', 'UPDATE_NOTIFY_INTERVAL_S', 'PATCH_NOW_CHECK_INTERVAL_S']
    if re.search(r'^UPDATE_NOTIFY_QUICK_RETRIES = ', APP, re.M):   # absent before ops #1305
        consts.append('UPDATE_NOTIFY_QUICK_RETRIES')
    _exec(n, '_update_notify_loop', consts=consts)
    with pytest.raises(_Stop):
        n['_update_notify_loop']()
    return calls


GOOD = {'pending': [], 'emailed': False}
RETRY = {'pending': [], 'emailed': False, 'retry_soon': True}


def test_loop_default_rhythm_is_one_full_sweep_every_six_hours():
    calls = _loop([GOOD], 14)
    fulls = [h for h, kind in calls if kind == 'full']
    assert len(fulls) >= 2
    assert fulls[1] - fulls[0] == pytest.approx(6.0, abs=0.5)


def test_loop_repeats_the_full_sweep_an_hour_after_a_failed_one():
    calls = _loop([RETRY, GOOD], 6)
    assert [kind for _, kind in calls[:3]] == ['full', 'full', 'fast'] or \
        [kind for _, kind in calls[:2]] == ['full', 'full']
    first, second = [h for h, kind in calls if kind == 'full'][:2]
    assert second - first == pytest.approx(1.0, abs=0.1)


def test_loop_repeats_a_full_sweep_that_raised():
    calls = _loop([RuntimeError('boom'), GOOD], 6)
    first, second = [h for h, kind in calls if kind == 'full'][:2]
    assert second - first == pytest.approx(1.0, abs=0.1)


def test_loop_gives_up_on_hourly_retries_after_six_and_waits_for_the_next_cycle():
    # a box with no route to GitHub must not run a full sweep every hour for ever
    calls = _loop([RETRY], 20)
    fulls = [h for h, kind in calls if kind == 'full']
    gaps = [round(b - a, 1) for a, b in zip(fulls, fulls[1:])]
    assert gaps[:6] == [1.0] * 6
    assert gaps[6] >= 5.0


def test_quiet_window_defer_is_unchanged():
    # ops #228 still reads quiet_until and still makes the next look the full sweep
    loop = _cut('_update_notify_loop')
    assert "r.get('quiet_until')" in loop and 'next_full = 0.0' in loop
