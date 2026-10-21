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
"""TAK Portal Update does not report a failure that a gateway made up (ops #72).

Field report (CORAZ, Azure, 2026-10-17): the console said the TAK Portal update failed, while
the portal was already running the new release with a healthy database and worker. Update was one
synchronous request lasting as long as the checkout + image build (135 s for 1.4.8 -> 2.0.12 on
test8). Azure Application Gateway's default request timeout is 20 s
(https://learn.microsoft.com/en-us/azure/application-gateway/configuration-http-settings#request-timeout),
so it answered 502/504 long before the box did — and the page discarded every non-200 body
(`d=r.ok?await r.json():{}`) and printed "✗ Update failed. Try Start below." (the controls are
above that line, not below).

Now the POST only starts a background job (202) and the page polls /api/takportal/update/status.
The node tests run the real portalUpdate() from the template with fetch and timers stubbed; the
Python tests run the real worker, recorder and status endpoint from app.py.
"""

import json
import pathlib
import re
import shutil
import subprocess
import threading
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TPL = (REPO / 'templates' / 'takportal.html').read_text(encoding='utf-8')
FN = TPL[TPL.index('async function portalUpdate(){'):TPL.index('async function deployPortal(){')]

# --------------------------------------------------------------------------- #
# the page (node)
# --------------------------------------------------------------------------- #

# A tiny DOM/fetch/timer harness. Fake clock: every setTimeout jumps the clock to its due time,
# so a 20-minute poll loop runs in milliseconds. `post` is what POST /api/takportal/control does;
# `status` is the sequence of /api/takportal/update/status answers (the last one repeats; null =
# that request fails).
HARNESS = r'''
var SC = %s;
var realTimeout = require('timers').setTimeout;   // the page's setTimeout below is the fake one
var now = 0, timers = [], statusIdx = 0, redirected = null;
Date.now = function(){ return now; };
function setTimeout(fn, ms){ timers.push({at: now + (ms||0), fn: fn}); }
var els = {};
function el(id){ return els[id] || (els[id] = {id: id, style: {}, textContent: '', innerHTML: '', disabled: false}); }
var document = {getElementById: el, querySelectorAll: function(){ return [el('start-btn')]; }};
var window = {location: {set href(v){ redirected = v; }}};
var location = window.location;
function confirm(){ return true; }
function jsonResp(status, body){
  return {ok: status < 400, status: status, json: function(){ return Promise.resolve(body); }};
}
function htmlResp(status){
  return {ok: false, status: status, json: function(){ return Promise.reject(new SyntaxError("Unexpected token '<'")); }};
}
function fetch(url, opts){
  if (url === '/api/takportal/update/status') {
    var s = SC.status[Math.min(statusIdx++, SC.status.length - 1)];
    return s === null ? Promise.reject(new TypeError('Failed to fetch')) : Promise.resolve(jsonResp(200, s));
  }
  if (url === '/api/takportal/control') {
    var p = SC.post;
    if (p.kind === 'drop') return Promise.reject(new TypeError('Failed to fetch'));
    if (p.kind === 'html') return Promise.resolve(htmlResp(p.status));
    return Promise.resolve(jsonResp(p.status, p.body));
  }
  return Promise.reject(new Error('unexpected fetch ' + url));
}
var PORTAL_BETA_MODE = false;
%s
(async function(){
  await portalUpdate();
  for (var i = 0; i < 1000; i++) {
    await new Promise(function(r){ realTimeout(r, 0); });   // let pending fetch chains settle
    if (!timers.length) break;
    timers.sort(function(a, b){ return a.at - b.at; });
    var t = timers.shift(); now = Math.max(now, t.at); t.fn();
  }
  await new Promise(function(r){ realTimeout(r, 0); });
  process.stdout.write('\n' + JSON.stringify({status: el('update-status').textContent, color: el('update-status').style.color,
                              btnDisabled: el('update-btn').disabled, redirected: redirected, polls: statusIdx,
                              clock: now}));
})();
'''

OK_RESULT = {'success': True, 'version': '2.0.12', 'pull': 'Updated from 2.0.11 to GitHub Release 2.0.12.'}
PREV = {'running': False, 'job': 'J1', 'result': {'success': True, 'version': '2.0.11'}, 'code': 200,
        'last': {'id': 'r1', 'outcome': 'ok', 'to': '2.0.11'}}
RUN2 = {'running': True, 'job': 'J2', 'result': None, 'code': None,
        'last': {'id': 'r2', 'outcome': 'running', 'step': 'started'}}
DONE2 = {'running': False, 'job': 'J2', 'result': OK_RESULT, 'code': 200,
         'last': {'id': 'r2', 'outcome': 'ok', 'to': '2.0.12'}}
STARTED = {'kind': 'json', 'status': 202, 'body': {'success': True, 'started': True, 'job': 'J2', 'action': 'update'}}


def _run(post, status):
    script = HARNESS % (json.dumps({'post': post, 'status': status}), FN)
    out = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


needs_node = pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')


@needs_node
def test_the_page_starts_the_job_and_shows_its_result():
    r = _run(STARTED, [PREV, RUN2, RUN2, DONE2])
    assert r['status'] == '✓ Updated — Updated from 2.0.11 to GitHub Release 2.0.12. (2.0.12)', r
    assert r['redirected'] == '/takportal'


@needs_node
@pytest.mark.parametrize('post', [
    {'kind': 'html', 'status': 504},          # gateway timeout page (HTML, not JSON)
    {'kind': 'html', 'status': 502},          # Application Gateway v1 answers 502
    {'kind': 'json', 'status': 504, 'body': {'error': 'gateway'}},
    {'kind': 'drop'},                         # connection reset
])
def test_a_gateway_answer_to_the_post_is_not_a_failure(post):
    """CORAZ: whatever the gateway says, the page ends on what the box did."""
    r = _run(post, [PREV, RUN2, DONE2])
    assert r['status'].startswith('✓ Updated'), r
    assert 'fail' not in r['status'].lower()
    assert r['redirected'] == '/takportal'


@needs_node
def test_a_real_failure_shows_the_consoles_whole_reason_and_hint():
    failed = dict(DONE2, result={'success': False, 'error': 'Build failed: npm ci did not complete',
                                 'hint': 'Check the container logs, fix the cause, and press Update again.'},
                  code=500)
    r = _run(STARTED, [PREV, RUN2, failed])
    assert r['status'] == ('✗ Build failed: npm ci did not complete Check the container logs, '
                           'fix the cause, and press Update again.'), r
    assert r['color'] == 'var(--red)' and r['btnDisabled'] is False and r['redirected'] is None
    assert 'below' not in r['status']


@needs_node
def test_a_console_restart_mid_update_reads_the_recorded_outcome():
    gone = {'running': False, 'job': '', 'result': None, 'code': None,
            'last': {'id': 'r2', 'outcome': 'interrupted', 'step': 'started',
                     'error': 'the console restarted while this was running (last step: started)'}}
    r = _run(STARTED, [PREV, RUN2, gone])
    assert r['status'] == '✗ Update failed: the console restarted while this was running (last step: started)', r
    assert r['btnDisabled'] is False


@needs_node
def test_the_previous_job_is_never_mistaken_for_this_update():
    """The POST never reached the console: only the OLD finished job exists. After a minute the
    page says nothing changed and frees the button — it does not claim J1's success."""
    r = _run({'kind': 'drop'}, [PREV])
    assert 'did not reach the console' in r['status'], r
    assert r['btnDisabled'] is False and r['redirected'] is None
    assert 60000 < r['clock'] < 120000


@needs_node
def test_without_a_prior_job_id_an_old_finished_job_is_still_not_adopted():
    r = _run({'kind': 'drop'}, [None, PREV])         # the pre-read itself failed
    assert 'did not reach the console' in r['status'], r


@needs_node
def test_an_update_already_running_is_followed_not_restarted():
    busy = {'kind': 'json', 'status': 409,
            'body': {'success': False, 'running': True, 'job': 'J2', 'error': 'A TAK Portal update is already running.'}}
    r = _run(busy, [PREV, RUN2, DONE2])
    assert r['status'].startswith('✓ Updated'), r


@needs_node
def test_a_direct_error_answer_is_shown_not_thrown_away():
    r = _run({'kind': 'json', 'status': 400, 'body': {'error': 'Invalid action'}}, [PREV])
    assert r['status'] == '✗ Invalid action', r
    assert r['btnDisabled'] is False and r['polls'] == 1      # only the pre-read, no polling


@needs_node
def test_a_box_that_never_finishes_reloads_after_twenty_minutes_instead_of_claiming_anything():
    r = _run(STARTED, [PREV, RUN2])
    assert r['redirected'] == '/takportal'
    assert '✓' not in r['status'] and '✗' not in r['status'], r
    assert r['clock'] >= 1200000


def test_template_source_contract():
    assert 'r.ok?await r.json():{}' not in FN              # the line that discarded the error
    assert "/api/takportal/update/status" in FN
    # the controls are ABOVE the status line (the comments may still quote the old text)
    assert "Start below.'" not in TPL and "Start below.'" not in APP
    assert 'press Start in Controls above.' in APP


# --------------------------------------------------------------------------- #
# the route, the job, the status endpoint (app.py)
# --------------------------------------------------------------------------- #

ROUTE = APP[APP.index("@app.route('/api/takportal/control'"):APP.index('# ops #72: TAK Portal Update as a background job')]
JOB = APP[APP.index('# ops #72: TAK Portal Update as a background job'):APP.index("@app.route('/api/takportal/deploy'")]


def test_the_route_starts_a_job_and_returns_at_once():
    head = ROUTE[:ROUTE.index('def takportal_control():')]
    assert '_records_module_update' not in head          # it would record the 202 as the outcome
    branch = ROUTE[ROUTE.index("    elif action == 'update':"):ROUTE.index("    else:\n        return jsonify({'error': 'Invalid action'}), 400")]
    assert 'threading.Thread(target=_takportal_update_worker, args=(portal_dir, job_id), daemon=True).start()' in branch
    assert "}), 202" in branch and "}), 409" in branch
    for blocking in ('_takportal_update_git(', "'up', '-d', '--build'", 'time.sleep('):
        assert blocking not in branch, blocking


def test_the_job_is_what_records_the_outcome():
    head = JOB[JOB.index('@_records_module_update('):JOB.index('def _takportal_run_update(portal_dir):')]
    assert "'takportal'" in head
    body = JOB[JOB.index('def _takportal_run_update(portal_dir):'):]
    assert 'jsonify' not in body.split("@app.route('/api/takportal/update/status')")[0]   # no app context on a thread
    i = APP.index("@app.route('/api/takportal/update/status')")
    assert '@login_required' in APP[i:i + 120]


@pytest.fixture
def ns(tmp_path):
    """The real module-results recorder + the real job/worker/status code from app.py."""
    import os
    import secrets
    from collections import deque
    from datetime import datetime
    from functools import wraps
    rec = APP[APP.index('# v10.2.8 W10: a failed module update records its own reason'):APP.index('def load_auth():')]
    n = {'os': os, 're': re, 'json': json, 'threading': threading, 'datetime': datetime, 'secrets': secrets,
         'wraps': wraps, 'deque': deque, 'CONFIG_DIR': str(tmp_path),
         'app': types.SimpleNamespace(jinja_env=types.SimpleNamespace(globals={}),
                                      route=lambda *a, **k: (lambda f: f)),
         'login_required': lambda f: f, 'jsonify': lambda d: d,
         '_get_takportal_version_info': lambda: {'version': '2.0.11'}}
    exec(compile(rec, 'app.py', 'exec'), n)
    exec(compile(JOB, 'app.py', 'exec'), n)
    return n


def test_a_failed_update_is_published_to_the_page_and_recorded(ns):
    ns['_takportal_update_git'] = lambda pd: {'ok': False, 'channel': 'stable',
                                             'error': 'git fetch failed: Could not resolve host: github.com.'}
    ns['_takportal_update_job'].update({'running': True, 'id': 'J9'})
    ns['_takportal_update_worker']('/home/takwerx/TAK-Portal', 'J9')
    st = ns['takportal_update_status']()
    assert st['running'] is False and st['job'] == 'J9' and st['code'] == 500
    assert st['result']['error'].startswith('git fetch failed')
    assert st['last']['outcome'] == 'failed' and 'Could not resolve host' in st['last']['error']
    assert st['last']['from'] == '2.0.11'


def test_a_crash_in_the_update_still_ends_the_job(ns):
    def boom(pd):
        raise RuntimeError('broker went away')
    ns['_takportal_update_git'] = boom
    ns['_takportal_update_job'].update({'running': True, 'id': 'J9'})
    ns['_takportal_update_worker']('/x', 'J9')
    st = ns['takportal_update_status']()
    assert st['running'] is False and st['result']['error'] == 'RuntimeError: broker went away'
    assert st['last']['outcome'] == 'failed'


def test_a_stale_worker_does_not_overwrite_a_newer_job(ns):
    ns['_takportal_update_git'] = lambda pd: {'ok': False, 'channel': 'stable', 'error': 'old'}
    ns['_takportal_update_job'].update({'running': True, 'id': 'NEW'})
    ns['_takportal_update_worker']('/x', 'OLD')
    assert ns['_takportal_update_job']['running'] is True and ns['_takportal_update_job']['result'] is None
