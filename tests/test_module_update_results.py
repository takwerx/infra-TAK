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
"""A failed module update records its own reason (v10.2.8 W10).

Field report (Richard, AUS-NSW, 2026-10-08): "Authentik failed to update" — and nothing he could
send from the UI said why. The Authentik Update ran synchronously and its reason existed ONLY in
the HTTP response; the page treated a gateway timeout as "still running" and reloaded; the async
updates kept their logs in memory, which any console restart wipes; Diagnostics had no update
section. Now every outcome lands in .config/module-results.json, the card shows the last failure,
and Diagnostics carries it.
"""

import json
import os
import pathlib
import re
import stat
import threading
import types
from collections import deque
from datetime import datetime
from functools import wraps

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
START = '# v10.2.8 W10: a failed module update records its own reason'
BLOCK = APP[APP.index(START):APP.index('def load_auth():')]


class _Resp:
    def __init__(self, data, code=200):
        self._d, self.status_code = data, code

    def get_json(self, silent=False):
        return self._d


@pytest.fixture
def h(tmp_path):
    import secrets
    ns = {'os': os, 're': re, 'json': json, 'threading': threading, 'datetime': datetime,
          'secrets': secrets,
          'wraps': wraps, 'deque': deque, 'CONFIG_DIR': str(tmp_path),
          'app': types.SimpleNamespace(jinja_env=types.SimpleNamespace(globals={}))}
    exec(compile(BLOCK, 'app.py', 'exec'), ns)
    ns['_tmp'] = tmp_path
    return ns


# --------------------------------------------------------------------------- #
# the error line
# --------------------------------------------------------------------------- #

def test_error_line_skips_pull_progress_and_takes_the_cause(h):
    out = ('[+] Pulling 3/4\n'
           ' server Pulling\n'
           ' 4f4fb700ef54 Already exists\n'
           ' 1a2b3c4d5e6f Downloading [=====>    ]  12MB/80MB\n'
           'Error response from daemon: Get "https://ghcr.io/v2/": dial tcp: lookup ghcr.io: '
           'no such host\n')
    assert h['_update_error_line'](out).startswith('Error response from daemon')


def test_error_line_strips_ansi_and_reads_log_lists(h):
    log = ['[12:00:01] ━━━ Step 3/6: Building ━━━', {'msg': '\x1b[31m✗ build failed: exit code 1\x1b[0m'},
           '[12:00:09] cleaning up']
    assert h['_update_error_line'](log) == '✗ build failed: exit code 1'


def test_error_line_falls_back_to_the_last_line(h):
    assert h['_update_error_line']('one\ntwo\nthe end') == 'the end'
    assert h['_update_error_line']('') == ''


# --------------------------------------------------------------------------- #
# the record
# --------------------------------------------------------------------------- #

def test_start_step_finish_persist_with_mode_600(h):
    h['_mod_result_start']('authentik', 'update', '2026.5.6', '2026.5.7')
    h['_mod_result_step']('authentik', 'pull + recreate')
    h['_mod_result_finish']('authentik', False, 'Authentik pull/recreate failed (compose pull): '
                                                '[+] Pulling\nmanifest unknown: tag 2026.5.7')
    path = h['_tmp'] / 'module-results.json'
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    last = json.loads(path.read_text())['authentik']['last']
    assert last['outcome'] == 'failed'
    assert last['step'] == 'pull + recreate'
    assert last['from'] == '2026.5.6' and last['to'] == '2026.5.7'
    assert last['error'] == 'manifest unknown: tag 2026.5.7'
    assert last['summary'].startswith('Authentik pull/recreate failed')


def test_success_clears_the_failure_and_history_keeps_both(h):
    h['_mod_result_start']('authentik')
    h['_mod_result_finish']('authentik', False, 'boom: error')
    h['_mod_result_start']('authentik')
    h['_mod_result_finish']('authentik', True, to='2026.5.7')
    rec = h['_mod_results_load']()['authentik']
    assert rec['last']['outcome'] == 'ok' and rec['last']['error'] == ''
    assert [e['outcome'] for e in rec['history']][:2] == ['ok', 'failed']


def test_a_restart_mid_update_is_recorded_as_interrupted(h):
    h['_mod_result_start']('cloudtak', 'update', '13.104.0', '13.105.0')
    h['_mod_result_step']('cloudtak', 'Step 4/6: Building images')
    h['_mod_results_mark_interrupted']()          # what the next console start runs
    last = h['_mod_result_last']('cloudtak')
    assert last['outcome'] == 'interrupted'
    assert 'console restarted' in last['error'] and 'Building images' in last['error']


def test_bookkeeping_never_raises(h, monkeypatch):
    monkeypatch.setitem(h, '_mod_results_save', lambda d: (_ for _ in ()).throw(OSError('ro fs')))
    assert h['_mod_result_start']('authentik') is None
    assert h['_mod_result_finish']('authentik', False, 'x') is None


# --------------------------------------------------------------------------- #
# sync routes: the decorator reads the response
# --------------------------------------------------------------------------- #

def _wrapped(h, view, active=True):
    return h['_records_module_update']('authentik', when=lambda: active,
                                       from_fn=lambda: '2026.5.6', to_fn=lambda: '2026.5.7')(view)


def test_decorator_records_an_error_response(h):
    v = _wrapped(h, lambda: (_Resp({'error': 'Authentik pull/recreate failed (compose pull): '
                                             'toomanyrequests: rate limit exceeded'}), 500))
    v()
    last = h['_mod_result_last']('authentik')
    assert last['outcome'] == 'failed' and 'rate limit' in last['error']


def test_decorator_records_success_with_the_running_version(h):
    _wrapped(h, lambda: _Resp({'success': True, 'version': '2026.5.7'}))()
    last = h['_mod_result_last']('authentik')
    assert last['outcome'] == 'ok' and last['to'] == '2026.5.7'


def test_decorator_records_an_exception_and_reraises(h):
    def boom():
        raise RuntimeError('broker went away')
    with pytest.raises(RuntimeError):
        _wrapped(h, boom)()
    assert 'broker went away' in h['_mod_result_last']('authentik')['error']


def test_decorator_ignores_other_actions(h):
    _wrapped(h, lambda: _Resp({'success': True}), active=False)()
    assert h['_mod_result_last']('authentik') is None


# --------------------------------------------------------------------------- #
# async routes: the tracked thread target reads status + log
# --------------------------------------------------------------------------- #

def test_tracked_job_failure_takes_reason_and_step_from_its_log(h):
    status, log = {'running': True, 'error': False}, []

    def job():
        log.extend(['━━━ Step 3/6: Pulling images ━━━', 'Pulling api', '✗ docker compose build failed (exit 1)'])
        status.update(running=False, error=True)
    h['_run_tracked']('cloudtak', status, log, job, frm='13.104.0', to='13.105.0')
    last = h['_mod_result_last']('cloudtak')
    assert last['outcome'] == 'failed'
    assert last['step'] == 'Step 3/6: Pulling images'
    assert last['error'] == '✗ docker compose build failed (exit 1)'


def test_tracked_job_success(h):
    status, log = {'error': False}, ['done']
    h['_run_tracked']('webodm', status, log, lambda: None)
    assert h['_mod_result_last']('webodm')['outcome'] == 'ok'


# --------------------------------------------------------------------------- #
# Authentik wiring, the card, Diagnostics
# --------------------------------------------------------------------------- #

def test_authentik_update_route_is_recorded_with_steps():
    head = APP[APP.index("@app.route('/api/authentik/control'"):APP.index('def authentik_control():')]
    assert "@_records_module_update(" in head and "'authentik'" in head
    assert "get('action') == 'update'" in head
    body = APP[APP.index('def authentik_control():'):APP.index("@app.route('/api/authentik/deploy'")]
    for step in ('pin the tag to', 'verify with docker compose config', 'pull + recreate',
                 'confirm the running image'):
        assert f"_mod_result_step('authentik', " in body and step in body, step
    # the real line, not the head/tail of pull progress
    assert '_update_error_line(_err)' in body


def test_authentik_card_shows_the_last_failure_and_page_polls_the_result():
    tpl = (REPO / 'templates' / 'authentik.html').read_text(encoding='utf-8')
    assert "last_update_result('authentik')" in tpl
    assert "/api/module-results/authentik" in tpl
    assert 'setTimeout(()=>location.reload(),180000)' not in tpl     # the blind reload is gone
    macro = (REPO / 'templates' / '_module_result.html').read_text(encoding='utf-8')
    assert 'module_last_result(module)' in macro and '|safe' not in macro   # autoescaped


def test_diagnostics_carries_the_last_result_per_module(h):
    src = APP[APP.index('def _diag_section_module_results('):APP.index('_DIAG_SECTIONS = (')]
    exec(compile(src, 'app.py', 'exec'), h)
    h['_mod_result_start']('authentik', 'update', '2026.5.6', '2026.5.7')
    h['_mod_result_step']('authentik', 'pull + recreate')
    h['_mod_result_finish']('authentik', False, 'Error response from daemon: no space left on device')
    lines = h['_diag_section_module_results']({})
    assert any('authentik' in l and 'FAILED' in l and 'no space left on device' in l
               and 'pull + recreate' in l for l in lines)
    assert not any('Z UTC' in l for l in lines)          # one timezone marker, not two
    assert "('Module updates — last result per module', _diag_section_module_results)" in APP


def test_results_api_is_login_required_and_name_checked():
    i = APP.index("@app.route('/api/module-results/<module>')")
    assert '@login_required' in APP[i:i + 120]
    assert '_MODULE_NAME_RE.match(module' in APP[i:i + 600]


# --------------------------------------------------------------------------- #
# every module with an Update button records its outcome, and its card shows it
# --------------------------------------------------------------------------- #

SYNC = {  # route -> module record
    "/api/authentik/control": 'authentik', "/api/netbird/control": 'netbird',
    "/api/takportal/control": 'takportal', "/api/caddy/update": 'caddy',
    "/api/guarddog/update": 'guarddog',
}
ASYNC = {  # module record -> the worker it tracks
    'cloudtak': 'run_cloudtak_update', 'fedhub': 'run_fedhub_remote_update',
    'webodm': '_run_webodm_update', 'remote-assist': '_run_remote_assist_update',
}
CARDS = {'authentik': 'authentik', 'netbird': 'netbird', 'takportal': 'takportal', 'caddy': 'caddy',
         'guarddog': 'guarddog', 'cloudtak': 'cloudtak', 'takserver': 'takserver', 'fedhub': 'fedhub',
         'webodm': 'webodm', 'remote_assist': 'remote-assist', 'tvr': 'tvr'}


@pytest.mark.parametrize('route,module', sorted(SYNC.items()))
def test_sync_update_routes_record(route, module):
    i = APP.index(f"@app.route('{route}'")
    head = APP[i:APP.index('\ndef ', i)]
    assert '@_records_module_update(' in head and f"'{module}'" in head


@pytest.mark.parametrize('module,worker', sorted(ASYNC.items()))
def test_async_update_routes_are_tracked(module, worker):
    assert re.search(r"target=_run_tracked,\s*(#[^\n]*)?\s*args=\('%s',[^)]*%s\)" % (re.escape(module), worker), APP), module


def test_takserver_update_factory_records_every_variant():
    body = APP[APP.index('def _tak_update_job('):APP.index('plugin_install_log = []')]
    assert "_mod_result_start('takserver'" in body and "_tracked_finish('takserver'" in body


def test_registry_modules_get_the_seams_and_use_them():
    ctx = APP[APP.index('_MODULE_CTX = {'):APP.index('_MODULE_CTX = {') + 600]
    assert "'mod_result_start': _mod_result_start" in ctx and "'tracked_finish': _tracked_finish" in ctx
    tvr = (REPO / 'modules' / 'tvr.py').read_text(encoding='utf-8')
    assert 'target=_run_update_recorded, args=(ctx,)' in tvr
    atlas = (REPO / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    assert 'target=_run_update_recorded, args=(ctx, inst)' in atlas
    assert '_run_update_recorded(ctx, inst)     # v10.2.8 W10' in atlas      # update-all too


@pytest.mark.parametrize('tpl,module', sorted(CARDS.items()))
def test_every_module_card_shows_its_last_failure(tpl, module):
    t = (REPO / 'templates' / f'{tpl}.html').read_text(encoding='utf-8')
    assert f"last_update_result('{module}')" in t


def test_atlas_page_shows_one_banner_per_deployment():
    t = (REPO / 'templates' / 'atlas.html').read_text(encoding='utf-8')
    assert "module_results_failing('atlas')" in t and 'last_update_result(_m' in t


def test_atlas_wrapper_records_per_deployment(monkeypatch):
    import sys
    sys.path.insert(0, str(REPO))
    import modules.atlas as atlas
    from modules import atlas_instances as ai
    calls = []
    slot = {'running': False, 'complete': True, 'error': True, 'log': ['✗ git fetch failed: could not resolve host']}
    monkeypatch.setattr(atlas, '_run_update', lambda ctx, inst=None: None)
    monkeypatch.setattr(atlas, '_update_slot', lambda inst=None: slot)
    monkeypatch.setattr(atlas, '_installed_version', lambda ctx, inst=None: 'v1.51.0')
    ctx = {'mod_result_start': lambda *a: calls.append(('start',) + a),
           'tracked_finish': lambda name, st, log, exc=None: calls.append(('finish', name, st['error'], log[-1]))}
    atlas._run_update_recorded(ctx, ai.make('corona', ai.MODE_DYNAMIC, 50, 8761))
    atlas._run_update_recorded(ctx, ai.make(None, ai.MODE_FIXED, 100, 8760))
    assert calls[0] == ('start', 'atlas-corona', 'update', 'v1.51.0', '')
    assert calls[1][:3] == ('finish', 'atlas-corona', True)
    assert calls[2][1] == 'atlas' and calls[3][1] == 'atlas'
    # without the seams (a stubbed ctx) the update still just runs
    atlas._run_update_recorded({}, None)


def test_tvr_wrapper_reads_the_current_status_at_the_end(monkeypatch):
    import sys
    sys.path.insert(0, str(REPO))
    import modules.tvr as tvr
    calls = []

    def fake_run(ctx):
        tvr._update_status = {'running': False, 'error': True, 'log': ['✗ docker build failed']}
    monkeypatch.setattr(tvr, '_run_update', fake_run)
    ctx = {'mod_result_start': lambda *a: calls.append(('start',) + a),
           'tracked_finish': lambda name, st, log, exc=None: calls.append(('finish', name, st['error'], log[-1]))}
    tvr._run_update_recorded(ctx)
    assert calls == [('start', 'tvr', 'update', '', ''), ('finish', 'tvr', True, '✗ docker build failed')]


def test_tracked_job_reads_the_log_the_worker_swapped_in(h):
    """W10 security-review finding: WebODM / Remote Assist replace status['log'] as they go."""
    status = {'running': True, 'error': False, 'log': []}

    def job():
        status['log'] = ['━━━ Step 2/4: Pulling ━━━', 'Error: pull access denied for webodm/webapp']
        status['error'] = 'pull failed'
    h['_run_tracked']('webodm', status, None, job)
    last = h['_mod_result_last']('webodm')
    assert last['step'] == 'Step 2/4: Pulling'
    assert last['error'] == 'pull failed'


def test_stored_error_is_scrubbed_of_credentials(h):
    h['_mod_result_start']('takportal')
    h['_mod_result_finish']('takportal', False,
                            "fatal: unable to access 'https://bot:ghp_abcdef123456@github.com/x/y.git/': error 403")
    err = h['_mod_result_last']('takportal')['error']
    assert 'ghp_abcdef123456' not in err and '[REDACTED]@github.com' in err


# --------------------------------------------------------------------------- #
# W10b: a failed Authentik Update leaves nothing changed (T&E test12, 2026-10-08)
# --------------------------------------------------------------------------- #

def _ak_update_body():
    body = APP[APP.index('def authentik_control():'):APP.index("@app.route('/api/authentik/deploy'")]
    return body[body.index("    elif action == 'update':\n        # v10.1.39 (COPIX"):]


def test_failed_update_restores_the_tag_pin_locally():
    b = _ak_update_body()
    # the original is captured BEFORE anything is written
    assert b.index("_pin_orig['compose'] = _cc") < b.index('_write_priv(cp, _new)')
    assert "_pin_orig['env_prev'] = _env_prev" in b
    # every failure exit restores it
    for marker in ("refusing to update '\n                                         f'a stack we cannot resolve: {_cerr} ({_restore_pin()})",
                   "_rp = _restore_pin()\n                return jsonify({'error': f'Refusing to update ({_rp})",
                   "({_restore_pin()})'}), 500"):
        assert marker in b, marker[:60]
    fail = b[b.index('if _last is None or _last.returncode != 0:'):b.index('# (e) Confirm the RUNNING image')]
    assert '_rp = _restore_pin()' in fail
    # a failed `up` (stack DOWN) is brought back up on the previous version
    assert "_last.args[-2:] == ['up', '-d']" in fail and "['docker', 'compose', 'up', '-d']" in fail


def test_failed_update_restores_the_tag_pin_remotely():
    body = APP[APP.index('def authentik_control():'):APP.index("@app.route('/api/authentik/deploy'")]
    remote = body[:body.index("    ak_dir = os.path.expanduser('~/authentik')")]
    assert remote.index('_remote_prev = ') < remote.index("sed -i 's/AUTHENTIK_TAG:-[^}}]*/AUTHENTIK_TAG:-{latest}/g'")
    assert remote.count('_remote_restore_pin()') >= 3      # def + pull failure + tag refusal


def test_the_rollback_note_at_the_end_of_a_long_error_is_kept(h):
    msg = ('Authentik pull/recreate failed (docker compose pull): Error response from daemon: failed to '
           'resolve reference "ghcr.io/goauthentik/ldap:2026.8.3": failed to do request: Head "https://'
           'ghcr.io/v2/goauthentik/ldap/manifests/2026.8.3": remote error: tls: internal error '
           '(the tag pin was restored to v2026.5.7 (compose))')
    assert h['_update_error_line'](msg).endswith('(the tag pin was restored to v2026.5.7 (compose))')
