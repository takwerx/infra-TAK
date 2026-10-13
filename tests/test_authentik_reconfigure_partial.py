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
"""Authentik reconfigure must not say "complete" when steps did not finish.

Field (v10.2.12 T&E): Authentik was overloaded during the post-update reconfigure. Eleven API
steps (Node-RED provider, forward auth, WebODM, access policies, show password, domain sync,
...) each timed out and logged a ⚠, and the run still ended on "✓ Reconfigure complete." with
status complete. Every step swallows its own error, so the only record of what failed is the
⚠/✗ lines in the log. The run now collects those and ends as partial, listing them.

app.py cannot be imported in a test, so the functions are cut out of it and run through the
remote-reconfigure path (no local files needed): the code under test is the shipped text.
"""

import ast
import datetime
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TEMPLATE = (REPO / 'templates' / 'authentik.html').read_text(encoding='utf-8')
_WANT = {'run_authentik_deploy', '_run_authentik_reconfigure_remote', '_authentik_reconfigure_finish'}


def _func(name):
    return next(ast.get_source_segment(APP, n) for n in ast.parse(APP).body
                if isinstance(n, ast.FunctionDef) and n.name == name)


def _run(step_warnings=(), status=None):
    """Run a remote reconfigure. step_warnings: ⚠ lines that API steps log, as in the field."""
    parts = [ast.get_source_segment(APP, n) for n in ast.parse(APP).body
             if isinstance(n, ast.FunctionDef) and n.name in _WANT]
    assert len(parts) == len(_WANT), 'a function under test was renamed or removed'
    log = []
    if status is None:
        status = {'running': True, 'complete': False, 'error': False}
    status.update({'running': True, 'complete': False, 'error': False})
    pending = list(step_warnings)

    def step(*a, plog=None, **k):
        # Each API step logs through the plog it was handed (positional or keyword).
        fn = plog or next((x for x in a if callable(x)), None)
        if pending and fn:
            fn(pending.pop(0))

    ns = {
        'os': __import__('os'), 'datetime': datetime.datetime,
        'authentik_deploy_log': log, 'authentik_deploy_status': status,
        'load_settings': lambda: {'fqdn': 'example.com', 'webodm_enabled': True},
        '_get_module_deployment_config': lambda s, k: {'target_mode': 'remote', 'remote': {'host': 'ak.example'}},
        '_module_run': lambda *a, **k: None,
        '_get_authentik_env_value': lambda s, k: 'tok',
        '_get_authentik_api_url': lambda s: 'http://ak',
        '_wait_for_authentik_api': lambda *a, **k: True,
        '_ensure_ldap_flow_authentication_none': lambda: (True, ''),
        '_is_module_deployed': lambda s, m: True,
        '_get_fedhub_deployment_config': lambda s: {},
        '_sync_webadmin_after_authentik_reconfigure': step,
    }
    for name in ('_ensure_proxy_providers_cookie_domain', '_sync_authentik_takportal_provider_url',
                 '_ensure_authentik_nodered_app', '_ensure_authentik_webodm_app',
                 '_ensure_authentik_fedhub_proxy_app', '_ensure_authentik_console_app',
                 '_repair_embedded_outpost_all_apps', '_ensure_app_access_policies',
                 '_authentik_enable_show_password'):
        ns[name] = step
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    ns['run_authentik_deploy'](reconfigure=True)
    return status, log


def test_clean_reconfigure_reports_complete():
    status, log = _run()
    assert status['complete'] and not status['error'] and not status['partial'], log
    assert status['issues'] == []
    assert any('✓ Reconfigure (remote) complete.' in m for m in log), log


def test_timed_out_steps_report_partial_not_complete():
    warnings = ['  ⚠ Proxy provider error: timed out',
                '  ⚠ Forward auth setup error: timed out',
                '  ⚠ App access policy setup: timed out']
    status, log = _run(warnings)
    assert status['partial'] and not status['running'], log
    assert not any('✓ Reconfigure' in m for m in log), 'must not claim complete'
    assert status['issues'] == [w.strip() for w in warnings]
    assert any('3 step(s) did not complete' in m for m in log), log
    # every failed step is named again in the summary, without its ⚠
    for w in warnings:
        assert any(m.endswith('    - ' + w.strip().lstrip('⚠ ')) for m in log), w


def test_a_late_failure_in_webadmin_sync_is_counted():
    # The WebAdmin/Caddy sync runs last; it used to run after "complete" was printed.
    status, log = _run(['  ⚠ WebAdmin sync failed: boom'])
    assert status['partial'], log


def test_a_new_run_clears_the_previous_partial():
    status, _ = _run(['  ⚠ x: timed out'])
    assert status['partial']
    _run(status=status)
    assert status['complete'] and not status['partial'] and status['issues'] == []


def test_local_reconfigure_ends_through_the_finish_helper():
    src = _func('run_authentik_deploy')
    assert '"\\u2713 Reconfigure complete."' not in src, 'unconditional complete line is back'
    tail = src[src.index('Ensuring password-recovery flow'):]
    sync = tail.index('_sync_webadmin_after_authentik_reconfigure(plog)')
    finish = tail.index('_authentik_reconfigure_finish(plog, issues')
    assert sync < finish, 'the Caddy sync must be counted before the verdict'


def test_log_api_and_page_carry_partial():
    api = _func('authentik_deploy_log_api')
    assert "'partial'" in api and "'issues'" in api
    assert re.search(r'd\.complete&&d\.partial', TEMPLATE)
    # the partial branch must come before the plain-complete one, or it never runs
    assert TEMPLATE.index('d.complete&&d.partial') < TEMPLATE.index('else if(d.complete){')
