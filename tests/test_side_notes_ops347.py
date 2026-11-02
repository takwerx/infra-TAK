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
"""Side notes from infra-TAK #346 (ops #347): audit-log secrets, systemctl show-environment,
Caddy reload vs restart, and the Authentik PG tuning log lines.
"""

import importlib.util
import pathlib
import re
import subprocess as _real_subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_t347',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


# ── audit log never carries the keytool / openssl password ───────────────────────────

@pytest.mark.parametrize('argv, secret', [
    (['keytool', '-list', '-keystore', '/opt/tak/certs/files/truststore.jks',
      '-storepass', 'S3cr3t-pw'], 'S3cr3t-pw'),
    (['keytool', '-importcert', '-keypass', 'K3y-pw', '-storepass', 'S3cr3t-pw'], 'K3y-pw'),
    (['keytool', '-importkeystore', '-srcstorepass', 'a-pw', '-deststorepass', 'b-pw'], 'b-pw'),
    (['openssl', 'pkcs12', '-in', 'x.p12', '-passin', 'pass:P12-pw'], 'P12-pw'),
])
def test_summary_masks_keystore_passwords(argv, secret):
    b = _broker()
    out = b._summary({'op': 'exec', 'argv': argv})
    assert secret not in out
    assert '***' in out


def test_summary_keeps_the_rest_of_the_keytool_line():
    b = _broker()
    out = b._summary({'op': 'exec', 'argv': ['keytool', '-list', '-keystore', '/x.jks',
                                             '-storepass', 'pw']})
    assert out == 'keytool -list -keystore /x.jks -storepass ***'


def test_summary_still_masks_the_old_shapes():
    b = _broker()
    out = b._summary({'op': 'exec', 'argv': ['nmcli', 'device', 'wifi', 'connect', 'x',
                                             'password', 'hunter2']})
    assert 'hunter2' not in out
    out = b._summary({'op': 'exec', 'argv': ['env', 'PGPASSWORD=pgpw', 'psql']})
    assert 'pgpw' not in out


# ── systemctl show-environment is read-only and allowed ──────────────────────────────

def test_systemctl_show_environment_is_allowed_but_set_environment_is_not():
    b = _broker()
    b._check_systemctl(['systemctl', 'show-environment'])
    for verb in ('set-environment', 'import-environment', 'edit', 'link'):
        with pytest.raises(b.Denied):
            b._check_systemctl(['systemctl', verb])


# ── Caddy: Reload reloads, Save reloads, a hung reload is cleared by a restart ───────

def _caddy_ns(calls, results):
    """results: list of CompletedProcess or exceptions, consumed per subprocess.run."""
    def fake_run(argv, *a, **k):
        calls.append((list(argv), k.get('timeout')))
        r = results.pop(0)
        if isinstance(r, BaseException):
            raise r
        return r

    def done(rc=0, out=''):
        return _real_subprocess.CompletedProcess([], rc, out, '')

    ns = {
        'subprocess': types.SimpleNamespace(run=fake_run, PIPE=-1, STDOUT=-2,
                                            TimeoutExpired=_real_subprocess.TimeoutExpired),
        'time': types.SimpleNamespace(sleep=lambda s: None, time=lambda: 1.0),
        '_sudo_wrap': lambda a: a,
        'generate_caddyfile': lambda s: None,
        'load_settings': lambda: {},
        'caddy_last_action': {},
        'CADDY_RELOAD_TIMEOUT': 45,
        '_caddy_failure_detail': lambda: '',
        'print': lambda *a, **k: None,
        'done': done,
    }
    exec(compile(_cut('_caddy_restart_after_response'), 'app.py', 'exec'), ns)
    return ns


def test_reload_verb_runs_systemctl_reload_not_restart():
    calls = []
    ns = _caddy_ns(calls, [_real_subprocess.CompletedProcess([], 0, '', ''),
                           _real_subprocess.CompletedProcess([], 0, 'active\n', '')])
    ns['_caddy_restart_after_response']('reload', 'reload')
    assert calls[0][0] == ['systemctl', 'reload', 'caddy']
    assert ns['caddy_last_action']['ok'] is True
    assert all('restart' not in c[0] for c in calls)


def test_a_hung_reload_falls_back_to_restart():
    calls = []
    ns = _caddy_ns(calls, [_real_subprocess.TimeoutExpired('systemctl', 45),
                           _real_subprocess.CompletedProcess([], 0, '', ''),
                           _real_subprocess.CompletedProcess([], 0, 'active\n', '')])
    ns['_caddy_restart_after_response']('reload', 'reload')
    assert [c[0][1] for c in calls[:2]] == ['reload', 'restart']
    assert calls[0][1] == 45
    assert ns['caddy_last_action']['ok'] is True


def test_a_refused_reload_is_reported_not_restarted():
    calls = []
    ns = _caddy_ns(calls, [_real_subprocess.CompletedProcess([], 1, 'bad config', '')])
    ns['_caddy_restart_after_response']('reload', 'reload')
    assert [c[0][1] for c in calls] == ['reload']
    assert ns['caddy_last_action']['ok'] is False


def test_restart_default_is_unchanged():
    calls = []
    ns = _caddy_ns(calls, [_real_subprocess.CompletedProcess([], 0, '', ''),
                           _real_subprocess.CompletedProcess([], 0, 'active\n', '')])
    ns['_caddy_restart_after_response']()
    assert calls[0] == (['systemctl', 'restart', 'caddy'], 90)


def test_reload_button_and_domain_save_pass_the_reload_verb():
    body = _cut('caddy_control')
    assert "'verb': 'reload' if action == 'reload' else 'restart'" in body
    body = _cut('caddy_save_domains')
    assert "'verb': 'reload'" in body


# ── Authentik PG tuning: log lines name this box's tier ─────────────────────────────

def test_pg_tuning_summary_names_the_tier_not_the_enterprise_values():
    ns = {'re': re}
    exec(compile(_cut('_authentik_pg_tuning_summary'), 'app.py', 'exec'), ns)
    cmd = ('postgres -c max_connections=1000 -c shared_buffers=4GB'
           ' -c effective_cache_size=12GB -c work_mem=8MB')
    assert ns['_authentik_pg_tuning_summary'](cmd) == (
        'max_connections=1000, shared_buffers=4GB, effective_cache_size=12GB')


def test_no_log_line_claims_36gb_for_every_box():
    assert 'effective_cache_size=36GB)")' not in APP
    assert 'applying v0.9.28 enterprise config' not in APP


def test_31gb_box_gets_the_16gb_tier():
    start = APP.index('_AUTHENTIK_PG_COMMAND_TAIL = (')
    end = APP.index('# v0.9.28-alpha: enterprise scaling — PgBouncer tier.')
    # the ladder block: consts + both helpers
    block = APP[APP.index('_AUTHENTIK_PG_COMMAND_ENTERPRISE = ('):end]
    ns = {}
    exec(compile(block, 'app.py', 'exec'), ns)
    cmd, label = ns['_authentik_pg_command_for_ram'](31900)
    assert 'effective_cache_size=12GB' in cmd and '36GB' not in cmd
    assert label == '16GB tier'
    assert start > 0
