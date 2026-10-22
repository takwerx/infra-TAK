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
"""v10.3.0 W4.e — upgrade the split install's database server from the core console.

Code-only proof (PLAN-v10.3.0-W4e §4): the preflight's verdicts from an injected probe,
the target resolution, the status payload the card reads on load, the database server's
job script, the route gates, Guard Dog's expiring stand-down, and the console card's
wiring. Nothing here touches a box ([[never-execute-destructive-negative-tests]]).
"""

import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import subprocess
import threading
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
CONSOLE = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')
GD = REPO / 'scripts' / 'guarddog'

GB, MB = 1024 ** 3, 1024 ** 2
HOST = '10.20.30.40'


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


OS_CONSTS = APP[APP.index('_OS_UPGRADE_UNIT = '):APP.index('\n\n\ndef _os_upgrade_unit_state')]
DBS_CONSTS = APP[APP.index('_DBSERVER_ACK = '):APP.index('_dbserver_start_lock = ')]
STEPS = ('pre-snapshot', 'db-dump', 'pin-pg16', 'release-upgrade', 'repos-noble', 'reassert', 'reboot')


def _settings(mode='two_server', host=HOST, **s1):
    return {'tak_deployment': {'mode': mode, 'server_one': dict({'host': host, 'ssh_user': 'ubuntu'}, **s1)}}


def _ns(settings=None, coreconfig_host=HOST, record=None):
    def _no_ssh(*a, **k):
        raise AssertionError('this path must not open an SSH session')
    settings = settings if settings is not None else _settings()
    ns = {'re': re, 'json': json, 'shlex': shlex, 'shutil': shutil, 'time': time, 'os': os,
          'socket': socket, 'threading': threading, 'subprocess': subprocess, 'types': types, 'CONFIG_DIR': '/nonexistent',
          'load_settings': lambda: settings,
          '_get_tak_deployment_config': lambda s: s.get('tak_deployment') or {},
          '_validate_ssh_target': lambda h, u, p: (True, ''),
          '_tak_db_host_from_coreconfig': lambda: coreconfig_host,
          '_os_upgrade_running_jobs': lambda: [],
          '_dbserver_record_read': lambda: dict(record or {}),
          '_ssh_probe': _no_ssh, '_dbserver_probe': _no_ssh}
    exec(compile(OS_CONSTS, 'app.py:W4-consts', 'exec'), ns)
    exec(compile(DBS_CONSTS, 'app.py:W4e-consts', 'exec'), ns)
    for name in ('_systemctl_show_tuple', '_dbserver_routes_available', '_dbserver_target',
                 '_dbserver_same_host', '_dbserver_remote_busy', '_dbserver_baseline',
                 '_dbserver_in_flight', '_dbserver_preflight', '_dbserver_status_payload',
                 '_os_upgrade_dbserver_script'):
        exec(compile(_fn(name), f'app.py:{name}', 'exec'), ns)
    return ns


def _probe(**over):
    d = {'os_id': 'ubuntu', 'os_version': '22.04', 'os_pretty': 'Ubuntu 22.04.5 LTS',
         'clusters': [['18', 'main', '5432', 'online']], 'cot': True,
         'tak_sessions': 12, 'tak_sessions_ssl': 12,
         'root_free': 50 * GB, 'boot_free': 900 * MB, 'cot_bytes': 2 * GB,
         'upgrader': '1:22.04.20', 'do_release_upgrade': True, 'prompt': 'lts',
         'pending': [], 'reboot_pkgs': [], 'reboot_required': False,
         'boot_id': 'boot-1', 'ssl': 'on', 'dbtls': 3,
         'hostssl': ['hostssl cot martiuser 10.20.30.1/32 scram-sha-256'],
         'ufw': {'status': 'active', 'rules': ['5432/tcp ALLOW 10.20.30.1']},
         'services': {'postgresql@18-main': 'active', 'ssh': 'active', 'tak-db-health': 'inactive'},
         'busy': [], 'jobs': {}}
    d.update(over)
    return (d, '', '')


def _checks(res):
    return {c['name']: c for c in res['checks']}


# ---------------------------------------------------------------------------
# preflight verdicts
# ---------------------------------------------------------------------------
def test_green_database_server_passes_every_check():
    res = _ns()['_dbserver_preflight'](probe=_probe())
    assert res['ok'], [c for c in res['checks'] if not c['pass']]
    assert [c['name'] for c in res['checks']] == [
        'split_config', 'ssh_sudo', 'os_type', 'is_tak_db', 'disk', 'no_job_running',
        'release_upgrader', 'os_up_to_date', 'no_reboot_pending', 'baseline']
    assert res['host'] == HOST and res['pending_count'] == 0
    assert res['baseline']['boot_id'] == 'boot-1'
    assert res['baseline']['services'] == ['postgresql@18-main', 'ssh']   # only the active ones


def test_already_on_2404_is_nothing_to_do_but_still_reports_updates():
    res = _ns()['_dbserver_preflight'](probe=_probe(os_version='24.04', os_pretty='Ubuntu 24.04.1 LTS',
                                                   pending=['libc6', 'openssl']))
    c = _checks(res)
    assert not res['ok'] and not c['os_type']['pass'] and 'already upgraded' in c['os_type']['detail']
    # the card stays the database server's Install updates path after the upgrade
    assert res['pending_count'] == 2 and not c['os_up_to_date']['pass']


def test_pending_updates_block_and_point_at_install_updates():
    res = _ns()['_dbserver_preflight'](probe=_probe(pending=['a', 'b', 'c']))
    c = _checks(res)
    assert not res['ok'] and res['pending_count'] == 3
    assert not c['os_up_to_date']['pass'] and 'Install updates' in c['os_up_to_date']['detail']


def test_pending_reboot_blocks_and_points_at_reboot():
    res = _ns()['_dbserver_preflight'](probe=_probe(reboot_pkgs=['linux-image-generic'], reboot_required=True))
    c = _checks(res)
    assert not res['ok'] and res['reboot_required']
    assert not c['no_reboot_pending']['pass'] and 'Reboot' in c['no_reboot_pending']['detail']


def test_pg15_cluster_says_run_the_58_update_first():
    res = _ns()['_dbserver_preflight'](probe=_probe(clusters=[['15', 'main', '5432', 'online']]))
    c = _checks(res)['is_tak_db']
    assert not c['pass'] and '5.8 update first' in c['detail']


def test_tak_not_connected_refuses():
    c = _checks(_ns()['_dbserver_preflight'](probe=_probe(tak_sessions=0)))['is_tak_db']
    assert not c['pass'] and 'start TAK Server first' in c['detail']


def test_coreconfig_pointing_elsewhere_refuses_to_touch_the_box():
    res = _ns(coreconfig_host='192.0.2.99')['_dbserver_preflight'](probe=_probe())
    c = _checks(res)['split_config']
    assert not res['ok'] and not c['pass'] and 'refusing' in c['detail']


def test_unreadable_coreconfig_refuses_rather_than_guesses():
    c = _checks(_ns(coreconfig_host='')['_dbserver_preflight'](probe=_probe()))['split_config']
    assert not c['pass'] and 'refusing to guess' in c['detail']


def test_sudo_password_prompt_stops_the_preflight():
    res = _ns()['_dbserver_preflight'](probe=(None, 'sudo', 'a password is required'))
    assert not res['ok'] and [c['name'] for c in res['checks']] == ['split_config', 'ssh_sudo']
    assert 'passwordless sudo' in res['checks'][-1]['detail']


def test_busy_database_server_blocks():
    c = _checks(_ns()['_dbserver_preflight'](probe=_probe(busy=['pg_dump'])))['no_job_running']
    assert not c['pass'] and 'database server: pg_dump' in c['detail']


def test_disk_floor_includes_room_for_the_dump():
    # 5 GB floor + 1.2 x a 10 GB database = 17 GB; 16 GB free is not enough
    c = _checks(_ns()['_dbserver_preflight'](probe=_probe(root_free=16 * GB, cot_bytes=10 * GB)))['disk']
    assert not c['pass']
    c = _checks(_ns()['_dbserver_preflight'](probe=_probe(root_free=18 * GB, cot_bytes=10 * GB)))['disk']
    assert c['pass']


def test_start_needs_the_exact_typed_acknowledgment():
    ns = _ns()
    assert ns['_DBSERVER_ACK'] == 'I have a snapshot of the database server'
    bad = ns['_dbserver_preflight'](for_start=True, data={'acknowledge': 'I have a snapshot'}, probe=_probe())
    assert not bad['ok'] and not _checks(bad)['acknowledge']['pass']
    good = ns['_dbserver_preflight'](for_start=True, data={'acknowledge': ns['_DBSERVER_ACK']}, probe=_probe())
    assert good['ok']


# ---------------------------------------------------------------------------
# target resolution + the status payload the card reads on load
# ---------------------------------------------------------------------------
@pytest.mark.parametrize('settings,want', [
    (_settings(mode='single'), 'this is not a split install'),
    (_settings(host=''), 'no database server is configured'),
    (_settings(use_localhost=True), 'the database server is this box'),
    (_settings(host='127.0.0.1'), 'the database server is this box'),
])
def test_target_refusals(settings, want):
    s1, why = _ns(settings)['_dbserver_target']()
    assert s1 is None and why.startswith(want)


def test_target_defaults_ssh_user_to_root():
    s1, why = _ns(_settings(ssh_user=''))['_dbserver_target']()
    assert why == '' and s1['ssh_user'] == 'root' and s1['host'] == HOST


def test_status_payload_names_the_target_without_ssh():
    d = _ns()['_dbserver_status_payload']()          # _ssh_probe stub raises if touched
    assert d['ok'] and d['state'] == 'idle' and not d['running']
    assert d['target_host'] == HOST and d['target_error'] == '' and d['target_is_local'] is False


def test_status_payload_flags_a_local_database_server():
    d = _ns(_settings(use_localhost=True))['_dbserver_status_payload']()
    assert d['target_host'] == '' and d['target_is_local'] is True


def test_status_payload_carries_steps_for_the_os_upgrade_only():
    rec = {'job': 'os-upgrade', 'phase': 'running', 'step': 'db-dump', 'host': HOST, 'started': 1000}
    d = _ns(record=rec)['_dbserver_status_payload']()
    assert d['running'] and tuple(d['steps']) == STEPS and d['raw'] == 'os-upgrade:running:1000'
    d = _ns(record={'job': 'updates', 'phase': 'done', 'started': 5})['_dbserver_status_payload']()
    assert d['steps'] == [] and not d['running']


def test_routes_exist_on_split_installs_only():
    assert _ns()['_dbserver_routes_available']()
    assert not _ns(_settings(mode='single'))['_dbserver_routes_available']()
    assert not _ns({})['_dbserver_routes_available']()


# ---------------------------------------------------------------------------
# the database server's job script
# ---------------------------------------------------------------------------
@pytest.fixture(scope='module')
def script():
    return _ns()['_os_upgrade_dbserver_script']('18')


def test_script_parses_in_bash(script):
    r = subprocess.run(['bash', '-n'], input=script, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_script_steps_in_plan_order(script):
    assert tuple(re.findall(r'^step (\S+)$', script, re.M)) == STEPS
    assert tuple(_ns()['_DBSERVER_OS_STEPS']) == STEPS


def test_script_dumps_before_any_package_moves(script):
    assert script.index('step db-dump') < script.index('step pin-pg16') < script.index('step release-upgrade')
    assert 'pg_dump' in script and 'pg_restore --list' in script


def test_script_holds_tak_database_package(script):
    assert 'TAK_PKGS="takserver-database"' in script


def test_script_interpolates_no_settings_value(script):
    assert HOST not in script and 'ubuntu@' not in script


def test_script_refuses_other_postgres_majors():
    with pytest.raises(ValueError):
        _ns()['_os_upgrade_dbserver_script']('16')


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize('path,methods', [
    ('preflight', ''), ('os-upgrade/start', ", methods=['POST']"), ('updates', ", methods=['POST']"),
    ('reboot', ", methods=['POST']"), ('status', ''), ('log', '')])
def test_route_is_login_required_and_split_gated(path, methods):
    decl = f"@app.route('/api/console/dbserver/{path}'{methods})\n@login_required\ndef "
    assert decl in APP, path
    body = APP[APP.index(decl):]
    body = body[:body.index('\n\n\n')]
    assert 'if not _dbserver_routes_available():' in body and '404' in body


@pytest.mark.parametrize('path', ['os-upgrade/start', 'reboot'])
def test_destructive_routes_need_the_console_password(path):
    decl = f"@app.route('/api/console/dbserver/{path}', methods=['POST'])"
    body = APP[APP.index(decl):]
    body = body[:body.index('\n\n\n')]
    assert '_require_admin_password(' in body


# ---------------------------------------------------------------------------
# Guard Dog stand-down (W4.e.3)
# ---------------------------------------------------------------------------
STANDDOWN_SCRIPTS = ('tak-remotedb-watch.sh', 'tak-remotedb-auth-watch.sh', 'tak-cotdb-watch.sh',
                     'tak-auto-vacuum.sh', 'tak-db-repack.sh', 'tak-retention-guard.sh')


@pytest.mark.parametrize('name', STANDDOWN_SCRIPTS)
def test_every_database_watcher_stands_down(name):
    assert 'gd_dbserver_standdown' in (GD / name).read_text(encoding='utf-8')


@pytest.fixture()
def standdown(tmp_path):
    lib = (GD / '_gd-tak-lib.sh').read_text(encoding='utf-8')
    m = re.search(r'^gd_dbserver_standdown\(\) \{.*?^\}', lib, re.S | re.M)
    assert m, 'gd_dbserver_standdown not found'
    fn = (m.group(0).replace('/var/lib/takguard', str(tmp_path))
          .replace('/var/log/takguard/restarts.log', str(tmp_path / 'restarts.log')))

    def run(marker):
        if marker is not None:
            (tmp_path / 'dbserver-maintenance').write_text(marker)
        r = subprocess.run(['bash', '-c', fn + '\ngd_dbserver_standdown tak-db-repack'],
                           capture_output=True, text=True)
        return r.returncode
    run.dir = tmp_path
    return run


def test_standdown_while_marker_is_live_and_logs_once(standdown):
    until = str(int(time.time()) + 3600)
    assert standdown(until) == 0
    assert standdown(until) == 0
    log = (standdown.dir / 'restarts.log').read_text()
    assert log.count('stand-down') == 1 and 'tak-db-repack' in log


@pytest.mark.parametrize('marker', [None, str(int(time.time()) - 1), 'garbage', ''])
def test_standdown_never_outlives_its_expiry(standdown, marker):
    assert standdown(marker) == 1


# ---------------------------------------------------------------------------
# console card
# ---------------------------------------------------------------------------
def test_card_is_outside_the_core_os_gate():
    gate = CONSOLE.index("{% if settings.get('os_type') in ('ubuntu-22.04', 'ubuntu-24.04') %}")
    gate_end = CONSOLE.index('{% endif %}', CONSOLE.index('id="os-upgrade-card"'))
    card = CONSOLE.index('id="dbserver-card"')
    assert not (gate < card < gate_end), 'a RHEL core with an Ubuntu database server must see the card'


def test_card_ack_phrase_matches_the_backend():
    assert "dbserver:'%s'" % _ns()['_DBSERVER_ACK'] in CONSOLE


@pytest.mark.parametrize('url', [
    '/api/console/dbserver/status', '/api/console/dbserver/log', '/api/console/dbserver/os-upgrade/start',
    "'/api/console/dbserver/'"])
def test_card_calls_the_dbserver_routes(url):
    assert url in CONSOLE


def test_card_sends_the_password_on_reboot_only_by_post():
    assert "_dbsPost('reboot',{admin_password:pw.value})" in CONSOLE
    assert "_dbsPost('updates')" in CONSOLE
