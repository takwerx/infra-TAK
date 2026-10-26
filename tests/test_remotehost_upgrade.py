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
"""v10.3.0 W4.g — upgrade every remote module host from the core console.

Code-only proof (PLAN-v10.3.0-W4g §4): which machines the card lists and which it refuses,
the preflight's verdicts from an injected probe, the after-reboot comparison, the watcher's
state machine, the job script, the Guard Dog stand-down the Fed Hub watcher honors, the
route gates and the card's wiring. Nothing here touches a box
([[never-execute-destructive-negative-tests]]).
"""

import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
CONSOLE = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')
FEDHUB_WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-fedhub-watch.sh').read_text(encoding='utf-8')

GB, MB = 1024 ** 3, 1024 ** 2
A, B, S1, CORE = '10.20.30.41', '10.20.30.42', '10.20.30.50', '10.20.30.1'


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


OS_CONSTS = APP[APP.index('_OS_UPGRADE_UNIT = '):APP.index('\n\n\ndef _os_upgrade_unit_state')]
RH_CONSTS = APP[APP.index('_RHOST_MODULES = ('):APP.index('_rhost_lock = ')]
PROBE = APP[APP.index('_RHOST_PROBE_PY = '):APP.index("\n\n\ndef _rhost_probe_text")]
PENDING = APP[APP.index('_OS_UPGRADE_PENDING_PY = ('):APP.index('_OS_UPGRADE_CORE_SERVICES = ')]


def _remote(host, **kw):
    return dict({'target_mode': 'remote', 'deployed': True,
                 'remote': {'host': host, 'ssh_user': 'ubuntu', 'ssh_port': 22}}, **kw)


def _settings(**mods):
    s = {'server_ip': CORE, 'fqdn': '', 'tak_deployment': {'mode': 'single'}}
    s.update({f'{k}_deployment': v for k, v in mods.items()})
    return s


def _ns(settings=None, records=None, other_core_jobs=None, dbserver_rec=None):
    def _no_ssh(*a, **k):
        raise AssertionError('this path must not open an SSH session')
    settings = settings if settings is not None else _settings(cloudtak=_remote(A), mediamtx=_remote(A), fedhub=_remote(B))
    ns = {'re': re, 'json': json, 'shlex': shlex, 'shutil': shutil, 'time': time, 'os': os,
          'socket': socket, 'threading': threading, 'subprocess': subprocess,
          'CONFIG_DIR': '/nonexistent',
          'load_settings': lambda: settings,
          '_get_tak_deployment_config': lambda s: s.get('tak_deployment') or {},
          '_get_fedhub_deployment_config': lambda s: s.get('fedhub_deployment') or {},
          '_get_cloudtak_deployment_config': lambda s: s.get('cloudtak_deployment') or {},
          '_get_module_deployment_config': lambda s, k: s.get(k) or {},
          '_validate_ssh_target': lambda h, u, p: (True, '') if re.fullmatch(r'[\w.-]+', h) else (False, 'bad host'),
          '_os_upgrade_running_jobs': lambda: list(other_core_jobs or []),
          '_dbserver_record_read': lambda: dict(dbserver_rec or {}),
          '_dbserver_in_flight': lambda r: (r or {}).get('phase') in ('running', 'rebooting', 'verifying'),
          '_ssh_probe': _no_ssh, '_rhost_probe': _no_ssh}
    exec(compile(OS_CONSTS, 'app.py:W4-consts', 'exec'), ns)
    exec(compile(PENDING, 'app.py:pending', 'exec'), ns)
    ns['_KERNEL_PATCH_TAK_PKGS'] = 'takserver takserver-fed-hub'
    exec(compile(RH_CONSTS, 'app.py:W4g-consts', 'exec'), ns)
    exec(compile(PROBE, 'app.py:W4g-probe', 'exec'), ns)
    for name in ('_systemctl_show_tuple', '_dbserver_same_host', '_dbserver_priv', '_os_upgrade_job_state',
                 '_rhost_probe_text', '_rhost_key', '_rhost_local_boot_id', '_rhost_module_cfg', '_rhost_is_this_box', '_remote_hosts',
                 '_rhost_target', '_rhost_remote_busy', '_rhost_baseline', '_rhost_other_jobs',
                 '_rhost_in_flight', '_rhost_preflight', '_rhost_compare', '_rhost_verify', '_rhost_tick',
                 '_rhost_status', '_rhost_list_payload', '_os_upgrade_remotehost_script'):
        exec(compile(_fn(name), f'app.py:{name}', 'exec'), ns)
    recs = {r['key']: dict(r) for r in (records or [])}
    ns['_rhost_records'] = lambda: [dict(r) for r in recs.values()]
    ns['_rhost_record_read'] = lambda k: dict(recs.get(k) or {})
    written = []
    ns['_rhost_record_write'] = lambda rec: written.append(dict(rec))
    ns['_written'] = written
    finished = []

    def _finish(rec, phase, step='', detail='', entry=None):
        rec.update({'phase': phase, 'step': step, 'detail': detail})
        finished.append(dict(rec))
        return rec
    ns['_rhost_finish'] = _finish
    ns['_finished'] = finished
    return ns


def _probe(**over):
    d = {'os_id': 'ubuntu', 'os_version': '22.04', 'os_pretty': 'Ubuntu 22.04.5 LTS', 'arch': 'x86_64',
         'boot_id': 'boot-1', 'jobs': {},
         'services': {'docker': 'active', 'ssh': 'active', 'mediamtx': 'active', 'mongod': 'inactive'},
         'containers': {'cloudtak-api-1': 'running', 'cloudtak-postgis-1': 'running', 'old-1': 'exited'},
         'ports': [22, 5000, 8554, 9997],
         'root_free': 40 * GB, 'boot_free': 900 * MB, 'busy': [],
         'upgrader': '1:22.04.20', 'do_release_upgrade': True, 'prompt': 'lts',
         'pending': [], 'reboot_pkgs': [], 'reboot_required': False}
    d.update(over)
    return (d, '', '')


def _checks(res):
    return {c['name']: c for c in res['checks']}


# ---------------------------------------------------------------------------
# which machines the card lists
# ---------------------------------------------------------------------------
def test_modules_on_one_machine_are_one_entry():
    hosts = {h['host']: h for h in _ns()['_remote_hosts']()}
    assert {k: h['modules'] for k, h in hosts.items()} == {A: ['cloudtak', 'mediamtx'], B: ['fedhub']}
    assert hosts[A]['labels'] == ['CloudTAK', 'MediaMTX'] and not hosts[A]['excluded']


def test_local_or_undeployed_modules_are_not_listed():
    s = _settings(cloudtak=dict(_remote(A), deployed=False), nodered={'target_mode': 'local', 'deployed': True},
                  webodm=_remote(B))
    assert [h['host'] for h in _ns(s)['_remote_hosts']()] == [B]


@pytest.mark.parametrize('host', ['127.0.0.1', 'localhost', CORE])
def test_a_remote_host_that_is_the_core_is_refused(host):
    # _ssh_probe runs a localhost target with a LOCAL shell — this must never reach a probe.
    h = _ns(_settings(authentik=_remote(host)))['_remote_hosts']()[0]
    assert 'core box itself' in h['excluded']


def test_the_database_server_has_one_upgrade_owner():
    s = _settings(nodered=_remote(S1))
    s['tak_deployment'] = {'mode': 'two_server', 'server_one': {'host': S1}}
    h = _ns(s)['_remote_hosts']()[0]
    assert 'Database server card' in h['excluded']


def test_unusable_ssh_settings_are_refused():
    h = _ns(_settings(nodered=_remote('bad host;x')))['_remote_hosts']()[0]
    assert 'not usable' in h['excluded']


def test_a_remote_host_reporting_this_boxs_boot_id_is_refused():
    # the core's LAN IP / a DNS name for it gets past the config check; the boot id does not lie
    ns = _ns()
    ns['_rhost_local_boot_id'] = lambda: 'boot-1'
    res = ns['_rhost_preflight'](_rhkey(A), probe=_probe(boot_id='boot-1'))
    assert not res['ok'] and 'this core box itself' in res['checks'][-1]['detail']
    assert 'ssh_sudo' not in _checks(res)


@pytest.mark.parametrize('host', ['0.0.0.0', '127.0.1.1'])
def test_wildcard_and_loopback_aliases_are_the_core(host):
    assert 'core box itself' in _ns(_settings(authentik=_remote(host)))['_remote_hosts']()[0]['excluded']


def test_url_key_never_becomes_a_hostname():
    ns = _ns()
    e, why = ns['_rhost_target']('evil.example')
    assert e is None and 'no deployed remote module' in why
    e, why = ns['_rhost_target'](ns['_rhost_key'](A))
    assert e['host'] == A


# ---------------------------------------------------------------------------
# preflight verdicts
# ---------------------------------------------------------------------------
def test_green_remote_host_passes_every_check():
    ns = _ns()
    res = ns['_rhost_preflight'](ns['_rhost_key'](A), probe=_probe())
    assert res['ok'], [c for c in res['checks'] if not c['pass']]
    assert [c['name'] for c in res['checks']] == [
        'target', 'ssh_sudo', 'os_type', 'arch', 'disk', 'no_job_running', 'release_upgrader',
        'os_up_to_date', 'no_reboot_pending', 'baseline']
    bl = res['baseline']
    assert bl['containers'] == ['cloudtak-api-1', 'cloudtak-postgis-1']        # running only
    assert bl['services'] == ['docker', 'mediamtx', 'ssh'] and bl['ports'] == [22, 5000, 8554, 9997]
    assert res['modules'] == ['CloudTAK', 'MediaMTX']


def test_arm_remote_host_is_refused_by_what_it_reports():
    c = _checks(_ns()['_rhost_preflight'](_rhkey(A), probe=_probe(arch='aarch64')))['arch']
    assert not c['pass'] and 'x86-64 only' in c['detail']


def test_rocky_remote_host_is_refused():
    c = _checks(_ns()['_rhost_preflight'](_rhkey(A), probe=_probe(os_id='rocky', os_version='9.4', os_pretty='Rocky Linux 9.4')))['os_type']
    assert not c['pass'] and '22.04 machines only' in c['detail']


def test_already_on_2404_is_nothing_to_do():
    c = _checks(_ns()['_rhost_preflight'](_rhkey(A), probe=_probe(os_version='24.04')))['os_type']
    assert not c['pass'] and 'already upgraded' in c['detail']


def test_sudo_password_prompt_stops_the_preflight():
    res = _ns()['_rhost_preflight'](_rhkey(A), probe=(None, 'sudo', 'a password is required'))
    assert [c['name'] for c in res['checks']] == ['target', 'ssh_sudo'] and 'passwordless sudo' in res['checks'][-1]['detail']


@pytest.mark.parametrize('kw,want', [
    ({'other_core_jobs': ['infratak-os-upgrade']}, 'core: infratak-os-upgrade'),
    ({'dbserver_rec': {'phase': 'running', 'job': 'os-upgrade'}}, 'database server: os-upgrade'),
    ({'records': [{'key': '10.20.30.42', 'host': B, 'job': 'updates', 'phase': 'running'}]}, f'{B}: updates'),
])
def test_one_machine_at_a_time(kw, want):
    c = _checks(_ns(**kw)['_rhost_preflight'](_rhkey(A), probe=_probe()))['no_job_running']
    assert not c['pass'] and want in c['detail']


def test_pending_updates_and_reboot_point_at_the_buttons():
    c = _checks(_ns()['_rhost_preflight'](_rhkey(A), probe=_probe(pending=['a'], reboot_pkgs=['libc6'], reboot_required=True)))
    assert 'Install updates' in c['os_up_to_date']['detail'] and 'Reboot' in c['no_reboot_pending']['detail']


def test_disk_floor_is_the_cores():
    c = _checks(_ns()['_rhost_preflight'](_rhkey(A), probe=_probe(root_free=9 * GB)))['disk']
    assert not c['pass']


def test_start_needs_the_exact_typed_acknowledgment():
    ns = _ns()
    bad = ns['_rhost_preflight'](_rhkey(A), for_start=True, data={'acknowledge': 'I have a snapshot'}, probe=_probe())
    assert not bad['ok']
    good = ns['_rhost_preflight'](_rhkey(A), for_start=True, data={'acknowledge': ns['_RHOST_ACK']}, probe=_probe())
    assert good['ok']


def _rhkey(h):
    return re.sub(r'[^a-z0-9.-]', '_', h.lower())


# ---------------------------------------------------------------------------
# after the job: everything that was up is up again
# ---------------------------------------------------------------------------
def _bl():
    return _ns()['_rhost_baseline'](_probe()[0])


def test_compare_clean_after_the_flip():
    assert _ns()['_rhost_compare'](_bl(), _probe(os_version='24.04')[0], True) == []


@pytest.mark.parametrize('over,want', [
    ({'os_version': '22.04'}, 'os-release='),
    ({'containers': {'cloudtak-api-1': 'running', 'cloudtak-postgis-1': 'restarting'}}, 'containers=cloudtak-postgis-1'),
    ({'services': {'docker': 'active', 'ssh': 'active', 'mediamtx': 'failed'}}, 'services=mediamtx'),
    ({'ports': [22, 5000, 9997]}, 'ports=8554'),
])
def test_compare_names_what_did_not_come_back(over, want):
    d = dict(_probe(os_version='24.04')[0], **over)
    assert any(p.startswith(want) for p in _ns()['_rhost_compare'](_bl(), d, True))


def test_an_exited_container_before_is_not_expected_after():
    d = dict(_probe(os_version='24.04')[0], containers={'cloudtak-api-1': 'running', 'cloudtak-postgis-1': 'running'})
    assert _ns()['_rhost_compare'](_bl(), d, True) == []


def _rec(**over):
    r = {'key': _rhkey(A), 'host': A, 'job': 'os-upgrade', 'phase': 'running', 'step': 'release-upgrade',
         'boot_id': 'boot-1', 'started': 1000.0, 'baseline': _bl(), 'modules': ['cloudtak', 'mediamtx']}
    r.update(over)
    return r


def test_tick_new_boot_id_verifies_and_finishes_done():
    ns = _ns()
    entry = {'key': _rhkey(A), 'host': A, 'ssh': {'host': A, 'ssh_user': 'ubuntu'}}
    probe = lambda e, mode: _probe(os_version='24.04', boot_id='boot-2')
    rec = ns['_rhost_tick'](_rec(phase='rebooting'), entry, probe_fn=probe, sleep=lambda s: None, now=lambda: 2000.0)
    assert rec['phase'] == 'done' and rec['os_version'] == '24.04'


def test_tick_verify_gives_up_after_the_window_and_names_the_problem():
    ns = _ns()
    entry = {'key': _rhkey(A), 'host': A, 'ssh': {}}
    t = [2000.0]

    def now():
        t[0] += 60
        return t[0]
    probe = lambda e, mode: _probe(os_version='24.04', boot_id='boot-2', ports=[22])
    rec = ns['_rhost_tick'](_rec(phase='rebooting'), entry, probe_fn=probe, sleep=lambda s: None, now=now)
    assert rec['phase'] == 'failed' and rec['step'] == 'verify' and 'ports=' in rec['detail']


def test_tick_unreachable_past_the_reboot_window_fails():
    ns = _ns()
    rec = ns['_rhost_tick'](_rec(phase='rebooting', reboot_at=1000.0, unreachable_since=1000.0), {'ssh': {}},
                            probe_fn=lambda e, m: (None, 'ssh', 'timeout'), now=lambda: 1000.0 + 1801)
    assert rec['phase'] == 'failed' and 'unreachable' in rec['detail']


def test_tick_failed_status_file_fails_at_its_step():
    ns = _ns()
    d = _probe(jobs={'os-upgrade': {'status': 'failed:release-upgrade', 'show': ''}})
    rec = ns['_rhost_tick'](_rec(), {'ssh': {}}, probe_fn=lambda e, m: d, now=lambda: 1500.0)
    assert rec['phase'] == 'failed' and rec['step'] == 'release-upgrade'


def test_list_payload_needs_no_ssh_and_names_the_running_machine():
    ns = _ns(records=[_rec()])
    p = ns['_rhost_list_payload']()
    by = {h['host']: h for h in p['hosts']}
    assert p['running_key'] == _rhkey(A) and by[A]['running'] and by[B]['state'] == 'idle'


# ---------------------------------------------------------------------------
# the job script
# ---------------------------------------------------------------------------
def test_script_reuses_the_cores_fragments_and_has_no_database_step():
    ns = _ns()
    s = ns['_os_upgrade_remotehost_script']()
    for frag in ('_OS_UPGRADE_SH_FUNCS', '_OS_UPGRADE_SH_HOLDS', '_OS_UPGRADE_SH_FLIP', '_OS_UPGRADE_SH_REBOOT'):
        assert ns[frag] in s
    assert 'pg_dump' not in s and 'PG_EXPECT' not in s.split(ns['_OS_UPGRADE_SH_FLIP'])[0]
    assert "TAK_PKGS='takserver takserver-fed-hub'" in s
    assert [m for m in re.findall(r'^step (\S+)', s, re.M)] == list(ns['_RHOST_OS_STEPS'])


@pytest.mark.skipif(not shutil.which('bash'), reason='bash not available')
def test_script_is_valid_bash():
    s = _ns()['_os_upgrade_remotehost_script']()
    r = subprocess.run(['bash', '-n'], input=s, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_probe_text_is_valid_python_built_from_constants_only():
    ns = _ns()
    for mode in ('full', 'status'):
        compile(ns['_rhost_probe_text'](mode), 'probe', 'exec')
    with pytest.raises(ValueError):
        ns['_rhost_probe_text']('x')


# ---------------------------------------------------------------------------
# Guard Dog stand-down the Fed Hub watcher honors
# ---------------------------------------------------------------------------
def _watch_block():
    start = FEDHUB_WATCH.index('RH_KEY=')
    end = FEDHUB_WATCH.index('fi\n', start) + 3
    return FEDHUB_WATCH[start:end]


@pytest.mark.skipif(not shutil.which('bash'), reason='bash not available')
@pytest.mark.parametrize('host', [A, 'FedHub.Example.COM', 'hub_1.example.com'])
def test_fedhub_watch_marker_name_matches_the_console(host, tmp_path):
    ns = _ns()
    marker = tmp_path / ('remotehost-maintenance.' + ns['_rhost_key'](host))
    script = f'STATE_DIR={shlex.quote(str(tmp_path))}\nFAIL_FILE="$STATE_DIR/f"\nFEDHUB_HOST={shlex.quote(host)}\n' + _watch_block() + '\necho RAN\n'
    marker.write_text(f'{int(time.time()) + 600}\n')
    r = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
    assert r.returncode == 0 and 'RAN' not in r.stdout          # stood down
    marker.write_text('0\n')
    r = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
    assert 'RAN' in r.stdout                                     # expired -> runs normally


def test_fedhub_watch_stands_down_before_any_ssh():
    assert FEDHUB_WATCH.index('remotehost-maintenance.') < FEDHUB_WATCH.index('SSH_CMD=')


# ---------------------------------------------------------------------------
# routes + card wiring
# ---------------------------------------------------------------------------
RH_ROUTES = re.findall(r"@app\.route\('(/api/console/remotehosts[^']*)'(?:, methods=\[([^\]]*)\])?\)\n(@\w+)", APP)


def test_every_route_is_login_required():
    assert len(RH_ROUTES) == 6
    assert all(dec == '@login_required' for _u, _m, dec in RH_ROUTES)


@pytest.mark.parametrize('fn', ['console_remotehost_os_upgrade_start_api', 'console_remotehost_reboot_api'])
def test_destructive_starts_need_the_console_password(fn):
    assert '_require_admin_password(' in _fn(fn)


def test_startup_resumes_the_watch():
    assert '_startup_rhost_watch()' in APP[APP.index('def _startup_dbserver_watch'):] and 'if _startup_rhost_watch():' in APP


def test_card_ack_phrase_matches_the_backend():
    assert "remotehost:'%s'" % _ns()['_RHOST_ACK'] in CONSOLE


def test_card_calls_the_routes_through_the_key():
    assert "'/api/console/remotehosts/'+encodeURIComponent(_rhKey)+'/'" in CONSOLE
    assert "fetch('/api/console/remotehosts'," in CONSOLE
    assert "osupOpenPreflight('remotehost',h.key,h.host)" in CONSOLE


# ---------------------------------------------------------------------------
# W4.g.2 — Federation Hub's MongoDB 8.x -> 7.0 before the flip (row 5, host B)
# ---------------------------------------------------------------------------
MONGO7 = APP[APP.index('_OS_UPGRADE_SH_MONGO7 = ('):APP.index('_OS_UPGRADE_SH_SNAPSHOT_HEAD = (')]


def _mongo7_text():
    ns = {}
    exec(compile(MONGO7, 'app.py:mongo7', 'exec'), ns)
    return ns['_OS_UPGRADE_SH_MONGO7']


def test_mongo7_runs_before_the_snapshot_in_the_core_and_remote_jobs_only():
    ns = _ns()
    rs = ns['_os_upgrade_remotehost_script']()
    m = _mongo7_text()
    assert m in rs and rs.index(m) < rs.index(ns['_OS_UPGRADE_SH_SNAPSHOT_HEAD']) and rs.index(ns['_OS_UPGRADE_SH_HOLDS']) < rs.index(m)
    core = _fn('_os_upgrade_script')
    assert '_OS_UPGRADE_SH_HOLDS,\n        _OS_UPGRADE_SH_MONGO7,\n        _OS_UPGRADE_SH_SNAPSHOT_HEAD,' in core
    assert '_OS_UPGRADE_SH_MONGO7' not in _fn('_os_upgrade_dbserver_script')     # W4.e untouched


def _run_mongo7(tmp_path, mongo_ver, mfdt):
    """Run the real fragment under bash with every system command stubbed into a log."""
    bin_ = tmp_path / 'bin'
    bin_.mkdir()
    log = tmp_path / 'calls.log'
    for cmd in ('systemctl', 'apt-get', 'curl', 'gpg', 'install', 'date', 'mv'):
        (bin_ / cmd).write_text(f'#!/bin/bash\necho "{cmd} $*" >> {log}\n[ "{cmd}" = date ] && echo 20261026120000\nexit 0\n')
    (bin_ / 'dpkg-query').write_text(f'#!/bin/bash\necho -n "{mongo_ver}"\n[ -n "{mongo_ver}" ]\n')
    (bin_ / 'mongosh').write_text('#!/bin/bash\necho 1\n')
    for f in bin_.iterdir():
        f.chmod(0o755)
    fhb = tmp_path / 'broker.yml'
    fhb.write_text(f'v2Enabled: true\nmissionFederationDisruptionEnabled: {"true" if mfdt else "false"}\n')
    frag = _mongo7_text().replace('/opt/tak/federation-hub/configs/federation-hub-broker.yml', str(fhb)) \
                         .replace('/etc/apt/sources.list.d/', str(tmp_path) + '/') \
                         .replace('[ -d /var/lib/mongodb ]', '[ -d /nonexistent-but-mv-is-stubbed ] || true; [ 1 = 1 ]')
    script = (f'STATUS={tmp_path}/status\nTS() {{ echo T; }}\nwait_for_apt() {{ return 0; }}\n' + frag + 'echo AFTER\n')
    r = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                       env={'PATH': f'{bin_}:/usr/bin:/bin'})
    calls = log.read_text() if log.exists() else ''
    status = (tmp_path / 'status').read_text().strip() if (tmp_path / 'status').exists() else ''
    return r, calls, status


@pytest.mark.skipif(not shutil.which('bash'), reason='bash not available')
def test_mongo7_is_a_noop_without_mongodb_8(tmp_path):
    for v in ('', '7.0.45', '4.4.29'):
        sub = tmp_path / (v or 'none')
        sub.mkdir()
        r, calls, status = _run_mongo7(sub, v, mfdt=False)
        assert 'AFTER' in r.stdout and calls == '' and status == ''


@pytest.mark.skipif(not shutil.which('bash'), reason='bash not available')
def test_mongo7_refuses_when_mfdt_holds_data_and_touches_nothing(tmp_path):
    r, calls, status = _run_mongo7(tmp_path, '8.0.34', mfdt=True)
    assert r.returncode == 1 and 'AFTER' not in r.stdout
    assert status == 'failed:mongo-7' and 'MFDT' in r.stdout and 'keep this host on 22.04' in r.stdout
    assert calls == ''                                   # not even systemctl stop


@pytest.mark.skipif(not shutil.which('bash'), reason='bash not available')
def test_mongo7_swaps_8_to_7_keeping_the_old_data(tmp_path):
    r, calls, status = _run_mongo7(tmp_path, '8.0.34', mfdt=False)
    assert r.returncode == 0 and 'AFTER' in r.stdout, r.stdout + r.stderr
    order = [l.split()[0] + ' ' + (l.split()[1] if len(l.split()) > 1 else '') for l in calls.splitlines()]
    assert order.index('systemctl stop') < order.index('mv /var/lib/mongodb') < order.index('apt-get remove') \
        < order.index('apt-get install') < order.index('systemctl start')
    assert 'mv /var/lib/mongodb /var/lib/mongodb.pre-7.0-20261026120000' in calls      # kept, never rm
    assert 'rm -rf' not in _mongo7_text() and 'purge' not in _mongo7_text()
    assert 'jammy/mongodb-org/7.0' in (tmp_path / 'mongodb-org-7.0.list').read_text()
    assert status == 'running:mongo-7'


def test_repos_noble_keeps_the_mongodb_7_list_on_jammy_and_tolerates_its_refresh():
    flip = _ns()['_OS_UPGRADE_SH_FLIP']
    assert 'mongodb-org-7.0.list) cp -a "$f"' in flip and 'continue ;; esac' in flip
    assert 'repo[.]mongodb[.]org' in flip


def test_new_fedhub_deploys_install_mongodb_7_from_jammy():
    assert "MONGO_VER=7.0; distro_codename=jammy; " in APP
    assert 'MONGO_VER=8.0' not in APP


@pytest.mark.parametrize('mongo,mfdt,want', [('8.0.34', False, (True, True)), ('8.0.34', True, (False, False)),
                                            ('7.0.45', False, None), ('', False, None)])
def test_remote_preflight_fedhub_mongo(mongo, mfdt, want):
    c = _checks(_ns()['_rhost_preflight'](_rhkey(B), probe=_probe(mongo=mongo, mfdt=mfdt))).get('fedhub_mongo')
    if want is None:
        assert c is None
    else:
        assert (c['pass'], c['notice']) == want


def test_probe_reads_mongo_version_and_mfdt():
    t = _ns()['_rhost_probe_text']('full')
    assert "'mongodb-org-server'" in t and 'missionFederationDisruptionEnabled' in t
