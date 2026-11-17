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
"""The 5.8 migration and Diagnostics must say when TAK Server's web API is not serving (ops #902).

Field (customer report, 2026-11-17): the 5.8 migration ended "ok" and the report said
`service: active`, but 8443 was closed. TAK's API had failed to bind 8446 and a Federation Hub
certificate answered there. TAK Portal got "connection refused" on 8443 for hours.
The functions are cut out of app.py and run with the system calls faked.
"""

import os
import pathlib
import re
import shlex
import subprocess as _real_subprocess
import time
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

# The connectors and listeners of the field report.
CORE_CONFIG = """<Configuration>
 <network>
  <connector port="8443" _name="https"/>
  <connector port="8444" _name="fed_https"/>
  <connector port="8446" clientAuth="false" _name="LetsEncrypt" keystore="JKS"/>
  <input _name="stdssl" protocol="tls" port="8089"/>
 </network>
</Configuration>"""

# `ss -tlnH` from the box: 8446 listens, 8443 does not.
SS_BROKEN = """\
LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*
LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*
LISTEN 0 4096 *:8089 *:*
LISTEN 0 4096 *:8446 *:*
LISTEN 0 4096 *:9100 *:*
LISTEN 0 4096 [::]:11935 [::]:*
"""
SS_HEALTHY = SS_BROKEN + "LISTEN 0 4096 *:8443 *:*\n"

SS_P_HOLDER = 'LISTEN 0 100 *:8446 *:* users:(("java",pid=4242,fd=88))'


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _load(*names, **extra):
    n = {'re': re, 'time': time, 'subprocess': _real_subprocess, 'os': os}
    n.update(extra)
    for name in names:
        m = re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M)
        if m:                      # absent on the base branch: the test then fails on its assertion
            exec(compile(m.group(0), 'app.py:' + name, 'exec'), n)
    return n


HELPERS = ('_tak_api_required_ports', '_tak_listening_ports', '_tak_port_holder',
           '_tak_port_holder_now', '_tak_api_wait_serving', '_tak_api_not_serving_lines')


# ── the pure helpers ──────────────────────────────────────────────────────────────────────

def test_required_ports_are_the_https_and_letsencrypt_connectors():
    n = _load(*HELPERS)
    # 8444 (fed_https) is not up on a box that does not federate, so it must not be required.
    assert n['_tak_api_required_ports'](CORE_CONFIG) == [8443, 8446]
    assert n['_tak_api_required_ports']('') == [8443]
    assert n['_tak_api_required_ports']('<connector port="8444" _name="fed_https"/>') == [8443]
    # a stock 5.8 CoreConfig (the box test): https 8443 + cert_https 8446, fed_https 8444 left out
    stock = ('<connector port="8443" _name="https"/><connector port="8444" useFederationTruststore="true" '
             '_name="fed_https"/><connector port="8446" clientAuth="false" _name="cert_https"/>')
    assert n['_tak_api_required_ports'](stock) == [8443, 8446]


def test_listening_ports_reads_every_address_shape():
    n = _load(*HELPERS)
    assert n['_tak_listening_ports'](SS_BROKEN) == {22, 53, 8089, 8446, 9100, 11935}
    assert n['_tak_listening_ports']('') == set()


def test_holder_is_named_and_federation_hub_is_recognised():
    n = _load(*HELPERS)
    assert n['_tak_port_holder'](SS_P_HOLDER) == 'java (pid 4242)'
    hub = '/usr/bin/java\0-jar\0/opt/tak/federation-hub/federation-hub-ui.jar\0'
    assert n['_tak_port_holder'](SS_P_HOLDER, hub) == 'java (pid 4242) = Federation Hub'
    assert n['_tak_port_holder']('', hub) == ''


def test_wait_returns_when_the_port_opens_and_gives_up_naming_the_holder():
    n = _load(*HELPERS)
    wait = n['_tak_api_wait_serving']
    clock = {'t': 0.0}
    seen = iter([{8446}, {8446}, {8443, 8446}])
    ok = wait([8443, 8446], timeout_s=60, poll_s=10, stable_s=0, listening=lambda: next(seen),
              holder=lambda p: 'x', sleep=lambda s: clock.update(t=clock['t'] + s),
              clock=lambda: clock['t'])
    assert ok['ok'] and ok['missing'] == []

    clock['t'] = 0.0
    bad = wait([8443, 8446], timeout_s=60, poll_s=10, stable_s=0, listening=lambda: {8446},
               holder=lambda p: 'java (pid 4242) = Federation Hub',
               sleep=lambda s: clock.update(t=clock['t'] + s), clock=lambda: clock['t'])
    assert not bad['ok'] and bad['missing'] == [8443]
    assert bad['holders'] == {8446: 'java (pid 4242) = Federation Hub'}
    text = '\n'.join(n['_tak_api_not_serving_lines'](bad))
    assert 'NOT listening on port 8443' in text
    assert 'Port 8446 is already in use' in text and 'Federation Hub' in text


def test_a_port_that_opens_and_closes_again_is_not_serving():
    # Box test (ops #902): with 8446 held by another program, 8443 was seen listening once, then
    # TAK's API gave up and closed it. The old check returned ok on that first sighting.
    n = _load(*HELPERS)
    wait = n['_tak_api_wait_serving']
    clock = {'t': 0.0}
    timeline = iter([set(), {8443}, set(), set(), set(), set(), set(), set(), set(), set()])
    res = wait([8443], timeout_s=40, poll_s=10, stable_s=60, listening=lambda: next(timeline),
               holder=lambda p: '', sleep=lambda s: clock.update(t=clock['t'] + s),
               clock=lambda: clock['t'])
    assert not res['ok'] and res['missing'] == [8443]
    # and a port that opens and stays is ok only after the stable wait
    clock['t'] = 0.0
    steady = {'n': 0}

    def up():
        steady['n'] += 1
        return {8443}
    res = wait([8443], timeout_s=40, poll_s=10, stable_s=60, listening=up, holder=lambda p: '',
               sleep=lambda s: clock.update(t=clock['t'] + s), clock=lambda: clock['t'])
    assert res['ok'] and clock['t'] >= 60 and steady['n'] >= 7


# ── PROOF TEST: the 5.8 migration may not end "ok" while the API is down ──────────────────

def _migrate(api_ports_up):
    """Run run_takserver_58_migration to its end on a managed database (so no upgrade-db.sh),
    with the box's listeners faked as api_ports_up. Returns (log, status)."""
    pf_calls = []

    def pf():
        pf_calls.append(1)
        return {'ready': True, 'facts': {'pg_running_major': 15 if len(pf_calls) == 1 else 18}}

    def fake_run(argv, *a, **k):
        out = ''
        if argv[:2] == ['dpkg-query', '-W']:
            out = 'install ok installed' if argv[2] == '-f=${Status}' else '5.8-RELEASE103'
        return _real_subprocess.CompletedProcess(argv, 0, out, '')

    fake_os = types.SimpleNamespace(
        path=types.SimpleNamespace(exists=lambda p: True, basename=os.path.basename,
                                   dirname=os.path.dirname))
    n = {
        'os': fake_os, 'shlex': shlex, 'time': time, 're': re,
        'subprocess': types.SimpleNamespace(run=fake_run),
        'tak58_log': [], 'tak58_status': {},
        '_sudo_wrap': lambda argv: argv,
        '_distro_family': lambda: 'debian',
        '_tak_58_preflight': pf,
        '_cotdb_fmt_bytes': str,
        '_tak_58_backup': lambda plog=None: {'ok': True, 'snapshot_path': '/opt/tak/snapshots/x'},
        '_tak_upgrade_apt_install_streamed': lambda cmd, cwd, log, timeout_sec=0: 0,
        '_pgdg_gis_pin_ensure': lambda log_fn=None: True,
        '_run_dpkg_configure_a': lambda say, log: 0,
        '_get_tak_deployment_config': lambda s: {'mode': 'external_db',
                                                 'external_db': {'host': 'db.example'}},
        '_tak58_external_schema_version': lambda edb: 106,
        '_TAK58_MIN_SCHEMA_VERSION': 100,
        '_read_own_or_priv': lambda p: CORE_CONFIG,
        'load_settings': dict,
        'TAK_PG_MAJOR': 18,
        '_TAK58_UPGRADE_DB_SH': '/nonexistent/upgrade-db.sh',
        '_TAK58_MANAGED_STORAGE': 'provider-managed',
    }
    for helper in ('_tak58_fmt_measured', '_tak58_preflight_summary_line') + HELPERS:
        m = re.search(rf'^def {helper}\(.*?(?=^\S)', APP, re.S | re.M)
        if m:
            exec(compile(m.group(0), 'app.py:' + helper, 'exec'), n)
    if '_tak_api_wait_serving' in n:
        real_wait = n['_tak_api_wait_serving']
        n['_tak_api_wait_serving'] = lambda req, **k: real_wait(
            req, timeout_s=0, poll_s=0, stable_s=0, listening=lambda: set(api_ports_up),
            holder=lambda p: 'java (pid 4242) = Federation Hub')
    exec(compile(_cut('run_takserver_58_migration'), 'app.py:run_takserver_58_migration', 'exec'), n)
    log, status = [], {}
    n['run_takserver_58_migration']('/tmp/takserver_5.8-RELEASE103_all.deb', log=log, status=status)
    return log, status


def test_migration_is_not_ok_when_the_api_never_opens_its_port():
    # The field-report state: 8446 is held by something else, 8443 is closed.
    log, status = _migrate({8089, 8446})
    text = '\n'.join(log)
    assert status.get('error') and not status.get('complete'), text
    assert 'NOT listening on port 8443' in text
    assert 'Port 8446 is already in use' in text and 'Federation Hub' in text
    assert 'MID-UPGRADE' not in text          # the database did migrate: do not call it mid-upgrade
    assert 'Migration complete' not in text


def test_migration_is_ok_when_the_api_listens():
    log, status = _migrate({8089, 8443, 8446})
    text = '\n'.join(log)
    assert status.get('complete') and not status.get('error'), text
    assert 'web API is listening on ports 8443, 8446' in text
    assert 'Migration complete' in text


# ── Diagnostics ───────────────────────────────────────────────────────────────────────────

def _diag():
    return _load('_tak_api_required_ports', '_tak_listening_ports', '_tak_port_holder',
                 '_tak_port_holder_now', '_diag_tak_api_ports')


def test_diagnostics_names_the_closed_port_and_who_holds_the_other():
    n = _diag()
    out = n['_diag_tak_api_ports'](CORE_CONFIG, True, ss_text=SS_BROKEN,
                                   holder=lambda p: 'java (pid 4242) = Federation Hub')
    text = '\n'.join(out)
    assert 'NOT listening on 8443' in text
    assert 'port 8446 is held by: java (pid 4242) = Federation Hub' in text


def test_diagnostics_says_all_listening_on_a_healthy_box_and_stays_quiet_when_stopped():
    n = _diag()
    assert n['_diag_tak_api_ports'](CORE_CONFIG, True, ss_text=SS_HEALTHY) == [
        'TAK API web ports (8443, 8446): all listening']
    stopped = n['_diag_tak_api_ports'](CORE_CONFIG, False, ss_text='')
    assert len(stopped) == 1 and 'not checked' in stopped[0]


def test_failed_unit_detail_gives_the_result_and_the_journal():
    calls = []

    def fake_cmd(argv, timeout=20, priv=True, stdin=None):
        calls.append(argv)
        if argv[:2] == ['systemctl', 'show']:
            return 'Result=timeout\nExecMainStatus=0'
        return '2026-11-17T14:49:02+0000 ots systemd[1]: takrestartwatch.service: Failed with result \'timeout\'.'

    n = _load('_diag_failed_unit_detail', _diag_cmd=fake_cmd)
    out = n['_diag_failed_unit_detail'](
        '● takrestartwatch.service loaded failed failed Guard Dog Unexpected-Restart Detector')
    text = '\n'.join(out)
    assert 'takrestartwatch.service: Result=timeout' in text
    assert "Failed with result 'timeout'" in text
    assert n['_diag_failed_unit_detail']('') == []
    assert ['systemctl', 'show', 'takrestartwatch.service'] == calls[0][:3]
