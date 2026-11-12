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
"""On a two-server box, the Guard Dog DB scripts render the same from both writers.

Seen on test8 (two_server) after #107, 2026-10-10: every Update Now logged
"Scripts installed: 1 changed (tak-remotedb-watch.sh)" although the file's bytes were the
same before and after. The startup sync (_sync_guarddog_remote_db_from_settings) writes
EXTERNAL_DB="" and run_guarddog_deploy() left the literal placeholder, so each one rewrote
the other's version. The startup sync also rewrote all six DB scripts on every console start.
Uses the real scripts from scripts/guarddog/.
"""

import os
import pathlib
import re
from datetime import datetime

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
DEPLOY_SRC = APP[APP.index('def run_guarddog_deploy(alert_email):'):APP.index("@app.route('/nodered')")]
# From GUARDDOG_CONF_PATH: the sync writes guarddog.conf through _write_guarddog_conf() (#101).
SYNC_SRC = APP[APP.index("GUARDDOG_CONF_PATH = '/opt/tak-guarddog/guarddog.conf'"):
               APP.index('def _remotedb_host_port_from_tak_settings(')]
STARTUP_SRC = APP[APP.index('def _auto_update_guarddog():'):
                  APP.index('def _start_guarddog_background_at_boot(')]
# ops #645 W2 part 2a: every fill-in goes through _gd_install_script (old path: no broker).
GD_HELPER_SRC = APP[APP.index('_GD_PLACEHOLDER_RE = re.compile('):APP.index('def _write_priv(')]
GD = '/opt/tak-guarddog'
DB_SCRIPTS = ('tak-remotedb-watch.sh', 'tak-remotedb-auth-watch.sh', 'tak-cotdb-watch.sh',
              'tak-auto-vacuum.sh', 'tak-db-repack.sh', 'tak-retention-guard.sh')
TAK_CFG = {
    'mode': 'two_server',
    'server_one': {'host': '10.9.8.7', 'ssh_user': 'root', 'ssh_key_path': '/root/.ssh/id_rsa'},
    'database': {'port': 5432},
}


class _StopAfterScripts(Exception):
    pass


class _Proc:
    @staticmethod
    def run(*a, **k):
        return None


@pytest.fixture
def h(tmp_path, monkeypatch):
    box = tmp_path / 'box'
    box.mkdir()
    writes = []

    def _box(path):
        assert path.startswith(GD + '/'), path
        return box / path[len(GD) + 1:]

    def _write_priv(path, content, mode='w', perm=None):
        writes.append(os.path.basename(path))
        _box(path).write_text(content)

    def _tak_is_container():
        raise _StopAfterScripts()   # first call after run_guarddog_deploy's script loop

    log = []
    ns = {
        'os': os, 'json': __import__('json'), 're': re, 'datetime': datetime, 'BASE_DIR': str(REPO),
        'VERSION': '10.2.11-alpha', 'AUTHENTIK_VETTED_RELEASE': '2025.10',
        'guarddog_deploy_log': log, 'guarddog_deploy_status': {}, 'subprocess': _Proc,
        '_sudo_wrap': lambda a: a, '_makedirs_priv': lambda d: None,
        '_read_priv': lambda p: _box(p).read_text(), '_write_priv': _write_priv,
        '_chmod_priv': lambda p, m: None, '_tak_is_container': _tak_is_container,
        'load_settings': lambda: {'guarddog_alert_email': 'ops@example.com'},
        '_get_tak_deployment_config': lambda s: TAK_CFG,
        '_find_ssh_key_for_server_one': lambda s1: '/root/.ssh/id_rsa',
        '_get_fedhub_deployment_config': lambda s: {},
        '_guarddog_alert_recipient_warning': lambda s: '',
        '_safe_alert_email_list': lambda e: e or '',
        '_get_tak_cert_password': lambda s: 'atakatak',
        '_broker_should_route': lambda: False,
    }
    exec(GD_HELPER_SRC, ns)
    exec(DEPLOY_SRC, ns)
    exec(SYNC_SRC, ns)
    exec(STARTUP_SRC, ns)
    real_exists, real_isdir = os.path.exists, os.path.isdir
    monkeypatch.setattr(os.path, 'exists',
                        lambda p: True if p in ('/opt/tak', GD) else real_exists(p))
    monkeypatch.setattr(os.path, 'isdir', lambda p: True if p == GD else real_isdir(p))

    def deploy():
        writes.clear(); log.clear()
        ns['run_guarddog_deploy']('ops@example.com')
        return [l for l in log if 'Scripts installed' in l]

    def sync():
        writes.clear()
        ok, msg = ns['_sync_guarddog_remote_db_from_settings']({'guarddog_alert_email': 'ops@example.com'})
        assert ok, msg
        return [w for w in writes if w.endswith('.sh')]

    def startup():
        writes.clear()
        try:
            ns['_auto_update_guarddog']()
        except AssertionError:
            pass                 # reached the systemd-unit installs after the script loop
        return [w for w in writes if w.endswith('.sh')]

    return deploy, sync, writes, box, startup


def test_both_writers_render_the_db_scripts_identically(h):
    deploy, sync, writes, box, startup = h
    deploy()
    by_deploy = {n: (box / n).read_text() for n in DB_SCRIPTS}
    assert sync() == []          # nothing to rewrite: same bytes
    for n in DB_SCRIPTS:
        assert (box / n).read_text() == by_deploy[n], n
    assert 'EXTERNAL_DB=""' in by_deploy['tak-remotedb-watch.sh']


def test_update_after_startup_sync_reports_nothing_changed(h):
    deploy, sync, writes, box, startup = h
    deploy()                     # box as installed
    sync()                       # console start
    lines = deploy()             # post-update redeploy
    assert [w for w in writes if w.endswith('.sh')] == []
    assert 'already current' in lines[0] and 'changed (' not in lines[0], lines[0]


def test_startup_sync_leaves_identical_scripts_alone(h):
    deploy, sync, writes, box, startup = h
    first = sync()
    assert sorted(first) == sorted(DB_SCRIPTS)
    mtimes = {n: (box / n).stat().st_mtime_ns for n in DB_SCRIPTS}
    assert sync() == []
    assert {n: (box / n).stat().st_mtime_ns for n in DB_SCRIPTS} == mtimes


def test_console_start_after_update_rewrites_no_db_script(h):
    deploy, sync, writes, box, startup = h
    deploy()                     # box as installed / last Update Now
    assert [w for w in startup() if w in DB_SCRIPTS] == []   # startup copy
    assert sync() == []          # startup two-server sync
    lines = deploy()             # post-update redeploy
    assert 'changed (' not in lines[0], lines[0]


def test_deploy_leaves_an_identical_tasklog_purge_script_alone():
    # Written outside the counted script loop, so it gets its own compare (seen rewritten
    # with identical bytes on every Update Now on test8).
    i = DEPLOY_SRC.index("_ak_purge_path = '/opt/tak-guarddog/tak-authentik-tasklog-purge.sh'")
    block = DEPLOY_SRC[i:i + 600]
    # ops #645 W2 part 2b: it goes through the shared installer, which compares first:
    # root's gd_render returns changed=False on the same bytes, and the old-broker path
    # reads the file and only chmods it when it is identical.
    assert "_gd_install_script('tak-authentik-tasklog-purge.sh', _AUTHENTIK_TASKLOG_PURGE_SCRIPT, {})" in block
    assert '_write_priv(_ak_purge_path' not in block
    assert GD_HELPER_SRC.index('if _read_priv(dest) == content:') < GD_HELPER_SRC.index('_write_priv(dest, content')


def test_startup_sync_still_rewrites_a_changed_script(h):
    deploy, sync, writes, box, startup = h
    sync()
    (box / 'tak-retention-guard.sh').write_text('#!/bin/bash\n# stale\n')
    assert sync() == ['tak-retention-guard.sh']
