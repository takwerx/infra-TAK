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
"""The Guard Dog redeploy only rewrites scripts that changed.

Field report (GH #98 thread, 2026-10-10): Update Now logged "Guard Dog: 1 script(s) updated"
while nearly every file in /opt/tak-guarddog/ got a new mtime at an identical byte size. The
startup copy (_auto_update_guarddog) was honest; the post-update run_guarddog_deploy() that
follows it rewrote every script unconditionally and logged no count.
"""

import os
import pathlib
from datetime import datetime

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
SRC = APP[APP.index('def run_guarddog_deploy(alert_email):'):APP.index("@app.route('/nodered')")]
GD = '/opt/tak-guarddog'


class _StopAfterScripts(Exception):
    pass


@pytest.fixture
def h(tmp_path):
    scripts = tmp_path / 'repo' / 'scripts' / 'guarddog'
    scripts.mkdir(parents=True)
    box = tmp_path / 'box'
    box.mkdir()
    writes, chmods = [], []

    def _box(path):
        assert path.startswith(GD + '/'), path
        return box / path[len(GD) + 1:]

    def _read_priv(path):
        return _box(path).read_text()

    def _write_priv(path, content, mode='w', perm=None):
        writes.append(os.path.basename(path))
        _box(path).write_text(content)

    def _chmod_priv(path, mode):
        if path.startswith(GD + '/') and path != GD + '/known_hosts':
            chmods.append(os.path.basename(path))

    def _tak_is_container():
        raise _StopAfterScripts()   # first call after the script loop

    real_exists = os.path.exists
    log, status = [], {}
    ns = {
        'os': os, 'datetime': datetime, 'BASE_DIR': str(tmp_path / 'repo'), 'VERSION': '10.2.11-alpha',
        'AUTHENTIK_VETTED_RELEASE': '2025.10', 'guarddog_deploy_log': log,
        'guarddog_deploy_status': status, 'subprocess': None,
        '_sudo_wrap': lambda a: a, '_makedirs_priv': lambda d: None,
        '_read_priv': _read_priv, '_write_priv': _write_priv, '_chmod_priv': _chmod_priv,
        '_tak_is_container': _tak_is_container,
        'load_settings': lambda: {'guarddog_alert_email': 'ops@example.com'},
        '_get_tak_deployment_config': lambda s: {'mode': 'single'},
        '_get_fedhub_deployment_config': lambda s: {},
        '_guarddog_alert_recipient_warning': lambda s: '',
        '_safe_alert_email_list': lambda e: e or '',
        '_get_tak_cert_password': lambda s: 'atakatak',
    }
    exec(SRC, ns)

    def run(monkeypatch):
        monkeypatch.setattr(os.path, 'exists',
                            lambda p: True if p == '/opt/tak' else real_exists(p))
        writes.clear(); chmods.clear(); log.clear()
        ns['run_guarddog_deploy']('ops@example.com')
        assert any('Error' in l for l in log)   # stopped by _StopAfterScripts, after the loop
        return [l for l in log if 'Scripts installed' in l]

    # Every script the deploy list names, with a placeholder so rendering matters.
    names = [n.strip(" '\"") for n in
             __import__('re').findall(r"'((?:_gd-|gd-|send-|tak-)[\w.-]+\.(?:sh|py))'",
                                      SRC[:SRC.index('# Optional: monitors')])]
    for n in set(names):
        (scripts / n).write_text(f'#!/bin/bash\n# {n}\nV=CONSOLE_VERSION_PLACEHOLDER\n')
    return run, writes, chmods, box, scripts


def test_first_deploy_writes_everything(h, monkeypatch):
    run, writes, chmods, box, scripts = h
    lines = run(monkeypatch)
    assert len(writes) > 20
    assert lines and 'changed' in lines[0] and '0 already current' in lines[0]
    assert (box / 'tak-retention-guard.sh').read_text().endswith('V=10.2.11-alpha\n')


def test_redeploy_with_nothing_changed_writes_nothing(h, monkeypatch):
    run, writes, chmods, box, scripts = h
    run(monkeypatch)
    n = len(writes)
    mtimes = {p.name: p.stat().st_mtime_ns for p in box.iterdir()}
    lines = run(monkeypatch)
    assert writes == []
    assert {p.name: p.stat().st_mtime_ns for p in box.iterdir()} == mtimes
    assert lines == [lines[0]] and f'all {n} already current' in lines[0]
    # .sh files still get their +x re-asserted without a rewrite
    assert 'tak-retention-guard.sh' in chmods
    assert 'tak-health-endpoint.py' not in chmods


def test_redeploy_rewrites_only_the_changed_script(h, monkeypatch):
    run, writes, chmods, box, scripts = h
    run(monkeypatch)
    (scripts / 'tak-retention-guard.sh').write_text('#!/bin/bash\n# new\n')
    lines = run(monkeypatch)
    assert writes == ['tak-retention-guard.sh']
    assert '1 changed (tak-retention-guard.sh)' in lines[0]


def test_unreadable_dest_is_rewritten(h, monkeypatch):
    run, writes, chmods, box, scripts = h
    run(monkeypatch)
    (box / 'tak-cert-watch.sh').unlink()
    run(monkeypatch)
    assert writes == ['tak-cert-watch.sh']


def test_post_update_logs_the_deploy_count():
    i = APP.index('print("Post-update: auto-deploying Guard Dog")')
    block = APP[i:i + 1200]
    assert 'guarddog_deploy_log.clear()' in block
    assert "'Scripts installed' in _gd_line" in block
