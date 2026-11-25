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
"""Going back to an older TAK Server package on Ubuntu (ops #1218).

Field (test12, Ubuntu 22.04, R105 -> R104):
- the Update button with the R104 .deb failed with "Packages were downgraded and -y was used
  without --allow-downgrades" (exit 100) - the Rocky path (dnf) worked;
- the Rollback button reported "complete" while dpkg still held R105.
The functions under test are cut out of app.py and run with the package manager faked.
"""

import os
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _ns(installed='5.8-RELEASE105', snapshots=None, extra=None):
    n = {
        'os': os, 're': re,
        '_get_takserver_version_info': lambda: {'version': installed},
        'load_settings': lambda: {'tak_snapshots': snapshots or []},
    }
    n.update(extra or {})
    exec(re.search(r'^_TAK_RELEASE_RE = .*$', APP, re.M).group(0), n)
    for fn in ('_tak_release_key', '_tak_package_downgrade', '_tak_fmt_release',
               '_tak_cross_minor_downgrade_message', '_tak_log_if_downgrade',
               '_tak_rollback_package_note'):
        exec(compile(_cut(fn), 'app.py:' + fn, 'exec'), n)
    return n


# ── the update path installs an older package ────────────────────────────────

def test_apt_install_of_an_older_deb_passes_allow_downgrades():
    seen = {}

    class _P:
        def __init__(self, cmd, **kw):
            seen['cmd'] = cmd
            self.stdout = types.SimpleNamespace(readline=lambda: '')
            self.returncode = 0

        def wait(self, timeout=None):
            return 0

    # No new helper needed here: on the base branch this fails on the missing flag itself.
    n = {
        'os': os, 'subprocess': types.SimpleNamespace(Popen=_P, PIPE=-1, STDOUT=-2,
                                                      TimeoutExpired=Exception),
        'shlex': __import__('shlex'), 'threading': __import__('threading'),
        '_pgdg_gis_pin_ensure': lambda log_fn=None: True,
    }
    exec(compile(_cut('_tak_upgrade_apt_install'), 'app.py:apt', 'exec'), n)
    assert n['_tak_upgrade_apt_install']('/tmp', 'takserver_5.8-RELEASE104_all.deb', []) == 0
    assert 'apt-get install -y --allow-downgrades ./takserver_5.8-RELEASE104_all.deb' in seen['cmd']


def test_two_server_database_install_also_allows_downgrades():
    assert re.search(r'apt-get install -y --allow-downgrades \./\{db_name\}', APP)


def test_older_release_in_same_minor_is_a_warned_downgrade_not_a_refusal():
    n = _ns('5.8-RELEASE105')
    d = n['_tak_package_downgrade']('takserver_5.8-RELEASE104_all.deb')
    assert d and d['cross_minor'] is False
    assert n['_tak_cross_minor_downgrade_message']('takserver_5.8-RELEASE104_all.deb') is None
    log = []
    assert n['_tak_log_if_downgrade']('takserver_5.8-RELEASE104_all.deb', log.append, 'pre-upgrade-1')
    text = '\n'.join(log)
    assert 'DOWNGRADE' in text and '5.8-RELEASE105' in text and 'pre-upgrade-1' in text


def test_same_or_newer_package_is_not_a_downgrade():
    n = _ns('5.8-RELEASE105')
    for pkg in ('takserver_5.8-RELEASE105_all.deb', 'takserver_5.8-RELEASE106_all.deb',
                'takserver_5.9-RELEASE1_all.deb', 'takserver_odd-name.deb'):
        assert n['_tak_package_downgrade'](pkg) is None
        log = []
        assert n['_tak_log_if_downgrade'](pkg, log.append) is False and not log


def test_unreadable_installed_version_never_blocks_an_update():
    n = _ns('')
    assert n['_tak_package_downgrade']('takserver_5.8-RELEASE104_all.deb') is None
    assert n['_tak_cross_minor_downgrade_message']('takserver_5.7-RELEASE1_all.deb') is None


def test_a_different_minor_is_refused_with_a_reason():
    # 5.8 -> 5.7 package: the database is on PostgreSQL 18 and a newer schema.
    n = _ns('5.8-RELEASE105')
    msg = n['_tak_cross_minor_downgrade_message']('takserver_5.7-RELEASE32_all.deb')
    assert msg and 'takserver_5.7-RELEASE32_all.deb' in msg and '5.8-RELEASE105' in msg
    assert 'major.minor' in msg and 'Snapshots & Recovery' in msg


def test_route_and_job_use_the_downgrade_helpers():
    route = re.search(r"^def takserver_update\(\):.*?(?=^@app\.route)", APP, re.S | re.M).group(0)
    assert route.count('_tak_cross_minor_downgrade_message(') == 2  # single and two-server (.deb)
    job = _cut('run_takserver_upgrade')
    assert job.index('_tak_log_if_downgrade(pkg_name') < job.index('_tak_upgrade_apt_install(')
    two = _cut('run_takserver_upgrade_two_server')
    assert two.index('_tak_log_if_downgrade(core_name') < two.index('_tak_upgrade_apt_install(')


# ── the rollback says what it restored ───────────────────────────────────────

def test_rollback_after_update_says_the_newer_package_is_still_installed():
    snaps = [{'label': 'pre-upgrade-1', 'tak_version': '5.8-RELEASE104'}]
    note = _ns('5.8-RELEASE105', snaps)['_tak_rollback_package_note']('pre-upgrade-1')
    assert 'still 5.8-RELEASE105' in note and '5.8-RELEASE104' in note
    assert 'does not reinstall' in note and 'Update' in note


def test_rollback_on_the_same_version_says_so():
    snaps = [{'label': 's', 'tak_version': '5.8-RELEASE105'}]
    note = _ns('5.8-RELEASE105', snaps)['_tak_rollback_package_note']('s')
    assert 'still' not in note and '5.8-RELEASE105' in note


def test_rollback_note_survives_missing_data():
    assert _ns('', [])['_tak_rollback_package_note']('x') == 'The TAK Server package was not changed.'
    note = _ns('5.8-RELEASE105', [{'label': 'x', 'tak_version': None}])['_tak_rollback_package_note']('x')
    assert '5.8-RELEASE105' in note


def test_last_rollback_line_is_not_a_bare_complete():
    # the Snapshots screen shows only the last log line (templates/takserver.html restoreSnapshot)
    body = _cut('_tak_rollback')
    assert 'configuration, certificates and database restored. {_pkg_note}' in body
    assert 'rollback [{label}]: complete"' not in body


# ── the broker keeps dpkg's `downgrade` for an apt call that asks for it ────────
# Measured on a fresh Ubuntu 22.04 box (non-root console, TAK Server R105 -> R104): the
# broker's DPKG_FORCE=confdef,confold replaces dpkg's defaults, `downgrade` included, so
# `apt-get install --allow-downgrades ./R104.deb` planned the downgrade, dpkg said
# "will not downgrade ... skipping" in term.log only, and apt exited 0 on R105.

def _broker():
    import importlib.util
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops1218',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _apt_env(monkeypatch, argv):
    B = _broker()
    monkeypatch.delenv('DPKG_FORCE', raising=False)
    seen = {}

    def run(argv_, **kw):
        seen['env'] = kw.get('env')
        return types.SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
    monkeypatch.setattr(B, '_run_maybe_ufw_locked', run)
    monkeypatch.setattr(B, '_pkg_stage_verified', lambda a, cwd, t: (a, None))
    assert B._do_exec({'argv': argv})['ok']
    return seen['env']


def test_broker_apt_with_allow_downgrades_keeps_dpkg_downgrade(monkeypatch):
    env = _apt_env(monkeypatch, ['apt-get', 'install', '-y', '--allow-downgrades',
                                 './takserver_5.8-RELEASE104_all.deb'])
    assert env['DPKG_FORCE'].split(',') == ['confdef', 'confold', 'downgrade']


def test_broker_apt_without_allow_downgrades_never_gets_downgrade(monkeypatch):
    env = _apt_env(monkeypatch, ['apt-get', 'install', '-y', './takserver_5.8-RELEASE105_all.deb'])
    assert env['DPKG_FORCE'] == 'confdef,confold'
