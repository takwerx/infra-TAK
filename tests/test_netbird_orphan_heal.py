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
"""NetBird orphaned-store heal + store-key persistence (ops #150).

Field (test6, test8): every NetBird user row was encrypted under a key from the 0.73
ephemeral-key era, and the console held no PAT. SSO login spun forever on 401 'token
invalid' ('decrypt user ... cipher: message authentication failed'), and the heal never ran:
its no-PAT branch only accepted an EMPTY store. test6 also had its key in config.yaml but not
in settings, so the next deploy would have minted a fresh key and orphaned the store again.

app.py cannot be imported in a test, so the functions are cut out of it and run: the code
under test is the shipped text.
"""

import ast
import datetime
import io
import json
import os
import pathlib
import sqlite3
import subprocess
import urllib.request

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_WANT = {'_heal_netbird_orphaned_store', '_ensure_netbird_store_key_setting', '_netbird_store_key_needed',
         '_netbird_version_tuple'}
KEY = 'q' * 43 + '='
SIG = 'ERRO failed to get user by ID x: decrypt user: decrypt name: decrypt: cipher: message authentication failed'


def _box(tmp_path, monkeypatch, users=2, key_in_config=True):
    home = tmp_path / 'home'
    nb = home / 'netbird'
    (nb / 'data').mkdir(parents=True)
    cfg = 'server:\n  authSecret: "s"\n'
    if key_in_config:
        cfg += f'  store:\n    encryptionKey: "{KEY}"\n'
    (nb / 'config.yaml').write_text(cfg)
    (nb / 'docker-compose.yml').write_text('services: {}\n')
    db = sqlite3.connect(nb / 'data' / 'store.db')
    db.execute('CREATE TABLE users (id text)')
    db.executemany('INSERT INTO users VALUES (?)', [(f'u{i}',) for i in range(users)])
    db.commit()
    db.close()
    monkeypatch.setenv('HOME', str(home))
    return nb


def _load(settings, monkeypatch, logs='', setup_required=False, pat_valid=False):
    parts = [ast.get_source_segment(APP, n) for n in ast.parse(APP).body
             if isinstance(n, ast.FunctionDef) and n.name in _WANT]
    assert len(parts) == len(_WANT), 'a function under test was renamed or removed'
    calls = {'exec': [], 'deploy': 0, 'saved': 0}

    def run(argv, **k):
        if argv[:2] == ['docker', 'logs']:
            return subprocess.CompletedProcess(argv, 0, logs, '')
        if argv[:2] == ['docker', 'exec']:
            calls['exec'].append(argv)
        return subprocess.CompletedProcess(argv, 0, '', '')

    def deploy(s):
        calls['deploy'] += 1
        s['netbird_pat'] = 'new-pat'

    def save(s):
        calls['saved'] += 1

    monkeypatch.setattr(subprocess, 'run', run)
    monkeypatch.setattr(urllib.request, 'urlopen',
                        lambda url, timeout=8: io.BytesIO(json.dumps({'setup_required': setup_required}).encode()))
    ns = {
        'os': os, 're': __import__('re'), 'json': json, 'subprocess': subprocess, 'datetime': datetime.datetime,
        'load_settings': lambda: settings, 'save_settings': save,
        '_read_priv': lambda p: open(p).read(),
        '_sudo_wrap': lambda argv: argv,
        '_get_netbird_target_images': lambda settings=None: ('netbirdio/netbird-server:0.80.0', 'netbirdio/dashboard:v2.94.0'),
        '_netbird_deploy_status': {'running': False},
        '_netbird_wait_instance': lambda plog, timeout_sec=120: {'setup_required': setup_required},
        '_netbird_pat_is_valid': lambda p: pat_valid or p == 'new-pat',
        '_run_netbird_deploy': deploy,
    }
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns, calls


def test_populated_orphaned_store_without_pat_is_healed(tmp_path, monkeypatch):
    """test6/test8: rows orphaned, no PAT, a login just failed with the decrypt signature."""
    _box(tmp_path, monkeypatch, users=2)
    settings = {'netbird_enabled': True}
    ns, calls = _load(settings, monkeypatch, logs=SIG)
    assert ns['_heal_netbird_orphaned_store'](lambda m: None) is True
    assert len(calls['exec']) == 1 and 'store.db' in calls['exec'][0][-1] and 'idp.db' in calls['exec'][0][-1]
    assert calls['deploy'] == 1


def test_lost_pat_but_working_store_is_left_alone(tmp_path, monkeypatch):
    """A box that only lost its PAT logs no decrypt failure; it must never be parked."""
    _box(tmp_path, monkeypatch, users=2)
    ns, calls = _load({'netbird_enabled': True}, monkeypatch, logs='INFO all good')
    assert ns['_heal_netbird_orphaned_store'](lambda m: None) is False
    assert calls['exec'] == [] and calls['deploy'] == 0


def test_no_pat_store_mid_setup_is_left_alone(tmp_path, monkeypatch):
    _box(tmp_path, monkeypatch, users=1)
    ns, calls = _load({'netbird_enabled': True}, monkeypatch, logs=SIG, setup_required=True)
    assert ns['_heal_netbird_orphaned_store'](lambda m: None) is False
    assert calls['exec'] == []


def test_netbird_not_enabled_is_left_alone(tmp_path, monkeypatch):
    _box(tmp_path, monkeypatch, users=2)
    ns, calls = _load({}, monkeypatch, logs=SIG)
    assert ns['_heal_netbird_orphaned_store'](lambda m: None) is False
    assert calls['exec'] == []


def test_torn_bootstrap_still_healed(tmp_path, monkeypatch):
    _box(tmp_path, monkeypatch, users=0)
    ns, calls = _load({'netbird_enabled': True}, monkeypatch, logs='')
    assert ns['_heal_netbird_orphaned_store'](lambda m: None) is True
    assert calls['deploy'] == 1


def test_valid_pat_is_healthy(tmp_path, monkeypatch):
    _box(tmp_path, monkeypatch, users=2)
    ns, calls = _load({'netbird_enabled': True, 'netbird_pat': 'p'}, monkeypatch, logs=SIG, pat_valid=True)
    assert ns['_heal_netbird_orphaned_store'](lambda m: None) is False
    assert calls['exec'] == []


def test_key_in_config_only_is_adopted_not_replaced(tmp_path, monkeypatch):
    _box(tmp_path, monkeypatch, key_in_config=True)
    settings = {}
    ns, calls = _load(settings, monkeypatch)
    assert ns['_ensure_netbird_store_key_setting'](settings) == KEY
    assert settings['netbird_store_encryption_key'] == KEY and calls['saved'] == 1


def test_settings_key_wins_and_is_not_resaved(tmp_path, monkeypatch):
    _box(tmp_path, monkeypatch, key_in_config=True)
    settings = {'netbird_store_encryption_key': 'from-settings'}
    ns, calls = _load(settings, monkeypatch)
    assert ns['_ensure_netbird_store_key_setting'](settings) == 'from-settings'
    assert calls['saved'] == 0


def test_no_key_anywhere_mints_one(tmp_path, monkeypatch):
    _box(tmp_path, monkeypatch, key_in_config=False)
    settings = {}
    ns, calls = _load(settings, monkeypatch)
    k = ns['_ensure_netbird_store_key_setting'](settings)
    assert len(k) == 44 and k != KEY and settings['netbird_store_encryption_key'] == k and calls['saved'] == 1
