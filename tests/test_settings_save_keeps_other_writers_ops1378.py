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
"""A settings save must not put back old values of keys another thread wrote (ops #1378).

Box fi-20261127-092858: the console saved `last_console_version` at 09:32:21; 21 minutes later
settings.json had no such key. A module deploy thread had loaded the settings dict early, run
for minutes and saved the whole dict at the end, so everything written in between was lost.

These tests run the real load_settings / save_settings from app.py against a temp folder.
They name only functions that exist on the base branch as required; the helpers this fix adds
are loaded when present, so the tests fail on the base branch for the right reason (a lost key),
not because a helper is missing.
"""

import ast
import json
import os
import pathlib
import tempfile
import threading

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

REQUIRED = ['_load_json_cached', 'load_settings', 'save_settings']
OPTIONAL = ['_load_json_cached_with_text', '_LoadedSettings', '_settings_baseline',
            '_merge_settings_with_disk']
CORE = ('ssl_mode', 'fqdn', 'server_ip', 'os_type', 'os_name',
        'pkg_mgr', 'arch', 'console_port', 'install_dir')


def _segment(name, required):
    for n in TREE.body:
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == name:
            return ast.get_source_segment(APP, n)
    if required:
        raise AssertionError(f'{name} was renamed or removed')
    return None


def _boot(config_dir, printed=None):
    ns = {'os': os, 'json': json, 'tempfile': tempfile, 'threading': threading,
          'CONFIG_DIR': str(config_dir), 'CORE_SETTINGS_KEYS': CORE,
          '_json_file_cache': {}, '_settings_write_lock': threading.Lock(),
          '_MISSING': object(),
          'print': (lambda *a, **k: printed.append(' '.join(str(x) for x in a))) if printed is not None
          else (lambda *a, **k: None)}
    for name in OPTIONAL + REQUIRED:
        src = _segment(name, name in REQUIRED)
        if src:
            exec(compile(src, 'app.py', 'exec'), ns)
    return ns


def _write(config_dir, data):
    (pathlib.Path(config_dir) / 'settings.json').write_text(json.dumps(data))


def _disk(config_dir):
    return json.loads((pathlib.Path(config_dir) / 'settings.json').read_text())


def _base_settings(**extra):
    d = {k: 'x' for k in CORE}
    d['console_port'] = 5001
    d.update(extra)
    return d


def test_key_written_by_another_thread_survives(tmp_path):
    """The bug: load, another writer adds a key, save. The key must still be there."""
    ns = _boot(tmp_path)
    _write(tmp_path, _base_settings())
    deploy = ns['load_settings']()           # a module deploy thread reads the settings...
    other = ns['load_settings']()            # ...the post-update thread writes its stamp...
    other['last_console_version'] = '10.4.9-alpha'
    other['last_console_sha'] = '9a76aa8'
    ns['save_settings'](other)
    deploy['authentik'] = {'deployed': True}  # ...and the deploy saves its own key at the end.
    ns['save_settings'](deploy)
    final = _disk(tmp_path)
    assert final['last_console_version'] == '10.4.9-alpha'
    assert final['last_console_sha'] == '9a76aa8'
    assert final['authentik'] == {'deployed': True}


def test_real_threads_one_waits_while_another_writes(tmp_path):
    ns = _boot(tmp_path)
    _write(tmp_path, _base_settings())
    loaded, may_save, saved = threading.Event(), threading.Event(), threading.Event()

    def deploy():
        s = ns['load_settings']()
        loaded.set()
        may_save.wait(10)
        s['webodm'] = {'ok': 1}
        ns['save_settings'](s)
        saved.set()

    t = threading.Thread(target=deploy)
    t.start()
    assert loaded.wait(10)
    s2 = ns['load_settings']()
    s2['last_console_version'] = '10.4.9-alpha'
    ns['save_settings'](s2)
    may_save.set()
    assert saved.wait(10)
    t.join()
    final = _disk(tmp_path)
    assert final['last_console_version'] == '10.4.9-alpha'
    assert final['webodm'] == {'ok': 1}


def test_removing_a_key_still_removes_it(tmp_path):
    ns = _boot(tmp_path)
    _write(tmp_path, _base_settings(email_relay={'a': 1}, keep='yes'))
    s = ns['load_settings']()
    s.pop('email_relay')
    ns['save_settings'](s)
    final = _disk(tmp_path)
    assert 'email_relay' not in final
    assert final['keep'] == 'yes'


def test_in_place_change_of_a_nested_dict_is_saved(tmp_path):
    ns = _boot(tmp_path)
    _write(tmp_path, _base_settings(tak_deployment={'step': 1, 'name': 'a'}))
    s = ns['load_settings']()
    s['tak_deployment']['step'] = 2
    ns['save_settings'](s)
    assert _disk(tmp_path)['tak_deployment'] == {'step': 2, 'name': 'a'}


def test_same_dict_saved_twice_second_removal_works(tmp_path):
    ns = _boot(tmp_path)
    _write(tmp_path, _base_settings())
    s = ns['load_settings']()
    s['temp_flag'] = True
    ns['save_settings'](s)
    assert _disk(tmp_path)['temp_flag'] is True
    del s['temp_flag']
    ns['save_settings'](s)
    assert 'temp_flag' not in _disk(tmp_path)


def test_same_key_changed_by_both_the_later_save_wins(tmp_path):
    ns = _boot(tmp_path)
    _write(tmp_path, _base_settings(update_channel='main'))
    a, b = ns['load_settings'](), ns['load_settings']()
    a['update_channel'] = 'dev'
    ns['save_settings'](a)
    b['update_channel'] = 'beta'
    ns['save_settings'](b)
    assert _disk(tmp_path)['update_channel'] == 'beta'


def test_plain_dict_is_saved_whole_as_before(tmp_path):
    ns = _boot(tmp_path)
    _write(tmp_path, _base_settings(old_key='old'))
    ns['save_settings'](_base_settings(new_key='new'))
    final = _disk(tmp_path)
    assert final['new_key'] == 'new'
    assert 'old_key' not in final


def test_torn_file_core_keys_are_still_refilled(tmp_path):
    """The never-drop guard stays: a caller that read a torn file (no core keys) must not wipe them."""
    ns = _boot(tmp_path)
    _write(tmp_path, _base_settings(guarddog_alert_email='a@example.org'))
    (pathlib.Path(tmp_path) / 'settings.json').write_text('{"fqdn": "x", ')   # torn
    s = ns['load_settings']()
    assert s == {}
    _write(tmp_path, _base_settings(guarddog_alert_email='a@example.org'))    # healed by someone
    s['telemetry'] = 1
    ns['save_settings'](s)
    final = _disk(tmp_path)
    assert final['fqdn'] == 'x' and final['guarddog_alert_email'] == 'a@example.org'
    assert final['telemetry'] == 1


def test_missing_file_is_created(tmp_path):
    ns = _boot(tmp_path)
    s = ns['load_settings']()
    s.update(_base_settings(first='run'))
    ns['save_settings'](s)
    assert _disk(tmp_path)['first'] == 'run'


def test_file_stays_mode_600(tmp_path):
    ns = _boot(tmp_path)
    _write(tmp_path, _base_settings())
    s = ns['load_settings']()
    s['k'] = 1
    ns['save_settings'](s)
    assert (pathlib.Path(tmp_path) / 'settings.json').stat().st_mode & 0o777 == 0o600


def test_journal_names_the_keys_it_kept_and_never_a_value(tmp_path):
    """The proof on a box: the journal says which keys the merge kept, so a lost stamp is visible."""
    printed = []
    ns = _boot(tmp_path, printed)
    _write(tmp_path, _base_settings())
    deploy = ns['load_settings']()
    other = ns['load_settings']()
    other['last_console_version'] = '10.4.9-alpha'
    other['webadmin_password'] = 'hunter2-secret'
    ns['save_settings'](other)
    deploy['authentik'] = {'deployed': True}
    printed.clear()
    ns['save_settings'](deploy)
    line = ' '.join(printed)
    assert 'last_console_version' in line and 'webadmin_password' in line
    assert 'hunter2-secret' not in line and '10.4.9-alpha' not in line
    assert 'authentik' not in line          # the caller's own key is not "kept"


def test_nothing_to_report_when_no_other_writer(tmp_path):
    printed = []
    ns = _boot(tmp_path, printed)
    _write(tmp_path, _base_settings())
    s = ns['load_settings']()
    s['k'] = 1
    ns['save_settings'](s)
    assert printed == []


def test_key_removed_by_another_writer_stays_removed(tmp_path):
    ns = _boot(tmp_path)
    _write(tmp_path, _base_settings(email_relay={'a': 1}))
    slow = ns['load_settings']()
    fast = ns['load_settings']()
    fast.pop('email_relay')
    ns['save_settings'](fast)
    slow['other'] = 1
    ns['save_settings'](slow)
    final = _disk(tmp_path)
    assert 'email_relay' not in final and final['other'] == 1
