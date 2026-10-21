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
"""A TAK Portal update must not reset the portal's settings to the template (GH #158).

Field report, 2.0.10 -> 2.0.11 from the console: settings.json came back as settings.example.json
(TAK_URL https://your-tak-server:8443/Marti, P12 ./data/certs/webadmin.p12, ~120 keys). `docker cp`
onto settings.json deletes the file and rewrites it in place, the still-running portal reloads it on
the mtime change, a torn read parses as {}, and its template merge writes the template over the file.
"""

import ast
import json
import os
import pathlib
import stat
import tempfile
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
SETTINGS = '/usr/src/app/data/settings.json'
KEEP = next(ast.literal_eval(n.value) for n in TREE.body if isinstance(n, ast.Assign)
            and getattr(n.targets[0], 'id', None) == 'TAKPORTAL_SETTINGS_BACKUP_KEEP')


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _load(name, ns):
    for k, v in {'os': os, 'json': json, 'tempfile': tempfile, 'print': lambda *a, **k: None}.items():
        ns.setdefault(k, v)
    exec(compile(_func(name), 'app.py', 'exec'), ns)
    return ns[name]


class _Docker:
    """Records docker argv; `fail` maps an argv word ('mv', 'cp') to a failing returncode."""

    def __init__(self, running=True, fail=()):
        self.running, self.fail, self.calls = running, set(fail), []

    def run(self, argv, **kw):
        self.calls.append(list(argv))
        verb = argv[3] if argv[1] == 'exec' else argv[1]
        return types.SimpleNamespace(returncode=1 if verb in self.fail else 0, stdout='', stderr='boom')

    def writer(self):
        self.backups = 0

        def backup(plog=None):
            self.backups += 1
            return ''
        return _load('_takportal_write_settings_json', {
            'subprocess': types.SimpleNamespace(run=self.run),
            '_sudo_wrap': lambda a: a,
            '_takportal_web_container': lambda: {'id': 'c0ffee'} if self.running else None,
            '_takportal_ref': lambda: 'c0ffee',
            '_takportal_backup_settings': backup,
        })


def test_a_running_portal_gets_a_staged_file_renamed_over_settings_json():
    d = _Docker()
    assert d.writer()('{}') == (True, '')
    assert d.backups == 1, 'the current file is backed up before every write'
    cp, mv = d.calls
    assert cp[:2] == ['docker', 'cp'] and cp[3] == 'c0ffee:/usr/src/app/data/.settings.json.infratak'
    assert mv == ['docker', 'exec', 'c0ffee', 'mv', '-f', '/usr/src/app/data/.settings.json.infratak', SETTINGS]
    assert not any(c[1] == 'cp' and c[-1].endswith(':' + SETTINGS) for c in d.calls), \
        'never docker cp onto settings.json under a running portal'


def test_a_refused_rename_cleans_up_and_still_writes():
    d = _Docker(fail={'mv'})
    assert d.writer()('{}') == (True, '')
    assert ['docker', 'exec', 'c0ffee', 'rm', '-f', '/usr/src/app/data/.settings.json.infratak'] in d.calls
    assert d.calls[-1][1] == 'cp' and d.calls[-1][-1] == 'c0ffee:' + SETTINGS


def test_a_stopped_portal_is_seeded_with_a_plain_copy():
    d = _Docker(running=False)
    assert d.writer()('{}') == (True, '')
    assert len(d.calls) == 1 and d.calls[0][-1] == 'c0ffee:' + SETTINGS


def test_a_failed_copy_is_reported():
    ok, err = _Docker(running=False, fail={'cp'}).writer()('{}')
    assert ok is False and err == 'boom'


def _backup(tmp_path, current):
    return _load('_takportal_backup_settings', {
        'CONFIG_DIR': str(tmp_path),
        '_takportal_get_existing_settings': lambda: current(),
        'datetime': __import__('datetime').datetime,
        'TAKPORTAL_SETTINGS_BACKUP_KEEP': KEEP,
    })


def test_backups_are_private_deduplicated_and_rotated(tmp_path):
    state = {'n': 0}
    backup = _backup(tmp_path, lambda: {'TAK_URL': f"https://tak{state['n']}:8443/Marti"})
    first = backup()
    assert first and stat.S_IMODE(os.stat(first).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path / 'takportal-settings-backups').st_mode) == 0o700
    assert json.loads(pathlib.Path(first).read_text())['TAK_URL'] == 'https://tak0:8443/Marti'
    assert backup() == first, 'an unchanged file is not backed up twice'
    for i in range(1, 15):
        state['n'] = i
        backup()
    kept = sorted(os.listdir(tmp_path / 'takportal-settings-backups'))
    assert len(kept) == KEEP == 10
    assert json.loads((tmp_path / 'takportal-settings-backups' / kept[-1]).read_text())['TAK_URL'] == 'https://tak14:8443/Marti'


def test_nothing_to_back_up_writes_nothing(tmp_path):
    assert _backup(tmp_path, lambda: {})() == ''
    assert not (tmp_path / 'takportal-settings-backups').exists()


def test_a_torn_read_is_retried_instead_of_returning_empty():
    """{} from this reader makes the merge rebuild the file from infra-TAK's seeds alone."""
    reads = iter(['{"TAK_URL": "https://tak.example', '{"TAK_URL": "https://tak.example.com:8443/Marti"}'])
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        return types.SimpleNamespace(returncode=0, stdout=next(reads), stderr='')
    read = _load('_takportal_get_existing_settings', {
        'subprocess': types.SimpleNamespace(run=run), '_sudo_wrap': lambda a: a,
        '_takportal_ref': lambda: 'c0ffee', 'time': types.SimpleNamespace(sleep=lambda s: None)})
    assert read() == {'TAK_URL': 'https://tak.example.com:8443/Marti'}
    assert len(calls) == 2


def test_update_verifies_the_tak_connection_survived_the_build():
    body = APP[APP.index("elif action == 'update':"):APP.index("@app.route('/api/takportal/deploy'")]
    verify = body[body.index('_keys = ['):body.index('_stale = (')]
    for k in ('TAK_URL', 'TAK_API_P12_PATH', 'TAK_API_P12_PASSPHRASE', 'TAK_CA_PATH'):
        assert f"'{k}'" in verify
