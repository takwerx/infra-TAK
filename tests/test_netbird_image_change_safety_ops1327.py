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
"""NetBird image changes: back up the store first, pull first, compare tags exactly, and never
reset the operator's approval setting on Update (ops #1327, found by the stack audit, ops #1311).

Four faults, one proof each (every test below fails on the base branch):
1. No copy of data/ (store.db, idp.db) before a NetBird image change. 0.83 migrates the store and
   upstream names no way back.
2. The heal rewrote the compose BEFORE the pull and never looked at the pull result: a failed pull
   left the new tag named over the old container.
3. The "already on the pin" test was a text match: 0.82.1 is found inside 0.82.10, and a tag-less
   `image: netbirdio/netbird-server` line was not matched by the rewrite, so the heal said
   "restored" and restored nothing.
4. Update ran _netbird_finalize_account_store, which UPDATEs accounts SET
   settings_extra_user_approval_required=0 on the live store: an operator who turned "users need
   approval" on lost it at the next Update.

app.py cannot be imported in a test, so the functions are cut out of it and run against a fake
Docker and real files: the code under test is the shipped text. Functions that exist only after the
fix are loaded when present, so on the base branch the OLD code runs and fails the assertions.
"""

import ast
import io
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import types
import urllib.error

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

_OLD = 'netbirdio/netbird-server:0.82.1'
_NEW = 'netbirdio/netbird-server:0.83.2'
_DASH_OLD = 'netbirdio/dashboard:v2.96.0'
_DASH_NEW = 'netbirdio/dashboard:v2.98.0'

_ENTRY = {'_heal_netbird_pinned_image', 'netbird_control_api', '_run_netbird_deploy',
          '_netbird_complete_setup'}
_SUPPORT = {
    '_netbird_sync_compose_image_tags', '_netbird_recreate_containers',
    '_netbird_finalize_account_store',
    # added by the fix: loaded only when present
    '_netbird_compose_image_tags', '_netbird_compose_on_target', '_netbird_pull_images',
    '_netbird_data_fingerprint', '_netbird_backup_data', '_netbird_prepare_image_change',
    '_netbird_revert_compose',
}


def _compose(srv='0.82.1', dash='v2.96.0', srv_line=None):
    srv_line = srv_line or f'netbirdio/netbird-server:{srv}'
    return (
        'services:\n'
        '  netbird-server:\n'
        f'    image: {srv_line}\n'
        '    container_name: netbird-server\n'
        '    volumes:\n'
        '      - ./data:/var/lib/netbird\n'
        '  dashboard:\n'
        f'    image: netbirdio/dashboard:{dash}\n'
        '    container_name: netbird-dashboard\n'
    )


def _make_store(data, approval=1):
    data.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(data / 'store.db')
    conn.executescript(
        'CREATE TABLE account_onboardings (onboarding_flow_pending INT, signup_form_pending INT);'
        'INSERT INTO account_onboardings VALUES (1, 1);'
        'CREATE TABLE accounts (settings_extra_user_approval_required INT);'
        f'INSERT INTO accounts VALUES ({approval});'
        'CREATE TABLE users (role TEXT, pending_approval INT);'
        "INSERT INTO users VALUES ('owner', 1), ('user', 1);"
        'CREATE TABLE peers (id TEXT);'
        "INSERT INTO peers VALUES ('peer-a'), ('peer-b');"
    )
    conn.commit()
    conn.close()
    (data / 'idp.db').write_bytes(b'idp-bytes-' * 100)


def _make_netbird(tmp_path, compose_txt=None, approval=1):
    nb = tmp_path / 'netbird'
    nb.mkdir(parents=True)
    (nb / 'docker-compose.yml').write_text(compose_txt or _compose())
    _make_store(nb / 'data', approval)
    return nb


def _accounts(db):
    conn = sqlite3.connect(f'file:{db}?mode=ro&immutable=1', uri=True)
    try:
        return (conn.execute('SELECT * FROM accounts').fetchall(),
                conn.execute('SELECT count(*) FROM peers').fetchone()[0])
    finally:
        conn.close()


class FakeDocker:
    """The docker CLI as the console calls it. Records every call with the compose text and the
    backup folders as they were at that moment, so a test can say what came BEFORE what."""

    def __init__(self, nb_dir, local_images=()):
        self.nb = pathlib.Path(nb_dir)
        self.events = []
        self.running = True
        self.local_images = set(local_images)
        self.pull_fail = set()        # image names whose pull fails
        self.compose_pull_fail = False
        self.up_fail_times = 0        # the next N `compose up` calls fail

    def _snap(self):
        compose = self.nb / 'docker-compose.yml'
        return {
            'compose': compose.read_text() if compose.exists() else None,
            'baks': sorted(p.name for p in self.nb.iterdir() if p.name.startswith('data.bak-')),
            'running': self.running,
        }

    def run(self, argv, *a, **k):
        argv = list(argv)
        ok = subprocess.CompletedProcess(argv, 0, '', '')
        bad = subprocess.CompletedProcess(argv, 1, '', 'boom')
        tag = None
        if argv[:2] == ['docker', 'pull']:
            tag = ('pull', argv[2])
            rc = bad if argv[2] in self.pull_fail else ok
            if rc is ok:
                self.local_images.add(argv[2])
        elif argv[:3] == ['docker', 'image', 'inspect']:
            return ok if argv[3] in self.local_images else bad
        elif argv[:3] == ['docker', 'compose', 'pull']:
            tag = ('compose-pull',)
            rc = bad if self.compose_pull_fail else ok
        elif argv[:3] == ['docker', 'compose', 'stop']:
            tag = ('stop',)
            self.running = False
            rc = ok
        elif argv[:3] == ['docker', 'compose', 'start']:
            tag = ('start',)
            self.running = True
            rc = ok
        elif argv[:3] == ['docker', 'compose', 'up']:
            tag = ('up',) + tuple(argv[3:])
            if self.up_fail_times > 0:
                self.up_fail_times -= 1
                rc = bad
            else:
                self.running = True
                rc = ok
        elif argv[:2] == ['docker', 'inspect']:
            return subprocess.CompletedProcess(argv, 0, 'true\n' if self.running else 'false\n', '')
        elif argv[:2] == ['cp', '-a']:
            tag = ('cp',)
            shutil.copytree(argv[2], argv[3], symlinks=True, copy_function=shutil.copy2)
            rc = ok
        else:
            raise AssertionError(f'unexpected command {argv}')
        self.events.append(tag + (self._snap(),))
        return rc

    def kinds(self):
        return [e[0] for e in self.events]


def _load(nb, monkeypatch, *, target=(_NEW, _DASH_NEW), settings=None, fake=None, extra=None):
    tree = ast.parse(APP)
    want = _ENTRY | _SUPPORT
    parts = [ast.get_source_segment(APP, n) for n in tree.body
             if isinstance(n, ast.FunctionDef) and n.name in want]
    assert {'_heal_netbird_pinned_image', 'netbird_control_api',
            '_netbird_sync_compose_image_tags'} <= {
        n.name for n in tree.body if isinstance(n, ast.FunctionDef)}, 'a function under test was renamed'
    fake = fake or FakeDocker(nb)
    state = {'settings': dict(settings or {}), 'saved': []}

    def save_settings(s):
        state['settings'] = dict(s)
        state['saved'].append(dict(s))

    ns = {
        'os': os, 'subprocess': subprocess, 'json': json, 're': __import__('re'),
        'NETBIRD_INSTALL_DIR': str(nb),
        'NETBIRD_SERVER_IMAGE': _OLD, 'NETBIRD_SERVER_DEV_IMAGE': _NEW,
        '_sudo_wrap': lambda argv: list(argv),
        '_get_netbird_target_images': lambda settings=None: target,
        '_read_priv': lambda p: pathlib.Path(p).read_text(),
        '_write_priv': lambda p, c, *a, **k: pathlib.Path(p).write_text(c),
        'load_settings': lambda: dict(state['settings']),
        'save_settings': save_settings,
        'request': types.SimpleNamespace(json={'action': 'update'}),
        'jsonify': lambda d: d,
        'time': types.SimpleNamespace(sleep=lambda s: None, time=lambda: 0),
        '_get_netbird_version_info': lambda: {'version': '0.83.2'},
    }
    ns.update(extra or {})
    monkeypatch.setattr(subprocess, 'run', fake.run)
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns, fake, state


def _heal(ns):
    log = []
    result = ns['_heal_netbird_pinned_image'](log.append)
    return result, log


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    # the heal looks in ~/netbird: point HOME at the test folder
    monkeypatch.setenv('HOME', str(tmp_path))


# ── 1. a copy of data/ exists before the image changes ─────────────────────────────────────────

def test_heal_backs_up_the_store_before_the_compose_names_the_new_image(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    ns, fake, _ = _load(nb, monkeypatch)
    before = _accounts(nb / 'data' / 'store.db')
    result, log = _heal(ns)
    assert result is True, log
    bak = nb / 'data.bak-0.82.1'
    assert bak.is_dir(), f'no backup of the data folder was made: {log}'
    assert _accounts(bak / 'store.db') == before == ([(1,)], 2)
    assert (bak / 'idp.db').read_bytes() == (nb / 'data' / 'idp.db').read_bytes()
    # order: the server is stopped while the compose still names the OLD tag, and the backup
    # exists by the time the compose names the NEW one
    stop = next(e for e in fake.events if e[0] == 'stop')[-1]
    assert 'netbird-server:0.82.1' in stop['compose']
    up = next(e for e in fake.events if e[0] == 'up')[-1]
    assert 'netbird-server:0.83.2' in up['compose']
    assert 'data.bak-0.82.1' in up['baks']


def test_rollback_down_to_the_pin_backs_up_the_newer_store_first(tmp_path, monkeypatch):
    """A main-channel box that ran 0.83.2 is moved down to 0.82.1 (ops #1088). The newer, migrated
    store is copied first, so the move down is itself reversible."""
    nb = _make_netbird(tmp_path, _compose('0.83.2', 'v2.98.0'))
    ns, fake, _ = _load(nb, monkeypatch, target=(_OLD, _DASH_OLD))
    result, log = _heal(ns)
    assert result is True, log
    assert (nb / 'data.bak-0.83.2').is_dir(), log
    assert 'netbird-server:0.82.1' in (nb / 'docker-compose.yml').read_text()


def test_the_store_is_copied_with_the_server_stopped(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    ns, fake, _ = _load(nb, monkeypatch)
    _heal(ns)
    kinds = fake.kinds()
    assert kinds.index('stop') < kinds.index('up'), kinds
    assert next(e for e in fake.events if e[0] == 'stop')[-1]['running'] is False


def test_unreadable_files_are_copied_through_the_broker(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    ns, fake, _ = _load(nb, monkeypatch)
    real = shutil.copytree
    calls = {'n': 0}

    def copytree(src, dst, **k):
        calls['n'] += 1
        if calls['n'] == 1:
            raise PermissionError('root-owned')   # the console's own copy is refused
        return real(src, dst, **k)                # the broker's `cp -a` (the fake runs it here)
    monkeypatch.setattr(shutil, 'copytree', copytree)
    result, log = _heal(ns)
    assert result is True, log
    assert 'cp' in fake.kinds()
    assert (nb / 'data.bak-0.82.1' / 'store.db').is_file()


def test_no_backup_means_no_image_change_and_the_server_keeps_running(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    ns, fake, _ = _load(nb, monkeypatch)
    monkeypatch.setattr(shutil, 'disk_usage', lambda p: types.SimpleNamespace(free=1024))
    result, log = _heal(ns)
    assert result is False
    assert 'netbird-server:0.82.1' in (nb / 'docker-compose.yml').read_text(), 'compose must stay on the old tag'
    assert fake.running is True, 'the server must be running again after a failed backup'
    assert not list(nb.glob('data.bak-*'))
    assert any('not enough free disk' in m for m in log), log


def test_an_identical_backup_is_reused_and_old_ones_are_pruned(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    ns, fake, _ = _load(nb, monkeypatch)
    ok1, p1, _m = ns['_netbird_backup_data'](str(nb), '0.82.1', lambda m: None)
    ok2, p2, _m = ns['_netbird_backup_data'](str(nb), '0.82.1', lambda m: None)
    assert ok1 and ok2 and p1 == p2, 'a retrying heal must not pile up copies of the same state'
    assert len(list(nb.glob('data.bak-*'))) == 1
    for i in range(7):  # seven different states
        (nb / 'data' / 'idp.db').write_bytes(b'x' * (i + 1))
        os.utime(nb / 'data' / 'idp.db', (1000 + i, 1000 + i))
        ns['_netbird_backup_data'](str(nb), f'0.82.{i}', lambda m: None)
    assert len(list(nb.glob('data.bak-*'))) == 5


def test_backup_is_private(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    ns, fake, _ = _load(nb, monkeypatch)
    ok, path, _m = ns['_netbird_backup_data'](str(nb), '0.82.1', lambda m: None)
    assert ok and (os.stat(path).st_mode & 0o077) == 0, 'the copy holds user data: owner only'


# ── 2. pull first, and look at the result ──────────────────────────────────────────────────────

def test_a_failed_pull_leaves_the_compose_and_the_container_alone(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    ns, fake, _ = _load(nb, monkeypatch)
    fake.pull_fail = {_NEW, _DASH_NEW}
    result, log = _heal(ns)
    assert result is False
    assert (nb / 'docker-compose.yml').read_text() == _compose(), 'a failed pull must not rewrite the compose'
    assert fake.running is True
    assert 'stop' not in fake.kinds() and 'up' not in fake.kinds(), fake.kinds()
    assert not list(nb.glob('data.bak-*')), 'nothing changes, so nothing to back up'


def test_a_failed_pull_of_an_image_already_on_the_box_is_not_fatal(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    fake = FakeDocker(nb, local_images={_NEW, _DASH_NEW})
    ns, fake, _ = _load(nb, monkeypatch, fake=fake)
    fake.pull_fail = {_NEW, _DASH_NEW}
    result, log = _heal(ns)
    assert result is True, log
    assert 'netbird-server:0.83.2' in (nb / 'docker-compose.yml').read_text()


def test_the_pull_comes_before_the_stop_and_the_compose_rewrite(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    ns, fake, _ = _load(nb, monkeypatch)
    _heal(ns)
    kinds = fake.kinds()
    assert kinds.index('pull') < kinds.index('stop') < kinds.index('up'), kinds
    first_pull = next(e for e in fake.events if e[0] == 'pull')[-1]
    assert 'netbird-server:0.82.1' in first_pull['compose']


def test_if_the_new_image_will_not_start_the_old_compose_comes_back(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    ns, fake, _ = _load(nb, monkeypatch)
    fake.up_fail_times = 1
    result, log = _heal(ns)
    assert result is False
    assert (nb / 'docker-compose.yml').read_text() == _compose(), log
    assert fake.running is True, 'the previous container must be up again'
    assert (nb / 'data.bak-0.82.1').is_dir(), 'the backup stays'


# ── 3. exact tag compare ───────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('srv_line,why', [
    ('netbirdio/netbird-server:0.83.20', '0.83.2 is found inside 0.83.20'),
    ('netbirdio/netbird-server', 'a tag-less line is :latest, not the pin'),
    ('netbirdio/netbird-server:0.83.2@sha256:' + 'a' * 64, 'a digest tag is not the pin'),
    ('netbirdio/netbird-server:0.83.1', 'an older tag'),
])
def test_a_tag_that_only_contains_the_pin_is_not_on_the_pin(tmp_path, monkeypatch, srv_line, why):
    nb = _make_netbird(tmp_path, _compose(dash='v2.98.0', srv_line=srv_line))
    ns, fake, _ = _load(nb, monkeypatch)
    result, log = _heal(ns)
    assert result is True, f'{why}: the heal must move it ({log})'
    assert (nb / 'docker-compose.yml').read_text() == _compose('0.83.2', 'v2.98.0')


def test_the_pin_is_a_no_op_with_no_docker_call_at_all(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path, _compose('0.83.2', 'v2.98.0'))
    ns, fake, _ = _load(nb, monkeypatch)
    result, log = _heal(ns)
    assert result is False
    assert fake.events == [], 'a box already on the pin must see no pull, stop, backup or restart'
    assert not list(nb.glob('data.bak-*'))


def test_the_old_pin_text_inside_a_longer_version_is_read_as_a_different_version(tmp_path, monkeypatch):
    """0.82.1 -> 0.82.10: the old text match said "on the pin" for the 0.82.10 compose."""
    nb = _make_netbird(tmp_path, _compose('0.82.10', 'v2.96.0'))
    ns, fake, _ = _load(nb, monkeypatch, target=(_OLD, _DASH_OLD))
    result, log = _heal(ns)
    assert result is True, log
    assert 'netbird-server:0.82.1\n' in (nb / 'docker-compose.yml').read_text()


def test_the_compose_helper_reads_whole_tags():
    ns = {}
    tree = ast.parse(APP)
    names = {'_netbird_compose_image_tags', '_netbird_compose_on_target'}
    parts = [ast.get_source_segment(APP, n) for n in tree.body
             if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(parts) == 2, 'the exact-tag compare is missing'
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    on = ns['_netbird_compose_on_target']
    assert on(_compose('0.82.1', 'v2.96.0'), _OLD, _DASH_OLD)
    assert not on(_compose('0.82.10', 'v2.96.0'), _OLD, _DASH_OLD)
    assert not on(_compose('0.82.1', 'v2.96.00'), _OLD, _DASH_OLD)
    assert not on(_compose(srv_line='netbirdio/netbird-server'), _OLD, _DASH_OLD)
    assert not on('services: {}\n', _OLD, _DASH_OLD)


# ── 4. Update does not reset the operator's approval setting ───────────────────────────────────

def test_update_keeps_users_need_approval_on_and_backs_up_first(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path, approval=1)
    ns, fake, state = _load(nb, monkeypatch, settings={'netbird_enabled': True})
    out = ns['netbird_control_api']()
    assert out['success'] is True, out
    assert _accounts(nb / 'data' / 'store.db')[0] == [(1,)], 'Update must not reset "users need approval"'
    assert _accounts(nb / 'data.bak-0.82.1' / 'store.db')[1] == 2, 'a backup of the old store exists'
    kinds = fake.kinds()
    assert kinds.index('stop') < kinds.index('up'), kinds


def test_update_still_clears_the_gates_while_a_deploy_owes_it(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path, _compose('0.83.2', 'v2.98.0'), approval=1)
    ns, fake, state = _load(nb, monkeypatch, settings={'netbird_finalize_pending': True})
    out = ns['netbird_control_api']()
    assert out['success'] is True, out
    assert _accounts(nb / 'data' / 'store.db')[0] == [(0,)]
    assert 'netbird_finalize_pending' not in state['settings'], 'the debt is paid once'


def test_update_with_a_failed_pull_changes_nothing(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    ns, fake, state = _load(nb, monkeypatch)
    fake.pull_fail = {_NEW, _DASH_NEW}
    out = ns['netbird_control_api']()
    body, status = out
    assert status == 500 and body['success'] is False, out
    assert (nb / 'docker-compose.yml').read_text() == _compose()
    assert fake.running is True
    assert 'stop' not in fake.kinds() and 'up' not in fake.kinds()


def test_update_on_the_pin_makes_no_backup_and_keeps_the_approval_setting(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path, _compose('0.83.2', 'v2.98.0'), approval=1)
    ns, fake, state = _load(nb, monkeypatch)
    out = ns['netbird_control_api']()
    assert out['success'] is True, out
    assert not list(nb.glob('data.bak-*')), 'the image does not change, so there is nothing to back up'
    assert _accounts(nb / 'data' / 'store.db')[0] == [(1,)]


def test_update_when_the_new_image_will_not_start_restores_the_old_compose(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    ns, fake, state = _load(nb, monkeypatch)
    fake.up_fail_times = 1
    body, status = ns['netbird_control_api']()
    assert status == 500 and 'data.bak-0.82.1' in body['error'], body
    assert (nb / 'docker-compose.yml').read_text() == _compose()
    assert fake.running is True


# ── 4b. deploy: finalize only for the account this install created ─────────────────────────────

class FakeNetBird:
    def __init__(self, setup_required):
        self.setup_required = setup_required

    def request(self, path, method='GET', data=None, token=None, timeout=15):
        if path == '/api/instance':
            return io.BytesIO(json.dumps({'setup_required': self.setup_required}).encode())
        if path == '/api/setup':
            if not self.setup_required:
                raise urllib.error.HTTPError(path, 412, 'done', {}, io.BytesIO(b''))
            self.setup_required = False
            return io.BytesIO(json.dumps({'email': 'a@x', 'personal_access_token': 'pat-1'}).encode())
        if path == '/api/users':
            return io.BytesIO(b'[]')
        raise AssertionError(path)


def _deploy(nb, monkeypatch, tmp_path, *, setup_required, settings=None, target=(_NEW, _DASH_NEW),
            fake=None):
    finalize_calls = []
    nbapi = FakeNetBird(setup_required)
    written = []
    status = {'running': True, 'complete': False, 'error': False}
    logs = []

    def write_compose(nb_dir, domain, secret, setup_pat_enabled=True, store_key=None):
        written.append({'baks': sorted(p.name for p in pathlib.Path(nb_dir).iterdir()
                                       if p.name.startswith('data.bak-'))})
        (pathlib.Path(nb_dir) / 'docker-compose.yml').write_text(_compose('0.83.2', 'v2.98.0'))
        if not (pathlib.Path(nb_dir) / 'data' / 'store.db').exists():
            _make_store(pathlib.Path(nb_dir) / 'data')   # the first start of the server makes it

    extra = {
        '_netbird_deploy_status': status, '_netbird_deploy_log': lambda m, status=None: logs.append(m),
        '_netbird_wait_instance': lambda plog, timeout_sec=120: json.loads(nbapi.request('/api/instance').read()),
        '_netbird_mgmt_request': nbapi.request, '_netbird_pat_is_valid': lambda p: True,
        '_netbird_admin_credentials': lambda s: ('a@x', 'akadmin', 'pw-long-enough-1'),
        '_netbird_register_authentik_idp': lambda *a, **k: True,
        '_netbird_write_compose': write_compose,
        '_netbird_read_auth_secret': lambda d: 'secret',
        '_netbird_store_key_needed': lambda img: True,
        '_ensure_netbird_store_key_setting': lambda s: 'key',
        '_docker_probe': lambda: (0, 'Docker version 29'), '_install_docker_engine': lambda plog: True,
        '_ensure_authentik_netbird_app': lambda s, plog=None: ('client-id-123456', 'secret'),
        '_w1_reassert_app_mfa': lambda plog: None,
        '_get_service_domain': lambda s, name: f'{name}.example.com',
        '_pub_hostport': lambda h, s=None: h, '_get_authentik_api_url': lambda s: 'http://ak',
        '_get_authentik_env_value': lambda s, k: None, '_ensure_app_access_policies': lambda *a: None,
        '_fw_allow': lambda port, proto='tcp': (True, ''),
        'generate_caddyfile': lambda s: None, '_caddy_reload': lambda timeout=90: None,
        'urllib': urllib,
    }
    ns, fk, state = _load(nb, monkeypatch, target=target, settings=settings, fake=fake, extra=extra)
    ns['urllib'] = urllib
    real_finalize = ns['_netbird_finalize_account_store']

    def counting_finalize(plog=None):
        finalize_calls.append(1)
        return real_finalize(plog)
    ns['_netbird_finalize_account_store'] = counting_finalize
    s = dict(settings or {})
    ns['_run_netbird_deploy'](s)
    return {'status': status, 'logs': logs, 'finalize': finalize_calls, 'settings': s,
            'written': written, 'fake': fk}


def test_a_fresh_deploy_clears_the_onboarding_gates_once(tmp_path, monkeypatch):
    nb = tmp_path / 'netbird'
    r = _deploy(nb, monkeypatch, tmp_path, setup_required=True, settings={'fqdn': 'x.example.com'})
    assert r['status']['error'] is False, r['logs']
    assert len(r['finalize']) == 1, 'the account was created by this deploy: the gates are cleared'
    assert 'netbird_finalize_pending' not in r['settings']


def test_a_redeploy_of_a_working_account_leaves_the_approval_setting_alone(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path, _compose('0.83.2', 'v2.98.0'), approval=1)
    r = _deploy(nb, monkeypatch, tmp_path, setup_required=False,
                settings={'fqdn': 'x.example.com', 'netbird_pat': 'pat-1'})
    assert r['status']['error'] is False, r['logs']
    assert r['finalize'] == [], 'a redeploy must not run the finalize step'
    assert _accounts(nb / 'data' / 'store.db')[0] == [(1,)]


def test_a_retry_after_a_failed_first_deploy_still_clears_the_gates(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path, _compose('0.83.2', 'v2.98.0'), approval=1)
    r = _deploy(nb, monkeypatch, tmp_path, setup_required=False,
                settings={'fqdn': 'x.example.com', 'netbird_pat': 'pat-1', 'netbird_finalize_pending': True})
    assert len(r['finalize']) == 1, 'the first deploy created the owner and never finalized'
    assert _accounts(nb / 'data' / 'store.db')[0] == [(0,)]
    assert 'netbird_finalize_pending' not in r['settings']


def test_a_redeploy_that_changes_the_image_backs_up_before_the_compose_is_rewritten(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)  # 0.82.1 on disk, target 0.83.2
    r = _deploy(nb, monkeypatch, tmp_path, setup_required=False,
                settings={'fqdn': 'x.example.com', 'netbird_pat': 'pat-1'})
    assert r['status']['error'] is False, r['logs']
    assert r['written'] and r['written'][0]['baks'] == ['data.bak-0.82.1'], (
        'the backup must exist before the compose is written', r['written'])


def test_a_redeploy_with_a_failed_pull_stops_before_touching_anything(tmp_path, monkeypatch):
    nb = _make_netbird(tmp_path)
    fake = FakeDocker(nb)
    fake.pull_fail = {_NEW, _DASH_NEW}
    r = _deploy(nb, monkeypatch, tmp_path, setup_required=False,
                settings={'fqdn': 'x.example.com', 'netbird_pat': 'pat-1'}, fake=fake)
    assert r['status']['error'] is True
    assert r['written'] == []
    assert (nb / 'docker-compose.yml').read_text() == _compose()
    assert fake.running is True
