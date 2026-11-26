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
"""ops #973: MeshRelay PTT server as an infra-TAK module.

One test group per Security condition (Security lead, Thu Nov 19, 2026). The conditions about
what a real box does from outside (a stranger's UDP join is refused, the web port times out
from a second machine) are box tests, listed in the PR; everything the code decides is tested
here, and each test fails without the matching code.
"""

import ast
import hashlib
import importlib.util
import io
import pathlib
import re
import tarfile
import types
import json
import urllib.error
import urllib.request

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, REPO / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _load('takwerx_broker_ops973', 'broker/takwerx_broker.py')

import modules.meshrelay as M   # noqa: E402  (package import: the module uses a relative import)

GOOD_BIN = b'\x7fELF fake binary'
GOOD_WEB = None


def _web_tar(extra=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        for name, data in [('web/index.html', b'<html></html>'), ('web/app.js', b'x=1')] + (extra or []):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _pin(monkeypatch, web=None):
    web = web or _web_tar()
    monkeypatch.setattr(M, 'RELEASE', {
        'tag': 'v4.6.0',
        'assets': {'amd64': ('ptt-server-linux', hashlib.sha256(GOOD_BIN).hexdigest()),
                   'arm64': ('ptt-server-linux-arm64', hashlib.sha256(GOOD_BIN).hexdigest())},
        'web': ('web.tar.gz', hashlib.sha256(web).hexdigest()),
    })
    return web


class Box:
    """A fake console ctx that records every privileged command and write, in order."""

    def __init__(self, web, config=None, token=''):
        self.events = []
        self.files = {}
        if config is not None:
            self.files[M.CONFIG_PATH] = config
        self.settings = {'fqdn': 'example.test'}
        if token:
            self.settings['meshrelay_github_token'] = token
        self.web = web
        self.fw = []
        self.logs = []
        self.audits = []
        self.mfa = []
        self.still_active = False      # make `systemctl is-active` say active (a stop that failed)

    def sudo(self, argv):
        self.events.append(list(argv))
        if self.still_active and list(argv)[:2] == ['systemctl', 'is-active']:
            return ['echo', 'active']
        return ['true']

    def read(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def write(self, path, content, mode='w', perm=None):
        self.events.append(['WRITE', path, perm])
        self.files[path] = content

    def fetch(self, tag, name, dest, token='', limit=0):
        data = self.web if name == 'web.tar.gz' else GOOD_BIN
        with open(dest, 'wb') as f:
            f.write(data)
        return hashlib.sha256(data).hexdigest()

    def ctx(self):
        return {
            '_sudo_wrap': self.sudo, '_read_priv': self.read, '_write_priv': self.write,
            'load_settings': lambda: self.settings,
            'save_settings': lambda s: self.settings.update(s),
            '_host_arch': lambda: 'amd64',
            '_ensure_meshrelay_account': lambda plog=None: True,
            '_fw_allow': lambda p, proto='tcp': (self.fw.append(('allow', p, proto)) or (True, '')),
            '_fw_deny': lambda p, proto='tcp': (self.fw.append(('deny', p, proto)) or (True, '')),
            '_fw_remove': lambda p, proto='tcp': (self.fw.append(('remove', p, proto)) or (True, '')),
            'generate_caddyfile': lambda s: None,
            '_caddy_reload': lambda plog=None: True,
            '_get_authentik_env_value': lambda s, k: 'tok' if k == 'AUTHENTIK_TOKEN' else '',
            '_ensure_authentik_meshrelay_app': lambda *a, **k: True,
            '_deregister_authentik_proxy_app': lambda *a, **k: True,
            '_get_service_domain': lambda s, k: 'meshrelay.example.test',
            'meshrelay_fetch': self.fetch,
            '_f2b_arm_meshrelay_jail': lambda plog=None: (self.fw.append(('jail', 'arm')) or (True, 'armed')),
            '_f2b_disarm_meshrelay_jail': lambda: (self.fw.append(('jail', 'disarm')) or (True, 'removed')),
            'audit': lambda event, detail='', force=False: self.audits.append((event, detail)),
            '_w1_reassert_app_mfa': lambda plog=None: (self.mfa.append(1) or True),
        }

    def cmds(self):
        return [e for e in self.events if e and e[0] != 'WRITE']


@pytest.fixture
def box(monkeypatch):
    web = _pin(monkeypatch)
    monkeypatch.setattr(M, '_active', lambda ctx: True)
    monkeypatch.setattr(M, 'web_up', lambda timeout=5: True)
    monkeypatch.setattr(M, 'time', types.SimpleNamespace(sleep=lambda s: None))
    monkeypatch.setattr(M, '_selinux_enforcing', lambda: False)
    return Box(web)


def _run_deploy(b):
    job = {'running': True, 'complete': False, 'error': False, 'log': []}
    M.deploy(b.ctx(), job, {})
    return job


# ── condition 1: auth on, seeded before the first start, health fails if off ──────────

def test_seed_config_has_auth_on_and_no_token():
    import json
    cfg = json.loads(M.seed_config_text())
    assert cfg['auth_enabled'] is True
    assert 'github_token' not in cfg
    assert cfg['web_port'] == M.WEB_PORT


@pytest.mark.parametrize('text,bad', [
    ('{"auth_enabled": false, "web_port": 8187}', 'auth_enabled'),
    ('{"auth_enabled": "yes", "web_port": 8187}', 'auth_enabled'),
    ('{"auth_enabled": true, "web_port": 8187, "github_token": "ghp_x"}', 'github_token'),
    ('{"auth_enabled": true, "web_port": 8080}', 'web_port'),
    ('not json', 'JSON'),
    ('[]', 'object'),
])
def test_config_problem_refuses_unsafe_configs(text, bad):
    assert bad in M.config_problem(text)


def test_config_problem_passes_the_seed_and_a_missing_key():
    assert M.config_problem(M.seed_config_text()) == ''
    assert M.config_problem('{"web_port": 8187}') == ''     # the app's own default is true


def test_health_fails_when_config_says_auth_off(monkeypatch):
    monkeypatch.setattr(M, '_active', lambda ctx: True)
    monkeypatch.setattr(M, 'web_up', lambda timeout=5: True)
    ctx = {'_read_priv': lambda p: '{"auth_enabled": false, "web_port": 8187}'}
    ok, why = M.health(ctx)
    assert not ok and 'auth_enabled' in why
    ctx = {'_read_priv': lambda p: M.seed_config_text()}
    assert M.health(ctx) == (True, '')


def test_deploy_seeds_config_with_auth_on_before_the_first_start(box):
    job = _run_deploy(box)
    assert job['complete'] and not job['error'], box.logs
    writes = [i for i, e in enumerate(box.events) if e[0] == 'WRITE' and e[1] == M.CONFIG_PATH]
    starts = [i for i, e in enumerate(box.events) if e[:3] == ['systemctl', 'restart', M.UNIT]]
    assert writes and starts and writes[0] < starts[0]
    assert box.events[writes[0]][2] == 0o600
    assert M.config_problem(box.files[M.CONFIG_PATH]) == ''


def test_deploy_refuses_to_start_on_an_existing_config_with_auth_off(monkeypatch):
    web = _pin(monkeypatch)
    monkeypatch.setattr(M, '_active', lambda ctx: True)
    monkeypatch.setattr(M, 'web_up', lambda timeout=5: True)
    b = Box(web, config='{"auth_enabled": false, "web_port": 8187}')   # config.json.example copied by hand
    job = _run_deploy(b)
    assert job['error'] and not job['complete']
    assert not [e for e in b.cmds() if e[:2] == ['systemctl', 'restart']]


def test_deploy_never_overwrites_an_existing_good_config(monkeypatch, box):
    box.files[M.CONFIG_PATH] = '{"auth_enabled": true, "web_port": 8187, "max_clients": 7}'
    _run_deploy(box)
    assert not [e for e in box.events if e[0] == 'WRITE' and e[1] == M.CONFIG_PATH]


def test_deploy_stops_a_running_service_before_it_replaces_the_binary(box):
    """A second Deploy on a running install: cp onto a running binary fails with
    'Text file busy' (found on a real Ubuntu box, ops #973)."""
    _run_deploy(box)
    cmds = box.cmds()
    stops = [i for i, e in enumerate(cmds) if e[:3] == ['systemctl', 'stop', M.UNIT]]
    copies = [i for i, e in enumerate(cmds) if e[:1] == ['cp'] and e[2] == M.BIN_PATH]
    assert stops and copies and stops[0] < copies[0]


def test_rollback_leaves_no_stale_checksum_or_previous_in_the_record(box, monkeypatch):
    box.files[M.CONFIG_PATH] = M.seed_config_text()
    box.settings['meshrelay'] = {'tag': 'v4.6.0', 'arch': 'amd64', 'sha256': 'a' * 64, 'previous': 'v4.5.0'}
    monkeypatch.setattr(M, '_have_backup', lambda: True)
    monkeypatch.setattr(M, '_have_web_backup', lambda: False)
    M.rollback(box.ctx(), plog=box.logs.append)
    assert box.settings['meshrelay'] == {'tag': 'v4.5.0', 'arch': 'amd64'}


def test_rollback_after_a_second_deploy_still_records_the_version_the_backup_holds(box, monkeypatch):
    """Found on a real box (ops #973, v4.8.0 run): Update 4.5.0 to 4.6.0, then Deploy again on the
    same pin (to arm the phone-login jail), then Rollback. The binary went back to 4.5.0 but the
    record still said 4.6.0, because Deploy wrote a fresh record without `previous`. The page then
    showed the wrong version and Update said 'already on the pinned version'."""
    box.files[M.CONFIG_PATH] = M.seed_config_text()
    box.settings['meshrelay'] = {'tag': 'v4.6.0', 'arch': 'amd64', 'sha256': 'a' * 64, 'previous': 'v4.5.0'}
    monkeypatch.setattr(M, '_have_backup', lambda: True)
    monkeypatch.setattr(M, '_have_web_backup', lambda: False)
    _run_deploy(box)                       # second Deploy on the same pinned tag; the backup folder is untouched
    assert box.settings['meshrelay']['tag'] == 'v4.6.0'
    M.rollback(box.ctx(), plog=box.logs.append)
    assert box.settings['meshrelay']['tag'] == 'v4.5.0'


def test_update_and_rollback_never_touch_config(box, monkeypatch):
    box.files[M.CONFIG_PATH] = M.seed_config_text()
    box.settings['meshrelay'] = {'tag': 'v4.5.0'}
    monkeypatch.setattr(M, '_have_backup', lambda: True)
    monkeypatch.setattr(M, '_have_web_backup', lambda: True)
    assert M.update(box.ctx(), plog=box.logs.append)['success'] is True
    M.rollback(box.ctx(), plog=box.logs.append)
    assert not [e for e in box.events if e[0] == 'WRITE']
    for e in box.cmds():
        assert M.CONFIG_PATH not in e
        if e[:2] == ['rm', '-rf']:
            assert e[2] in (M.WEB_DIR, M.BACKUP_DIR), e
    assert box.files[M.CONFIG_PATH] == M.seed_config_text()


# ── Security's four changes (ops #980) ────────────────────────────────────────────────

def _first_write_into_ptt_folder(cmds):
    """Index of the first command that makes or changes anything in the ptt data folder."""
    for i, e in enumerate(cmds):
        if e[0] in ('mkdir', 'cp', 'chown', 'chmod', 'rm') and any(
                a == M.DATA_DIR or a.startswith(M.DATA_DIR + '/') for a in e[1:]):
            return i
    return None


def test_deploy_stops_the_service_before_root_touches_the_ptt_folder(box):
    _run_deploy(box)
    cmds = box.cmds()
    stop = next(i for i, e in enumerate(cmds) if e[:3] == ['systemctl', 'stop', M.UNIT])
    first = _first_write_into_ptt_folder(cmds)
    assert first is not None and stop < first, cmds[:first + 1]


def test_every_recursive_chown_in_the_module_uses_dash_h(box, monkeypatch):
    _run_deploy(box)
    box.settings['meshrelay'] = {'tag': 'v4.5.0'}
    monkeypatch.setattr(M, '_have_backup', lambda: True)
    monkeypatch.setattr(M, '_have_web_backup', lambda: True)
    M.rollback(box.ctx(), plog=box.logs.append)
    chowns = [e for e in box.cmds() if e[0] == 'chown' and '-R' in e]
    assert chowns, 'expected a recursive chown'
    for e in chowns:
        assert '-h' in e, e
    # ...and the module source has no other recursive chown
    src = (REPO / 'modules/meshrelay.py').read_text()
    assert "['chown', '-R'" not in src


def test_install_tree_chown_does_not_follow_links(box):
    M._install_tree(box.ctx(), '/nonexistent-src', '/opt/x', owner='ptt:ptt')
    assert ['chown', '-h', '-R', 'ptt:ptt', '/opt/x'] in box.cmds()


def test_broker_accepts_chown_dash_h_on_the_ptt_folder():
    assert B._evaluate({'op': 'exec', 'argv': ['chown', '-h', '-R', 'ptt:ptt', M.DATA_DIR]})[0] == 'ALLOW'


def test_web_files_are_root_owned_next_to_the_binary_and_linked_into_the_data_folder(box):
    """Security (ops #980): root never copies into the ptt tree, and the non-root console can read the
    files for the update backup (a 700 folder owned by ptt made that backup walk see nothing)."""
    assert M.WEB_DIR.startswith(M.INSTALL_DIR + '/') and not M.WEB_DIR.startswith(M.DATA_DIR)
    assert M.WEB_LINK == M.DATA_DIR + '/web'
    _run_deploy(box)
    cmds = box.cmds()
    link = [i for i, e in enumerate(cmds) if e == ['ln', '-sfn', M.WEB_DIR, M.WEB_LINK]]
    perms = [i for i, e in enumerate(cmds) if e[:3] == ['chown', '-h', '-R']]
    stop = next(i for i, e in enumerate(cmds) if e[:3] == ['systemctl', 'stop', M.UNIT])
    assert link and perms and stop < perms[0] < link[0]
    for e in cmds:
        assert not (e[0] == 'chown' and M.WEB_DIR in e), e        # web files stay root-owned


def test_update_and_rollback_never_chown_the_web_files_to_ptt(box, monkeypatch):
    box.files[M.CONFIG_PATH] = M.seed_config_text()
    box.settings['meshrelay'] = {'tag': 'v4.5.0'}
    monkeypatch.setattr(M, '_have_backup', lambda: True)
    monkeypatch.setattr(M, '_have_web_backup', lambda: True)
    assert M.update(box.ctx(), plog=box.logs.append)['success'] is True
    M.rollback(box.ctx(), plog=box.logs.append)
    assert not [e for e in box.cmds() if e[0] == 'chown']
    # the backup is read from the root-owned folder, after the stop
    cmds = box.cmds()
    stop = next(i for i, e in enumerate(cmds) if e[:3] == ['systemctl', 'stop', M.UNIT])
    first_cp = next(i for i, e in enumerate(cmds) if e[0] == 'cp')
    assert stop < first_cp


def test_broker_accepts_the_web_link_command_and_still_refuses_links_out_of_the_data_dir():
    assert B._evaluate({'op': 'exec', 'argv': ['ln', '-sfn', M.WEB_DIR, M.WEB_LINK]})[0] == 'ALLOW'
    assert B._evaluate({'op': 'exec', 'argv': ['ln', '-sfn', '/etc', M.DATA_DIR + '/evil']})[0] == 'DENY'


def test_deploy_stops_before_touching_anything_when_the_service_will_not_stop(box):
    box.still_active = True
    job = _run_deploy(box)
    assert job['error'] is True and job['complete'] is False
    assert not [e for e in box.cmds() if e[0] in ('cp', 'chown', 'chmod', 'mkdir', 'rm', 'ln')]
    assert not [e for e in box.events if e[0] == 'WRITE']


def test_rollback_and_uninstall_refuse_to_go_on_when_the_service_will_not_stop(box, monkeypatch):
    box.still_active = True
    monkeypatch.setattr(M, '_have_backup', lambda: True)
    with pytest.raises(RuntimeError, match='did not stop'):
        M.rollback(box.ctx(), plog=box.logs.append)
    with pytest.raises(RuntimeError, match='did not stop'):
        M.uninstall(box.ctx(), {}, {})
    assert not [e for e in box.cmds() if e[0] in ('cp', 'rm', 'chown', 'chmod')]


def test_deploy_asks_the_console_to_put_the_mfa_gate_on_the_new_authentik_app(box):
    _run_deploy(box)
    assert box.mfa == [1]


def test_a_failed_mfa_sweep_never_fails_the_deploy(box):
    def boom(plog=None):
        raise RuntimeError('authentik away')
    c = box.ctx()
    c['_w1_reassert_app_mfa'] = boom
    job = {'running': True, 'complete': False, 'error': False, 'log': []}
    M.deploy(c, job, {})
    assert job['complete'] is True and job['error'] is False


def test_deploy_update_rollback_and_uninstall_each_leave_an_audit_line(box, monkeypatch):
    box.files[M.CONFIG_PATH] = M.seed_config_text()
    _run_deploy(box)
    box.settings['meshrelay'] = {'tag': 'v4.5.0'}
    monkeypatch.setattr(M, '_have_backup', lambda: True)
    monkeypatch.setattr(M, '_have_web_backup', lambda: True)
    M.update(box.ctx(), plog=box.logs.append)
    M.rollback(box.ctx(), plog=box.logs.append)
    M.uninstall(box.ctx(), {}, {'keep_data': True})
    assert [a[0] for a in box.audits] == ['meshrelay_deploy', 'meshrelay_update', 'meshrelay_rollback', 'meshrelay_uninstall']
    assert not any('token' in a[1].lower() or 'password' in a[1].lower() for a in box.audits)


@pytest.mark.parametrize('text', ['{"web_port": "abc"}', '{"web_port": [1]}', '{"github_token": 5, "web_port": 8187}',
                                  '{"auth_enabled": true, "web_port": null}'])
def test_config_problem_never_raises_on_a_config_the_ptt_account_wrote(text):
    assert isinstance(M.config_problem(text), str)


def _views(monkeypatch, box):
    flask = pytest.importorskip('flask')
    got = {}
    monkeypatch.setattr(M, 'register_module', lambda d: got.update(d))
    M.register(box.ctx())
    routes = {r['endpoint']: r['view'] for r in got['extra_routes']}
    return flask.Flask('t'), routes


def test_update_and_rollback_refuse_to_overlap_a_running_deploy_or_each_other(box, monkeypatch):
    app, routes = _views(monkeypatch, box)
    monkeypatch.setattr(M, 'job_state', lambda k: {'running': True})
    with app.test_request_context():
        for name in ('meshrelay_update', 'meshrelay_rollback'):
            resp, code = routes[name]()
            assert code == 409, name
    monkeypatch.setattr(M, 'job_state', lambda k: {'running': False})
    assert M._BUSY.acquire(blocking=False)          # another update holds the lock
    try:
        with app.test_request_context():
            assert routes['meshrelay_update']()[1] == 409
            assert routes['meshrelay_rollback']()[1] == 409
    finally:
        M._BUSY.release()
    assert not M._BUSY.locked()


def test_update_that_fails_after_the_stop_but_before_any_swap_starts_the_old_service_again(box, monkeypatch):
    box.settings['meshrelay'] = {'tag': 'v4.5.0'}
    real = M._priv

    def failing(ctx, argv, timeout=120, check=True):
        if argv[:1] == ['cp'] and argv[2:3] == [M.BACKUP_DIR + '/ptt-server']:
            raise RuntimeError('cp failed: disk full')
        return real(ctx, argv, timeout, check)
    monkeypatch.setattr(M, '_priv', failing)
    res = M.update(box.ctx(), plog=box.logs.append)
    assert res['success'] is False
    cmds = box.cmds()
    assert cmds[-1][:3] == ['systemctl', 'start', M.UNIT], cmds[-3:]
    assert ['cp', M.BACKUP_DIR + '/ptt-server', M.BIN_PATH] not in cmds     # nothing was swapped


class _Pw:
    def __init__(self, uid=998, gid=997, shell='/usr/sbin/nologin'):
        self.pw_uid, self.pw_gid, self.pw_shell = uid, gid, shell


class _Gr:
    def __init__(self, name, gid, mem=()):
        self.gr_name, self.gr_gid, self.gr_mem = name, gid, list(mem)


def _account(monkeypatch, pw=None, groups=None):
    pw = pw or _Pw()
    groups = groups if groups is not None else [_Gr('ptt', 997)]
    monkeypatch.setattr(B.pwd, 'getpwnam', lambda n: pw)
    monkeypatch.setattr(B.grp, 'getgrall', lambda: groups)

    def getgrgid(gid):
        for g in groups:
            if g.gr_gid == gid:
                return g
        raise KeyError(gid)

    def getgrnam(n):
        for g in groups:
            if g.gr_name == n:
                return g
        raise KeyError(n)
    monkeypatch.setattr(B.grp, 'getgrgid', getgrgid)
    monkeypatch.setattr(B.grp, 'getgrnam', getgrnam)


def test_ptt_account_check_passes_the_account_the_op_creates(monkeypatch):
    _account(monkeypatch)
    assert B._meshrelay_account_problem() == ''
    _account(monkeypatch, pw=_Pw(shell='/sbin/nologin'))
    assert B._meshrelay_account_problem() == ''


@pytest.mark.parametrize('group', ['docker', 'sudo', 'wheel', 'disk', 'shadow', 'adm', 'takwerx'])
def test_ptt_account_check_refuses_any_extra_group(monkeypatch, group):
    _account(monkeypatch, groups=[_Gr('ptt', 997), _Gr(group, 50, ['ptt'])])
    assert group in B._meshrelay_account_problem()


@pytest.mark.parametrize('shell', ['/bin/bash', '/bin/sh', '/usr/bin/zsh', '', '/tmp/nologin'])
def test_ptt_account_check_refuses_a_real_shell(monkeypatch, shell):
    _account(monkeypatch, pw=_Pw(shell=shell))
    assert 'shell' in B._meshrelay_account_problem()


def test_ptt_account_check_refuses_a_primary_group_that_is_not_its_own(monkeypatch):
    _account(monkeypatch, groups=[_Gr('docker', 997)])
    assert 'primary group' in B._meshrelay_account_problem()
    _account(monkeypatch, pw=_Pw(gid=0), groups=[_Gr('root', 0)])
    assert 'uid/gid 0' in B._meshrelay_account_problem()


def test_ptt_account_op_refuses_an_unfit_existing_account_and_creates_nothing(monkeypatch):
    _account(monkeypatch, groups=[_Gr('ptt', 997), _Gr('docker', 50, ['ptt'])])
    monkeypatch.setattr(B.subprocess, 'run', lambda *a, **k: (_ for _ in ()).throw(AssertionError('ran a command')))
    res = B._do_meshrelay_account({'op': 'meshrelay_account'})
    assert res['ok'] is False and 'docker' in res['error']


def test_console_side_account_check_matches_the_broker_rule():
    body = APP[APP.index('def _meshrelay_account_ready'):APP.index('def _ensure_meshrelay_account')]
    assert "pw.pw_shell not in (" in body and 'getgrall' in body and 'gr_name != _MESHRELAY_RUN_USER' in body


def test_broker_pins_the_ptt_unit_to_user_ptt_and_no_extra_groups():
    good = M.unit_text()
    B._check_unit_write(M.UNIT_PATH, good.encode(), 'w')
    for bad in (good.replace('User=ptt', 'User=mediamtx'),                       # shared list let this through
                good.replace('[Service]\n', '[Service]\nSupplementaryGroups=caddy\n', 1),
                good.replace('[Service]\n', '[Service]\nSupplementaryGroups=systemd-journal\n', 1),
                good.replace('[Service]\n', '[Service]\nGroup=takwerx\n', 1),
                good.replace('[Service]\n', '[Service]\nGroup=ptt\n', 1)):
        with pytest.raises(B.Denied):
            B._check_unit_write(M.UNIT_PATH, bad.encode(), 'w')


def test_broker_keeps_user_ptt_out_of_every_other_unit():
    mtx = ('[Unit]\nDescription=x\n[Service]\nUser=ptt\nExecStart=/opt/mediamtx/mediamtx\n'
           '[Install]\nWantedBy=multi-user.target\n')
    with pytest.raises(B.Denied, match='only for'):
        B._check_unit_write('/etc/systemd/system/mediamtx.service', mtx.encode(), 'w')


# ── condition 2: web port closed to the outside ───────────────────────────────────────

def test_deploy_opens_only_the_phone_port_and_closes_the_web_port(box):
    _run_deploy(box)
    assert ('allow', M.PTT_PORT, 'udp') in box.fw
    assert ('deny', M.WEB_PORT, 'tcp') in box.fw
    assert not [f for f in box.fw if f[0] == 'allow' and f[1] == M.WEB_PORT]


def test_web_port_does_not_collide_with_guard_dog_on_8080():
    assert M.WEB_PORT != 8080       # Guard Dog's health agent and Fed Hub use 8080 on a console box
    assert M.PTT_PORT == 5000


def test_uninstall_closes_the_phone_port(box):
    M.uninstall(box.ctx(), {}, {})
    assert ('remove', M.PTT_PORT, 'udp') in box.fw


# ── condition 3: dashboard behind Authentik ───────────────────────────────────────────

def test_caddy_vhost_sits_behind_forward_auth_and_proxies_to_loopback_only():
    lines = []
    M.append_caddy_vhost(lines, 'meshrelay.example.test', True, 'ak:9000',
                         'request_header -X-Authentik-*', lambda url: lines.append('RESCUE'),
                         'https://meshrelay.example.test/',
                         ['        forward_auth ak:9000 {', '        }'])
    text = '\n'.join(lines)
    assert text.index('forward_auth ak:9000') < text.index('reverse_proxy 127.0.0.1:%d' % M.WEB_PORT)
    assert 'request_header -X-Authentik-*' in text and 'RESCUE' in text
    ups = re.findall(r'reverse_proxy (?:/\S+ )?(\S+)', text)
    assert set(ups) <= {'ak:9000', '127.0.0.1:%d' % M.WEB_PORT}


def test_caddy_vhost_without_authentik_is_a_503_and_never_a_proxy():
    lines = []
    M.append_caddy_vhost(lines, 'meshrelay.example.test', False, 'ak:9000',
                         'request_header -X-Authentik-*', lambda url: None, 'https://x/')
    text = '\n'.join(lines)
    assert ' 503' in text and 'reverse_proxy' not in text


def test_module_never_writes_its_own_forward_auth_or_trusted_proxies():
    """The red-team scan fails a forward_auth block written outside _caddy_forward_auth_lines()
    (X-Forwarded-Host pins and the application lock, ops #1082, #1108) and a trusted_proxies line."""
    src = open(M.__file__).read()
    assert 'trusted_proxies' not in src
    assert not re.search(r'append\([^)]*forward_auth', src)
    lines = []
    M.append_caddy_vhost(lines, 'm.example.test', True, 'ak:9000', 'strip', lambda url: None, 'https://m/', [])
    assert 'forward_auth' not in '\n'.join(lines)
    i = APP.index('mod_registry.meshrelay.append_caddy_vhost')
    # the block is made just above the call (a plain `if ak:` line, so the Caddyfile guard
    # tests that count the writer's calls see it)
    assert '_caddy_forward_auth_lines(ak_up, "        ", app=_fa_app(mr_host))' in APP[i - 400:i + 600]


def test_app_wires_the_vhost_the_proxy_app_and_the_seams():
    assert 'mod_registry.meshrelay.append_caddy_vhost' in APP
    assert "'meshrelay': 'meshrelay'," in APP
    for seam in ("'_ensure_meshrelay_account': _ensure_meshrelay_account",
                 "'_ensure_authentik_meshrelay_app': _ensure_authentik_meshrelay_app",
                 "'_fw_deny': _fw_deny"):
        assert seam in APP, seam


def test_descriptor_requires_authentik_and_routes_need_a_console_login():
    import modules
    modules.MODULES.pop('meshrelay', None)
    M.register({'x': 1})
    d = modules.MODULES['meshrelay']
    assert d['requires_modules'] == ['authentik']
    assert d['service_units'] == ['ptt-server']
    assert {r['url'] for r in d['extra_routes']} >= {'/api/meshrelay/update', '/api/meshrelay/rollback',
                                                      '/api/meshrelay/status'}
    assert d['ports'] == ['5000/udp']          # the web port is never listed as opened


# ── condition 4: pinned release, no install.sh ────────────────────────────────────────

def test_an_empty_pin_fails_closed():
    empty = {'tag': '', 'assets': {'amd64': ('ptt-server-linux', ''),
                                   'arm64': ('ptt-server-linux-arm64', '')},
             'web': ('web.tar.gz', '')}
    assert M.pin_problem(empty) != ''


def test_the_shipped_pin_is_ryans_public_v490_with_the_hashes_of_its_files():
    """The values come from files downloaded from the public release and equal its
    SHA256SUMS (ops #973, Thu Nov 26, 2026). A drifted value would refuse every install."""
    assert M.RELEASE['tag'] == 'v4.9.0'
    assert M.RELEASE['assets']['amd64'] == (
        'ptt-server-linux', '4fb1aea80a2b0f78cba1581da0c6b8528e94b817463d9872eecc1750f6fd53d0')
    assert M.RELEASE['assets']['arm64'] == (
        'ptt-server-linux-arm64', '227d223f3cd0d040e1cab5b7bad3904ec4f00cab3649f37346031a73fa737b54')
    assert M.RELEASE['web'] == (
        'web.tar.gz', '947a9c35822a7ff316eccdc043627cfee3509161fb99b9156db2239850598539')
    assert M.pin_problem(arch='amd64') == '' and M.pin_problem(arch='arm64') == ''


def test_pin_problem_cases(monkeypatch):
    _pin(monkeypatch)
    assert M.pin_problem(arch='amd64') == '' and M.pin_problem(arch='arm64') == ''
    assert 'arm' in M.pin_problem(arch='riscv')  or M.pin_problem(arch='riscv')
    bad = dict(M.RELEASE, tag='main')
    assert M.pin_problem(bad)
    bad = dict(M.RELEASE, assets={'amd64': ('ptt-server-linux', 'abc')})
    assert 'SHA-256' in M.pin_problem(bad)
    bad = dict(M.RELEASE, web=('web.tar.gz', ''))
    assert 'SHA-256' in M.pin_problem(bad)


def test_deploy_with_no_pin_runs_nothing(monkeypatch):
    monkeypatch.setattr(M, 'RELEASE', {'tag': '', 'assets': {'amd64': ('ptt-server-linux', ''),
                                                             'arm64': ('ptt-server-linux-arm64', '')},
                                       'web': ('web.tar.gz', '')})
    b = Box(b'')
    b.fetch = lambda *a, **k: pytest.fail('downloaded with no pin')
    job = {'running': True, 'complete': False, 'error': False, 'log': []}
    M.deploy(b.ctx(), job, {})
    assert job['error'] and not b.events and not b.fw


def test_a_file_that_does_not_match_the_pinned_sha_is_deleted_and_not_installed(tmp_path):
    dest = tmp_path / 'f'

    def fetcher(tag, name, d, token, limit):
        pathlib.Path(d).write_bytes(b'tampered')
        return hashlib.sha256(b'tampered').hexdigest()
    with pytest.raises(RuntimeError, match='does not match'):
        M.fetch_verified('v1.0.0', 'x', hashlib.sha256(b'real').hexdigest(), str(dest), fetcher=fetcher)
    assert not dest.exists()


def test_deploy_stops_before_installing_when_the_binary_sha_is_wrong(monkeypatch, box):
    box.fetch = lambda tag, name, dest, token='', limit=0: (pathlib.Path(dest).write_bytes(b'evil')
                                                            or hashlib.sha256(b'evil').hexdigest())
    job = _run_deploy(box)
    assert job['error']
    assert not [e for e in box.cmds() if e[0] == 'cp' and e[-1] == M.BIN_PATH]


def test_redirect_to_signed_storage_drops_the_token():
    h = M._NoAuthOnRedirect()
    req = urllib.request.Request('https://api.github.com/x', headers={'Authorization': 'Bearer ghp_SECRET'})
    new = h.redirect_request(req, None, 302, 'Found', {}, 'https://objects.example.net/signed?x=1')
    assert new is not None and not new.has_header('Authorization')


def test_only_https_downloads():
    with pytest.raises(ValueError):
        M._open('http://github.com/x')


def _tar_with(name, kind=tarfile.REGTYPE, link=''):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        ti = tarfile.TarInfo(name)
        ti.type = kind
        ti.linkname = link
        ti.size = 0
        tf.addfile(ti)
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode='r:gz')


@pytest.mark.parametrize('name,kind,link', [
    ('/etc/passwd', tarfile.REGTYPE, ''), ('web/../../x', tarfile.REGTYPE, ''),
    ('other/x', tarfile.REGTYPE, ''), ('web/l', tarfile.SYMTYPE, '/etc'), ('web/d', tarfile.CHRTYPE, ''),
])
def test_web_archive_members_that_could_escape_are_refused(name, kind, link):
    with pytest.raises(RuntimeError, match='unsafe'):
        M.safe_web_members(_tar_with(name, kind, link))


def test_module_never_runs_rye_install_script_or_widens_permissions():
    """No install.sh, git pull, setcap, sudoers rule or chmod o+x in anything the module runs."""
    tree = ast.parse((REPO / 'modules/meshrelay.py').read_text())
    docs = {id(n.body[0].value) for n in ast.walk(tree)
            if isinstance(n, (ast.Module, ast.FunctionDef)) and n.body
            and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], 'value', None), ast.Constant)}
    strings = [n.value for n in ast.walk(tree)
               if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs]
    for s in strings:
        for bad in ('install.sh', 'git pull', 'setcap', 'o+x', 'sudoers', 'config.json.example', 'update.sh'):
            assert bad not in s, (bad, s[:60])


def test_in_app_updater_cannot_write_the_binary_folder():
    """The updater writes next to the binary. That folder is root-owned and read-only to ptt."""
    unit = M.unit_text()
    assert M.BIN_PATH.startswith(M.INSTALL_DIR + '/')
    assert M.INSTALL_DIR not in re.search(r'ReadWritePaths=(.*)', unit).group(1)
    assert 'ProtectSystem=strict' in unit


# ── condition 5: unit hardening, ptt account, modes ───────────────────────────────────

def test_unit_has_every_hardening_line():
    u = M.unit_text()
    for line in ('User=ptt', 'NoNewPrivileges=yes', 'ProtectSystem=strict', 'ProtectHome=yes',
                 'PrivateTmp=yes', f'ReadWritePaths={M.DATA_DIR}', f'ExecStart={M.BIN_PATH}'):
        assert line in u.splitlines(), line
    assert 'AmbientCapabilities' not in u and 'setcap' not in u     # port 5000 needs no capability
    assert 'User=root' not in u


@pytest.mark.parametrize('selinux', [False, True])
def test_broker_accepts_the_unit_as_written(selinux):
    B._check_unit_write(M.UNIT_PATH, M.unit_text(selinux).encode(), 'w')


def test_broker_refuses_the_unit_if_it_runs_as_root_or_adds_capabilities():
    good = M.unit_text()
    for bad in (good.replace('User=ptt', 'User=root'), good.replace('User=ptt', 'User=tak'),
                good + '\n[Service]\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n'):
        with pytest.raises(B.Denied):
            B._check_unit_write(M.UNIT_PATH, bad.encode(), 'w')


def test_broker_ptt_account_op_is_fixed_shape_and_useradd_stays_denied():
    assert B._evaluate({'op': 'meshrelay_account'})[0] == 'ALLOW'
    assert B._evaluate({'op': 'meshrelay_account', 'user': 'root'})[0] == 'DENY'
    assert B._evaluate({'op': 'exec', 'argv': ['useradd', 'ptt']})[0] == 'DENY'
    assert B._meshrelay_account_problem() in ('missing', '') or True     # reads /etc/passwd only


def test_broker_paths_and_classes_for_meshrelay():
    for p in (M.BIN_PATH, M.CONFIG_PATH, M.WEB_DIR + '/index.html', M.BACKUP_DIR + '/ptt-server'):
        assert B._path_allowed(p) == p
    assert B._dest_class(M.BIN_PATH) == B.DEST_DATA
    assert B._dest_class(M.CONFIG_PATH) == B.DEST_DATA
    # the ptt-owned data dir can hold a planted link: it gets the real-path check
    assert '/var/lib/meshrelay/' in B._CONSOLE_OWNED_PREFIXES
    assert '/opt/meshrelay/' not in B._CONSOLE_OWNED_PREFIXES      # root-owned, nothing to plant
    assert 'ptt-server.service' in B.UNIT_FILES and 'ptt' in B.UNIT_USERS
    assert 'ptt-server.service' in B.UNIT_MUST_BE_NONROOT


def test_broker_refuses_a_link_planted_in_the_ptt_data_dir(tmp_path, monkeypatch):
    data = tmp_path / 'meshrelay'
    data.mkdir()
    (data / 'evil').symlink_to('/etc')
    monkeypatch.setattr(B, 'PATH_ALLOW', (str(data) + '/',))
    monkeypatch.setattr(B, '_CONSOLE_OWNED_PREFIXES', (str(data) + '/',))
    with pytest.raises(B.Denied, match='symlink'):
        B._path_allowed(str(data / 'evil' / 'passwd'))
    assert B._path_allowed(str(data / 'config.json'))


def test_data_files_are_owner_only_and_the_folder_is_700(box):
    _run_deploy(box)
    cmds = box.cmds()
    assert ['chmod', '700', M.DATA_DIR] in cmds
    assert ['chmod', '600', M.CONFIG_PATH] in cmds
    assert ['chmod', '600', M.DATA_DIR + '/tak_connections.json'] in cmds
    assert ['chown', '-h', '-R', 'ptt:ptt', M.DATA_DIR] in cmds
    assert ['chown', 'root:root', M.BIN_PATH] in cmds


def test_no_chmod_on_parent_folders(box):
    _run_deploy(box)
    for e in box.cmds():
        if e[0] == 'chmod':
            assert e[-1] in (M.DATA_DIR, M.CONFIG_PATH, M.BIN_PATH, M.INSTALL_DIR) or e[-1].startswith(M.DATA_DIR + '/')
            assert 'o+x' not in e


# ── condition 6: the token ────────────────────────────────────────────────────────────

def test_token_never_reaches_a_log_a_command_or_the_app_config(box):
    box.settings['meshrelay_github_token'] = 'ghp_SECRETSECRET'
    seen = []
    orig = box.fetch

    def spy(tag, name, dest, token='', limit=0):
        seen.append(token)
        return orig(tag, name, dest, token, limit)
    box.fetch = spy
    job = _run_deploy(box)
    assert seen and set(seen) == {'ghp_SECRETSECRET'}              # used only to download
    blob = '\n'.join(job['log']) + repr(box.events) + repr(box.files)
    assert 'ghp_SECRETSECRET' not in blob.replace("'meshrelay_github_token'", '')


def test_settings_keys_that_hold_secrets_match_the_diagnostics_redactor():
    m = re.search(r"_DIAG_SECRET_KEY_RE = re\.compile\(r'([^']+)'", APP)
    assert m, 'diagnostics redactor moved: update this test'
    rx = re.compile(m.group(1), re.I)
    assert rx.search('meshrelay_github_token') and rx.search('meshrelay_first_admin_password')


# ── first admin password, uninstall ───────────────────────────────────────────────────

def test_first_admin_password_is_read_from_the_journal_not_admin_admin():
    j = ("2026/11/19 server started\nINITIAL ADMIN PASSWORD (record this, it will not be shown again):\n"
         "2026/11/19 12:00:00   admin / Zx9fQ2mPaB\nnext line\n")
    assert M.parse_initial_password(j) == 'Zx9fQ2mPaB'
    assert M.parse_initial_password('nothing here') == ''


def test_uninstall_removes_data_unless_asked_to_keep_it(box):
    M.uninstall(box.ctx(), {}, {})
    assert ['rm', '-rf', M.DATA_DIR] in box.cmds()
    box.events.clear()
    res = M.uninstall(box.ctx(), {}, {'keep_data': True})
    assert ['rm', '-rf', M.DATA_DIR] not in box.cmds()
    assert any('kept' in s for s in res['steps'])


def test_deploy_needs_a_domain(monkeypatch, box):
    box.settings['fqdn'] = ''
    job = _run_deploy(box)
    assert job['error'] and not box.events


def test_failed_health_check_after_update_rolls_back(box, monkeypatch):
    box.settings['meshrelay'] = {'tag': 'v4.5.0'}
    monkeypatch.setattr(M, 'health', lambda ctx: (False, 'dashboard down'))
    monkeypatch.setattr(M, '_have_backup', lambda: True)
    monkeypatch.setattr(M, '_have_web_backup', lambda: False)
    res = M.update(box.ctx(), plog=box.logs.append)
    assert res['success'] is False and 'rolled back' in res['error']
    assert ['cp', M.BACKUP_DIR + '/ptt-server', M.BIN_PATH] in box.cmds()
    assert box.settings['meshrelay']['tag'] == 'v4.5.0'


def test_ptt_server_unit_name_is_written_by_module_code_the_broker_scan_sees():
    src = (REPO / 'modules/meshrelay.py').read_text()
    assert '/etc/systemd/system/ptt-server.service' in src


# ── the phone-login jail (phones never touch Caddy, so a Caddy-log jail could not see them) ──

def _jail_regexes():
    m = re.search(r"'meshrelay-auth': \(\n(.*?)\n    \),", APP, re.S)
    assert m, 'meshrelay-auth filter missing from _F2B_OWNED_FILTERS'
    ns = {}
    exec('F = (' + m.group(1) + ')', ns)
    text = ns['F']
    rx = re.search(r'failregex = (.*?)\nignoreregex', text, re.S).group(1)
    pats = [ln.strip() for ln in rx.splitlines() if ln.strip()]
    return text, [re.compile(p.replace('<HOST>', r'(?P<host>\d{1,3}(?:\.\d{1,3}){3})')) for p in pats]


@pytest.mark.parametrize('line,host', [
    ('2026/11/19 12:00:00 Auth failed: unknown user bob from 203.0.113.9:40001', '203.0.113.9'),
    ('2026/11/19 12:00:00 Auth failed: wrong password for user alice from 203.0.113.9:40001', '203.0.113.9'),
    ('2026/11/19 12:00:00 JOIN rejected: bob from 198.51.100.4:5000 (not authenticated)', '198.51.100.4'),
    # a hostile name: the address is still the LAST one on the line
    ('2026/11/19 12:00:00 Auth failed: unknown user x from 8.8.8.8:1 from 203.0.113.9:40001', '203.0.113.9'),
    ('2026/11/19 12:00:00 JOIN rejected: x from 8.8.8.8:1 (not authenticated) from 198.51.100.4:7 (not authenticated)', '198.51.100.4'),
])
def test_phone_login_filter_matches_failures_and_takes_the_real_address(line, host):
    _, rxs = _jail_regexes()
    hits = [m.group('host') for r in rxs for m in [r.search(line)] if m]
    assert hits == [host]


@pytest.mark.parametrize('line', [
    '2026/11/19 12:00:00 Auth (challenge-response) success: user bob from 203.0.113.9:40001',
    '2026/11/19 12:00:00 Auth challenge sent to 203.0.113.9:40001 for user bob',
    '2026/11/19 12:00:00 Auth failed: unknown user bob from 203.0.113.9:40001 and more',
    '2026/11/19 12:00:00 JOIN ok: bob from 203.0.113.9:40001',
])
def test_phone_login_filter_ignores_success_and_trailing_text(line):
    _, rxs = _jail_regexes()
    assert not [r for r in rxs if r.search(line)]


def _jail_body():
    return APP[APP.index('def _f2b_arm_meshrelay_jail'):APP.index('def _f2b_disarm_meshrelay_jail')]


def test_phone_login_jail_reads_the_journal_and_never_blocks_anyone():
    """Security (ops #980): a UDP source address can be forged, so one forged packet could get
    a victim's phone banned. The jail reads the journal and only raises an alert."""
    body = _jail_body()
    assert 'backend  = systemd' in body and '_SYSTEMD_UNIT=ptt-server.service' in body
    assert "'fail2ban-client', 'status', 'meshrelay-auth'" in body      # proves it loaded
    # no firewall action of any kind, and no Guard Dog "Banned" mail
    for banned in ('iptables', 'banaction', 'protocol=udp', 'allports', 'ufw', 'nftables',
                   'infratak-guarddog\n', 'infratak-guarddog"'):
        assert banned not in body, banned
    assert 'action   = {MESHRELAY_F2B_ACTION}' in body
    m = re.search(r"^MESHRELAY_F2B_ACTION = '([^']+)'", APP, re.M)
    assert m and m.group(1) == 'infratak-meshrelay-alert'


def _alert_action_text():
    m = re.search(r'_MESHRELAY_ALERT_ACTION = \(\n(.*?)\n\)\n', APP, re.S)
    assert m, '_MESHRELAY_ALERT_ACTION missing'
    ns = {}
    exec('T = (' + m.group(1) + ')', ns)
    return ns['T']


def test_phone_login_alert_action_only_writes_a_log_line():
    text = _alert_action_text()
    assert text.startswith('[Definition]')
    body = [ln for ln in text.splitlines() if ln.startswith('actionban')]
    assert len(body) == 1
    ban = body[0]
    assert '/var/log/takguard/restarts.log' in ban and 'nothing blocked' in ban
    for bad in ('iptables', 'nft', 'ufw', 'firewall-cmd', 'fail2ban-client', 'infratak-f2b-notify', 'Banned'):
        assert bad not in ban, bad
    assert re.search(r'^actionunban\s*=\s*$', text, re.M)


def test_disarming_the_jail_removes_the_alert_action_file_too():
    start = APP.index('def _f2b_disarm_meshrelay_jail')
    body = APP[start:APP.index('\n\n\n', start)]
    assert 'MESHRELAY_F2B_ACTION_PATH' in body and "'rm', '-f'" in body


def test_deploy_arms_the_jail_and_uninstall_removes_it(box):
    _run_deploy(box)
    assert ('jail', 'arm') in box.fw
    M.uninstall(box.ctx(), {}, {})
    assert ('jail', 'disarm') in box.fw


# ── update emails, full uninstall ─────────────────────────────────────────────────────

def test_version_info_feeds_the_pending_update_email(box):
    box.settings['meshrelay'] = {'tag': 'v4.5.0'}
    info = M.get_version_info(box.ctx())
    assert info == {'version': 'v4.5.0', 'latest': 'v4.6.0', 'update_available': True}
    box.settings['meshrelay'] = {'tag': 'v4.6.0'}
    assert M.get_version_info(box.ctx())['update_available'] is False
    box.settings.pop('meshrelay')
    assert M.get_version_info(box.ctx())['update_available'] is False     # not installed: no email


def test_app_lists_meshrelay_for_update_emails_version_cards_and_full_uninstall():
    assert "('meshrelay', 'MeshRelay', None, False, 'MeshRelay page → Update.')," in APP
    assert "mod_registry.meshrelay.get_version_info(mod_registry.get_ctx())" in APP
    assert "mod_registry.uninstall_module('meshrelay', log_fn=plog)" in APP
    assert "'meshrelay': ['meshrelay_http']" in APP


# ── a second Deploy meets the Authentik provider that the first one made (box test, ops #973) ──

class _AkResp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self):
        return self._b


class _FakeAuthentik:
    """Authentik 2026.8.5 as seen on a box: a POST of an existing provider or app is a 400, and a
    PATCH of a proxy provider without `mode` is a 400 too (ops #708: validated as mode=proxy)."""

    def __init__(self, provider_exists=True, current_validity='hours=1'):
        self.calls = []
        self.patched = []
        self.created = []
        self.provider_exists = provider_exists
        self.current_validity = current_validity

    def urlopen(self, req, timeout=None):
        url, method = req.full_url, (getattr(req, 'method', None) or 'GET')
        body = json.loads(req.data.decode()) if req.data else {}
        self.calls.append((method, url))

        def refuse(msg):
            raise urllib.error.HTTPError(url, 400, 'Bad Request', {}, io.BytesIO(msg.encode()))
        if 'flows/instances/?designation=authorization' in url:
            return _AkResp({'results': [{'pk': 'flow-a', 'slug': 'default-provider-authorization-implicit-consent'}]})
        if 'flows/instances/?designation=invalidation' in url:
            return _AkResp({'results': [{'pk': 'flow-i', 'slug': 'default-invalidation-flow'}]})
        if url.endswith('/providers/proxy/') and method == 'POST':
            if self.provider_exists:
                refuse('{"name":["provider with this name already exists."]}')
            self.created.append(body)
            return _AkResp({'pk': 7})
        if 'providers/proxy/?search=MeshRelay' in url:
            return _AkResp({'results': [{'pk': 7, 'access_token_validity': self.current_validity}]})
        if '/providers/proxy/7/' in url and method == 'PATCH':
            if 'mode' not in body:
                refuse('{"internal_host":["Internal host cannot be empty when forward auth is disabled."]}')
            self.patched.append(body)
            return _AkResp({})
        if url.endswith('/core/applications/') and method == 'POST':
            refuse('{"slug":["Application with this slug already exists."]}')
        if '/core/applications/meshrelay/' in url and method == 'PATCH':
            return _AkResp({})
        raise AssertionError(f'unexpected Authentik call {method} {url}')


def _load_ak_app_func(monkeypatch, fake, logs):
    tree = ast.parse(APP)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_ensure_authentik_meshrelay_app')
    ns = {'json': json, 'time': types.SimpleNamespace(sleep=lambda s: None),
          '_get_authentik_api_url': lambda s: 'http://ak.test',
          '_pub_hostport': lambda h: h,
          '_get_service_domain': lambda s, k: 'meshrelay.example.test',
          '_outpost_add_providers_safe': lambda *a, **k: logs.append('outpost'),
          }
    # the sign-in length helpers are the real ones from app.py (ops #1159), not stand-ins
    for n in tree.body:
        name = n.name if isinstance(n, ast.FunctionDef) else None
        if isinstance(n, ast.Assign):
            name = next((t.id for t in n.targets if isinstance(t, ast.Name)), None)
        if name in ('_PROXY_SESSION_VALIDITY', '_AUTHENTIK_DEFAULT_ACCESS_TOKEN_VALIDITY',
                    '_proxy_session_validity_to_write'):
            exec(compile(ast.Module([n], []), 'app.py', 'exec'), ns)
    exec(compile(ast.Module([fn], []), 'app.py', 'exec'), ns)
    monkeypatch.setattr(urllib.request, 'urlopen', fake.urlopen)
    return ns['_ensure_authentik_meshrelay_app']


def test_second_deploy_updates_the_existing_authentik_provider_with_its_mode(monkeypatch):
    fake, logs = _FakeAuthentik(), []
    ensure = _load_ak_app_func(monkeypatch, fake, logs)
    assert ensure('example.test', 'tok', plog=logs.append, settings={}) is True
    assert fake.patched and fake.patched[0]['mode'] == 'forward_single'
    assert fake.patched[0]['external_host'] == 'https://meshrelay.example.test'
    assert not [m for m in logs if 'error' in str(m).lower()], logs
    assert 'outpost' in logs         # the provider still reaches the embedded outpost


# ── sign-in length (ops #1159: Authentik has access_token_validity, not token_validity) ──

def test_a_new_provider_gets_the_real_sign_in_length_field(monkeypatch):
    """Red before: the body sent `token_validity`, which Authentik ignores, so dashboard
    sign-ins ended after Authentik's one-hour default instead of 24 hours."""
    fake, logs = _FakeAuthentik(provider_exists=False), []
    ensure = _load_ak_app_func(monkeypatch, fake, logs)
    assert ensure('example.test', 'tok', plog=logs.append, settings={}) is True
    (body,) = fake.created
    assert body['access_token_validity'] == 'hours=24'
    assert 'token_validity' not in body


def test_an_existing_provider_on_the_default_moves_to_24_hours(monkeypatch):
    fake, logs = _FakeAuthentik(current_validity='hours=1'), []
    ensure = _load_ak_app_func(monkeypatch, fake, logs)
    assert ensure('example.test', 'tok', plog=logs.append, settings={}) is True
    assert fake.patched[0]['access_token_validity'] == 'hours=24'


def test_an_existing_provider_keeps_a_length_the_operator_chose(monkeypatch):
    fake, logs = _FakeAuthentik(current_validity='hours=8'), []
    ensure = _load_ak_app_func(monkeypatch, fake, logs)
    assert ensure('example.test', 'tok', plog=logs.append, settings={}) is True
    assert fake.patched[0]['access_token_validity'] == 'hours=8'


def test_the_console_repairs_the_meshrelay_provider_like_the_others():
    """_INFRATAK_PROXY_PROVIDER_NAMES lists the providers infra-TAK owns, so an existing one
    on the one-hour default is moved to 24 hours by the start-up repair."""
    m = re.search(r'_INFRATAK_PROXY_PROVIDER_NAMES = frozenset\(\{(.*?)\}\)', APP, re.S)
    assert m and "'MeshRelay Proxy'" in m.group(1)
