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
"""ops #643, console half: MediaMTX and its web editor do not run as the console's account.

Both units said `User=takwerx`, the console's own account. Least privilege: the local
deploy now writes `User=mediamtx` (its own account), and a startup
migration moves boxes already installed, putting everything back if a service does not
come back up. Every path that re-owns MediaMTX's files gives them to whoever runs it,
never back to takwerx, and never follows a link that account could plant.
"""
import os
import pathlib
import re
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

ED_UNIT = '/etc/systemd/system/mediamtx-webeditor.service'
MTX_UNIT = '/etc/systemd/system/mediamtx.service'
DROPIN = '/etc/systemd/system/mediamtx-webeditor.service.d/20-infratak-home.conf'
SOCK = '/run/takwerx-broker-mediamtx.sock'


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


def _fn_full(name):
    """A top-level function whose body holds column-0 text (big f-strings): up to the next
    top-level def or decorator after a blank line."""
    a = APP.index(f'\ndef {name}(') + 1
    m = re.search(r'\n\n+(?=(def |@|class |[A-Z_]+ = ))', APP[a:])
    return APP[a:a + m.start()]


def _const(name):
    m = re.search(r'^%s = (.+?)$' % re.escape(name), APP, re.M)
    assert m, f'{name} not found in app.py'
    return m.group(1)


def _ns(**extra):
    ns = {'os': os, 're': re}
    for c in ('_MEDIAMTX_EDITOR_UNIT', '_MEDIAMTX_EDITOR_HOME_DROPIN', '_MEDIAMTX_CONF_DIR',
              '_MEDIAMTX_TRUSTED_PROXIES_KEY'):
        exec(f'{c} = {_const(c)}', ns)
    # the ops #643 constants block, as written
    a = APP.index("_MEDIAMTX_RUN_USER = 'mediamtx'")
    exec(APP[a:APP.index('\n\n\ndef ', a)], ns)
    for f in ('_unit_text_with_env', '_mediamtx_unit_text_as', '_mediamtx_unit_with_caddy_group'):
        exec(_fn(f), ns)
    ns.update(extra)
    return ns


OLD_MTX = """[Unit]
Description=MediaMTX RTSP/HLS/SRT Streaming Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mediamtx /usr/local/etc/mediamtx.yml
Restart=always
RestartSec=5
User=takwerx
SupplementaryGroups=caddy

[Install]
WantedBy=multi-user.target
"""

OLD_ED = """[Unit]
Description=MediaMTX Web Configuration Editor
After=network.target mediamtx.service

[Service]
Type=simple
ExecStartPre=-/usr/bin/python3 /opt/mediamtx-webeditor/ensure_overlay.py
ExecStart=/usr/bin/python3 /opt/mediamtx-webeditor/mediamtx_config_editor.py
WorkingDirectory=/opt/mediamtx-webeditor
Environment=PORT=5080
Environment=MEDIAMTX_API_URL=http://127.0.0.1:9898
Environment=INFRATAK_TRUSTED_PROXIES=127.0.0.1,::1
Restart=always
RestartSec=5
User=takwerx
UMask=0027

[Install]
WantedBy=multi-user.target
"""


# --- the proof: what the deploy writes and what the migration leaves -------------------
def test_local_deploy_units_name_the_run_user_not_takwerx():
    """Fails on dev: both local units were written straight from `User=takwerx` text."""
    src = _fn_full('run_mediamtx_deploy')
    assert "_ensure_mediamtx_account(plog=plog)" in src
    assert "_run_user = _mediamtx_run_user()" in src
    assert "mediamtx_svc = _mediamtx_unit_text_as(mediamtx_svc, _run_user)" in src
    assert "webeditor_svc = _mediamtx_unit_text_as(webeditor_svc, _run_user, editor=True)" in src
    # each write of a unit comes after its _run_user rewrite
    for var, unit in (('mediamtx_svc', 'mediamtx.service'), ('webeditor_svc', 'mediamtx-webeditor.service')):
        w = src.index(f"_write_priv('/etc/systemd/system/{unit}', {var})")
        assert src.rindex(f'{var} = _mediamtx_unit_text_as(', 0, w) < w
    assert "_mediamtx_hand_over_files(_run_user)" in src


def test_unit_text_as_mediamtx():
    ns = _ns()
    mtx = ns['_mediamtx_unit_text_as'](OLD_MTX, 'mediamtx')
    assert re.search(r'(?m)^User=mediamtx$', mtx) and 'User=takwerx' not in mtx
    assert 'SupplementaryGroups=caddy' in mtx
    ed = ns['_mediamtx_unit_text_as'](OLD_ED, 'mediamtx', editor=True)
    assert re.search(r'(?m)^User=mediamtx$', ed)
    assert 'Environment=TAKWERX_BROKER_SOCKET=/run/takwerx-broker-mediamtx.sock' in ed
    assert 'Environment=PYTHONPATH=/opt/mediamtx-webeditor-pylib' in ed
    assert ns['_mediamtx_unit_text_as'](ed, 'mediamtx', editor=True) == ed      # idempotent
    # the takwerx fallback leaves the editor's environment alone
    assert 'TAKWERX_BROKER_SOCKET' not in ns['_mediamtx_unit_text_as'](OLD_ED, 'takwerx', editor=True)


def test_caddy_group_follows_any_user():
    ns = _ns()
    txt = OLD_MTX.replace('SupplementaryGroups=caddy\n', '').replace('User=takwerx', 'User=mediamtx')
    out = ns['_mediamtx_unit_with_caddy_group'](txt)
    assert 'User=mediamtx\nSupplementaryGroups=caddy' in out


class Host:
    """A fake box for _mediamtx_move_to_own_account."""

    def __init__(self, files, active=('mediamtx', 'mediamtx-webeditor'), fail_as_mediamtx=(),
                 account=True, broker=True, run_user='mediamtx', pylib_ok=True, pylib_install_ok=True,
                 remote=False):
        self.files = dict(files)
        self.active = set(active)
        self.fail = set(fail_as_mediamtx)
        self.calls, self.handovers = [], []
        self.account, self.broker, self.run_user_v = account, broker, run_user
        self.pylib, self.pylib_install_ok, self.remote = pylib_ok, pylib_install_ok, remote

    def run(self, argv, **kw):
        self.calls.append(list(argv))
        if argv[:2] == ['systemctl', 'is-active']:
            return types.SimpleNamespace(returncode=0, stdout='active\n' if argv[2] in self.active else 'inactive\n')
        if argv[:2] == ['systemctl', 'stop']:
            self.active.discard(argv[2])
        if argv[:2] == ['systemctl', 'start']:
            unit = ED_UNIT if argv[2] == 'mediamtx-webeditor' else MTX_UNIT
            if not ('User=mediamtx' in self.files.get(unit, '') and argv[2] in self.fail):
                self.active.add(argv[2])
        if argv[:2] == ['rm', '-f']:
            self.files.pop(argv[2], None)
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    def ns(self):
        h = self
        fake_os = types.SimpleNamespace(path=types.SimpleNamespace(
            exists=lambda p: p in h.files or p == '/usr/local/bin/mediamtx',
            basename=os.path.basename))

        def install():
            h.pylib = h.pylib_install_ok
            return h.pylib_install_ok, '' if h.pylib_install_ok else 'ERROR: network unreachable'
        return _ns(
            os=fake_os,
            time=types.SimpleNamespace(sleep=lambda s: None),
            subprocess=types.SimpleNamespace(run=h.run),
            _sudo_wrap=lambda a: a,
            load_settings=lambda: {},
            _get_module_deployment_config=lambda s, k: {'target_mode': 'remote' if h.remote else 'local'},
            _read_priv=lambda p: h.files[p],
            _read_own_or_priv=lambda p: h.files.get(p, ''),
            _write_priv=lambda p, c, **k: h.files.__setitem__(p, c),
            _ensure_mediamtx_account=lambda plog=None: h.account,
            _mediamtx_run_user=lambda: h.run_user_v,
            _mediamtx_editor_pylib_ok=lambda: h.pylib,
            _mediamtx_editor_install_pylib=install,
            _mediamtx_hand_over_files=lambda user, plog=None: h.handovers.append(user),
        )

    def move(self):
        ns = self.ns()
        exec(_fn('_mediamtx_move_to_own_account'), ns)
        return ns['_mediamtx_move_to_own_account'](log=lambda m: None)


def _box(**kw):
    files = {MTX_UNIT: OLD_MTX, ED_UNIT: OLD_ED, DROPIN: '[Service]\nEnvironment=HOME=/home/takwerx\n',
             '/usr/local/etc/mediamtx.yml': 'rtsp: yes\npaths:\n  all_others:\n'}
    files.update(kw.pop('files', {}))
    return Host(files, **kw)


def test_migration_moves_both_units_off_the_console_account():
    h = _box()
    assert h.move() == 'moved'
    assert re.search(r'(?m)^User=mediamtx$', h.files[MTX_UNIT])
    assert re.search(r'(?m)^User=mediamtx$', h.files[ED_UNIT])
    assert 'User=takwerx' not in h.files[MTX_UNIT] + h.files[ED_UNIT]
    assert 'Environment=TAKWERX_BROKER_SOCKET=' + SOCK in h.files[ED_UNIT]
    assert 'Environment=PYTHONPATH=/opt/mediamtx-webeditor-pylib' in h.files[ED_UNIT]
    assert DROPIN not in h.files                    # no more HOME in the console's home
    assert h.handovers == ['mediamtx']
    assert {'mediamtx', 'mediamtx-webeditor'} <= h.active
    # stopped before the files changed hands, started after
    stops = [i for i, c in enumerate(h.calls) if c[:2] == ['systemctl', 'stop']]
    starts = [i for i, c in enumerate(h.calls) if c[:2] == ['systemctl', 'start']]
    assert stops and starts and max(stops) < min(starts)
    # and a second run changes nothing
    assert h.move() == 'already'


def test_migration_rolls_back_when_editor_will_not_start():
    h = _box(fail_as_mediamtx=('mediamtx-webeditor',))
    res = h.move()
    assert res.startswith('rolled back') and 'mediamtx-webeditor' in res
    assert h.files[MTX_UNIT] == OLD_MTX and h.files[ED_UNIT] == OLD_ED
    assert h.files[DROPIN].startswith('[Service]')
    assert h.handovers == ['mediamtx', 'takwerx']
    assert {'mediamtx', 'mediamtx-webeditor'} <= h.active


def test_migration_leaves_a_stopped_service_stopped():
    h = _box(active=('mediamtx',))
    assert h.move() == 'moved'
    assert 'mediamtx-webeditor' not in h.active


@pytest.mark.parametrize('kw,why', [
    (dict(remote=True), 'remote'),
    (dict(files={MTX_UNIT: OLD_MTX.replace('User=takwerx', 'User=root')}), 'root'),
    (dict(files={'/usr/local/etc/mediamtx.yml': 'paths:\n  cam1:\n    record: yes\n'}), 'recording'),
    (dict(files={'/usr/local/etc/mediamtx.yml': 'playback: yes\n'}), 'recording'),
    (dict(account=False), 'account'),
    (dict(run_user='takwerx'), 'broker'),
    (dict(pylib_ok=False, pylib_install_ok=False), 'packages'),
])
def test_migration_refuses_rather_than_guesses(kw, why):
    h = _box(**kw)
    res = h.move()
    assert res.startswith('skipped') and why in res, res
    assert h.files[ED_UNIT] == OLD_ED
    assert not any(c[:2] == ['systemctl', 'stop'] for c in h.calls)
    assert h.handovers == []


def test_migration_installs_editor_packages_first():
    h = _box(pylib_ok=False, pylib_install_ok=True)
    assert h.move() == 'moved'


def test_migration_runs_at_startup():
    assert '_startup_converge_mediamtx_own_account()' in APP
    start = APP.index('def _startup_migrations')
    assert APP.index('            _startup_converge_mediamtx_own_account()', start) > \
        APP.index('            _startup_heal_mediamtx_editor_prestart()', start)


# --- file ownership: given to whoever runs it, never followed through a link ----------
def test_hand_over_files_mediamtx():
    calls = []
    ns = _ns(subprocess=types.SimpleNamespace(run=lambda a, **k: calls.append(list(a))),
             _sudo_wrap=lambda a: a)
    ns['os'] = types.SimpleNamespace(
        path=types.SimpleNamespace(isdir=lambda p: True, join=os.path.join),
        listdir=lambda d: ['mediamtx.yml', 'mediamtx.yml.backup_20261110_150000',
                           'mediamtx.yml.pre_rollback', 'mediamtx.yml.$(id)', 'other.conf'])
    exec(_fn('_mediamtx_hand_over_files'), ns)
    ns['_mediamtx_hand_over_files']('mediamtx')
    assert ['chown', '-R', 'mediamtx:mediamtx', '/opt/mediamtx-webeditor'] in calls
    assert ['chown', 'mediamtx:takwerx', '/usr/local/etc'] in calls
    assert ['chmod', '2775', '/usr/local/etc'] in calls
    singles = [c for c in calls if c[:2] == ['chown', '-h']]
    assert [c[3] for c in singles] == ['/usr/local/etc/mediamtx.yml',
                                       '/usr/local/etc/mediamtx.yml.backup_20261110_150000',
                                       '/usr/local/etc/mediamtx.yml.pre_rollback']
    assert all(c[2] == 'mediamtx:takwerx' for c in singles)
    # every chown is either recursive (GNU -R never dereferences) or -h
    # (the config dir itself sits in root-owned /usr/local, so it cannot be a planted link)
    assert all(c[1] in ('-R', '-h') or c[1:] == ['mediamtx:takwerx', '/usr/local/etc']
               for c in calls if c[0] == 'chown')


def test_nothing_hands_mediamtx_files_back_to_takwerx():
    """Fails on dev: the SSL converge, the overlay converge and the deploy chowned the yml /
    overlay to takwerx:takwerx without -h — on a moved box that would lock MediaMTX out of
    its own config and follow a planted link."""
    assert not re.search(r"\['chown', 'takwerx:takwerx', (yml|dst)\]", APP)
    assert "_mediamtx_chown_yml(yml)" in _fn('_startup_converge_mediamtx_ssl')
    ov = _fn('_startup_converge_mediamtx_overlay')
    assert "['chown', '-h', f'{_owner}:{_owner}', dst]" in ov
    assert "'-h'" in _fn('_mediamtx_chown_yml')


def test_editor_write_converge_never_puts_the_editor_back_on_takwerx():
    src = _fn('_startup_converge_mediamtx_editor_write')
    assert "re.sub(r'(?m)^User=\\S+[ \\t]*$', 'User=takwerx'" not in src
    assert "re.sub(r'(?m)^User=root[ \\t]*$', 'User=takwerx'" in src


def test_config_dir_grant_respects_the_owner():
    src = _fn('_mediamtx_grant_config_dir_write')
    i = src.index("owner = _mediamtx_owner()")
    assert src.index("_mediamtx_hand_over_files(owner)") > i
    assert src.index("_mediamtx_hand_over_files(owner)") < src.index("'chown', 'root:takwerx'")


# --- the console never writes through a link the editor could plant --------------------
def test_root_write_priv_does_not_follow_links_in_mediamtx_dirs(tmp_path):
    ns = {'os': None}
    exec('import os as _real\n', ns)

    class _OS:
        def __getattr__(self, k):
            return getattr(os, k)

        @staticmethod
        def getuid():
            return 0
    ns.update(os=_OS(), _backup_coreconfig_before_write=lambda *a: None,
              _broker_should_route=lambda: False, _broker_available=lambda: False,
              _priv_write_wants_atomic=lambda path, mode: False,   # ops #666: not under test here
              _MEDIAMTX_NOFOLLOW_PREFIXES=(str(tmp_path) + '/ed/',))
    exec(_fn('_write_priv'), ns)
    (tmp_path / 'ed').mkdir()
    secret = tmp_path / 'console-code.py'
    secret.write_text('ORIGINAL')
    (tmp_path / 'ed' / 'mediamtx_ldap_overlay.py').symlink_to(secret)
    with pytest.raises(OSError):
        ns['_write_priv'](str(tmp_path / 'ed' / 'mediamtx_ldap_overlay.py'), 'OVERLAY')
    assert secret.read_text() == 'ORIGINAL'
    ns['_write_priv'](str(tmp_path / 'ed' / 'ensure_overlay.py'), 'X', perm=0o755)
    assert (tmp_path / 'ed' / 'ensure_overlay.py').read_text() == 'X'
    assert oct((tmp_path / 'ed' / 'ensure_overlay.py').stat().st_mode & 0o777) == '0o755'


def test_deploy_and_patch_take_the_dir_back_before_writing():
    dep = _fn_full('run_mediamtx_deploy')
    assert dep.index('_mediamtx_editor_reclaim(plog=plog)') < dep.index("_shutil.copy2(webeditor_src")
    rec = _fn_full('mediamtx_recovery')
    assert rec.index('_mediamtx_editor_reclaim()') < rec.index('_write_priv(editor_path, content)')
    assert '_mediamtx_hand_over_files(_mediamtx_owner())' in rec
    # no more takwerx copy into the editor's dir, and no fixed /tmp hop on the local box
    assert "_write_priv('/opt/mediamtx-webeditor/ensure_overlay.py', MEDIAMTX_ENSURE_OVERLAY_SCRIPT" in rec


def test_reclaim_drops_links_and_special_files(tmp_path):
    ed = tmp_path / 'ed'
    (ed / 'sub').mkdir(parents=True)
    (ed / 'mediamtx_config_editor.py').write_text('ok')
    (ed / 'sub' / 'keep.json').write_text('{}')
    (ed / 'mediamtx_ldap_overlay.py').symlink_to('/opt/infratak/app.py')
    (ed / 'sub' / 'evil').symlink_to(tmp_path)
    os.mkfifo(ed / 'fifo')
    calls = []
    ns = _ns(subprocess=types.SimpleNamespace(run=lambda a, **k: calls.append(list(a)) or
                                              types.SimpleNamespace(stdout='active\n')),
             _sudo_wrap=lambda a: a, _mediamtx_owner=lambda: 'mediamtx',
             _mediamtx_account_ready=lambda: True)
    import stat as _stat
    ns.update(_stat=_stat, _MEDIAMTX_EDITOR_DIR=str(ed), _MEDIAMTX_CONF_DIR=str(tmp_path / 'etc'))
    exec(_fn('_mediamtx_editor_reclaim'), ns)
    stopped = ns['_mediamtx_editor_reclaim']()
    assert stopped == ['mediamtx-webeditor', 'mediamtx']
    assert sorted(p.name for p in ed.rglob('*')) == ['keep.json', 'mediamtx_config_editor.py', 'sub']
    assert ['systemctl', 'stop', 'mediamtx-webeditor'] in calls
    assert calls.index(['systemctl', 'stop', 'mediamtx']) < calls.index(
        ['chown', '-R', 'takwerx:takwerx', str(ed)])


# --- the editor's packages: its own dir, owned by the console --------------------------
def test_editor_packages_come_from_its_own_dir_once_moved():
    ok = _fn('_mediamtx_editor_python_ok')
    assert ok.index('if _mediamtx_editor_uses_pylib():') < ok.index('runuser')
    ens = _fn('_mediamtx_editor_ensure_py_deps')
    assert ens.index('_mediamtx_editor_uses_pylib()') < ens.index('_mediamtx_editor_pin_home()')
    inst = _fn('_mediamtx_editor_install_pylib')
    assert "'--target', _MEDIAMTX_EDITOR_PYLIB" in inst
    assert "'chown', '-R', 'takwerx:takwerx', _MEDIAMTX_EDITOR_PYLIB" in inst   # never the editor's
    cert = _fn('_upgrade_mediamtx_certifi')
    assert cert.index('_mediamtx_editor_uses_pylib()') < cert.index("{'op': 'certifi_upgrade'}")


# --- nobody higher runs the binary MediaMTX's account can swap -------------------------
def test_console_reads_the_version_from_the_api_not_the_binary():
    """Fails on dev: the console ran /usr/local/bin/mediamtx -version as itself. The editor's
    upgrade button can put any binary there, so that ran the editor's code as the console."""
    src = _fn('_get_mediamtx_version_info')
    api = src.index("'http://127.0.0.1:9898/v3/info'")
    gate = src.index("and _mediamtx_owner() == 'takwerx':")
    assert api < gate < src.index("_run_ver(f'{bin_path} -version 2>&1')")


def test_guard_dog_never_runs_the_binary_as_root():
    sh = (REPO / 'scripts' / 'guarddog' / 'tak-updates-watch.sh').read_text()
    runs = [l for l in sh.splitlines() if '/usr/local/bin/mediamtx -version' in l]
    assert runs and all('runuser -u nobody -- /usr/local/bin/mediamtx -version' in l for l in runs)


def test_hand_back_to_takwerx_clears_the_setgid_bit():
    """Found on test6: `chmod 775` on a directory keeps its setgid bit (GNU), so a rollback
    left /usr/local/etc at 2775."""
    calls = []
    ns = _ns(subprocess=types.SimpleNamespace(run=lambda a, **k: calls.append(list(a))),
             _sudo_wrap=lambda a: a)
    ns['os'] = types.SimpleNamespace(path=types.SimpleNamespace(isdir=lambda p: True, join=os.path.join),
                                     listdir=lambda d: ['mediamtx.yml'])
    exec(_fn('_mediamtx_hand_over_files'), ns)
    ns['_mediamtx_hand_over_files']('takwerx')
    assert ['chown', 'root:takwerx', '/usr/local/etc'] in calls
    assert calls.index(['chmod', 'g-s', '/usr/local/etc']) > calls.index(['chmod', '775', '/usr/local/etc'])
    assert ['chown', '-h', 'takwerx:takwerx', '/usr/local/etc/mediamtx.yml'] in calls


# --- ops #649 meets #643: the editor login script runs as the editor's own account -----
def _login_runner(owner, dir_writable, calls):
    class _R:
        stdout = 'MTXLOGIN keep\n'
    ns = _ns()
    ns.update({
        'subprocess': types.SimpleNamespace(run=lambda argv, **kw: calls.append(argv) or _R()),
        '_get_module_deployment_config': lambda s, k: {},
        '_mediamtx_editor_login_target': lambda s: 'local',
        '_MEDIAMTX_EDITOR_USERS_FILE': '/opt/mediamtx-webeditor/users.json',
        '_MEDIAMTX_EDITOR_LOGIN_SCRIPT': 'print(1)',
        '_mediamtx_owner': lambda: owner,
        '_sudo_wrap': lambda argv: ['BROKER'] + list(argv),
        'os': types.SimpleNamespace(access=lambda p, m: dir_writable, W_OK=os.W_OK, path=os.path),
    })
    exec(_fn('_mediamtx_editor_run_login_script'), ns)
    return ns['_mediamtx_editor_run_login_script']


def test_login_script_runs_as_mediamtx_once_the_box_moved():
    """Moved box: the editor's dir is mediamtx's. As takwerx the write fails (site stays 503
    on a non-root box); as root it would write where that account can plant links."""
    calls = []
    assert _login_runner('mediamtx', False, calls)({}) == 'MTXLOGIN keep'
    assert calls == [['BROKER', 'runuser', '-u', 'mediamtx', '--',
                      'python3', '-I', '-', '/opt/mediamtx-webeditor/users.json']]


def test_login_script_unchanged_on_a_box_not_moved():
    calls = []
    _login_runner('takwerx', True, calls)({})
    assert calls == [['python3', '-I', '-', '/opt/mediamtx-webeditor/users.json']]
