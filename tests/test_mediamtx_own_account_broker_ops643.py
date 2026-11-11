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
"""ops #643, broker half: MediaMTX + its web editor get their own socket and short list.

They used to run as the console's account, so an editor bug could send the broker anything
the console may. Now they run as `mediamtx`, which the main socket refuses, and their own
socket serves only the argv shapes the editor actually sends (mediamtx-installer
config-editor/mediamtx_config_editor.py), always enforced.
"""

import importlib.util
import os
import pathlib
import stat

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops643',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()


# --- what the editor sends today: every shape must still pass ------------------------
@pytest.mark.parametrize('argv,kind', [
    (['systemctl', 'is-active', 'takwerx-broker'], 'root'),     # _broker_available probe
    (['systemctl', 'is-enabled', 'mediamtx'], 'root'),          # mtx_priv_mode probe
    (['systemctl', 'stop', 'mediamtx'], 'root'),
    (['systemctl', 'start', 'mediamtx'], 'root'),
    (['systemctl', 'restart', 'mediamtx'], 'root'),
    (['systemctl', 'restart', 'mediamtx-webeditor'], 'root'),
    (['test', '-f', '/var/lib/caddy/.local/share/caddy/certificates/x/s.example.com/s.example.com.crt'], 'root'),
    (['cp', '/usr/local/bin/mediamtx', '/opt/mediamtx-webeditor/binbackups/mediamtx.backup_20261110_150000'], 'user'),
    (['cp', '/opt/mediamtx-webeditor/binstage/mediamtx', '/usr/local/bin/mediamtx'], 'install'),
    (['chmod', '755', '/usr/local/bin/mediamtx'], 'root'),
    (['restorecon', '/usr/local/bin/mediamtx'], 'root'),
    (['cp', '/usr/local/etc/mediamtx.yml', '/usr/local/etc/mediamtx.yml.backup_20261110_150000'], 'user'),
    (['cp', '/usr/local/etc/mediamtx.yml.backup_20261110_150000', '/usr/local/etc/mediamtx.yml'], 'user'),
    (['cp', '/usr/local/etc/mediamtx.yml', '/usr/local/etc/mediamtx.yml.pre_rollback'], 'user'),
    (['apt-get', 'update', '-qq'], 'root'),
    (['apt-get', 'install', '-y', '-q', 'gstreamer1.0-tools', 'gstreamer1.0-plugins-bad'], 'root'),
    (['apt-get', 'install', '-y', '-q', 'ffmpeg'], 'root'),
    (['dnf', '-q', 'makecache'], 'root'),
    (['dnf', 'install', '-y', 'gstreamer1', 'gstreamer1-rtsp-server'], 'root'),
    (['ufw', 'status'], 'root'),
    (['ufw', 'allow', '8554/tcp'], 'root'),
    (['ufw', 'delete', 'allow', '8890/udp'], 'root'),
    (['firewall-cmd', '--list-ports'], 'root'),
    (['firewall-cmd', '--add-port=8554/tcp'], 'root'),
    (['firewall-cmd', '--permanent', '--remove-port=8890/udp'], 'root'),
])
def test_editor_shapes_still_allowed(argv, kind):
    assert B.check_mediamtx_exec(argv) == kind


# --- anything else is refused ---------------------------------------------------------
@pytest.mark.parametrize('argv', [
    ['bash', '-c', 'id'],
    ['runuser', '-u', 'root', '--', 'id'],
    ['/tmp/systemctl', 'restart', 'mediamtx'],                    # argv[0] with a directory
    ['systemctl', 'restart', 'takwerx-console'],                  # not its unit
    ['systemctl', 'restart', 'takwerx-broker'],
    ['systemctl', 'edit', 'mediamtx'],
    ['systemctl', 'daemon-reload'],
    ['systemctl', 'is-active', 'takwerx-broker', 'extra'],
    ['cp', '/etc/shadow', '/opt/mediamtx-webeditor/x'],           # read a root file
    ['cp', '/opt/mediamtx-webeditor/x', '/etc/cron.d/x'],         # write a root path
    ['cp', '/opt/mediamtx-webeditor/x', '/opt/infratak/app.py'],  # the console's code
    ['cp', '/opt/mediamtx-webeditor/evil', '/usr/local/bin/mediamtx'],
    ['cp', '/usr/local/etc/mediamtx_backups/../../../etc/passwd', '/opt/mediamtx-webeditor/x'],
    ['cp', '-a', '/usr/local/bin/mediamtx', '/opt/mediamtx-webeditor/x'],
    ['cp', '/usr/local/etc/mediamtx.yml', '/usr/local/etc/mediamtx.yml.d/../../x'],
    ['cp', '/opt/mediamtx-webeditor/gst-plugins/.staged-rtspclientsink.so',
     '/usr/lib64/gstreamer-1.0/libgstrtspclientsink.so'],        # editor falls back to its own dir
    ['chmod', '4755', '/usr/local/bin/mediamtx'],
    ['chmod', '755', '/usr/local/bin/other'],
    ['restorecon', '-R', '/'],
    ['test', '-f', '/etc/shadow'],
    ['test', '-x', '/usr/local/bin/mediamtx'],
    ['apt-get', 'install', '-y', '-q', 'openssh-server'],
    ['apt-get', 'install', '-y', '-q', '-o', 'Dpkg::Options::=--force-confnew', 'ffmpeg'],
    ['apt-get', 'install', '-y', '-q', './evil.deb'],
    ['apt-get', 'remove', '-y', 'ffmpeg'],
    ['dnf', 'install', '-y', 'ffmpeg', '--setopt=install_weak_deps=0'],
    ['dnf', 'update', '-qq'],
    ['ufw', 'disable'],
    ['ufw', 'allow', '5001/tcp'],                                 # console
    ['ufw', 'allow', '9898/tcp'],                                 # MediaMTX API
    ['ufw', 'delete', 'allow', '22/tcp'],                         # lock the admin out
    ['ufw', 'delete', 'allow', '443/tcp'],
    ['ufw', 'allow', 'from', '1.2.3.4'],
    ['ufw', 'allow', '0/tcp'],
    ['firewall-cmd', '--add-port=5432/tcp'],
    ['firewall-cmd', '--add-service=ssh'],
    ['firewall-cmd', '--reload'],
    ['firewall-cmd', '--permanent', '--add-port=8554/tcp', '--add-port=9090/tcp'],
    ['iptables', '-F'],
    ['rm', '-rf', '/opt/infratak'],
    [],
    ['systemctl', 'restart', 'mediamtx\x00'],
])
def test_everything_else_denied(argv):
    with pytest.raises(B.Denied):
        B.check_mediamtx_exec(argv)


def test_only_exec_is_served_on_the_mediamtx_socket(monkeypatch):
    seen = []
    monkeypatch.setattr(B, 'audit', lambda *a, **k: seen.append(a))
    for req in ({'op': 'write', 'path': '/etc/cron.d/x', 'content_b64': ''},
                {'op': 'read', 'path': '/etc/shadow'},
                {'op': 'enforce_enable'},
                {'op': 'mediamtx_account'},
                {'op': 'certifi_upgrade'},
                {'op': 'check', 'req': {'op': 'exec', 'argv': ['id']}}):
        resp = B._dispatch_mediamtx(req, (1, 999, 999))
        assert resp['ok'] is False and resp['code'] == 'DENIED', req
    assert all(a[3] == 'DENY' for a in seen)


def test_denied_exec_never_runs(monkeypatch):
    ran = []
    monkeypatch.setattr(B, 'audit', lambda *a, **k: None)
    monkeypatch.setattr(B, '_mtx_run', lambda *a, **k: ran.append(a))
    monkeypatch.setattr(B, 'ENFORCE', False)       # permissive main socket changes nothing here
    resp = B._dispatch_mediamtx({'op': 'exec', 'argv': ['systemctl', 'restart', 'takwerx-console']},
                                (1, 999, 999))
    assert resp['code'] == 'DENIED' and ran == []


def test_mediamtx_peer_only_on_its_socket(monkeypatch):
    monkeypatch.setattr(B, '_mtx_uid', lambda: 990)

    class _PW:
        pw_uid = 1001
    monkeypatch.setattr(B.pwd, 'getpwnam', lambda n: _PW())
    assert B._allowed_mediamtx_peer(990)
    assert B._allowed_mediamtx_peer(0)
    assert not B._allowed_mediamtx_peer(1001)      # the console has its own socket
    assert not B._allowed_mediamtx_peer(-1)
    # and the main socket refuses the mediamtx uid
    assert B._allowed_peer(1001)
    assert not B._allowed_peer(990)


def test_mediamtx_dirs_get_symlink_protection():
    for p in ('/opt/mediamtx-webeditor/mediamtx_ldap_overlay.py', '/usr/local/etc/mediamtx.yml'):
        assert B._is_console_owned(p), p          # O_NOFOLLOW on broker writes there
    assert '/opt/mediamtx-webeditor/' in B._CONSOLE_OWNED_PREFIXES
    assert '/usr/local/etc/' in B._CONSOLE_OWNED_PREFIXES   # realpath containment


def test_account_op_takes_no_arguments():
    assert B._evaluate({'op': 'mediamtx_account'}) == ('ALLOW', '')
    v, why = B._evaluate({'op': 'mediamtx_account', 'groups': 'takwerx'})
    assert v == 'DENY' and 'no arguments' in why


def test_account_unfit_when_in_console_group(monkeypatch):
    class _PW:
        pw_uid, pw_gid = 990, 990

    class _GR:
        gr_mem, gr_gid = ['mediamtx'], 1001
    monkeypatch.setattr(B.pwd, 'getpwnam', lambda n: _PW())
    monkeypatch.setattr(B.grp, 'getgrnam', lambda n: _GR())
    assert 'group takwerx' in B._mtx_account_problem()


# --- the binary swap: never follows a planted link, never copies a non-ELF -------------
@pytest.fixture
def swap(tmp_path, monkeypatch):
    stage = tmp_path / 'opt' / 'binstage'
    stage.mkdir(parents=True)
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    monkeypatch.setattr(B, '_MTX_BIN_STAGED', str(stage / 'mediamtx'))
    monkeypatch.setattr(B, '_MTX_BIN', str(bindir / 'mediamtx'))
    monkeypatch.setattr(B, '_mtx_uid', lambda: os.geteuid())
    (bindir / 'mediamtx').write_bytes(b'\x7fELFold')
    return stage / 'mediamtx', bindir / 'mediamtx', tmp_path


def test_swap_installs_staged_elf(swap):
    staged, target, _ = swap
    staged.write_bytes(b'\x7fELFnew-binary' * 1000)
    assert B._mtx_install_binary()['returncode'] == 0
    assert target.read_bytes() == b'\x7fELFnew-binary' * 1000
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_swap_refuses_symlinked_stage(swap):
    staged, target, tmp = swap
    secret = tmp / 'shadow'
    secret.write_bytes(b'\x7fELFroot-only-secret')
    staged.symlink_to(secret)
    with pytest.raises(OSError):
        B._mtx_install_binary()
    assert target.read_bytes() == b'\x7fELFold'


def test_swap_refuses_symlinked_stage_dir(swap, monkeypatch):
    staged, target, tmp = swap
    real = tmp / 'elsewhere'
    real.mkdir()
    (real / 'mediamtx').write_bytes(b'\x7fELFx')
    link = tmp / 'opt' / 'linkstage'
    link.symlink_to(real)
    monkeypatch.setattr(B, '_MTX_BIN_STAGED', str(link / 'mediamtx'))
    with pytest.raises(B.Denied):
        B._mtx_install_binary()
    assert target.read_bytes() == b'\x7fELFold'


def test_swap_refuses_non_elf_and_foreign_owner(swap, monkeypatch):
    staged, target, _ = swap
    staged.write_bytes(b'#!/bin/sh\nid\n')
    with pytest.raises(B.Denied):
        B._mtx_install_binary()
    staged.write_bytes(b'\x7fELFok')
    monkeypatch.setattr(B, '_mtx_uid', lambda: os.geteuid() + 1)
    with pytest.raises(B.Denied):
        B._mtx_install_binary()
    assert target.read_bytes() == b'\x7fELFold'


def test_user_kind_copies_drop_to_the_mediamtx_account(monkeypatch):
    calls = []

    class _P:
        returncode, stdout, stderr = 0, b'', b''

    class _PW:
        pw_gid = 990
    monkeypatch.setattr(B, '_mtx_uid', lambda: 990)
    monkeypatch.setattr(B.pwd, 'getpwuid', lambda u: _PW())
    monkeypatch.setattr(B.shutil, 'which', lambda c, path=None: '/usr/bin/' + c)
    monkeypatch.setattr(B.subprocess, 'run', lambda argv, **kw: calls.append((argv, kw)) or _P())
    B._mtx_run(['cp', '/usr/local/etc/mediamtx.yml', '/usr/local/etc/mediamtx.yml.pre_rollback'],
               25, as_user=True)
    argv, kw = calls[0]
    assert argv[0] == '/usr/bin/cp'
    assert kw['user'] == 990 and kw['group'] == 990 and kw['extra_groups'] == []
    assert kw['env']['HOME'] == '/'


def test_editor_package_dir_is_on_the_console_list_not_the_editors():
    """Found on test6: the console could not create its package dir through the broker."""
    assert B._path_allowed('/opt/mediamtx-webeditor-pylib') == '/opt/mediamtx-webeditor-pylib'
    assert '/opt/mediamtx-webeditor-pylib/' in B._CONSOLE_OWNED_PREFIXES
    assert not B._mtx_own_path('/opt/mediamtx-webeditor-pylib/flask/__init__.py')


# --- ops #649 meets #643: the console may run the login script as mediamtx, nothing else -
def test_console_may_run_the_editor_login_script_as_mediamtx():
    B.check_exec(['runuser', '-u', 'mediamtx', '--', 'python3', '-I', '-',
                  '/opt/mediamtx-webeditor/users.json'])


@pytest.mark.parametrize('tail', [
    ['python3', '-I', '-', '/etc/shadow'],
    ['python3', '-c', 'import os'],
    ['python3', '-I', '-', '/opt/mediamtx-webeditor/users.json', 'x'],
    ['bash', '-c', 'id'],
    ['/tmp/python3', '-I', '-', '/opt/mediamtx-webeditor/users.json'],
])
def test_nothing_else_runs_as_mediamtx(tail):
    with pytest.raises(B.Denied):
        B.check_exec(['runuser', '-u', 'mediamtx', '--'] + tail)


def test_the_mediamtx_socket_still_refuses_runuser():
    with pytest.raises(B.Denied):
        B.check_mediamtx_exec(['runuser', '-u', 'mediamtx', '--', 'python3', '-I', '-',
                               '/opt/mediamtx-webeditor/users.json'])
