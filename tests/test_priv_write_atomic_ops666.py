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
"""ops #666 / infra-TAK #473: Guard Dog scripts are never rewritten under a running process.

After a reboot `tak-post-start.service` could end `failed` (exit 2) although it had started
every service: the console's startup Guard Dog sync rewrote /opt/tak-guarddog/tak-post-start.sh
IN PLACE (open + O_TRUNC) while bash was still reading it, and bash carried on from its old
byte offset in the new content. Privileged writes under /opt/tak-guarddog/ and
/etc/systemd/system/ now go by temp file + rename, on both the broker path and the root
console path, so a running script keeps its old file.

Everything else stays in place on purpose: a rename breaks a single-file bind mount into a
container and a log that a running process holds open.
"""

import errno
import importlib.util
import os
import pathlib
import re
import secrets
import stat as _stat
import subprocess
import threading

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops666',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()


class _Os:
    """The real os module, except that the console looks like root."""
    def __init__(self, uid=0):
        self._uid = uid

    def getuid(self):
        return self._uid

    def __getattr__(self, name):
        return getattr(os, name)


class BrokerError(Exception):
    pass


def _app_ns(prefixes, sent=None, broker=False, uid=0):
    """app.py's privileged-write helpers, cut out of the source and run in a small namespace."""
    src = APP[APP.index('_ATOMIC_WRITE_PREFIXES = '):APP.index('def _read_priv_bytes(')]
    src = src.replace("_ATOMIC_WRITE_PREFIXES = ('/opt/tak-guarddog/', '/etc/systemd/system/')",
                      '_ATOMIC_WRITE_PREFIXES = %r' % (tuple(prefixes),))
    ns = {
        'os': _Os(uid), 'secrets': secrets, 'errno': errno, '_stat': _stat, 're': re,
        'subprocess': subprocess, '_b64': __import__('base64'),
        'BrokerError': BrokerError,
        '_MEDIAMTX_NOFOLLOW_PREFIXES': ('/nonexistent/',),
        '_backup_coreconfig_before_write': lambda *a, **k: None,
        '_broker_should_route': lambda: broker,
        '_broker_available': lambda: broker,
        '_broker_request': lambda req: (sent.append(req) if sent is not None else None) or {'ok': True},
    }
    exec(compile(src, 'app_priv_write_slice', 'exec'), ns)
    return ns


def _bash_script(started, gate):
    return ('#!/bin/bash\n'
            'touch %s\n'
            'read -r _ < %s\n'
            'echo OLD-SCRIPT-FINISHED\n' % (started, gate))


# The new script is longer and has no valid command at the byte offset where the old bash
# stopped reading: that is how a rewrite under a running bash ends in a syntax error (exit 2).
_NEW_SCRIPT = '#!/bin/bash\n' + 'x' * 4000 + ' (\necho NEW\n'


def _run_rewrite_under_running_bash(tmp_path, rewrite):
    """Start bash on a script, wait until it is blocked mid-script, rewrite the file with
    `rewrite(path, content)`, let bash go on. Returns (returncode, stdout)."""
    script = tmp_path / 'tak-post-start.sh'
    started = tmp_path / 'started'
    gate = tmp_path / 'gate'
    os.mkfifo(str(gate))
    script.write_text(_bash_script(started, gate))
    script.chmod(0o755)
    proc = subprocess.Popen(['bash', str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(500):
        if started.exists():
            break
        threading.Event().wait(0.01)
    assert started.exists(), 'the script never started'
    threading.Event().wait(0.2)            # bash is now blocked in `read`, past line 2
    rewrite(str(script), _NEW_SCRIPT)
    with open(str(gate), 'w') as g:        # release `read`
        g.write('go\n')
    out, _err = proc.communicate(timeout=20)
    return proc.returncode, out.decode()


def _in_place(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.write(fd, content.encode())
    os.close(fd)


# --- the field bug, reproduced with real bash ---------------------------------------------

def test_in_place_rewrite_breaks_a_running_script(tmp_path):
    """The bug itself: the old in-place write kills a running bash script with exit 2."""
    rc, out = _run_rewrite_under_running_bash(tmp_path, _in_place)
    assert rc == 2


def test_broker_atomic_write_leaves_a_running_script_alone(tmp_path):
    def rewrite(path, content):
        B._do_write({'path': path, 'content_b64': __import__('base64').b64encode(content.encode()).decode(),
                     'mode': 'w', 'perm': 0o755, 'atomic': True})
    rc, out = _run_rewrite_under_running_bash(tmp_path, rewrite)
    assert rc == 0
    assert 'OLD-SCRIPT-FINISHED' in out
    assert (tmp_path / 'tak-post-start.sh').read_text() == _NEW_SCRIPT     # the next run gets the new one


def test_broker_without_the_flag_still_writes_in_place(tmp_path):
    """Opt-in: an older console (or any other path) sends no `atomic`, and gets what it always got."""
    def rewrite(path, content):
        B._do_write({'path': path, 'content_b64': __import__('base64').b64encode(content.encode()).decode(),
                     'mode': 'w'})
    rc, _out = _run_rewrite_under_running_bash(tmp_path, rewrite)
    assert rc == 2


def test_root_console_write_leaves_a_running_script_alone(tmp_path):
    ns = _app_ns([str(tmp_path) + '/'])
    rc, out = _run_rewrite_under_running_bash(
        tmp_path, lambda path, content: ns['_write_priv'](path, content, perm=0o755))
    assert rc == 0
    assert 'OLD-SCRIPT-FINISHED' in out


# --- which writes go atomic ---------------------------------------------------------------

@pytest.mark.parametrize('path,mode,want', [
    ('/opt/tak-guarddog/tak-post-start.sh', 'w', True),
    ('/opt/tak-guarddog/guarddog.conf', 'w', True),
    ('/etc/systemd/system/tak-post-start.service', 'w', True),
    ('/opt/tak-guarddog/tak-x.log', 'a', False),                   # append stays append
    ('/var/log/authentik/auth.log', 'w', False),                   # a log a process holds open
    ('/opt/tak/CoreConfig.xml', 'w', False),                       # may be bind-mounted into a container
    ('/etc/caddy/Caddyfile', 'w', False),
    ('/opt/tak-guarddogX/x', 'w', False),                          # prefix, not substring
])
def test_which_writes_ask_the_broker_for_atomic(path, mode, want):
    sent = []
    ns = _app_ns(('/opt/tak-guarddog/', '/etc/systemd/system/'), sent=sent, broker=True)
    ns['_write_priv'](path, 'data', mode=mode, perm=0o755)
    assert len(sent) == 1
    assert sent[0].get('atomic', False) is want


def test_the_real_prefix_list_is_what_the_issue_needs():
    m = __import__('re').search(r"_ATOMIC_WRITE_PREFIXES = (\(.*?\))\n", APP)
    prefixes = eval(m.group(1))
    assert '/opt/tak-guarddog/' in prefixes
    for p in prefixes:                      # every one must already be writable through the broker
        assert p in B.PATH_ALLOW, p


# --- the broker flag buys nothing the allow-list did not already give ---------------------

@pytest.mark.parametrize('path', ['/etc/passwd', '/etc/sudoers.d/evil', '/root/.ssh/authorized_keys'])
def test_atomic_flag_does_not_bypass_the_allow_list(path):
    verdict, _reason = B._evaluate({'op': 'write', 'path': path, 'content_b64': '', 'atomic': True})
    assert verdict == 'DENY'


# --- behaviour of the write itself (broker and root console must agree) -------------------

def _broker_write(path, content, perm=None, mode='w'):
    req = {'path': path, 'content_b64': __import__('base64').b64encode(content).decode(),
           'mode': mode, 'atomic': True}
    if perm is not None:
        req['perm'] = perm
    assert B._do_write(req) == {'ok': True}


def _local_write(path, content, perm=None, mode='w'):
    ns = _app_ns([os.path.dirname(path) + '/'])
    ns['_write_priv'](path, content, mode=mode, perm=perm)


WRITERS = pytest.mark.parametrize('write', [_broker_write, _local_write], ids=['broker', 'root-console'])


@WRITERS
def test_new_content_lands_and_no_temp_file_is_left(tmp_path, write):
    target = tmp_path / 'tak-x.sh'
    target.write_bytes(b'old\n')
    write(str(target), b'new content\n')
    assert target.read_bytes() == b'new content\n'
    assert [p.name for p in tmp_path.iterdir()] == ['tak-x.sh']


@WRITERS
def test_a_replaced_file_keeps_its_mode(tmp_path, write):
    target = tmp_path / 'tak-x.sh'
    target.write_bytes(b'old\n')
    target.chmod(0o750)
    write(str(target), b'new\n')
    assert _stat.S_IMODE(target.stat().st_mode) == 0o750


@WRITERS
def test_perm_wins_over_the_old_mode(tmp_path, write):
    target = tmp_path / 'guarddog.conf'
    target.write_bytes(b'old\n')
    target.chmod(0o644)
    write(str(target), b'{"k": 1}\n', perm=0o600)
    assert _stat.S_IMODE(target.stat().st_mode) == 0o600


@WRITERS
def test_a_new_file_is_created(tmp_path, write):
    target = tmp_path / 'brand-new.sh'
    write(str(target), b'hello\n', perm=0o755)
    assert target.read_bytes() == b'hello\n'
    assert _stat.S_IMODE(target.stat().st_mode) == 0o755
    assert [p.name for p in tmp_path.iterdir()] == ['brand-new.sh']


@WRITERS
def test_a_new_file_without_perm_is_world_readable_like_before(tmp_path, write):
    target = tmp_path / 'brand-new.service'
    old = os.umask(0o022)
    try:
        write(str(target), b'[Unit]\n')
    finally:
        os.umask(old)
    assert _stat.S_IMODE(target.stat().st_mode) == 0o644


@WRITERS
def test_empty_content_replaces_with_an_empty_file(tmp_path, write):
    target = tmp_path / 'tak-x.sh'
    target.write_bytes(b'old\n')
    write(str(target), b'')
    assert target.read_bytes() == b''


@WRITERS
def test_a_symlink_target_is_written_through_as_before(tmp_path, write):
    real = tmp_path / 'real.conf'
    real.write_bytes(b'old\n')
    link = tmp_path / 'link.conf'
    link.symlink_to(real)
    write(str(link), b'new\n')
    assert link.is_symlink()
    assert real.read_bytes() == b'new\n'


@WRITERS
def test_a_hard_linked_file_is_written_in_place_so_the_other_name_sees_it(tmp_path, write):
    a = tmp_path / 'a.sh'
    a.write_bytes(b'old\n')
    b = tmp_path / 'b.sh'
    os.link(str(a), str(b))
    write(str(a), b'new\n')
    assert b.read_bytes() == b'new\n'


def test_append_is_never_atomic(tmp_path):
    target = tmp_path / 'x.log'
    target.write_bytes(b'one\n')
    ino = target.stat().st_ino
    _broker_write(str(target), b'two\n', mode='a')
    assert target.read_bytes() == b'one\ntwo\n'
    assert target.stat().st_ino == ino


@pytest.mark.parametrize('how', ['broker', 'root-console'])
def test_the_atomic_write_changes_the_inode_but_a_reader_keeps_the_old_file(tmp_path, how):
    target = tmp_path / 'tak-x.sh'
    target.write_bytes(b'old old old\n')
    held = open(str(target), 'rb')                 # what a running bash holds
    ino = target.stat().st_ino
    (_broker_write if how == 'broker' else _local_write)(str(target), b'new\n')
    assert target.stat().st_ino != ino
    assert held.read() == b'old old old\n'
    held.close()


# --- failure never leaves a half-written or emptied target --------------------------------

@pytest.mark.parametrize('how', ['broker', 'root-console'])
def test_a_failed_write_leaves_the_old_file_and_no_temp(tmp_path, monkeypatch, how):
    target = tmp_path / 'tak-x.sh'
    target.write_bytes(b'old\n')
    real_write = os.write

    def disk_full(fd, data):
        raise OSError(errno.ENOSPC, 'No space left on device')
    monkeypatch.setattr(os, 'write', disk_full)
    with pytest.raises(OSError):
        (_broker_write if how == 'broker' else _local_write)(str(target), b'new content\n')
    monkeypatch.setattr(os, 'write', real_write)
    assert target.read_bytes() == b'old\n'
    assert [p.name for p in tmp_path.iterdir()] == ['tak-x.sh']


@pytest.mark.parametrize('how', ['broker', 'root-console'])
def test_a_rename_refused_for_a_mount_point_falls_back_to_in_place(tmp_path, monkeypatch, how):
    target = tmp_path / 'resolv.conf'
    target.write_bytes(b'old\n')
    real_rename = os.rename

    def busy(src, dst):
        raise OSError(errno.EBUSY, 'Device or resource busy')
    monkeypatch.setattr(os, 'rename', busy)
    (_broker_write if how == 'broker' else _local_write)(str(target), b'new\n')
    monkeypatch.setattr(os, 'rename', real_rename)
    assert target.read_bytes() == b'new\n'
    assert [p.name for p in tmp_path.iterdir()] == ['resolv.conf']


# --- guarddog.conf: readers (watchers run every minute) never see it empty -----------------

def test_a_reader_never_sees_a_half_written_guarddog_conf(tmp_path):
    target = tmp_path / 'guarddog.conf'
    payload = b'{"k": "' + b'v' * 20000 + b'"}\n'
    target.write_bytes(payload)
    stop = threading.Event()
    bad = []

    def reader():
        while not stop.is_set():
            try:
                data = target.read_bytes()
            except FileNotFoundError:
                bad.append('missing')
                continue
            if data != payload:
                bad.append(len(data))
    t = threading.Thread(target=reader)
    t.start()
    try:
        for _ in range(300):
            _broker_write(str(target), payload, perm=0o600)
    finally:
        stop.set()
        t.join()
    assert bad == []
