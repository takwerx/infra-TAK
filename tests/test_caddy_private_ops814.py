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
"""Caddy's admin API is a unix socket and the proxy-auth values are in files (ops #814).

What must hold on a box that has been moved (`private` in proxy_auth.json):
  - the generated Caddyfile names the admin socket and holds a `{file.…}` placeholder
    where the proxy-auth value used to be, for the console and (a different file) ATLAS;
  - the value files are 0400, owned by `caddy`, swapped in by rename;
  - the move restarts Caddy once, checks the result, rotates the values, and puts the old
    config back when anything fails; it runs again when the live config was put back;
  - rotation is a file swap: no Caddyfile write, no reload, ATLAS gets its own value;
  - the broker lets the console write `RuntimeDirectory=caddy` in the Caddy drop-in and
    nowhere else.
A box not moved yet (an old Caddy, or the move failed) keeps the old layout.

app.py cannot be imported in a test, so the functions are cut out of it and run against
stubs: the code under test is the shipped text.
"""
import ast
import base64
import importlib.util
import json
import os
import pathlib
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
MARKER = '# ---- user blocks ----'
CF = '/etc/caddy/Caddyfile'
SOCK = '/run/caddy/admin.sock'
OLD = 'a' * 64
OLD_ATLAS = 'b' * 64
HEX64 = re.compile(r'^[0-9a-f]{64}$')


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _load(names, ns):
    exec(compile('\n\n'.join(_segment(n) for n in names), 'app.py', 'exec'), ns)
    return ns


_CONSTS = ['CADDY_ADMIN_SOCKET', 'CADDY_ADMIN_SOCKET_MODE', '_CADDY_MIN_FILE_PLACEHOLDER',
           '_CADDY_PROXY_AUTH_FILES', '_PROXY_AUTH_VALUE_RE', 'CADDY_BOOT_DROPIN',
           'CADDY_BOOT_DROPIN_TEXT']


def _consts(extra=None):
    ns = {'re': re, 'os': os}
    ns.update(extra or {})
    return _load(_CONSTS, ns)


def _private_caddyfile(home='/var/lib/caddy'):
    return ('{\n    grace_period 10s\n    admin unix//run/caddy/admin.sock|0220\n}\n'
            'infratak.example.com {\n'
            '    request_header @needs_sso X-Infratak-Proxy-Auth {file.%s/infratak-proxy-auth-console}\n'
            '}\n%s\n' % (home, MARKER))


def _old_caddyfile(secret=OLD):
    return ('{\n    grace_period 10s\n}\ninfratak.example.com {\n'
            '    request_header @needs_sso X-Infratak-Proxy-Auth %s\n}\n%s\n' % (secret, MARKER))


# ── what the generator writes ────────────────────────────────────────────────

def _global_lines(private):
    ns = _consts({'CADDY_GRACE_PERIOD': '10s', '_caddy_private': lambda: private,
                  '_caddy_port_option_lines': lambda settings=None: [],
                  '_caddy_acme_inner_lines': lambda cfg=None: [],
                  '_caddy_read_body_idle_lines': lambda grpc: []})
    return _load(['_caddy_global_options_lines'], ns)['_caddy_global_options_lines']()


def test_a_moved_box_puts_the_admin_api_on_the_socket():
    assert _global_lines(True) == ['{', '    grace_period 10s',
                                   '    admin unix//run/caddy/admin.sock|0220', '}', '']


def test_a_box_not_moved_yet_keeps_its_global_block():
    """Caddy has no /run/caddy before the move, so it must not be told to listen there."""
    assert _global_lines(False) == ['{', '    grace_period 10s', '}', '']


def _token(private, kind, value=OLD):
    ns = _consts({'_caddy_private': lambda: private,
                  '_caddy_account': lambda: ('/var/lib/caddy', 998, 999)})
    _load(['_caddy_proxy_auth_path', '_caddy_proxy_auth_token'], ns)
    return ns['_caddy_proxy_auth_token'](kind, value)


def test_a_moved_box_writes_a_file_placeholder_not_the_value():
    assert _token(True, 'console') == '{file./var/lib/caddy/infratak-proxy-auth-console}'
    assert _token(True, 'atlas') == '{file./var/lib/caddy/infratak-proxy-auth-atlas}'
    assert OLD not in _token(True, 'console') + _token(True, 'atlas')


def test_atlas_and_the_console_never_share_a_file():
    assert _token(True, 'console') != _token(True, 'atlas')


def test_a_box_not_moved_yet_still_gets_the_value():
    assert _token(False, 'console') == OLD


def test_generate_caddyfile_only_writes_the_token():
    """The two lines that attach the header go through _caddy_proxy_auth_token()."""
    src = _segment('generate_caddyfile')
    lines = [l for l in src.splitlines() if 'X-Infratak-Proxy-Auth {' in l and 'lines.append' in l]
    assert len(lines) == 2, lines
    assert all('{_pa_token}' in l or '{_at_token}' in l for l in lines), lines
    assert "_caddy_proxy_auth_token('console', _pa_secret)" in src
    assert "_caddy_proxy_auth_token('atlas', _at_pa)" in src
    assert "_at_state.get('atlas_secret') if _caddy_private()" in src


@pytest.mark.parametrize('text,want', [
    (_private_caddyfile(), True),
    (_old_caddyfile(), False),                                              # value in the file
    (_private_caddyfile().replace('    admin unix//run/caddy/admin.sock|0220\n', ''), False),
    (_private_caddyfile() + 'x {\n  request_header X-Infratak-Proxy-Auth %s\n}\n' % OLD, True),  # below the marker: the operator's
    ('', False),
])
def test_caddyfile_is_private(text, want):
    ns = _consts({'CADDYFILE_USER_BLOCKS_MARKER': MARKER})
    assert _load(['_caddyfile_is_private'], ns)['_caddyfile_is_private'](text) is want


# ── the value files ──────────────────────────────────────────────────────────

def _writer(tmp_path, *, root=True, chain_rc=0):
    calls = []
    ns = _consts({
        '_caddy_account': lambda: (str(tmp_path), os.getuid(), os.getgid()),
        '_broker_should_route': lambda: not root, '_broker_available': lambda: not root,
        '_write_priv': lambda path, content, perm=None: calls.append(('write', path, content, perm)),
        '_run_priv_chain': lambda cmds, mode='and', timeout=120: (
            calls.append(('chain', cmds, mode)),
            subprocess.CompletedProcess(cmds, chain_rc, '', 'denied'))[1],
    })
    fake_os = types.SimpleNamespace(**{k: getattr(os, k) for k in (
        'open', 'fdopen', 'fchmod', 'fchown', 'replace', 'path', 'O_WRONLY', 'O_CREAT', 'O_TRUNC',
        'O_NOFOLLOW')})
    fake_os.getuid = lambda: 0 if root else 997
    ns['os'] = fake_os
    _load(['_caddy_proxy_auth_path', '_caddy_write_proxy_auth_file'], ns)
    return ns['_caddy_write_proxy_auth_file'], calls


def test_value_file_is_0400_and_complete(tmp_path):
    write, _ = _writer(tmp_path)
    path = write('console', OLD)
    assert path == str(tmp_path / 'infratak-proxy-auth-console')
    assert open(path).read() == OLD                       # no newline: Caddy sends it as is
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o400
    assert sorted(os.listdir(tmp_path)) == ['infratak-proxy-auth-console']


def test_value_file_can_be_replaced(tmp_path):
    write, _ = _writer(tmp_path)
    write('console', OLD)
    write('console', 'c' * 64)                            # the old one is 0400: rename, not rewrite
    assert open(tmp_path / 'infratak-proxy-auth-console').read() == 'c' * 64


def test_value_file_is_not_written_through_a_planted_link(tmp_path):
    victim = tmp_path / 'victim'
    victim.write_text('keep')
    os.symlink(victim, tmp_path / 'infratak-proxy-auth-console.new')
    write, _ = _writer(tmp_path)
    with pytest.raises(OSError):
        write('console', OLD)
    assert victim.read_text() == 'keep'


@pytest.mark.parametrize('bad', ['', 'short', 'A' * 64, 'a' * 63 + '\n', 'a' * 64 + ' }\nadmin :2019', None])
def test_only_a_64_hex_value_is_ever_written(tmp_path, bad):
    write, calls = _writer(tmp_path)
    with pytest.raises(ValueError):
        write('console', bad)
    assert calls == [] and os.listdir(tmp_path) == []


def test_non_root_console_installs_the_file_through_the_broker(tmp_path):
    write, calls = _writer(tmp_path, root=False)
    path = write('atlas', OLD)
    tmp = path + '.new'
    assert calls[0] == ('write', tmp, OLD, 0o600)         # private before the value is in it
    owner = '%d:%d' % (os.getuid(), os.getgid())
    assert calls[1] == ('chain', [['chown', owner, tmp], ['chmod', '400', tmp],
                                  ['mv', '-f', tmp, path]], 'and')


def test_a_refused_broker_step_is_an_error_not_a_silent_pass(tmp_path):
    write, _ = _writer(tmp_path, root=False, chain_rc=1)
    with pytest.raises(RuntimeError):
        write('console', OLD)


# ── the move ─────────────────────────────────────────────────────────────────

class Box:
    """A fake host for _caddy_make_private_locked()."""

    def __init__(self, *, fqdn='example.com', state=None, caddyfile=None, version=(2, 11, 9),
                 dropin_ok=True, generate_rejects=False, restart_rc=0, problem='',
                 atlas_errs=None, tcp_open=False, files=None):
        self.state = dict(state if state is not None else {'secret': OLD, 'enforce': True})
        self.caddyfile = _old_caddyfile() if caddyfile is None else caddyfile
        self.files = dict(files or {})
        self.events, self.says, self.audits, self.atlas_calls = [], [], [], []
        self.restart_rc, self.problem, self.tcp_open = restart_rc, problem, tcp_open
        box = self

        def save_state(st):
            box.state = dict(st)
            box.events.append('save-state')

        def generate(settings=None):
            box.events.append('generate')
            if not generate_rejects:
                box.caddyfile = _private_caddyfile() if box.state.get('private') else _old_caddyfile(box.state['secret'])

        def run(argv, **kw):
            box.events.append(' '.join(argv))
            rc = box.restart_rc if argv[:2] == ['systemctl', 'restart'] else 0
            if isinstance(rc, list):
                rc = rc.pop(0)
            return subprocess.CompletedProcess(argv, rc, '', 'boom' if rc else '')

        def write_file(kind, value):
            box.events.append('file:' + kind)
            box.files[kind] = value

        def write_priv(path, content, **kw):
            box.events.append('write-caddyfile')
            box.caddyfile = content

        fake_os = types.SimpleNamespace(
            path=types.SimpleNamespace(exists=lambda p: True),
            remove=lambda p: box.events.append('remove:' + p))
        self.ns = _consts({
            'os': fake_os, 'time': types.SimpleNamespace(time=lambda: 1794800000),
            'secrets': __import__('secrets'), 'CADDYFILE_PATH': CF,
            'CADDYFILE_USER_BLOCKS_MARKER': MARKER,
            'shutil': types.SimpleNamespace(which=lambda n: '/usr/bin/caddy'),
            'subprocess': types.SimpleNamespace(run=run),
            '_sudo_wrap': lambda argv: argv,
            'load_settings': lambda: {'fqdn': fqdn},
            '_caddy_account': lambda: ('/var/lib/caddy', 998, 999),
            '_proxy_auth_state': lambda create=False: dict(box.state),
            '_save_proxy_auth_state': save_state,
            '_read_priv': lambda p: box.caddyfile, '_write_priv': write_priv,
            '_caddy_tcp_admin_open': lambda: box.tcp_open,
            '_caddy_boot_dropin_ensure': lambda: (box.events.append('dropin'), (dropin_ok, dropin_ok))[1],
            '_caddy_read_proxy_auth_file': lambda kind: box.files.get(kind, ''),
            '_caddy_write_proxy_auth_file': write_file,
            '_caddy_version_tuple': lambda refresh=False: version,
            'generate_caddyfile': generate,
            '_caddy_last_validate_error': {'err': 'unknown directive'},
            '_caddy_private_problem': lambda st: (box.events.append('check'), box.problem)[1],
            '_proxy_auth_atlas_apply': lambda secret, plog=None: (
                box.atlas_calls.append(secret), list(atlas_errs or []))[1],
            '_PROXY_AUTH_CADDYFILE_BACKUP': '/cfg/Caddyfile.pre-rotate',
            '_PROXY_AUTH_BACKUP_FILE': '/cfg/proxy_auth.pre-rotate.json',
            'audit': lambda ev, detail='', force=False: box.audits.append(ev),
        })
        _load(['_caddyfile_is_private', '_caddy_make_private_locked'], self.ns)

    def move(self):
        return self.ns['_caddy_make_private_locked'](self.says.append)


def test_the_move_does_each_step_in_order_and_rotates_the_values():
    box = Box()
    assert box.move() == 'private'
    ev = box.events
    assert ev.index('dropin') < ev.index('file:console') < ev.index('generate') \
        < ev.index('systemctl restart caddy') < ev.index('check')
    assert ev.count('systemctl restart caddy') == 1 and 'systemctl reload caddy' not in ev
    st = box.state
    assert st['private'] is True and 'previous' not in st and st['enforce'] is True
    assert HEX64.match(st['secret']) and HEX64.match(st['atlas_secret'])
    assert len({OLD, st['secret'], st['atlas_secret']}) == 3      # both new, and not the same
    assert box.files == {'console': st['secret'], 'atlas': st['atlas_secret']}
    assert box.atlas_calls == [st['atlas_secret']]                 # never the console's value
    assert box.audits == ['caddy-private:applied']
    assert 'remove:/cfg/Caddyfile.pre-rotate' in ev                # it held the old value
    assert not any(v in s for s in box.says for v in (OLD, st['secret'], st['atlas_secret']))


def test_the_old_value_is_accepted_until_caddy_has_restarted():
    """Caddy sends the old value until its restart lands; signing in must not break."""
    box = Box()
    seen = []
    real = box.ns['_caddy_private_problem']
    box.ns['_caddy_private_problem'] = lambda st: (seen.append(dict(box.state)), real(st))[1]
    box.move()
    assert seen[0]['previous'] == OLD and seen[0]['secret'] != OLD


@pytest.mark.parametrize('kw', [{'fqdn': ''}])
def test_no_domain_means_nothing_to_move(kw):
    box = Box(**kw)
    assert box.move() == 'skipped'
    assert box.events == [] and box.state == {'secret': OLD, 'enforce': True}


@pytest.mark.parametrize('version', [(2, 7, 6), (2, 6, 2), ()])
def test_an_old_caddy_keeps_the_old_layout_and_says_so(version):
    box = Box(version=version)
    assert box.move() == 'old-caddy'
    assert box.events == [] and 'private' not in box.state
    assert any('SECURITY' in s and 'older than 2.8' in s for s in box.says)


def test_a_refused_drop_in_changes_nothing_else():
    """A broker from before this release refuses RuntimeDirectory=."""
    box = Box(dropin_ok=False)
    assert box.move() == 'failed'
    assert box.events == ['dropin'] and 'private' not in box.state
    assert box.caddyfile == _old_caddyfile()


def _assert_put_back(box, restarts):
    assert box.state == {'secret': OLD, 'enforce': True}
    assert box.caddyfile == _old_caddyfile()
    assert box.events.count('systemctl restart caddy') == restarts
    assert box.audits == ['caddy-private:failed'] and box.atlas_calls == []
    assert any('SECURITY' in s for s in box.says)


def test_a_rejected_caddyfile_puts_everything_back():
    box = Box(generate_rejects=True)
    assert box.move() == 'failed'
    _assert_put_back(box, restarts=1)                      # only the one on the old config


def test_a_failed_restart_puts_everything_back():
    box = Box(restart_rc=[1, 0])
    assert box.move() == 'failed'
    _assert_put_back(box, restarts=2)
    assert box.events[-1] == 'systemctl restart caddy' and 'write-caddyfile' in box.events


@pytest.mark.parametrize('problem', ['the admin API still answers on 127.0.0.1:2019',
                                     'Caddy did not create its admin socket',
                                     'Caddy is not running after the restart'])
def test_a_failed_check_puts_everything_back(problem):
    box = Box(problem=problem)
    assert box.move() == 'failed'
    _assert_put_back(box, restarts=2)
    assert any(problem in s for s in box.says)


def test_atlas_not_switching_is_retried_not_rolled_back():
    box = Box(atlas_errs=['ATLAS: compose failed'])
    assert box.move() == 'private'
    assert box.state['private'] is True and box.state['atlas_pending'] is True


def _moved_state(**extra):
    st = {'secret': 'c' * 64, 'atlas_secret': 'd' * 64, 'enforce': True, 'private': True}
    st.update(extra)
    return st


def test_a_moved_box_is_left_alone():
    box = Box(state=_moved_state(), caddyfile=_private_caddyfile(),
              files={'console': 'c' * 64, 'atlas': 'd' * 64})
    assert box.move() == 'already'
    assert box.events == ['dropin'] and box.atlas_calls == []


def test_a_moved_box_gets_a_lost_value_file_back():
    box = Box(state=_moved_state(), caddyfile=_private_caddyfile(), files={'atlas': 'd' * 64})
    assert box.move() == 'already'
    assert box.files['console'] == 'c' * 64 and 'file:atlas' not in box.events
    assert not any('restart' in e for e in box.events)


def test_a_moved_box_tries_atlas_again():
    box = Box(state=_moved_state(atlas_pending=True), caddyfile=_private_caddyfile(),
              files={'console': 'c' * 64, 'atlas': 'd' * 64})
    assert box.move() == 'already'
    assert box.atlas_calls == ['d' * 64] and 'atlas_pending' not in box.state


@pytest.mark.parametrize('kw', [{'caddyfile': _old_caddyfile('c' * 64)}, {'tcp_open': True}])
def test_a_box_whose_live_config_went_back_is_moved_again(kw):
    """After a rollback to an older release and an update again, the secret file still
    says `private` but Caddy runs the old layout."""
    kw.setdefault('caddyfile', _private_caddyfile())
    box = Box(state=_moved_state(), **kw)
    assert box.move() == 'private'
    assert box.events.count('systemctl restart caddy') == 1
    assert box.state['secret'] not in ('c' * 64, OLD)


def test_make_private_never_raises_and_never_runs_twice_at_once():
    lock = threading.Lock()
    said = []
    ns = {'_caddy_private_lock': lock, 'print': lambda *a, **k: said.append(a[0]),
          '_caddy_make_private_locked': lambda say, plog=None: 1 / 0}
    fn = _load(['_caddy_make_private'], ns)['_caddy_make_private']
    assert fn() == 'failed' and 'SECURITY' in said[0] and not lock.locked()
    lock.acquire()
    assert fn() == 'failed'


# ── the check after the restart ──────────────────────────────────────────────

def _problem(*, active='active', tcp_open=False, sock_mode=stat.S_IFSOCK | 0o220, stat_exc=None,
             running_has=False):
    def os_stat(path):
        assert path == SOCK
        if stat_exc:
            raise stat_exc
        return types.SimpleNamespace(st_mode=sock_mode)

    clock = iter(range(0, 1000, 5))
    ns = _consts({
        'os': types.SimpleNamespace(stat=os_stat), 'time': types.SimpleNamespace(),
        'subprocess': types.SimpleNamespace(run=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, active + '\n', '')),
        '_sudo_wrap': lambda argv: argv, '_caddy_tcp_admin_open': lambda: tcp_open,
        '_caddy_running_config_has': lambda needle: running_has,
    })
    fn = _load(['_caddy_private_problem'], ns)['_caddy_private_problem']
    return fn({'secret': 'c' * 64, 'atlas_secret': 'd' * 64, 'previous': OLD},
              wait=4, sleep=lambda s: None, clock=lambda: next(clock))


def test_check_passes_on_a_good_restart():
    assert _problem() == ''
    assert _problem(sock_mode=stat.S_IFSOCK | 0o200) == ''


@pytest.mark.parametrize('kw,want', [
    ({'active': 'failed'}, 'not running'),
    ({'tcp_open': True}, '127.0.0.1:2019'),
    ({'stat_exc': FileNotFoundError()}, 'did not create its admin socket'),
    ({'sock_mode': stat.S_IFSOCK | 0o222}, 'mode 222'),
    ({'sock_mode': stat.S_IFSOCK | 0o660}, 'mode 660'),
    ({'sock_mode': stat.S_IFREG | 0o220}, 'not a socket'),
    ({'running_has': True}, 'still holds a proxy auth value'),
])
def test_check_names_what_is_wrong(kw, want):
    assert want in _problem(**kw)


def test_check_does_not_fail_what_it_cannot_see():
    """A console account outside group caddy cannot look into /run/caddy, and cannot ask
    the admin API (None): neither is evidence of a problem."""
    assert _problem(stat_exc=PermissionError(), running_has=None) == ''


def test_running_config_is_read_from_the_socket_on_a_moved_box():
    d = tempfile.mkdtemp(dir='/tmp')
    path = os.path.join(d, 'a.sock')
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    got = []

    def serve():
        c, _ = srv.accept()
        got.append(c.recv(4096).decode())
        body = b'{"apps":{"marker-814":1}}'
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(body) + body)
        c.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        ns = {'_socket': socket, 'CADDY_ADMIN_SOCKET': path, '_caddy_private': lambda: True}
        _load(['_caddy_admin_config_text', '_caddy_running_config_has'], ns)
        assert ns['_caddy_running_config_has']('marker-814') is True
        assert got[0].startswith('GET /config/ ')
        ns['CADDY_ADMIN_SOCKET'] = path + '.gone'
        assert ns['_caddy_running_config_has']('marker-814') is None
    finally:
        t.join(2)
        srv.close()
        os.unlink(path)
        os.rmdir(d)


# ── rotation on a moved box ──────────────────────────────────────────────────

class Rot:
    def __init__(self, *, caddyfile=None, write_fails_on=None, readback=None, atlas_errs=None,
                 atlas_enabled=True):
        self.state = {'secret': OLD, 'atlas_secret': OLD_ATLAS, 'enforce': True, 'private': True}
        self.caddyfile = _private_caddyfile() if caddyfile is None else caddyfile
        self.files = {'console': OLD, 'atlas': OLD_ATLAS}
        self.calls, self.atlas_calls, self.audits, self.saved = [], [], [], []
        self.backups = {}
        rot = self
        errs = list(atlas_errs or [])

        def write_file(kind, value):
            rot.calls.append(('file', kind))
            if write_fails_on == kind and value not in (OLD, OLD_ATLAS):
                raise RuntimeError('denied')
            rot.files[kind] = value

        def atlas_apply(secret, plog=None):
            rot.atlas_calls.append(secret)
            return errs.pop(0) if errs else []

        def save(st):
            rot.state = dict(st)
            rot.saved.append(dict(st))

        self.ns = _consts({
            'json': json, 'secrets': __import__('secrets'), 'threading': threading,
            'time': __import__('time'), 'print': lambda *a, **k: None, 'CADDYFILE_PATH': CF,
            'load_settings': lambda: {'fqdn': 'example.com', 'atlas_enabled': atlas_enabled},
            '_proxy_auth_state': lambda create=False: dict(rot.state),
            '_save_proxy_auth_state': save, '_caddy_private': lambda: True,
            '_caddy_account': lambda: ('/var/lib/caddy', 998, 999),
            '_read_priv': lambda p: rot.caddyfile,
            '_write_priv': lambda *a, **k: rot.calls.append(('write-caddyfile',)),
            'generate_caddyfile': lambda s=None: rot.calls.append(('generate',)),
            '_caddy_reload_if_changed': lambda **k: rot.calls.append(('reload',)),
            '_caddy_write_proxy_auth_file': write_file,
            '_caddy_read_proxy_auth_file': lambda kind: (readback or rot.files).get(kind, ''),
            '_proxy_auth_atlas_apply': atlas_apply,
            '_write_private_file': lambda path, content: rot.backups.__setitem__(path, content),
            '_PROXY_AUTH_BACKUP_FILE': '/cfg/proxy_auth.pre-rotate.json',
            '_proxy_auth_rotate_lock': threading.Lock(),
            'audit': lambda ev, detail='', force=False: rot.audits.append(ev),
        })
        _load(['_caddy_proxy_auth_path', '_caddy_proxy_auth_token', '_rotate_proxy_auth_private',
               '_rotate_proxy_auth_secret'], self.ns)

    def rotate(self):
        return self.ns['_rotate_proxy_auth_secret']()


def test_rotation_is_a_file_swap_with_no_reload():
    rot = Rot()
    res = rot.rotate()
    assert res['success'] is True, res
    st = rot.state
    assert HEX64.match(st['secret']) and HEX64.match(st['atlas_secret'])
    assert len({OLD, OLD_ATLAS, st['secret'], st['atlas_secret']}) == 4
    assert rot.files == {'console': st['secret'], 'atlas': st['atlas_secret']}
    assert 'previous' not in st and st['private'] is True and st['enforce'] is True
    assert rot.calls == [('file', 'console'), ('file', 'atlas')]   # no Caddyfile write, no reload
    assert rot.atlas_calls == [st['atlas_secret']]
    assert rot.audits == ['proxy-auth:rotated']
    assert json.loads(rot.backups['/cfg/proxy_auth.pre-rotate.json'])['secret'] == OLD


def test_rotation_never_shows_a_value():
    rot = Rot()
    text = json.dumps(rot.rotate())
    assert not any(v in text for v in (OLD, OLD_ATLAS, rot.state['secret'], rot.state['atlas_secret']))


def test_old_and_new_are_both_accepted_while_the_files_switch():
    rot = Rot()
    rot.rotate()
    during = rot.saved[0]
    assert during['previous'] == OLD and during['secret'] != OLD


@pytest.mark.parametrize('kind', ['console', 'atlas'])
def test_a_value_file_that_cannot_be_written_rolls_back(kind):
    rot = Rot(write_fails_on=kind)
    res = rot.rotate()
    assert res['success'] is False and res['rolled_back'] is True
    assert rot.state == {'secret': OLD, 'atlas_secret': OLD_ATLAS, 'enforce': True, 'private': True}
    assert rot.files == {'console': OLD, 'atlas': OLD_ATLAS}
    assert rot.atlas_calls == [] and rot.audits == ['proxy-auth:rotate-failed']


def test_a_value_file_that_does_not_read_back_rolls_back():
    rot = Rot(readback={'console': 'e' * 64})
    res = rot.rotate()
    assert res['success'] is False and 'does not hold the new value' in res['error']
    assert rot.state['secret'] == OLD and rot.files == {'console': OLD, 'atlas': OLD_ATLAS}


def test_atlas_failure_rolls_back_files_and_gives_atlas_its_old_value():
    rot = Rot(atlas_errs=[['ATLAS: compose failed']])
    res = rot.rotate()
    assert res['success'] is False and res['rolled_back'] is True
    assert rot.files == {'console': OLD, 'atlas': OLD_ATLAS} and rot.state['secret'] == OLD
    assert rot.atlas_calls[-1] == OLD_ATLAS and len(rot.atlas_calls) == 2


def test_caddy_not_sending_the_value_changes_nothing():
    rot = Rot(caddyfile='infratak.example.com {\n}\n')
    res = rot.rotate()
    assert res['success'] is False and 'not sending a proxy auth value' in res['error']
    assert rot.calls == [] and rot.saved == []


# ── the broker, the drop-in and the wiring ───────────────────────────────────

def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops814',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()
DROPIN_TEXT = _consts()['CADDY_BOOT_DROPIN_TEXT']


def _unit_write(rel, text):
    return B._evaluate({'op': 'write', 'path': f'{B.UNIT_DIR}/{rel}', 'mode': 'w',
                        'content_b64': base64.b64encode(text.encode()).decode()})


def test_the_broker_accepts_the_drop_in_the_console_writes():
    assert 'RuntimeDirectory=caddy\n' in DROPIN_TEXT and 'RuntimeDirectoryMode=0750\n' in DROPIN_TEXT
    assert _consts()['CADDY_BOOT_DROPIN'] == f'{B.UNIT_DIR}/caddy.service.d/10-takwerx-boot.conf'
    v = _unit_write('caddy.service.d/10-takwerx-boot.conf', DROPIN_TEXT)
    assert v[0] != 'DENY', v


@pytest.mark.parametrize('rel,text', [
    ('caddy.service.d/10-takwerx-boot.conf', '[Service]\nRuntimeDirectory=systemd\n'),
    ('caddy.service.d/10-takwerx-boot.conf', '[Service]\nRuntimeDirectory=caddy ../etc\n'),
    ('caddy.service.d/10-takwerx-boot.conf', '[Service]\nRuntimeDirectory=caddy\nRuntimeDirectoryMode=0777\n'),
    ('caddy.service.d/10-takwerx-acme-eab.conf', '[Service]\nRuntimeDirectory=caddy\n'),
    ('takserver.service.d/soft-start.conf', '[Service]\nRuntimeDirectory=caddy\n'),
    ('takwerx-console.service', '[Service]\nUser=takwerx\nExecStart=/opt/infratak/x\nRuntimeDirectory=caddy\n'),
    ('takserver.service.d/soft-start.conf', '[Service]\nRuntimeDirectoryMode=0750\n'),
])
def test_the_broker_refuses_any_other_runtime_directory(rel, text):
    v = _unit_write(rel, text)
    assert v[0] == 'DENY' and 'RuntimeDirectory' in v[1], v


def test_start_sh_writes_the_same_drop_in():
    sh = (REPO / 'start.sh').read_text(encoding='utf-8')
    body = sh.split("10-takwerx-boot.conf << 'EOF'\n", 1)[1].split('\nEOF\n', 1)[0] + '\n'
    assert body == DROPIN_TEXT


def test_startup_and_caddy_deploy_both_make_the_box_private():
    mig = _segment('_startup_migrations')
    assert mig.index("s.get('caddy_proxy_auth_gate_v1')") < mig.index('_caddy_make_private()')
    assert APP.count('_caddy_make_private(plog)') >= 1            # the Caddy deploy
    assert '_caddy_boot_dropin_ensure()' in _segment('_startup_harden_caddy_boot')


def test_nothing_in_the_product_talks_to_the_old_admin_address():
    """Only _caddy_admin_config_text() (a box not moved yet) and the probe that proves
    the port is closed may name 127.0.0.1:2019."""
    hits = [m.start() for m in re.finditer(r'127\.0\.0\.1[\'", :]+2019', APP)]
    owners = set()
    src_lines = APP.splitlines()
    for pos in hits:
        line = APP.count('\n', 0, pos) + 1
        if src_lines[line - 1].lstrip().startswith('#'):
            continue                                              # a comment, not a caller
        owners.add(next((n.name for n in TREE.body if isinstance(n, ast.FunctionDef)
                         and n.lineno <= line <= n.end_lineno), None))
    assert owners <= {'_caddy_admin_config_text', '_caddy_tcp_admin_open', '_caddy_private_problem'}, owners


# ── ATLAS reads its own value ────────────────────────────────────────────────

def test_atlas_uses_its_own_value_on_a_moved_box(tmp_path):
    import modules.atlas as atlas
    (tmp_path / 'proxy_auth.json').write_text(json.dumps(
        {'secret': OLD, 'atlas_secret': OLD_ATLAS, 'private': True}))
    assert atlas._proxy_auth_secret({'CONFIG_DIR': str(tmp_path)}) == OLD_ATLAS


def test_atlas_keeps_the_console_value_until_the_box_is_moved(tmp_path):
    import modules.atlas as atlas
    (tmp_path / 'proxy_auth.json').write_text(json.dumps({'secret': OLD, 'atlas_secret': OLD_ATLAS}))
    assert atlas._proxy_auth_secret({'CONFIG_DIR': str(tmp_path)}) == OLD
