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
"""One lock for every ufw call, and the IPv4 repair (v10.4.6).

ufw has no lock of its own. At boot fail2ban restored its bans (`ufw insert`) in the
same seconds the console ran `ufw --force delete allow 8080/tcp` and `5001/tcp`; 31
IPv4 rules were lost (22/80/443/8089 among them) and the box dropped every TCP port.
The IPv6 rules were complete: fail2ban bans are IPv4 and rewrite only user.rules.

The broker rulebook and lock are run from the shipped broker; the console functions
from the shipped app.py text, against fakes. Nothing touches a real firewall.
"""

import ast
import fcntl
import importlib.util
import os
import pathlib
import re
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ufwlock',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()


def _seg(node):
    return ast.get_source_segment(APP, node)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return _seg(n)
    raise AssertionError(f'{name} was renamed or removed')


def _const(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return _seg(n)
    raise AssertionError(f'{name} was renamed or removed')


# ── broker ──────────────────────────────────────────────────────────────────

def test_flock_allows_only_the_locked_fail2ban_stop():
    assert B.check_exec(list(B.FLOCK_F2B_STOP_ARGV)) == B.FLOCK_F2B_STOP_ARGV
    lock = B.UFW_LOCK_PATH
    for argv in (
        ['flock', lock, 'sh', '-c', 'id'],
        ['flock', '-w', '90', lock, 'bash', '-c', 'id'],
        ['flock', '-w', '90', lock, 'systemctl', 'stop', 'fail2ban', ';', 'id'],
        ['flock', '-w', '90', '/tmp/x', 'systemctl', 'stop', 'fail2ban'],
        ['flock', '-w', '90', lock, 'systemctl', 'start', 'sshd'],
        ['flock', '-c', 'id', lock],
        ['/usr/bin/flock', '-w', '90', lock, 'systemctl', 'stop', 'fail2ban'],
    ):
        with pytest.raises(B.Denied):
            B.check_exec(argv)


def test_the_console_sends_exactly_the_argv_the_broker_allows():
    src = _func('_startup_f2b_ufw_lock_switch')
    # The path is a literal at the call site on purpose: broker/scan_enforce_coverage.py reads
    # the argv shape, and a variable shows up as <var> and is reported as a denied call site
    # (tests/test_broker_escapes_ops645.py). So the literal must equal the broker's exact argv.
    assert str(B.FLOCK_F2B_STOP_ARGV) in src
    assert _const('_UFW_LOCK_PATH').endswith(repr(B.UFW_LOCK_PATH))


@pytest.fixture
def lockfile(tmp_path, monkeypatch):
    p = str(tmp_path / 'ufw.lock')
    monkeypatch.setattr(B, 'UFW_LOCK_PATH', p)
    monkeypatch.setattr(B, 'UFW_LOCK_WAIT', 0.5)
    return p


def test_ufw_waits_for_the_lock_and_is_not_run_if_it_stays_held(lockfile, monkeypatch):
    ran = []
    monkeypatch.setattr(B.subprocess, 'run', lambda argv, **kw: ran.append(argv) or
                        subprocess.CompletedProcess(argv, 0, b'', b''))
    fd = os.open(lockfile, os.O_RDWR | os.O_CREAT, 0o644)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        r = B._run_maybe_ufw_locked(['ufw', 'allow', '22/tcp'], capture_output=True)
    finally:
        os.close(fd)
    assert r.returncode == 75 and b'not run' in r.stderr
    assert ran == []                                   # never runs unlocked
    r = B._run_maybe_ufw_locked(['ufw', 'allow', '22/tcp'], capture_output=True)
    assert r.returncode == 0 and ran == [['ufw', 'allow', '22/tcp']]
    assert oct(os.stat(lockfile).st_mode & 0o777) == oct(0o600)   # 644 from flock is tightened


def test_ufw_holds_the_lock_while_it_runs(lockfile, monkeypatch):
    held = []

    def fake_run(argv, **kw):
        fd = os.open(lockfile, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            held.append(False)
        except BlockingIOError:
            held.append(True)
        finally:
            os.close(fd)
        return subprocess.CompletedProcess(argv, 0, b'', b'')
    monkeypatch.setattr(B.subprocess, 'run', fake_run)
    B._run_maybe_ufw_locked(['/usr/sbin/ufw', 'status'])
    B._run_maybe_ufw_locked(['systemctl', 'is-active', 'fail2ban'])
    assert held == [True, False]                      # ufw under the lock, nothing else


def test_both_broker_exec_paths_use_the_lock():
    src = (REPO / 'broker' / 'takwerx_broker.py').read_text(encoding='utf-8')
    assert src.count('_run_maybe_ufw_locked(') == 3   # the def + console exec + MediaMTX exec
    do_exec = src[src.index('def _do_exec('):src.index('def _is_console_owned(')]
    assert 'proc = _run_maybe_ufw_locked(argv, input=input_bytes' in do_exec
    mtx = src[src.index('def _mtx_run('):src.index('def _dispatch_mediamtx(')]
    assert '_run_maybe_ufw_locked([resolved]' in mtx


# ── the other writers ───────────────────────────────────────────────────────

def test_selfheal_ip_and_start_sh_take_the_same_lock():
    sh = (REPO / 'selfheal_ip.py').read_text(encoding='utf-8')
    assert f"_UFW_LOCK = '{B.UFW_LOCK_PATH}'" in sh
    assert not re.search(r"subprocess\.run\(\['ufw'", sh)
    start = (REPO / 'start.sh').read_text(encoding='utf-8')
    assert f'flock -w 90 {B.UFW_LOCK_PATH} ufw allow 5001/tcp' in start


def test_root_console_without_broker_wraps_ufw_in_flock():
    ns = {'_broker_should_route': lambda: False, '_broker_available': lambda: False,
          'os': types.SimpleNamespace(getuid=lambda: 0),
          'shutil': types.SimpleNamespace(which=lambda b: '/usr/bin/flock'),
          '_UFW_LOCK_PATH': B.UFW_LOCK_PATH, '_sys': None,
          '_BROKER_CLIENT_PYFLAGS': [], '_BROKER_CLIENT': ''}
    exec(_func('_sudo_wrap'), ns)
    assert ns['_sudo_wrap'](['ufw', 'allow', '22/tcp']) == \
        ['flock', '-w', '90', B.UFW_LOCK_PATH, 'ufw', 'allow', '22/tcp']
    assert ns['_sudo_wrap'](['systemctl', 'status']) == ['systemctl', 'status']


def test_fail2ban_action_takes_the_lock_on_ban_and_unban():
    ns = {'_UFW_LOCK_PATH': B.UFW_LOCK_PATH}
    exec(_const('_F2B_UFW_ACTION_CONF'), ns)
    conf = ns['_F2B_UFW_ACTION_CONF']
    ban = re.search(r'(?m)^actionban = (.*)$', conf).group(1)
    unban = re.search(r'(?m)^actionunban = (.*)$', conf).group(1)
    for cmd in (ban, unban):
        assert cmd.startswith(f'flock -w 90 {B.UFW_LOCK_PATH} ufw ')
    # ops #1275: `ufw insert 1` refuses an IPv6 address (Invalid position '1'); prepend does not
    assert 'ufw prepend <blocktype> from <ip> to <destination>' in ban
    assert 'insert' not in ban and 'insertpos' not in conf
    assert 'ufw delete <blocktype> from <ip> to <destination>' in unban
    timeout = int(re.search(r'(?m)^timeout = (\d+)$', conf).group(1))
    assert timeout > 90                                # fail2ban must not kill a waiting ban
    for key in ('blocktype', 'destination', 'comment'):
        assert re.search(rf'(?m)^{key} = \S', conf), key   # every tag is defined here (0.11 and 1.0)


# ── jail rewrite + ban action choice ────────────────────────────────────────

def _stale_re():
    ns = {'re': re}
    exec(_const('_F2B_STALE_UFW_RE'), ns)
    return ns['_F2B_STALE_UFW_RE']


def test_jail_rewrite_keeps_the_guarddog_line_and_nothing_else_changes():
    R = _stale_re()
    jail = ('[sshd]\nenabled  = true\nmaxretry = 3\n'
            'action   = ufw\n         infratak-guarddog\n')
    out = R.sub(r'\g<1>infratak-ufw', jail)
    assert out == jail.replace('action   = ufw\n', 'action   = infratak-ufw\n')
    for line in ('action   = iptables-multiport[name=x, port="80", protocol=tcp]\n',
                 'action   = infratak-ufw\n', 'action   = ufw-custom\n', 'banaction = ufw\n'):
        assert not R.search(line), line


def _banaction(rhel=False, action_file=False, jails=(), write_ok=True):
    writes = []
    ns = {'_distro_family': lambda: 'rhel' if rhel else 'debian',
          '_F2B_UFW_ACTION_PATH': '/etc/fail2ban/action.d/infratak-ufw.conf',
          'os': types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: action_file)),
          '_f2b_ensure_ufw_action': lambda: writes.append(1) or write_ok}
    exec(_func('_f2b_banaction'), ns)
    import glob as real_glob
    orig = real_glob.glob
    real_glob.glob = lambda pat: list(jails)
    try:
        return ns['_f2b_banaction'](), writes
    finally:
        real_glob.glob = orig


def test_ban_action_choice():
    assert _banaction(rhel=True)[0] == 'iptables-allports'
    assert _banaction(action_file=True, jails=['x'])[0] == 'infratak-ufw'
    # jails still on the old action and the move has not run: never change it by a reload
    act, writes = _banaction(jails=['/etc/fail2ban/jail.d/infratak-sshd.conf'])
    assert act == 'ufw' and writes == []
    # fresh box, nothing running on the old action: write the file, use it
    act, writes = _banaction(jails=[])
    assert act == 'infratak-ufw' and writes == [1]
    assert _banaction(jails=[], write_ok=False)[0] == 'ufw'


# ── the move ────────────────────────────────────────────────────────────────

def _switch(stop_rc=0, active='active', stale=True, outdated=False, enabled='enabled',
            stop_timeout=False, ensure_raises=False, write_raises=False, start_rc=0,
            start_raises_first=False):
    """Run the shipped _startup_f2b_ufw_lock_switch against fakes. `box` is fail2ban's state:
    a stop (or a timed-out stop, which still goes on in systemd) makes it inactive, a start
    makes it active, so the test can tell whether fail2ban ends up running (ops #1342)."""
    calls, writes, logs = [], {}, []
    box = {'active': active, 'start_raised': False}

    def run(argv, **kw):
        calls.append(list(argv))
        if argv[:3] == ['systemctl', 'is-active', 'fail2ban']:
            return subprocess.CompletedProcess(argv, 0 if box['active'] == 'active' else 3,
                                               box['active'] + '\n', '')
        if argv[:3] == ['systemctl', 'is-enabled', 'fail2ban']:
            return subprocess.CompletedProcess(argv, 0, enabled + '\n', '')
        if argv[0] == 'flock':
            if stop_timeout:
                box['active'] = 'inactive'          # the stop goes on in systemd after the client dies
                raise subprocess.TimeoutExpired(argv, kw.get('timeout'))
            if stop_rc == 0:
                box['active'] = 'inactive'
            return subprocess.CompletedProcess(argv, stop_rc, '', 'denied' if stop_rc else '')
        if argv[:3] == ['systemctl', 'start', 'fail2ban']:
            if start_raises_first and not box['start_raised']:
                box['start_raised'] = True
                raise subprocess.TimeoutExpired(argv, kw.get('timeout'))
            if start_rc == 0:
                box['active'] = 'active'
            return subprocess.CompletedProcess(argv, start_rc, '', '')
        return subprocess.CompletedProcess(argv, 0, '', '')

    def ensure():
        calls.append(['ENSURE'])
        if ensure_raises:
            raise RuntimeError('disk full')
        return True

    def write(p, t):
        if write_raises:
            raise OSError('read-only file system')
        writes[p] = t
    ns = {'_distro_family': lambda: 'debian', '_fw_backend': lambda: 'ufw',
          'os': types.SimpleNamespace(path=types.SimpleNamespace(isdir=lambda p: True),
                                      path_basename=None),
          'subprocess': types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired),
          '_sudo_wrap': lambda c: list(c),
          '_UFW_LOCK_PATH': B.UFW_LOCK_PATH,
          '_f2b_stale_ufw_jails': lambda: [('/etc/fail2ban/jail.d/infratak-sshd.conf',
                                            'action   = ufw\n         infratak-guarddog\n')] if stale else [],
          '_f2b_ufw_action_outdated': lambda: outdated,
          '_f2b_ensure_ufw_action': ensure,
          '_F2B_STALE_UFW_RE': _stale_re(),
          '_write_priv': write,
          '_ufw_ipv4_parity_heal': lambda log: calls.append(['PARITY']),
          'threading': types.SimpleNamespace(Thread=lambda **kw: types.SimpleNamespace(start=lambda: None)),
          'time': None, 'print': lambda *a, **k: logs.append(a[0])}
    ns['os'].path.basename = os.path.basename
    exec(_func('_f2b_start_if_down'), ns)
    exec(_func('_f2b_enabled_but_down'), ns)
    exec(_func('_startup_f2b_ufw_lock_switch'), ns)
    ns['_startup_f2b_ufw_lock_switch']()
    return calls, writes, logs, box


def test_move_stops_fail2ban_under_the_lock_before_anything_changes():
    calls, writes, logs, box = _switch()
    i_stop = calls.index(list(B.FLOCK_F2B_STOP_ARGV))
    i_ensure = calls.index(['ENSURE'])
    i_start = calls.index(['systemctl', 'start', 'fail2ban'])
    assert i_stop < i_ensure < i_start                 # stop under lock, then write, then start
    assert ['systemctl', 'restart', 'fail2ban'] not in calls
    assert writes == {'/etc/fail2ban/jail.d/infratak-sshd.conf':
                      'action   = infratak-ufw\n         infratak-guarddog\n'}
    assert calls[-1] == ['PARITY']
    assert any('moved to the locked infratak-ufw action' in m for m in logs)


def test_move_changes_nothing_when_the_locked_stop_is_refused():
    calls, writes, logs, box = _switch(stop_rc=1)
    assert writes == {} and ['ENSURE'] not in calls
    assert ['systemctl', 'start', 'fail2ban'] not in calls
    assert any('next console start tries again' in m for m in logs)


def test_move_on_a_disabled_stopped_fail2ban_rewrites_without_starting_it():
    # a fail2ban that is stopped AND not enabled at boot (uninstalled, or the operator's choice)
    # is not ours to start
    calls, writes, logs, box = _switch(active='inactive', enabled='disabled')
    assert list(B.FLOCK_F2B_STOP_ARGV) not in calls
    assert ['systemctl', 'start', 'fail2ban'] not in calls
    assert writes
    assert box['active'] == 'inactive'


def test_a_stop_that_times_out_still_puts_fail2ban_back_ops1342():
    # The stop under the lock waits up to 300 s (200+ unbans). On a timeout the old code jumped to
    # the outer except and never started fail2ban; on Debian nothing else does.
    calls, writes, logs, box = _switch(stop_timeout=True)
    assert list(B.FLOCK_F2B_STOP_ARGV) in calls
    assert ['systemctl', 'start', 'fail2ban'] in calls
    assert box['active'] == 'active'
    assert writes == {}                                 # the jails were not changed
    assert any('took over 300 s' in m for m in logs)


def test_an_error_after_the_stop_still_puts_fail2ban_back_ops1342():
    for kw in ({'ensure_raises': True}, {'write_raises': True}):
        calls, writes, logs, box = _switch(**kw)
        assert list(B.FLOCK_F2B_STOP_ARGV) in calls
        assert box['active'] == 'active', kw            # stopped, then the step raised: started anyway
        assert any('error (non-fatal)' in m for m in logs)


def test_the_normal_move_starts_fail2ban_once_ops1342():
    calls, writes, logs, box = _switch()
    assert calls.count(['systemctl', 'start', 'fail2ban']) == 1
    assert box['active'] == 'active'


def test_a_start_that_times_out_is_tried_again_by_the_finally_ops1342():
    calls, writes, logs, box = _switch(start_raises_first=True)
    assert calls.count(['systemctl', 'start', 'fail2ban']) == 2
    assert box['active'] == 'active'


def test_next_boot_starts_an_enabled_but_stopped_fail2ban_ops1342():
    # the console died between the stop and the start: jails not yet moved
    calls, writes, logs, box = _switch(active='inactive', enabled='enabled')
    assert box['active'] == 'active'
    assert writes                                       # the move still happens, then the start
    assert any('was enabled but stopped' in m for m in logs)
    # the console died after the jail files were written: nothing stale, nothing outdated
    calls, writes, logs, box = _switch(active='inactive', enabled='enabled', stale=False, outdated=False)
    assert box['active'] == 'active'
    assert any('enabled but not running' in m for m in logs)
    # a failed unit (crashed at start) counts as down
    calls, writes, logs, box = _switch(active='failed', enabled='enabled', stale=False, outdated=False)
    assert box['active'] == 'active'


def test_next_boot_leaves_fail2ban_alone_when_it_is_running_or_not_enabled_ops1342():
    for kw in ({'active': 'active', 'stale': False, 'outdated': False},
               {'active': 'inactive', 'enabled': 'disabled', 'stale': False, 'outdated': False},
               {'active': 'inactive', 'enabled': 'not-found', 'stale': False, 'outdated': False}):
        calls, writes, logs, box = _switch(**kw)
        assert ['systemctl', 'start', 'fail2ban'] not in calls, kw


def test_old_action_file_on_a_box_already_moved_is_loaded_by_a_locked_restart():
    # ops #1275: boxes on the 10.4.6+ action (ufw insert 1) get the prepend action; a reload
    # would leave current bans on the old action, so fail2ban stops under the lock and starts
    calls, writes, logs, box = _switch(stale=False, outdated=True)
    i_stop = calls.index(list(B.FLOCK_F2B_STOP_ARGV))
    i_ensure = calls.index(['ENSURE'])
    i_start = calls.index(['systemctl', 'start', 'fail2ban'])
    assert i_stop < i_ensure < i_start
    assert writes == {}                                 # no jail file changes: only the action file
    assert any('action updated' in m and 'restarted' in m for m in logs)


def test_current_action_file_and_moved_jails_do_not_restart_fail2ban():
    calls, writes, logs, box = _switch(stale=False, outdated=False)
    assert list(B.FLOCK_F2B_STOP_ARGV) not in calls
    assert ['systemctl', 'start', 'fail2ban'] not in calls
    assert ['ENSURE'] in calls                          # the file is still kept current


def test_outdated_check_compares_the_file_with_the_current_action(tmp_path):
    ns = {'_UFW_LOCK_PATH': B.UFW_LOCK_PATH}
    exec(_const('_F2B_UFW_ACTION_CONF'), ns)
    f = tmp_path / 'infratak-ufw.conf'
    ns['_F2B_UFW_ACTION_PATH'] = str(f)
    exec(_func('_f2b_ufw_action_outdated'), ns)
    assert ns['_f2b_ufw_action_outdated']() is False    # no file: nothing to update
    f.write_text(ns['_F2B_UFW_ACTION_CONF'].replace('ufw prepend', 'ufw insert 1'))
    assert ns['_f2b_ufw_action_outdated']() is True
    f.write_text(ns['_F2B_UFW_ACTION_CONF'])
    assert ns['_f2b_ufw_action_outdated']() is False


# ── IPv4 repair ─────────────────────────────────────────────────────────────

STATUS = """Status: active

To                         Action      From
--                         ------      ----
Anywhere                   REJECT      109.160.32.157             # by Fail2Ban after 3 attempts against recidive
22/tcp                     ALLOW       Anywhere
8080/tcp                   ALLOW       190.0.2.10
5001/tcp                   ALLOW       Anywhere
8765/tcp                   DENY        Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
443/tcp (v6)               ALLOW       Anywhere (v6)
8000/udp (v6)              ALLOW       Anywhere (v6)
60000:61000/udp (v6)       ALLOW       Anywhere (v6)
8765/tcp (v6)              DENY        Anywhere (v6)
9000/tcp (v6)              DENY        Anywhere (v6)
8080/tcp (v6)              ALLOW       2001:db8::1
OpenSSH (v6)               ALLOW       Anywhere (v6)
3000/tcp on eth0 (v6)      ALLOW       Anywhere (v6)
"""


def _parity(status=STATUS, rc=0, backend='ufw'):
    calls, logs = [], []

    def run(argv, **kw):
        calls.append(list(argv))
        if argv == ['ufw', 'status']:
            return subprocess.CompletedProcess(argv, rc, status, '')
        return subprocess.CompletedProcess(argv, 0, '', '')
    ns = {'re': re, '_fw_backend': lambda: backend, '_sudo_wrap': lambda c: list(c),
          'subprocess': types.SimpleNamespace(run=run)}
    exec(_const('_UFW_STATUS_ROW_RE'), ns)
    exec(_func('_ufw_ipv4_parity_heal'), ns)
    added = ns['_ufw_ipv4_parity_heal'](logs.append)
    return added, calls[1:], logs


def test_parity_adds_back_only_ipv4_twins_of_ipv6_anywhere_port_rules():
    added, calls, logs = _parity()
    assert sorted(added) == ['allow 443/tcp', 'allow 60000:61000/udp', 'allow 8000/udp',
                             'deny 9000/tcp']
    assert sorted(calls) == sorted([['ufw', a.split()[0], a.split()[1]] for a in added])
    # never re-adds an IPv4-only rule the console may have meant (5001), never touches
    # source-scoped (8080), app-profile or interface rules
    assert not any('5001' in ' '.join(c) or '8080' in ' '.join(c) or 'OpenSSH' in ' '.join(c)
                   or '3000' in ' '.join(c) for c in calls)
    assert logs and '4 IPv4 rule(s) were missing' in logs[0]


def test_parity_does_nothing_when_sets_match_or_ufw_is_off():
    whole = STATUS + '443/tcp                    ALLOW       Anywhere\n' \
                     '8000/udp                   ALLOW       Anywhere\n' \
                     '60000:61000/udp            ALLOW       Anywhere\n' \
                     '9000/tcp                   DENY        Anywhere\n'
    assert _parity(whole)[0] == [] and _parity(whole)[1] == []
    assert _parity('Status: inactive\n')[1] == []
    assert _parity(rc=1)[1] == []
    added, calls, _ = _parity(backend='firewalld')
    assert added == [] and calls == []


# ── startup order ───────────────────────────────────────────────────────────

def _call_line(call):
    m = re.search(rf'(?m)^{re.escape(call)}', APP)
    assert m, call
    return m.start()


def test_startup_order():
    # the repair runs before the console's own boot firewall calls
    assert _call_line('_startup_ufw_ipv4_parity()') < _call_line('_fw_remove_blanket_internal_ports()')
    assert _call_line('_startup_ufw_ipv4_parity()') < _call_line('_auto_harden_guarddog_8080()')
    # the move runs after the broker has this checkout's code, before the jail writers
    assert _call_line('_startup_broker_converge()') < _call_line('_startup_f2b_ufw_lock_switch()')
    assert _call_line('_startup_f2b_ufw_lock_switch()') < _call_line('_startup_migrations()')
