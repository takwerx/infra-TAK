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
"""ops #1149: MediaMTX's HLS port on a REMOTE host closes to the console once Caddy on the
console no longer reads it.

After ops #1110 Caddy sends stream site video through the sign-in to the web editor on the
host, and the editor reads MediaMTX on loopback there. The HLS port (8888) was still open to
the console's address and bound to every interface.

What runs here for real: the shell the console sends to the host (the firewall scope and the
bind change), under `sh`, against small stand-ins for `ufw`, `firewall-cmd`, `ss`, `systemctl`
and `sudo` that keep their state in files. The console side (`_module_run`, Caddy's admin
API, the settings) is a stub.

On a tree without the change, a console start leaves the allow rule for 8888 and the bind on
every interface, and the proof test fails on that outcome.
"""

import ast
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

HOST = '10.0.0.5'                 # the remote MediaMTX host
CONSOLE = '203.0.113.7'           # the console, as the host sees it
OLD_CONSOLE = '198.51.100.9'      # a console address from an earlier deploy
YML_PATH = '/usr/local/etc/mediamtx.yml'

NAMES = (
    # this change
    '_MEDIAMTX_REMOTE_HLS_PORT', '_MEDIAMTX_REMOTE_HLS_CLOSED_FILE', '_mediamtx_remote_hls_closed',
    '_MEDIAMTX_REMOTE_HLS_BIND_SH', '_mediamtx_remote_hls_bind', '_mediamtx_remote_hls_port',
    '_startup_converge_mediamtx_remote_hls_port', '_console_release_app_has',
    '_mediamtx_remote_hls_port_before_rollback',
    # what it builds on
    '_REMOTE_SUDO_SH', '_MEDIAMTX_REMOTE_CONSOLE_PORTS', '_MEDIAMTX_REMOTE_FW_RULES',
    '_mediamtx_remote_console_scope_sh', '_mediamtx_remote_firewall',
    '_MEDIAMTX_REMOTE_HLS_ROAD_FILE', '_mediamtx_remote_hls_via_editor',
)


def _src(*names):
    """Top-level defs/assignments from app.py, in file order. A name app.py does not have
    is skipped, so the tests run (and fail on the outcome) on a tree without this change."""
    parts = []
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name in names:
            parts.append(ast.get_source_segment(APP, n))
        elif isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in names for t in n.targets):
            parts.append(ast.get_source_segment(APP, n))
    return '\n\n'.join(parts)


# ── stand-ins for the host's tools: state in files under $FAKE ─────────────────────────────

UFW = r'''#!/usr/bin/env python3
import os, sys
F = os.path.join(os.environ['FAKE'], 'ufw.rules')
rules = open(F).read().splitlines() if os.path.exists(F) else []
a = [x for x in sys.argv[1:] if x != '--force']
def save():
    open(F, 'w').write(''.join(r + '\n' for r in rules))
if a[:2] == ['show', 'added']:
    print("Added user rules (see 'ufw status' for running firewall):")
    print('\n'.join(rules))
elif a[:1] == ['delete']:
    line = 'ufw ' + ' '.join(a[1:])
    if line in rules and not os.environ.get('UFW_STUCK'):
        rules.remove(line); save()
elif a[:1] in (['allow'], ['deny']):
    line = 'ufw ' + ' '.join(a)
    if line not in rules:
        rules.append(line); save()
else:
    sys.exit(2)
'''

FIREWALL_CMD = r'''#!/usr/bin/env python3
import os, sys
D = os.environ['FAKE']
def load(n):
    p = os.path.join(D, n)
    return open(p).read().splitlines() if os.path.exists(p) else []
def save(n, rows):
    open(os.path.join(D, n), 'w').write(''.join(r + '\n' for r in rows))
a = sys.argv[1:]
perm = '--permanent' in a
a = [x for x in a if x != '--permanent']
kind = 'perm' if perm else 'run'
arg = a[0] if a else ''
if arg == '--state':
    sys.exit(0)
elif arg == '--reload':
    save('fwd.run.rich', load('fwd.perm.rich')); save('fwd.run.ports', load('fwd.perm.ports'))
elif arg == '--list-rich-rules':
    print('\n'.join(load('fwd.%s.rich' % kind)))
elif arg == '--list-ports':
    print(' '.join(load('fwd.%s.ports' % kind)))
elif arg.startswith('--add-rich-rule='):
    r = arg.split('=', 1)[1].replace("'", '"')
    rows = load('fwd.%s.rich' % kind)
    if r not in rows:
        rows.append(r); save('fwd.%s.rich' % kind, rows)
elif arg.startswith('--remove-rich-rule='):
    r = arg.split('=', 1)[1].replace("'", '"')
    rows = load('fwd.%s.rich' % kind)
    if r in rows and not os.environ.get('FWD_STUCK'):
        rows.remove(r); save('fwd.%s.rich' % kind, rows)
elif arg.startswith('--remove-port='):
    p = arg.split('=', 1)[1]
    rows = [x for x in load('fwd.%s.ports' % kind) if x != p]
    save('fwd.%s.ports' % kind, rows)
else:
    sys.exit(2)
'''

# MediaMTX's listener: FAKE/listen holds the address it listens on. With FAKE/hot present it
# follows mediamtx.yml by itself (MediaMTX loads a changed file); without, only a restart does.
SS = r'''#!/bin/sh
if [ -f "$FAKE/stopped" ]; then exit 0; fi
if [ -f "$FAKE/hot" ]; then A=$(sed -n 's/^hlsAddress:[[:space:]]*//p' "$FAKE/mediamtx.yml" | head -n 1)
else A=$(cat "$FAKE/listen"); fi
echo "LISTEN 0      4096   127.0.0.1:9898      0.0.0.0:*"
echo "LISTEN 0      4096   $A      0.0.0.0:*"
'''

SYSTEMCTL = r'''#!/bin/sh
case "$1" in
is-active) [ -f "$FAKE/stopped" ] && exit 3; exit 0 ;;
restart) echo restart >> "$FAKE/restarts"; rm -f "$FAKE/stopped"
         sed -n 's/^hlsAddress:[[:space:]]*//p' "$FAKE/mediamtx.yml" | head -n 1 > "$FAKE/listen" ;;
esac
exit 0
'''

SUDO = '#!/bin/sh\n[ "$1" = "-n" ] && shift\nexec "$@"\n'
SLEEP = '#!/bin/sh\nexit 0\n'
# BSD sed (a developer's Mac) wants an argument after -i; the host has GNU sed.
SED_BSD = '#!/bin/sh\nif [ "$1" = "-i" ]; then shift; exec /usr/bin/sed -i "" "$@"; fi\nexec /usr/bin/sed "$@"\n'


class Host:
    """The remote MediaMTX host: runs the console's shell for real, with the stand-ins."""

    def __init__(self, tmp, firewall='ufw'):
        self.dir = tmp
        self.bin = tmp / 'bin'
        self.bin.mkdir()
        tools = {'ss': SS, 'systemctl': SYSTEMCTL, 'sudo': SUDO, 'sleep': SLEEP,
                 ('ufw' if firewall == 'ufw' else 'firewall-cmd'): (UFW if firewall == 'ufw' else FIREWALL_CMD)}
        if sys.platform == 'darwin':
            tools['sed'] = SED_BSD
        for name, body in tools.items():
            p = self.bin / name
            p.write_text(body)
            p.chmod(p.stat().st_mode | stat.S_IXUSR)
        self.firewall = firewall
        self.yml = tmp / 'mediamtx.yml'
        self.yml.write_text('hls: yes\nhlsAddress: 0.0.0.0:8888\nhlsEncryption: no\n')
        (tmp / 'listen').write_text('0.0.0.0:8888\n')
        (tmp / 'hot').write_text('')
        self.env = {}
        self.sent = []          # what the console asked, in order: 'scope-open', 'scope-closed', 'bind-...'
        self.reachable = True

    # the state before this change: the console's address allowed on both ports
    def seed_rules(self, extra_8888=()):
        if self.firewall == 'ufw':
            rows = [f'ufw allow from {CONSOLE} to any port 5080 proto tcp', 'ufw deny 5080/tcp']
            rows += [f'ufw allow from {a} to any port 8888 proto tcp' for a in (CONSOLE,) + tuple(extra_8888)]
            rows += ['ufw deny 8888/tcp']
            (self.dir / 'ufw.rules').write_text(''.join(r + '\n' for r in rows))
        else:
            rows = [f'rule family="ipv4" source address="{a}" port port="{p}" protocol="tcp" accept'
                    for p, srcs in ((5080, (CONSOLE,)), (8888, (CONSOLE,) + tuple(extra_8888))) for a in srcs]
            for n in ('fwd.perm.rich', 'fwd.run.rich'):
                (self.dir / n).write_text(''.join(r + '\n' for r in rows))

    def run(self, sh, **env):
        e = {'PATH': f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}", 'FAKE': str(self.dir),
             'SSH_CLIENT': f'{CONSOLE} 50022 22', 'HOME': str(self.dir)}
        e.update(self.env)
        e.update(env)
        r = subprocess.run(['sh', '-c', sh.replace(YML_PATH, str(self.yml))], env=e,
                           capture_output=True, text=True, timeout=60)
        return r.returncode == 0, r.stdout + r.stderr

    def module_run(self, cfg, sh, timeout=120, log_fn=None):
        """Stands in for app.py's _module_run on a remote target."""
        if 'SCOPE_RC' in sh:
            # the open scope adds an allow rule for the HLS port, the closed one never does
            opens = re.search(r'for P in [0-9 ]*\b8888\b[0-9 ]*; do\s+(for A in \$SRCS|\$S ufw --force delete deny \$P/tcp >/dev/null 2>&1; '
                              r'\s+\$S ufw --force delete allow \$P/tcp >/dev/null 2>&1; \s+for A in \$SRCS)', sh)
            self.sent.append('scope-open' if opens else 'scope-closed')
        elif 'HLS_BIND' in sh:
            self.sent.append('bind-' + re.search(r'W="([0-9.]+):', sh).group(1))
        else:
            self.sent.append('other')
        if not self.reachable:
            return False, 'ssh: connect to host: Connection timed out'
        return self.run(sh)

    # what the host looks like now
    def allows(self, port):
        if self.firewall == 'ufw':
            rows = (self.dir / 'ufw.rules').read_text().splitlines()
            return sorted(m.group(1) for m in (re.match(
                rf'ufw allow from (\S+) to any port {port} proto tcp$', r) for r in rows) if m)
        rows = (self.dir / 'fwd.run.rich').read_text().splitlines()
        return sorted(m.group(1) for m in (re.search(
            rf'source address="([^"]+)" port port="{port}" protocol="tcp" accept', r) for r in rows) if m)

    def bind(self):
        return re.search(r'(?m)^hlsAddress:\s*(\S+)', self.yml.read_text()).group(1)

    def restarts(self):
        p = self.dir / 'restarts'
        return len(p.read_text().splitlines()) if p.exists() else 0


@pytest.fixture(params=['ufw', 'firewalld'])
def host(request, tmp_path):
    h = Host(tmp_path / 'host', request.param) if (tmp_path / 'host').mkdir() is None else None
    h.seed_rules()
    return h


class Console:
    """The console side of app.py: the functions of this change, with stubs around them."""

    def __init__(self, tmp, host, marked=True, caddy_dials=False):
        self.cfg_dir = tmp / 'config'
        self.cfg_dir.mkdir()
        self.host = host
        self.caddy_dials = caddy_dials          # True / False / None (cannot be asked)
        self.log = []
        self.cfg = {'target_mode': 'remote', 'deployed': True,
                    'remote': {'host': HOST, 'ssh_user': 'ops', 'ssh_port': 22}}
        self.settings = {'fqdn': 'example.org', 'server_ip': CONSOLE, 'mediamtx_deployment': self.cfg}
        self.road_calls = []
        ns = {
            'os': os, 're': re, 'tempfile': tempfile, 'time': time, 'threading': threading,
            'subprocess': subprocess, 'CONFIG_DIR': str(self.cfg_dir),
            '_get_module_deployment_config': lambda s, k: self.cfg,
            '_module_run': host.module_run,
            '_module_fw_ensure_active': lambda cfg, log_fn=None: (True, host.firewall, ''),
            '_module_fw': lambda cfg, verb, port, proto='tcp', log_fn=None: (True, ''),
            '_fedhub_caddy_source_ip': lambda s: CONSOLE,
            '_caddy_running_config_has': self._caddy_has,
            'load_settings': lambda: self.settings,
            '_startup_converge_mediamtx_remote_hls_road': self._road,
            'print': lambda *a, **k: self.log.append(' '.join(str(x) for x in a)),
        }
        exec(_src(*NAMES), ns)
        self.ns = ns
        if marked:
            (self.cfg_dir / 'mediamtx_remote_hls_via_editor').write_text(HOST + '\n')

    def _caddy_has(self, needle):
        assert needle == f'{HOST}:8888'
        return self.caddy_dials

    def _road(self, after=None):
        self.road_calls.append(after)
        return 'on'

    def closed_mark(self):
        p = self.cfg_dir / 'mediamtx_remote_hls_port_closed'
        return p.read_text().strip() if p.exists() else None

    def start(self):
        """A console start: the video road pass, then (in its own thread, after that one) the
        HLS port pass. A tree without the change has the road pass alone."""
        road = threading.Thread(target=self.ns['_startup_converge_mediamtx_remote_hls_road'])
        road.start()
        fn = self.ns.get('_startup_converge_mediamtx_remote_hls_port')
        if fn is None:
            road.join(30)
            return None
        res = fn(road)
        assert not road.is_alive(), 'the port pass did not wait for the road pass'
        return res

    def port(self, **kw):
        return self.ns['_mediamtx_remote_hls_port'](self.settings, self.cfg, self.log.append, **kw)


@pytest.fixture
def console(tmp_path, host):
    return Console(tmp_path, host)


# ── the proof test ─────────────────────────────────────────────────────────────────────────

def test_console_start_closes_the_hls_port_once_caddy_no_longer_reads_it(console, host):
    """The customer's update: the console starts on the new version, nothing is pressed. The
    host is on the road through the editor and the running Caddy has no upstream on 8888."""
    assert host.allows(8888) == [CONSOLE] and host.bind() == '0.0.0.0:8888'
    console.start()
    assert host.allows(8888) == [], 'the console is still allowed on the HLS port'
    assert host.allows(5080) == [CONSOLE], 'the editor must stay open to the console'
    assert host.bind() == '127.0.0.1:8888', 'MediaMTX still binds HLS to every interface'
    assert console.closed_mark() == HOST
    assert host.restarts() == 0, 'MediaMTX loaded the file by itself: no restart'
    assert any('closed to the console' in ln for ln in console.log)


# ── the order: only after Caddy runs without the direct road ───────────────────────────────

def test_the_port_pass_waits_for_the_road_pass(console, host):
    gate = threading.Event()
    seen = []

    def slow_road(after=None):
        gate.wait(10)
        seen.append(list(host.sent))
        return 'on'

    console.ns['_startup_converge_mediamtx_remote_hls_road'] = slow_road
    t = threading.Timer(0.3, gate.set)
    t.start()
    console.start()
    t.join()
    assert seen == [[]], 'the host was asked to close the port before the road pass ended'
    assert host.allows(8888) == []


@pytest.mark.parametrize('dials', [True, None])
def test_port_stays_open_while_caddy_reads_it_or_cannot_be_asked(tmp_path, host, dials):
    c = Console(tmp_path, host, caddy_dials=dials)
    assert c.port() == ('open' if dials else 'kept')
    assert host.sent == [] and host.allows(8888) == [CONSOLE] and host.bind() == '0.0.0.0:8888'
    assert c.closed_mark() is None


def test_port_stays_as_it_is_for_a_host_not_on_the_road_through_the_editor(tmp_path, host):
    c = Console(tmp_path, host, marked=False)
    assert c.port() == 'kept'
    assert host.sent == [] and host.allows(8888) == [CONSOLE]


def test_firewall_closes_before_the_bind_changes(console, host):
    assert console.port() == 'closed'
    assert host.sent == ['scope-closed', 'bind-127.0.0.1']


def test_a_firewall_that_refuses_keeps_everything(console, host):
    host.env = {'UFW_STUCK': '1', 'FWD_STUCK': '1'}
    assert console.port() == 'kept'
    assert host.sent == ['scope-closed'], 'the bind must not change when the rule did not go'
    assert console.closed_mark() is None and host.bind() == '0.0.0.0:8888'
    assert any('could not be closed' in ln for ln in console.log)


def test_an_unreachable_host_changes_nothing(console, host):
    host.reachable = False
    assert console.port() == 'kept'
    assert console.closed_mark() is None


def test_every_allow_rule_for_the_port_goes_also_an_old_console_address(tmp_path, host):
    host.seed_rules(extra_8888=(OLD_CONSOLE,))
    assert host.allows(8888) == sorted([CONSOLE, OLD_CONSOLE])
    c = Console(tmp_path, host)
    assert c.port() == 'closed'
    assert host.allows(8888) == [] and host.allows(5080) == [CONSOLE]


def test_ufw_keeps_its_deny_rule_for_the_port(tmp_path):
    (tmp_path / 'host').mkdir()
    h = Host(tmp_path / 'host', 'ufw')
    h.seed_rules()
    assert Console(tmp_path, h).port() == 'closed'
    rows = (h.dir / 'ufw.rules').read_text().splitlines()
    assert 'ufw deny 8888/tcp' in rows and 'ufw deny 5080/tcp' in rows
    assert rows.index(f'ufw allow from {CONSOLE} to any port 5080 proto tcp') < rows.index('ufw deny 5080/tcp')


# ── the bind ───────────────────────────────────────────────────────────────────────────────

def test_mediamtx_is_restarted_once_when_it_does_not_load_the_file_by_itself(console, host):
    (host.dir / 'hot').unlink()
    assert console.port() == 'closed'
    assert host.bind() == '127.0.0.1:8888' and host.restarts() == 1
    assert (host.dir / 'listen').read_text().strip() == '127.0.0.1:8888'


def test_a_stopped_mediamtx_is_left_stopped(console, host):
    (host.dir / 'stopped').write_text('')
    assert console.port() == 'closed'
    assert host.bind() == '127.0.0.1:8888' and host.restarts() == 0


def test_a_file_without_the_line_is_said_and_the_firewall_still_closes(console, host):
    host.yml.write_text('hls: yes\n')
    assert console.port() == 'closed'
    assert host.allows(8888) == []
    assert any('still listens on it for every address (noline)' in ln for ln in console.log)


def test_bind_takes_only_the_two_addresses(console, host):
    assert console.ns['_mediamtx_remote_hls_bind'](console.cfg, '0.0.0.0; reboot') == 'fail'
    assert host.sent == []


# ── later console starts ───────────────────────────────────────────────────────────────────

def test_second_start_changes_nothing_and_does_not_open_the_port(console, host):
    console.start()
    host.sent.clear()
    console.log.clear()
    # the firewall check of the next start (it runs before the road pass), then the pass
    state, failed = console.ns['_mediamtx_remote_firewall'](console.settings, console.cfg, console.log.append)
    assert (state, failed) == ('on', [])
    assert host.sent == ['scope-closed'], 'a console start opened the HLS port again'
    assert host.allows(8888) == [] and host.allows(5080) == [CONSOLE]
    assert any('HLS and API closed' in ln for ln in console.log)
    console.start()
    assert host.sent == ['scope-closed', 'bind-127.0.0.1']
    assert host.bind() == '127.0.0.1:8888' and host.restarts() == 0


def test_firewall_check_of_a_host_that_is_not_closed_is_as_before(console, host):
    state, failed = console.ns['_mediamtx_remote_firewall'](console.settings, console.cfg, console.log.append)
    assert (state, failed) == ('on', []) and host.sent == ['scope-open']
    assert host.allows(8888) == [CONSOLE] and host.allows(5080) == [CONSOLE]
    assert any('web editor and HLS open to the console only' in ln for ln in console.log)


def test_a_bind_someone_changed_back_is_set_again(console, host):
    console.start()
    host.yml.write_text(host.yml.read_text().replace('127.0.0.1:8888', '0.0.0.0:8888'))
    console.start()
    assert host.bind() == '127.0.0.1:8888'


# ── the way back ───────────────────────────────────────────────────────────────────────────

def test_port_opens_again_when_caddy_reads_it_again(console, host):
    """Authentik removed: Caddy sends video straight to MediaMTX on the host again."""
    console.start()
    host.sent.clear()
    console.caddy_dials = True
    assert console.port() == 'open'
    assert host.sent == ['bind-0.0.0.0', 'scope-open'], 'bind first, then the rule'
    assert host.allows(8888) == [CONSOLE] and host.bind() == '0.0.0.0:8888'
    assert console.closed_mark() is None


def test_rollback_to_a_release_without_this_opens_the_port_first(console, host, tmp_path):
    console.start()
    host.sent.clear()
    console.ns['_console_release_app_has'] = lambda d, tag, needle: False
    fn = console.ns['_mediamtx_remote_hls_port_before_rollback']
    assert fn(console.settings, str(tmp_path), 'v10.4.6-alpha') == 'opened'
    assert host.allows(8888) == [CONSOLE] and host.bind() == '0.0.0.0:8888'
    assert console.closed_mark() is None


def test_rollback_to_a_release_with_this_changes_nothing(console, host, tmp_path):
    console.start()
    host.sent.clear()
    console.ns['_console_release_app_has'] = lambda d, tag, needle: True
    fn = console.ns['_mediamtx_remote_hls_port_before_rollback']
    assert fn(console.settings, str(tmp_path), 'v10.4.7-alpha') == 'none'
    assert host.sent == [] and console.closed_mark() == HOST


def test_rollback_with_nothing_closed_does_not_talk_to_the_host(console, host, tmp_path):
    fn = console.ns['_mediamtx_remote_hls_port_before_rollback']
    assert fn(console.settings, str(tmp_path), 'v10.4.6-alpha') == 'none'
    assert host.sent == []


def test_release_lookup_reads_the_tag_with_git(tmp_path):
    ns = {'os': os, 're': re, 'subprocess': subprocess}
    exec(_src('_console_release_app_has'), ns)
    has = ns['_console_release_app_has']
    d = tmp_path / 'repo'
    d.mkdir()
    env = {**os.environ, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.org',
           'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@example.org',
           'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}   # the machine's own git settings stay out

    def git(*a):
        subprocess.run(['git', *a], cwd=d, env=env, check=True, capture_output=True)

    git('init', '-q')
    (d / 'app.py').write_text('X = 1\n')
    git('add', 'app.py')
    git('commit', '-qm', 'old')
    git('tag', 'v1')
    (d / 'app.py').write_text("X = 1\n_MEDIAMTX_REMOTE_HLS_CLOSED_FILE = 'f'\n")
    git('commit', '-qam', 'new')
    git('tag', 'v2')
    assert has(str(d), 'v1', '_MEDIAMTX_REMOTE_HLS_CLOSED_FILE') is False
    assert has(str(d), 'v2', '_MEDIAMTX_REMOTE_HLS_CLOSED_FILE') is True
    assert has(str(d), 'v9', '_MEDIAMTX_REMOTE_HLS_CLOSED_FILE') is None
    assert has(str(d), '--upload-pack=x', '_MEDIAMTX_REMOTE_HLS_CLOSED_FILE') is None


# ── where it is called ─────────────────────────────────────────────────────────────────────

def _fn(name):
    return next(ast.get_source_segment(APP, n) for n in TREE.body
                if isinstance(n, ast.FunctionDef) and n.name == name)


def test_console_start_runs_the_port_pass_after_the_firewall_check():
    m = re.search(r'(\w+) = threading\.Thread\(target=_startup_converge_mediamtx_remote_hls_road,\s*'
                  r'args=\(_mtx_remote_fw_t,\)', APP)
    assert m, 'the road pass thread has no name to wait for'
    assert re.search(r'threading\.Thread\(target=_startup_converge_mediamtx_remote_hls_port,\s*'
                     r'args=\(%s,\),\s*daemon=True' % m.group(1), APP), \
        'the console start does not run the HLS port pass after the road pass'


def test_remote_deploy_writes_the_bind_it_closed_and_looks_again_at_the_end():
    dep = _fn('_run_mediamtx_deploy_remote')
    assert 'hlsAddress: {_hls_bind_addr}:8888' in dep and 'hlsAddress: 0.0.0.0:8888' not in dep
    assert "'127.0.0.1' if _mediamtx_remote_hls_closed(deploy_cfg) else '0.0.0.0'" in dep
    caddy, port = dep.index('_caddy_apply_and_verify('), dep.index('_mediamtx_remote_hls_port(settings, cfg, plog)')
    assert caddy < port, 'the port is looked at only after Caddy runs the new site'


def test_console_rollback_opens_the_port_before_the_checkout():
    rb = _fn('console_rollback_api')
    assert rb.index('_mediamtx_remote_hls_port_before_rollback(') < rb.index("['checkout', '--force', prev_tag]")


def test_a_direct_road_to_a_closed_port_opens_it_again():
    gen = _fn('generate_caddyfile')
    i = gen.index('_mtx_direct = _mediamtx_hls_direct(')
    block = gen[i:i + 1400]
    assert re.search(r'if _mtx_direct:\n(?:\s+#[^\n]*\n)*\s+_mtx_dep_cfg = [^\n]+\n'
                     r'\s+if _mediamtx_remote_hls_closed\(_mtx_dep_cfg\):\n'
                     r'\s+_mediamtx_remote_hls_reopen_bg\(settings, _mtx_dep_cfg\)', block)
