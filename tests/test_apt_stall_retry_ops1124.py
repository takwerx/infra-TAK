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
"""ops #1124 — three fresh Ubuntu 22.04 boxes stopped at "apt-get install ... timed out after
300 seconds" because the download host answered but then sent nothing. The console ran the apt
step once and failed. Now an apt step that times out is run once more; on Ubuntu the second try
runs on a host that delivers a real package, and the operator's apt source files are put back
afterwards.

The helpers are cut out of app.py and run against fakes (no network, no root): the code under
test is the shipped text.
"""

import ast
import gzip
import pathlib
import re
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
from urllib.parse import urlparse

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

STALLED = 'us-east-2.ec2.archive.ubuntu.com'


def _hosts(text):
    """The host names of every http(s) URL in a text, parsed (never a substring match on a URL)."""
    return {urlparse(u).hostname for u in re.findall(r'https?://[^\s\]\'",]+', text)}
JAMMY_LIST = (
    f'deb http://{STALLED}/ubuntu jammy main restricted\n'
    f'deb http://{STALLED}/ubuntu jammy-updates main restricted\n'
    'deb http://security.ubuntu.com/ubuntu jammy-security main restricted\n'
)
OTHER_LIST = 'deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt jammy-pgdg main\n'

PACKAGE = 'pool/main/o/openjdk-17/openjdk-17-jre-headless_17.0.9_amd64.deb'
PACKAGES_GZ = gzip.compress((
    'Package: tiny\nFilename: pool/main/t/tiny/tiny_1_amd64.deb\nSize: 1000\n\n'
    f'Package: openjdk-17-jre-headless\nFilename: {PACKAGE}\nSize: 5000000\n').encode())


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


NAMES = (
    '_APT_STALL_HOSTS', '_APT_MIRROR_MIN_KBS', '_APT_MIRROR_PROBE_S', '_APT_UBUNTU_HOST_RE',
    '_APT_PROBE_FILE_RE', '_apt_current_host', '_apt_rewrite_hosts', '_apt_probe_file',
    '_apt_probe_kbs', '_apt_mirror_ok', '_apt_pick_mirror', '_apt_switch_ubuntu_hosts',
    '_apt_restore_sources', '_apt_stalled', '_APT_TRANSIENT_RE', '_apt_failure_is_transient', '_apt_broker_env', '_apt_chain_run', '_apt_retry_stalled', '_pkg_install',
)


class Box:
    """A fake box: apt source files in a scratch folder, a fake curl, a fake apt-get."""

    def __init__(self, installs, speeds=None, release_ok=None, arch='amd64', ubuntu=True, sources=None):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix='ops1124-'))
        self.src = self.dir / 'sources.list'
        self.src.write_text(JAMMY_LIST if sources is None else sources)
        self.other = self.dir / 'pgdg.list'
        self.other.write_text(OTHER_LIST)
        self.installs = list(installs)       # outcomes of the apt-get install calls, in turn
        self.speeds = speeds or {}           # host -> bytes per second a real package comes at
        self.release_ok = release_ok or {}   # (host, pocket) -> False when that Release is missing
        self.events = []                     # ordered record of what ran
        self.seen_sources = []               # the sources text at each install call
        self.envs = []                       # the env of each apt call
        ns = {
            're': re, 'os': __import__('os'), 'shutil': shutil, 'tempfile': tempfile,
            '_pkg_mgr': lambda: 'apt', '_sudo_wrap': lambda c: list(c),
            '_apt_codename': lambda: 'jammy', '_host_arch': lambda: arch,
            '_apt_is_ubuntu': lambda: ubuntu,
            '_apt_ubuntu_source_files': lambda: [str(self.src), str(self.other)],
            '_apt_wait_for_lock': lambda max_wait=300, log_fn=None: self.events.append('wait-lock') or True,
            '_write_priv': lambda path, content, **kw: pathlib.Path(path).write_text(content),
            '_run_priv_chain': self._chain,
            'subprocess': SimpleNamespace(run=self._run, CompletedProcess=subprocess.CompletedProcess,
                                          TimeoutExpired=subprocess.TimeoutExpired),
        }
        for n in NAMES:
            exec(_segment(n), ns)
        self.ns = ns

    def _chain(self, cmds, mode='and', timeout=120, **kw):
        self.envs.append(kw.get('env'))
        for c in cmds:
            self.events.append('chain:' + ' '.join(c[:2]))
        return subprocess.CompletedProcess(cmds, 0, '', '')

    def _run(self, argv, **kw):
        if argv[0] == 'curl':
            return self._curl(argv)
        assert argv[:3] == ['apt-get', 'install', '-y'], argv
        self.events.append('install')
        self.envs.append(kw.get('env'))
        self.seen_sources.append(self.src.read_text())
        out = self.installs.pop(0) if len(self.installs) > 1 else self.installs[0]
        if out == 'timeout':
            raise subprocess.TimeoutExpired(argv, kw.get('timeout', 0))
        rc, err = out
        return subprocess.CompletedProcess(argv, rc, '', err)

    def _curl(self, argv):
        url = argv[-1]
        host = url.split('/')[2]
        m = re.search(r'/dists/([a-z-]+)/Release$', url)
        if m:
            ok = self.release_ok.get((host, m.group(1)), True)
            return subprocess.CompletedProcess(argv, 0 if ok else 22, '', '')
        out = argv[argv.index('-o') + 1]
        if url.endswith('Packages.gz'):
            pathlib.Path(out).write_bytes(PACKAGES_GZ)
            return subprocess.CompletedProcess(argv, 0, '1000000', '')
        assert url.endswith(PACKAGE), url
        return subprocess.CompletedProcess(argv, 0, str(self.speeds.get(host, 0)), '')

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def _install(box, logs=None):
    return box.ns['_pkg_install'](['wget', 'ffmpeg'], log_fn=(logs.append if logs is not None else None),
                                  timeout=300)


# ---- the proof test: a stalled apt step fails once, then passes on the retry -------------------

def test_stalled_apt_step_is_run_again_and_passes():
    box = Box(installs=['timeout', (0, '')], speeds={'us.archive.ubuntu.com': 20_000_000})
    try:
        ok, out = _install(box)
        assert ok is True, out
        assert box.events.count('install') == 2
    finally:
        box.close()


def test_second_try_runs_on_a_host_that_delivers_and_sources_are_put_back():
    box = Box(installs=['timeout', (0, '')], speeds={'us.archive.ubuntu.com': 20_000_000})
    try:
        ok, _ = _install(box)
        assert ok
        first, second = box.seen_sources
        assert first == JAMMY_LIST                         # try 1: the box's own hosts
        assert STALLED not in second and 'security.ubuntu.com' not in second
        assert second.count('http://us.archive.ubuntu.com/ubuntu ') == 3   # try 2: all three lines moved
        assert box.src.read_text() == JAMMY_LIST           # restored for the operator
        assert box.other.read_text() == OTHER_LIST         # third-party repo never touched
        # the lists are refreshed after the swap and again after the restore
        assert box.events.count('chain:apt-get update') == 2
    finally:
        box.close()


def test_a_host_that_answers_but_delivers_nothing_is_skipped():
    # us.archive answers the Release files and then gives 0 KB/s, like the AWS mirror on Nov 23
    box = Box(installs=['timeout', (0, '')],
              speeds={'us.archive.ubuntu.com': 0, 'mirrors.edge.kernel.org': 7_000_000})
    try:
        ok, _ = _install(box)
        assert ok
        assert 'http://mirrors.edge.kernel.org/ubuntu ' in box.seen_sources[1]
        assert 'us.archive.ubuntu.com' not in _hosts(box.seen_sources[1])
    finally:
        box.close()


def test_a_host_without_the_security_pocket_is_skipped():
    box = Box(installs=['timeout', (0, '')],
              speeds={'us.archive.ubuntu.com': 20_000_000, 'mirrors.edge.kernel.org': 7_000_000},
              release_ok={('us.archive.ubuntu.com', 'jammy-security'): False})
    try:
        _install(box)
        assert 'mirrors.edge.kernel.org' in _hosts(box.seen_sources[1])
    finally:
        box.close()


def test_when_no_host_delivers_the_second_try_uses_the_boxs_own_host():
    box = Box(installs=['timeout', (0, '')], speeds={})
    logs = []
    try:
        ok, _ = _install(box, logs)
        assert ok
        assert box.seen_sources[1] == JAMMY_LIST
        assert box.events.count('chain:apt-get update') == 0   # nothing changed, nothing to refresh
        assert any('own host' in m for m in logs), logs
    finally:
        box.close()


def test_failed_second_try_names_both_tries_and_restores_sources():
    box = Box(installs=['timeout', (100, 'E: Unable to fetch some archives')],
              speeds={'us.archive.ubuntu.com': 20_000_000})
    logs = []
    try:
        ok, out = _install(box, logs)
        assert ok is False
        assert 'first try stalled or timed out' in out and 'us.archive.ubuntu.com' in out.split()   # the host as a whole word
        assert box.src.read_text() == JAMMY_LIST
    finally:
        box.close()


def test_apt_giving_up_on_a_silent_host_itself_is_retried_too():
    # apt's own 120 s no-data limit usually fires before the console's step limit: rc 100, not a timeout
    err = 'E: Failed to fetch http://us-east-2.ec2.archive.ubuntu.com/ubuntu/pool/x.deb  Connection timed out [IP: 3.1.2.3 80]'
    box = Box(installs=[(100, err), (0, '')], speeds={'us.archive.ubuntu.com': 20_000_000})
    try:
        ok, _ = _install(box)
        assert ok and box.events.count('install') == 2
        assert 'us.archive.ubuntu.com' in _hosts(box.seen_sources[1])
    finally:
        box.close()


def test_apt_steps_ask_the_broker_to_stop_apt_before_the_console_gives_up():
    # box test, ops #1124: the console only killed its own brokerctl at the limit, the root apt-get kept the
    # dpkg lock for minutes and the second try died with "Could not get lock". The broker kills apt-get at
    # TAKWERX_BROKER_TIMEOUT, so it must be set, and below the console's own limit.
    box = Box(installs=[(0, '')])
    try:
        _install(box)                                           # timeout=300
        box.ns['_apt_chain_run']([['apt-get', 'update', '-qq']], 300)
        box.ns['_apt_chain_run']([['apt-get', 'update', '-qq']], 20, env={'X': '1'})
        got = [e['TAKWERX_BROKER_TIMEOUT'] for e in box.envs]
        assert got == ['290', '290', '30'], got
        assert box.envs[2]['X'] == '1'                          # a caller's env is kept
    finally:
        box.close()


def test_the_brokers_own_timeout_message_is_a_stall_too():
    # seen on the box: the broker kills apt-get at the deadline and brokerctl prints this with exit code 126
    box = Box(installs=[(126, 'takwerx_broker: TIMEOUT: command timed out'), (0, '')],
              speeds={'us.archive.ubuntu.com': 20_000_000})
    try:
        ok, _ = _install(box)
        assert ok and box.events.count('install') == 2
    finally:
        box.close()


def test_a_real_apt_error_is_not_retried():
    box = Box(installs=[(100, 'E: Unable to locate package ffmpeg')])
    try:
        ok, out = _install(box)
        assert ok is False and 'Unable to locate package' in out
        assert box.events.count('install') == 1
    finally:
        box.close()


def test_a_step_that_works_first_time_is_not_touched():
    box = Box(installs=[(0, '')], speeds={'us.archive.ubuntu.com': 20_000_000})
    try:
        ok, _ = _install(box)
        assert ok and box.events == ['install']
        assert box.src.read_text() == JAMMY_LIST
    finally:
        box.close()


def test_a_box_that_is_not_ubuntu_gets_the_retry_but_no_host_switch():
    box = Box(installs=['timeout', (0, '')], ubuntu=False, speeds={'us.archive.ubuntu.com': 20_000_000})
    try:
        ok, _ = _install(box)
        assert ok and box.events.count('install') == 2
        assert box.seen_sources == [JAMMY_LIST, JAMMY_LIST]
    finally:
        box.close()


def test_arm_box_uses_ports_ubuntu_com_with_the_ubuntu_ports_path():
    ports = ('deb http://us-east-2.ec2.ports.ubuntu.com/ubuntu-ports jammy main\n'
             'deb http://ports.ubuntu.com/ubuntu-ports jammy-security main\n')
    box = Box(installs=['timeout', (0, '')], arch='arm64', sources=ports,
              speeds={'ports.ubuntu.com': 9_000_000})
    try:
        ok, _ = _install(box)
        assert ok
        assert box.seen_sources[1].count('http://ports.ubuntu.com/ubuntu-ports ') == 2
        assert box.src.read_text() == ports
    finally:
        box.close()


# ---- the rewrite and the probe on their own ---------------------------------------------------

def test_rewrite_moves_archive_and_security_hosts_only():
    box = Box(installs=[(0, '')])
    try:
        rw = box.ns['_apt_rewrite_hosts']
        out = rw(JAMMY_LIST + OTHER_LIST, 'mirrors.edge.kernel.org', 'ubuntu')
        assert STALLED not in out and 'security.ubuntu.com' not in out
        assert out.endswith(OTHER_LIST)
        deb822 = 'Types: deb\nURIs: http://archive.ubuntu.com/ubuntu\nSuites: jammy\n'
        assert 'URIs: http://mirrors.edge.kernel.org/ubuntu\n' in rw(deb822, 'mirrors.edge.kernel.org', 'ubuntu')
    finally:
        box.close()


def test_probe_rejects_a_host_that_gives_zero_kbs_and_accepts_a_fast_one():
    box = Box(installs=[(0, '')], speeds={'slow.example': 0, 'fast.example': 5_000_000, 'edge.example': 50_000})
    try:
        ok = box.ns['_apt_mirror_ok']
        assert ok('slow.example', 'ubuntu', 'jammy', 'amd64') is False
        assert ok('edge.example', 'ubuntu', 'jammy', 'amd64') is False      # 48 KB/s is under 100
        assert ok('fast.example', 'ubuntu', 'jammy', 'amd64') is True
    finally:
        box.close()


def test_probe_file_choice_ignores_tiny_packages_and_odd_paths():
    box = Box(installs=[(0, '')])
    try:
        p = pathlib.Path(box.dir) / 'p.gz'
        p.write_bytes(PACKAGES_GZ)
        assert box.ns['_apt_probe_file'](str(p)) == PACKAGE
        p.write_bytes(gzip.compress(b'Package: x\nFilename: ../../etc/passwd\nSize: 5000000\n'))
        assert box.ns['_apt_probe_file'](str(p)) == ''
    finally:
        box.close()


# ---- the callers use it ------------------------------------------------------------------------

def test_mediamtx_deps_step_and_caddy_install_use_the_retry():
    mtx = APP[APP.index("wait_for_apt_lock(plog, mediamtx_deploy_log)"):]
    mtx = mtx[:mtx.index("plog(\"✓ Dependencies installed")]
    assert '_apt_retry_stalled(' in mtx and "'python3-pip']" in mtx
    assert "_apt_retry_stalled(_once, log_fn)" in _segment('_apt_run_waiting')
    assert '_apt_retry_stalled(_apt_once, log_fn)' in _segment('_pkg_install')
