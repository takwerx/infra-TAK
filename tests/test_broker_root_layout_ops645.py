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
"""Broker runs from root-owned, verified code (ops #645 W1).

Until W1 the broker unit ran <console repo>/broker/takwerx_broker.py, a file the
console user owns: edit it, restart the broker, and the console user is root.
Now root fetches the code from GitHub itself, installs a commit only when it is on
main, dev or a v* tag and not below the running broker's security level, and the
unit runs that root-owned copy with the system python in isolated mode.

A local bare git repo stands in for GitHub; nothing here needs root or a network.
"""

import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
GIT = shutil.which('git')
pytestmark = pytest.mark.skipif(not GIT, reason='git not installed')


def _broker(name='takwerx_broker_ops645_w1'):
    spec = importlib.util.spec_from_file_location(name, REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()
GOOD = f'BROKER_ROOT_LAYOUT = 1\nBROKER_SECURITY_LEVEL = {B.BROKER_SECURITY_LEVEL}\nprint("broker")\n'


def _g(cwd, *args):
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.invalid',
               GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.invalid')
    r = subprocess.run([GIT, *args], cwd=cwd, capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def _commit(work, text, msg):
    (work / 'broker').mkdir(exist_ok=True)
    (work / 'selinux').mkdir(exist_ok=True)
    (work / 'broker' / 'takwerx_broker.py').write_text(text)
    (work / 'selinux' / 'takwerx_console.te').write_text('module takwerx_console 1.0;\n')
    (work / 'app.py').write_text('# console, not archived\n')
    _g(work, 'add', '-A')
    _g(work, 'commit', '-q', '-m', msg)
    return _g(work, 'rev-parse', 'HEAD')


@pytest.fixture
def gh(tmp_path, monkeypatch):
    """A fake GitHub: dev has a good commit, main a good tagged release, a side
    branch a good commit that is on no allowed ref, plus an older-level commit."""
    work = tmp_path / 'work'
    work.mkdir()
    _g(work, 'init', '-q', '-b', 'main')
    c = types.SimpleNamespace()
    c.pre_w1 = _commit(work, 'print("old broker, no layout marker")\n', 'pre-W1')
    c.release = _commit(work, GOOD, 'release')
    _g(work, 'tag', 'v10.4.0')
    _g(work, 'checkout', '-q', '-b', 'dev')
    c.dev = _commit(work, GOOD + '# dev\n', 'dev work')
    _g(work, 'checkout', '-q', '-b', 'side')
    c.side = _commit(work, GOOD + '# unmerged\n', 'unmerged branch')
    _g(work, 'checkout', '-q', 'dev')
    c.low = _commit(work, f'BROKER_ROOT_LAYOUT = 1\nBROKER_SECURITY_LEVEL = {B.BROKER_SECURITY_LEVEL - 1}\n',
                    'low level')
    c.dev_head = _commit(work, GOOD + '# dev head\n', 'dev head')
    remote = tmp_path / 'github.git'
    _g(tmp_path, 'clone', '-q', '--bare', str(work), str(remote))
    _g(remote, 'config', 'uploadpack.allowFilter', 'true')
    _g(remote, 'config', 'uploadpack.allowAnySHA1InWant', 'true')
    _g(remote, 'branch', '-D', 'side')
    c.local_only = _commit(work, GOOD + '# local edit\n', 'local only')   # never pushed
    monkeypatch.setattr(B, 'BROKER_SRC_URL', 'file://' + str(remote))
    monkeypatch.setattr(B, 'ROOT_CODE_DIR', str(tmp_path / 'lib' / 'infratak-broker'))
    monkeypatch.setattr(B, 'ROOT_CODE_CURRENT', str(tmp_path / 'lib' / 'infratak-broker' / 'current'))
    monkeypatch.setattr(B, 'ROOT_SRC_GIT', str(tmp_path / 'state' / 'src.git'))
    monkeypatch.setattr(B, 'ROOT_CONF_DIR', str(tmp_path / 'etc' / 'infratak'))
    monkeypatch.setattr(B, 'ROOT_CONF', str(tmp_path / 'etc' / 'infratak' / 'broker.conf'))
    monkeypatch.setattr(B, 'BROKER_TRUSTED_PATH', os.path.dirname(GIT) + ':/usr/bin:/bin')
    monkeypatch.setattr(B.os, 'chown', lambda *a, **k: None)
    c.work, c.remote, c.tmp = work, remote, tmp_path
    return c


# --- install: only verified commits -----------------------------------------------------

@pytest.mark.parametrize('which', ['dev', 'release', 'dev_head'])
def test_commit_on_main_dev_or_tag_is_installed(gh, which):
    commit = getattr(gh, which)
    dest = B._root_install(commit)
    assert dest == os.path.join(B.ROOT_CODE_DIR, commit)
    assert os.readlink(B.ROOT_CODE_CURRENT) == commit
    assert (pathlib.Path(dest) / 'broker' / 'takwerx_broker.py').read_text().startswith('BROKER_ROOT_LAYOUT = 1')
    assert (pathlib.Path(dest) / 'selinux' / 'takwerx_console.te').exists()
    assert not (pathlib.Path(dest) / 'app.py').exists()          # only broker/ + selinux/
    for root, dirs, files in os.walk(dest):
        for n in dirs:
            assert os.stat(os.path.join(root, n)).st_mode & 0o777 == 0o755
        for n in files:
            assert os.stat(os.path.join(root, n)).st_mode & 0o777 == 0o644


@pytest.mark.parametrize('which,why', [
    ('side', 'not on main, dev or a release tag'),
    ('local_only', 'is not on GitHub'),
    ('low', f'security level {B.BROKER_SECURITY_LEVEL - 1}, below'),
    ('pre_w1', 'predates the root-owned broker layout'),
])
def test_unverified_commit_is_refused_and_nothing_changes(gh, which, why):
    B._root_install(gh.dev)                                   # a good current install
    with pytest.raises(B.Denied, match=why):
        B._root_install(getattr(gh, which))
    assert os.readlink(B.ROOT_CODE_CURRENT) == gh.dev          # current untouched
    assert sorted(n for n in os.listdir(B.ROOT_CODE_DIR) if not n.startswith('.')) == \
        sorted([gh.dev, 'current'])


@pytest.mark.parametrize('commit', ['HEAD', 'dev', 'abc123', '../../etc', '-x', 'A' * 40, None, 7])
def test_commit_must_be_a_full_id(gh, commit):
    with pytest.raises(B.Denied, match='full 40-character'):
        B._src_verify(commit)


def test_fetch_ignores_a_changed_remote_url(gh):
    """The mirror's remote URL is the broker constant on every fetch: a console that
    could reach the mirror config still cannot point it elsewhere."""
    B._src_fetch()
    subprocess.run([GIT, '--git-dir', B.ROOT_SRC_GIT, 'config', 'remote.origin.url',
                    'file:///nonexistent'], check=True)
    B._src_fetch()
    assert B._src_git(['config', 'remote.origin.url']).stdout.strip() == B.BROKER_SRC_URL


def test_old_installs_are_pruned_but_current_kept(gh):
    for c in (gh.release, gh.dev, gh.dev_head):
        B._root_install(c)
    B._root_install(gh.dev)
    left = {n for n in os.listdir(B.ROOT_CODE_DIR) if re.match(r'^[0-9a-f]{40}$', n)}
    assert gh.dev in left and len(left) <= B._ROOT_KEEP
    assert os.readlink(B.ROOT_CODE_CURRENT) == gh.dev


# --- unit, config, deny-list ------------------------------------------------------------

UNIT = """[Unit]
Description=infra-TAK privileged broker (least-privilege console mediation)

[Service]
Type=simple
SELinuxContext=system_u:system_r:unconfined_service_t:s0
ExecStart=/opt/infratak/.venv/bin/python3 /opt/infratak/broker/takwerx_broker.py serve
Restart=always
Environment=TAKWERX_BROKER_ENFORCE=1

[Install]
WantedBy=multi-user.target
"""


def test_unit_points_at_root_code_with_system_python(tmp_path):
    u = tmp_path / 'takwerx-broker.service'
    u.write_text(UNIT)
    calls = []
    assert B._unit_point_at_root(str(u), run=lambda a, **k: calls.append(a)) is True
    text = u.read_text()
    assert ('ExecStart=/usr/bin/python3 -I /usr/local/lib/infratak-broker/current/'
            'broker/takwerx_broker.py serve\n') in text
    assert '.venv' not in text and '/opt/infratak/broker' not in text
    assert 'Environment=TAKWERX_BROKER_ENFORCE=1' in text and 'SELinuxContext=' in text
    assert calls and calls[0][-1] == 'daemon-reload'
    assert B._unit_point_at_root(str(u), run=lambda a, **k: calls.append(a)) is False


def test_console_repo_dir_comes_from_root_owned_conf(tmp_path, monkeypatch):
    conf = tmp_path / 'broker.conf'
    conf.write_text('console_dir=/opt/infratak\n')
    os.chmod(conf, 0o644)
    monkeypatch.setattr(B, 'RUNNING_FROM_ROOT', True)
    monkeypatch.setattr(B, 'ROOT_CONF', str(conf))
    uid = os.getuid()
    monkeypatch.setattr(B.os, 'lstat', lambda p, _l=os.lstat: types.SimpleNamespace(
        st_mode=_l(p).st_mode, st_uid=0 if uid else _l(p).st_uid))
    assert B._console_repo_dir() == '/opt/infratak'
    conf.write_text('console_dir=../../etc\n')
    assert B._console_repo_dir() == '/nonexistent'


def test_conf_not_owned_by_root_or_writable_is_ignored(tmp_path):
    conf = tmp_path / 'broker.conf'
    conf.write_text('console_dir=/opt/infratak\n')
    os.chmod(conf, 0o666)
    assert B._read_root_conf(str(conf)) == {}


@pytest.mark.parametrize('path', [
    '/usr/local/lib/infratak-broker', '/usr/local/lib/infratak-broker/current',
    '/usr/local/lib/infratak-broker/0123456789012345678901234567890123456789/broker/takwerx_broker.py',
    '/etc/infratak', '/etc/infratak/broker.conf', '/var/lib/takwerx-broker',
    '/var/lib/takwerx-broker/src.git/config',
])
def test_root_code_and_conf_are_not_writable(path):
    with pytest.raises(B.Denied):
        B._path_allowed(path)


@pytest.mark.parametrize('argv', [
    ['ln', '-sfn', '/home/takwerx/evil', '/usr/local/lib/infratak-broker/current'],
    ['tee', '/etc/infratak/broker.conf'],
    ['rm', '-rf', '/usr/local/lib/infratak-broker'],
    ['cp', '/home/takwerx/x.py', '/usr/local/lib/infratak-broker/current/broker/takwerx_broker.py'],
    ['git', '--git-dir=/var/lib/takwerx-broker/src.git', 'config', 'remote.origin.url', 'x'],
])
def test_console_cannot_touch_root_code_by_command(argv):
    with pytest.raises(B.Denied):
        B.check_exec(argv, '/home/takwerx')


# --- the op, ping, first move ------------------------------------------------------------

class _Audit:
    def __init__(self):
        self.lines = []

    def info(self, m):
        self.lines.append(json.loads(m))
    warning = info


@pytest.mark.parametrize('req', [
    {'op': 'broker_update'},
    {'op': 'broker_update', 'commit': 'HEAD'},
    {'op': 'broker_update', 'commit': 'a' * 40, 'url': 'https://evil.example/x.git'},
    {'op': 'broker_update', 'commit': 'a' * 40, 'path': '/home/takwerx/infra-TAK'},
])
def test_broker_update_bad_request_is_denied_in_both_modes(monkeypatch, req):
    called = []
    monkeypatch.setattr(B, '_do_broker_update', lambda r: called.append(r))
    monkeypatch.setattr(B, 'AUDIT', _Audit())
    for enforce in (False, True):
        monkeypatch.setattr(B, 'ENFORCE', enforce)
        r = B._dispatch(dict(req), (1, 999, 999))
        assert r['ok'] is False and r['code'] == 'DENIED'
    assert not called


def test_broker_update_installs_points_unit_and_restarts(gh, monkeypatch, tmp_path):
    u = tmp_path / 'unit'
    u.write_text(UNIT)
    monkeypatch.setattr(B, 'BROKER_UNIT', str(u))
    monkeypatch.setattr(B, '_unit_point_at_root',
                        lambda unit_path=str(u), run=None, _f=B._unit_point_at_root:
                        _f(unit_path, run=lambda *a, **k: None))
    monkeypatch.setattr(B, 'CONSOLE_REPO_DIR', '/opt/infratak')
    restarts = []
    r = B._do_broker_update({'commit': gh.dev}, restart=lambda: restarts.append(1))
    assert r == {'ok': True, 'installed_commit': gh.dev, 'changed': True, 'restarting': True}
    assert restarts == [1]
    assert B.ROOT_EXEC_START in u.read_text()
    assert 'console_dir=/opt/infratak' in pathlib.Path(B.ROOT_CONF).read_text()
    # a refused commit: no restart, the unit and current link stay
    r = B._do_broker_update({'commit': gh.side}, restart=lambda: restarts.append(2))
    assert r['ok'] is False and 'not on main, dev' in r['error'] and restarts == [1]
    assert os.readlink(B.ROOT_CODE_CURRENT) == gh.dev


def test_ping_reports_installed_commit():
    r = B._dispatch({'op': 'ping'}, (1, 0, 0)) if B.AUDIT is None else None
    r = r or B._dispatch({'op': 'ping'}, (1, 0, 0))
    assert 'installed_commit' in r and r['installed_commit'] == ''      # repo path here
    assert r['security_level'] == B.BROKER_SECURITY_LEVEL
    assert r['root_install']['state'] in ('not-started', 'pending', 'running', 'installed')


def test_repo_head_commit_reads_files_only(gh):
    head = B._repo_head_commit(str(gh.work))
    assert head == gh.local_only
    _g(gh.work, 'pack-refs', '--all')
    assert B._repo_head_commit(str(gh.work)) == gh.local_only
    _g(gh.work, 'checkout', '-q', '--detach', gh.dev)
    assert B._repo_head_commit(str(gh.work)) == gh.dev
    assert B._repo_head_commit(str(gh.tmp / 'nothing')) == ''


def test_repo_head_commit_refuses_links_and_fifos(gh, tmp_path):
    """Security review hygiene: a ref that is a FIFO must not hang the broker, a ref
    dir linked out of .git and a .git that is itself a link are not read."""
    gd = gh.work / '.git'
    _g(gh.work, 'checkout', '-q', 'dev')
    head_ref = gd / 'refs' / 'heads' / 'dev'
    head_ref.unlink()
    (gd / 'packed-refs').unlink(missing_ok=True)
    os.mkfifo(head_ref)                                   # open would block without O_NONBLOCK
    assert B._repo_head_commit(str(gh.work)) == ''
    head_ref.unlink()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'dev').write_text(gh.dev + '\n')
    shutil.rmtree(gd / 'refs' / 'heads')
    (gd / 'refs' / 'heads').symlink_to(outside)           # parent dir leaves .git
    assert B._repo_head_commit(str(gh.work)) == ''
    linked = tmp_path / 'linked'
    linked.mkdir()
    (linked / '.git').symlink_to(gd)                      # .git itself is a link
    assert B._repo_head_commit(str(linked)) == ''


def test_first_move_installs_the_console_commit(gh, monkeypatch, tmp_path):
    _g(gh.work, 'checkout', '-q', '--detach', gh.dev_head)
    u = tmp_path / 'unit'
    u.write_text(UNIT)
    monkeypatch.setattr(B, 'CONSOLE_REPO_DIR', str(gh.work))
    monkeypatch.setattr(B.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(B, '_unit_point_at_root',
                        lambda _f=B._unit_point_at_root: _f(str(u), run=lambda *a, **k: None))
    logs, restarts = [], []
    assert B._root_move_first(restart=lambda: restarts.append(1),
                              log=lambda v, s: logs.append((v, s))) is True
    assert os.readlink(B.ROOT_CODE_CURRENT) == gh.dev_head and restarts == [1]
    assert B.ROOT_EXEC_START in u.read_text()
    assert B.ROOT_MOVE_STATE['state'] == 'installed'


def test_first_move_from_an_unpushed_commit_stays_put_and_says_why(gh, monkeypatch, tmp_path):
    _g(gh.work, 'checkout', '-q', '--detach', gh.local_only)
    u = tmp_path / 'unit'
    u.write_text(UNIT)
    monkeypatch.setattr(B, 'CONSOLE_REPO_DIR', str(gh.work))
    monkeypatch.setattr(B.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(B, '_unit_point_at_root',
                        lambda _f=B._unit_point_at_root: _f(str(u), run=lambda *a, **k: None))
    logs, restarts = [], []
    assert B._root_move_first(restart=lambda: restarts.append(1),
                              log=lambda v, s: logs.append((v, s))) is False
    assert restarts == [] and u.read_text() == UNIT
    assert B.ROOT_MOVE_STATE['state'] == 'pending'
    assert 'is not on GitHub' in B.ROOT_MOVE_STATE['reason']


# --- console side -----------------------------------------------------------------------

def _app_func(name):
    src = (REPO / 'app.py').read_text()
    m = re.search(r'^def %s\(.*?(?=^def |^try:|^# )' % name, src, re.S | re.M)
    assert m, name
    return m.group(0)


def test_console_converges_by_commit_not_by_file_hash():
    """A broker on the root layout: a local edit of the repo file must not trigger a
    restart; a different checked-out commit asks the broker to install that commit."""
    ns = {'json': json, 'subprocess': types.SimpleNamespace(run=None), '_sys': types.SimpleNamespace(executable='py'),
          '_BROKER_SCRIPT': '/opt/infratak/broker/takwerx_broker.py', 're': re}
    exec(_app_func('_broker_converge_root_commit'), ns)
    f = ns['_broker_converge_root_commit']
    sent = []

    def run(argv, **k):
        sent.append(argv)
        return types.SimpleNamespace(returncode=0, stdout=json.dumps(
            {'ok': True, 'changed': True, 'installed_commit': argv[-1]}))
    ns['subprocess'].run = run
    have, want = 'a' * 40, 'b' * 40
    logs = []
    # same commit (even if the repo FILE was edited): nothing happens
    assert f({'installed_commit': have}, None, logs.append, sleep=lambda s: None, head=have) is False
    assert sent == []
    pings = iter([{'pong': True, 'installed_commit': want}])
    assert f({'installed_commit': have}, lambda timeout=20: next(pings), logs.append,
             sleep=lambda s: None, head=want) is True
    assert sent == [['py', '/opt/infratak/broker/takwerx_broker.py', 'update', want]]


def test_console_routes_root_layout_to_commit_converge():
    body = _app_func('_broker_converge_running_source')
    assert "if (resp.get('installed_commit') or '').strip():" in body
    assert body.index('_broker_converge_root_commit') < body.index("have = (resp.get('src_sha')")


def test_console_and_start_sh_keep_the_root_exec_start():
    app = (REPO / 'app.py').read_text()
    assert "' /usr/local/lib/infratak-broker/current/' in _ln" in app
    assert "f'{exec_line}'" in app
    sh = (REPO / 'start.sh').read_text()
    assert 'ExecStart=$broker_exec' in sh
    assert 'broker_exec="/usr/bin/python3 -I $root_broker serve"' in sh
    assert B.ROOT_EXEC_START == ('ExecStart=/usr/bin/python3 -I /usr/local/lib/infratak-broker/'
                                 'current/broker/takwerx_broker.py serve')


def test_guarddog_templates_are_installed_with_the_broker(gh):
    """ops #645 W2 part 2a: root renders Guard Dog scripts from scripts/guarddog/ in
    the tree it installed, so the install carries that dir (and nothing else of
    scripts/)."""
    (gh.work / 'scripts' / 'guarddog').mkdir(parents=True)
    (gh.work / 'scripts' / 'guarddog' / 'tak-disk-watch.sh').write_text(
        '#!/bin/bash\nALERT="ALERT_EMAIL_PLACEHOLDER"\n')
    (gh.work / 'scripts' / 'other.sh').write_text('echo not archived\n')
    _g(gh.work, 'checkout', '-q', 'dev')
    c = _commit(gh.work, GOOD + '# with templates\n', 'templates')
    _g(gh.work, 'push', '-q', str(gh.remote), 'dev')
    dest = pathlib.Path(B._root_install(c))
    assert (dest / 'scripts' / 'guarddog' / 'tak-disk-watch.sh').read_text().startswith('#!/bin/bash')
    assert not (dest / 'scripts' / 'other.sh').exists()
    assert os.stat(dest / 'scripts' / 'guarddog' / 'tak-disk-watch.sh').st_mode & 0o777 == 0o644
