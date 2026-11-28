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
"""ops #1328: every path that can start the WebODM 4.x images has the 9.5 → 18 safeguards.

Update had the room check, the dump and the restore (ops #579). Deploy, Reapply and the remote
deploy wrote the 4.x compose and ran `up -d` with none of them, so a 3.x box that pressed Reapply
had its database upgraded one way with no dump (box result in ops #1311: a Reapply with 110 MB
free left WebODM down and the log said "deployed successfully"). The compose was also written
before the pull, so a console that died in the pull left 4.x over 9.5 data. And a database
version outside {9.5, 18} counted as "already 18".

One test group per path: Update, local Deploy/Reapply, remote Deploy. Each fails on the code
before the fix (no dump, compose written first, no refusal).
"""

import ast
import os
import pathlib
import re
import shlex
import sys
import time
import types
import urllib.request

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import test_webodm_v4_upgrade_ops579 as wo579  # noqa: E402  (the box fake and the loader)

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
OLD = wo579.OLD
HOME = '/home/takwerx'
PENDING = f'{HOME}/webodm/docker-compose.pending.yml'

DEPLOY_WANT = wo579.WANT | {
    '_run_webodm_deploy', '_run_webodm_deploy_remote', 'WEBODM_DOCKER_COMPOSE', 'WEBODM_LOCAL_SETTINGS_STUB',
    'WEBODM_OVERLAY_REPO', 'WEBODM_OVERLAY_REF', 'WEBODM_OVERLAY_SHA', '_webodm_deploy_log', 'ODM_MAX_CORES',
}


def _load(want):
    ns = {'re': re, 'os': os, 'shlex': shlex, 'tempfile': __import__('tempfile'),
          'time': types.SimpleNamespace(time=lambda: 0, sleep=lambda s: None,
                                        strftime=lambda f: '20261109-060000')}
    for node in TREE.body:
        names = ({t.id for t in node.targets if isinstance(t, ast.Name)} if isinstance(node, ast.Assign)
                 else {node.name} if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else set())
        if names & want:
            exec(compile(ast.Module([node], []), 'app.py', 'exec'), ns)
    ticks = iter(range(0, 10 ** 6, 400))
    ns['time'].time = lambda: next(ticks)
    return ns


def _common_stubs(ns, box):
    status = {'running': True, 'complete': False, 'error': False, 'log': []}
    ns.update({
        '_webodm_deploy_status': status,
        '_sudo_wrap': lambda a: a,
        '_webodm_compose': box.compose_cmd,
        '_write_priv': box.write,
        '_read_priv': lambda p: box.compose,
        '_chmod_priv': lambda *a, **k: None,
        '_webodm_odm_limits': lambda cores, cfg: (4, 8),
        'ODM_MAX_CORES': 8,
        '_distro_family': lambda: 'debian',
        '_webodm_wait_migrations': lambda cfg, plog, tries=24: True,
        '_webodm_ensure_admin': lambda cfg, plog: None,
        'load_settings': lambda: {},
        'save_settings': lambda s: None,
        'generate_caddyfile': lambda s: None,
        '_caddy_reload': lambda plog=None: True,
        '_get_authentik_env_value': lambda s, k: '',
        '_ensure_authentik_webodm_app': lambda *a, **k: None,
        '_webodm_dir': lambda: f'{HOME}/webodm',
    })
    return status


@pytest.fixture(autouse=True)
def _no_real_waiting(monkeypatch):
    monkeypatch.setattr(time, 'sleep', lambda s: None)

    def _refused(*a, **k):
        raise OSError('connection refused')
    monkeypatch.setattr(urllib.request, 'urlopen', _refused)


# ── Update ──────────────────────────────────────────────────────────────────────────────────────

def test_update_compose_on_disk_is_still_3x_while_the_images_are_pulled():
    # A console killed in the pull must leave the compose on what the box runs: a later `up -d`
    # (Reapply, restart) would otherwise start 4.x on the 9.5 data with no room check or dump.
    box = wo579.Box()
    status, ns = wo579._run(box)
    assert status['complete'], status['log']
    assert box.compose_at_pull == OLD
    assert box.pending is None or box.pending_writes  # the new set went to the side file
    assert box.pending_writes and box.pending_writes[0] == box.compose
    assert box.pull_files == [PENDING]


def test_update_removes_its_side_file_in_every_ending():
    for kw in ({}, {'pull_ok': False}, {'dump_ok': False}, {'upgrade_fails': True}):
        box = wo579.Box(**kw)
        wo579._run(box)
        assert ('run', ('rm', '-f', PENDING)) in box.calls, kw


def test_update_stops_on_a_database_version_it_does_not_know():
    for ver in ('19', '16', '17'):
        box = wo579.Box(pg=ver)
        status, _ = wo579._run(box)
        assert status['error'] and 'does not know how to move' in status['error'], (ver, status)
        assert box.writes == [] and box.pending_writes == [] and box.compose == OLD
        assert ('compose', 'pull') not in box.calls and ('compose', 'up -d') not in box.calls


def test_update_reads_the_data_without_starting_the_database_when_wo_db_is_down():
    # Reading the version never starts wo_db: a one-off container with a shell as its entrypoint.
    # Only afterwards, for a 9.5 database and a compose that still names the old image, is wo_db
    # started (the room check and the dump run inside it).
    box = wo579.Box(exec_fails=True)
    status, _ = wo579._run(box)
    assert status['complete'], status['log']
    keys = [c[1] for c in box.calls if c[0] == 'compose']
    probe = next(i for i, a in enumerate(keys) if a.startswith('run --rm --no-deps -T --entrypoint sh wo_db'))
    assert probe < keys.index('up -d wo_db') < keys.index('pull')
    assert box.events == ['pull', 'dump', 'write', 'up']


def test_a_half_finished_update_is_not_started_blind():
    # An earlier update that died after writing the 4.x compose leaves 4.x pins over 9.5 data
    # with wo_db stopped. `up -d wo_db` there would start the one-way upgrade with no dump.
    box = wo579.Box(exec_fails=True)
    box.compose = box.compose.replace('image: webodm/webodm_db@sha256:03f18ec0089325ec2b8975ba1781277bcdc212b6d86c9de33f6409d313e90430',
                                      'image: webodm/webodm_db:18@sha256:' + 'a' * 64)
    status, _ = wo579._run(box)
    assert status['error'] and 'did not finish' in status['error'], status
    assert ('compose', 'up -d wo_db') not in box.calls and ('compose', 'up -d') not in box.calls
    assert ('compose', 'pull') not in box.calls and box.writes == [] and box.pending_writes == []


def test_update_with_an_empty_database_volume_has_nothing_to_upgrade():
    box = wo579.Box(pg='none')
    status, _ = wo579._run(box)
    assert status['complete'], status['log']
    flat = ' '.join(' '.join(map(str, c[1])) for c in box.calls)
    assert 'pg_dumpall' not in flat and 'docker stop' not in flat


# ── Deploy / Reapply on this box ────────────────────────────────────────────────────────────────

def _deploy_local(box, has_compose=True, tmp=None):
    ns = _load(DEPLOY_WANT)
    status = _common_stubs(ns, box)
    wo_dir = pathlib.Path(tmp) / 'webodm'
    wo_dir.mkdir(parents=True, exist_ok=True)
    if has_compose:
        (wo_dir / 'docker-compose.yml').write_text('x')

    def fake_run(argv, **kw):
        if argv and argv[0] == 'git':
            if argv[1] == 'clone':
                os.makedirs(argv[-1], exist_ok=True)
                pathlib.Path(argv[-1], '__init__.py').write_text('from .plugin import Plugin\n')
                return box._r()
            if argv[1:3] == ['-C', argv[2]] and 'rev-parse' in argv:
                return box._r(out=ns['WEBODM_OVERLAY_SHA'] + '\n')
        return box.run(argv, **kw)

    class _Os:
        path = types.SimpleNamespace(
            join=os.path.join, isdir=os.path.isdir,
            expanduser=lambda p: p.replace('~', str(tmp)),
            exists=lambda p: has_compose if str(p).endswith('docker-compose.yml') else os.path.exists(p))
        makedirs = staticmethod(os.makedirs)
        cpu_count = staticmethod(lambda: 4)

        @staticmethod
        def expanduser(p):
            return p.replace('~', str(tmp))

    ns['os'] = _Os
    ns['subprocess'] = types.SimpleNamespace(run=fake_run)
    ns['_get_module_deployment_config'] = lambda s, k: {}
    # `import subprocess as _sp` inside the function reads sys.modules
    real = sys.modules['subprocess']
    sys.modules['subprocess'] = ns['subprocess']
    try:
        ns['_webodm_dir'] = lambda: str(wo_dir)
        ns['_run_webodm_deploy']({'webodm_port': 8765})
    finally:
        sys.modules['subprocess'] = real
    return status, ns


def test_reapply_on_a_3x_box_checks_room_dumps_then_writes_the_compose_and_starts(tmp_path):
    box = wo579.Box()
    status, ns = _deploy_local(box, tmp=tmp_path)
    assert status['complete'] and not status['error'], status['log']
    assert box.events == ['pull', 'dump', 'write', 'up'], box.events
    assert any('du -sk' in ' '.join(c[1]) for c in box.calls if c[0] == 'run')
    assert box.compose_at_pull == OLD
    assert wo579._images(box.running_images) == ns['WEBODM_IMAGES']
    assert any('backup-infratak-' in m for m in status['log'])


def test_reapply_without_room_changes_nothing_and_does_not_say_deployed(tmp_path):
    # ops #1311 box result: 110 MB free, wo_db restart loop, and the log said deployed successfully.
    box = wo579.Box(used_kb=1_000_000, free_kb=3_000_000)
    status, _ = _deploy_local(box, tmp=tmp_path)
    assert status['error'] and 'not enough free disk' in status['error']
    assert not status['complete']
    assert box.writes == [] and box.compose == OLD and box.pending_writes == []
    assert box.calls and ('compose', 'up -d') not in box.calls and ('compose', 'pull') not in box.calls
    assert not any('deployed successfully' in m for m in status['log'])


def test_reapply_with_a_failed_dump_keeps_3x_running_and_the_old_compose(tmp_path):
    box = wo579.Box(dump_ok=False)
    status, _ = _deploy_local(box, tmp=tmp_path)
    assert status['error'] and 'backup failed' in status['error']
    assert box.compose == OLD and wo579._images(box.running_images)['wo_webapp'].endswith(':3.3.1')


def test_reapply_with_a_failed_pull_stops_before_any_change(tmp_path):
    # The deploy used to treat a failed pull as "warning (non-fatal)" and went on to `up -d`.
    box = wo579.Box(pull_ok=False)
    status, _ = _deploy_local(box, tmp=tmp_path)
    assert status['error'] and 'pull failed' in status['error']
    assert box.compose == OLD and ('compose', 'up -d') not in box.calls
    assert not any('pg_dumpall' in ' '.join(c[1]) for c in box.calls)


def test_reapply_whose_upgrade_fails_puts_3x_and_its_data_back(tmp_path):
    box = wo579.Box(upgrade_fails=True)
    status, _ = _deploy_local(box, tmp=tmp_path)
    assert status['error'] and 'previous version and its data are back' in status['error']
    assert box.compose == OLD and wo579._images(box.running_images)['wo_webapp'].endswith(':3.3.1')


def test_reapply_stops_on_a_database_version_it_does_not_know(tmp_path):
    box = wo579.Box(pg='19')
    status, _ = _deploy_local(box, tmp=tmp_path)
    assert status['error'] and 'does not know how to move' in status['error']
    assert box.calls and ('compose', 'pull') not in box.calls and ('compose', 'up -d') not in box.calls
    assert box.writes == [] and box.compose == OLD


def test_reapply_on_a_4x_box_makes_no_dump_and_no_stop(tmp_path):
    box = wo579.Box(pg='18')
    status, _ = _deploy_local(box, tmp=tmp_path)
    assert status['complete'], status['log']
    flat = ' '.join(' '.join(map(str, c[1])) for c in box.calls)
    assert 'pg_dumpall' not in flat and 'docker stop' not in flat and 'du -sk' not in flat
    assert box.events == ['pull', 'write', 'up']


def test_a_first_install_has_no_database_to_read_and_pulls_before_it_starts(tmp_path):
    box = wo579.Box()
    status, _ = _deploy_local(box, has_compose=False, tmp=tmp_path)
    assert status['complete'], status['log']
    flat = ' '.join(' '.join(map(str, c[1])) for c in box.calls)
    assert 'PG_VERSION' not in flat and 'pg_dumpall' not in flat
    assert box.events == ['pull', 'write', 'up']


# ── Deploy on a remote host ─────────────────────────────────────────────────────────────────────

def _deploy_remote(box, has_compose=True):
    ns = _load(DEPLOY_WANT)
    status = _common_stubs(ns, box)
    REMOTE = '/home/ubuntu/webodm'
    ns['PENDING'] = f'{REMOTE}/docker-compose.pending.yml'
    cfg = {'target_mode': 'remote', 'remote': {'host': '203.0.113.9'}}

    def module_run(c, cmd, timeout=120, log_fn=None):
        if cmd == 'echo $HOME':
            return True, '/home/ubuntu\n'
        if cmd.startswith('docker --version'):
            return True, 'Docker version 27.1\n'
        if cmd.startswith('nproc'):
            return True, '4\n'
        if cmd == f'test -f {REMOTE}/docker-compose.yml':
            return has_compose, ''
        if cmd == f'cat {REMOTE}/docker-compose.yml':
            return True, box.compose
        argv = shlex.split(cmd)
        if argv[:2] == ['docker', 'compose'] and '--project-directory' not in argv:
            box.calls.append(('compose', ' '.join(argv[2:])))   # a compose command of the deploy's own
            return True, ''
        if argv[:2] == ['docker', 'compose']:
            i = argv.index('--project-directory')
            action = ' '.join(shlex.quote(a) for a in argv[i + 2:])
            r = box.compose_cmd(argv[i + 1], action, timeout=timeout)
            return r.returncode == 0, (r.stdout or '') + (r.stderr or '')
        if argv[:1] == ['docker']:
            r = box.run(argv, timeout=timeout)
            return r.returncode == 0, (r.stdout or '') + (r.stderr or '')
        if argv[:2] == ['rm', '-f']:
            box.calls.append(('run', tuple(argv)))
            return True, ''
        if cmd.startswith('curl'):
            return True, '200'
        return True, ''

    def module_copy(c, local, remote_path, timeout=30, log_fn=None):
        box.write(remote_path, pathlib.Path(local).read_text())
        return True, ''

    box.write_orig = box.write
    ns.update({
        '_module_run': module_run, '_module_copy': module_copy,
        '_docker_install_cmd': lambda sudo_fallback=False: 'true',
        '_remote_docker_group': lambda c, plog: None,
        '_remote_ensure_git': lambda c, plog: (True, ''),
        '_remote_docker_port_guard': lambda *a, **k: (True, ''),
        '_fedhub_caddy_source_ip': lambda s: '',
        '_normalize_module_deployment_config': lambda c: c,
        '_webodm_ensure_admin': lambda c, plog: None,
        'WEBODM_OVERLAY_SHA': '3f0efb383a9f1bd022eac15ac4b3da83e643fccc',
        'subprocess': types.SimpleNamespace(run=box.run),
    })
    ns['_run_webodm_deploy_remote']({'webodm_port': 8765}, cfg, ns['_webodm_deploy_log'] if False else
                                    (lambda m, st=None: status['log'].append(m)))
    return status, ns


def test_remote_redeploy_on_a_3x_host_checks_room_dumps_then_writes_the_compose_and_starts():
    box = wo579.Box()
    status, ns = _deploy_remote(box)
    assert status['complete'] and not status['error'], status['log']
    assert box.events == ['pull', 'dump', 'write', 'up'], box.events
    assert any('du -sk' in ' '.join(c[1]) for c in box.calls if c[0] == 'run')
    assert box.compose_at_pull == OLD
    assert wo579._images(box.running_images)['wo_db'] == ns['WEBODM_IMAGES']['wo_db']


def test_remote_redeploy_without_room_changes_nothing():
    box = wo579.Box(used_kb=1_000_000, free_kb=3_000_000)
    status, _ = _deploy_remote(box)
    assert status['error'] and 'not enough free disk' in status['error']
    assert not status['complete']
    assert box.writes == [] and box.compose == OLD
    assert ('compose', 'pull') not in box.calls and ('compose', 'up -d') not in box.calls


def test_remote_pull_that_fails_or_times_out_does_not_start_a_half_pulled_set():
    # The remote pull was "non-fatal" with a 600 s limit and `up -d` had 120 s.
    for kw in ({'pull_ok': False}, {'times_out': {'pull'}}):
        box = wo579.Box(**kw)
        status, _ = _deploy_remote(box, has_compose=False)
        assert status['error'], (kw, status)
        assert ('compose', 'up -d') not in box.calls and box.running_images is None
    box = wo579.Box()
    _, ns = _deploy_remote(box, has_compose=False)
    assert box.timeouts['pull'] == ns['WEBODM_PULL_TIMEOUT_S'] >= 1800


def test_remote_redeploy_stops_on_a_database_version_it_does_not_know():
    box = wo579.Box(pg='19')
    status, _ = _deploy_remote(box)
    assert status['error'] and 'does not know how to move' in status['error']
    assert ('compose', 'pull') not in box.calls and box.writes == [] and box.compose == OLD


def test_remote_failed_upgrade_puts_3x_back_on_the_host():
    box = wo579.Box(upgrade_fails=True)
    status, _ = _deploy_remote(box)
    assert status['error'] and 'previous version and its data are back' in status['error']
    assert box.compose == OLD and wo579._images(box.running_images)['wo_webapp'].endswith(':3.3.1')


# ── Nothing else starts the new images ──────────────────────────────────────────────────────────

def _src(name):
    return ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name))


def test_deploy_paths_start_the_images_only_through_the_shared_routine():
    for fn in ('_run_webodm_deploy', '_run_webodm_deploy_remote', '_run_webodm_update'):
        src = re.sub(r'#.*', '', _src(fn))   # comments may talk about the pull
        assert '_webodm_move_to_new_images(' in src, fn
        # no compose command of their own: pull and up -d run only inside the routine
        assert '_webodm_compose(' not in src and 'docker compose' not in src and "'compose'" not in src, fn
        assert '_webodm_db_needs_upgrade(' in src, fn
        # the check comes before the first thing the path changes
        assert src.index('_webodm_db_needs_upgrade(') < src.index('_webodm_move_to_new_images('), fn
