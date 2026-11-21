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
"""CloudTAK Update refuses early when the disk is too full (ops #983, infra-TAK #601).

Field (v10.3.13, CloudTAK 13.113.0 -> 13.124.0): the update checked out the new tag, ran the
build, died on "no space left on device" (tippecanoe make, npm install), and the revert of the
checkout failed for the same reason. Nothing checked free space first.

app.py cannot be imported in a test, so the functions are cut out of it.
"""

import ast
import collections
import os
import pathlib
import re
import shlex

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
GB = 1024 ** 3
_FUNCS = {'_cloudtak_fs_free_local', '_cloudtak_fs_free_remote',
          '_cloudtak_update_space_problem', '_cloudtak_update_space_lines'}
_CONSTS = {'_CLOUDTAK_UPDATE_MEASURED_GB', '_CLOUDTAK_UPDATE_MIN_FREE',
           '_CLOUDTAK_UPDATE_MIN_FREE_CHECKOUT'}
REMOTE = {'host': '203.0.113.7', 'ssh_user': 'root'}


def _cut(names, consts=()):
    tree = ast.parse(APP)
    parts, found = [], set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            parts.append(ast.get_source_segment(APP, node))
            found.add(node.name)
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in consts for t in node.targets):
            parts.append(ast.get_source_segment(APP, node))
    assert found == set(names), f'missing in app.py: {set(names) - found}'
    return '\n\n'.join(parts)


def _ns(docker_root='/var/lib/docker', local=None, remote=None, ssh=None, strict=True):
    """Namespace with the space helpers. `local` maps path -> (fs id, free) for the local reads."""
    ns = {'os': os, 're': re, 'shlex': shlex}
    ns['_cloudtak_docker'] = lambda argv, remote_cfg=None, timeout=60: (0, docker_root + '\n', '')
    ns['_ssh_probe'] = ssh or (lambda cfg, cmd='echo ok', timeout=15: (True, ''))
    if strict:
        exec(compile(_cut(_FUNCS, _CONSTS), 'app.py', 'exec'), ns)
    else:   # the end-to-end run below must also load on a tree that has no space check at all
        have = {n.name for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef)}
        exec(compile(_cut(_FUNCS & have, _CONSTS), 'app.py', 'exec'), ns)
    if local is not None:
        ns['_cloudtak_fs_free_local'] = lambda path: local.get(path, (None, None))
    if remote is not None:
        ns['_cloudtak_fs_free_remote'] = lambda cfg, path: remote.get(path, (None, None))
    return ns


def test_floor_is_a_measured_positive_number():
    ns = _ns()
    assert ns['_CLOUDTAK_UPDATE_MEASURED_GB'] > 0
    assert ns['_CLOUDTAK_UPDATE_MIN_FREE'] == ns['_CLOUDTAK_UPDATE_MEASURED_GB'] * GB


# --------------------------------------------------------------------------- #
# the decision
# --------------------------------------------------------------------------- #
def test_enough_room_on_one_disk_passes():
    n = _ns(local={'/var/lib/docker': ('d1', 400 * GB), '/home/takwerx/CloudTAK': ('d1', 400 * GB)})
    assert n['_cloudtak_update_space_problem']('/home/takwerx/CloudTAK') is None


def test_full_disk_is_refused_and_names_the_disk():
    """The reporter's case: the images folder and the checkout share a nearly full disk."""
    n = _ns(local={'/var/lib/docker': ('d1', 3 * GB), '/home/takwerx/CloudTAK': ('d1', 3 * GB)})
    p = n['_cloudtak_update_space_problem']('/home/takwerx/CloudTAK')
    assert p and p['where'] == '/var/lib/docker' and p['free'] == 3 * GB
    # one disk: the images need and the checkout need add up
    assert p['need'] == n['_CLOUDTAK_UPDATE_MIN_FREE'] + n['_CLOUDTAK_UPDATE_MIN_FREE_CHECKOUT']


def test_just_under_and_just_over_the_line():
    n = _ns(local={})
    need = n['_CLOUDTAK_UPDATE_MIN_FREE'] + n['_CLOUDTAK_UPDATE_MIN_FREE_CHECKOUT']
    for free, short in ((need - 1, True), (need, False)):
        n = _ns(local={'/var/lib/docker': ('d1', free), '/home/t/CloudTAK': ('d1', free)})
        assert bool(n['_cloudtak_update_space_problem']('/home/t/CloudTAK')) is short


def test_separate_disks_each_checked_for_its_own_need():
    n = _ns(local={'/var/lib/docker': ('d1', 400 * GB), '/home/t/CloudTAK': ('d2', GB // 10)})
    p = n['_cloudtak_update_space_problem']('/home/t/CloudTAK')
    assert p and p['where'] == '/home/t/CloudTAK' and p['need'] == n['_CLOUDTAK_UPDATE_MIN_FREE_CHECKOUT']
    n = _ns(local={'/var/lib/docker': ('d1', GB), '/home/t/CloudTAK': ('d2', 400 * GB)})
    p = n['_cloudtak_update_space_problem']('/home/t/CloudTAK')
    assert p and p['where'] == '/var/lib/docker' and p['need'] == n['_CLOUDTAK_UPDATE_MIN_FREE']


def test_unreadable_numbers_never_block():
    """No answer is not a refusal: an Update that worked yesterday must not stop on a probe error."""
    n = _ns(local={})
    assert n['_cloudtak_update_space_problem']('/home/t/CloudTAK') is None


def test_docker_data_folder_comes_from_docker_with_a_default():
    n = _ns(docker_root='/data/docker', local={'/data/docker': ('d9', GB), '/home/t/CloudTAK': ('d1', 400 * GB)})
    assert n['_cloudtak_update_space_problem']('/home/t/CloudTAK')['where'] == '/data/docker'
    n = _ns(docker_root='garbage', local={'/var/lib/docker': ('d9', GB), '/home/t/CloudTAK': ('d1', 400 * GB)})
    assert n['_cloudtak_update_space_problem']('/home/t/CloudTAK')['where'] == '/var/lib/docker'


def test_remote_host_is_measured_over_ssh_not_locally():
    n = _ns(local={'/var/lib/docker': ('LOCAL', 999 * GB)},
            remote={'/var/lib/docker': ('r1', 2 * GB), '$HOME/CloudTAK': ('r1', 2 * GB)})
    p = n['_cloudtak_update_space_problem'](None, remote_cfg=REMOTE)
    assert p and p['free'] == 2 * GB
    n = _ns(remote={'/var/lib/docker': ('r1', 400 * GB), '$HOME/CloudTAK': ('r1', 400 * GB)})
    assert n['_cloudtak_update_space_problem'](None, remote_cfg=REMOTE) is None


def test_remote_df_command_and_parse():
    seen = []

    def ssh(cfg, cmd='echo ok', timeout=15):
        seen.append(cmd)
        return True, 'overlay 12345678\n'
    n = _ns(ssh=ssh)
    assert n['_cloudtak_fs_free_remote'](REMOTE, '$HOME/CloudTAK') == ('overlay', 12345678)
    assert 'df -P -B1' in seen[0] and '"$HOME/CloudTAK"' in seen[0]
    n = _ns(ssh=lambda cfg, cmd='', timeout=15: (False, 'timeout'))
    assert n['_cloudtak_fs_free_remote'](REMOTE, '/var/lib/docker') == (None, None)
    # a path with a shell character is quoted, never run
    n = _ns(ssh=ssh)
    n['_cloudtak_fs_free_remote'](REMOTE, '/x; rm -rf /')
    assert "'/x; rm -rf /'" in seen[-1]


def test_local_free_reads_a_real_path_and_walks_up(tmp_path):
    n = _ns()
    dev, free = n['_cloudtak_fs_free_local'](str(tmp_path))
    assert dev is not None and free > 0
    # a root-only or missing folder answers for its nearest readable parent
    assert n['_cloudtak_fs_free_local'](str(tmp_path / 'no' / 'such')) == (dev, free) or \
        n['_cloudtak_fs_free_local'](str(tmp_path / 'no' / 'such'))[0] == dev


def test_message_says_nothing_changed_and_what_to_do():
    n = _ns()
    lines = n['_cloudtak_update_space_lines']({'what': 'the CloudTAK images and build cache',
                                               'where': '/var/lib/docker', 'free': 3 * GB, 'need': 25 * GB})
    text = '\n'.join(lines)
    assert '3.0 GB free' in text and 'about 25 GB' in text
    assert 'Nothing was changed' in text and 'press Update again' in text
    assert 'docker builder prune -f' in text and 'Do not delete Docker volumes' in text


# --------------------------------------------------------------------------- #
# wiring: run_cloudtak_update runs the check before it touches anything
# --------------------------------------------------------------------------- #
def _update_src():
    i = APP.index('def run_cloudtak_update(')
    j = APP.index('\ndef ', i + 10)
    return APP[i:j]


def test_update_checks_space_before_checkout_and_build():
    b = _update_src()
    i_chk = b.index('_cloudtak_update_space_problem(')
    for later in ('Step 2/3', '_mod_result_versions(', '_cloudtak_git_prep(', 'checkout -f', 'build --no-cache'):
        assert i_chk < b.index(later), f'space check must come before {later}'
    blk = b[i_chk:b.index('Step 2/3')]
    assert "'error': True" in blk and 'return' in blk, 'a refused update must end with an error'


class _Boom(Exception):
    pass


def _run_update(free, tmp_path):
    """Run the top of run_cloudtak_update with stubs; return (log, status, calls)."""
    tree = ast.parse(APP)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_cloudtak_update')
    code = ast.get_source_segment(APP, node)
    n = _ns(local={'/var/lib/docker': ('d1', free), str(tmp_path): ('d1', free)}, strict=False)
    log, status, calls = collections.deque(), {'running': True, 'error': False}, []

    def tripwire(*a, **k):
        calls.append(('subprocess', a))
        raise _Boom('the update went on to touch the box')
    n.update({
        'datetime': __import__('datetime').datetime, 'cloudtak_deploy_log': log,
        'cloudtak_deploy_status': status, 'load_settings': lambda: {},
        '_get_cloudtak_deployment_config': lambda s: {'target_mode': 'local'},
        '_get_cloudtak_target_release_tag': lambda *a, **k: 'v13.124.0',
        '_cloudtak_running_version': lambda *a, **k: '13.113.0',
        '_mod_result_versions': lambda *a, **k: calls.append(('versions', a)),
        'subprocess': type('S', (), {'run': staticmethod(tripwire), 'Popen': staticmethod(tripwire)}),
        '_cloudtak_git_prep': lambda *a, **k: calls.append(('git_prep', a)),
        'CLOUDTAK_PLUGINS': [], 'threading': None, 'deque': collections.deque,
        'traceback': __import__('traceback'),
    })
    # the update reads ~/CloudTAK: point it at the temp folder
    (tmp_path / '.git').mkdir()
    n['os'] = type('O', (), {'path': type('P', (), {
        'expanduser': staticmethod(lambda p: str(tmp_path)),
        'isdir': staticmethod(os.path.isdir), 'join': staticmethod(os.path.join),
        'exists': staticmethod(os.path.exists), 'dirname': staticmethod(os.path.dirname),
        'islink': staticmethod(os.path.islink)}), 'statvfs': os.statvfs, 'stat': os.stat,
        'makedirs': os.makedirs})
    n['_cloudtak_fs_free_local'] = lambda path: ('d1', free)
    exec(compile(code, 'app.py', 'exec'), n)
    try:
        n['run_cloudtak_update']()
    except _Boom:
        pass
    return list(log), status, calls


def test_full_disk_update_stops_before_anything_changes(tmp_path):
    log, status, calls = _run_update(2 * GB, tmp_path)
    text = '\n'.join(log)
    assert 'Not enough free disk space to update CloudTAK' in text
    assert 'Step 2/3' not in text and 'Checking out' not in text
    assert status['error'] is True and status['running'] is False
    assert calls == [], f'a refused update must touch nothing, it did: {calls}'


def test_update_with_room_goes_on_to_the_checkout(tmp_path):
    log, status, calls = _run_update(400 * GB, tmp_path)
    text = '\n'.join(log)
    assert 'Not enough free disk space' not in text
    assert 'Step 2/3' in text
    assert any(c[0] == 'versions' for c in calls), 'with room the update records its versions and goes on'
