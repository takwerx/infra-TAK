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
"""CloudTAK Update clears old Docker build cache instead of refusing for it (ops #1452).

Field (box test of ops #1325): the third CloudTAK Update on one box said "15.8 GB free for the
CloudTAK images and build cache, the update needs about 17 GB". Two earlier Updates had left 19 GB
of build cache that no build reads (every CloudTAK build is --no-cache) and that Guard Dog's 20 GB
cap leaves alone. `docker builder prune -af` freed it and the next Update passed.

app.py cannot be imported in a test, so the functions are cut out of it.
"""

import ast
import collections
import os
import pathlib
import re
import shlex

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
GB = 1024 ** 3
_FUNCS = {'_cloudtak_fs_free_local', '_cloudtak_fs_free_remote', '_cloudtak_update_space_problem',
          '_cloudtak_update_space_lines', '_cloudtak_prune_build_cache'}
_CONSTS = {'_CLOUDTAK_UPDATE_MEASURED_GB', '_CLOUDTAK_UPDATE_MIN_FREE',
           '_CLOUDTAK_UPDATE_MIN_FREE_CHECKOUT', '_FREE_SPACE_BACKUPS_HINT'}


def _cut(names, consts=()):
    tree = ast.parse(APP)
    parts = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            parts.append(ast.get_source_segment(APP, node))
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in consts for t in node.targets):
            parts.append(ast.get_source_segment(APP, node))
    return '\n\n'.join(parts)


class FakeDocker:
    """A Docker host with a disk: free = disk - cache (the images are already counted out)."""

    def __init__(self, disk_free_without_cache, cache, prune_rc=0, prune_out=None):
        self.base, self.cache = disk_free_without_cache, cache
        self.rc, self.out = prune_rc, prune_out
        self.argvs = []

    def free(self):
        return self.base - self.cache

    def docker(self, argv, remote_cfg=None, timeout=60):
        self.argvs.append(list(argv))
        if argv[:2] == ['docker', 'info']:
            return 0, '/var/lib/docker\n', ''
        if argv[:3] == ['docker', 'builder', 'prune']:
            if self.rc != 0:
                return self.rc, '', 'Cannot connect to the Docker daemon'
            was, self.cache = self.cache, 0
            return 0, self.out if self.out is not None else \
                f'ID  RECLAIMABLE  SIZE  LAST ACCESSED\nTotal:\t{was / 1e9:.1f}GB\n', ''
        raise AssertionError(f'unexpected docker call {argv}')


def _ns(fake):
    ns = {'os': os, 're': re, 'shlex': shlex, '_cloudtak_docker': fake.docker,
          '_ssh_probe': lambda cfg, cmd='', timeout=15: (True, '')}
    exec(compile(_cut(_FUNCS, _CONSTS), 'app.py', 'exec'), ns)
    ns['_cloudtak_fs_free_local'] = lambda path: ('d1', fake.free())
    return ns


# ── the helper ────────────────────────────────────────────────────────────────

def test_prune_runs_builder_prune_only_and_reports_the_total():
    fake = FakeDocker(40 * GB, 19 * GB)
    msgs = []
    total = _ns(fake)['_cloudtak_prune_build_cache'](msgs.append)
    assert fake.argvs == [['docker', 'builder', 'prune', '-af']]
    assert total.endswith('GB') and fake.cache == 0 and msgs == []


def test_prune_never_touches_images_containers_or_volumes():
    body = _cut({'_cloudtak_prune_build_cache'})
    code = '\n'.join(l for l in body.splitlines() if not l.strip().startswith('#'))
    assert "'builder', 'prune'" in code
    for bad in ("'image'", "'system'", "'volume'", "'rm'", '--volumes'):
        assert bad not in code, f'the cache prune must not run {bad}'


def test_failed_prune_returns_none_logs_and_does_not_raise():
    fake = FakeDocker(40 * GB, 19 * GB, prune_rc=1)
    msgs = []
    assert _ns(fake)['_cloudtak_prune_build_cache'](msgs.append) is None
    assert msgs and 'Going on without it' in msgs[0]

    def boom(argv, remote_cfg=None, timeout=60):
        raise TimeoutError('docker hung')
    ns = _ns(fake)
    ns['_cloudtak_docker'] = boom
    msgs.clear()
    assert ns['_cloudtak_prune_build_cache'](msgs.append) is None and msgs


def test_prune_goes_to_the_remote_host_when_asked():
    seen = []
    fake = FakeDocker(40 * GB, 19 * GB)
    ns = _ns(fake)
    ns['_cloudtak_docker'] = lambda argv, remote_cfg=None, timeout=60: (
        seen.append(remote_cfg) or fake.docker(argv, remote_cfg, timeout))
    ns['_cloudtak_prune_build_cache'](lambda m: None, remote_cfg={'host': '203.0.113.7'})
    assert seen == [{'host': '203.0.113.7'}]


# ── the Update: the top of run_cloudtak_update, run for real with stubs ────────

class _Boom(Exception):
    pass


def _run_update_top(fake, tmp_path):
    tree = ast.parse(APP)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_cloudtak_update')
    code = ast.get_source_segment(APP, node)
    n = _ns(fake)
    log, status, calls = collections.deque(), {'running': True, 'error': False}, []

    def tripwire(*a, **k):
        calls.append(('subprocess', a))
        raise _Boom('the update went on to touch the box')
    n.update({
        'datetime': __import__('datetime').datetime, 'cloudtak_deploy_log': log,
        'cloudtak_deploy_status': status, 'load_settings': lambda: {},
        '_get_cloudtak_deployment_config': lambda s: {'target_mode': 'local'},
        '_get_cloudtak_target_release_tag': lambda *a, **k: 'v14.4.2',
        '_cloudtak_needs_minio_hop': lambda tag: False, '_cloudtak_minio_hop_tag': lambda: None,
        '_cloudtak_running_version': lambda *a, **k: '14.0.1',
        '_mod_result_versions': lambda *a, **k: calls.append(('versions', a)),
        'subprocess': type('S', (), {'run': staticmethod(tripwire), 'Popen': staticmethod(tripwire)}),
        '_cloudtak_git_prep': lambda *a, **k: calls.append(('git_prep', a)),
        'CLOUDTAK_PLUGINS': [], 'threading': None, 'deque': collections.deque,
        'traceback': __import__('traceback'),
    })
    (tmp_path / '.git').mkdir()
    n['os'] = type('O', (), {'path': type('P', (), {
        'expanduser': staticmethod(lambda p: str(tmp_path)),
        'isdir': staticmethod(os.path.isdir), 'join': staticmethod(os.path.join),
        'exists': staticmethod(os.path.exists), 'dirname': staticmethod(os.path.dirname),
        'islink': staticmethod(os.path.islink)}), 'statvfs': os.statvfs, 'stat': os.stat,
        'makedirs': os.makedirs})
    exec(compile(code, 'app.py', 'exec'), n)
    try:
        n['run_cloudtak_update']()
    except _Boom:
        pass
    return '\n'.join(log), status, calls


def test_third_update_with_old_cache_clears_it_and_goes_on(tmp_path):
    # Field numbers: 15.8 GB free with 19 GB of cache on top, need 17 GB.
    fake = FakeDocker(disk_free_without_cache=int(34.8 * GB), cache=19 * GB)
    text, status, calls = _run_update_top(fake, tmp_path)
    assert ['docker', 'builder', 'prune', '-af'] in fake.argvs
    assert 'Old build cache cleared' in text
    assert 'Not enough free disk space to update CloudTAK' not in text
    assert 'Step 2/3' in text and any(c[0] == 'versions' for c in calls)


def test_still_short_after_the_prune_refuses_and_stops_advising_the_prune(tmp_path):
    fake = FakeDocker(disk_free_without_cache=8 * GB, cache=3 * GB)
    text, status, calls = _run_update_top(fake, tmp_path)
    assert 'Not enough free disk space to update CloudTAK' in text
    assert 'The old build cache was already cleared' in text
    assert 'docker builder prune -af' not in text
    assert 'Step 2/3' not in text and status['error'] is True and calls == []


def test_a_failing_prune_leaves_the_old_refusal_unchanged(tmp_path):
    fake = FakeDocker(disk_free_without_cache=int(34.8 * GB), cache=19 * GB, prune_rc=1)
    text, status, calls = _run_update_top(fake, tmp_path)
    assert 'Not enough free disk space to update CloudTAK' in text
    assert 'docker builder prune -af' in text      # the manual advice still stands
    assert status['error'] is True and calls == []


def test_room_enough_never_prunes(tmp_path):
    fake = FakeDocker(disk_free_without_cache=400 * GB, cache=19 * GB)
    text, status, calls = _run_update_top(fake, tmp_path)
    assert not any(a[:3] == ['docker', 'builder', 'prune'] for a in fake.argvs)
    assert 'Step 2/3' in text


# ── the Update: after a good build, the cache it wrote is cleared ──────────────

def _update_src():
    i = APP.index('def run_cloudtak_update(')
    return APP[i:APP.index('\ndef ', i + 10)]


def test_prune_after_success_comes_after_rollback_pins_and_before_done():
    b = _update_src()
    code = re.sub(r'#.*', '', b)
    m = re.search(r'_cloudtak_drop_rollback_pins\(_ct_snap, remote_cfg=\(remote_cfg if is_remote else None\)\)\s+_freed_after = _cloudtak_prune_build_cache\(', code)
    assert m, 'the post-success prune must directly follow dropping the rollback pins'
    i_prune = m.end()
    i_done = code.index('✓ CloudTAK updated to')
    assert i_prune < i_done


def test_prune_after_success_is_not_in_any_failure_path():
    code = re.sub(r'#.*', '', _update_src())
    uses = [m.start() for m in re.finditer(r'_cloudtak_prune_build_cache\(', code)]
    assert len(uses) == 2, 'one before the check, one after success'
    # every `return` between the start of Step 3/3 and the success line is a failure exit
    step3 = code.index('Step 3/3')
    done = code.index('✓ CloudTAK updated to')
    assert not any(step3 < u < done and u != uses[-1] for u in uses)
    assert uses[-1] > code.rindex('return', step3, done)
