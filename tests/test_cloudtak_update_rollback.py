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
"""A failed CloudTAK Update leaves the running CloudTAK as it was (ops #129).

Field (ops1, v10.2.21): three Updates in a row failed. Two died inside the build on the api
Dockerfile's first stage — `wget -O data.zip "$DATA_SOURCE_URL" && unzip data.zip ...`, the
CloudTAK-Data zip fetched from GitHub inside the build. The third built fine, then
`docker compose up -d` exited 1 and the update simply stopped: tree on the new tag, image tags
moved to the new build, old containers still running, nothing put back, and the record said
"? -> ?".

app.py cannot be imported in a test, so the functions are cut out of it.
"""

import ast
import io
import json
import os
import pathlib
import re
import shlex
import zipfile

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_FUNCS = {
    '_cloudtak_running_version', '_cloudtak_snapshot_images', '_cloudtak_restore_images',
    '_cloudtak_rollback_after_failed_up', '_cloudtak_prefetch_build_data',
    '_cloudtak_drop_build_data', '_cloudtak_rollback_ref', '_cloudtak_drop_rollback_pins',
    '_cloudtak_docker', '_cloudtak_compose_at',
    '_snapshot_cloudtak_plugin_state', '_rollback_cloudtak_plugin_state', '_cleanup_snapshot',
}
DOCKERFILE = '''FROM alpine:3.24 AS data

ARG DATA_SOURCE_URL=https://github.com/dfpc-coe/CloudTAK-Data/archive/refs/tags/v1.2.0.zip
ARG USE_LOCAL_ZIP=false

WORKDIR /tmp/data

COPY api/data.zip* ./

RUN if [ "$USE_LOCAL_ZIP" != "true" ]; then wget -O data.zip "$DATA_SOURCE_URL"; fi \\
    && unzip data.zip
'''
API_ID = 'sha256:' + 'a' * 64
EV_ID = 'sha256:' + 'b' * 64


def _zip_bytes(top='CloudTAK-Data-1.2.0/'):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr(top + 'icons/a.png', b'png')
    return buf.getvalue()


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class Urlopen:
    """Stand-in for urllib.request.urlopen: answers from a list, one entry per attempt."""
    def __init__(self, answers):
        self.answers, self.calls = list(answers), []

    def __call__(self, req, timeout=None):
        self.calls.append(req.full_url)
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return _Resp(a)


class Run:
    """Stand-in for subprocess.run: records argv, answers `docker inspect`/`exec` from a table."""
    def __init__(self, inspect_out='', tag_rc=0, version='13.109.3'):
        self.calls, self.inspect_out, self.tag_rc, self.version = [], inspect_out, tag_rc, version

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        out, rc = '', 0
        if argv[:2] == ['docker', 'inspect']:
            out = self.inspect_out
        elif argv[:2] == ['docker', 'tag']:
            rc = self.tag_rc
        elif argv[:2] == ['docker', 'exec']:
            out = self.version
        return type('R', (), {'returncode': rc, 'stdout': out, 'stderr': ''})()


class Compose:
    def __init__(self, fail_on=None):
        self.calls, self.fail_on = [], fail_on

    def __call__(self, cloudtak_dir, args, timeout=600):
        self.calls.append(list(args))
        if self.fail_on and self.fail_on == args[:len(self.fail_on)]:
            return 1, 'Error response from daemon: boom'
        if args[:2] == ['ps', '-a']:
            return 0, '\n'.join(c * 12 for c in '1234') + '\n'
        if args[:2] == ['ps', '-q']:
            return 0, '9' * 12 + '\n'
        return 0, ''


class Ssh:
    """Stand-in for _ssh_probe: records each remote shell command, answers like the remote host."""
    def __init__(self, inspect_out='', tag_ok=True, version='13.109.3', fail_on=None):
        self.cmds, self.inspect_out, self.tag_ok, self.version = [], inspect_out, tag_ok, version
        self.fail_on = fail_on

    def __call__(self, host_cfg, cmd='echo ok', timeout=15):
        assert host_cfg == REMOTE
        self.cmds.append(cmd)
        if self.fail_on and self.fail_on in cmd:
            return False, 'Error response from daemon: boom'
        if cmd.endswith('ps -a -q'):
            return True, '\n'.join(c * 12 for c in '1234')
        if cmd.endswith('ps -q api'):
            return True, '9' * 12
        if cmd.startswith('docker inspect'):
            return True, self.inspect_out
        if cmd.startswith('docker tag'):
            return (True, '') if self.tag_ok else (False, 'Error: No such image')
        if cmd.startswith('docker exec'):
            return True, self.version
        if cmd.startswith('cat '):
            return True, '{"version": "13.111.3"}'
        return True, ''


REMOTE = {'host': '203.0.113.7', 'ssh_user': 'root'}


def _no_local(*a, **k):
    pytest.fail('a remote CloudTAK must not be touched with a local docker command')


def _ns(compose=None, run=None, ssh=None):
    tree = ast.parse(APP)
    parts = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in _FUNCS:
            parts.append(ast.get_source_segment(APP, node))
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id.startswith('_CT_') for t in node.targets):
            parts.append(ast.get_source_segment(APP, node))
    names = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert _FUNCS <= names, 'a function under test was renamed or removed'
    ns = {'os': os, 're': re, 'json': json, 'shlex': shlex, 'VERSION': '10.2.24-alpha',
          '_ssh_probe': ssh or Ssh(), '_compose_cmd': lambda remote_cfg=None: 'docker compose',
          '_cloudtak_server_routes_dir': lambda d: os.path.join(d, 'api', 'routes'),
          'time': type('T', (), {'sleep': staticmethod(lambda s: None)}),
          'subprocess': type('S', (), {'run': staticmethod(run or Run())}),
          '_sudo_wrap': lambda a: a, '_update_error_line': lambda t: (t or '').strip().splitlines()[-1] if t else '',
          '_cloudtak_compose_run': compose or Compose()}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


@pytest.fixture
def ct(tmp_path):
    (tmp_path / 'api').mkdir()
    (tmp_path / 'Dockerfile').write_text(DOCKERFILE)
    return tmp_path


@pytest.fixture
def stub_urlopen(monkeypatch):
    def _set(answers):
        u = Urlopen(answers)
        import urllib.request
        monkeypatch.setattr(urllib.request, 'urlopen', u)
        return u
    return _set


# --------------------------------------------------------------------------- #
# the map-data zip, fetched on the host before the build
# --------------------------------------------------------------------------- #

def test_data_zip_is_fetched_at_the_dockerfile_url_and_used_by_the_build(ct, stub_urlopen):
    u = stub_urlopen([_zip_bytes()])
    log = []
    ok, use_local, err = _ns()['_cloudtak_prefetch_build_data'](str(ct), log.append)
    assert ok and use_local and err == ''
    assert u.calls == ['https://github.com/dfpc-coe/CloudTAK-Data/archive/refs/tags/v1.2.0.zip']
    assert zipfile.ZipFile(ct / 'api' / 'data.zip').namelist() == ['CloudTAK-Data-1.2.0/icons/a.png']
    assert not (ct / 'api' / 'data.zip.part').exists()


def test_a_dropped_download_is_retried(ct, stub_urlopen):
    u = stub_urlopen([OSError('Connection reset by peer'), b'<html>504 Gateway Time-out</html>', _zip_bytes()])
    log = []
    ok, use_local, _ = _ns()['_cloudtak_prefetch_build_data'](str(ct), log.append)
    assert ok and use_local and len(u.calls) == 3
    assert sum('attempt' in l for l in log) == 2


def test_download_down_stops_with_a_reason_and_leaves_no_zip(ct, stub_urlopen):
    stub_urlopen([OSError('Name or service not known')] * 3)
    ok, use_local, err = _ns()['_cloudtak_prefetch_build_data'](str(ct), lambda m: None)
    assert not ok and not use_local
    assert 'could not download CloudTAK map data' in err and 'Name or service not known' in err
    assert not (ct / 'api' / 'data.zip').exists() and not (ct / 'api' / 'data.zip.part').exists()


def test_a_zip_that_is_not_cloudtak_data_is_refused(ct, stub_urlopen):
    stub_urlopen([_zip_bytes('something-else/')] * 3)
    ok, _, err = _ns()['_cloudtak_prefetch_build_data'](str(ct), lambda m: None)
    assert not ok and 'not the CloudTAK-Data archive' in err
    assert not (ct / 'api' / 'data.zip').exists()


def test_a_tree_without_the_data_stage_is_left_alone(ct, stub_urlopen):
    (ct / 'Dockerfile').write_text('FROM nginx:alpine\nRUN true\n')
    u = stub_urlopen([])
    assert _ns()['_cloudtak_prefetch_build_data'](str(ct), lambda m: None) == (True, False, '')
    assert u.calls == []


def test_only_https_urls_are_fetched(ct, stub_urlopen):
    (ct / 'Dockerfile').write_text(DOCKERFILE.replace('https://github.com', 'http://github.com'))
    u = stub_urlopen([])
    assert _ns()['_cloudtak_prefetch_build_data'](str(ct), lambda m: None) == (True, False, '')
    assert u.calls == []


def test_drop_build_data_removes_the_zip(ct):
    (ct / 'api' / 'data.zip').write_bytes(b'x')
    _ns()['_cloudtak_drop_build_data'](str(ct))
    assert not (ct / 'api' / 'data.zip').exists()
    _ns()['_cloudtak_drop_build_data'](str(ct))       # absent: no error


# --------------------------------------------------------------------------- #
# image snapshot / restore / rollback
# --------------------------------------------------------------------------- #

def test_snapshot_keeps_only_locally_built_images_and_pins_them(ct):
    run = Run(inspect_out=f'cloudtak-api {API_ID}\ncloudtak-events:latest {EV_ID}\n'
                          f'postgis/postgis:17-3.6-alpine sha256:{"c" * 64}\n'
                          f'dxflrs/garage:v2.4.1 sha256:{"d" * 64}\n')
    snap = _ns(run=run)['_cloudtak_snapshot_images'](str(ct))
    assert snap == [('cloudtak-api', API_ID), ('cloudtak-events:latest', EV_ID)]
    # Docker 29's containerd store deletes an untagged image once its container is replaced
    # (box test, ops #129) — the old images must hold a real tag until the update is over.
    assert ['docker', 'tag', API_ID, 'cloudtak-api:infratak-rollback'] in run.calls
    assert ['docker', 'tag', EV_ID, 'cloudtak-events:infratak-rollback'] in run.calls
    assert not [c for c in run.calls if c[:2] == ['docker', 'tag'] and 'postgis' in ' '.join(c)]


def test_an_image_that_cannot_be_pinned_is_not_in_the_snapshot(ct):
    run = Run(inspect_out=f'cloudtak-api {API_ID}\n', tag_rc=1)
    assert _ns(run=run)['_cloudtak_snapshot_images'](str(ct)) == []


def test_restore_points_each_tag_back_then_drops_the_pins(ct):
    run, log = Run(), []
    ok = _ns(run=run)['_cloudtak_restore_images']([('cloudtak-api', API_ID), ('cloudtak-events', EV_ID)], log.append)
    assert ok
    i_tag = run.calls.index(['docker', 'tag', API_ID, 'cloudtak-api'])
    assert ['docker', 'tag', EV_ID, 'cloudtak-events'] in run.calls
    i_rm = run.calls.index(['docker', 'image', 'rm', 'cloudtak-api:infratak-rollback'])
    assert i_tag < i_rm


def test_a_failed_restore_keeps_the_pins_and_says_so(ct):
    run, log = Run(tag_rc=1), []
    assert _ns(run=run)['_cloudtak_restore_images']([('cloudtak-api', API_ID)], log.append) is False
    assert not [c for c in run.calls if c[:3] == ['docker', 'image', 'rm']]
    assert any('Could not point cloudtak-api back' in l for l in log)


def test_rollback_reverts_tree_then_tags_then_starts_without_building(ct):
    order, compose, run = [], Compose(), Run()
    ns = _ns(compose=compose, run=run)
    ns['_cloudtak_revert_checkout'] = lambda *a, **k: order.append('revert') or True
    real_restore = ns['_cloudtak_restore_images']
    ns['_cloudtak_restore_images'] = lambda s, p, **k: order.append('tags') or real_restore(s, p, **k)
    real_compose = ns['_cloudtak_compose_run']

    def _c(d, args, timeout=600):
        if args[:1] == ['up']:
            order.append('up')
        return real_compose(d, args, timeout)
    ns['_cloudtak_compose_run'] = _c
    log = []
    ok = ns['_cloudtak_rollback_after_failed_up'](str(ct), 'f' * 40, [('cloudtak-api', API_ID)], log.append,
                                                  expect_version='13.109.3')
    assert ok, log
    assert order == ['revert', 'tags', 'up']
    assert ['up', '-d', '--no-build'] in compose.calls
    assert ['up', '-d'] not in compose.calls                   # never a plain up (would build/recreate new)
    assert any('running on the previous version again (13.109.3)' in l for l in log)


def test_rollback_is_judged_by_the_version_actually_running(ct):
    # Box test, first cut: "running on the previous version" was printed while the NEW images
    # served — the check only asked whether api was up.
    ns = _ns(run=Run(version='13.111.3'))
    ns['_cloudtak_revert_checkout'] = lambda *a, **k: True
    log = []
    assert ns['_cloudtak_rollback_after_failed_up'](str(ct), 'f' * 40, [('cloudtak-api', API_ID)], log.append,
                                                    expect_version='13.109.3') is False
    assert any('running 13.111.3, not the previous 13.109.3' in l for l in log)
    assert not any('previous version again' in l for l in log)


def test_rollback_does_not_start_anything_when_an_old_image_is_missing(ct):
    compose = Compose()
    ns = _ns(compose=compose, run=Run(tag_rc=1))
    ns['_cloudtak_revert_checkout'] = lambda *a, **k: True
    log = []
    assert ns['_cloudtak_rollback_after_failed_up'](str(ct), 'f' * 40, [('cloudtak-api', API_ID)], log.append) is False
    assert not [c for c in compose.calls if c[:1] == ['up']]   # would start NEW images on the OLD tree


def test_rollback_without_a_snapshot_does_not_touch_anything(ct):
    compose = Compose()
    ns = _ns(compose=compose)
    ns['_cloudtak_revert_checkout'] = lambda *a, **k: pytest.fail('must not revert without images to match')
    assert ns['_cloudtak_rollback_after_failed_up'](str(ct), 'f' * 40, [], lambda m: None) is False
    assert compose.calls == []


def test_rollback_reports_when_the_old_stack_will_not_start(ct):
    compose = Compose(fail_on=['up', '-d', '--no-build'])
    ns = _ns(compose=compose)
    ns['_cloudtak_revert_checkout'] = lambda *a, **k: True
    log = []
    assert ns['_cloudtak_rollback_after_failed_up'](str(ct), 'f' * 40, [('cloudtak-api', API_ID)], log.append) is False
    assert any('failed too' in l for l in log)


def test_running_version_prefers_the_container_over_the_tree(ct):
    (ct / 'api' / 'package.json').write_text('{"version": "13.111.3"}')
    assert _ns()['_cloudtak_running_version'](str(ct)) == '13.109.3'
    compose = Compose(fail_on=['ps', '-q', 'api'])
    assert _ns(compose=compose)['_cloudtak_running_version'](str(ct)) == '13.111.3'


# --------------------------------------------------------------------------- #
# wiring in run_cloudtak_update (local branch)
# --------------------------------------------------------------------------- #

def _update_body():
    body = APP[APP.index('def run_cloudtak_update('):]
    return re.sub(r'#.*', '', body[:body.index('\ndef ', 1)])


def test_update_prefetches_then_snapshots_before_the_build():
    b = _update_body()
    i_pre = b.index('_cloudtak_prefetch_build_data(cloudtak_dir, plog)')
    i_snap = b.index('_ct_snap = _cloudtak_snapshot_images(cloudtak_dir)')
    i_build = b.index("f'{dcc} build --no-cache'")
    assert i_pre < i_snap < i_build          # a failed prefetch leaves no rollback pins behind
    assert "' --build-arg USE_LOCAL_ZIP=true' if _use_local_zip" in b
    # a failed prefetch stops before anything is built and reverts the checkout
    stop = b[i_pre:i_snap]
    assert '_cloudtak_revert_checkout(prev_sha, plog, cloudtak_dir=cloudtak_dir)' in stop
    assert 'return' in stop


def test_a_successful_update_drops_the_rollback_pins():
    b = _update_body()
    i_up = b.index("_cloudtak_compose_run(cloudtak_dir, ['up', '-d'], timeout=1800)")
    i_ok = b.index('plog("✓ Containers rebuilt and restarted")')
    assert '_cloudtak_drop_rollback_pins(_ct_snap)' in b[i_up:i_ok]
    assert 'expect_version=from_ver' in b[i_up:i_ok]


def test_every_local_failure_after_the_build_puts_the_image_tags_back():
    b = _update_body()
    i_build = b.index("f'{dcc} build --no-cache'")
    tail = b[i_build:]
    # build failed, build timed out, Garage step failed
    assert tail.count('_cloudtak_restore_images(_ct_snap, plog)') >= 3
    # up -d failed: the full rollback, and the reason on the ✗ line
    i_up = tail.index("_cloudtak_compose_run(cloudtak_dir, ['up', '-d'], timeout=1800)")
    after = tail[i_up:]
    assert '_cloudtak_rollback_after_failed_up(cloudtak_dir, prev_sha, _ct_snap, plog,' in after
    assert '_why = _update_error_line(_uout)' in after
    assert after.index('_cloudtak_rollback_after_failed_up(') < after.index("plog(\"✓ Containers rebuilt and restarted\")")


def test_up_failure_after_a_fresh_minio_move_does_not_roll_back_to_minio():
    b = _update_body()
    assert "_had_minio_store = os.path.isdir(os.path.join(cloudtak_dir, '.docker-store'))" in b
    i = b.index('if _migrated_now:')
    j = b.index('_cloudtak_rollback_after_failed_up(', i)
    assert 'else:' in b[i:j]


# --------------------------------------------------------------------------- #
# ops #133: the same pins and rollback for a CloudTAK on a remote host
# --------------------------------------------------------------------------- #

def test_local_helpers_never_reach_for_ssh(ct):
    ssh = Ssh()
    ns = _ns(run=Run(inspect_out=f'cloudtak-api {API_ID}\n'), ssh=ssh)
    snap = ns['_cloudtak_snapshot_images'](str(ct))
    assert snap == [('cloudtak-api', API_ID)]
    assert ns['_cloudtak_restore_images'](snap, lambda m: None)
    assert ssh.cmds == []


def test_remote_snapshot_pins_on_the_remote_host(ct):
    ssh = Ssh(inspect_out=f'cloudtak-api {API_ID}\nnodered/node-red:4.1.16-22 sha256:{"c" * 64}')
    ns = _ns(run=_no_local, compose=_no_local, ssh=ssh)
    assert ns['_cloudtak_snapshot_images'](None, remote_cfg=REMOTE) == [('cloudtak-api', API_ID)]
    assert ssh.cmds[0] == 'cd ~/CloudTAK && docker compose ps -a -q'
    # the Go template reaches the remote shell as ONE quoted word, not split or expanded
    assert ssh.cmds[1].startswith("docker inspect -f '{{.Config.Image}} {{.Image}}' " + '1' * 12)
    assert f'docker tag {API_ID} cloudtak-api:infratak-rollback' in ssh.cmds
    assert not [c for c in ssh.cmds if 'node-red' in c and c.startswith('docker tag')]


def test_remote_restore_tags_back_then_drops_the_pins(ct):
    ssh = Ssh()
    log = []
    ok = _ns(run=_no_local, ssh=ssh)['_cloudtak_restore_images']([('cloudtak-api', API_ID)], log.append,
                                                                remote_cfg=REMOTE)
    assert ok
    assert ssh.cmds == [f'docker tag {API_ID} cloudtak-api', 'docker image rm cloudtak-api:infratak-rollback']
    assert any('Image tags put back' in l for l in log)


def test_remote_failed_restore_keeps_the_pins_and_says_why(ct):
    ssh, log = Ssh(tag_ok=False), []
    assert _ns(run=_no_local, ssh=ssh)['_cloudtak_restore_images'](
        [('cloudtak-api', API_ID)], log.append, remote_cfg=REMOTE) is False
    assert not [c for c in ssh.cmds if c.startswith('docker image rm')]
    assert any('No such image' in l for l in log)


def test_remote_rollback_reverts_remote_tree_then_tags_then_starts_without_building(ct):
    ssh = Ssh()
    ns = _ns(run=_no_local, compose=_no_local, ssh=ssh)
    reverted = []
    ns['_cloudtak_revert_checkout'] = lambda *a, **k: reverted.append(k) or True
    log = []
    ok = ns['_cloudtak_rollback_after_failed_up'](None, 'f' * 40, [('cloudtak-api', API_ID)], log.append,
                                                  expect_version='13.109.3', remote_cfg=REMOTE)
    assert ok, log
    assert reverted == [{'remote_cfg': REMOTE}]
    i_tag = ssh.cmds.index(f'docker tag {API_ID} cloudtak-api')
    i_up = ssh.cmds.index('cd ~/CloudTAK && docker compose up -d --no-build')
    assert i_tag < i_up
    assert 'cd ~/CloudTAK && docker compose up -d' not in ssh.cmds
    assert any(c.startswith('docker exec ' + '9' * 12 + ' node -e') for c in ssh.cmds)
    assert any('running on the previous version again (13.109.3)' in l for l in log)


def test_remote_rollback_does_not_start_anything_when_an_old_image_is_missing(ct):
    ssh = Ssh(tag_ok=False)
    ns = _ns(run=_no_local, compose=_no_local, ssh=ssh)
    ns['_cloudtak_revert_checkout'] = lambda *a, **k: True
    assert ns['_cloudtak_rollback_after_failed_up'](None, 'f' * 40, [('cloudtak-api', API_ID)], lambda m: None,
                                                    remote_cfg=REMOTE) is False
    assert not [c for c in ssh.cmds if ' up ' in c]


def test_remote_running_version_prefers_the_container_then_the_tree(ct):
    assert _ns(run=_no_local, ssh=Ssh())['_cloudtak_running_version'](None, remote_cfg=REMOTE) == '13.109.3'
    no_api = Ssh(fail_on='ps -q api')
    assert _ns(run=_no_local, ssh=no_api)['_cloudtak_running_version'](None, remote_cfg=REMOTE) == '13.111.3'
    assert _ns(run=_no_local, ssh=Ssh(fail_on='ps -q api'))['_cloudtak_running_version'](
        None, container_only=True, remote_cfg=REMOTE) == ''


def _remote_body():
    b = _update_body()
    i = b.index('build_cmd = f"cd ~/CloudTAK && {dcc} build --no-cache"')
    return b[b.rindex('if is_remote:', 0, i):b.index('else:\n            cloudtak_dir = os.path.expanduser', i)]


def test_remote_update_pins_before_the_build_and_puts_tags_back_on_every_failure():
    r = _remote_body()
    i_snap = r.index('_ct_snap = _cloudtak_snapshot_images(None, remote_cfg=remote_cfg)')
    i_build = r.index('_ssh_probe(remote_cfg, build_cmd, timeout=5400)')
    assert i_snap < i_build
    tail = r[i_build:]
    # build failed, Garage step failed
    assert tail.count('_cloudtak_restore_images(_ct_snap, plog, remote_cfg=remote_cfg)') == 2
    i_gr = tail.index('_cloudtak_remote_garage_rollback(remote_cfg, prev_sha, plog)')
    assert tail.index('_cloudtak_restore_images(', i_gr) > i_gr


def test_remote_up_failure_rolls_back_unless_the_files_just_moved_to_garage():
    r = _remote_body()
    i_up = r.index('f"cd ~/CloudTAK && {dcc} up -d"')
    after = r[i_up:]
    assert '_why = _update_error_line(out)' in after
    i_mig = after.index('if _migrated_now:')
    i_rb = after.index('_cloudtak_rollback_after_failed_up(None, prev_sha, _ct_snap, plog,')
    assert i_mig < i_rb and 'else:' in after[i_mig:i_rb]
    assert 'expect_version=from_ver, remote_cfg=remote_cfg' in after
    # success: the pins go
    assert after.rstrip().endswith('_cloudtak_drop_rollback_pins(_ct_snap, remote_cfg=remote_cfg)')
    # the MinIO check brackets the Garage step
    assert r.index('_had_minio_store = ') < r.index('_cloudtak_remote_compose_is_garage(remote_cfg)') \
        < r.index('_migrated_now = ')


class PluginRun(Run):
    """Run, plus what `docker image inspect cloudtak-api` says the tag points at now."""
    def __init__(self, tag_now=API_ID, **kw):
        super().__init__(inspect_out=f'cloudtak-api {API_ID}\n', **kw)
        self.tag_now = tag_now

    def __call__(self, argv, **kw):
        if argv[:3] == ['docker', 'image', 'inspect']:
            self.calls.append(list(argv))
            return type('R', (), {'returncode': 0, 'stdout': self.tag_now + '\n', 'stderr': ''})()
        return super().__call__(argv, **kw)


def _plugin_snap(ct, run, compose=None):
    (ct / 'api' / 'routes').mkdir(parents=True)
    web = ct / 'web-plugin'
    web.mkdir()
    ns = _ns(run=run, compose=compose or Compose())
    return ns, str(web), ns['_snapshot_cloudtak_plugin_state'](str(ct), str(web))


def test_plugin_snapshot_pins_the_api_image_before_the_build(ct):
    compose, run = Compose(), PluginRun()
    ns, web, snap = _plugin_snap(ct, run, compose)
    assert ['ps', '-a', '-q', 'api'] in compose.calls          # api only: the plugin rebuild builds api alone
    assert snap['api_images'] == [('cloudtak-api', API_ID)]
    assert ['docker', 'tag', API_ID, 'cloudtak-api:infratak-rollback'] in run.calls


def test_plugin_rollback_after_the_tag_moved_puts_it_back_from_the_pin(ct):
    # test8, Docker 29.9.1: once the build moves the tag the old ID is gone for `docker tag`,
    # running container or not — the retag only works because of the pin.
    run, log = PluginRun(tag_now=EV_ID), []
    ns, web, snap = _plugin_snap(ct, run)
    run.calls.clear()
    ns['_rollback_cloudtak_plugin_state'](str(ct), web, snap, log.append)
    i_tag = run.calls.index(['docker', 'tag', API_ID, 'cloudtak-api'])
    i_rm = run.calls.index(['docker', 'image', 'rm', 'cloudtak-api:infratak-rollback'])
    assert i_tag < i_rm
    assert any('Image tags put back' in l for l in log)
    run.calls.clear()
    ns['_cleanup_snapshot'](snap)                              # the finally: nothing left to do
    assert run.calls == []


def test_plugin_rollback_with_the_tag_unmoved_only_drops_the_pin(ct):
    run = PluginRun(tag_now=API_ID)
    ns, web, snap = _plugin_snap(ct, run)
    run.calls.clear()
    ns['_rollback_cloudtak_plugin_state'](str(ct), web, snap, lambda m: None)
    assert not [c for c in run.calls if c[:2] == ['docker', 'tag']]
    assert ['docker', 'image', 'rm', 'cloudtak-api:infratak-rollback'] in run.calls


def test_plugin_rollback_that_cannot_retag_keeps_the_pin_and_says_so(ct):
    run, log = PluginRun(tag_now=EV_ID), []
    ns, web, snap = _plugin_snap(ct, run)
    run.tag_rc = 1
    run.calls.clear()
    ns['_rollback_cloudtak_plugin_state'](str(ct), web, snap, log.append)
    ns['_cleanup_snapshot'](snap)
    assert not [c for c in run.calls if c[:3] == ['docker', 'image', 'rm']]
    assert any('Could not point cloudtak-api back' in l for l in log)
    assert not any('Re-pointed' in l for l in log)


def test_a_finished_plugin_action_drops_the_pin(ct):
    run = PluginRun()
    ns, web, snap = _plugin_snap(ct, run)
    run.calls.clear()
    ns['_cleanup_snapshot'](snap)
    assert run.calls == [['docker', 'image', 'rm', 'cloudtak-api:infratak-rollback']]


def test_remote_from_version_is_what_the_remote_container_runs():
    b = _update_body()
    assert "from_ver = _cloudtak_running_version(None, remote_cfg=remote_cfg) if remote_host else ''" in b
