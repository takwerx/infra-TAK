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
import zipfile

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_FUNCS = {
    '_cloudtak_running_version', '_cloudtak_snapshot_images', '_cloudtak_restore_images',
    '_cloudtak_rollback_after_failed_up', '_cloudtak_prefetch_build_data',
    '_cloudtak_drop_build_data',
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
    """Stand-in for subprocess.run: records argv, answers `docker inspect` from a table."""
    def __init__(self, inspect_out='', tag_rc=0, running='true'):
        self.calls, self.inspect_out, self.tag_rc, self.running = [], inspect_out, tag_rc, running

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        out, rc = '', 0
        if argv[:2] == ['docker', 'inspect'] and '{{.State.Running}}' in argv:
            out = self.running
        elif argv[:2] == ['docker', 'inspect']:
            out = self.inspect_out
        elif argv[:2] == ['docker', 'tag']:
            rc = self.tag_rc
        elif argv[:2] == ['docker', 'exec']:
            out = '13.109.3'
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


def _ns(compose=None, run=None):
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
    ns = {'os': os, 're': re, 'json': json, 'VERSION': '10.2.24-alpha',
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

def test_snapshot_keeps_only_locally_built_images(ct):
    run = Run(inspect_out=f'cloudtak-api {API_ID}\ncloudtak-events {EV_ID}\n'
                          f'postgis/postgis:17-3.6-alpine sha256:{"c" * 64}\n'
                          f'dxflrs/garage:v2.4.1 sha256:{"d" * 64}\n')
    snap = _ns(run=run)['_cloudtak_snapshot_images'](str(ct))
    assert snap == [('cloudtak-api', API_ID), ('cloudtak-events', EV_ID)]


def test_restore_points_each_tag_back(ct):
    run, log = Run(), []
    n = _ns(run=run)['_cloudtak_restore_images']([('cloudtak-api', API_ID), ('cloudtak-events', EV_ID)], log.append)
    assert n == 2
    assert ['docker', 'tag', API_ID, 'cloudtak-api'] in run.calls
    assert ['docker', 'tag', EV_ID, 'cloudtak-events'] in run.calls


def test_rollback_reverts_tree_then_tags_then_starts_without_building(ct):
    order, compose, run = [], Compose(), Run()
    ns = _ns(compose=compose, run=run)
    ns['_cloudtak_revert_checkout'] = lambda *a, **k: order.append('revert') or True
    real_restore = ns['_cloudtak_restore_images']
    ns['_cloudtak_restore_images'] = lambda s, p: order.append('tags') or real_restore(s, p)
    real_compose = ns['_cloudtak_compose_run']

    def _c(d, args, timeout=600):
        if args[:1] == ['up']:
            order.append('up')
        return real_compose(d, args, timeout)
    ns['_cloudtak_compose_run'] = _c
    log = []
    ok = ns['_cloudtak_rollback_after_failed_up'](str(ct), 'f' * 40, [('cloudtak-api', API_ID)], log.append)
    assert ok, log
    assert order == ['revert', 'tags', 'up']
    assert ['up', '-d', '--no-build'] in compose.calls
    assert ['up', '-d'] not in compose.calls                   # never a plain up (would build/recreate new)
    assert any('running on the previous version' in l for l in log)


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


def test_update_snapshots_and_prefetches_before_the_build():
    b = _update_body()
    i_snap = b.index('_ct_snap = _cloudtak_snapshot_images(cloudtak_dir)')
    i_pre = b.index('_cloudtak_prefetch_build_data(cloudtak_dir, plog)')
    i_build = b.index("f'{dcc} build --no-cache'")
    assert i_snap < i_pre < i_build
    assert "' --build-arg USE_LOCAL_ZIP=true' if _use_local_zip" in b
    # a failed prefetch stops before anything is built and reverts the checkout
    stop = b[i_pre:i_build]
    assert '_cloudtak_revert_checkout(prev_sha, plog, cloudtak_dir=cloudtak_dir)' in stop
    assert 'return' in stop


def test_every_local_failure_after_the_build_puts_the_image_tags_back():
    b = _update_body()
    i_build = b.index("f'{dcc} build --no-cache'")
    tail = b[i_build:]
    # build failed, build timed out, Garage step failed
    assert tail.count('_cloudtak_restore_images(_ct_snap, plog)') >= 3
    # up -d failed: the full rollback, and the reason on the ✗ line
    i_up = tail.index("_cloudtak_compose_run(cloudtak_dir, ['up', '-d'], timeout=1800)")
    after = tail[i_up:]
    assert '_cloudtak_rollback_after_failed_up(cloudtak_dir, prev_sha, _ct_snap, plog)' in after
    assert '_why = _update_error_line(_uout)' in after
    assert after.index('_cloudtak_rollback_after_failed_up(') < after.index("plog(\"✓ Containers rebuilt and restarted\")")


def test_up_failure_after_a_fresh_minio_move_does_not_roll_back_to_minio():
    b = _update_body()
    assert "_had_minio_store = os.path.isdir(os.path.join(cloudtak_dir, '.docker-store'))" in b
    i = b.index('if _migrated_now:')
    j = b.index('_cloudtak_rollback_after_failed_up(', i)
    assert 'else:' in b[i:j]
