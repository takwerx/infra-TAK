# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ETL Runner pre-land /module-scan fixes (2026-11-09), console + broker side.

Pins:
  * ETL images build on the ETL network, so third-party RUN steps get the W5 egress block
    (live proof: BuildKit's default bridge reached 169.254.169.254 with HTTP 200); the broker
    runs exactly that argv with DOCKER_BUILDKIT=0 and refuses it when the block is not enforced;
  * no other argv gets a caller-chosen environment;
  * catalog git is https-only with LFS smudge off; catalog URLs sent to CloudTAK are github only;
  * the overlay temp file never inherits an old, wider mode.
"""
import ast
import importlib.util
import json
import os
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
_FNS = {n.name: n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef)}


def _src(name):
    return ast.get_source_segment(APP, _FNS[name])


@pytest.fixture
def b():
    spec = importlib.util.spec_from_file_location('tb_etl_sr', ROOT / 'broker' / 'takwerx_broker.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_build_runs_on_the_etl_network():
    src = _src('_etlcat_build')
    assert "'docker', 'build', '--network', _etl.ETL_NETWORK" in src
    assert "'--network', 'host'" not in src


@pytest.mark.parametrize('argv,yes', [
    (['docker', 'build', '--network', 'cloudtak_etl', '-t', 'x', '/s'], True),
    (['/usr/bin/docker', 'build', '--label', 'a=b', '--network=cloudtak_etl', '/s'], True),
    (['docker', 'build', '--network', 'host', '/s'], False),
    (['docker', 'build', '/s'], False),
    (['docker', 'run', '--network', 'cloudtak_etl', 'img'], False),
    (['docker', 'compose', 'build', '--network', 'cloudtak_etl'], False),
    (['apt-get', 'build', '--network', 'cloudtak_etl'], False),
])
def test_is_etl_build(b, argv, yes):
    assert b._is_etl_build(argv) is yes


def test_exec_sets_buildkit_off_only_for_the_etl_build(b):
    src = ast.get_source_segment(b.__loader__.get_source('tb_etl_sr'),
                                 next(n for n in ast.parse(b.__loader__.get_source('tb_etl_sr')).body
                                      if isinstance(n, ast.FunctionDef) and 'DOCKER_BUILDKIT' in
                                      (ast.get_source_segment(b.__loader__.get_source('tb_etl_sr'), n) or '')))
    assert "env = dict(os.environ, DOCKER_BUILDKIT='0')" in src
    assert 'if _is_etl_build(argv):' in src
    assert "raise Denied(f'docker build on {ETL_NETWORK}: {why}')" in src


def test_gate_refusal_blocks_the_build(b):
    fn = next(n for n in ast.parse(b.__loader__.get_source('tb_etl_sr')).body
              if isinstance(n, ast.FunctionDef) and "_is_etl_build(argv)" in
              (ast.get_source_segment(b.__loader__.get_source('tb_etl_sr'), n) or '')
              and n.name != '_is_etl_build')
    # the gate check comes before the env is set and before subprocess.run
    body = ast.get_source_segment(b.__loader__.get_source('tb_etl_sr'), fn)
    assert body.index('_etl_egress_gate()') < body.index("DOCKER_BUILDKIT='0'") < body.index('subprocess.run(argv')


def test_git_is_https_only_without_lfs():
    src = _src('_etlcat_git')
    for flag in ("'protocol.allow=never'", "'protocol.https.allow=always'", "'filter.lfs.smudge='",
                 "'GIT_LFS_SKIP_SMUDGE': '1'"):
        assert flag in src


@pytest.mark.parametrize('u,ok', [
    ('https://github.com/dfpc-coe/etl-cot', True),
    ('https://raw.githubusercontent.com/dfpc-coe/etl-cot/abc/README.md', True),
    ('http://github.com/x/y', False), ('https://evil.com/x', False),
    ('javascript:alert(1)', False), ('https://github.com/x/y?a=<b>', False), (None, False),
])
def test_gh_url(u, ok):
    ns = {'re': re}
    exec(compile(_src('_etlcat_gh_url'), 'app.py', 'exec'), ns)
    assert (ns['_etlcat_gh_url'](u) == u) is ok


def test_overlay_tmp_never_keeps_an_old_mode(tmp_path):
    ns = {'os': os}
    exec(compile(_src('_etlrunner_write'), 'app.py', 'exec'), ns)
    p = tmp_path / 'ov.yml'
    p.write_text('old')
    tmp = tmp_path / 'ov.yml.infratak-tmp'
    tmp.write_text('stale')
    os.chmod(tmp, 0o666)
    old = os.umask(0o022)
    try:
        assert ns['_etlrunner_write'](str(p), 'new', mode=0o600)
    finally:
        os.umask(old)
    assert p.read_text() == 'new' and p.stat().st_mode & 0o777 == 0o600


def test_egress_route_validates_before_the_broker():
    src = _src('cloudtak_etl_egress')
    assert src.index('_etl.egress_allow_norm(allow)') < src.index("_etlrunner_egress('apply'")
