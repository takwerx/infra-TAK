# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #841 / infra-TAK #523: First Due ETL build failed with
`network mode "cloudtak_etl" not supported by buildkit` on a console that runs as root.

Cause: `_sudo_wrap` returns the bare argv for a root console, so `docker build --network
cloudtak_etl` ran straight under BuildKit (and skipped the broker's egress gate). Every fleet box
runs the console as takwerx, where `_sudo_wrap` already routes through the broker, so it never
showed there. The broker is the only place that sets DOCKER_BUILDKIT=0 for this build, so the
console must send it there whoever it runs as.

These tests run the real `_etlcat_build` out of app.py as a root console would: `_sudo_wrap` is
the root-console version (argv unchanged).
"""
import ast
import os
import pathlib
import shutil
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
_FNS = {n.name: n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef)}

PREFIX = ['/usr/bin/python3', '-I', '-S', '/opt/infratak/broker/takwerx_brokerctl.py', 'exec', '--']
SHA = 'a' * 40


def _ns(socket_present, runs):
    class CP:
        def __init__(self, rc=0, out='', err=''):
            self.returncode, self.stdout, self.stderr = rc, out, err

    def fake_run(argv, **kw):
        runs.append(list(argv))
        return CP()

    def git(args, cwd=None, timeout=300):
        r = CP(0, SHA if args[0] == 'rev-parse' else '')
        return r

    ns = {
        'os': os, 'shutil': shutil, 'json': __import__('json'),
        '_b64': __import__('base64'),
        'subprocess': types.SimpleNamespace(run=fake_run),
        '_etl': types.SimpleNamespace(
            image_tag=lambda p, v: f'etl-local:{p}-{v}', SHA_LABEL='org.sha', CAP_LABEL='org.cap',
            ETL_NETWORK='cloudtak_etl'),
        # a root console: the privileged-command wrapper leaves argv alone
        '_sudo_wrap': lambda cmd: list(cmd),
        '_broker_socket_present': lambda: socket_present,
        '_broker_client_prefix': lambda: list(PREFIX),
        '_etlcat_src_root': lambda: str(ns['_tmp']),
        '_etlcat_git': git,
        '_ETLCAT_LOGO_MAX': 1024,
    }
    for name in ('_etl_build_cmd', '_etlcat_build'):
        if name not in _FNS:      # base code has no helper: the build test must fail on behavior
            continue
        exec(compile(ast.get_source_segment(APP, _FNS[name]), 'app.py', 'exec'), ns)
    return ns


def _entry():
    return {'prefix': 'first-due', 'version': 'v1.3.0', 'sha': SHA, 'ref': 'v1.3.0',
            'source': 'dfpc-coe/etl-first-due'}


def test_root_console_sends_the_etl_build_through_the_broker(tmp_path):
    runs, logs = [], []
    ns = _ns(True, runs)
    ns['_tmp'] = tmp_path
    ok, _logo = ns['_etlcat_build'](_entry(), logs.append)
    assert ok, logs
    builds = [r for r in runs if r[len(PREFIX):len(PREFIX) + 2] == ['docker', 'build']]
    assert len(builds) == 1, runs
    b = builds[0]
    assert b[:len(PREFIX)] == PREFIX
    assert b[b.index('--network') + 1] == 'cloudtak_etl'
    # no `docker build` ever runs bare (that is BuildKit, no gate)
    assert not [r for r in runs if r[:2] == ['docker', 'build']]


def test_no_broker_socket_refuses_the_build_instead_of_running_bare(tmp_path):
    runs, logs = [], []
    ns = _ns(False, runs)
    ns['_tmp'] = tmp_path
    ok, _logo = ns['_etlcat_build'](_entry(), logs.append)
    assert ok is False
    assert not [r for r in runs if 'build' in r], runs
    assert any('broker is not running' in m for m in logs), logs


def test_build_cmd_is_the_broker_prefix_plus_argv():
    assert '_etl_build_cmd' in _FNS
    ns = _ns(True, [])
    assert ns['_etl_build_cmd'](['docker', 'build', '.']) == PREFIX + ['docker', 'build', '.']
    ns = _ns(False, [])
    assert ns['_etl_build_cmd'](['docker', 'build', '.']) is None


def test_non_root_console_runs_the_same_argv_as_before():
    """Regression: a console that already routes through the broker (every fresh install, the
    whole fleet) must run exactly what _sudo_wrap gave it before this fix."""
    ns = {'os': os, '_sys': types.SimpleNamespace(executable='/usr/bin/python3'),
          '_BROKER_CLIENT_PYFLAGS': ['-I', '-S'], '_BROKER_CLIENT': '/opt/infratak/broker/takwerx_brokerctl.py',
          '_broker_should_route': lambda: True, '_broker_available': lambda: True,
          '_broker_socket_present': lambda: True}
    for name in ('_broker_client_prefix', '_sudo_wrap', '_etl_build_cmd'):
        exec(compile(ast.get_source_segment(APP, _FNS[name]), 'app.py', 'exec'), ns)
    argv = ['docker', 'build', '--network', 'cloudtak_etl', '--force-rm', '-t', 'x', '/src']
    assert ns['_etl_build_cmd'](argv) == ns['_sudo_wrap'](argv)
