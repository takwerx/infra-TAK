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
"""TAK Portal and Remote Assist rebuild on a fresh base image (ops #135).

`docker compose up -d --build` never pulls: a `node:22-alpine` already on the box is reused,
so Remote Assist on test6 was still on Node 22.23.0 after Docker Hub had 22.23.4. Every Deploy
and Update of both now `docker pull`s each Dockerfile FROM image, then builds without --pull.

The first cut ran `docker compose build --pull` and "fell back" to a plain build when that
failed. T&E (ops #136, test8 with Docker Hub blocked) showed the fallback never worked: with
the containerd image store a base BuildKit fetched itself is not a tagged image, so the plain
build asked the registry again and failed too. A `docker pull` tags it, so the build after a
failed pull runs on the copy on the box. A failed or hung pull must never stop the build.
"""

import os
import pathlib
import re
import subprocess
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
HELPER = APP[APP.index('_DOCKERFILE_FROM_RE = '):APP.index('def _remote_assist_compose_files(')]


def _ns(results=None, exc=None):
    """Load the helpers with a fake subprocess. `results` maps image -> run result."""
    calls = []

    def run(argv, **kw):
        calls.append((argv, kw))
        if exc:
            raise exc
        return (results or {}).get(argv[-1], _r(0))

    fake = types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired)
    n = {'subprocess': fake, 'os': os, 're': re, 'print': lambda *a, **k: None}
    exec(compile(HELPER, 'app.py', 'exec'), n)
    return n, calls


def _r(rc, out='', err=''):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def _portal(d):
    """TAK Portal's layout: one Dockerfile at the top of the checkout."""
    d.mkdir(exist_ok=True)
    (d / 'Dockerfile').write_text('# syntax=docker/dockerfile:1\nFROM node:22-alpine\nWORKDIR /usr/src/app\n')
    return str(d)


def _remote_assist(d):
    """Remote Assist's layout: server/ and web/ Dockerfiles, both multi-stage."""
    for sub in ('server', 'web', 'node_modules'):
        (d / sub).mkdir(parents=True, exist_ok=True)
    (d / 'server' / 'Dockerfile').write_text(
        'FROM node:22-alpine AS builder\nRUN npm ci\nFROM node:22-alpine\nCOPY --from=builder /a /a\n')
    (d / 'web' / 'Dockerfile').write_text(
        'FROM node:22-alpine AS builder\nRUN npm run build\nfrom --platform=linux/arm64 nginx:alpine\n')
    return str(d)


def test_base_images_of_both_layouts(tmp_path):
    n, _ = _ns()
    assert n['_dockerfile_base_images'](_portal(tmp_path / 'portal')) == ['node:22-alpine']
    assert n['_dockerfile_base_images'](_remote_assist(tmp_path / 'ra')) == ['node:22-alpine', 'nginx:alpine']


def test_stage_names_scratch_and_args_are_not_pulled(tmp_path):
    (tmp_path / 'Dockerfile').write_text(
        'ARG BASE=node:22\nFROM $BASE AS deps\nFROM deps AS build\nFROM BUILD\nFROM scratch\nFROM alpine:3.22\n')
    n, _ = _ns()
    assert n['_dockerfile_base_images'](str(tmp_path)) == ['alpine:3.22']


def test_no_dockerfile_pulls_nothing(tmp_path):
    n, calls = _ns()
    assert n['_pull_base_images'](str(tmp_path / 'missing')) == []
    assert calls == []


def test_each_base_is_pulled_through_wrap(tmp_path):
    n, calls = _ns()
    logs = []
    failed = n['_pull_base_images'](_remote_assist(tmp_path), wrap=lambda a: ['brokerctl', 'exec', '--'] + a,
                                    plog=logs.append)
    assert failed == []
    assert [c[0] for c in calls] == [['brokerctl', 'exec', '--', 'docker', 'pull', 'node:22-alpine'],
                                     ['brokerctl', 'exec', '--', 'docker', 'pull', 'nginx:alpine']]
    assert all(c[1]['timeout'] == 300 and c[1]['cwd'] == str(tmp_path) for c in calls)
    assert sum('current' in m for m in logs) == 2


def test_a_failed_pull_is_logged_and_does_not_raise(tmp_path):
    err = ('Using default tag: latest\n'
           'Error response from daemon: Get "https://registry-1.docker.io/v2/": dial tcp 0.0.0.0:443: '
           'connect: connection refused\n')
    n, calls = _ns({'node:22-alpine': _r(1, err=err)})
    logs = []
    failed = n['_pull_base_images'](_remote_assist(tmp_path), plog=logs.append)
    assert failed == ['node:22-alpine']
    assert len(calls) == 2  # nginx:alpine is still tried
    warn = [m for m in logs if '⚠' in m]
    assert len(warn) == 1 and 'node:22-alpine' in warn[0] and 'connection refused' in warn[0]
    assert 'Using default tag' not in warn[0]  # the actual error, not other output


def test_a_timeout_or_missing_docker_does_not_raise(tmp_path):
    for exc in (subprocess.TimeoutExpired(['docker'], 300), FileNotFoundError('docker')):
        n, _ = _ns(exc=exc)
        logs = []
        assert n['_pull_base_images'](_portal(tmp_path), plog=logs.append) == ['node:22-alpine']
        assert any('⚠' in m for m in logs)


def _body(start, end):
    return APP[APP.index(start):APP.index(end)]


SITES = [
    ('remote assist deploy', 'def _run_remote_assist_deploy(', 'def _remote_assist_github_repo_path(',
     '_pull_base_images(ra_dir, plog=plog)',
     "_remote_assist_compose_cmd(ra_dir, 'up', '-d', '--build')"),
    ('remote assist update', 'def _run_remote_assist_update(', "@app.route('/api/remote-assist/version')",
     '_pull_base_images(ra_dir, plog=plog)',
     "_remote_assist_compose_cmd(ra_dir, 'up', '-d', '--build')"),
    ('tak portal update', 'def _takportal_run_update(portal_dir):', "@app.route('/api/takportal/update/status')",
     '_pull_base_images(portal_dir, wrap=_sudo_wrap)',
     "_sudo_wrap(['docker', 'compose', 'up', '-d', '--build'])"),
    ('tak portal deploy', 'def run_takportal_deploy():', '_ensure_infratak_network_for_portal()\n        _ensure_infratak_network_for_authentik()\n\n        # Seed real settings.json',
     '_pull_base_images(portal_dir, wrap=_sudo_wrap, plog=plog)',
     "_sudo_wrap(['docker', 'compose', 'up', '-d', '--build', '--no-start'])"),
]


def test_every_build_pulls_first_and_builds_without_pull():
    for name, start, end, pull, build in SITES:
        body = _body(start, end)
        assert pull in body, name
        assert build in body, name
        assert body.index(pull) < body.index(build), name
        # `--pull` on the build is what made the build itself need the registry
        assert "'--pull'" not in body, name


def test_build_pull_helper_is_gone():
    assert '_compose_build_pull' not in APP
