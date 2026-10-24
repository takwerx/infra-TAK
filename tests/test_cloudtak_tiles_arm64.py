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
"""CloudTAK tiles runs on arm64 after an Update, not only after a Deploy.

aws-arm, v10.2.11 T&E: cloudtak-tiles-1 `Exited (1)`. The alpine→bookworm-slim swap that
lets @mapbox/vtquery's glibc arm64 prebuilt load ran only in Deploy. Update's
`git checkout -f <tag>` puts the tracked Dockerfile back to Alpine and rebuilds, so tiles
crashed again, and the old `restart: 'no'` gate kept it down for good.
"""

import ast
import os
import pathlib
import re
import shlex
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

ALPINE_DF = 'FROM node:26-alpine3.24\n\nEXPOSE 5002\n\nRUN npm install\n'
COMPOSE = """services:
    tiles:
        build:
          context: .
          dockerfile: ./tasks/pmtiles/Dockerfile.compose
        restart: 'always'
        ports:
            - "5002:5002"
"""


def _load(arch, *names):
    if '_patch_cloudtak_compose_ports' in names:
        # it also runs the media stream-port patch (ops #193)
        names += ('_CT_MEDIA_STREAM_PORTS', '_cloudtak_media_listen_patch')
    src = ''.join(ast.get_source_segment(APP, n) + '\n\n' for n in TREE.body
                  if (isinstance(n, ast.FunctionDef) and n.name in names)
                  or (isinstance(n, ast.Assign) and any(getattr(t, 'id', '') in names for t in n.targets)))
    ns = {'os': os, 're': re, 'shlex': shlex, 'subprocess': subprocess, '_host_arch': lambda: arch,
          '_CLOUDTAK_TILES_DOCKERFILE': os.path.join('tasks', 'pmtiles', 'Dockerfile.compose')}
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns


def _box(tmp_path, df=ALPINE_DF, compose=COMPOSE):
    (tmp_path / 'tasks' / 'pmtiles').mkdir(parents=True)
    (tmp_path / 'tasks' / 'pmtiles' / 'Dockerfile.compose').write_text(df)
    (tmp_path / 'docker-compose.yml').write_text(compose)
    return tmp_path


def _df(box):
    return (box / 'tasks' / 'pmtiles' / 'Dockerfile.compose').read_text()


def _restart(box):
    return re.search(r"restart:\s*(\S+)", (box / 'docker-compose.yml').read_text()).group(1)


def test_arm64_swaps_tiles_base_to_glibc_once(tmp_path):
    box = _box(tmp_path)
    ns = _load('arm64', '_patch_cloudtak_tiles_arm64')
    assert ns['_patch_cloudtak_tiles_arm64'](str(box)) is True
    assert _df(box).startswith('FROM node:26-bookworm-slim\n')
    assert ns['_patch_cloudtak_tiles_arm64'](str(box)) is False


def test_amd64_keeps_upstream_alpine(tmp_path):
    box = _box(tmp_path)
    ns = _load('amd64', '_patch_cloudtak_tiles_arm64')
    assert ns['_patch_cloudtak_tiles_arm64'](str(box)) is False
    assert _df(box) == ALPINE_DF


def test_arm64_gate_holds_tiles_down_while_it_still_builds_on_alpine(tmp_path):
    box = _box(tmp_path)
    ns = _load('arm64', '_patch_cloudtak_compose_ports', '_cloudtak_tiles_builds_on_alpine')
    ns['_patch_cloudtak_compose_ports'](str(box))
    assert _restart(box) == "'no'"


def test_arm64_tiles_restarts_always_once_it_builds_on_glibc(tmp_path):
    box = _box(tmp_path)
    ns = _load('arm64', '_patch_cloudtak_tiles_arm64', '_patch_cloudtak_compose_ports',
               '_cloudtak_tiles_builds_on_alpine')
    ns['_patch_cloudtak_tiles_arm64'](str(box))
    ns['_patch_cloudtak_compose_ports'](str(box))
    assert _restart(box) == "'always'"


def test_arm64_lifts_the_old_gate_on_a_glibc_build(tmp_path):
    # A box deployed with the swap but gated by the pre-fix code.
    box = _box(tmp_path, df='FROM node:26-bookworm-slim\n',
               compose=COMPOSE.replace("restart: 'always'", "restart: 'no'"))
    ns = _load('arm64', '_patch_cloudtak_compose_ports', '_cloudtak_tiles_builds_on_alpine')
    assert ns['_patch_cloudtak_compose_ports'](str(box)) is True
    assert _restart(box) == "'always'"


def test_amd64_compose_restart_untouched(tmp_path):
    box = _box(tmp_path)
    ns = _load('amd64', '_patch_cloudtak_compose_ports', '_cloudtak_tiles_builds_on_alpine')
    ns['_patch_cloudtak_compose_ports'](str(box))
    assert _restart(box) == "'always'"


def _body(name):
    return ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name))


def test_update_reapplies_the_swap_before_the_compose_patch_and_build():
    body = _body('run_cloudtak_update')
    i_tiles = body.index('_patch_cloudtak_tiles_arm64(cloudtak_dir)')
    assert i_tiles < body.index('_patch_cloudtak_compose_ports(cloudtak_dir)')
    assert i_tiles < body.index("f'{dcc} build --no-cache'")


def test_deploy_applies_the_swap_before_the_compose_patch():
    body = _body('run_cloudtak_deploy')
    assert body.index('_patch_cloudtak_tiles_arm64(cloudtak_dir)') < \
        body.index('_patch_cloudtak_compose_ports(cloudtak_dir)')


def test_tiles_dockerfile_path_constant():
    assert "_CLOUDTAK_TILES_DOCKERFILE = os.path.join('tasks', 'pmtiles', 'Dockerfile.compose')" in APP
