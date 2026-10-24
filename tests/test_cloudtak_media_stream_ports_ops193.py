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
"""CloudTAK's stream URLs point at CloudTAK's media server, not the standalone MediaMTX.

GH #256 (ops #193): CloudTAK builds the RTSP/RTMP/SRT URLs it hands out from the media
container's own listen ports (8554/1935/8890). infra-TAK publishes that container on
18554/11935/18890 so the standalone MediaMTX keeps 8554, so a lease's publish URL sent ATAK
to the standalone MediaMTX, which refused it and the broadcast ended. The compose patch now
makes media listen on the host port and publish it 1:1.
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

# Upstream CloudTAK docker-compose.yml media block (13.109.x).
UPSTREAM = """services:
    api:
        environment:
            - CLOUDTAK_Config_media_url=${CLOUDTAK_Config_media_url}
        ports:
            - "5000:5000"

    media:
        image: ghcr.io/dfpc-coe/media-infra:v9.10.0
        restart: 'always'
        environment:
            - API_URL=${API_URL}
            - SigningSecret=${SigningSecret}
            - MEDIAMTX_LOGLEVEL=${MEDIAMTX_LOGLEVEL:-info}
            - CLOUDTAK_Config_media_url=${CLOUDTAK_Config_media_url}
        ports:
            - "${MEDIA_PORT_API:-9997}:9997"
            - "${MEDIA_PORT_RTSP:-8554}:8554"
            - "${MEDIA_PORT_RTMP:-1935}:1935"
            - "${MEDIA_PORT_HLS:-8888}:8888"
            - "${MEDIA_PORT_SRT:-8890}:8890"

    postgis:
        image: postgis/postgis:17-3.4-alpine
"""


def _load(*names):
    src = ''
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name in names:
            src += ast.get_source_segment(APP, n) + '\n\n'
        elif isinstance(n, ast.Assign) and any(getattr(t, 'id', '') in names for t in n.targets):
            src += ast.get_source_segment(APP, n) + '\n\n'
    ns = {'os': os, 're': re, 'shlex': shlex, 'subprocess': subprocess, '_host_arch': lambda: 'amd64'}
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns


def _patch(text):
    return _load('_CT_MEDIA_STREAM_PORTS', '_cloudtak_media_listen_patch')['_cloudtak_media_listen_patch'](text)


def _media_block(text):
    return re.search(r'(?ms)^    media:\n.*?(?=^    \S|\Z)', text).group(0)


def test_ports_published_one_to_one_and_srt_is_udp():
    media = _media_block(_patch(UPSTREAM))
    assert '"${MEDIA_PORT_RTSP:-18554}:${MEDIA_PORT_RTSP:-18554}"' in media
    assert '"${MEDIA_PORT_RTMP:-11935}:${MEDIA_PORT_RTMP:-11935}"' in media
    assert '"${MEDIA_PORT_SRT:-18890}:${MEDIA_PORT_SRT:-18890}/udp"' in media
    assert ':8554"' not in media and ':1935"' not in media and ':8890"' not in media


def test_mediamtx_listens_on_the_same_port_it_is_published_on():
    media = _media_block(_patch(UPSTREAM))
    assert '            - MTX_RTSPADDRESS=:${MEDIA_PORT_RTSP:-18554}\n' in media
    assert '            - MTX_RTMPADDRESS=:${MEDIA_PORT_RTMP:-11935}\n' in media
    assert '            - MTX_SRTADDRESS=:${MEDIA_PORT_SRT:-18890}\n' in media
    # inside media's environment list, before its ports
    assert media.index('MTX_RTSPADDRESS') > media.index('environment:')
    assert media.index('MTX_RTSPADDRESS') < media.index('ports:')


def test_other_services_untouched():
    out = _patch(UPSTREAM)
    assert out.count('MTX_RTSPADDRESS') == 1
    api = re.search(r'(?ms)^    api:\n.*?(?=^    \S)', out).group(0)
    assert 'MTX_' not in api
    assert out.replace(_media_block(out), '') == UPSTREAM.replace(_media_block(UPSTREAM), '')


def test_idempotent():
    once = _patch(UPSTREAM)
    assert _patch(once) == once


def test_all_or_nothing_when_upstream_layout_changes():
    # a port line we do not recognise: no half patch (MediaMTX on 18554 behind →8554)
    moved = UPSTREAM.replace('"${MEDIA_PORT_SRT:-8890}:8890"', '"${MEDIA_SRT:-8890}:8890/udp"')
    assert _patch(moved) == moved
    # media environment as a mapping, not a list: leave it alone
    mapping = re.sub(r'(?m)^            - (\w+)=(.*)$', r'            \1: \2', UPSTREAM)
    assert _patch(mapping) == mapping


def test_wired_into_compose_port_hardening(tmp_path):
    ns = _load('_CT_MEDIA_STREAM_PORTS', '_cloudtak_media_listen_patch', '_patch_cloudtak_compose_ports')
    (tmp_path / 'docker-compose.yml').write_text(UPSTREAM)
    assert ns['_patch_cloudtak_compose_ports'](str(tmp_path)) is True
    out = (tmp_path / 'docker-compose.yml').read_text()
    assert '"127.0.0.1:${MEDIA_PORT_API:-9997}:9997"' in out
    assert '- MTX_RTSPADDRESS=:${MEDIA_PORT_RTSP:-18554}' in out
    assert ns['_patch_cloudtak_compose_ports'](str(tmp_path)) is False


def test_env_file_still_sets_the_host_ports():
    # the 1:1 publish and the MTX_* listen both read these; they must stay set
    body = ast.get_source_segment(APP, next(n for n in TREE.body if isinstance(n, ast.FunctionDef)
                                            and n.name == '_cloudtak_build_env_content'))
    for line in ('MEDIA_PORT_RTSP=18554', 'MEDIA_PORT_RTMP=11935', 'MEDIA_PORT_SRT=18890'):
        assert line in body
