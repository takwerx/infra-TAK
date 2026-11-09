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
"""CloudTAK video from this box's own MediaMTX plays on a cloud box (ops #560).

The fresh-install video check failed on a real-domain AWS box: CloudTAK's media container pulled
rtsp://stream.<fqdn>:8554/<path> and MediaMTX answered 401, so the HLS playlist was HTTP 500 "source
of path ... has timed out". The standalone MediaMTX lets CloudTAK's Docker network read without a
password (ops #193), but through the public name the pull leaves the box and the provider's NAT
returns it with the box's own public address as the source (seen with `ss` on the box). Checked
on that box from inside the media container: the public name 401, the box's private address and
the Docker gateway 404 (auth passed). The override now pins the stream name to the box's own
address in the media container, so the pull stays on the box and no new address is trusted.
"""

import ast
import os
import pathlib
import re
import types

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

NIC = '172.31.27.21'


def _fn(name):
    return next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name)


def _load(*names, **extra):
    ns = {'os': os, 're': re}
    ns.update(extra)
    for name in names:
        exec(compile(ast.get_source_segment(APP, _fn(name)), 'app.py', 'exec'), ns)
    return ns


def _pin(settings=None, installed=True, remote=False, stream='stream.cloud.example.com', ip=NIC):
    fake_os = types.SimpleNamespace(path=types.SimpleNamespace(
        exists=lambda p: installed and p == '/usr/local/bin/mediamtx'))
    ns = _load('_cloudtak_stream_host_pin', os=fake_os,
               _get_cloudtak_deployment_config=lambda s: {'target_mode': 'remote' if remote else 'local'},
               _get_service_domain=lambda s, k: stream if k == 'mediamtx' else '',
               _cloudtak_caddy_bind_ip=lambda s: ip)
    return ns['_cloudtak_stream_host_pin'](settings if settings is not None else {'fqdn': 'cloud.example.com'})


def test_stream_name_is_pinned_to_the_boxs_own_address():
    assert _pin() == f'stream.cloud.example.com:{NIC}'


def test_pin_keeps_a_custom_stream_name_and_drops_trailing_options():
    assert _pin(stream='cams.example.org tls internal') == f'cams.example.org:{NIC}'


def test_nothing_to_pin_without_a_local_mediamtx_a_domain_an_address_or_on_a_remote_cloudtak():
    assert _pin(installed=False) == ''          # stream.<fqdn> may then point at another machine
    assert _pin(remote=True) == ''
    assert _pin(settings={'fqdn': ''}) == ''
    assert _pin(stream='') == ''
    assert _pin(ip='') == ''


def _override(stream_pin, video_pin=''):
    """The real override builder, with only its collaborators stubbed (as ops #471's test does)."""
    import socket
    ns = {
        'os': os, 're': re, 'CONFIG_DIR': '/nonexistent', '_sock': socket,
        '_get_takserver_host': lambda s: 'takserver.cloud.example.com',
        '_get_cloudtak_deployment_config': lambda s: {'target_mode': 'local'},
        '_ensure_infratak_docker_network': lambda: None, 'INFRATAK_DOCKER_NETWORK': 'infratak',
        'MEDIA_INFRA_IMAGE': 'ghcr.io/dfpc-coe/media-infra:v9.12.1',
        'POSTGIS_IMAGE': 'postgis/postgis:17-3.6-alpine', 'POSTGIS_IMAGE_ARM64': 'x',
        '_host_arch': lambda: 'x86_64', '_container_ca_trust': lambda node=False: ('', ''),
        '_cloudtak_video_host_pin': lambda s: video_pin,
        '_cloudtak_stream_host_pin': lambda s: stream_pin,
        '_cloudtak_takserver_host_pin': lambda s: None,   # infra-TAK #439: has its own tests
    }
    exec(compile(ast.get_source_segment(APP, _fn('_cloudtak_build_override_yml')), 'app.py', 'exec'), ns)
    socket.gethostbyname, real = (lambda h: '3.145.217.175'), socket.gethostbyname
    try:
        return ns['_cloudtak_build_override_yml']({'fqdn': 'cloud.example.com', 'server_ip': NIC})
    finally:
        socket.gethostbyname = real


def test_override_pins_the_stream_name_in_the_media_container_only():
    doc = yaml.safe_load(_override(f'stream.cloud.example.com:{NIC}', video_pin=f'video.cloud.example.com:{NIC}'))
    media = doc['services']['media']['extra_hosts']
    assert f'stream.cloud.example.com:{NIC}' in media
    assert 'takserver.cloud.example.com:3.145.217.175' in media          # TAK Server name resolves as before
    for svc in ('api', 'events'):
        assert not any(h.startswith('stream.') for h in doc['services'][svc]['extra_hosts'])
    # the video pin (ops #471) stays in api only
    assert not any(h.startswith('video.') for h in media)
    assert f'video.cloud.example.com:{NIC}' in doc['services']['api']['extra_hosts']


def test_override_without_a_pin_is_unchanged():
    doc = yaml.safe_load(_override(''))
    assert not any(h.startswith('stream.') for h in doc['services']['media']['extra_hosts'])


OLD = """# TAKWERX
services:
  api:
    extra_hosts:
      - "host.docker.internal:host-gateway"
  media:
    image: x
    extra_hosts:
      - "host.docker.internal:host-gateway"
  postgis:
    image: y
"""
NEW_MEDIA = OLD.replace('  media:\n    image: x\n    extra_hosts:\n      - "host.docker.internal:host-gateway"\n',
                        '  media:\n    image: x\n    extra_hosts:\n      - "host.docker.internal:host-gateway"\n'
                        f'      - "stream.cloud.example.com:{NIC}"\n')
NEW_API = OLD.replace('  api:\n    extra_hosts:\n      - "host.docker.internal:host-gateway"\n',
                      '  api:\n    extra_hosts:\n      - "host.docker.internal:host-gateway"\n      - "video.x:1.2.3.4"\n')


def _refresh(tmp_path, monkeypatch, old, new):
    """The real refresh function on a temp ~/CloudTAK; returns what it ran."""
    monkeypatch.setenv('HOME', str(tmp_path))
    ct = tmp_path / 'CloudTAK'
    ct.mkdir()
    (ct / 'compose.yaml').write_text('services: {}\n')
    if old is not None:
        (ct / 'docker-compose.override.yml').write_text(old)
    ran, healed, threads = [], [], []

    def compose(d, action, timeout=300):
        ran.append(action)
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    ns = _load('_cloudtak_override_service_block', '_cloudtak_refresh_override',
               load_settings=lambda: {}, _get_cloudtak_deployment_config=lambda s: {'target_mode': 'local'},
               _cloudtak_build_override_yml=lambda s: new, _broker_compose=compose,
               _cloudtak_media_hls_heal=lambda log, **kw: healed.append(kw) or True,
               threading=types.SimpleNamespace(Thread=lambda **kw: types.SimpleNamespace(
                   start=lambda: threads.append(kw.get('name')))),
               time=types.SimpleNamespace(sleep=lambda s: None),
               _selfheal_cloudtak_corrupt_icons=lambda **kw: None)
    result = ns['_cloudtak_refresh_override'](lambda m: None)
    return result, ran, healed, threads, (ct / 'docker-compose.override.yml').read_text()


def test_pin_arriving_recreates_only_media_and_converges_its_hls_profile(tmp_path, monkeypatch):
    (changed, _), ran, healed, threads, written = _refresh(tmp_path, monkeypatch, OLD, NEW_MEDIA)
    assert changed and written.strip() == NEW_MEDIA.strip()
    assert ran == ['up -d --no-deps media']
    assert healed == [{'wait': True}]       # a recreate puts the image's HLS profile back
    assert threads == []                    # the api was not recreated: no icon watch


def test_an_api_change_still_recreates_the_api_as_before(tmp_path, monkeypatch):
    (changed, _), ran, healed, threads, _w = _refresh(tmp_path, monkeypatch, OLD, NEW_API)
    assert changed and ran == ['up -d --no-deps api'] and healed == []
    assert threads == ['cloudtak-simlink-icon-heal']


def test_a_first_override_recreates_both(tmp_path, monkeypatch):
    (changed, _), ran, healed, _t, _w = _refresh(tmp_path, monkeypatch, None, NEW_MEDIA)
    assert changed and ran == ['up -d --no-deps api media'] and healed == [{'wait': True}]


def test_an_unchanged_override_does_nothing(tmp_path, monkeypatch):
    (changed, _), ran, healed, threads, _w = _refresh(tmp_path, monkeypatch, NEW_MEDIA, NEW_MEDIA)
    assert not changed and ran == [] and healed == [] and threads == []


def test_the_mediamtx_link_converge_refreshes_the_override_before_its_early_returns():
    # MediaMTX installed after CloudTAK, or CloudTAK updated from a release without the pin: the pin
    # must follow even when mediamtx.yml itself needs no change (the converge returns early then)
    body = ast.get_source_segment(APP, _fn('_mediamtx_converge_cloudtak_read'))
    assert body.index('_cloudtak_refresh_override(_log)') < body.index('if patched == cur')
    assert body.index('_cloudtak_refresh_override(_log)') < body.index("cfg_path = '/usr/local/etc/mediamtx.yml'")
