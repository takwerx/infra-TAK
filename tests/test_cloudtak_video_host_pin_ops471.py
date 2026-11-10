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
"""CloudTAK video: the api container reaches the media server on this box (ops #471).

CloudTAK's api calls its media server at `https://<video host>:9997` for every lease
(video-service.ts forces port 9997). The container resolved that name through public DNS, so on a
relay box (the relay never carried 9997) or a home/office network (no NAT hairpin) the connect
timed out after 10 s and every proxy lease failed with "Failed to generate proxy stream".
infra-TAK's override now pins the video name to the address Caddy's :9997 listener binds, in the
api container only.
"""

import ast
import pathlib
import re

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

LOCAL_NIC = '10.10.10.51'


def _fn(name):
    return ast.get_source_segment(APP, next(
        n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef) and n.name == name))


def _ns(local_ips=(LOCAL_NIC,), primary=LOCAL_NIC, remote=False, video='video.nuc.example.com'):
    ns = {
        '_list_local_ipv4s': lambda: set(local_ips),
        '_primary_local_ipv4': lambda: primary,
        '_get_cloudtak_deployment_config': lambda s: {'target_mode': 'remote' if remote else 'local'},
        '_get_service_domain': lambda s, k: video if k == 'cloudtak_video' else '',
    }
    for name in ('_cloudtak_caddy_bind_ip', '_cloudtak_video_host_pin'):
        exec(compile(_fn(name), 'app.py', 'exec'), ns)
    return ns


def test_pin_is_the_address_caddy_binds_for_9997():
    pin = _ns()['_cloudtak_video_host_pin']({'fqdn': 'nuc.example.com', 'server_ip': LOCAL_NIC})
    assert pin == f'video.nuc.example.com:{LOCAL_NIC}'


def test_pin_falls_back_to_the_primary_address_when_server_ip_is_not_on_a_nic():
    # NAT / cloud box: settings.server_ip is the public address, which Caddy cannot bind
    pin = _ns()['_cloudtak_video_host_pin']({'fqdn': 'nuc.example.com', 'server_ip': '47.153.3.83'})
    assert pin == f'video.nuc.example.com:{LOCAL_NIC}'


def test_pin_drops_tls_options_after_the_host():
    pin = _ns(video='video.nuc.example.com tls internal')['_cloudtak_video_host_pin'](
        {'fqdn': 'nuc.example.com', 'server_ip': LOCAL_NIC})
    assert pin == f'video.nuc.example.com:{LOCAL_NIC}'


def test_nothing_to_pin_without_a_domain_a_bind_address_or_on_a_remote_cloudtak():
    pin = _ns()['_cloudtak_video_host_pin']
    assert pin({'fqdn': '', 'server_ip': LOCAL_NIC}) == ''
    assert _ns(primary='')['_cloudtak_video_host_pin']({'fqdn': 'nuc.example.com', 'server_ip': ''}) == ''
    assert _ns(remote=True)['_cloudtak_video_host_pin']({'fqdn': 'nuc.example.com', 'server_ip': LOCAL_NIC}) == ''
    assert _ns(video='')['_cloudtak_video_host_pin']({'fqdn': 'nuc.example.com', 'server_ip': LOCAL_NIC}) == ''


def test_caddyfile_and_pin_use_the_same_bind_address():
    body = _fn('generate_caddyfile')
    assert '_cloudtak_caddy_bind_ip(settings)' in body
    assert '_list_local_ipv4s()' not in body.split('CloudTAK Media (video) on :9997')[0][-1500:]


def _override(pin):
    """The real override builder, with only its collaborators stubbed."""
    ns = {
        'os': __import__('os'), 're': re, 'CONFIG_DIR': '/nonexistent',
        '_get_takserver_host': lambda s: 'takserver.nuc.example.com',
        '_get_cloudtak_deployment_config': lambda s: {'target_mode': 'local'},
        '_ensure_infratak_docker_network': lambda: None, 'INFRATAK_DOCKER_NETWORK': 'infratak',
        'MEDIA_INFRA_IMAGE': 'ghcr.io/dfpc-coe/media-infra:v9.12.1',
        'POSTGIS_IMAGE': 'postgis/postgis:17-3.6-alpine', 'POSTGIS_IMAGE_ARM64': 'x',
        '_host_arch': lambda: 'x86_64', '_container_ca_trust': lambda node=False: ('', ''),
        '_cloudtak_video_host_pin': lambda s: pin,
        '_cloudtak_stream_host_pin': lambda s: '',
        '_cloudtak_takserver_host_pin': lambda s: None,   # infra-TAK #439: has its own tests
    }
    ns['_sock'] = None
    src = _fn('_cloudtak_build_override_yml')
    exec(compile(src, 'app.py', 'exec'), ns)
    import socket
    ns['_sock'] = socket
    return ns['_cloudtak_build_override_yml']({'fqdn': 'nuc.example.com', 'server_ip': LOCAL_NIC})


def test_override_pins_video_name_in_api_only(monkeypatch):
    import socket
    monkeypatch.setattr(socket, 'gethostbyname', lambda h: '129.146.3.144')   # the relay
    doc = yaml.safe_load(_override(f'video.nuc.example.com:{LOCAL_NIC}'))
    api = doc['services']['api']['extra_hosts']
    assert f'video.nuc.example.com:{LOCAL_NIC}' in api
    # the TAK Server name keeps resolving the way it did
    assert 'takserver.nuc.example.com:129.146.3.144' in api
    for svc in ('events', 'media'):
        assert not any(h.startswith('video.') for h in doc['services'][svc]['extra_hosts'])


def test_override_without_a_pin_is_unchanged(monkeypatch):
    import socket
    monkeypatch.setattr(socket, 'gethostbyname', lambda h: '129.146.3.144')
    doc = yaml.safe_load(_override(''))
    assert not any(h.startswith('video.') for h in doc['services']['api']['extra_hosts'])
