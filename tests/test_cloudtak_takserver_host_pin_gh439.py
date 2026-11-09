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
"""CloudTAK's api container reaches TAK Server on this box at this box's address (infra-TAK #439).

CloudTAK dials ssl://<takserver host>:8089 (mutual TLS). The override pinned that name to whatever
public DNS returned at deploy time. On a home network that is the router's public address, so the
call went out and back in through the router and the reverse proxy in front of 8089 (HAProxy on
pfSense in the report). A proxy that ends TLS drops CloudTAK's client certificate: TAK Server
logged "Certificate error: peer not verified", reset the connection, and the api container
restarted in a loop (HTTP 502).
"""

import ast
import pathlib

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

LOCAL_NIC = '192.168.11.20'
ROUTER_WAN = '203.0.113.9'
TAK_HOST = 'takserver.home.example.com'


def _fn(name):
    return ast.get_source_segment(APP, next(
        n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef) and n.name == name))


def _pin(remote=False, tak_local=True, host=TAK_HOST, primary=LOCAL_NIC, server_ip=LOCAL_NIC):
    ns = {
        '_list_local_ipv4s': lambda: {LOCAL_NIC},
        '_primary_local_ipv4': lambda: primary,
        '_get_cloudtak_deployment_config': lambda s: {'target_mode': 'remote' if remote else 'local'},
        '_takserver_installed_local': lambda: tak_local,
        '_get_takserver_host': lambda s: host,
    }
    for name in ('_cloudtak_caddy_bind_ip', '_cloudtak_takserver_host_pin'):
        exec(compile(_fn(name), 'app.py', 'exec'), ns)
    return ns['_cloudtak_takserver_host_pin']({'fqdn': 'home.example.com', 'server_ip': server_ip})


def test_pin_is_this_boxs_own_address():
    assert _pin() == (TAK_HOST, LOCAL_NIC)


def test_pin_uses_the_primary_address_when_server_ip_is_the_public_one():
    assert _pin(server_ip=ROUTER_WAN) == (TAK_HOST, LOCAL_NIC)


def test_nothing_to_pin_for_a_remote_cloudtak_a_remote_tak_server_or_no_address():
    assert _pin(remote=True) is None
    assert _pin(tak_local=False) is None
    assert _pin(host='') is None
    assert _pin(primary='', server_ip='') is None


def _override(pin, dns_ip=ROUTER_WAN):
    """The real override builder, with only its collaborators stubbed."""
    import os
    import re
    import socket
    ns = {
        'os': os, 're': re, 'CONFIG_DIR': '/nonexistent',
        '_get_takserver_host': lambda s: TAK_HOST,
        '_get_cloudtak_deployment_config': lambda s: {'target_mode': 'local'},
        '_ensure_infratak_docker_network': lambda: None, 'INFRATAK_DOCKER_NETWORK': 'infratak',
        'MEDIA_INFRA_IMAGE': 'ghcr.io/dfpc-coe/media-infra:v9.12.1',
        'POSTGIS_IMAGE': 'postgis/postgis:17-3.6-alpine', 'POSTGIS_IMAGE_ARM64': 'x',
        '_host_arch': lambda: 'x86_64', '_container_ca_trust': lambda node=False: ('', ''),
        '_cloudtak_video_host_pin': lambda s: '',
        '_cloudtak_stream_host_pin': lambda s: '',
        '_cloudtak_takserver_host_pin': lambda s: pin,
        '_sock': socket,
    }
    exec(compile(_fn('_cloudtak_build_override_yml'), 'app.py', 'exec'), ns)
    real = socket.gethostbyname
    socket.gethostbyname = lambda h: dns_ip
    try:
        return yaml.safe_load(ns['_cloudtak_build_override_yml'](
            {'fqdn': 'home.example.com', 'server_ip': LOCAL_NIC}))
    finally:
        socket.gethostbyname = real


def test_override_pins_takserver_to_this_box_not_to_public_dns():
    hosts = _override((TAK_HOST, LOCAL_NIC))['services']['api']['extra_hosts']
    assert f'{TAK_HOST}:{LOCAL_NIC}' in hosts
    assert not any(h.endswith(ROUTER_WAN) for h in hosts)


def test_override_without_a_pin_keeps_the_dns_answer():
    hosts = _override(None)['services']['api']['extra_hosts']
    assert f'{TAK_HOST}:{ROUTER_WAN}' in hosts
