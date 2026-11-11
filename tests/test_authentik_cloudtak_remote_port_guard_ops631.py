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
"""ops #631: Authentik and remote CloudTAK published ports answer only the console.

- A remote Authentik's 9090 and LDAP 389/636, and a remote CloudTAK's API, tiles, video,
  PostGIS and store ports, get the DOCKER-USER port guard (the ops #615 helper) before the
  containers start, on Update config, and on every console start.
- A remote CloudTAK with no domain keeps 5000/5002 open: the browser goes there directly.
- A fresh LOCAL Authentik binds its published ports to 127.0.0.1 in the compose patcher the
  deploy already runs.
The pure helpers run for real here; the deploy and startup wiring are checked on the source.
"""

import ast
import base64
import ipaddress
import pathlib
import re
import socket

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_CONSTS = ('_PORT_GUARD_NAME_RE', 'REMOTE_AUTHENTIK_GUARD_PORTS', 'REMOTE_CLOUDTAK_GUARD_PORTS',
           '_REMOTE_MODULE_DEPLOYMENT_KEYS', 'SERVICE_DOMAIN_DEFAULTS')
_FUNCS = ('_docker_port_guard_files', '_remote_docker_port_guard', '_remote_module_peer_ips',
          '_remote_authentik_port_guard', '_remote_cloudtak_port_guard', '_authentik_loopback_port',
          '_ensure_authentik_compose_patches', '_remote_cloudtak_guard_ports', '_get_service_domain')


def _ns(module_run=None, server_ip=None):
    ns = {'re': re, 'ipaddress': ipaddress, 'socket': socket, '_b64': base64, 'os': __import__('os'),
          '_module_run': module_run or (lambda *a, **k: (True, '')),
          '_fedhub_caddy_source_ip': lambda s: server_ip,
          '_get_module_deployment_config': lambda s, k: {
              'target_mode': (s.get(k) or {}).get('target_mode', 'local'),
              'remote': {'host': ((s.get(k) or {}).get('remote') or {}).get('host', '')}},
          '_local_ram_mb': lambda: 8192,
          '_authentik_pg_command_for_ram': lambda mb: ('postgres -c max_connections=200', 'standard'),
          '_yaml_duplicate_keys': lambda raw, y: []}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _FUNCS:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') in _CONSTS:
            exec(ast.get_source_segment(APP, node), ns)
    missing = [n for n in _FUNCS + _CONSTS if n not in ns]
    assert not missing, f'ops #631 helpers missing from app.py: {missing}'
    return ns


def _func_src(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def _installed_script(install_cmd):
    return base64.b64decode(
        re.search(r'echo (\S+) \| base64 -d \| \$S tee /usr/local/sbin/', install_cmd).group(1)).decode()


def _fake_remote(sent, ssh_src='10.0.0.9'):
    def run(cfg, cmd, timeout=120, log_fn=None):
        sent.append(cmd)
        if cmd.startswith('echo "SSHSRC'):
            return True, f'SSHSRC {ssh_src}'
        return True, 'GUARD_OK had=no'
    return run


# ── remote Authentik ─────────────────────────────────────────────────────────

def test_remote_authentik_guard_covers_admin_and_ldap():
    ports = _ns()['REMOTE_AUTHENTIK_GUARD_PORTS']
    for p in (9090, 389, 636):
        assert p in ports


def test_remote_authentik_guard_locks_every_port_to_console_and_peer_hosts():
    sent = []
    settings = {'authentik_deployment': {'target_mode': 'remote', 'remote': {'host': '192.0.2.50'}},
                'takportal_deployment': {'target_mode': 'remote', 'remote': {'host': '192.0.2.60'}},
                'cloudtak_deployment': {'target_mode': 'local', 'remote': {'host': '192.0.2.70'}}}
    ok, first = _ns(_fake_remote(sent), server_ip='198.51.100.7')['_remote_authentik_port_guard'](
        {'target_mode': 'remote'}, settings)
    assert (ok, first) == (True, True)
    script = _installed_script(sent[-1])
    for src in ('10.0.0.9', '198.51.100.7', '192.0.2.60'):
        assert f'-s {src} -j RETURN' in script, src
    assert '-s 192.0.2.70 ' not in script, 'a module that is not remote is no peer'
    assert '-s 192.0.2.50 ' not in script, 'the Authentik host itself is no peer'
    for p in (9090, 389, 636):
        assert f'--ctorigdstport {p} --ctdir ORIGINAL -j "$C"' in script, p
    assert 'systemctl enable infratak-port-guard-authentik.service' in sent[-1]


def test_remote_authentik_deploy_locks_ports_before_compose_up():
    src = _func_src('_run_authentik_deploy_remote')
    assert '"0.0.0.0:${COMPOSE_PORT_HTTP:-9090}:9000"' in src  # still published for Caddy
    guard = src.index('_remote_authentik_port_guard(deploy_cfg, settings')
    assert guard < src.index('docker compose down -v') < src.index('docker compose up -d')
    after = src[guard:src.index('docker compose down -v')]
    assert 'if not _ak_guard_ok' in after and 'return' in after, 'no lock must mean no start'


def test_remote_authentik_update_config_relocks_before_compose_up():
    src = _func_src('_run_authentik_reconfigure_remote')
    assert src.index('_remote_authentik_port_guard(deploy_cfg, settings') < src.index('docker compose up -d')


# ── remote CloudTAK ──────────────────────────────────────────────────────────

def test_remote_cloudtak_guard_covers_caddy_upstreams_db_and_store():
    ports = _ns()['REMOTE_CLOUDTAK_GUARD_PORTS']
    for p in (5000, 5002, 5003, 5433, 9000, 9002, 9997, 18888):
        assert p in ports, p
    for p in (18554, 11935, 18890):  # RTSP/RTMP/SRT stay public for clients
        assert p not in ports, p


def test_remote_cloudtak_guard_install():
    sent = []
    settings = {'cloudtak_deployment': {'target_mode': 'remote', 'remote': {'host': '192.0.2.70'}}}
    ok, _ = _ns(_fake_remote(sent), server_ip='198.51.100.7')['_remote_cloudtak_port_guard'](
        {'target_mode': 'remote'}, settings)
    assert ok
    script = _installed_script(sent[-1])
    assert '-s 198.51.100.7 -j RETURN' in script
    assert '--ctorigdstport 5433 --ctdir ORIGINAL' in script
    assert 'systemctl enable infratak-port-guard-cloudtak.service' in sent[-1]


def test_remote_cloudtak_with_a_domain_locks_the_caddy_upstreams_too():
    sent = []
    settings = {'fqdn': 'example.org',
                'cloudtak_deployment': {'target_mode': 'remote', 'remote': {'host': '192.0.2.70'}}}
    ok, _ = _ns(_fake_remote(sent), server_ip='198.51.100.7')['_remote_cloudtak_port_guard'](
        {'target_mode': 'remote'}, settings)
    assert ok
    script = _installed_script(sent[-1])
    for p in (5000, 5002, 9997, 18888, 5433, 9000):
        assert f'--ctorigdstport {p} --ctdir ORIGINAL' in script, p


@pytest.mark.parametrize('settings,open_ports', [
    ({}, (5000, 5002)),                                   # no domain: the browser goes to :5000/:5002
    ({'fqdn': 'example.org'}, ()),
    ({'cloudtak_map_domain': 'map.example.org', 'cloudtak_tiles_domain': 'tiles.example.org',
      'cloudtak_video_domain': 'video.example.org'}, ()),
    ({'cloudtak_map_domain': 'map.example.org'}, (5000, 5002)),  # CloudTAK's env needs all three
])
def test_remote_cloudtak_guard_ports_follow_the_domain(settings, open_ports):
    ports = _ns()['_remote_cloudtak_guard_ports'](settings)
    for p in (5000, 5002):
        assert (p in ports) == (p not in open_ports), p
    for p in (5433, 9000, 9002, 5003, 9997, 18888):
        assert p in ports, p


def test_remote_cloudtak_deploy_locks_before_build_and_opens_nothing():
    src = _func_src('run_cloudtak_deploy')
    remote = src[src.index("if target_mode == 'remote':"):]
    guard = remote.index('_remote_cloudtak_port_guard(cfg, settings')
    assert guard < remote.index('docker compose build --no-cache')
    after = remote[guard:remote.index('docker compose build --no-cache')]
    assert 'if not _ct_guard_ok' in after and 'return' in after, 'no lock must mean no start'
    assert 'sudo ufw allow 5000/tcp' not in src and 'sudo ufw allow 5002/tcp' not in src
    assert '--add-port=5000' not in src and '--add-port=5002' not in src


# ── peer hosts ───────────────────────────────────────────────────────────────

def test_peer_ips_skip_bad_and_unresolvable_hosts(monkeypatch):
    ns = _ns()

    def fake_resolve(h):
        if h == 'portal.example':
            return '192.0.2.61'
        raise OSError('no such host')
    ns['socket'] = type('S', (), {'gethostbyname': staticmethod(fake_resolve)})
    settings = {'authentik_deployment': {'target_mode': 'remote', 'remote': {'host': '192.0.2.50'}},
                'takportal_deployment': {'target_mode': 'remote', 'remote': {'host': 'portal.example'}},
                'webodm_deployment': {'target_mode': 'remote', 'remote': {'host': 'nowhere.invalid'}},
                'mediamtx_deployment': {'target_mode': 'remote', 'remote': {'host': '192.0.2.50'}}}
    assert ns['_remote_module_peer_ips'](settings, 'authentik_deployment') == ['192.0.2.61']


# ── fresh local Authentik ────────────────────────────────────────────────────

@pytest.mark.parametrize('entry,want', [
    ('${COMPOSE_PORT_HTTP:-9000}:9000', '127.0.0.1:${COMPOSE_PORT_HTTP:-9000}:9000'),
    ('${COMPOSE_PORT_HTTPS:-9443}:9443', '127.0.0.1:${COMPOSE_PORT_HTTPS:-9443}:9443'),
    ('9000:9000', '127.0.0.1:9000:9000'),
    ('389:3389', '127.0.0.1:389:3389'),
    ('0.0.0.0:9090:9000', '127.0.0.1:9090:9000'),
    ('[::]:9090:9000', '127.0.0.1:9090:9000'),
    ('9000', '127.0.0.1::9000'),
    ('9000:9000/tcp', '127.0.0.1:9000:9000/tcp'),
    ('127.0.0.1:${COMPOSE_PORT_HTTP:-9000}:9000', '127.0.0.1:${COMPOSE_PORT_HTTP:-9000}:9000'),
    ('10.1.2.3:389:3389', '10.1.2.3:389:3389'),  # an operator's own bind address stays
    ({'target': 9000, 'published': 9000}, {'target': 9000, 'published': 9000, 'host_ip': '127.0.0.1'}),
    ({'target': 9000, 'published': 9000, 'host_ip': '10.1.2.3'},
     {'target': 9000, 'published': 9000, 'host_ip': '10.1.2.3'}),
])
def test_loopback_port(entry, want):
    assert _ns()['_authentik_loopback_port'](entry) == want


UPSTREAM_COMPOSE = """\
services:
  postgresql:
    image: docker.io/library/postgres:16-alpine
  redis:
    image: docker.io/library/redis:alpine
  server:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2026.2.0}
    command: server
    ports:
      - "${COMPOSE_PORT_HTTP:-9000}:9000"
      - "${COMPOSE_PORT_HTTPS:-9443}:9443"
  worker:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2026.2.0}
    command: worker
  ldap:
    image: ghcr.io/goauthentik/ldap:${AUTHENTIK_TAG:-2026.2.0}
    ports:
    - 127.0.0.1:389:3389
    - 127.0.0.1:636:6636
volumes:
  database:
    driver: local
"""


def test_fresh_authentik_compose_is_bound_to_loopback(tmp_path):
    yaml = pytest.importorskip('yaml')
    path = tmp_path / 'docker-compose.yml'
    path.write_text(UPSTREAM_COMPOSE)
    ns = _ns()
    assert ns['_ensure_authentik_compose_patches'](str(path)) is True
    data = yaml.safe_load(path.read_text())
    assert data['services']['server']['ports'] == ['127.0.0.1:${COMPOSE_PORT_HTTP:-9000}:9000',
                                                   '127.0.0.1:${COMPOSE_PORT_HTTPS:-9443}:9443']
    assert data['services']['ldap']['ports'] == ['127.0.0.1:389:3389', '127.0.0.1:636:6636']
    # A second run finds nothing left to bind.
    before = path.read_text()
    ns['_ensure_authentik_compose_patches'](str(path))
    assert path.read_text() == before


def test_local_deploy_runs_the_patcher_before_compose_up():
    src = _func_src('run_authentik_deploy')
    patch = src.index('_ensure_authentik_compose_patches(compose_path, plog)\n        if _patch_authentik_compose_network()')
    assert patch < src.index("'docker', 'compose', 'up', '-d', 'server', 'worker'")


# ── existing boxes ───────────────────────────────────────────────────────────

def test_existing_remote_boxes_get_the_guard_on_console_start():
    src = _func_src('_startup_guard_remote_authentik_cloudtak_ports')
    assert "'authentik_deployment', _remote_authentik_port_guard" in src
    assert "'cloudtak_deployment', _remote_cloudtak_port_guard" in src
    assert "cfg.get('target_mode') == 'remote'" in src and "cfg.get('deployed')" in src
    assert 'threading.Thread(target=_startup_guard_remote_authentik_cloudtak_ports, daemon=True).start()' in APP
