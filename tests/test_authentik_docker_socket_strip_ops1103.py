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
"""ops #1103 (docker-bench 5.32): the Authentik worker has no Docker socket mount.

Upstream's stock compose mounts /var/run/docker.sock in the worker. Nothing of ours uses it,
and with it a takeover of the worker is a takeover of the host. Before this change only the
post-update step stripped it, so a fresh deploy kept it. Now the compose patcher (deploy,
reconfigure, update, tuning heal, Hardened apply) strips it from every service, and a startup
converge recreates a running worker that still has it. The functions run from the shipped
app.py text.
"""

import ast
import pathlib
import re
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_FUNCS = ('_authentik_volume_is_docker_socket', '_authentik_strip_docker_socket',
          '_ensure_authentik_compose_patches', '_ensure_authentik_compose_patches_legacy',
          '_authentik_loopback_port', '_authentik_docker_socket_converge')
_CONSTS = ('_DOCKER_SOCKET_PATHS', 'AUTHENTIK_REDIS_IMAGE')

STOCK = """\
services:
  postgresql:
    image: docker.io/library/postgres:16-alpine
    volumes:
    - database:/var/lib/postgresql/data
  server:
    image: ghcr.io/goauthentik/server:2026.8.5
    command: server
    ports:
    - ${COMPOSE_PORT_HTTP:-9000}:9000
    volumes:
    - ./media:/media
    - ./custom-templates:/templates
  worker:
    image: ghcr.io/goauthentik/server:2026.8.5
    command: worker
    user: root
    volumes:
    - /var/run/docker.sock:/var/run/docker.sock
    - ./media:/media
    - ./certs:/certs
    - ./custom-templates:/templates
  ldap:
    image: ghcr.io/goauthentik/ldap:2026.8.5
    ports:
    - 127.0.0.1:389:3389
volumes:
  database:
    driver: local
"""


def _ns(**extra):
    ns = {'re': re, 'os': __import__('os'), 'subprocess': subprocess, 'AUTHENTIK_REDIS_IMAGE': 'redis:7',
          '_local_ram_mb': lambda: 16384,
          '_authentik_pg_command_for_ram': lambda mb: ('postgres -c max_connections=200', 'standard'),
          '_yaml_duplicate_keys': lambda raw, y: []}
    ns.update(extra)
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _FUNCS:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') in _CONSTS:
            exec(ast.get_source_segment(APP, node), ns)
    missing = [n for n in _FUNCS + _CONSTS if n not in ns]
    assert not missing, f'ops #1103 helpers missing from app.py: {missing}'
    return ns


def _volumes(compose_text, service):
    import yaml
    return yaml.safe_load(compose_text)['services'][service].get('volumes', [])


# ── what counts as the socket ─────────────────────────────────────────────────

@pytest.mark.parametrize('vol', [
    '/var/run/docker.sock:/var/run/docker.sock',
    '/var/run/docker.sock:/var/run/docker.sock:ro',
    '/run/docker.sock:/var/run/docker.sock',
    '/var/run/docker.sock',
    {'type': 'bind', 'source': '/var/run/docker.sock', 'target': '/var/run/docker.sock'},
])
def test_every_spelling_of_the_socket_mount_is_recognised(vol):
    assert _ns()['_authentik_volume_is_docker_socket'](vol) is True


@pytest.mark.parametrize('vol', [
    './media:/media', 'database:/var/lib/postgresql/data', './certs:/certs',
    '/var/run/docker.sock.bak:/x',
    {'type': 'bind', 'source': './media', 'target': '/media'},
])
def test_other_mounts_are_not_the_socket(vol):
    assert _ns()['_authentik_volume_is_docker_socket'](vol) is False


# ── the compose patcher (deploy, reconfigure, update, tuning heal, Hardened apply) ─

def test_patcher_takes_the_socket_out_of_a_stock_compose_and_keeps_the_rest(tmp_path):
    cp = tmp_path / 'docker-compose.yml'
    cp.write_text(STOCK)
    assert _ns()['_ensure_authentik_compose_patches'](str(cp)) is True
    out = cp.read_text()
    assert 'docker.sock' not in out
    assert _volumes(out, 'worker') == ['./media:/media', './certs:/certs', './custom-templates:/templates']
    assert _volumes(out, 'server') == ['./media:/media', './custom-templates:/templates']
    assert _volumes(out, 'postgresql') == ['database:/var/lib/postgresql/data']
    # the LDAP outpost is our own compose service and is not touched
    import yaml
    ldap = yaml.safe_load(out)['services']['ldap']
    assert ldap['image'] == 'ghcr.io/goauthentik/ldap:2026.8.5'
    assert ldap['ports'] == ['127.0.0.1:389:3389']


def test_patcher_strips_the_long_form_and_drops_an_emptied_volumes_key(tmp_path):
    cp = tmp_path / 'docker-compose.yml'
    cp.write_text(STOCK.replace(
        "    volumes:\n    - /var/run/docker.sock:/var/run/docker.sock\n    - ./media:/media\n    - ./certs:/certs\n"
        "    - ./custom-templates:/templates\n",
        "    volumes:\n    - type: bind\n      source: /var/run/docker.sock\n      target: /var/run/docker.sock\n"))
    _ns()['_ensure_authentik_compose_patches'](str(cp))
    import yaml
    worker = yaml.safe_load(cp.read_text())['services']['worker']
    assert 'volumes' not in worker, 'a volumes key with nothing left in it is dropped, not left empty'


def test_patcher_is_idempotent_once_the_socket_is_gone(tmp_path):
    cp = tmp_path / 'docker-compose.yml'
    cp.write_text(STOCK)
    ns = _ns()
    ns['_ensure_authentik_compose_patches'](str(cp))
    assert ns['_ensure_authentik_compose_patches'](str(cp)) is False


def test_the_socket_alone_is_reported_as_a_change(tmp_path):
    """Only the socket differs from the patched form, and that alone must trigger the rewrite."""
    cp = tmp_path / 'docker-compose.yml'
    cp.write_text(STOCK)
    ns = _ns()
    ns['_ensure_authentik_compose_patches'](str(cp))
    text = cp.read_text().replace(
        "- ./media:/media\n    - ./certs:/certs",
        "- /var/run/docker.sock:/var/run/docker.sock\n    - ./media:/media\n    - ./certs:/certs", 1)
    cp.write_text(text)
    assert 'docker.sock' in cp.read_text()
    assert ns['_ensure_authentik_compose_patches'](str(cp)) is True
    assert 'docker.sock' not in cp.read_text()


def test_legacy_text_patcher_strips_the_socket_line_too(tmp_path):
    cp = tmp_path / 'docker-compose.yml'
    cp.write_text(STOCK)
    assert _ns()['_ensure_authentik_compose_patches_legacy'](str(cp)) is True
    out = cp.read_text()
    assert 'docker.sock' not in out
    assert './certs:/certs' in out


# ── the startup converge ──────────────────────────────────────────────────────

def _converge(monkeypatch, tmp_path, compose_text, inspect_out=None, inspect_rc=0):
    """Run _authentik_docker_socket_converge against a fake HOME and a fake `docker inspect`."""
    home = tmp_path / 'home'
    (home / 'authentik').mkdir(parents=True)
    (home / 'authentik' / 'docker-compose.yml').write_text(compose_text)
    monkeypatch.setenv('HOME', str(home))
    calls = {'inspect': [], 'recreate': []}

    def fake_run(cmd, **kw):
        calls['inspect'].append(cmd)
        return types.SimpleNamespace(returncode=inspect_rc, stdout=inspect_out or '', stderr='')

    def fake_recreate(plog, reason, services=('server', 'worker')):
        calls['recreate'].append((reason, tuple(services)))
        return True

    ns = _ns(_sudo_wrap=lambda c: c, _recreate_authentik_server_worker=fake_recreate,
             subprocess=types.SimpleNamespace(run=fake_run))
    logs = []
    acted = ns['_authentik_docker_socket_converge'](logs.append)
    return acted, calls, (home / 'authentik' / 'docker-compose.yml').read_text(), logs


def test_converge_fixes_the_file_and_recreates_only_the_worker(monkeypatch, tmp_path):
    acted, calls, out, _ = _converge(monkeypatch, tmp_path, STOCK, inspect_out='/var/run/docker.sock\n/x/media\n')
    assert acted is True
    assert 'docker.sock' not in out
    assert calls['recreate'] == [('docker-socket-strip', ('worker',))], 'server and LDAP are not recreated'


def test_converge_recreates_a_worker_whose_file_is_already_clean(monkeypatch, tmp_path):
    """The compose file was fixed by a deploy but the container was never recreated."""
    clean = re.sub(r'    - /var/run/docker.sock:/var/run/docker.sock\n', '', STOCK)
    acted, calls, _, _ = _converge(monkeypatch, tmp_path, clean, inspect_out='/var/run/docker.sock\n')
    assert acted is True
    assert calls['recreate'] == [('docker-socket-strip', ('worker',))]


def test_converge_does_nothing_on_a_clean_box(monkeypatch, tmp_path):
    clean = re.sub(r'    - /var/run/docker.sock:/var/run/docker.sock\n', '', STOCK)
    acted, calls, out, logs = _converge(monkeypatch, tmp_path, clean, inspect_out='/x/media\n/x/certs\n')
    assert acted is False
    assert calls['recreate'] == []
    assert out == clean, 'a clean file is not rewritten'
    assert logs == []


def test_converge_with_no_worker_container_only_fixes_the_file(monkeypatch, tmp_path):
    acted, calls, out, _ = _converge(monkeypatch, tmp_path, STOCK, inspect_rc=1)
    assert acted is True and 'docker.sock' not in out
    assert calls['recreate'] == []


# ── the worker-only recreate, and the wiring ──────────────────────────────────

def _func_src(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def test_recreate_helper_takes_a_service_list_and_defaults_to_server_and_worker(monkeypatch, tmp_path):
    (tmp_path / 'authentik').mkdir()
    (tmp_path / 'authentik' / 'docker-compose.yml').write_text('services: {}\n')
    monkeypatch.setenv('HOME', str(tmp_path))
    sent = []

    class _Lock:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return True

        def __exit__(self, *a):
            return False

    def fake_run(cmd, **kw):
        sent.append(cmd)
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    ns = {'os': __import__('os'), 'time': __import__('time'), '_sudo_wrap': lambda c: c,
          '_clear_stale_authentik_migration_lock': lambda plog: None,
          '_authentik_compose_lock': lambda *a, **k: _Lock(),
          'subprocess': types.SimpleNamespace(run=fake_run), 'load_settings': lambda: {},
          'save_settings': lambda s: None}
    exec(_func_src('_recreate_authentik_server_worker'), ns)
    ns['_recreate_authentik_server_worker'](lambda m: None, 'x', services=('worker',))
    ns['_recreate_authentik_server_worker'](lambda m: None, 'y')
    ups = [c for c in sent if 'up' in c]
    assert ups[0][-1] == 'worker' and 'server' not in ups[0]
    assert ups[1][-2:] == ['server', 'worker']


def test_console_start_runs_the_converge():
    start = APP.index("_auto_remove_stale_docker_service_connections(label='Startup migration')")
    assert '_authentik_docker_socket_converge(' in APP[start:start + 1500]


def test_the_deploy_reconfigure_and_update_paths_all_go_through_the_patcher():
    # Each of these runs the compose patcher, which now strips the socket.
    assert APP.count('_ensure_authentik_compose_patches(') >= 7
    assert '_authentik_strip_docker_socket(services, plog)' in _func_src('_ensure_authentik_compose_patches')
