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
"""CA trust store updates (ops #202).

A container's CA bundle is frozen when its image is built, so a root a later CA update removed
from the host stays trusted inside it. CloudTAK's media container (MediaMTX + Node) and the
NetBird server now get the host bundle mounted read-only, with SSL_CERT_FILE / SSL_CERT_DIR /
REQUESTS_CA_BUNDLE pointing at it, and Node in media runs with --use-openssl-ca: its
compiled-in roots are otherwise trusted whatever the bundle says (NODE_EXTRA_CA_CERTS only
adds). The MediaMTX module upgrades the host's pip-installed certifi on every deploy.
"""

import ast
import json
import pathlib
import re
import shutil
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(APP)
HOST = '/etc/ssl/certs/ca-certificates.crt'


def _src(name):
    return ast.get_source_segment(APP, next(
        n for n in _TREE.body if isinstance(n, ast.FunctionDef) and n.name == name))


def _const(name):
    node = next(n for n in _TREE.body if isinstance(n, ast.Assign)
                and any(getattr(t, 'id', None) == name for t in n.targets))
    return ast.literal_eval(node.value)


def _load(names, ns):
    for name in names:
        exec(compile(_src(name), 'app.py', 'exec'), ns)
    return ns


def _trust_ns(bundle=HOST, **extra):
    ns = {'CONTAINER_CA_BUNDLE': _const('CONTAINER_CA_BUNDLE'),
          'CONTAINER_CA_DIR': _const('CONTAINER_CA_DIR'),
          '_host_ca_bundle': lambda: bundle}
    ns.update(extra)
    return _load(['_container_ca_trust'], ns)


# --- host bundle ----------------------------------------------------------------------------

def test_host_bundle_paths_per_family():
    assert _const('HOST_CA_BUNDLES') == {
        'debian': '/etc/ssl/certs/ca-certificates.crt',
        'rhel': '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'}
    assert _const('CONTAINER_CA_BUNDLE') == '/etc/ssl/certs/ca-certificates.crt'


@pytest.mark.parametrize('family', ['debian', 'rhel'])
def test_host_bundle_follows_the_family(tmp_path, family):
    deb, rhel = tmp_path / 'deb.crt', tmp_path / 'rhel.pem'
    deb.write_text('-----BEGIN CERTIFICATE-----\n')
    rhel.write_text('-----BEGIN CERTIFICATE-----\n')
    ns = _load(['_host_ca_bundle'], {'os': __import__('os'), '_distro_family': lambda: family,
                                     'HOST_CA_BUNDLES': {'debian': str(deb), 'rhel': str(rhel)}})
    assert ns['_host_ca_bundle']() == str(deb if family == 'debian' else rhel)


def test_missing_or_empty_host_bundle_mounts_nothing(tmp_path):
    # Docker turns a missing bind-mount source into an empty DIRECTORY at that path.
    empty = tmp_path / 'empty.crt'
    empty.write_text('')
    for path in (str(tmp_path / 'missing.crt'), str(empty)):
        ns = _load(['_host_ca_bundle'], {'os': __import__('os'), '_distro_family': lambda: 'debian',
                                         'HOST_CA_BUNDLES': {'debian': path}})
        assert ns['_host_ca_bundle']() is None
    assert _trust_ns(bundle=None)['_container_ca_trust'](node=True) == ('', '')


def test_trust_block_env_and_mounts():
    env, vols = _trust_ns()['_container_ca_trust'](node=True)
    assert 'SSL_CERT_FILE: "/etc/ssl/certs/ca-certificates.crt"' in env
    assert 'SSL_CERT_DIR: "/etc/ssl/infratak-ca"' in env
    assert 'REQUESTS_CA_BUNDLE: "/etc/ssl/certs/ca-certificates.crt"' in env
    assert 'NODE_OPTIONS: "--use-openssl-ca"' in env
    # Read-only, over the image's own bundle AND alone in the SSL_CERT_DIR directory: the
    # image's /etc/ssl/certs still holds its frozen per-root copies, which Go also loads.
    assert vols.splitlines() == [
        f'      - "{HOST}:/etc/ssl/certs/ca-certificates.crt:ro"',
        f'      - "{HOST}:/etc/ssl/infratak-ca/ca-certificates.crt:ro"']
    env_plain, _ = _trust_ns()['_container_ca_trust']()
    assert 'NODE_OPTIONS' not in env_plain


def test_node_is_not_left_on_extra_ca_certs_alone():
    # NODE_EXTRA_CA_CERTS adds to Node's compiled-in roots; it can't remove one.
    env, _ = _trust_ns()['_container_ca_trust'](node=True)
    assert 'NODE_EXTRA_CA_CERTS' not in env and '--use-openssl-ca' in env


# --- CloudTAK media -------------------------------------------------------------------------

def _override(tmp_path, mode='local', bundle=HOST):
    ns = _trust_ns(bundle=bundle)
    ns.update({
        'os': __import__('os'), 'CONFIG_DIR': str(tmp_path),
        '_get_takserver_host': lambda s: '',
        '_get_cloudtak_deployment_config': lambda s: {'target_mode': mode},
        '_host_arch': lambda: 'amd64', '_ensure_infratak_docker_network': lambda: None,
        'INFRATAK_DOCKER_NETWORK': 'infratak',
        'MEDIA_INFRA_IMAGE': 'ghcr.io/dfpc-coe/media-infra:v9.12.1',
        'POSTGIS_IMAGE': 'postgis/postgis:17-3.6-alpine',
        'POSTGIS_IMAGE_ARM64': 'imresamu/postgis:17-3.6-alpine',
    })
    _load(['_cloudtak_build_override_yml'], ns)
    return ns['_cloudtak_build_override_yml']({})


def _service(yml, name):
    return re.search(rf'^  {name}:\n(.*?)(?=^  \S|^\S|\Z)', yml, re.S | re.M).group(1)


def test_media_trusts_the_host_bundle(tmp_path):
    yml = _override(tmp_path)
    media = _service(yml, 'media')
    assert f'- "{HOST}:/etc/ssl/certs/ca-certificates.crt:ro"' in media
    assert 'NODE_OPTIONS: "--use-openssl-ca"' in media
    assert 'SSL_CERT_DIR: "/etc/ssl/infratak-ca"' in media
    assert 'API_URL: "http://api:5000"' in media
    # Only media: api / events / postgis are out of scope and unchanged.
    for other in ('api', 'events', 'postgis'):
        assert 'infratak-ca' not in _service(yml, other)
        assert 'NODE_OPTIONS' not in _service(yml, other)


def test_remote_cloudtak_and_no_bundle_leave_media_alone(tmp_path):
    for yml in (_override(tmp_path, mode='remote'), _override(tmp_path, bundle=None)):
        media = _service(yml, 'media')
        assert 'volumes:' not in media and 'SSL_CERT_FILE' not in media
        assert 'API_URL: "http://api:5000"' in media
        assert re.search(r'^  postgis:\n    # ops #110', yml, re.M)


# --- NetBird server -------------------------------------------------------------------------

def _nb_ns(bundle=HOST, calls=None):
    ns = _trust_ns(bundle=bundle)
    ns.update({'os': __import__('os'), 'NETBIRD_CA_OVERRIDE_HEADER': _const('NETBIRD_CA_OVERRIDE_HEADER'),
               '_read_priv': None, '_write_priv': None, '_sudo_wrap': lambda a: a})

    def run(argv, **kw):
        calls.append((argv, kw.get('cwd')))
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')
    ns['subprocess'] = types.SimpleNamespace(run=run)
    return _load(['_netbird_write_ca_override', '_heal_netbird_ca_trust'], ns)


def test_netbird_override_written_once(tmp_path):
    ns = _nb_ns()
    assert ns['_netbird_write_ca_override'](str(tmp_path)) is True
    txt = (tmp_path / 'docker-compose.override.yml').read_text()
    assert txt.startswith('# TAKWERX: NetBird server trusts the host CA bundle')
    srv = _service(txt, 'netbird-server')
    assert 'SSL_CERT_FILE: "/etc/ssl/certs/ca-certificates.crt"' in srv
    assert 'SSL_CERT_DIR: "/etc/ssl/infratak-ca"' in srv
    assert f'- "{HOST}:/etc/ssl/certs/ca-certificates.crt:ro"' in srv
    assert 'NODE_OPTIONS' not in srv       # Go binary
    assert 'dashboard' not in txt          # static files, no outbound TLS
    assert ns['_netbird_write_ca_override'](str(tmp_path)) is False


def test_netbird_override_skipped_without_host_bundle(tmp_path):
    assert _nb_ns(bundle=None)['_netbird_write_ca_override'](str(tmp_path)) is False
    assert not (tmp_path / 'docker-compose.override.yml').exists()


def test_netbird_heal_recreates_server_only_once(tmp_path, monkeypatch):
    nb = tmp_path / 'netbird'
    nb.mkdir()
    (nb / 'docker-compose.yml').write_text('services: {}\n')
    monkeypatch.setenv('HOME', str(tmp_path))
    calls, logs = [], []
    ns = _nb_ns(calls=calls)
    assert ns['_heal_netbird_ca_trust'](logs.append) is True
    assert calls == [(['docker', 'compose', 'up', '-d', 'netbird-server'], str(nb))]
    assert any('trusts the host CA bundle' in l for l in logs)
    assert ns['_heal_netbird_ca_trust'](logs.append) is False
    assert len(calls) == 1


def test_netbird_heal_without_netbird_is_a_noop(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    calls = []
    assert _nb_ns(calls=calls)['_heal_netbird_ca_trust'](lambda m: None) is False
    assert calls == []


def test_netbird_wiring():
    assert '_netbird_write_ca_override(nb_dir)' in _src('_netbird_write_compose')
    mig = _src('_startup_migrations')
    assert '_heal_netbird_ca_trust(' in mig
    assert mig.index('_heal_netbird_pinned_image(') < mig.index('_heal_netbird_ca_trust(')


# --- what Compose actually merges (needs the docker compose CLI, not a daemon) --------------

def _compose_config(d):
    if not shutil.which('docker'):
        pytest.skip('docker CLI not installed')
    r = subprocess.run(['docker', 'compose', 'config', '--format', 'json'], cwd=d,
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 and 'is not a docker command' in r.stderr:
        pytest.skip('docker compose plugin not installed')
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _mounts(svc):
    return {(v['source'], v['target'], v.get('read_only', False)) for v in svc.get('volumes', [])}


def test_compose_merges_netbird_override(tmp_path):
    (tmp_path / 'docker-compose.yml').write_text(
        'services:\n  netbird-server:\n    image: netbirdio/netbird-server:0.80.0\n'
        '    volumes:\n      - ./config.yaml:/etc/netbird/config.yaml\n      - ./data:/var/lib/netbird\n'
        '    environment:\n      - NB_SETUP_PAT_ENABLED=true\n'
        '  dashboard:\n    image: netbirdio/dashboard:v2.94.0\n')
    _nb_ns()['_netbird_write_ca_override'](str(tmp_path))
    cfg = _compose_config(tmp_path)['services']
    srv = cfg['netbird-server']
    assert srv['environment']['NB_SETUP_PAT_ENABLED'] == 'true'     # list form kept
    assert srv['environment']['SSL_CERT_DIR'] == '/etc/ssl/infratak-ca'
    assert {(HOST, '/etc/ssl/certs/ca-certificates.crt', True),
            (HOST, '/etc/ssl/infratak-ca/ca-certificates.crt', True)} <= _mounts(srv)
    assert any(t == '/etc/netbird/config.yaml' for _, t, _ in _mounts(srv))
    assert 'environment' not in cfg['dashboard'] or 'SSL_CERT_FILE' not in cfg['dashboard']['environment']


def test_compose_merges_cloudtak_media(tmp_path):
    (tmp_path / 'docker-compose.yml').write_text(
        'services:\n'
        '    api:\n        image: cloudtak-api\n'
        '    tiles:\n        image: cloudtak-tiles\n'
        '    events:\n        image: cloudtak-events\n'
        '    media:\n        image: ghcr.io/dfpc-coe/media-infra:v9.10.0\n'
        '        environment:\n            - API_URL=${API_URL}\n            - SigningSecret=x\n'
        '    postgis:\n        image: postgis/postgis:17-3.4-alpine\n')
    (tmp_path / 'docker-compose.override.yml').write_text(_override(tmp_path))
    cfg = _compose_config(tmp_path)['services']
    media = cfg['media']
    assert media['image'] == 'ghcr.io/dfpc-coe/media-infra:v9.12.1'
    assert media['environment']['NODE_OPTIONS'] == '--use-openssl-ca'
    assert media['environment']['SigningSecret'] == 'x'
    assert (HOST, '/etc/ssl/certs/ca-certificates.crt', True) in _mounts(media)
    assert 'NODE_OPTIONS' not in (cfg['api'].get('environment') or {})


# --- MediaMTX module: host python certifi ---------------------------------------------------

def test_every_mediamtx_pip_install_upgrades_certifi():
    # v10.3.0 W4.b moved the local installs into _mediamtx_editor_install_py_deps(); the remote
    # deploy keeps its shell string. Both paths must upgrade certifi, flag matching the install.
    # GH #330: the remote command is built by _pip(flag) (root's ~/.local off, apt-owned blinker
    # retried with --ignore-installed); certifi goes through the same helper with the same flag.
    r = APP.index('def _mediamtx_editor_remote_py_deps(')
    remote = APP[r:APP.index('\ndef ', r + 1)]
    assert "f'_pi {_pkgs} && _pi -U certifi')" in remote
    assert 'pip3 install "$@" {flag} 2>&1' in remote
    assert "_pip('--break-system-packages')" in remote and "_pip('')" in remote   # + old-pip fallback
    i = APP.index('def _mediamtx_editor_install_py_deps(')
    body = APP[i:APP.index('\ndef ', i + 1)]
    assert "_pip(['pip3', 'install', '-U', 'certifi'] + _flag)" in body
    assert "_flag = []" in body                 # old pip: certifi without the flag too
    assert "if 'pip3 install Flask" not in APP
