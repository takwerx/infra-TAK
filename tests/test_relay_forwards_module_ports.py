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
"""Every public port a module opens reaches relays and the docs (v10.2.9, GH #92).

GH #62 (8448, EUD Remote Assist) and GH #92 (8449, ATLAS MDM) were the same bug: a
module opened a device port in the box firewall and wrote it into an enrolment QR, and
the relay bootstrap forwarded everything except that port. The tablet timed out while
the admin side on 443 looked healthy. Same reporter both times. Writing the general
check below found the same gap for TAK Video Restreamer's and CloudTAK's video ports.

The rule these tests enforce is docs/MODULE-DEVELOPMENT.md section 9.3: a public port
is in the module's `ports`, the relay's forward lists, RELAY-SETUP.md (table and the
paste-in rule JSON), the README's Tier 1 table and DDNS-SETUP.md's router table.
"""

import ast
import hashlib
import json
import os
import pathlib
import re
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
ATLAS = (REPO / 'modules' / 'atlas.py').read_text(encoding='utf-8')
BOOTSTRAP_PATH = 'scripts/connectivity-anchor-bootstrap.sh'
BOOTSTRAP = (REPO / BOOTSTRAP_PATH).read_text(encoding='utf-8')
RELAY_DOC = (REPO / 'docs' / 'RELAY-SETUP.md').read_text(encoding='utf-8')
DDNS_DOC = (REPO / 'docs' / 'DDNS-SETUP.md').read_text(encoding='utf-8')
README = (REPO / 'README.md').read_text(encoding='utf-8')

# Public ports a relay deliberately does not carry. Each one needs its reason.
NOT_RELAYED = {
    8000: "MediaMTX RTP over UDP: our MediaMTX ships rtspTransports [tcp], so no client negotiates it",
    8001: "MediaMTX RTCP over UDP: same as 8000",
}


def _app_const(name):
    for n in ast.parse(APP).body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError('%s not found in app.py' % name)


def _bootstrap_defaults():
    """VAR -> default for every `VAR="${VAR:-default}"` line in the bootstrap."""
    return dict(re.findall(r'^(\w+)="\$\{\w+:-([^}]*)\}"', BOOTSTRAP, re.M))


def _relay_tcp_forwards():
    """FWD_PORTS as the bootstrap expands it with no overrides in the environment."""
    defaults = _bootstrap_defaults()
    fwd = re.search(r'^FWD_PORTS="([^"]+)"', BOOTSTRAP, re.M).group(1)
    ports = set()
    for var in re.findall(r'\$(\w+)', fwd):
        ports.update(int(p) for p in defaults[var].split())
    return ports


def _relay_udp_forwards():
    """UDP_FWD_PORTS plus the CoTURN media range, as the bootstrap expands them."""
    defaults = _bootstrap_defaults()
    ports = {int(p) for p in defaults['UDP_FWD_PORTS'].split()}
    for r in defaults['RA_UDP_RANGE'].split():
        lo, hi = (int(x) for x in r.split(':'))
        ports.update(range(lo, hi + 1))
    return ports


def _ingress_rules():
    block = re.search(r"cat > ingress\.json <<'EOF'\n(.*?)\nEOF", RELAY_DOC, re.S).group(1)
    return json.loads(block)


def _ingress_ports(proto):
    key, number = ('tcpOptions', '6') if proto == 'tcp' else ('udpOptions', '17')
    ports = set()
    for r in _ingress_rules():
        if r['protocol'] == number:
            rng = r[key]['destinationPortRange']
            ports.update(range(rng['min'], rng['max'] + 1))
    return ports


def _table_ports(markdown):
    """Ports named in the Port column (the second) of every markdown table row.

    `8000/8001` reads as both ports, and `3479 / 50000–50050` as 3479 plus the range."""
    ports = set()
    for line in markdown.splitlines():
        if not line.startswith('|'):
            continue
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        if len(cells) < 2:
            continue
        cell = cells[1].replace('*', '')
        for lo, hi in re.findall(r'(\d+)\s*[–-]\s*(\d+)', cell):
            ports.update(range(int(lo), int(hi) + 1))
        cell = re.sub(r'(\d+)\s*[–-]\s*(\d+)', ' ', cell)
        ports.update(int(p) for p in re.findall(r'\d+', cell))
    return ports


def _readme_tier1():
    return README.split('### Tier 1', 1)[1].split('\n### ', 1)[0]


def _declared_module_ports():
    """(module, port, proto) for every port in a Marketplace module manifest's `ports`.

    Read with ast rather than imported, since modules expect the console's ctx. A
    manifest is a dict with both `ports` and `deploy`. Module-level constants are
    resolved, so `f'{DEVICE_PORT}/tcp'` reads as '8449/tcp'."""
    found = []
    for path in sorted((REPO / 'modules').glob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        consts = {}
        for n in tree.body:
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        consts[t.id] = n.value.value
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            keys = {k.value: v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant)}
            if 'ports' not in keys or 'deploy' not in keys or not isinstance(keys['ports'], ast.List):
                continue
            for elt in keys['ports'].elts:
                spec = eval(compile(ast.Expression(elt), str(path), 'eval'), {}, dict(consts))
                port, proto = spec.split('/')
                found.append((path.stem, int(port), proto))
    return found


DECLARED = _declared_module_ports()


def test_atlas_port_in_app_matches_the_module():
    module_port = int(re.search(r'^DEVICE_PORT = (\d+)$', ATLAS, re.M).group(1))
    assert _app_const('ATLAS_DEVICE_PORT') == module_port == 8449


def test_relay_forwards_every_module_device_port():
    fwd = _relay_tcp_forwards()
    assert {80, 443, 8089, 8443, 8446, 5001} <= fwd
    assert _app_const('REMOTE_ASSIST_DEVICE_PORT') in fwd     # GH #62
    assert _app_const('ATLAS_DEVICE_PORT') in fwd             # GH #92


def test_the_manifest_scan_finds_the_modules_that_open_ports():
    """Guards the scan itself: if it ever finds nothing, the per-port test below passes
    vacuously."""
    got = set(DECLARED)
    assert ('atlas', 8449, 'tcp') in got
    assert {('tvr', 8555, 'tcp'), ('tvr', 1935, 'tcp'), ('tvr', 8890, 'udp')} <= got


@pytest.mark.parametrize('module,port,proto', DECLARED)
def test_every_declared_module_port_reaches_relays_and_the_docs(module, port, proto):
    relayed = _relay_tcp_forwards() if proto == 'tcp' else _relay_udp_forwards()
    assert port in relayed, '%s: %d/%s is in no relay forward list (%s)' % (module, port, proto, BOOTSTRAP_PATH)
    assert port in _table_ports(RELAY_DOC), '%s: %d missing from the port table in docs/RELAY-SETUP.md' % (module, port)
    assert port in _ingress_ports(proto), '%s: %d/%s missing from the ingress.json block in docs/RELAY-SETUP.md' % (module, port, proto)
    assert port in _table_ports(_readme_tier1()), '%s: %d missing from the README Tier 1 ports table' % (module, port)
    assert port in _table_ports(DDNS_DOC), '%s: %d missing from the router table in docs/DDNS-SETUP.md' % (module, port)


def test_every_readme_public_port_is_relayed():
    """Built-in services (TAK Server, MediaMTX, CloudTAK, Remote Assist) have no manifest,
    so the README's Tier 1 table is their list. CloudTAK's video ports were public there
    and forwarded by no relay until v10.2.9."""
    relayed = _relay_tcp_forwards() | _relay_udp_forwards()
    missing = sorted(_table_ports(_readme_tier1()) - relayed - set(NOT_RELAYED))
    assert not missing, 'README Tier 1 ports no relay forwards: %s' % missing


def test_relay_guide_opens_every_forwarded_port_in_the_cloud_firewall():
    assert '| TCP | 8449 |' in RELAY_DOC
    assert _relay_tcp_forwards() <= _ingress_ports('tcp')
    assert _relay_udp_forwards() <= _ingress_ports('udp')
    stated = int(re.search(r'you should see (\d+) ingress rules', RELAY_DOC).group(1))
    assert stated == len(_ingress_rules())


def _fake_os(existing=()):
    """Just enough of `os` for _conn_verify_ports: only the paths in `existing` exist."""
    path = types.SimpleNamespace(
        join=os.path.join,
        isdir=lambda p: False,
        expanduser=lambda p: p.replace('~', '/home/takwerx', 1),
        exists=lambda p: p in existing,
    )
    return types.SimpleNamespace(path=path)


def _verify_ports(settings, **overrides):
    parts = []
    for n in ast.parse(APP).body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in (
                '_CONN_VERIFY_PORTS', 'ATLAS_DEVICE_PORT', 'REMOTE_ASSIST_DEVICE_PORT')
                for t in n.targets):
            parts.append(ast.get_source_segment(APP, n))
        if isinstance(n, ast.FunctionDef) and n.name == '_conn_verify_ports':
            parts.append(ast.get_source_segment(APP, n))
    ns = {
        'os': _fake_os(),
        'REMOTE_ASSIST_INSTALL_DIR': '/nonexistent/eud-remote-assist',
        '_get_module_deployment_config': lambda s, k: s.get(k),
        '_get_cloudtak_deployment_config': lambda s: s.get('cloudtak_deployment') or {},
    }
    ns.update(overrides)
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return {p: (label, req) for p, label, req in ns['_conn_verify_ports'](settings)}


def test_verify_probes_8449_only_when_atlas_is_installed():
    assert 8449 not in _verify_ports({})
    label, required = _verify_ports({'atlas_enabled': True})[8449]
    assert required and 'ATLAS' in label


def test_verify_probes_tvr_streaming_ports_only_when_tvr_is_installed():
    assert not {8554, 8555, 1935} & set(_verify_ports({}))
    assert {8554, 8555, 1935} <= set(_verify_ports({'tak_video_restreamer_enabled': True}))


def test_verify_probes_cloudtak_video_only_for_a_local_cloudtak():
    local = _fake_os(existing={'/home/takwerx/CloudTAK/docker-compose.yml'})
    assert not {18554, 11935} & set(_verify_ports({}))
    assert {18554, 11935} <= set(_verify_ports({}, os=local))
    remote = {'cloudtak_deployment': {'target_mode': 'remote'}}
    assert not {18554, 11935} & set(_verify_ports(remote, os=local))


def test_pinned_bootstrap_is_the_one_in_this_tree():
    """app.py fetches the bootstrap from a pinned commit and checks its SHA-256. Editing
    the script without bumping both means relays never get the edit (the 8448 fix needed
    a follow-up commit for exactly this)."""
    commit = _app_const('_CONN_ANCHOR_BOOTSTRAP_COMMIT')
    digest = _app_const('_CONN_ANCHOR_BOOTSTRAP_SHA256')
    assert hashlib.sha256((REPO / BOOTSTRAP_PATH).read_bytes()).hexdigest() == digest
    try:
        pinned = subprocess.run(['git', '-C', str(REPO), 'show', '%s:%s' % (commit, BOOTSTRAP_PATH)],
                                capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip('git is not available')
    if pinned.returncode != 0:
        pytest.skip('pinned commit %s is not in this clone' % commit[:7])
    assert hashlib.sha256(pinned.stdout).hexdigest() == digest
