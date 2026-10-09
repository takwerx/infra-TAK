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
"""The relay forwards every device port a module puts in a QR (v10.2.9, GH #92).

GH #62 (8448, EUD Remote Assist) and GH #92 (8449, ATLAS MDM) were the same bug: a
module opened a device port in the box firewall and wrote it into an enrolment QR, and
the relay bootstrap forwarded everything except that port. The tablet timed out while
the admin side on 443 looked healthy. Same reporter both times.
"""

import ast
import hashlib
import json
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
ATLAS = (REPO / 'modules' / 'atlas.py').read_text(encoding='utf-8')
BOOTSTRAP_PATH = 'scripts/connectivity-anchor-bootstrap.sh'
BOOTSTRAP = (REPO / BOOTSTRAP_PATH).read_text(encoding='utf-8')
RELAY_DOC = (REPO / 'docs' / 'RELAY-SETUP.md').read_text(encoding='utf-8')


def _app_const(name):
    for n in ast.parse(APP).body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError('%s not found in app.py' % name)


def _relay_tcp_forwards():
    """FWD_PORTS as the bootstrap expands it with no overrides in the environment."""
    defaults = dict(re.findall(r'^(\w+)="\$\{\w+:-([^}]*)\}"', BOOTSTRAP, re.M))
    fwd = re.search(r'^FWD_PORTS="([^"]+)"', BOOTSTRAP, re.M).group(1)
    ports = set()
    for var in re.findall(r'\$(\w+)', fwd):
        ports.update(int(p) for p in defaults[var].split())
    return ports


def test_atlas_port_in_app_matches_the_module():
    module_port = int(re.search(r'^DEVICE_PORT = (\d+)$', ATLAS, re.M).group(1))
    assert _app_const('ATLAS_DEVICE_PORT') == module_port == 8449


def test_relay_forwards_every_module_device_port():
    fwd = _relay_tcp_forwards()
    assert {80, 443, 8089, 8443, 8446, 5001} <= fwd
    assert _app_const('REMOTE_ASSIST_DEVICE_PORT') in fwd     # GH #62
    assert _app_const('ATLAS_DEVICE_PORT') in fwd             # GH #92


def test_relay_guide_opens_the_atlas_port_in_the_cloud_firewall():
    assert '| TCP | 8449 |' in RELAY_DOC
    block = re.search(r"cat > ingress\.json <<'EOF'\n(.*?)\nEOF", RELAY_DOC, re.S).group(1)
    rules = json.loads(block)
    tcp = {r['tcpOptions']['destinationPortRange']['min'] for r in rules if r['protocol'] == '6'}
    assert _relay_tcp_forwards() <= tcp
    stated = int(re.search(r'you should see (\d+) ingress rules', RELAY_DOC).group(1))
    assert stated == len(rules)


def _verify_ports(settings):
    parts = []
    for n in ast.parse(APP).body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in (
                '_CONN_VERIFY_PORTS', 'ATLAS_DEVICE_PORT', 'REMOTE_ASSIST_DEVICE_PORT')
                for t in n.targets):
            parts.append(ast.get_source_segment(APP, n))
        if isinstance(n, ast.FunctionDef) and n.name == '_conn_verify_ports':
            parts.append(ast.get_source_segment(APP, n))
    ns = {
        'os': __import__('os'),
        'REMOTE_ASSIST_INSTALL_DIR': '/nonexistent/eud-remote-assist',
        '_get_module_deployment_config': lambda s, k: s.get(k),
    }
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return {p: (label, req) for p, label, req in ns['_conn_verify_ports'](settings)}


def test_verify_probes_8449_only_when_atlas_is_installed():
    assert 8449 not in _verify_ports({})
    label, required = _verify_ports({'atlas_enabled': True})[8449]
    assert required and 'ATLAS' in label


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
