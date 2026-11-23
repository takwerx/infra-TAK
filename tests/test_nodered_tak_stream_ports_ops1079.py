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
"""ops #1079 (infra-TAK #642): Node-RED cannot reach a TAK datafeed port the host firewall shut.

The TAK Server deploy opens 8089/8443/8446 to everyone. A datafeed an operator adds (8095 for
PulsePoint) is opened by nothing, so with ufw or firewalld on, the container's TCP out node
waits and ends in ETIMEDOUT. The fix reads the datafeed and input ports from CoreConfig and
allows the Docker networks (172.16.0.0/12 only) to each one. The helpers are pure enough to
run for real here; the wiring is checked on the source.
"""

import ast
import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_FUNCS = ('_coreconfig_nodered_stream_ports', '_heal_nodered_tak_stream_ports')
_CONSTS = ('_NODERED_DOCKER_SRC', '_NODERED_TAK_PORTS_OPEN')

# What the reporter's CoreConfig looked like, plus the neighbours that must NOT be opened.
CORECONFIG = '''<Configuration>
  <network>
    <input _name="stdssl" protocol="tls" port="8089" auth="x509"/>
    <input auth="anonymous" _name="stdtcp" protocol="tcp" port="8087"/>
    <input _name="anon_tls" protocol="tls" port="8091" auth="anonymous"/>
    <input _name="mcast" protocol="mcast" group="239.2.3.1" port="6969"/>
    <datafeed auth="x509" _name="pulsepoint" protocol="tls" port="8095" archive="true"/>
    <datafeed _name="weather" protocol="tls" auth="ldap" port="8096"/>
    <!-- <datafeed auth="x509" _name="old" protocol="tls" port="8097"/> -->
    <connector port="8443" _name="https"/>
    <connector port="8446" _name="cert_https"/>
  </network>
</Configuration>
'''


def _ns(**over):
    ns = {'re': re, 'os': __import__('os'), 'subprocess': subprocess,
          '_broker_shim_env': lambda: {}}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _FUNCS:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') in _CONSTS:
            exec(ast.get_source_segment(APP, node), ns)
    missing = [n for n in _FUNCS + _CONSTS if n not in ns]
    assert not missing, f'ops #1079 helpers missing from app.py: {missing}'
    ns.update(over)
    return ns


def _heal_env(tmp_path, monkeypatch, *, present=True, cc=CORECONFIG, backend='ufw', fw_ok=True):
    """Run the heal with a fake firewall; returns (opened, calls, said)."""
    home = tmp_path / 'home'
    (home / 'node-red').mkdir(parents=True)
    if present:
        (home / 'node-red' / 'docker-compose.yml').write_text('services: {}\n')
    monkeypatch.setenv('HOME', str(home))
    calls, said = [], []

    def fake_allow_from(src, port, proto='tcp'):
        calls.append((src, port, proto))
        return (fw_ok, '' if fw_ok else 'ERROR: nope')

    def fake_read():
        if cc is None:
            raise FileNotFoundError('no CoreConfig')
        return cc

    def fake_run(*a, **k):                     # `docker ps` finds no container
        return subprocess.CompletedProcess(a, 0, stdout='', stderr='')

    sub = type('S', (), {'run': staticmethod(fake_run)})
    ns = _ns(_fw_allow_from=fake_allow_from, _read_coreconfig=fake_read,
             _fw_backend=lambda: backend, subprocess=sub)
    opened = ns['_heal_nodered_tak_stream_ports'](said.append)
    return opened, calls, said


# ---------------------------------------------------------------- port parsing

def test_parse_finds_the_datafeed_ports_and_leaves_the_rest():
    ports = _ns()['_coreconfig_nodered_stream_ports'](CORECONFIG)
    # 8095 (the reporter's PulsePoint datafeed) and 8096 (ldap auth) are TLS and need a login.
    assert ports == [8095, 8096]


def test_parse_leaves_out_plain_anonymous_commented_and_already_open_ports():
    ports = set(_ns()['_coreconfig_nodered_stream_ports'](CORECONFIG))
    assert 8089 not in ports          # TAK deploy already opens it to everyone
    assert 8443 not in ports and 8446 not in ports
    assert 8087 not in ports          # plain tcp, anonymous
    assert 8091 not in ports          # tls but anonymous: no login, never opened for containers
    assert 6969 not in ports          # multicast
    assert 8097 not in ports          # commented out


def test_parse_handles_empty_and_junk():
    f = _ns()['_coreconfig_nodered_stream_ports']
    assert f('') == [] and f(None) == []
    assert f('<datafeed protocol="tls" port="99999" auth="x509"/>') == []   # not a port
    assert f('<datafeed protocol="tls" auth="x509"/>') == []                # no port
    assert f('<datafeed protocol="tls" port="8095"/><datafeed protocol="tls" port="8095"/>') == [8095]


# ---------------------------------------------------------------- the heal

def test_heal_opens_each_datafeed_port_for_the_docker_networks_only(tmp_path, monkeypatch):
    opened, calls, said = _heal_env(tmp_path, monkeypatch)
    assert opened == [8095, 8096]
    assert calls == [('172.16.0.0/12', 8095, 'tcp'), ('172.16.0.0/12', 8096, 'tcp')]
    assert any('8095' in m for m in said)


def test_heal_never_opens_a_port_to_everyone(tmp_path, monkeypatch):
    # The only firewall call the heal may make is the source-scoped one.
    body = ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == '_heal_nodered_tak_stream_ports'))
    assert '_fw_allow_from(' in body
    assert not re.search(r'\b_fw_allow\(', body)
    src = re.search(r"^_NODERED_DOCKER_SRC\s*=\s*'([^']+)'", APP, re.M).group(1)
    assert src == '172.16.0.0/12'          # Docker bridges only; 0.0.0.0/0 would open the internet


def test_heal_does_nothing_without_a_local_node_red(tmp_path, monkeypatch):
    opened, calls, _ = _heal_env(tmp_path, monkeypatch, present=False)
    assert opened == [] and calls == []


def test_heal_does_nothing_when_coreconfig_is_not_here(tmp_path, monkeypatch):
    opened, calls, _ = _heal_env(tmp_path, monkeypatch, cc=None)     # remote or no TAK Server
    assert opened == [] and calls == []


def test_heal_does_nothing_with_no_firewall(tmp_path, monkeypatch):
    opened, calls, _ = _heal_env(tmp_path, monkeypatch, backend=None)
    assert opened == [] and calls == []


def test_heal_says_so_and_does_not_raise_when_the_firewall_refuses(tmp_path, monkeypatch):
    opened, calls, said = _heal_env(tmp_path, monkeypatch, fw_ok=False)
    assert opened == [] and len(calls) == 2
    assert any('could not open' in m for m in said)


def test_heal_with_only_the_default_ports_makes_no_firewall_call(tmp_path, monkeypatch):
    default_cc = '<input _name="stdssl" protocol="tls" port="8089" auth="x509"/>'
    opened, calls, _ = _heal_env(tmp_path, monkeypatch, cc=default_cc)
    assert opened == [] and calls == []


# ---------------------------------------------------------------- wiring

def _src(name):
    return ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name))


def test_runs_at_every_console_start():
    assert '_heal_nodered_tak_stream_ports(' in _src('_startup_migrations')


def test_runs_after_a_node_red_deploy_before_the_caddy_step():
    body = _src('run_nodered_deploy')
    i = body.index('_heal_nodered_tak_stream_ports(')
    assert body.index('Step 3b') < i < body.index('Step 4/4')
