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
"""Remote Assist CoTURN: calls where both ends relay through this server (ops #212).

Each side asks permission for the other's relayed address, <external IP>:500xx. coturn maps
a peer at the external IP to its own relay address before the peer ACL is checked. With no
--relay-ip that is 0.0.0.0 (from --listening-ip), which coturn always refuses, so the call
failed on v10.2.28 and on #269 alike. The override now pins the relay address to the
container's own address and allows exactly that address, both worked out by the image's
entrypoint at start. Everything else the ACL refuses stays refused.
"""

import ipaddress
import os
import re
import shutil
import stat
import subprocess
import threading
import types

import pytest
import yaml

REPO = __import__('pathlib').Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

PUB = '203.0.113.50'          # advertised --external-ip
CTR = '172.25.0.6'            # coturn's container address = its relay address
IP_ADDR = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 10.0.1.5/24 brd 10.0.1.255 scope global dynamic eth0\\       valid_lft 3000sec
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever
8: br-8cca2a52cb78    inet 172.25.0.1/16 brd 172.25.255.255 scope global br-8cca2a52cb78\\       valid_lft forever
"""

# coturn/coturn:4.18.0 docker/coturn/rootfs/usr/local/bin/docker-entrypoint.sh, verbatim
ENTRYPOINT = r'''#!/bin/bash
if [ "${1:0:1}" == '-' ]; then
  set -- turnserver "$@"
fi
expanded=()
for i in "$@"; do
  expanded+=("$(eval "echo $i")")
done
printf '%s\n' "${expanded[@]}"
'''


def _ns(tmp_path):
    def run(argv, **kw):
        if argv[:2] == ['ip', '-o']:
            return types.SimpleNamespace(returncode=0, stdout=IP_ADDR, stderr='')
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    n = {'os': os, 're': re, 'ipaddress': ipaddress, 'threading': threading,
         'subprocess': types.SimpleNamespace(run=run),
         'REMOTE_ASSIST_INSTALL_DIR': str(tmp_path), 'load_settings': dict,
         'print': lambda *a, **k: None}
    i = APP.index('def _valid_core_ip(')
    src = (APP[APP.index('def _remote_assist_compose_files('):APP.index('def _ensure_authentik_remote_assist_app(')]
           + APP[i:APP.index('\ndef ', i + 1)] + '\n'
           + "_F2B_CONTAINER_IFACE_PREFIXES = ('docker', 'br-', 'podman', 'cni-podman')\n"
           + APP[APP.index("COTURN_IMAGE = "):APP.index('def _netbird_coturn_status(')])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


def _override(tmp_path, block_private=True):
    n = _ns(tmp_path)
    own, subnets = n['_coturn_box_addresses']()
    return n['_coturn_override_content']('3479', PUB, 'turnuser', 's3cretPass9', 'tak.example.com',
                                         block_private, own, subnets)


def _command(text):
    """coturn's argv as compose hands it to the entrypoint ($$ -> $)."""
    cmd = yaml.safe_load(text)['services']['coturn']['command']
    return [c.replace('$$', '$') for c in cmd]


def _entrypoint(tmp_path, args, hostname_out):
    """Run the image's entrypoint expansion with a stub `hostname -i`."""
    if not shutil.which('bash'):
        pytest.skip('bash not available')
    bindir = tmp_path / 'bin'
    bindir.mkdir(exist_ok=True)
    stub = bindir / 'hostname'
    stub.write_text(f'#!/bin/sh\n[ "$1" = "-i" ] && echo "{hostname_out}"\n')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    ep = tmp_path / 'entrypoint.sh'
    ep.write_text(ENTRYPOINT)
    env = dict(os.environ, PATH=f'{bindir}:{os.environ.get("PATH", "/usr/bin:/bin")}')
    r = subprocess.run(['bash', str(ep)] + args, capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout.splitlines()


def _ranges(argv, flag):
    out = []
    for a in argv:
        if a.startswith(f'--{flag}='):
            lo, _, hi = a.split('=', 1)[1].partition('-')
            out.append((ipaddress.ip_address(lo), ipaddress.ip_address(hi or lo)))
    return out


def _coturn_allows(argv, peer):
    """coturn 4.18 good_peer_addr() for an IPv4 peer, after its external->relay mapping
    (ns_turn_msg.c stun_attr_get_addr_str: a peer at --external-ip becomes the relay address,
    which is the --listening-ip, 0.0.0.0, when no --relay-ip is given)."""
    ext = next(a.split('=', 1)[1] for a in argv if a.startswith('--external-ip='))
    relay = next((a.split('=', 1)[1] for a in argv if a.startswith('--relay-ip=')), '0.0.0.0')
    if peer == ext:
        peer = relay
    p = ipaddress.ip_address(peer)
    if p.is_loopback or int(p) >> 24 == 0 or p.is_link_local:
        return False
    if any(lo <= p <= hi for lo, hi in _ranges(argv, 'allowed-peer-ip')):
        return True
    return not any(lo <= p <= hi for lo, hi in _ranges(argv, 'denied-peer-ip'))


def test_override_pins_the_relay_address_and_allows_exactly_it(tmp_path):
    text = _override(tmp_path)
    cmd = _command(text)
    self_addr = "$(hostname -i | cut -d' ' -f1)"
    assert [c for c in cmd if c.startswith('--allowed-peer-ip')] == [f'--allowed-peer-ip={self_addr}']
    assert [c for c in cmd if c.startswith('--relay-ip')] == [f'--relay-ip={self_addr}']
    # never the external IP: coturn maps it to the relay address before the check anyway
    assert PUB not in text.split('--allowed-peer-ip', 1)[1].split('\n', 1)[0]


@pytest.mark.parametrize('hostname_out', [CTR, f'{CTR} fd00:dead::6'])
def test_entrypoint_expands_it_to_the_container_address(tmp_path, hostname_out):
    argv = _entrypoint(tmp_path, _command(_override(tmp_path)), hostname_out)
    assert argv[0] == 'turnserver'
    assert f'--allowed-peer-ip={CTR}' in argv and f'--relay-ip={CTR}' in argv
    # every other argument comes through unchanged
    mine = ('--allowed-peer-ip', '--relay-ip')
    assert [a for a in argv[1:] if not a.startswith(mine)] == \
        [c for c in _command(_override(tmp_path)) if not c.startswith(mine)]


@pytest.mark.parametrize('block_private', [True, False])
def test_both_sides_relayed_call_is_allowed(tmp_path, block_private):
    argv = _entrypoint(tmp_path, _command(_override(tmp_path, block_private)), CTR)
    # A permits B's relayed address and vice versa: both are <external IP>:500xx
    assert _coturn_allows(argv, PUB)
    # and an ordinary internet peer still works
    assert _coturn_allows(argv, '8.8.8.8')


@pytest.mark.parametrize('block_private', [True, False])
def test_the_box_and_its_networks_stay_refused(tmp_path, block_private):
    argv = _entrypoint(tmp_path, _command(_override(tmp_path, block_private)), CTR)
    for peer in ('10.0.1.5', '172.17.0.1', '172.25.0.1', '172.25.0.2', '172.25.0.7', '172.20.0.3',
                 '127.0.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.1'):
        assert not _coturn_allows(argv, peer), (peer, block_private)
    for peer in ('10.9.9.9', '192.168.1.1'):
        assert _coturn_allows(argv, peer) is (not block_private), (peer, block_private)


def test_without_the_pinned_relay_address_the_call_is_refused(tmp_path):
    # the #269 override and the v10.2.28 one (no ACL at all): the external IP maps to 0.0.0.0
    mine = ('--allowed-peer-ip', '--relay-ip')
    argv = [a for a in _entrypoint(tmp_path, _command(_override(tmp_path)), CTR) if not a.startswith(mine)]
    assert not _coturn_allows(argv, PUB)
    assert not _coturn_allows([a for a in argv if not a.startswith('--denied-peer-ip')], PUB)
    # allowing the address without pinning the relay to it is not enough either
    argv_allow_only = [a for a in _entrypoint(tmp_path, _command(_override(tmp_path)), CTR)
                       if not a.startswith('--relay-ip')]
    assert not _coturn_allows(argv_allow_only, PUB)


def test_existing_269_override_is_converged_to_the_fix(tmp_path):
    n = _ns(tmp_path)
    old = re.sub(r'      - "--(relay-ip|allowed-peer-ip)=.*\n', '', _override(tmp_path))
    assert '--allowed-peer-ip' not in old and '--relay-ip' not in old
    (tmp_path / 'docker-compose.override.yml').write_text(old)
    settings = {'coturn_ip': PUB, 'coturn_port': '3479', 'coturn_username': 'turnuser',
                'coturn_password': 's3cretPass9', 'fqdn': 'tak.example.com'}
    assert n['_coturn_converge_override'](settings=settings) == 'rewritten'
    assert (tmp_path / 'docker-compose.override.yml').read_text() == _override(tmp_path)
