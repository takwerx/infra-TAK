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
"""Security update for Remote Assist CoTURN (ops #201).

Console start and Remote Assist update rewrite an existing CoTURN override onto the pinned
image and current flags (keeping port, user and realm) and recreate only the coturn service.
The relay refuses loopback / link-local / CGNAT / Docker ranges and the box's own addresses,
and 10/8 + 192.168/16 unless "Block private peers" is turned off.
"""

import ipaddress
import os
import re
import threading
import types

REPO = __import__('pathlib').Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TEMPLATE = (REPO / 'templates' / 'remote_assist.html').read_text(encoding='utf-8')

# What the pre-v10.2.8 install wrote.
OLD_OVERRIDE = """services:
  coturn:
    image: coturn/coturn:4.14.0
    restart: unless-stopped
    ports:
      - "3479:3479/tcp"
      - "3479:3479/udp"
      - "50000-50050:50000-50050/udp"
    command:
      - -c
      - ""
      - --log-file=stdout
      - --external-ip=203.0.113.50
      - --listening-port=3479
      - --listening-ip=0.0.0.0
      - --min-port=50000
      - --max-port=50050
      - --user=turnuser:s3cretPass9
      - --realm=tak.example.com
"""

IP_ADDR = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 10.0.1.5/24 brd 10.0.1.255 scope global dynamic eth0\\       valid_lft 3000sec
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever
7: br-0a1b2c3d4e5f    inet 192.168.48.1/20 brd 192.168.63.255 scope global br-0a1b2c3d4e5f\\       valid_lft forever
"""

RANGE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(-\d{1,3}(\.\d{1,3}){3})?$')


def _func(name):
    i = APP.index(f'def {name}(')
    j = APP.index('\ndef ', i + 1)
    return APP[i:j] + '\n'


def _ns(tmp_path, settings=None, compose_rc=0, ip_out=IP_ADDR):
    calls = []

    def run(argv, **kw):
        calls.append((argv, kw))
        if argv[:2] == ['ip', '-o']:
            return types.SimpleNamespace(returncode=0, stdout=ip_out, stderr='')
        return types.SimpleNamespace(returncode=compose_rc, stdout='',
                                     stderr='' if compose_rc == 0 else 'Error response from daemon: pull failed')

    logs = []
    n = {'os': os, 're': re, 'ipaddress': ipaddress, 'threading': threading,
         'subprocess': types.SimpleNamespace(run=run),
         'REMOTE_ASSIST_INSTALL_DIR': str(tmp_path),
         'load_settings': lambda: dict(settings or {}),
         'print': lambda *a, **k: logs.append(' '.join(str(x) for x in a))}
    # the CoTURN block runs as written; its few seams come from the real helpers or stubs
    src = (APP[APP.index('def _remote_assist_compose_files('):APP.index('def _ensure_authentik_remote_assist_app(')]
           + _func('_valid_core_ip')
           + "_F2B_CONTAINER_IFACE_PREFIXES = ('docker', 'br-', 'podman', 'cni-podman')\n"
           + APP[APP.index("COTURN_IMAGE = "):APP.index('def _netbird_coturn_status(')])
    exec(compile(src, 'app.py', 'exec'), n)
    return n, calls, logs


def _flags(text):
    return re.findall(r'^\s*- (--[a-z-]+(?:=\S*)?)\s*$', text, re.M)


def _write(tmp_path, text):
    p = tmp_path / 'docker-compose.override.yml'
    p.write_text(text)
    return p


SETTINGS = {'coturn_installed': True, 'coturn_ip': '203.0.113.50', 'coturn_port': '3479',
            'coturn_username': 'turnuser', 'coturn_password': 's3cretPass9', 'fqdn': 'tak.example.com'}


def test_old_4140_override_is_rewritten_and_only_coturn_recreated(tmp_path):
    p = _write(tmp_path, OLD_OVERRIDE)
    n, calls, _ = _ns(tmp_path, SETTINGS)
    assert n['_coturn_converge_override']() == 'rewritten'
    new = p.read_text()
    assert 'image: coturn/coturn:4.18.0' in new and '4.14.0' not in new
    assert n['COTURN_IMAGE'] == 'coturn/coturn:4.18.0'
    # port, user, password, realm and external IP kept from the file
    for keep in ('"3479:3479/tcp"', '"3479:3479/udp"', '--listening-port=3479',
                 '--user=turnuser:s3cretPass9', '--realm=tak.example.com',
                 '--external-ip=203.0.113.50'):
        assert keep in new, keep
    compose = [a for a, _ in calls if a[:2] == ['docker', 'compose']]
    assert compose == [['docker', 'compose', '-f', str(tmp_path / 'docker-compose.yml'),
                        '-f', str(p), 'up', '-d', '--no-deps', 'coturn']]


def test_file_values_win_over_settings(tmp_path):
    # Keep what the running CoTURN actually uses, even if settings drifted.
    p = _write(tmp_path, OLD_OVERRIDE)
    drifted = dict(SETTINGS, coturn_port='4000', coturn_username='other', fqdn='new.example.org')
    n, _, _ = _ns(tmp_path, drifted)
    n['_coturn_converge_override']()
    new = p.read_text()
    assert '--listening-port=3479' in new and '--user=turnuser:' in new and '--realm=tak.example.com' in new


def test_rewritten_override_has_the_hardening_flags(tmp_path):
    p = _write(tmp_path, OLD_OVERRIDE)
    n, _, _ = _ns(tmp_path, SETTINGS)
    n['_coturn_converge_override']()
    flags = _flags(p.read_text())
    assert '--no-tcp-relay' in flags
    assert '--no-multicast-peers' in flags
    # never turn the telnet CLI on; --no-cli is deprecated in 4.18 (logs an ERROR) and CLI is off by default
    assert not any(f.startswith('--cli') for f in flags)
    denied = [f.split('=', 1)[1] for f in flags if f.startswith('--denied-peer-ip=')]
    for want in ('0.0.0.0-0.255.255.255', '127.0.0.0-127.255.255.255', '169.254.0.0-169.254.255.255',
                 '100.64.0.0-100.127.255.255', '172.16.0.0-172.31.255.255',
                 '10.0.0.0-10.255.255.255', '192.168.0.0-192.168.255.255'):
        assert want in denied, want
    # the box's own addresses, incl. the advertised external IP
    for own in ('10.0.1.5', '172.17.0.1', '192.168.48.1', '203.0.113.50'):
        assert _covered(own, denied), own
    assert '203.0.113.50' in denied
    # coturn aborts on a CIDR value — every value is IP or IP-IP
    assert denied and all(RANGE.match(d) for d in denied), denied
    # nothing re-opens a refused address
    assert not any(f.startswith('--allowed-peer-ip') for f in flags)
    # no entry sits inside another one
    assert len(denied) == len(set(denied))
    assert not any(d != e and _covered(d.split('-')[0], [e]) and _covered(d.split('-')[-1], [e])
                   for d in denied for e in denied)


def _in(addr, value):
    lo, _, hi = value.partition('-')
    return ipaddress.ip_address(lo) <= ipaddress.ip_address(addr) <= ipaddress.ip_address(hi or lo)


def _covered(addr, denied):
    return any(_in(addr, d) for d in denied)


def test_169_254_169_254_and_docker_bridge_gateway_are_denied(tmp_path):
    n, _, _ = _ns(tmp_path, SETTINGS)
    for block in (True, False):
        denied = n['_coturn_peer_acl']('203.0.113.50', block, ['172.17.0.1'], ['172.17.0.0/16'])
        for peer in ('169.254.169.254', '172.17.0.1', '127.0.0.1', '100.100.100.200', '203.0.113.50'):
            assert _covered(peer, denied), (peer, block)
        assert not _covered('8.8.8.8', denied)


def test_opt_out_drops_only_10_8_and_192_168_16(tmp_path):
    n, _, _ = _ns(tmp_path, SETTINGS)
    own, subnets = ['10.0.1.5', '192.168.48.1'], ['172.17.0.0/16', '192.168.48.0/20']
    on = n['_coturn_peer_acl']('203.0.113.50', True, own, subnets)
    off = n['_coturn_peer_acl']('203.0.113.50', False, own, subnets)
    assert set(on) - set(off) == {'10.0.0.0-10.255.255.255', '192.168.0.0-192.168.255.255'}
    probes = ['10.0.0.1', '10.0.1.5', '10.200.3.4', '192.168.1.1', '192.168.48.7', '192.168.48.1',
              '172.17.0.1', '172.20.5.5', '169.254.169.254', '127.0.0.1', '100.64.0.1', '0.1.2.3',
              '203.0.113.50', '8.8.8.8', '1.1.1.1']
    opened = {p for p in probes if _covered(p, on) and not _covered(p, off)}
    assert opened == {'10.0.0.1', '10.200.3.4', '192.168.1.1'}
    assert not {p for p in probes if _covered(p, off) and not _covered(p, on)}
    # a Docker network in 192.168/16 and the host's own LAN address stay refused with the opt-out
    assert '192.168.48.0-192.168.63.255' in off and '10.0.1.5' in off


def test_setting_defaults_on_and_opt_out_reaches_the_file(tmp_path):
    n, _, _ = _ns(tmp_path, SETTINGS)
    assert n['_coturn_block_private_peers']({}) is True
    assert n['_coturn_block_private_peers']({'coturn_block_private_peers': True}) is True
    assert n['_coturn_block_private_peers']({'coturn_block_private_peers': False}) is False
    p = _write(tmp_path, OLD_OVERRIDE)
    n, _, _ = _ns(tmp_path, dict(SETTINGS, coturn_block_private_peers=False))
    assert n['_coturn_converge_override']() == 'rewritten'
    text = p.read_text()
    assert '10.0.0.0-10.255.255.255' not in text and '192.168.0.0-192.168.255.255' not in text
    assert '172.16.0.0-172.31.255.255' in text and '169.254.0.0-169.254.255.255' in text


def test_current_override_is_left_alone(tmp_path):
    p = _write(tmp_path, OLD_OVERRIDE)
    n, _, _ = _ns(tmp_path, SETTINGS)
    n['_coturn_converge_override']()
    first = p.read_text()
    n, calls, _ = _ns(tmp_path, SETTINGS)
    assert n['_coturn_converge_override']() == 'current'
    assert p.read_text() == first
    assert not [a for a, _ in calls if a[:2] == ['docker', 'compose']]


def test_compose_failure_restores_the_old_file_so_next_start_retries(tmp_path):
    p = _write(tmp_path, OLD_OVERRIDE)
    n, _, logs = _ns(tmp_path, SETTINGS, compose_rc=1)
    assert n['_coturn_converge_override']() == 'failed'
    assert p.read_text() == OLD_OVERRIDE
    assert any('pull failed' in l for l in logs)


def test_no_override_and_netbird_shared_mode_are_untouched(tmp_path):
    n, calls, _ = _ns(tmp_path, SETTINGS)
    assert n['_coturn_converge_override']() == 'absent'
    p = _write(tmp_path, OLD_OVERRIDE)
    n, calls, _ = _ns(tmp_path, dict(SETTINGS, netbird_coturn_in_use=True))
    assert n['_coturn_converge_override']() == 'netbird'
    assert p.read_text() == OLD_OVERRIDE and not calls


def test_unreadable_override_is_skipped_not_clobbered(tmp_path):
    hostile = OLD_OVERRIDE.replace('--user=turnuser:s3cretPass9', '--user=bad user:"x\ny"')
    p = _write(tmp_path, hostile)
    n, calls, logs = _ns(tmp_path, {'coturn_installed': True})   # nothing usable in settings either
    assert n['_coturn_converge_override']() == 'skipped'
    assert p.read_text() == hostile
    assert not [a for a, _ in calls if a[:2] == ['docker', 'compose']]


def test_box_addresses_from_ip_addr(tmp_path):
    n, _, _ = _ns(tmp_path, SETTINGS)
    own, subnets = n['_coturn_box_addresses']()
    assert own == ['10.0.1.5', '127.0.0.1', '172.17.0.1', '192.168.48.1']
    assert subnets == ['172.17.0.0/16', '192.168.48.0/20']


def test_install_uses_the_one_builder():
    # one writer: a fresh install and a converged box get the same file
    assert APP.count('image: {COTURN_IMAGE}') == 1
    body = _func('remote_assist_coturn_install')
    assert '_coturn_override_content(' in body and 'override_content = f"""' not in body


def test_startup_and_remote_assist_update_run_the_converge():
    mig = APP[APP.index('def _startup_migrations('):]
    mig = mig[:mig.index('\ndef ')]
    assert 'target=_startup_converge_coturn' in mig
    assert '_coturn_converge_override(' in _func('_run_remote_assist_update')


def test_opt_out_route_is_authed_and_asks_for_the_admin_password():
    i = APP.index("@app.route('/api/remote-assist/coturn/peer-policy'")
    head = APP[i:APP.index('def remote_assist_coturn_peer_policy(', i)]
    assert '@login_required' in head
    body = _func('remote_assist_coturn_peer_policy')
    assert re.search(r'if not block:\s+_denied = _require_admin_password\(data\)', body)


def test_page_has_the_block_private_peers_setting():
    import jinja2
    jinja2.Environment().parse(TEMPLATE)          # template still compiles
    assert 'coturn_block_private=_coturn_block_private_peers(settings)' in _func('remote_assist_page')
    assert 'id="coturn-block-private"{% if coturn_block_private %} checked{% endif %}' in TEMPLATE
    assert 'Block private peers' in TEMPLATE and 'field-kit' in TEMPLATE
    assert "/api/remote-assist/coturn/peer-policy" in TEMPLATE
