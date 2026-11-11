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
"""ops #615: a remote Node-RED's port 1880 is reachable only from the console.

The remote compose publishes 0.0.0.0:1880 (Caddy on the console proxies to it). The deploy
then ran `ufw deny 1880/tcp`, but Docker's published ports skip ufw, so the port answered
from anywhere (proved on Azure Ubuntu 22.04, 2026-11-10).
The fix is a DOCKER-USER guard installed as a systemd unit tied to docker.service. The
helpers are pure, so these tests run them for real (the script under sh with a fake
iptables); the deploy and startup wiring are checked on the source.
"""

import ast
import base64
import ipaddress
import os
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_NAMES = ('_docker_port_guard_files', '_remote_docker_port_guard')


def _ns(module_run=None, server_ip=None):
    ns = {'re': re, 'ipaddress': ipaddress, '_b64': base64,
          '_module_run': module_run or (lambda *a, **k: (True, '')),
          '_fedhub_caddy_source_ip': lambda s: server_ip}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _NAMES:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') == '_PORT_GUARD_NAME_RE':
            exec(ast.get_source_segment(APP, node), ns)
    missing = [n for n in _NAMES if n not in ns]
    assert not missing, f'ops #615 port guard helpers missing from app.py: {missing}'
    return ns


def _func_src(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def test_guard_drops_everyone_but_console_and_local_bridges():
    script, _ = _ns()['_docker_port_guard_files']('nodered', [1880], ['203.0.113.10'])
    body = [ln for ln in script.splitlines() if ln.startswith('iptables')]
    chain_rules = [ln for ln in body if ' -A "$C" ' in ln]
    assert chain_rules[0].startswith('iptables -w -A "$C" -s 203.0.113.10 -j RETURN')
    assert any('-i docker0 -j RETURN' in ln for ln in chain_rules)
    assert any('-i br-+ -j RETURN' in ln for ln in chain_rules)
    assert chain_rules[-1].startswith('iptables -w -A "$C" -j DROP'), 'last rule must drop everyone else'
    # Host port before DNAT, original direction only, and only inserted once.
    assert ('iptables -w -C DOCKER-USER -p tcp -m conntrack --ctorigdstport 1880 --ctdir ORIGINAL -j "$C" 2>/dev/null'
            ' || iptables -w -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 1880 --ctdir ORIGINAL -j "$C"') in script


def test_no_console_ip_fails_closed():
    script, _ = _ns()['_docker_port_guard_files']('nodered', [1880], [])
    assert ' -s ' not in script
    assert 'iptables -w -A "$C" -j DROP' in script


def test_unit_comes_back_with_every_docker_start():
    _, unit = _ns()['_docker_port_guard_files']('nodered', [1880], ['203.0.113.10'])
    for line in ('After=docker.service', 'PartOf=docker.service', 'WantedBy=docker.service',
                 'Type=oneshot', 'RemainAfterExit=yes', 'ExecStart=/usr/local/sbin/infratak-port-guard-nodered'):
        assert line in unit.splitlines(), line


@pytest.mark.parametrize('name,ports,ips', [
    ('node red', [1880], []), ('nodered;id', [1880], []), ('nodered', [], []),
    ('nodered', [0], []), ('nodered', [70000], []), ('nodered', [1880], ['1.2.3.4; rm -rf /']),
    ('nodered', [1880], ['2001:db8::1']),
])
def test_bad_input_never_reaches_the_script(name, ports, ips):
    with pytest.raises(ValueError):
        _ns()['_docker_port_guard_files'](name, ports, ips)


def test_script_runs_and_is_idempotent(tmp_path):
    """Run the real script under sh with a fake iptables that logs and knows which rules exist."""
    script, _ = _ns()['_docker_port_guard_files']('nodered', [1880], ['203.0.113.10'])
    # this test is about the IPv4 rules: take the kernel's IPv6 marker out of the picture
    # (the IPv6 half is covered in test_docker_port_guard_ipv6_ops672.py)
    (tmp_path / 'guard.sh').write_text(script.replace('/proc/net/if_inet6', str(tmp_path / 'no-ipv6')))
    fake = tmp_path / 'bin' / 'iptables'
    fake.parent.mkdir()
    fake.write_text('#!/bin/sh\n'
                    'echo "$*" >> "$LOG"\n'
                    'case "$*" in *" -C DOCKER-USER "*) [ -f "$STATE" ] && exit 0 || exit 1;; '
                    '*" -I DOCKER-USER "*) touch "$STATE";; esac\nexit 0\n')
    fake.chmod(0o755)
    env = {**os.environ, 'PATH': f'{fake.parent}:/usr/bin:/bin',
           'LOG': str(tmp_path / 'log'), 'STATE': str(tmp_path / 'inserted')}
    for _ in range(2):
        r = subprocess.run(['sh', str(tmp_path / 'guard.sh')], env=env, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
    calls = (tmp_path / 'log').read_text().splitlines()
    assert sum(' -I DOCKER-USER ' in c for c in calls) == 1, 'a rerun must not stack a second jump'
    assert sum(c.endswith('-j DROP') for c in calls) == 2  # chain rebuilt each run (flush + refill)


def test_remote_install_allows_ssh_source_and_server_ip_only():
    sent = []

    def run(cfg, cmd, timeout=120, log_fn=None):
        sent.append(cmd)
        if cmd.startswith('echo "SSHSRC'):
            return True, 'SSHSRC 10.0.0.9'
        return True, 'GUARD_OK had=no'

    ok, first = _ns(run, server_ip='198.51.100.7')['_remote_docker_port_guard'](
        {'target_mode': 'remote'}, {}, 'nodered', [1880])
    assert (ok, first) == (True, True)
    install = sent[-1]
    script = base64.b64decode(re.search(r'echo (\S+) \| base64 -d \| \$S tee /usr/local/sbin/', install).group(1)).decode()
    assert '-s 10.0.0.9 -j RETURN' in script and '-s 198.51.100.7 -j RETURN' in script
    assert 'systemctl enable infratak-port-guard-nodered.service' in install
    assert 'iptables -w -C DOCKER-USER -p tcp -m conntrack --ctorigdstport 1880' in install


def test_remote_install_ignores_a_garbage_ssh_source_and_reports_failure():
    def run(cfg, cmd, timeout=120, log_fn=None):
        if cmd.startswith('echo "SSHSRC'):
            return True, 'SSHSRC $(id)'
        return False, 'sudo: a password is required'

    ok, first = _ns(run)['_remote_docker_port_guard']({'target_mode': 'remote'}, {}, 'nodered', [1880])
    assert (ok, first) == (False, False)


def test_local_target_sends_nothing():
    sent = []
    ok, _ = _ns(lambda *a, **k: sent.append(a) or (True, ''))['_remote_docker_port_guard'](
        {'target_mode': 'local'}, {}, 'nodered', [1880])
    assert ok and not sent


def test_remote_deploy_locks_1880_before_the_container_starts():
    src = _func_src('_run_nodered_deploy_remote')
    assert '"0.0.0.0:1880:1880"' in src  # still published for Caddy, so the guard is required
    guard = src.index("_remote_docker_port_guard(deploy_cfg, settings, 'nodered', [1880]")
    assert guard < src.index('docker compose pull') < src.index('docker compose up -d')
    # No lock means no start.
    after = src[guard:src.index('docker compose pull')]
    assert 'if not _nr_guard_ok' in after and 'return' in after


def test_existing_remote_boxes_get_the_guard_on_console_start():
    src = _func_src('_startup_guard_remote_nodered_port')
    assert "_remote_docker_port_guard(cfg, settings, 'nodered', [1880]" in src
    assert 'you did not write' in src and 'delete it and rebuild the remote box' in src
    assert 'threading.Thread(target=_startup_guard_remote_nodered_port, daemon=True).start()' in APP
