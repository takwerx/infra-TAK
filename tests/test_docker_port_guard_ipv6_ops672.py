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
"""ops #672: the remote-host port guard covers IPv6 as well as IPv4.

Docker publishes each port on 0.0.0.0 and on [::] (docker-proxy). The IPv4 side is DNAT'd and
filtered in DOCKER-USER; the IPv6 side is proxied, so it enters through INPUT and DOCKER-USER
does not see it. The guard therefore also refuses IPv6 to its ports in INPUT (and in ip6tables
DOCKER-USER where that chain exists), for everything except the box's own interfaces.
The guard script is pure text, so these tests run the real script under sh with fake
iptables/ip6tables that log their calls and know which rules exist.
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

# Fake firewall tool: log every call; answer -C (check) from a state file; list the rules the
# test planted for -S; create/insert/delete update the state.
_FAKE = r'''#!/bin/sh
tool=$(basename "$0")
all="$*"
echo "$tool $all" >> "$LOG"
case "$all" in
  *" -S "*)
    chain="${all##* -S }"
    [ -f "$STATE.$tool.$chain" ] && cat "$STATE.$tool.$chain"
    exit 0;;
  *" -C "*) grep -qxF -- "$all" "$STATE.checked.$tool" 2>/dev/null && exit 0 || exit 1;;
  *" -I "*) echo "$all" | sed 's/ -I / -C /' >> "$STATE.checked.$tool";;
  *" -N "*) [ -f "$STATE.chain.$tool" ] && exit 1; touch "$STATE.chain.$tool";;
esac
exit 0
'''


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


def _script(ports=(9090, 5000), ips=('203.0.113.10',), name='guard'):
    return _ns()['_docker_port_guard_files'](name, list(ports), list(ips))[0]


def _run(tmp_path, script, *, ip6tables=True, ipv6_kernel=True, planted=None, runs=1, env_extra=None):
    """Run `script` under sh. Returns (last CompletedProcess, [logged calls])."""
    bindir = tmp_path / 'bin'
    bindir.mkdir(exist_ok=True)
    for tool in ('iptables', 'ip6tables'):
        if tool == 'ip6tables' and not ip6tables:
            continue
        f = bindir / tool
        f.write_text(_FAKE)
        f.chmod(0o755)
    marker = tmp_path / 'if_inet6'
    if ipv6_kernel:
        marker.write_text('')
    # the script tests the kernel's IPv6 marker file; point it at a path the test controls
    script = script.replace('/proc/net/if_inet6', str(marker))
    (tmp_path / 'guard.sh').write_text(script)
    for key, text in (planted or {}).items():
        (tmp_path / f'state.{key}').write_text(text)
    env = {**os.environ, 'PATH': f'{bindir}:/usr/bin:/bin', 'LOG': str(tmp_path / 'log'),
           'STATE': str(tmp_path / 'state'), **(env_extra or {})}
    r = None
    for _ in range(runs):
        r = subprocess.run(['sh', str(tmp_path / 'guard.sh')], env=env, capture_output=True, text=True)
    log = (tmp_path / 'log').read_text().splitlines() if (tmp_path / 'log').exists() else []
    return r, log


def _v6(log):
    return [c for c in log if c.startswith('ip6tables ')]


def test_script_refuses_ipv6_to_each_port_in_input():
    script = _script()
    for p in (9090, 5000):
        assert f'ip6tables -w -I INPUT -p tcp --dport {p} -j "$C"' in script
    chain = [ln.strip() for ln in script.splitlines() if ln.strip().startswith('ip6tables -w -A "$C"')]
    assert any('-i lo -j RETURN' in ln for ln in chain), 'the box itself keeps access'
    assert any('-i docker0 -j RETURN' in ln for ln in chain)
    assert any('-i br-+ -j RETURN' in ln for ln in chain)
    # No source is allowed over IPv6, and the last rule resets the connection (not DROP): a client
    # that tries IPv6 first falls back to IPv4 at once.
    assert not any(' -s ' in ln for ln in chain)
    assert chain[-1].startswith('ip6tables -w -A "$C" -p tcp -j REJECT --reject-with tcp-reset')


def test_script_also_covers_ipv6_docker_forwarding():
    script = _script()
    assert 'ip6tables -w -S DOCKER-USER >/dev/null 2>&1' in script
    assert ('ip6tables -w -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 9090 --ctdir ORIGINAL -j "$C"') in script


def test_script_installs_the_ipv6_rules_and_is_idempotent(tmp_path):
    r, log = _run(tmp_path, _script(), runs=2)
    assert r.returncode == 0, r.stderr
    v6 = _v6(log)
    assert sum(' -I INPUT ' in c for c in v6) == 2, 'one jump per port, a rerun must not stack more'
    assert sum(c.endswith('-j REJECT --reject-with tcp-reset') for c in v6) == 2  # chain rebuilt each run
    assert sum(' -I DOCKER-USER ' in c for c in v6) == 2


def test_script_skips_ipv6_when_the_kernel_has_none(tmp_path):
    r, log = _run(tmp_path, _script(), ip6tables=False, ipv6_kernel=False)
    assert r.returncode == 0, r.stderr
    assert not _v6(log)
    assert any(c.startswith('iptables ') and '-I DOCKER-USER' in c for c in log), 'the IPv4 guard still installs'


def test_script_fails_closed_when_ipv6_is_on_but_ip6tables_is_missing(tmp_path):
    r, _ = _run(tmp_path, _script(), ip6tables=False, ipv6_kernel=True)
    assert r.returncode == 1
    assert 'ip6tables not found' in r.stderr


def test_script_stops_when_an_ipv6_rule_cannot_be_added(tmp_path):
    r, _ = _run(tmp_path, _script().replace('ip6tables -w -A "$C" -i lo -j RETURN || exit 1',
                                        'false || exit 1'))
    assert r.returncode == 1


def test_a_port_left_off_the_list_gets_its_ipv6_jumps_removed(tmp_path):
    planted = {
        'ip6tables.INPUT': ('-P INPUT ACCEPT\n'
                            '-A INPUT -p tcp -m tcp --dport 5000 -j INFRATAK-GUARD\n'
                            '-A INPUT -p tcp -m tcp --dport 9090 -j INFRATAK-GUARD\n'
                            '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n'),
        'ip6tables.DOCKER-USER': ('-N DOCKER-USER\n'
                                  '-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 5000 --ctdir ORIGINAL -j INFRATAK-GUARD\n'),
        'iptables.DOCKER-USER': '',
    }
    r, log = _run(tmp_path, _script(ports=(9090,)), planted=planted)
    assert r.returncode == 0, r.stderr
    v6 = _v6(log)
    assert 'ip6tables -w -D INPUT -p tcp --dport 5000 -j INFRATAK-GUARD' in v6
    assert 'ip6tables -w -D DOCKER-USER -p tcp -m conntrack --ctorigdstport 5000 --ctdir ORIGINAL -j INFRATAK-GUARD' in v6
    assert not any(' -D ' in c and ('9090' in c or ' 22 ' in c) for c in v6), 'only the dropped port, only our chain'


def test_ipv6_console_address_is_still_refused_as_input():
    # The console reaches the remote over IPv4 only; an IPv6 "console" never gets an allow rule.
    with pytest.raises(ValueError):
        _ns()['_docker_port_guard_files']('guard', [9090], ['2001:db8::1'])


def test_remote_install_checks_the_ipv6_jump_too():
    sent = []

    def run(cfg, cmd, timeout=120, log_fn=None):
        sent.append(cmd)
        if cmd.startswith('echo "SSHSRC'):
            return True, 'SSHSRC 10.0.0.9'
        return True, 'GUARD_OK had=no'

    ok, _ = _ns(run)['_remote_docker_port_guard']({'target_mode': 'remote'}, {}, 'nodered', [1880])
    assert ok
    install = sent[-1]
    assert ('{ [ ! -e /proc/net/if_inet6 ] || $S ip6tables -w -C INPUT -p tcp --dport 1880 -j INFRATAK-NODERED; }'
            in install)
    # the check sits before GUARD_OK, so a missing IPv6 jump makes the install report a failure
    assert install.index('ip6tables -w -C INPUT') < install.index('GUARD_OK')
    script = base64.b64decode(re.search(r'echo (\S+) \| base64 -d \| \$S tee /usr/local/sbin/', install).group(1)).decode()
    assert 'ip6tables -w -I INPUT -p tcp --dport 1880 -j "$C"' in script


@pytest.mark.parametrize('name,ports', [('nodered', [1880]), ('webodm', [8000]),
                                        ('authentik', [9090, 389, 636, 9443]), ('cloudtak', [5000, 5002, 9000])])
def test_every_guard_name_gets_the_ipv6_rules(name, ports):
    script = _script(ports=ports, name=name)
    for p in ports:
        assert f'ip6tables -w -I INPUT -p tcp --dport {p} -j "$C"' in script
    assert f'C=INFRATAK-{name.upper()}' in script
