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
"""GH #315 — Firewall > Service Exposure flagged ZeroTier's 9993/tcp "review".

Two causes. The firewall-rule reader ignored the protocol, so the `9993/udp ALLOW` rule ZeroTier
needs made the TCP 9993 listener look reachable (and so flagged). And ZeroTier was not a
recognised service. Now UDP rules don't count for a TCP listener, and `zerotier-one` is known.
An unknown listener that is really reachable must still be flagged.

The audit is cut out of app.py and run (app.py cannot be imported in a test), so the code under
test is the shipped text.
"""

import ast
import pathlib
import re
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_WANT = {'PORT_EXPOSURE_POLICY', '_KNOWN_PUBLIC_PORTS', '_EXPOSURE_TTL',
         '_exposure_bind_of', '_exposure_fw_states', '_exposure_verdict', '_exposure_report'}


def _report(listeners, rules, enabled=True):
    """listeners: {port: proc name}, all bound publicly. rules: ufw-style rule lines."""
    parts = []
    for n in ast.parse(APP).body:
        name = n.name if isinstance(n, ast.FunctionDef) else None
        if isinstance(n, ast.Assign):
            name = next((t.id for t in n.targets if isinstance(t, ast.Name)), None)
        if name in _WANT or name == '_KNOWN_PUBLIC_PROCS':
            parts.append(ast.get_source_segment(APP, n))
    assert len(parts) >= len(_WANT), 'a function under test was renamed or removed'
    listen_map = {p: {'scopes': {'public'}, 'procs': {proc}, 'pids': set()}
                  for p, proc in listeners.items()}
    ns = {'time': time, 're': re, '_exposure_cache': {'ts': 0.0, 'data': None},
          'load_settings': lambda: {}, 'detect_modules': lambda: {},
          '_exposure_listen_map': lambda: listen_map,
          '_firewall_status_local': lambda: {'supported': True, 'enabled': enabled, 'rules': rules},
          '_policy_port': lambda ent, settings, cp: ent['port'] or cp,
          '_caddy_https_port': lambda s: 443, '_caddy_http_port': lambda s: 80,
          '_pid_is_takserver': lambda pid: False}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns['_exposure_report'](force=True)


# What `ufw status` prints on a ZeroTier host: UDP 9993 allowed, no TCP rule for it.
ZT_RULES = ['22/tcp                     ALLOW       Anywhere',
            '9993/udp                   ALLOW       Anywhere',
            '9993/udp (v6)              ALLOW       Anywhere (v6)']


def test_zerotier_tcp_listener_with_udp_rule_is_not_flagged():
    r = _report({9993: 'zerotier-one'}, ZT_RULES)
    assert r['undeclared'] == []
    assert r['summary'] == {'status': 'ok', 'issue_count': 0, 'warn_count': 0}


def test_udp_allow_does_not_make_a_tcp_listener_reachable():
    # An unrelated daemon on 9993/tcp, with only the UDP rule: blocked, so counted as blocked,
    # not flagged. Before the fix the UDP rule marked it open and it landed in `undeclared`.
    r = _report({9993: 'mystery'}, ZT_RULES)
    assert r['undeclared'] == []
    assert r['firewall_blocked'] == 1
    assert r['summary']['warn_count'] == 0


def test_reachable_unknown_listener_is_still_flagged():
    r = _report({9993: 'mystery'}, ZT_RULES + ['9993/tcp                   ALLOW       Anywhere'])
    assert [u['port'] for u in r['undeclared']] == [9993]
    assert r['summary']['status'] == 'warn'


def test_unknown_listener_with_no_firewall_is_still_flagged():
    r = _report({6666: 'mystery'}, [], enabled=False)
    assert [u['port'] for u in r['undeclared']] == [6666]
