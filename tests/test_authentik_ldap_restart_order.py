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
"""The LDAP outpost is (re)started only after the Authentik server it talks to.

Field (v10.2.11 T&E, all 5 boxes): the post-update auto-reconfigure recreated LDAP and THEN
restarted server/worker. The fresh outpost fetched its config from the old server, the server
stopped, the provider list came back 502 and the outpost panicked ("Failed to run server"),
recovering only through docker's restart policy. An outpost that starts while the server is
still booting just retries its config fetch, so the safe order is server, wait, LDAP.

The two restarts live inline in large functions, so this checks the shipped text: within each
block the server restart comes first, then the wait, then the LDAP recreate.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _block(start_marker, end_marker):
    start = APP.index(start_marker)
    end = APP.index(end_marker, start)
    return APP[start:end]


def _pos(block, pattern):
    m = re.search(pattern, block)
    assert m, f'not found in block: {pattern}'
    return m.start()


def test_reconfigure_domain_sync_restarts_server_before_ldap():
    # ops #316: the restart now runs only when the domain really changed, after the sync's
    # own "Domain sync:" error line, so the block ends at the restart's success line.
    block = _block('Syncing Authentik domain from Caddy/Domains', 'to pick up new domain')
    server = _pos(block, r"'restart', 'server', 'worker'")
    wait = _pos(block, r'_wait_for_authentik_api\(')
    ldap = _pos(block, r"'--force-recreate', 'ldap'")
    assert server < wait < ldap
    # exactly one LDAP recreate in the block: no leftover from the old order
    assert len(re.findall(r"'ldap'\]", block)) == 1


def test_post_update_compose_hardening_recreates_ldap_after_server():
    block = _block('Authentik compose hardened', 'CapDrop was applied')
    core = _pos(block, r"'--force-recreate', 'worker', 'server'\]")
    wait = _pos(block, r'_wait_for_authentik_stack_healthy\(')
    ldap = _pos(block, r"'--force-recreate', '--no-deps', 'ldap'\]")
    assert core < wait < ldap
    # LDAP must not ride along in the server/worker `up`
    assert "'worker', 'server', 'ldap'" not in block


def test_no_ldap_recreate_immediately_followed_by_server_restart():
    # The exact anti-pattern: an LDAP recreate whose next compose call restarts the server.
    calls = re.findall(r"_sudo_wrap\(\['docker', 'compose'[^\]]*\]", APP)
    for prev, nxt in zip(calls, calls[1:]):
        if re.search(r"'(up|restart)'[^\]]*'ldap'", prev) and 'ldap' not in nxt:
            assert not re.search(r"'restart'[^\]]*'server'", nxt), (prev, nxt)
