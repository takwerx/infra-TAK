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
"""NetBird opens and closes STUN 3478/udp through the firewall helpers, never bare `sudo ufw` (ops #1176).

Field: on a non-root console (every fresh install) the deploy step "Firewall & Reverse Proxy"
ran `sudo ufw allow 3478/udp` directly. The journal showed `user NOT in sudoers ...
COMMAND=/usr/sbin/ufw allow 3478/udp`, the result was ignored, and the log still printed
"STUN 3478/udp allowed". Uninstall had the same bare `sudo ufw delete`. Hard rule 1: firewall
changes go through _fw_allow / _fw_remove (ufw, firewalld, broker-wrapped).
"""

import pathlib
import re
import textwrap
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

STEP_START = "plog('━━━ Step 6/6: Firewall & Reverse Proxy ━━━')"
STEP_END = "fqdn = settings.get('fqdn', 'localhost')"


def _step6_block():
    start = APP.rindex(STEP_START) + len(STEP_START)  # the NetBird deploy is the last one
    end = APP.index(STEP_END, start)
    return textwrap.dedent(APP[start:end])


def _run_step6(fw_result):
    """Run the real Step 6 source with stubs; return (log lines, fw calls, saved settings)."""
    logs, calls, saved = [], [], []
    settings = {}

    def fw_allow(port, proto='tcp'):
        calls.append((port, proto))
        return fw_result

    ns = {
        'plog': logs.append,
        '_sp': types.SimpleNamespace(run=lambda *a, **k: None),  # old bare call, if present
        '_fw_allow': fw_allow,
        'settings': settings,
        'save_settings': lambda s: saved.append(dict(s)),
        'generate_caddyfile': lambda s: None,
        '_caddy_reload': lambda timeout=0: None,
    }
    exec(compile(_step6_block(), 'app.py:netbird-step6', 'exec'), ns)
    return logs, calls, saved


def test_no_bare_sudo_ufw_anywhere_in_app():
    bare = re.findall(r"\[\s*'sudo'\s*,\s*'ufw'", APP)
    assert bare == [], 'bare sudo ufw call found: use _fw_allow / _fw_remove / _sudo_wrap'


def test_deploy_opens_stun_through_fw_allow():
    _, calls, saved = _run_step6((True, ''))
    assert calls == [(3478, 'udp')]
    assert saved and saved[-1].get('netbird_enabled') is True


def test_deploy_says_allowed_only_when_the_rule_was_added():
    logs, _, _ = _run_step6((True, ''))
    assert any('STUN 3478/udp allowed' in l for l in logs)
    assert not any('⚠' in l for l in logs)


def test_deploy_warns_and_does_not_claim_allowed_when_firewall_refuses():
    logs, calls, saved = _run_step6((False, 'user NOT in sudoers'))
    assert calls == [(3478, 'udp')]
    assert not any('STUN 3478/udp allowed' in l for l in logs)
    assert any('⚠' in l and '3478/udp' in l for l in logs)
    # the refusal must not stop Caddy routes from going live
    assert saved and saved[-1].get('netbird_enabled') is True


def test_uninstall_closes_stun_through_fw_remove():
    anchor = APP.index('nb_dir = NETBIRD_INSTALL_DIR\n            # Tear down docker containers')
    body = APP[anchor:anchor + 1500]
    assert "_fw_remove(3478, 'udp')" in body
