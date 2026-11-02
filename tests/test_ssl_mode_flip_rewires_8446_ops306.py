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
"""Switching from a custom certificate back to automatic HTTPS re-wires TAK Server's 8446
enrollment connector (ops #306).

Uploading a custom certificate re-wires 8446 onto it, but /api/caddy/ssl-mode (back to Let's
Encrypt) only regenerated the Caddyfile. 8446 stayed on the operator's certificate (Cloudflare
Origin on the Cape Security Patrol box, trusted by nothing but Cloudflare) until the daily
console restart, so QR enrollment and CloudTAK login kept failing after the operator had done
the right thing. The helper now starts the 8446 install in the background and the route calls it.

app.py cannot be imported in a test, so the helper is cut out of it and run against stubs: the
code under test is the shipped text.
"""

import ast
import pathlib
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _helper(tak_present, host, calls, done):
    """Load the shipped helper with its collaborators stubbed."""
    class _OS:
        class path:
            @staticmethod
            def exists(p):
                return tak_present and p == '/opt/tak/CoreConfig.xml'

    def _install(h, log):
        calls.append(h)
        log('stub')
        done.set()

    ns = {
        'os': _OS,
        'threading': threading,
        'load_settings': lambda: {'fqdn': 'example.org'},
        '_get_service_domain': lambda s, name: host if name == 'takserver' else '',
        '_install_le_cert_on_8446_at_deploy': _install,
    }
    exec(_segment('_rewire_8446_after_acme_flip'), ns)
    return ns['_rewire_8446_after_acme_flip']


def test_flip_to_automatic_starts_the_8446_install_for_the_tak_server_name():
    calls, done = [], threading.Event()
    assert _helper(True, 'takserver.example.org', calls, done)() is True
    assert done.wait(5)
    assert calls == ['takserver.example.org']


def test_no_tak_server_here_means_nothing_to_rewire():
    calls, done = [], threading.Event()
    assert _helper(False, 'takserver.example.org', calls, done)() is False
    assert not done.wait(0.2) and calls == []


def test_no_tak_server_name_means_nothing_to_rewire():
    calls, done = [], threading.Event()
    assert _helper(True, '', calls, done)() is False
    assert not done.wait(0.2) and calls == []


def test_a_failing_install_does_not_raise_into_the_request():
    done = threading.Event()
    helper = _helper(True, 'takserver.example.org', [], done)
    # replace the stub install with one that raises
    helper.__globals__['_install_le_cert_on_8446_at_deploy'] = lambda h, log: (_ for _ in ()).throw(RuntimeError('boom'))
    assert helper() is True


def test_the_ssl_mode_route_calls_the_helper_after_reloading_caddy():
    route = _segment('caddy_set_ssl_mode')
    assert '_rewire_8446_after_acme_flip()' in route
    assert route.index('_caddy_reload_checked') < route.index('_rewire_8446_after_acme_flip()')
