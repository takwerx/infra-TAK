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
"""Every console start dropped ATLAS's Caddy sites and :8449 (GH #137 follow-up).

Registry-resident modules (ATLAS MDM, TVR, Email Relay, Client Feed, Simulator) only read
as installed once `mod_registry.load_all()` has run, at the bottom of app.py. Three things
regenerate the Caddyfile at import, before that: the Hardened-posture re-assert, the
startup migrations and the post-update regen. Each wrote a file without those modules'
sites and reloaded Caddy. Before the GH #137 fix the validate backstop reverted that file
on Caddy 2.11.7, which hid it; with the fix it stuck (T&E on test8).

Now generate_caddyfile() builds but does not write until the registry is up, and one
catch-up regen runs right after it loads.

app.py cannot be imported in a test, so its helpers are cut out of it and run against
stubs: the code under test is the shipped text.
"""

import ast
import pathlib
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_GATE = ('_CADDY_REGISTRY_READY', '_CADDY_REGEN_DEFER_LOCK', '_CADDY_REGEN_DEFERRED',
         '_caddy_defer_until_registry', '_caddy_registry_loaded')


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _load(names, ns):
    exec(compile('\n\n'.join(_segment(n) for n in names), 'app.py:' + names[-1], 'exec'), ns)
    return ns


class _Caddy:
    """Stands in for the writer: records whether a regen happened before or after the
    registry, the way the real one decides (through the shipped gate)."""

    def __init__(self, ns, fqdn=True):
        self.ns, self.fqdn = ns, fqdn
        self.written, self.reloads, self.calls = [], 0, 0

    def generate(self, settings=None):
        self.calls += 1
        if not self.fqdn:
            return None
        text = 'atlas.example.com:8449 {}' if self.ns['registry_up'] else 'no atlas'
        if self.ns['_caddy_defer_until_registry']('generate_caddyfile'):
            return text
        self.written.append(text)
        return text

    def reload_if_changed(self, *a, **k):
        self.reloads += 1
        return True, ''


def _boot(fqdn=True):
    ns = {'threading': threading, 'registry_up': False}
    _load(_GATE, ns)
    caddy = _Caddy(ns, fqdn)
    ns['generate_caddyfile'] = caddy.generate
    ns['_caddy_reload_if_changed'] = caddy.reload_if_changed
    return ns, caddy


def _registry_loads(ns):
    ns['registry_up'] = True
    ns['_caddy_registry_loaded']()


# ── the gate ────────────────────────────────────────────────────────────────

def test_an_early_regen_is_not_written():
    ns, caddy = _boot()
    out = caddy.generate()
    assert out == 'no atlas'            # callers still get the content they check
    assert caddy.written == []          # but the box's file is untouched
    assert ns['_CADDY_REGEN_DEFERRED'] == ['generate_caddyfile']


def test_the_catch_up_writes_once_with_every_module_known():
    ns, caddy = _boot()
    caddy.generate()
    caddy.generate()
    caddy.generate()
    _registry_loads(ns)
    assert caddy.written == ['atlas.example.com:8449 {}']
    assert caddy.reloads == 1
    assert ns['_CADDY_REGEN_DEFERRED'] == []


def test_after_the_registry_a_regen_writes_straight_away():
    ns, caddy = _boot()
    _registry_loads(ns)
    assert caddy.written == []          # nothing was queued, so no catch-up
    caddy.generate()
    assert caddy.written == ['atlas.example.com:8449 {}']
    assert ns['_CADDY_REGEN_DEFERRED'] == []


def test_no_early_request_means_no_extra_regen_or_reload():
    """A box where nothing asked during import must not gain a regen + reload per start."""
    ns, caddy = _boot()
    _registry_loads(ns)
    assert caddy.written == [] and caddy.reloads == 0


def test_no_fqdn_means_no_reload():
    ns, caddy = _boot(fqdn=False)
    ns['_caddy_defer_until_registry']('hardening posture')
    _registry_loads(ns)
    assert caddy.reloads == 0


def test_a_failed_catch_up_does_not_break_the_import(capsys):
    ns, caddy = _boot()
    caddy.generate()

    def boom(settings=None):
        raise RuntimeError('broker down')
    ns['generate_caddyfile'] = boom
    _registry_loads(ns)                 # must not raise: app.py would fail to import
    assert 'post-registry Caddyfile regen failed' in capsys.readouterr().out


def test_the_catch_up_uses_the_unforced_reload():
    # GH #90: a forced reload cuts every WebTAK/CloudTAK socket on each console start.
    body = _segment('_caddy_registry_loaded')
    assert '_caddy_reload_if_changed()' in body
    assert '_caddy_reload()' not in body and '_caddy_reload_checked(' not in body


# ── the Hardened-posture re-assert (the call T&E caught) ──────────────────────

def _posture(locked=True):
    ns, caddy = _boot()
    printed = []
    ns.update({
        'load_hardening': lambda: {'posture': 'hardened',
                                   'applied': {'W1_sso': {'caddy_login_locked': locked}}},
        'os': type('os', (), {'getuid': staticmethod(lambda: 0)}),
        '_broker_should_route': lambda: False,
        'load_settings': lambda: {'console_port': 5001},
        '_w1_console_port_public': lambda p: False,
        '_fw_remove': lambda *a: printed.append(('fw_remove',) + a),
        'print': lambda *a, **k: printed.append(a),
    })
    _load(['_startup_ensure_hardening_posture'], ns)
    return ns, caddy, printed


def test_posture_at_import_queues_instead_of_writing():
    ns, caddy, printed = _posture()
    ns['_startup_ensure_hardening_posture']()
    assert caddy.calls == 0 and caddy.reloads == 0   # not even built: detect_modules is slow
    assert ('fw_remove', 5001, 'tcp') in printed     # the firewall half still runs at once
    _registry_loads(ns)
    assert caddy.written == ['atlas.example.com:8449 {}']
    assert caddy.reloads == 1


def test_posture_checks_the_gate_before_building_anything():
    body = _segment('_startup_ensure_hardening_posture')
    assert body.index("_caddy_defer_until_registry('hardening posture')") < body.index('generate_caddyfile()')
    # the firewall re-close is not held back
    assert body.index('_fw_remove(port') < body.index('_caddy_defer_until_registry(')


def test_posture_without_the_login_lock_queues_nothing():
    ns, caddy, _ = _posture(locked=False)
    ns['_startup_ensure_hardening_posture']()
    assert ns['_CADDY_REGEN_DEFERRED'] == []


# ── generate_caddyfile itself ─────────────────────────────────────────────────

def test_generate_returns_before_any_write():
    body = _segment('generate_caddyfile')
    gate = body.index("if _caddy_defer_until_registry('generate_caddyfile'):")
    # the content is complete (user blocks kept) before the gate...
    assert body.index('caddyfile += \'\\n\' + user_blocks') < gate
    # ...and nothing touches the box before it
    for write in ('_makedirs_priv(', '_write_priv(CADDYFILE_PATH', '_caddy_validate_or_restore(',
                  '_selinux_sync_caddy_ports()'):
        assert gate < body.index(write), write
    assert 'return caddyfile' in body[gate:body.index('_makedirs_priv(')]


# ── import order ──────────────────────────────────────────────────────────────

def _module_level_calls():
    out = []
    for node in TREE.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) \
                and isinstance(node.value.func, (ast.Name, ast.Attribute)):
            f = node.value.func
            out.append((node.lineno, f.id if isinstance(f, ast.Name) else f.attr))
    return out


def test_the_catch_up_runs_once_right_after_the_registry():
    calls = _module_level_calls()
    names = [n for _, n in calls]
    assert names.count('_caddy_registry_loaded') == 1
    line = dict((n, l) for l, n in calls)
    assert line['init_registry'] < line['_caddy_registry_loaded']
    # every import-time regen that T&E traced comes before it
    for early in ('_startup_ensure_hardening_posture', '_startup_migrations',
                  '_post_update_auto_deploy'):
        assert line[early] < line['_caddy_registry_loaded'], early


def test_the_gate_is_defined_before_anything_can_call_it():
    gate_line = next(n.lineno for n in TREE.body if isinstance(n, ast.Assign)
                     and any(getattr(t, 'id', None) == '_CADDY_REGISTRY_READY' for t in n.targets))
    line = dict((n, l) for l, n in _module_level_calls())
    for early in ('_startup_ensure_hardening_posture', '_startup_migrations',
                  '_post_update_auto_deploy'):
        assert gate_line < line[early], early
