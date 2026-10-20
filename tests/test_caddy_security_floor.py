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
"""Caddy security floor (2.11.7).

Caddy is not pinned: a box keeps whatever version it was installed at. The fleet
was mixed (2.11.4 on most boxes, 2.11.7 on one), and the only version gate was
the 2.7 parse floor, so nothing ever moved a 2.11.4 box. _caddy_lift_to_secure_floor
does, and console Update, Caddy → Update and the deploy gate all call it.

2.11.6 also added a 1-minute request-body idle timeout that cuts NetBird's quiet
gRPC streams (measured: a 90 s quiet HTTP/2 body is cut at 60.0 s through 2.11.7,
completes through 2.11.4 and through 2.11.7 with `read_body_idle -1s`).

app.py cannot be imported in a test, so the helper is cut out of it and run
against stubs: the code under test is the shipped text.
"""

import ast
import pathlib
import subprocess
from types import SimpleNamespace

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


class _Box:
    """A fake host: a Caddy version that the package sources can move."""

    def __init__(self, version, pm='apt', repo_ok=True, pkg_gives=(2, 11, 7),
                 fallback_gives=(2, 11, 7), validate=('ok', '')):
        self.version, self.pm, self.repo_ok = version, pm, repo_ok
        self.pkg_gives, self.fallback_gives = pkg_gives, fallback_gives
        self.verdict = validate
        self.calls, self.log = [], []

    def run(self, argv, **kw):
        self.calls.append(tuple(argv))
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    def pkg_install(self, pkgs, **kw):
        self.calls.append(('pkg_install',) + tuple(pkgs))
        if self.pkg_gives:
            self.version = max(self.version, self.pkg_gives)
        return True, ''

    def fallback(self, name):
        def _f(*a, **k):
            self.calls.append((name,))
            if self.fallback_gives:
                self.version = max(self.version, self.fallback_gives)
            return bool(self.fallback_gives)
        return _f

    def validate(self, *a, **k):
        self.calls.append(('validate',))
        return self.verdict

    def lift(self, restart=True, regenerate=True):
        ns = {
            'subprocess': SimpleNamespace(run=self.run, PIPE=subprocess.PIPE, STDOUT=subprocess.STDOUT),
            '_sudo_wrap': lambda argv: ['sudo'] + list(argv),
            '_caddy_version_tuple': lambda refresh=False: self.version,
            '_caddy_version_cache': {'ver': None},
            '_pkg_mgr': lambda: self.pm,
            '_pkg_install': self.pkg_install,
            '_caddy_ensure_apt_repo': lambda log=None: (self.calls.append(('ensure_repo',)) or self.repo_ok),
            '_caddy_install_github_deb': self.fallback('github_deb'),
            '_caddy_install_official_static': self.fallback('static'),
            '_caddy_validate_config': self.validate,
            'load_settings': lambda: {'fqdn': 'example.com'},
            'generate_caddyfile': lambda s: self.calls.append(('generate',)),
        }
        src = '\n\n'.join(_segment(n) for n in ('_CADDY_MIN_SECURE', '_caddy_lift_to_secure_floor'))
        exec(compile(src, 'app.py:_caddy_lift_to_secure_floor', 'exec'), ns)
        return ns['_caddy_lift_to_secure_floor'](self.log.append, restart=restart,
                                                 regenerate=regenerate)

    def did(self, name):
        return any(c[0] == name or name in c for c in self.calls)

    @property
    def restarts(self):
        return [c for c in self.calls if 'restart' in c]


def test_the_floor_is_2_11_7():
    ns = {}
    exec(_segment('_CADDY_MIN_SECURE'), ns)
    assert ns['_CADDY_MIN_SECURE'] == (2, 11, 7)


@pytest.mark.parametrize('version', [(2, 11, 7), (2, 12, 0), (3, 0, 0)])
def test_a_box_at_or_above_the_floor_is_left_alone(version):
    box = _Box(version)
    assert box.lift() == (version, version)
    assert box.calls == []


def test_an_unreadable_version_is_left_alone():
    """No Caddy, or `caddy version` failing: nothing to lift, and nothing safe to install over."""
    box = _Box(())
    assert box.lift() == ((), ())
    assert box.calls == []


def test_apt_lifts_from_the_package_repo_and_restarts_once():
    box = _Box((2, 11, 4))
    assert box.lift() == ((2, 11, 4), (2, 11, 7))
    assert box.did('ensure_repo') and box.did('pkg_install')
    assert not box.did('github_deb')
    assert len(box.restarts) == 1
    assert box.calls.index(('validate',)) < box.calls.index(box.restarts[0])


def test_apt_falls_back_to_the_github_deb_when_the_repo_is_not_serving():
    box = _Box((2, 11, 4), repo_ok=False)
    assert box.lift()[1] == (2, 11, 7)
    assert not box.did('pkg_install')
    assert box.did('github_deb')


def test_apt_falls_back_when_the_repo_is_behind():
    box = _Box((2, 11, 4), pkg_gives=(2, 11, 6))
    assert box.lift()[1] == (2, 11, 7)
    assert box.did('pkg_install') and box.did('github_deb')


def test_dnf_lifts_from_the_copr():
    box = _Box((2, 11, 4), pm='dnf')
    assert box.lift()[1] == (2, 11, 7)
    assert ('pkg_install', 'caddy') in box.calls
    assert not box.did('static')
    assert not box.did('ensure_repo')


def test_dnf_falls_back_to_the_static_build_when_the_copr_lags():
    box = _Box((2, 11, 4), pm='dnf', pkg_gives=None)
    assert box.lift()[1] == (2, 11, 7)
    assert box.did('static')


def test_still_short_is_said_out_loud_and_not_restarted_into():
    box = _Box((2, 11, 4), pkg_gives=None, fallback_gives=None)
    assert box.lift() == ((2, 11, 4), (2, 11, 4))
    assert any('still 2.11.4' in m for m in box.log)
    assert box.restarts == []


def test_the_caddyfile_is_regenerated_for_the_new_version_before_the_restart():
    """What the file emits depends on the version (read_body_idle for NetBird)."""
    box = _Box((2, 11, 4))
    box.lift()
    assert box.calls.index(('generate',)) < box.calls.index(('validate',)) \
        < box.calls.index(box.restarts[0])


def test_a_caddyfile_the_new_caddy_rejects_is_never_restarted_into():
    box = _Box((2, 11, 4), validate=('bad', 'duplicate forward_auth uri'))
    box.lift()
    assert box.restarts == []
    assert any('NOT restarting' in m for m in box.log)


def test_restart_false_regenerates_but_leaves_restarting_to_the_caller():
    box = _Box((2, 11, 4))
    box.lift(restart=False)
    assert box.did('generate')
    assert box.restarts == [] and not box.did('validate')


def test_deploy_mode_touches_neither_the_file_nor_the_service():
    box = _Box((2, 11, 4))
    box.lift(restart=False, regenerate=False)
    assert not box.did('generate') and box.restarts == []


def test_no_version_change_means_no_regeneration_and_no_restart():
    box = _Box((2, 11, 4), pkg_gives=None, fallback_gives=None)
    box.lift()
    assert not box.did('generate') and box.restarts == []


# ── read_body_idle: Caddy 2.11.6+ cuts quiet gRPC streams (NetBird) after 1 minute ──

def _rbi(version, grpc_streams):
    ns = {'_caddy_version_tuple': lambda: version}
    src = '\n\n'.join(_segment(n) for n in ('_CADDY_MIN_READ_BODY_IDLE', '_caddy_read_body_idle_lines'))
    exec(compile(src, 'app.py:_caddy_read_body_idle_lines', 'exec'), ns)
    return ns['_caddy_read_body_idle_lines'](grpc_streams)


@pytest.mark.parametrize('version', [(2, 11, 6), (2, 11, 7), (2, 12, 0)])
def test_netbird_boxes_on_2_11_6_and_newer_turn_read_body_idle_off(version):
    assert '\n'.join(_rbi(version, True)) == (
        '    servers {\n        timeouts {\n            read_body_idle -1s\n        }\n    }')


@pytest.mark.parametrize('version', [(2, 11, 4), (2, 7, 6), ()])
def test_older_or_unknown_caddy_gets_nothing(version):
    """2.11.4 rejects the whole file: "unrecognized timeouts option 'read_body_idle'"."""
    assert _rbi(version, True) == []


def test_boxes_without_netbird_keep_the_hardening():
    assert _rbi((2, 11, 7), False) == []


def test_the_global_block_carries_it_and_the_generator_keys_it_off_netbird():
    assert '_caddy_read_body_idle_lines(grpc_streams)' in _segment('_caddy_global_options_lines')
    assert "grpc_streams=bool(modules.get('netbird', {}).get('installed'))" in \
        _segment('generate_caddyfile')


def test_boxes_already_on_2_11_6_converge_at_console_start():
    body = _segment('_startup_migrations')
    assert body.index('\n            _startup_caddy_read_body_idle_converge()') < \
        body.index('\n            _startup_caddy_selfheal()')


# ── every path that should move a box calls it ───────────────────────────────

def test_console_update_lifts_the_box():
    """Console Update restarts the console, which runs the startup self-heal."""
    assert '_caddy_lift_to_secure_floor(' in _segment('_startup_caddy_selfheal')


def test_caddy_update_button_lifts_the_box_and_restarts_after():
    body = _segment('caddy_update')
    assert '_caddy_lift_to_secure_floor(_lift_log.append, restart=False)' in body
    assert body.index('_caddy_lift_to_secure_floor(') < body.index("'systemctl', 'restart', 'caddy'")


def test_deploy_lifts_a_caddy_that_was_already_installed():
    body = _segment('run_caddy_deploy')
    assert '_caddy_lift_to_secure_floor(plog, restart=False, regenerate=False)' in body
    assert body.index('_caddy_lift_to_secure_floor(') < body.index('Step 4/4')
