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
"""WebTAK / CloudTAK sockets across a Caddy reload (GH #90).

Caddy closes every proxied WebSocket the moment a reload unloads the config, and
`systemctl reload caddy` is `caddy reload --force`, so it reloads even when nothing changed.
Two startup steps regenerated the Caddyfile and reloaded it on every console start (and every
gunicorn worker respawn), so WebTAK went red each time.

  * the TAK Server and CloudTAK map vhosts carry `stream_close_delay` (Caddy >= 2.7 only —
    an unknown directive makes the whole Caddyfile unloadable), and
  * those startup steps use an unforced reload, which Caddy skips when it is already running
    the file.

app.py cannot be imported in a test, so the helpers are cut out of it and run against stubs:
the code under test is the shipped text.
"""

import ast
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


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


# ── stream_close_delay emitter ───────────────────────────────────────────────

def _delay_lines(version):
    ns = _load(['CADDY_STREAM_CLOSE_DELAY', '_CADDY_MIN_STREAM_CLOSE_DELAY',
                '_caddy_stream_close_delay_lines'],
               {'_caddy_version_tuple': lambda: version})
    return ns['_caddy_stream_close_delay_lines']('        ')


def test_delay_emitted_on_modern_caddy():
    assert _delay_lines((2, 11, 4)) == ['        stream_close_delay 5m']
    assert _delay_lines((2, 7, 0)) == ['        stream_close_delay 5m']


@pytest.mark.parametrize('version', [(2, 6, 2), (2, 4, 5), ()])
def test_delay_never_emitted_on_old_or_unknown_caddy(version):
    # Below 2.7 the directive does not exist and the whole Caddyfile would fail to load;
    # an unknown version fails closed exactly like the heredoc gate.
    assert _delay_lines(version) == []


# ── unforced reload ──────────────────────────────────────────────────────────

class _Run:
    def __init__(self, rc=0, exc=None):
        self.rc, self.exc, self.calls = rc, exc, []

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        if self.exc:
            raise self.exc
        return subprocess.CompletedProcess(argv, self.rc, '', '')


def _reload_if_changed(run, have_caddy=True):
    fallback = []

    class _Sub:
        TimeoutExpired = subprocess.TimeoutExpired

    _Sub.run = staticmethod(run)

    class _Shutil:
        @staticmethod
        def which(name):
            return '/usr/bin/caddy' if have_caddy else None

    def _checked(plog=None, timeout=None, restart_on_error=True):
        fallback.append({'plog': plog, 'timeout': timeout, 'restart_on_error': restart_on_error})
        return True, 'forced'

    ns = _load(['_caddy_reload_if_changed'],
               {'subprocess': _Sub, 'shutil': _Shutil, 'CADDYFILE_PATH': '/etc/caddy/Caddyfile',
                'CADDY_RELOAD_TIMEOUT': 45, '_caddy_reload_checked': _checked})
    return ns['_caddy_reload_if_changed'], fallback


def test_unforced_reload_success_skips_the_forced_one():
    run = _Run(rc=0)
    fn, fallback = _reload_if_changed(run)
    assert fn(timeout=60) == (True, '')
    assert fallback == []
    argv, kw = run.calls[0]
    assert argv[:2] == ['caddy', 'reload'] and '--force' not in argv
    assert '/etc/caddy/Caddyfile' in argv
    assert kw['timeout'] == 60


@pytest.mark.parametrize('run,have_caddy', [
    (_Run(rc=1), True),                                              # refused / admin API down
    (_Run(exc=subprocess.TimeoutExpired('caddy', 60)), True),        # hung
    (_Run(exc=OSError('exec failed')), True),
    (_Run(rc=0), False),                                             # no caddy on PATH
])
def test_any_failure_falls_back_with_the_callers_arguments(run, have_caddy):
    fn, fallback = _reload_if_changed(run, have_caddy=have_caddy)
    assert fn(plog='P', timeout=60, restart_on_error=False) == (True, 'forced')
    assert fallback == [{'plog': 'P', 'timeout': 60, 'restart_on_error': False}]


# ── static guards: where the pieces are wired in ─────────────────────────────

def _body(name):
    return _segment(name)


def test_tak_and_cloudtak_vhosts_emit_the_delay():
    gen = _body('generate_caddyfile')
    tak = gen[gen.index('lines.append(f"# TAK Server")'):gen.index('lines.append(f"# Authentik")')]
    assert '_caddy_stream_close_delay_lines(' in tak
    assert tak.index('_caddy_stream_close_delay_lines(') < tak.index('header_down Location')
    ct = gen[gen.index('# CloudTAK Web UI'):gen.index('# CloudTAK Tile Server')]
    assert '_caddy_stream_close_delay_lines(' in ct


def test_startup_steps_use_the_unforced_reload():
    posture = _body('_startup_ensure_hardening_posture')
    assert '_caddy_reload_if_changed()' in posture
    assert '_caddy_reload()' not in posture
    portal = _body('_f2b_selfheal_portal_caddy_log')
    assert '_caddy_reload_if_changed(timeout=60, restart_on_error=False)' in portal
    assert '_caddy_reload_checked(' not in portal


def test_existing_boxes_converge_at_startup():
    assert '_startup_caddy_stream_close_delay_converge()' in APP
    conv = _body('_startup_caddy_stream_close_delay_converge')
    # idempotent: returns before regenerating when the directive is already there
    assert conv.index("'stream_close_delay' in generated") < conv.index('generate_caddyfile(')
