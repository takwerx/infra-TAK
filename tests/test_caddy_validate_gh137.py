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
"""ATLAS deploy stops: "Caddyfile was rendered without the :8449 device listener" (GH #137).

The listener was rendered; the file on disk was not the one rendered. Two ways
`caddy validate` rejected it and the console's backstop put the previous one
back, after which the ATLAS guard blamed the render:

  * on a non-root console with Caddy 2.11.7, a log file it cannot open — an
    inconclusive result the console already allows for, but could no longer
    see (reproduced on a non-root box), and
  * on Caddy 2.7.x, `client_auth { trust_pool … }`, which landed in 2.8.0
    (measured with the official 2.7.6 and 2.8.4 builds).

app.py cannot be imported in a test, so its helpers are cut out of it and run
against stubs: the code under test is the shipped text.
"""

import ast
import json
import os
import pathlib
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _supports(version):
    ns = {'_caddy_version_tuple': lambda: version}
    src = '\n\n'.join(_segment(n) for n in ('_CADDY_MIN_TRUST_POOL', '_caddy_supports_trust_pool'))
    exec(compile(src, 'app.py:_caddy_supports_trust_pool', 'exec'), ns)
    return ns['_caddy_supports_trust_pool']()


# ── `caddy validate` as the non-root console ─────────────────────────────────
#
# The reporter's actual failure, reproduced on a non-root box: run as `takwerx`, Caddy
# cannot open its own access log, so validate exits 1. That is inconclusive,
# not a bad config — but 2.11.7 reports it only as a JSON error line, which the
# cleaner dropped, so the carve-out never saw "permission denied" and every
# regeneration was reverted. Both outputs below are verbatim from the boxes.

_WARN = ('{"level":"warn","ts":1791998258.39,"msg":"Caddyfile input is not formatted; run '
         "'caddy fmt --overwrite' to fix inconsistencies\",\"adapter\":\"caddyfile\","
         '"file":"/etc/caddy/Caddyfile","line":3}')
_LOGW = ("setting up custom log 'log0': opening log writer using &logging.FileWriter"
         '{Filename:"/var/log/caddy/takportal-access.log"}: open '
         '/var/log/caddy/takportal-access.log: permission denied')
CADDY_2_11_7 = _WARN + '\n' + json.dumps(
    {'level': 'error', 'ts': 1791998258.40, 'msg': _LOGW}, separators=(',', ':'))
CADDY_2_11_4 = _WARN + '\nError: ' + _LOGW


class _Done:
    def __init__(self, rc, out):
        self.returncode, self.stdout, self.stderr = rc, '', out


def _validate(rc, out):
    """Run the shipped `_caddy_validate_config` with `caddy validate` stubbed out."""
    ns = {'os': os, 'json': json, 'CADDYFILE_PATH': '/etc/caddy/Caddyfile',
          '_caddy_acme_env': lambda: {},
          'shutil': SimpleNamespace(which=lambda n: '/usr/bin/caddy'),
          'subprocess': SimpleNamespace(run=lambda *a, **k: _Done(rc, out),
                                        TimeoutExpired=subprocess.TimeoutExpired)}
    src ='\n\n'.join(_segment(n) for n in ('_caddy_validate_clean', '_caddy_validate_config'))
    exec(compile(src, 'app.py:_caddy_validate_config', 'exec'), ns)
    return ns['_caddy_validate_config']()


@pytest.mark.parametrize('out', [CADDY_2_11_7, CADDY_2_11_4], ids=['2.11.7', '2.11.4'])
def test_a_log_file_the_console_cannot_open_is_inconclusive(out):
    verdict, detail = _validate(1, out)
    assert verdict == 'unknown'
    assert 'permission denied' in detail


def test_an_error_only_in_json_is_still_reported():
    """It used to come back as "caddy validate failed with no output"."""
    bad = _WARN + '\n' + json.dumps({'level': 'error', 'msg': 'unrecognized directive: nope'})
    verdict, detail = _validate(1, bad)
    assert verdict == 'bad'
    assert detail == 'unrecognized directive: nope'


def test_a_real_parse_error_is_still_bad():
    out = 'Error: adapting config using caddyfile: unknown subdirective for client_auth: trust_pool'
    assert _validate(1, out) == ('bad', out)


def test_warnings_are_still_dropped_and_a_good_config_is_ok():
    assert _validate(0, _WARN + '\nValid configuration') == ('ok', 'Valid configuration')


# ── the version gate ─────────────────────────────────────────────────────────

@pytest.mark.parametrize('version', [(2, 7, 0), (2, 7, 6), (2, 6, 2)])
def test_a_caddy_older_than_2_8_cannot_take_the_device_site(version):
    assert _supports(version) is False


@pytest.mark.parametrize('version', [(2, 8, 0), (2, 8, 4), (2, 11, 4), (3, 0, 0)])
def test_2_8_and_newer_can(version):
    assert _supports(version) is True


def test_an_unknown_version_keeps_the_device_site():
    """Fails open on purpose: dropping the block on a bad `caddy version` moment
    would take a working device channel off the box, while emitting it onto a
    too-old Caddy is caught by the validate-or-restore backstop."""
    assert _supports(()) is True


def test_the_render_asks_before_emitting_trust_pool():
    body = _segment('generate_caddyfile')
    gate = body.index('if at_ca and not _caddy_supports_trust_pool():')
    emit = body.index('trust_pool file {{')
    assert gate < body.index('elif at_ca:') < emit


def test_the_module_is_handed_the_seams_it_reads():
    ctx = _segment('_MODULE_CTX')
    for seam in ('_caddy_version_tuple', '_caddy_supports_trust_pool',
                 '_caddy_last_validate_error'):
        assert "'%s': %s," % (seam, seam) in ctx


# ── the deploy refuses before building anything ──────────────────────────────

def _ctx(supports, version=(2, 7, 6)):
    # No `_docker_probe`: reaching step 1 would be a KeyError, not the refusal.
    return {
        'load_settings': lambda: {'fqdn': 'example.com'},
        '_get_service_domain': lambda s, k: 'atlas.example.com',
        '_caddy_supports_trust_pool': lambda: supports,
        '_caddy_version_tuple': lambda: version,
    }


@pytest.fixture
def log(monkeypatch):
    lines = []
    monkeypatch.setattr(atlas, 'load_instances', lambda c: [])
    monkeypatch.setattr(atlas, 'instance_is_stranded', lambda c, i: False)
    monkeypatch.setattr(atlas, '_plog', lambda m='', *a, **k: lines.append(m))
    return lines


def _run(ctx, log):
    job = {}
    atlas.deploy(ctx, job, {})
    assert job['error'] is True
    return [m for m in log if m.startswith('ERROR:')]


def test_deploy_stops_on_caddy_2_7_and_says_what_to_click(log):
    errors = _run(_ctx(False), log)
    assert len(errors) == 1
    assert 'Caddy 2.8 or newer' in errors[0]
    assert '2.7.6' in errors[0]
    assert 'click Update' in errors[0]
    assert not any('Step 1/7' in m for m in log), 'refused before building anything'


def test_deploy_goes_on_where_caddy_is_new_enough(log):
    errors = _run(_ctx(True, (2, 11, 4)), log)
    assert any('Step 1/7' in m for m in log)
    assert errors == ["ERROR: '_docker_probe'"]


def test_a_console_without_the_seam_is_not_refused(log):
    ctx = _ctx(True)
    del ctx['_caddy_supports_trust_pool']
    errors = _run(ctx, log)
    assert errors == ["ERROR: '_docker_probe'"]


# ── the read-back and its message ────────────────────────────────────────────

def test_an_unreadable_caddyfile_is_asked_of_the_broker(monkeypatch):
    """A read the console cannot make is not "absent"."""
    asked = []
    ctx = {'_read_priv': lambda p: asked.append(p) or 'atlas.example.com:8449 {\n}\n'}
    monkeypatch.setattr(atlas.os, 'open',
                        lambda *a, **k: (_ for _ in ()).throw(PermissionError(13, 'denied')))
    assert atlas._caddyfile_has_device_listener('atlas.example.com', ctx) is True
    assert asked == ['/etc/caddy/Caddyfile']


def test_a_caddyfile_without_the_site_is_still_missing(monkeypatch):
    ctx = {'_read_priv': lambda p: 'atlas.example.com {\n}\n'}
    monkeypatch.setattr(atlas.os, 'open',
                        lambda *a, **k: (_ for _ in ()).throw(PermissionError(13, 'denied')))
    assert atlas._caddyfile_has_device_listener('atlas.example.com', ctx) is False


def test_a_rejection_during_this_render_is_named():
    ctx = {'_caddy_last_validate_error': {
        'err': 'unknown subdirective for client_auth: trust_pool', 'ts': 200.0}}
    msg = atlas._device_listener_missing(ctx, 'atlas.example.com', '/x/device-ca.crt', 100.0)
    assert msg.startswith('Caddy rejected the new Caddyfile')
    assert 'trust_pool' in msg
    assert 'rendered without' not in msg


def test_an_older_rejection_is_not_blamed():
    ctx = {'_caddy_last_validate_error': {'err': 'something from earlier', 'ts': 50.0}}
    msg = atlas._device_listener_missing(ctx, 'atlas.example.com', '/x/device-ca.crt', 100.0)
    assert 'rendered without' in msg
    assert 'something from earlier' not in msg
