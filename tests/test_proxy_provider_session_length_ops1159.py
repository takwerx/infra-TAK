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
"""ops #1159 — sign-ins through Authentik lasted 1 hour, not the 24 hours asked for.

infra-TAK sent `'token_validity': 'hours=24'` when it made or repaired a proxy provider.
Authentik's proxy provider API has no such field (its fields are `access_token_validity`
and `refresh_token_validity`), ignored the key, and kept the default, `hours=1`. The
outpost ends a session when the access token ends.

Part 1 reads the shipped text: the wrong key is gone and every provider write that used
it now sends the real field. Part 2 runs the repair for providers that already exist
(cut out of app.py and run against a fake Authentik, because app.py cannot be imported).
"""

import ast
import io
import json
import pathlib
import re
import types
import urllib.error

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
ATLAS = (REPO / 'modules' / 'atlas.py').read_text(encoding='utf-8')


# ---- Part 1: the text that ships --------------------------------------------------

def test_no_provider_write_sends_the_field_authentik_ignores():
    """`token_validity` is not a proxy provider field. It must not be written anywhere
    (reads of `access_token_validity` do not match this pattern)."""
    bad = [m.group(0) for src in (APP, ATLAS)
           for m in re.finditer(r"""['"]token_validity['"]""", src)]
    assert bad == [], f'the unknown key token_validity is still sent: {len(bad)} place(s)'


def test_every_provider_write_names_the_real_field():
    """Each body that makes or rewrites a proxy provider (it has `'mode': 'forward_single'`
    and a cookie_domain) carries access_token_validity. Counted from the text so a new
    write site cannot forget it."""
    bodies = 0
    for src in (APP, ATLAS):
        for m in re.finditer(r"'mode': 'forward_single'", src):
            window = src[max(0, m.start() - 400):m.start() + 400]
            if "'cookie_domain'" not in window or 'providers/proxy' not in src[max(0, m.start() - 1500):m.start() + 1500]:
                continue
            bodies += 1
            assert "'access_token_validity'" in window, (
                'a provider body near offset %d has no access_token_validity' % m.start())
    assert bodies >= 11, f'expected the known provider write sites, found {bodies}'


def test_the_sign_in_length_is_24_hours():
    assert "_PROXY_SESSION_VALIDITY = 'hours=24'" in APP
    assert "'access_token_validity': 'hours=24'" in ATLAS


# ---- Part 2: the repair of providers that already exist ---------------------------

_WANT = {'_PROXY_SESSION_VALIDITY', '_AUTHENTIK_DEFAULT_ACCESS_TOKEN_VALIDITY',
         '_INFRATAK_PROXY_PROVIDER_NAMES', '_is_infratak_proxy_provider_name',
         '_proxy_session_validity_to_write', '_ensure_proxy_providers_session_length'}


def _load(monkeypatch, providers, patch_status=200):
    """Cut the shipped helper out of app.py and run it against a fake Authentik.
    Returns (namespace, calls); ns['_run'](log) runs the repair."""
    import urllib.request
    parts = []
    for n in ast.parse(APP).body:
        name = n.name if isinstance(n, ast.FunctionDef) else None
        if isinstance(n, ast.Assign):
            name = next((t.id for t in n.targets if isinstance(t, ast.Name)), None)
        if name in _WANT:
            parts.append(ast.get_source_segment(APP, n))
    assert len(parts) == len(_WANT), 'a function under test was renamed or removed'

    calls = []

    def urlopen(req, timeout=None):
        calls.append((req.get_method(), req.full_url,
                      json.loads(req.data.decode()) if req.data else None))
        if req.get_method() == 'GET':
            return io.BytesIO(json.dumps({'results': providers}).encode())
        if patch_status != 200:
            raise urllib.error.HTTPError(req.full_url, patch_status, 'x', {}, io.BytesIO(b'{}'))
        return io.BytesIO(b'{}')

    monkeypatch.setattr(urllib.request, 'urlopen', urlopen)
    ns = {'json': json}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    ns['_run'] = lambda log=None: ns['_ensure_proxy_providers_session_length'](
        'http://ak', {'Authorization': 'Bearer x'}, log)
    return ns, calls


def _prov(pk, name, validity, mode='forward_single', internal_host=''):
    return {'pk': pk, 'name': name, 'access_token_validity': validity, 'mode': mode,
            'internal_host': internal_host}


def _patches(calls):
    return [(u, b) for m, u, b in calls if m == 'PATCH']


def test_a_provider_on_the_default_gets_24_hours(monkeypatch):
    ns, calls = _load(monkeypatch, [_prov(3, 'TAK Portal Proxy', 'hours=1')])
    assert ns['_run']() == 1
    assert _patches(calls) == [('http://ak/api/v3/providers/proxy/3/',
                                {'mode': 'forward_single', 'internal_host': '',
                                 'access_token_validity': 'hours=24'})]


def test_the_patch_carries_mode_because_authentik_refuses_it_without(monkeypatch):
    """Seen on Authentik 2026.8.5: a PATCH with no mode fails the internal_host check
    with HTTP 400. The body must always name the mode and the internal host."""
    ns, calls = _load(monkeypatch, [_prov(4, 'MediaMTX', 'hours=1', mode='proxy',
                             internal_host='http://127.0.0.1:8888')])
    ns['_run']()
    (_, body), = _patches(calls)
    assert body['mode'] == 'proxy' and body['internal_host'] == 'http://127.0.0.1:8888'


def test_a_length_the_operator_chose_is_left_alone(monkeypatch):
    ns, calls = _load(monkeypatch, [_prov(5, 'Node-RED Proxy', 'hours=8'),
                       _prov(6, 'WebODM Proxy', 'days=7')])
    assert ns['_run']() == 0
    assert _patches(calls) == []


def test_providers_that_are_not_ours_are_left_alone(monkeypatch):
    ns, calls = _load(monkeypatch, [_prov(7, 'My Own App', 'hours=1'), _prov(8, 'grafana', 'hours=1')])
    assert ns['_run']() == 0
    assert _patches(calls) == []


def test_every_provider_name_infratak_creates_is_covered(monkeypatch):
    ns, calls = _load(monkeypatch, [_prov(i, n, 'hours=1') for i, n in enumerate(
        ['infra-TAK', 'TAK Portal Proxy', 'Node-RED Proxy', 'MediaMTX', 'Federation Hub Proxy',
         'WebODM Proxy', 'TAK Video Restreamer Proxy', 'ATLAS MDM Proxy',
         'ATLAS MDM Proxy (agency-a)'], start=10)])
    assert ns['_run']() == 9


def test_a_second_run_finds_nothing_to_do(monkeypatch):
    ns, calls = _load(monkeypatch, [_prov(3, 'TAK Portal Proxy', 'hours=24')])
    assert ns['_run']() == 0
    assert _patches(calls) == []


def test_a_refused_patch_is_logged_and_does_not_stop_the_rest(monkeypatch):
    logs = []
    ns, calls = _load(monkeypatch, [_prov(3, 'TAK Portal Proxy', 'hours=1'),
                       _prov(4, 'Node-RED Proxy', 'hours=1')], patch_status=400)
    assert ns['_run'](logs.append) == 0
    assert len(_patches(calls)) == 2          # it tried both
    assert any('HTTP 400' in m for m in logs)


def test_a_write_that_already_happens_keeps_the_operators_length(monkeypatch):
    """The two existing full-body PUTs (host fix, chain heal) must not undo a length the
    operator set, and must move a provider on the default to 24 hours."""
    ns, _ = _load(monkeypatch, [])
    f = ns['_proxy_session_validity_to_write']
    assert f('hours=1') == 'hours=24'
    assert f(None) == 'hours=24' and f('') == 'hours=24'
    assert f('hours=8') == 'hours=8'
    assert f('hours=24') == 'hours=24'


def test_the_repair_runs_at_console_start_and_after_an_update():
    assert "Startup migration: {m}\", flush=True))" in APP.split('ops #1159: the sign-in length')[1][:300]
    assert APP.count('_ensure_authentik_proxy_session_length(') >= 3   # def + start + post-update
