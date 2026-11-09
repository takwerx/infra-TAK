# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ETL Runner W7 (v10.4.0): webhooks behind a box secret.

Pins:
  * the secret is 256 bits and goes to the shim only; CloudTAK's api gets the base URL with it,
    so the URL CloudTAK shows on a layer is the one that works;
  * no public route unless the map host is a plain https name;
  * the overlay (it holds the secret) is written 0600, other files keep 0644;
  * the Caddy route exists only while the runner is on AND the shim reports a webhook layer,
    and a shim that cannot be read never flips it (no flapping on a restart).
"""
import ast
import json
import os
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from modules import etlrunner as etl  # noqa: E402

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
_FNS = {n.name: n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef)}


def _load(names, **ns):
    ns.setdefault('os', os)
    ns.setdefault('json', json)
    for n in names:
        exec(compile(ast.get_source_segment(APP, _FNS[n]), 'app.py', 'exec'), ns)
    return ns


SEC = etl.new_hook_secret()


def test_secret_shape():
    assert etl.HOOK_SECRET_RE.match(SEC) and len({etl.new_hook_secret() for _ in range(50)}) == 50


@pytest.mark.parametrize('api,ok', [
    ('https://map.example.org', True), ('https://map.example.org/', True),
    ('https://map.example.org:8443', True),
    ('http://map.example.org', False), ('https://map.example.org/sub', False),
    ('https://user:pw@map.example.org', False), ('', False), (None, False),
    ('https://map.exa mple.org', False), ('javascript:alert(1)', False),
])
def test_webhooks_base(api, ok):
    b = etl.webhooks_base(api, SEC)
    assert (b is not None) is ok
    if ok:
        assert b.startswith('https://map.example.org') and b.endswith(f'{etl.HOOK_PATH}/{SEC}')


def test_webhooks_base_needs_a_valid_secret():
    for bad in ('', None, 'short', SEC + 'x', SEC[:-1] + '/'):
        assert etl.webhooks_base('https://map.example.org', bad) is None


def _overlay(secret, url):
    return etl.overlay_yml('/h/CloudTAK', 990, 990, '/run/takwerx-etl', '/var/lib/takwerx-etl',
                           '/var/lib/takwerx-etl-tls', secret, url)


def test_overlay_secret_to_shim_url_to_api_only():
    yaml = pytest.importorskip('yaml')
    url = etl.webhooks_base('https://map.example.org', SEC)
    d = yaml.safe_load(_overlay(SEC, url))
    assert d['services']['api']['environment']['WEBHOOKS_URL'] == url
    assert d['services'][etl.SHIM_SERVICE]['environment']['SHIM_HOOK_SECRET'] == SEC
    assert 'SHIM_HOOK_SECRET' not in d['services']['api']['environment']
    assert 'WEBHOOKS_URL' not in d['services']['events']['environment']
    assert 'SHIM_HOOK_SECRET' not in d['services']['events']['environment']


def test_overlay_without_secret_carries_none():
    yaml = pytest.importorskip('yaml')
    for sec in (None, 'not-a-secret'):
        d = yaml.safe_load(_overlay(sec, None))
        assert 'SHIM_HOOK_SECRET' not in d['services'][etl.SHIM_SERVICE]['environment']
        assert 'WEBHOOKS_URL' not in d['services']['api']['environment']


def test_caddy_lines_shape():
    lines = '\n'.join(etl.caddy_hook_lines())
    assert f'@etl_hooks path {etl.HOOK_PATH}/*' in lines
    assert f'reverse_proxy 127.0.0.1:{etl.HOOK_LOOPBACK_PORT}' in lines
    assert 'max_size 1MB' in lines
    code = [ln.strip() for ln in etl.caddy_hook_lines() if not ln.strip().startswith('#')]
    assert not any(ln.startswith(('log', 'forward_auth')) for ln in code)   # no access log, no SSO


def test_write_modes(tmp_path):
    ns = _load(['_etlrunner_write'])
    w = ns['_etlrunner_write']
    old = os.umask(0o022)
    try:
        assert w(str(tmp_path / 'ov.yml'), 'a', mode=0o600)
        assert (tmp_path / 'ov.yml').stat().st_mode & 0o777 == 0o600
        assert w(str(tmp_path / 'ov.yml'), 'b', mode=0o600)          # replace path
        assert (tmp_path / 'ov.yml').stat().st_mode & 0o777 == 0o600
        assert w(str(tmp_path / 'ca.pem'), 'c')
        assert (tmp_path / 'ca.pem').stat().st_mode & 0o777 == 0o644
        assert not w(str(tmp_path / 'ca.pem'), 'c')                    # unchanged: not written
    finally:
        os.umask(old)


class Box:
    def __init__(self, enabled=True, route=False, layers=0, readable=True):
        self.settings = {'etl_runner': {'enabled': enabled, 'hooks_route': route, 'hook_secret': SEC}}
        self.layers, self.readable = layers, readable
        self.caddy = []
        self.ns = _load(['_etlrunner_cfg', '_etlrunner_hooks_wanted', '_etlrunner_hooks_converge'],
                        load_settings=lambda: json.loads(json.dumps(self.settings)),
                        save_settings=self._save, _etl=etl,
                        _etlrunner_shim_status=lambda: ({'hooks': {'secret': True, 'layers': self.layers}}
                                                        if self.readable else None),
                        generate_caddyfile=lambda s: self.caddy.append(
                            'hooks' if self.ns['_etlrunner_hooks_wanted'](s) else 'none'),
                        _caddy_reload_if_changed=lambda plog=None: (True, ''))

    def _save(self, s):
        self.settings = s

    def converge(self):
        return self.ns['_etlrunner_hooks_converge'](lambda m: None)


def test_route_opens_when_a_webhook_layer_appears_and_closes_after():
    b = Box(layers=0)
    assert b.converge() is False and b.caddy == []           # nothing to do, no reload
    b.layers = 1
    assert b.converge() is True and b.caddy == ['hooks']
    assert b.converge() is True and b.caddy == ['hooks']     # steady: no second reload
    b.layers = 0
    assert b.converge() is False and b.caddy == ['hooks', 'none']


def test_unreadable_shim_never_flips():
    b = Box(route=True, layers=1, readable=False)
    assert b.converge() is True and b.caddy == []
    b = Box(route=False, layers=1, readable=False)
    assert b.converge() is False and b.caddy == []


def test_runner_off_closes_route_without_asking_shim():
    b = Box(enabled=False, route=True, readable=False)
    assert b.converge() is False and b.caddy == ['none']


def test_route_needs_a_valid_secret():
    b = Box(route=True)
    b.settings['etl_runner']['hook_secret'] = 'short'
    assert b.ns['_etlrunner_hooks_wanted'](b.settings) is False
