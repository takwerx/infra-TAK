# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ETL Runner W3 phase 2 (v10.4.0): the catalog fetched from takwerx/infratak-etl-catalog.

The catalog pins what a box builds and runs (source + sha + reviewed), so a fetched copy is used
only when its Ed25519 signature verifies with the key that ships in infra-TAK. Pins:
  * a tampered byte, a wrong key, a bad or short signature all fail closed (bundled is used);
  * a lower serial than the bundled one or the last accepted one is refused (no rollback);
  * on an equal serial the bundled file wins;
  * the fetch reads both files at one commit, caches 0600 in a 0700 dir, and records failures;
  * every app.py consumer goes through _etl_catalog(), never the bundled file directly.
"""
import ast
import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from modules import etlrunner as etl  # noqa: E402

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
_FNS = {n.name: n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef)}

pytestmark = pytest.mark.skipif(shutil.which('openssl') is None, reason='needs the openssl CLI')


def _keypair(d, name):
    k, p = d / f'{name}.pem', d / f'{name}.pub'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out', str(k)], check=True,
                   capture_output=True)
    pub = subprocess.run(['openssl', 'pkey', '-in', str(k), '-pubout'], check=True,
                         capture_output=True, text=True).stdout
    p.write_text('# comment line\n' + pub)
    return k, p


def _sign(raw, key, d):
    m, s = d / 'm', d / 's'
    m.write_bytes(raw)
    subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', str(m),
                    '-out', str(s)], check=True, capture_output=True)
    return base64.b64encode(s.read_bytes()).decode() + '\n'


def _cat(serial, prefix='etl-x'):
    e = {'prefix': prefix, 'version': '1.0.0', 'sha': 'a' * 40, 'source': 'dfpc-coe/etl-x',
         'name': prefix, 'flags': {'schedule': True}, 'reviewed': 'scan'}
    return (json.dumps({'schema': 1, 'serial': serial, 'entries': [e]}, indent=2) + '\n').encode()


@pytest.fixture
def keys(tmp_path):
    k, p = _keypair(tmp_path, 'good')
    k2, p2 = _keypair(tmp_path, 'evil')
    return {'key': k, 'pub': p, 'evil': k2, 'evilpub': p2, 'dir': tmp_path}


def test_shipped_public_key_is_one_ed25519_key():
    keys = etl._pubkeys()
    assert len(keys) == 1
    out = subprocess.run(['openssl', 'pkey', '-pubin', '-text', '-noout'], input=keys[0],
                         capture_output=True, text=True)
    assert out.returncode == 0 and 'ED25519' in out.stdout.upper()


def test_signature_verifies_and_fails_closed(keys):
    raw = _cat(5)
    sig = _sign(raw, keys['key'], keys['dir'])
    assert etl.verify_signature(raw, sig, str(keys['pub']))
    assert not etl.verify_signature(raw.replace(b'1.0.0', b'1.0.1'), sig, str(keys['pub']))  # tampered
    assert not etl.verify_signature(raw, _sign(raw, keys['evil'], keys['dir']), str(keys['pub']))
    for bad in ('', 'not base64!!', base64.b64encode(b'x' * 63).decode(), None):
        assert not etl.verify_signature(raw, bad, str(keys['pub']))
    assert not etl.verify_signature(raw, sig, str(keys['dir'] / 'missing.pub'))
    assert not etl.verify_signature(raw, sig, str(keys['pub']), openssl='/nonexistent/openssl')


@pytest.mark.parametrize('doc', [
    {'schema': 2, 'serial': 1, 'entries': []}, {'schema': 1, 'entries': []},
    {'schema': 1, 'serial': True, 'entries': []}, {'schema': 1, 'serial': 0, 'entries': []},
    {'schema': 1, 'serial': '5', 'entries': []}, {'schema': 1, 'serial': 1, 'entries': {}}, [],
])
def test_parse_refuses_bad_shapes(doc):
    with pytest.raises(ValueError):
        etl.parse_catalog(json.dumps(doc).encode())


def test_parse_refuses_oversize_and_non_json():
    with pytest.raises(ValueError):
        etl.parse_catalog(b' ' * (etl.CATALOG_MAX_BYTES + 1))
    with pytest.raises(ValueError):
        etl.parse_catalog(b'\xff\xfe')


def test_accept_refuses_rollback(keys):
    raw = _cat(10)
    sig = _sign(raw, keys['key'], keys['dir'])
    assert etl.accept_fetched(raw, sig, 10, str(keys['pub']))[0] is not None
    d, why = etl.accept_fetched(raw, sig, 11, str(keys['pub']))
    assert d is None and 'rollback' in why
    d, why = etl.accept_fetched(raw, _sign(raw, keys['evil'], keys['dir']), 0, str(keys['pub']))
    assert d is None and 'signature' in why


def _bundle(tmp, serial):
    b = tmp / 'bundled.json'
    b.write_bytes(_cat(serial, 'etl-bundled'))
    return b


def _cache(tmp, raw, sig):
    c = tmp / 'cache'
    c.mkdir(exist_ok=True)
    (c / 'catalog.json').write_bytes(raw)
    (c / 'catalog.json.sig').write_text(sig)
    return c


def test_active_catalog_picks_only_a_newer_verified_cache(keys):
    t = keys['dir']
    b = _bundle(t, 100)
    pub = str(keys['pub'])
    assert etl.active_catalog(None, str(b), pub)[1] == 'bundled'
    assert etl.active_catalog(str(t / 'nocache'), str(b), pub)[1] == 'bundled'

    raw = _cat(101, 'etl-fetched')
    c = _cache(t, raw, _sign(raw, keys['key'], t))
    d, src = etl.active_catalog(str(c), str(b), pub)
    assert src == 'fetched' and d['entries'][0]['prefix'] == 'etl-fetched'
    assert [e['prefix'] for e in etl.load_catalog(str(b), str(c), pub)] == ['etl-fetched']

    time.sleep(0.01)                          # tamper after it verified: mtime changes, re-checked
    (c / 'catalog.json').write_bytes(raw.replace(b'1.0.0', b'9.9.9'))
    assert etl.active_catalog(str(c), str(b), pub)[1] == 'bundled'

    raw = _cat(100, 'etl-fetched')            # equal serial: bundled wins
    c = _cache(t, raw, _sign(raw, keys['key'], t))
    assert etl.active_catalog(str(c), str(b), pub)[1] == 'bundled'

    raw = _cat(200, 'etl-evil')               # newer but signed by the wrong key
    c = _cache(t, raw, _sign(raw, keys['evil'], t))
    assert etl.active_catalog(str(c), str(b), pub)[1] == 'bundled'


class Box:
    """_etlcat_refresh with GitHub stubbed: `files` maps URL suffix -> bytes."""

    def __init__(self, tmp, keys, bundled_serial=100, settings=None):
        self.settings = settings or {'etl_runner': {'enabled': True}}
        self.urls = []
        self.files = {}
        self.cache = tmp / 'cfg' / 'etl-catalog'
        b = _bundle(tmp, bundled_serial)
        pub = str(keys['pub'])

        class E:                                 # the module, pointed at the test key and bundle
            def __getattr__(_, n):
                return getattr(etl, n)
            bundled_catalog = staticmethod(lambda: etl.bundled_catalog(str(b)))
            accept_fetched = staticmethod(lambda r, s, f: etl.accept_fetched(r, s, f, pub))
        ns = {'os': os, 'json': json, 'time': time, '_etl': E(), '_ETLCAT_CACHE': str(self.cache),
              '_ETLCAT_REFRESH_LOCK': threading.Lock(), 'print': lambda *a, **k: None,
              'load_settings': lambda: json.loads(json.dumps(self.settings)),
              'save_settings': self._save, '_etlcat_fetch': self._fetch}
        for n in ('_etlrunner_cfg', '_etlcat_cache_write', '_etlcat_refresh', '_etlcat_refresh_due'):
            exec(compile(ast.get_source_segment(APP, _FNS[n]), 'app.py', 'exec'), ns)
        self.ns = ns

    def _save(self, s):
        self.settings = s

    def _fetch(self, url, limit):
        self.urls.append(url)
        for k, v in self.files.items():
            if url.endswith(k):
                if len(v) > limit:
                    raise ValueError('too large')
                return v
        raise OSError('HTTP Error 404: Not Found')

    def serve(self, raw, sig, sha='b' * 40):
        self.files = {'/commits/main': json.dumps({'sha': sha}).encode(),
                      f'/{sha}/catalog.json': raw, f'/{sha}/catalog.json.sig': sig.encode()}

    def refresh(self):
        return self.ns['_etlcat_refresh']()


def test_refresh_caches_a_good_catalog_private(keys, tmp_path):
    b = Box(tmp_path, keys)
    raw = _cat(150)
    b.serve(raw, _sign(raw, keys['key'], tmp_path))
    rec = b.refresh()
    assert rec['ok'] and rec['serial'] == 150 and rec['commit'] == 'b' * 40
    assert b.urls[0].startswith('https://api.github.com/repos/takwerx/infratak-etl-catalog/commits/main')
    assert all(u.startswith(f'https://raw.githubusercontent.com/takwerx/infratak-etl-catalog/{"b" * 40}/')
               for u in b.urls[1:])                                  # both files at one commit
    assert (b.cache / 'catalog.json').read_bytes() == raw
    assert b.cache.stat().st_mode & 0o777 == 0o700
    assert (b.cache / 'catalog.json').stat().st_mode & 0o777 == 0o600
    assert b.settings['etl_runner']['catalog_serial'] == 150
    assert b.settings['etl_runner']['enabled'] is True               # other keys kept


@pytest.mark.parametrize('case', ['evil-sig', 'rollback-bundled', 'rollback-accepted', 'bad-sha', 'http'])
def test_refresh_refuses_and_keeps_the_cache(keys, tmp_path, case):
    b = Box(tmp_path, keys, settings={'etl_runner': {'enabled': True, 'catalog_serial': 300}}
            if case == 'rollback-accepted' else None)
    raw = _cat(50 if case == 'rollback-bundled' else 200)
    sig = _sign(raw, keys['evil' if case == 'evil-sig' else 'key'], tmp_path)
    b.serve(raw, sig, sha='not-a-sha' if case == 'bad-sha' else 'b' * 40)
    if case == 'http':
        b.files = {}
    rec = b.refresh()
    assert rec['ok'] is False and rec['error']
    assert not (b.cache / 'catalog.json').exists()
    c = b.settings['etl_runner']
    assert c['catalog_check']['ok'] is False
    assert c.get('catalog_serial', 0) == (300 if case == 'rollback-accepted' else 0)


def test_refresh_is_single_flight(keys, tmp_path):
    b = Box(tmp_path, keys)
    b.ns['_ETLCAT_REFRESH_LOCK'].acquire()
    assert b.refresh() == {'ok': False, 'error': 'a catalog check is already running'}
    assert b.urls == []


def test_refresh_due():
    b = {'_etl': etl, 'time': time}
    exec(compile(ast.get_source_segment(APP, _FNS['_etlcat_refresh_due']), 'app.py', 'exec'), b)
    due = b['_etlcat_refresh_due']
    now = 10 ** 9
    assert due({}, now)
    assert not due({'catalog_check': {'at': now - 3600, 'ok': True}}, now)
    assert due({'catalog_check': {'at': now - etl.CATALOG_CHECK_SEC, 'ok': True}}, now)
    assert due({'catalog_check': {'at': now - 3600, 'ok': False}}, now)     # failed: retry hourly
    assert not due({'catalog_check': {'at': now - 60, 'ok': False}}, now)


def test_app_reads_the_catalog_only_through_the_signed_path():
    assert APP.count('_etl.load_catalog(') == 1                   # the helper itself
    assert '_etl.bundled_catalog()' not in APP.replace(
        'max(_etl.catalog_serial(_etl.bundled_catalog())', '')     # the rollback floor only
    assert APP.count('_etl_catalog()') >= 4
    src = ast.get_source_segment(APP, _FNS['_etl_catalog'])
    assert 'cache_dir=_ETLCAT_CACHE' in src


def test_refresh_only_while_runner_is_on():
    loop = ast.get_source_segment(APP, _FNS['_etlrunner_hooks_loop'])
    assert "c.get('enabled') and _etlcat_refresh_due(c)" in loop
    route = ast.get_source_segment(APP, _FNS['cloudtak_etl_catalog_action'])
    assert "action == 'refresh'" in route and "get('enabled')" in route
