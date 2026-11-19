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
              'save_settings': self._save, '_etlcat_fetch': self._fetch,
              '_git_ls_remote': self._ls_remote}
        for n in ('_etlrunner_cfg', '_etlcat_cache_write', '_etlcat_refresh', '_etlcat_refresh_due'):
            exec(compile(ast.get_source_segment(APP, _FNS[n]), 'app.py', 'exec'), ns)
        self.ns = ns

    ls_remote = None                              # {ref: sha} the git endpoint answers, None = fails

    def _ls_remote(self, *patterns, repo=None):
        self.ls_calls = getattr(self, 'ls_calls', []) + [(patterns, repo)]
        return self.ls_remote

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


def test_bundled_catalog_carries_the_signed_ops911_bumps():
    """The bundled copy must not be older than the signed public catalog (serial 202611190517).
    A box on this release reads the bundled file when the fetch fails, and a lower bundled serial
    would put these 37 ETLs back on their old, already-superseded versions (ops #911; the 3 bumps
    of ops #725 are inside this list at their newer versions). etl-arcgis 7.36.0 came in with
    serial 202611190517 (ops #975)."""
    d = etl.bundled_catalog()
    assert etl.catalog_serial(d) >= 202611190517
    by = {e['prefix']: e for e in d['entries']}
    want = {
        'etl-active911': ('4.13.0', '68b546bd992e80e980657c71e2d9acc13fa52923'),
        'etl-adsbx': ('5.19.0', '037125b214373c6c122651ed04f3f67dfe10e9e2'),
        'etl-air-data': ('2.16.0', '73169bd65ce591c62433789f095e62cb85142cc5'),
        'etl-AlertWest': ('2.5.0', '8ad42a8c3a10416f810ec3e1dfb0f8aec17a0818'),
        'etl-axon': ('1.20.0', 'dadda43de514128e831d4cc7f01026bdd4aa41be'),
        'etl-brinc': ('1.10.0', 'b88e318a06a36856922f1d9ca33a31b513036050'),
        'etl-buddi': ('1.16.0', '7cf935f6af3d48c212a4ae036637cf6412e8a789'),
        'etl-caic': ('3.20.0', '43137e8b1e243834ebac44fc278cccb665b1d521'),
        'etl-caltopo': ('5.21.0', '22e3083b3ac4b847727b455b40dc2a557cc59ef2'),
        'etl-cellping': ('1.5.0', '06929a1825759a0d4da566a92262c4cb992e10d6'),
        'etl-central-square': ('1.14.0', '9fb475fd7b5ae20999d6f9efc6a10670b71de47d'),
        'etl-cot': ('1.6.0', '4d730d985c89e79682b069d47ba392e3bc722abf'),
        'etl-cotrip-cameras': ('2.17.0', '1cacdb7d5e87025cea5e4a83b7f8b791fc2918ba'),
        'etl-cotrip-incidents': ('5.16.0', '484793886100b592b9468b48200a8249d50fa632'),
        'etl-cotrip-plows': ('4.16.0', '604add5ef167707c5a11b102242a7ebe379579d1'),
        'etl-dji-flight-hub': ('1.10.0', 'a713bb336c52aaf5614aadb36014c99c440bb9ce'),
        'etl-drone-sense': ('2.17.0', '54ffa3510d5ad5d73124c333a4d280196ea3473f'),
        'etl-ensurity': ('1.10.0', '6b8642a37ea0f0f2d328887b66ae98277b70bce7'),
        'etl-everywhere-hub': ('1.16.0', '725254f0342a5cc7eb3dfd95a38f123fa933d88f'),
        'etl-first-due': ('1.5.0', '70d42918384c69aa7c5b29aba714889ddabd4ce7'),
        'etl-geojson': ('2.16.0', '4cebe08b1ad2b500ba12bbc4fc030349747a40bc'),
        'etl-geotab': ('3.14.0', '5cd08fc1e21c8e2e5b3276052d79974037c67c3a'),
        'etl-inreach': ('6.5.0', '07b7fbf78daf8eaa2d696f926808960f895739d6'),
        'etl-jeffcom': ('1.22.0', '8f8ac489408a73f5c36b2192f04d0f708ff3dde4'),
        'etl-nasa-acero': ('1.12.0', 'e8977853631aba0fc6fd3cee81b16885cb0c26d4'),
        'etl-optimus': ('1.21.0', '450dd991401df479f6a71facfa685c124aab1471'),
        'etl-santa': ('2.14.0', 'f5218580dcf529e640d6e3a93cfda8fe3f15bfdc'),
        'etl-shotover': ('2.15.0', '281a07bddf186dc83ad8d43dabbf513e7230f90f'),
        'etl-skydio': ('1.5.0', '81a1d77bb5af9be4ac5639499b1ffd18572c85bc'),
        'etl-skymira': ('2.14.0', 'dd26df4ebf4843c79ae051bdc62186637303d03e'),
        'etl-slack-bsar': ('1.16.0', 'f8ffa0a948ab87db5324f21a684edf76bbb61605'),
        'etl-spider-tracks': ('2.14.0', '6b962ade07d9407fff64c7b6b12eb92fe869185f'),
        'etl-spot': ('3.13.0', '1d623bfc3163343ecde33bf5b8f0a9e9ceb9698e'),
        'etl-usgs-gauges': ('1.7.0', 'b96ff6dcdc6a222ebf11cea3da01ea6d8fd07ecd'),
        'etl-verkada': ('1.22.0', '14c11fd608cb8cb1bf3c09630d833c96daf07b3f'),
        'etl-waze': ('1.4.0', 'cc6cf82c76b3f5c36339b3cd5352919a0099b096'),
        'etl-wildweb': ('4.16.0', 'acec1934aa5b31fc040eb9be5993bc9903549634'),
    }
    assert len(want) == 37
    for prefix, (ver, sha) in want.items():
        e = by[prefix]
        assert (e['version'], e['sha'], e['ref']) == (ver, sha, 'v' + ver), prefix
        assert e.get('reviewed', '').startswith('2026-11-17'), prefix
    arc = by['etl-arcgis']
    assert (arc['version'], arc['sha'], arc['ref']) == (
        '7.36.0', '910fc609a3f6e60735351e3c83d76870a14e1400', 'v7.36.0')
    assert arc.get('reviewed', '').startswith('2026-11-18')


# v10.4.0 T&E (test12, nuc): "Check now" failed with "HTTP Error 403: rate limit exceeded".
# The commit now comes from git's smart-HTTP endpoint, which is not in the REST API quota.
def test_refresh_takes_the_commit_from_git_ls_remote_and_skips_the_api(keys, tmp_path):
    b = Box(tmp_path, keys)
    raw = _cat(160)
    sha = 'c' * 40
    b.serve(raw, _sign(raw, keys['key'], tmp_path), sha=sha)
    b.ls_remote = {'refs/heads/main': sha}
    rec = b.refresh()
    assert rec['ok'] and rec['serial'] == 160 and rec['commit'] == sha
    assert b.ls_calls == [(('refs/heads/main',), 'takwerx/infratak-etl-catalog')]
    assert not any('api.github.com' in u for u in b.urls)
    assert all(u.startswith(f'https://raw.githubusercontent.com/takwerx/infratak-etl-catalog/{sha}/') for u in b.urls)


def test_refresh_falls_back_to_the_api_when_git_fails_or_answers_junk(keys, tmp_path):
    for answer in (None, {}, {'refs/heads/main': 'not-a-sha'}):
        b = Box(tmp_path, keys)
        raw = _cat(170)
        b.serve(raw, _sign(raw, keys['key'], tmp_path))
        b.ls_remote = answer
        rec = b.refresh()
        assert rec['ok'] and rec['commit'] == 'b' * 40
        assert b.urls[0].startswith('https://api.github.com/repos/takwerx/infratak-etl-catalog/commits/main')


def test_a_bad_signature_is_still_refused_when_the_commit_comes_from_git(keys, tmp_path):
    b = Box(tmp_path, keys)
    raw = _cat(180)
    sha = 'd' * 40
    b.serve(raw, 'AAAA' + _sign(raw, keys['key'], tmp_path)[4:], sha=sha)
    b.ls_remote = {'refs/heads/main': sha}
    rec = b.refresh()
    assert rec['ok'] is False and rec['commit'] == sha
    assert not (b.cache / 'catalog.json').exists()
