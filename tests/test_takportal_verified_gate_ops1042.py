# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""TAK Portal releases reach users only after they pass our Marketplace gate (ops #1042).

TAK Portal 2.0.38 broke every Marketplace plugin install (ops #1037) and infra-TAK took TAK Portal's
newest GitHub release the day it came out. Now deploy, the Update button, the update badge and Guard
Dog's "Update pending" read one signed file that names the release that passed our gate.

Pins, each red on the code before this change and green with it:
  * with GitHub saying 2.0.38 and the signed file saying 2.0.37, deploy, update and badge say 2.0.37;
  * with no valid signed file, deploy uses the pinned floor and badge and update say nothing;
  * a forged file, a replayed older file, and a file edited on disk after it was cached are not used;
  * the container's own "[update] ... available" log line no longer makes a badge (Guard Dog's source);
  * the tag must still point at the commit we tested;
  * no code in the repo asks GitHub's releases API about TAK Portal.
"""
import ast
import base64
import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time
import types
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
_FNS = {n.name: n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef)}

pytestmark = pytest.mark.skipif(shutil.which('openssl') is None, reason='needs the openssl CLI')

GOOD = 'c' * 40
FLOOR = '2.0.30'


def _tpv():
    from modules import takportal_verified
    return takportal_verified


def _keypair(d, name):
    k, p = d / f'{name}.pem', d / f'{name}.pub'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out', str(k)], check=True,
                   capture_output=True)
    pub = subprocess.run(['openssl', 'pkey', '-in', str(k), '-pubout'], check=True,
                         capture_output=True, text=True).stdout
    p.write_text(pub)
    return k, p


def _sign(raw, key, d):
    m, s = d / 'm', d / 's'
    m.write_bytes(raw)
    subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', str(m),
                    '-out', str(s)], check=True, capture_output=True)
    return base64.b64encode(s.read_bytes()).decode() + '\n'


def _future(days=60):
    return (datetime.datetime.now(datetime.timezone.utc).date() + datetime.timedelta(days=days)).isoformat()


def _doc(serial, tag, commit=GOOD, held=(), **over):
    d = {'schema': 1, 'kind': 'takportal-verified', 'serial': serial, 'tag': tag, 'commit': commit,
         'gate': 1043, 'expires': _future(),
         'held': [{'tag': h, 'reason': 'failed the Marketplace gate'} for h in held]}
    d.update(over)
    d = {k: v for k, v in d.items() if v is not None}       # over={'kind': None} drops the field
    return (json.dumps(d, indent=2) + '\n').encode()


@pytest.fixture
def keys(tmp_path):
    k, p = _keypair(tmp_path, 'good')
    k2, p2 = _keypair(tmp_path, 'evil')
    return {'key': k, 'pub': p, 'evil': k2, 'dir': tmp_path}


class Box:
    """The TAK Portal release readers with GitHub stubbed.

    GitHub's releases API answers 2.0.38 (the broken release) to anything that still asks it;
    `files` is what the catalog repo serves, keyed by URL suffix."""

    NAMES = ('_takportal_version_tuple', '_etlcat_cache_write', '_takportal_verified_http',
             '_takportal_verified_refresh', '_takportal_verified_release',
             '_takportal_expected_commit', '_takportal_latest_tag', '_fetch_takportal_latest',
             '_takportal_release_tag_strict')

    def __init__(self, tmp, keys, monkeypatch, settings=None):
        self.settings = settings if settings is not None else {}
        self.urls = []
        self.files = {}
        self.ls_remote = None
        self.github_latest = '2.0.38'
        self.cache = tmp / 'cfg' / 'takportal-verified'
        pub = str(keys['pub'])
        real = _tpv()

        class P:                          # the module, pointed at the test key
            def __getattr__(_, n):
                return getattr(real, n)
            cached = staticmethod(lambda d, pubkey_path=None: real.cached(d, pub))
            accept_fetched = staticmethod(lambda r, s, f: real.accept_fetched(r, s, f, pub))

        self.ns = {'os': os, 'json': json, 're': re, 'time': time, 'threading': threading,
                   'subprocess': subprocess, '_tpv': P(), 'print': lambda *a, **k: None,
                   'TAKPORTAL_REF_FALLBACK': FLOOR, 'CONFIG_DIR': str(tmp / 'cfg'),
                   '_TAKPORTAL_VERIFIED_CACHE': str(self.cache),
                   '_TAKPORTAL_VERIFIED_LOCK': threading.Lock(),
                   '_takportal_verified_attempt': {'ts': 0.0},
                   '_takportal_upstream_cache': {'latest': None, 'ts': 0},
                   'TAKPORTAL_UPSTREAM_CACHE_TTL': 1800, '_ETLCAT_CACHE': str(tmp / 'cfg' / 'etl-catalog'),
                   'load_settings': lambda: json.loads(json.dumps(self.settings)),
                   'save_settings': self._save, '_git_ls_remote': self._ls_remote}
        for n in self.NAMES:
            if n in _FNS:                 # the code before ops #1042 has only the three readers
                exec(compile(ast.get_source_segment(APP, _FNS[n]), 'app.py', 'exec'), self.ns)
        self.ns['_takportal_verified_http'] = self._http      # the network, stubbed
        monkeypatch.setattr(urllib.request, 'urlopen', self._urlopen)

    def _save(self, s):
        self.settings = s

    def _ls_remote(self, *patterns, repo=None):
        return self.ls_remote

    def _http(self, url, limit, timeout=8):
        self.urls.append(url)
        for k, v in self.files.items():
            if url.endswith(k):
                return v
        raise OSError('HTTP Error 404: Not Found')

    def _urlopen(self, req, timeout=None):
        url = getattr(req, 'full_url', req)
        self.urls.append(url)
        assert url.endswith('/TAK-Portal/releases/latest'), f'unexpected network call {url}'
        body = json.dumps({'tag_name': self.github_latest}).encode()

        class Resp:                        # a real context manager: `with urlopen(...) as r`
            def __enter__(_):
                return _

            def __exit__(_, *a):
                return False

            def read(_):
                return body
        return Resp()

    # -- helpers
    def serve(self, raw, sig, sha='b' * 40):
        self.ls_remote = {'refs/heads/main': sha}
        self.files = {f'/{sha}/takportal-verified.json': raw,
                      f'/{sha}/takportal-verified.json.sig': sig.encode()}

    def cache_file(self, raw, sig):
        self.cache.mkdir(parents=True, exist_ok=True)
        (self.cache / 'takportal-verified.json').write_bytes(raw)
        (self.cache / 'takportal-verified.json.sig').write_text(sig)

    def deploy_tag(self):
        return self.ns['_takportal_latest_tag']()

    def badge(self, fresh=True):
        self.ns['_takportal_upstream_cache'].update(latest=None, ts=0)
        return self.ns['_fetch_takportal_latest'](fresh=fresh)

    def update_tag(self):
        return self.ns['_takportal_release_tag_strict']('/nonexistent', plog=lambda m: None)


@pytest.fixture
def box(tmp_path, keys, monkeypatch):
    return Box(tmp_path, keys, monkeypatch)


def _pass(box, keys, serial, tag, **kw):
    raw = _doc(serial, tag, **kw)
    box.serve(raw, _sign(raw, keys['key'], keys['dir']))


# ---------------------------------------------------------------- the gate

def test_all_three_readers_follow_the_signed_file_not_githubs_newest(box, keys):
    """The bug: GitHub says 2.0.38 (broken), the gate passed 2.0.37, and users got 2.0.38."""
    _pass(box, keys, 7, '2.0.37')
    assert box.deploy_tag() == '2.0.37'
    assert box.badge() == '2.0.37'
    assert box.update_tag() == '2.0.37'


def test_no_signed_file_means_floor_for_deploy_and_silence_for_update_and_badge(box):
    """Offline (or never fetched): deploy still works from the floor; nothing invents an update."""
    assert box.deploy_tag() == FLOOR
    assert box.badge() is None
    assert box.update_tag() is None


def test_a_newer_signed_file_moves_every_reader_and_keeps_the_tag_exactly(box, keys):
    _pass(box, keys, 7, '2.0.37')
    assert box.deploy_tag() == '2.0.37'
    _pass(box, keys, 8, 'v2.0.39', commit='d' * 40)             # after a later gate passed
    assert box.deploy_tag() == 'v2.0.39'                          # goes to git checkout as published
    assert box.update_tag() == 'v2.0.39'
    assert box.badge() == '2.0.39'                                # the badge compares numbers
    assert box.settings['takportal_verified_serial'] == 8


def test_forged_file_is_not_used(box, keys):
    raw = _doc(9, '2.0.38')
    box.serve(raw, _sign(raw, keys['evil'], keys['dir']))
    assert box.deploy_tag() == FLOOR
    assert box.update_tag() is None and not (box.cache / 'takportal-verified.json').exists()


def test_replayed_older_file_is_refused_even_after_the_cache_is_lost(box, keys):
    _pass(box, keys, 8, '2.0.37')
    assert box.deploy_tag() == '2.0.37'
    shutil.rmtree(box.cache)                                      # cache gone, settings keep the floor
    _pass(box, keys, 7, '2.0.36')
    assert box.deploy_tag() == FLOOR                              # refused, not 2.0.36
    assert box.settings['takportal_verified_serial'] == 8


def test_moving_the_verified_version_back_is_a_new_file_with_a_higher_serial(box, keys):
    _pass(box, keys, 8, '2.0.37')
    assert box.deploy_tag() == '2.0.37'
    _pass(box, keys, 9, '2.0.35')                                 # 2.0.37 turned out bad
    assert box.deploy_tag() == '2.0.35'


def test_a_cached_file_edited_on_disk_is_not_trusted(box, keys):
    raw = _doc(7, '2.0.37')
    box.cache_file(raw, _sign(raw, keys['key'], keys['dir']))
    assert box.deploy_tag() == '2.0.37'
    (box.cache / 'takportal-verified.json').write_bytes(raw.replace(b'2.0.37', b'2.0.99'))
    assert box.deploy_tag() == FLOOR


def test_a_gate_box_can_test_a_release_before_it_is_signed_on_main(box, keys):
    """The gate path: the worker signs X locally (not pushed) and puts the two files in a gate box's
    cache folder. Deploy and the Update button then use X through the real code, while main still says
    the older verified release (lower serial: refused as a rollback, so it cannot undo the test)."""
    old = _doc(7, '2.0.37')
    box.serve(old, _sign(old, keys['key'], keys['dir']))                  # main: 2.0.37, serial 7
    cand = _doc(202611211200, '2.0.39', commit='e' * 40)                  # local gate file, newer serial
    box.cache_file(cand, _sign(cand, keys['key'], keys['dir']))
    assert box.deploy_tag() == '2.0.39'
    assert box.update_tag() == '2.0.39'
    assert box.ns['_takportal_expected_commit']('2.0.39') == 'e' * 40
    real = _doc(202611211500, '2.0.39', commit='e' * 40)                  # later, the real signing lands on main
    box.serve(real, _sign(real, keys['key'], keys['dir']))
    assert box.deploy_tag() == '2.0.39' and box.settings['takportal_verified_serial'] == 202611211500


def test_the_cached_answer_survives_github_going_away(box, keys):
    _pass(box, keys, 7, '2.0.37')
    assert box.deploy_tag() == '2.0.37'
    box.files, box.ls_remote = {}, None                           # offline from here
    assert box.update_tag() == '2.0.37'
    assert box.badge() == '2.0.37'


def test_the_check_is_throttled_but_fresh_asks_again(box, keys):
    _pass(box, keys, 7, '2.0.37')
    assert box.ns['_takportal_verified_release'](fresh=False)[0] == '2.0.37'
    n = len(box.urls)
    box.ns['_takportal_verified_release'](fresh=False)
    assert len(box.urls) == n                                      # inside the interval: no network
    box.ns['_takportal_verified_release'](fresh=True)
    assert len(box.urls) > n


def test_expected_commit_is_only_given_for_the_verified_tag(box, keys):
    _pass(box, keys, 7, '2.0.37', commit='a1' * 20)
    box.deploy_tag()
    assert box.ns['_takportal_expected_commit']('2.0.37') == 'a1' * 20
    assert box.ns['_takportal_expected_commit']('2.0.38') == ''
    assert box.ns['_takportal_expected_commit']('') == ''


def test_the_floor_has_no_commit_to_check(box):
    assert box.ns['_takportal_verified_release']()[1:] == (None, 'floor')


# ------------------------------------------------------------ the file's own shape

OK = {'kind': 'takportal-verified', 'expires': '2099-01-01'}


@pytest.mark.parametrize('doc', [
    {**OK, 'schema': 2, 'serial': 1, 'tag': '2.0.37', 'commit': GOOD},
    {**OK, 'schema': 1, 'tag': '2.0.37', 'commit': GOOD},
    {**OK, 'schema': 1, 'serial': True, 'tag': '2.0.37', 'commit': GOOD},
    {**OK, 'schema': 1, 'serial': 1, 'tag': '2.0.37; rm -rf /', 'commit': GOOD},
    {**OK, 'schema': 1, 'serial': 1, 'tag': '--upload-pack=x', 'commit': GOOD},
    {**OK, 'schema': 1, 'serial': 1, 'tag': '2.0.37', 'commit': 'abc'},
    {**OK, 'schema': 1, 'serial': 1, 'tag': '2.0.37', 'commit': 'C' * 40},
    {**OK, 'schema': 1, 'serial': 1, 'tag': '2.0.37', 'commit': GOOD, 'held': 'x'},
    {**OK, 'schema': 1, 'serial': 1, 'tag': '2.0.37', 'commit': GOOD, 'held': [{'tag': '$(id)'}]},
])
def test_bad_shapes_are_refused_before_the_signature_is_even_looked_at(doc):
    with pytest.raises(ValueError):
        _tpv().parse(json.dumps(doc).encode())


def test_not_json_and_too_large_are_refused():
    with pytest.raises(ValueError):
        _tpv().parse(b'\xff\xfe not json')
    with pytest.raises(ValueError):
        _tpv().parse(b'{' + b' ' * _tpv().VERIFIED_MAX_BYTES + b'}')


# ----------------------------------------------- kind and expires (Security's hardening, ops #1042)

def _past(days=1):
    return _future(-days)


def test_a_file_of_another_kind_is_not_used_even_with_a_good_signature(box, keys):
    """The ETL catalog is signed with the same key. A signed file that is not marked takportal-verified
    must never pick the TAK Portal release, whatever else it carries."""
    for over in ({'kind': None}, {'kind': 'etl-catalog'}, {'kind': 'TAKPORTAL-VERIFIED'}, {'kind': 1}):
        raw = _doc(9, '2.0.38', **over)
        box.serve(raw, _sign(raw, keys['key'], keys['dir']))
        box.ns['_takportal_verified_attempt']['ts'] = 0.0
        assert box.deploy_tag() == FLOOR, over
        assert box.update_tag() is None and not (box.cache / 'takportal-verified.json').exists()


def test_a_cached_file_of_another_kind_is_not_trusted(box, keys):
    raw = _doc(7, '2.0.37', kind=None)
    box.cache_file(raw, _sign(raw, keys['key'], keys['dir']))
    assert box.deploy_tag() == FLOOR


def test_an_old_signed_file_replayed_to_a_new_box_is_refused_once_it_has_expired(box, keys):
    """A brand-new box has serial floor 0 and no cache, so a real older file replayed to it would
    otherwise be taken. Its expires date makes it stale."""
    raw = _doc(7, '2.0.36', expires=_past())
    box.serve(raw, _sign(raw, keys['key'], keys['dir']))
    assert box.deploy_tag() == FLOOR
    assert box.update_tag() is None and not (box.cache / 'takportal-verified.json').exists()
    assert box.settings.get('takportal_verified_serial', 0) == 0


def test_a_file_a_box_already_accepted_keeps_working_after_its_date(box, keys):
    """A missed renewal must not push every box back to the floor: the date gates what a box newly
    accepts, not what it holds. A newer file past its date is still refused and the cache stays."""
    raw = _doc(7, '2.0.37', expires=_past(30))
    box.cache_file(raw, _sign(raw, keys['key'], keys['dir']))
    assert box.deploy_tag() == '2.0.37' and box.update_tag() == '2.0.37'
    stale = _doc(8, '2.0.39', commit='d' * 40, expires=_past())
    box.serve(stale, _sign(stale, keys['key'], keys['dir']))
    assert box.deploy_tag() == '2.0.37'


def test_a_file_is_good_all_through_its_last_day():
    d = datetime.date(2026, 12, 31)
    rec = _tpv().parse(_doc(1, '2.0.37', expires='2026-12-31'))
    assert not _tpv().is_expired(rec, today=d)
    assert _tpv().is_expired(rec, today=d + datetime.timedelta(days=1))
    assert not _tpv().is_expired(rec, today=d - datetime.timedelta(days=400))


@pytest.mark.parametrize('expires', [
    '2026-13-01', '2026-02-30', 'tomorrow', '2026-12-31T00:00:00Z', '20261231', '2026-1-5', 20261231, True, [], '',
])
def test_a_missing_or_malformed_expires_is_refused(expires):
    with pytest.raises(ValueError):
        _tpv().parse(_doc(1, '2.0.37', expires=expires))
    with pytest.raises(ValueError):
        _tpv().parse(_doc(1, '2.0.37', expires=None))
    assert _tpv().is_expired({'expires': expires}) is True        # never "fresh" by accident


def test_the_etl_catalog_refuses_a_file_signed_for_something_else():
    """The other direction of the same replay: takportal-verified.json is not an ETL catalog (its
    shape already fails, and a declared kind that is not etl-catalog fails first)."""
    from modules import etlrunner
    with pytest.raises(ValueError):
        etlrunner.parse_catalog(_doc(1, '2.0.37', entries=[]))
    etlrunner.parse_catalog(json.dumps({'schema': 1, 'serial': 1, 'entries': []}).encode())
    etlrunner.parse_catalog(json.dumps({'schema': 1, 'kind': 'etl-catalog', 'serial': 1, 'entries': []}).encode())
    with pytest.raises(ValueError):
        etlrunner.parse_catalog(json.dumps({'schema': 1, 'kind': 'x', 'serial': 1, 'entries': []}).encode())


def test_held_list_names_what_failed_the_gate():
    rec = _tpv().parse(_doc(3, '2.0.37', held=('2.0.38', 'v2.0.40')))
    assert _tpv().is_held(rec, '2.0.38') and _tpv().is_held(rec, '2.0.40') and _tpv().is_held(rec, 'v2.0.38')
    assert not _tpv().is_held(rec, '2.0.37') and not _tpv().is_held(None, '2.0.38')


def test_shipped_public_key_is_the_one_the_catalog_uses():
    from modules import etlrunner
    assert _tpv().VERIFIED_REPO == etlrunner.CATALOG_REPO == 'takwerx/infratak-etl-catalog'
    assert len(etlrunner._pubkeys()) == 1


# ------------------------------------------------------- Guard Dog / the badge source

def _version_info(tmp_path, monkeypatch, installed, latest, log_line):
    """_get_takportal_version_info on a box with TAK Portal `installed`, the verified answer
    `latest`, and a container whose own log says `log_line`."""
    portal = tmp_path / 'TAK-Portal'
    portal.mkdir(exist_ok=True)
    (portal / 'package.json').write_text(json.dumps({'version': installed}))
    fake_os = types.SimpleNamespace(
        path=types.SimpleNamespace(expanduser=lambda p: str(portal) if p == '~/TAK-Portal' else p,
                                   join=os.path.join, isfile=os.path.isfile, isdir=os.path.isdir))

    def run(*a, **k):
        return types.SimpleNamespace(returncode=0, stdout=log_line, stderr='')

    ns = {'os': fake_os, 'json': json, 're': re,
          'subprocess': types.SimpleNamespace(run=run, PIPE=-1, STDOUT=-2),
          '_sudo_wrap': lambda a: a, '_takportal_web_container': lambda: {'id': 'web1'},
          '_takportal_beta_channel_state': lambda: 'release',
          '_takportal_head_release_tag': lambda d: '',
          '_fetch_takportal_latest': lambda fresh=False: latest}
    for n in ('_takportal_version_tuple', '_get_takportal_version_info'):
        exec(compile(ast.get_source_segment(APP, _FNS[n]), 'app.py', 'exec'), ns)
    return ns['_get_takportal_version_info']()


def test_a_box_on_the_verified_release_gets_no_update_pending(tmp_path, monkeypatch):
    info = _version_info(tmp_path, monkeypatch, '2.0.37', '2.0.37', '')
    assert info['update_available'] is False and info['latest'] == '2.0.37'


def test_a_box_behind_the_verified_release_does_get_one(tmp_path, monkeypatch):
    info = _version_info(tmp_path, monkeypatch, '2.0.35', '2.0.37', '')
    assert info['update_available'] is True and info['latest'] == '2.0.37'


def test_the_containers_own_update_line_never_becomes_an_update_pending(tmp_path, monkeypatch):
    """With no verified answer, TAK Portal's log line ("[update] 2.0.37 -> 2.0.38 available") used to
    become `update_available`, which is what Guard Dog's email reads. 2.0.38 is the broken release."""
    line = '[update] 2.0.37 → 2.0.38 available\n'
    info = _version_info(tmp_path, monkeypatch, '2.0.37', None, line)
    assert info['update_available'] is False and info['latest'] is None
    old = '[update-check] current=2.0.37 latest=2.0.38 update=true\n'
    info = _version_info(tmp_path, monkeypatch, '2.0.37', None, old)
    assert info['update_available'] is False and info['latest'] is None


def test_guard_dog_reads_the_same_version_helper_as_the_card():
    src = ast.get_source_segment(APP, _FNS['_module_update_info'])
    assert "key == 'takportal'" in src and '_get_takportal_version_info()' in src


# --------------------------------------------------------------- nothing bypasses the gate

def _string_constants(path):
    return [n.value for n in ast.walk(ast.parse(path.read_text(encoding='utf-8')))
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def test_no_code_asks_githubs_releases_or_tags_api_about_tak_portal():
    """Fails if deploy, update, the badge or anything new reads `releases/latest` (or the repo's own
    tag list) for TAK Portal instead of the verified-version file."""
    files = [ROOT / 'app.py', ROOT / 'start.sh'] + sorted((ROOT / 'modules').rglob('*.py')) \
        + sorted((ROOT / 'broker').glob('*.py')) + sorted((ROOT / 'scripts').rglob('*.sh')) \
        + sorted((ROOT / 'scripts').rglob('*.py'))
    pat = re.compile(r'TAK-Portal/(releases|tags|git/refs/tags)|TAK-Portal\.git.*ls-remote|ls-remote.*TAK-Portal', re.I)
    hits = []
    for f in files:
        if f.suffix == '.py':
            texts = _string_constants(f)
        else:
            texts = [ln for ln in f.read_text(encoding='utf-8').splitlines() if not ln.lstrip().startswith('#')]
        hits += [f'{f.relative_to(ROOT)}: {t[:100]}' for t in texts if pat.search(t)]
    assert not hits, hits


def test_the_three_readers_go_through_the_verified_release():
    for n in ('_takportal_latest_tag', '_fetch_takportal_latest', '_takportal_release_tag_strict'):
        assert '_takportal_verified_release(' in ast.get_source_segment(APP, _FNS[n]), n


def test_the_readers_never_fall_back_to_githubs_newest_or_the_log():
    for n in ('_takportal_latest_tag', '_fetch_takportal_latest', '_takportal_release_tag_strict',
              '_get_takportal_version_info'):
        src = ast.get_source_segment(APP, _FNS[n])
        code = '\n'.join(ln for ln in src.splitlines() if not ln.lstrip().startswith('#'))
        assert 'urlopen' not in code and 'ls-remote' not in code and "'logs'" not in code, n


def test_deploy_and_update_check_the_tag_still_points_at_the_tested_commit():
    upd = ast.get_source_segment(APP, _FNS['_takportal_update_git'])
    assert '_takportal_expected_commit(tag)' in upd
    assert upd.index('_takportal_expected_commit(tag)') < upd.index("'checkout', '--force', tag")
    dep = next(ast.get_source_segment(APP, f) for n, f in _FNS.items()
               if '_takportal_latest_tag(plog)' in (ast.get_source_segment(APP, f) or ''))
    assert '_takportal_expected_commit(_tp_tag)' in dep
    assert dep.index('_takportal_expected_commit(_tp_tag)') < dep.index('Step 3/6')
