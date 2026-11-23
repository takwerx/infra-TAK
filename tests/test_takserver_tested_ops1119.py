# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Tell customers when a new TAK Server version is tested, and show it on the TAK Server page (ops #1119).

tak.gov needs a login, so a box cannot read the newest TAK Server version there. We publish the newest
version that passed our fresh install and our update test in a small signed file instead. Pins:

  * only a file signed by our key, of kind takserver-tested, with a serial that never goes down and an
    `expires` date in the future (for a fetch), with BOTH the install and the update marked passed, is used;
  * a box that runs an older TAK Server than the tested one is mailed ONCE per tested version, in plain
    words ("We tested TAK Server X. It installs and updates fine."), and never again for that version;
  * a box that runs the tested version, or a newer one, or has no TAK Server, or has no signed file, is
    not mailed, and the page says so honestly (a newer one is "not tested yet", never "behind");
  * nothing in app.py asks tak.gov for anything.
"""
import ast
import base64
import datetime
import json
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
PAGE = (ROOT / 'templates' / 'takserver.html').read_text(encoding='utf-8')
_FNS = {n.name: n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef)}

pytestmark = pytest.mark.skipif(shutil.which('openssl') is None, reason='needs the openssl CLI')

V = '5.8-RELEASE104'


def _tst():
    from modules import takserver_tested
    return takserver_tested


def _keypair(d, name):
    k, p = d / f'{name}.pem', d / f'{name}.pub'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out', str(k)], check=True, capture_output=True)
    p.write_text(subprocess.run(['openssl', 'pkey', '-in', str(k), '-pubout'], check=True,
                                capture_output=True, text=True).stdout)
    return k, p


def _sign(raw, key, d):
    m, s = d / 'm', d / 's'
    m.write_bytes(raw)
    subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', str(m), '-out', str(s)],
                   check=True, capture_output=True)
    return base64.b64encode(s.read_bytes()).decode() + '\n'


def _future(days=60):
    return (datetime.datetime.now(datetime.timezone.utc).date() + datetime.timedelta(days=days)).isoformat()


def _doc(serial=1, version=V, **over):
    d = {'schema': 1, 'kind': 'takserver-tested', 'serial': serial, 'version': version, 'tested': '2026-11-23',
         'installs': True, 'updates': True, 'evidence': 'ops #1119', 'expires': _future()}
    d.update(over)
    d = {k: v for k, v in d.items() if v is not None}
    return (json.dumps(d, indent=2) + '\n').encode()


@pytest.fixture
def keys(tmp_path):
    k, p = _keypair(tmp_path, 'good')
    k2, p2 = _keypair(tmp_path, 'evil')
    return {'key': k, 'pub': p, 'evil': k2, 'dir': tmp_path}


# ── the signed file ───────────────────────────────────────────────────────────

def test_a_file_signed_by_our_key_is_accepted(keys):
    raw = _doc()
    d, why = _tst().accept_fetched(raw, _sign(raw, keys['key'], keys['dir']), 0, str(keys['pub']))
    assert why == '' and d['version'] == V


def test_a_file_signed_by_another_key_is_refused(keys):
    raw = _doc()
    d, why = _tst().accept_fetched(raw, _sign(raw, keys['evil'], keys['dir']), 0, str(keys['pub']))
    assert d is None and 'signature' in why


def test_a_file_changed_after_signing_is_refused(keys):
    raw = _doc()
    sig = _sign(raw, keys['key'], keys['dir'])
    d, why = _tst().accept_fetched(_doc(version='5.9-RELEASE1'), sig, 0, str(keys['pub']))
    assert d is None and 'signature' in why


def test_an_older_serial_is_a_rollback_and_is_refused(keys):
    raw = _doc(serial=3)
    d, why = _tst().accept_fetched(raw, _sign(raw, keys['key'], keys['dir']), 4, str(keys['pub']))
    assert d is None and 'rollback' in why


def test_a_fetched_file_past_its_date_is_refused_but_a_cached_one_keeps_working(keys, tmp_path):
    raw = _doc(expires='2020-01-01')
    sig = _sign(raw, keys['key'], keys['dir'])
    d, why = _tst().accept_fetched(raw, sig, 0, str(keys['pub']))
    assert d is None and 'expired' in why
    cache = tmp_path / 'cache'
    cache.mkdir()
    (cache / 'takserver-tested.json').write_bytes(raw)
    (cache / 'takserver-tested.json.sig').write_text(sig)
    assert _tst().cached(str(cache), str(keys['pub']))['version'] == V


def test_a_cached_file_edited_on_disk_is_not_trusted(keys, tmp_path):
    raw = _doc()
    cache = tmp_path / 'cache'
    cache.mkdir()
    (cache / 'takserver-tested.json').write_bytes(_doc(version='5.9-RELEASE1'))
    (cache / 'takserver-tested.json.sig').write_text(_sign(raw, keys['key'], keys['dir']))
    assert _tst().cached(str(cache), str(keys['pub'])) is None


@pytest.mark.parametrize('over, reason', [
    ({'kind': 'takportal-verified'}, 'kind'), ({'kind': None}, 'kind'),
    ({'installs': False}, 'install'), ({'updates': False}, 'install'),
    ({'updates': None}, 'install'),
    ({'version': '5.8'}, 'version'), ({'version': '5.8-RELEASE-104'}, 'version'),
    ({'version': 'main'}, 'version'), ({'tested': 'yesterday'}, 'tested date'),
    ({'expires': None}, 'expires'), ({'serial': 0}, 'serial'), ({'schema': 2}, 'schema'),
])
def test_a_file_that_does_not_say_both_tests_passed_for_a_real_version_is_refused(over, reason):
    with pytest.raises(ValueError, match=reason):
        _tst().parse(_doc(**over))


def test_a_file_signed_for_another_purpose_with_the_same_key_is_not_taken_for_this_one(keys):
    raw = _doc(kind='takportal-verified')
    d, why = _tst().accept_fetched(raw, _sign(raw, keys['key'], keys['dir']), 0, str(keys['pub']))
    assert d is None and 'kind' in why


# ── what the page and the mail say ────────────────────────────────────────────

REC = json.loads(_doc())


@pytest.mark.parametrize('installed, state', [
    ('5.8-RELEASE84', 'behind'), ('5.7-RELEASE43', 'behind'), ('5.8-RELEASE103', 'behind'),
    ('5.8-RELEASE104', 'current'), ('5.8-RELEASE-104', 'current'),
    ('5.8-RELEASE105', 'newer'), ('5.9-RELEASE1', 'newer'),
    ('5.8-RELEASE104-ubuntu1', 'current'),         # a package suffix does not change the release
    ('', 'unknown'), ('not-a-version', 'unknown'), (None, 'unknown'),
])
def test_page_state_compares_release_numbers_as_numbers(installed, state):
    got = _tst().page_state(installed, REC)
    assert got['state'] == state and got['tested'] == V


def test_release_104_is_newer_than_release_84_not_older():
    # a text compare says "5.8-RELEASE84" > "5.8-RELEASE104": the wrong answer, mailed to the wrong boxes
    assert _tst().page_state('5.8-RELEASE84', REC)['state'] == 'behind'
    assert _tst().page_state('5.8-RELEASE104', json.loads(_doc(version='5.8-RELEASE84')))['state'] == 'newer'


def test_no_signed_file_means_no_claim():
    assert _tst().page_state('5.8-RELEASE84', None) == {'tested': '', 'tested_date': '', 'state': 'unknown'}
    assert _tst().pending_item('5.8-RELEASE84', None, 'x') is None


def test_the_mail_item_says_in_plain_words_what_we_tested_and_where_to_click():
    it = _tst().pending_item('5.8-RELEASE84', REC, 'TAK Server page → Update TAK Server.')
    assert it['summary'] == f'We tested TAK Server {V}. It installs and updates fine.'
    assert it['identity'] == V and it['target'] == V and it['installed'] == '5.8-RELEASE84'
    assert it['how'] == 'TAK Server page → Update TAK Server.'
    assert any('tak.gov' in line and 'upload' in line for line in it['detail'])
    assert it['tested_new'] is True


@pytest.mark.parametrize('installed', ['5.8-RELEASE104', '5.8-RELEASE105', '', 'junk'])
def test_a_box_that_is_current_or_newer_or_unreadable_gets_no_item(installed):
    assert _tst().pending_item(installed, REC, 'x') is None


# ── the real collector, cut out of app.py ─────────────────────────────────────

def _exec(ns, *names):
    for n in names:
        exec(compile(ast.get_source_segment(APP, _FNS[n]), 'app.py', 'exec'), ns)


def _items(installed, record, tak_installed=True):
    unknown = set()
    ns = {'detect_modules': lambda: {'takserver': {'installed': tak_installed}},
          '_get_takserver_version_info': lambda: {'version': installed},
          '_takserver_tested_record': lambda fresh=False: record,
          '_tst': _tst(), 'print': lambda *a, **k: None}
    _exec(ns, '_takserver_tested_items')
    return ns['_takserver_tested_items'](unknown), unknown


def test_collector_returns_one_item_for_an_older_box():
    items, unknown = _items('5.8-RELEASE84', REC)
    assert [i['identity'] for i in items] == [V] and not unknown


def test_collector_is_silent_without_tak_server_without_a_file_and_when_current():
    assert _items('5.8-RELEASE84', REC, tak_installed=False) == ([], set())
    assert _items('5.8-RELEASE84', None) == ([], set())
    assert _items('5.8-RELEASE104', REC) == ([], set())


def test_collector_carries_dedup_state_when_the_version_cannot_be_read():
    items, unknown = _items('', REC)
    assert items == [] and unknown == {'takserver-tested'}


def test_collector_never_raises_into_the_sweep():
    ns = {'detect_modules': lambda: (_ for _ in ()).throw(RuntimeError('boom')), '_tst': _tst(),
          'print': lambda *a, **k: None}
    _exec(ns, '_takserver_tested_items')
    u = set()
    assert ns['_takserver_tested_items'](u) == [] and u == {'takserver-tested'}


# ── the real mail sweep: one mail per tested version ──────────────────────────

def _sweep(items, state):
    import test_patch_now_ops377 as pn
    return pn._sweep([], state, 1_800_000_000.0, fast=False, normal=items)


def _item(installed='5.8-RELEASE84', version=V):
    return _tst().pending_item(installed, json.loads(_doc(version=version)), 'TAK Server page → Update TAK Server.')


def test_one_plain_mail_the_first_time_and_none_the_second():
    r, sent, saved, _ = _sweep([_item()], {})
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == f'✅ TAK Server {V} tested: ready to update on tak-prod-1'
    assert f'We tested TAK Server {V}. It installs and updates fine.' in body
    assert 'To install: TAK Server page → Update TAK Server.' in body
    assert 'tak.gov' in body
    state = saved[-1]
    assert state['takserver-tested'] == V
    r2, sent2, saved2, _ = _sweep([_item()], state)
    assert sent2 == [] and r2['emailed'] is False      # same version: never mailed twice


def test_a_new_tested_version_is_mailed_once_more():
    _, _, saved, _ = _sweep([_item()], {})
    _, sent, _, _ = _sweep([_item(version='5.8-RELEASE110')], saved[-1])
    assert len(sent) == 1 and 'TAK Server 5.8-RELEASE110' in sent[0][1]


def test_a_failed_send_is_retried_not_recorded():
    import test_patch_now_ops377 as pn
    r, sent, saved, _ = pn._sweep([], {}, 1_800_000_000.0, fast=False, normal=[_item()], send_fails=True)
    assert r['emailed'] is False and not saved       # nothing recorded, so the next sweep tries again


# ── the real refresh, cut out of app.py ───────────────────────────────────────

class Box:
    NAMES = ('_takserver_tested_refresh', '_takserver_tested_record', '_takportal_verified_http')

    def __init__(self, tmp, keys):
        self.settings = {}
        self.files = {}
        self.cache = tmp / 'cfg' / 'takserver-tested'
        pub = str(keys['pub'])
        real = _tst()

        class P:
            def __getattr__(_, n):
                return getattr(real, n)
            cached = staticmethod(lambda d, pubkey_path=None: real.cached(d, pub))
            accept_fetched = staticmethod(lambda r, s, f: real.accept_fetched(r, s, f, pub))

        def etl_write(name, data, cache_dir=None):
            cache_dir = pathlib.Path(cache_dir)
            cache_dir.mkdir(parents=True, exist_ok=True)
            (cache_dir / name).write_bytes(data)

        self.ns = {'os': __import__('os'), 'time': time, 'threading': threading, '_tst': P(),
                   'print': lambda *a, **k: None, '_TAKSERVER_TESTED_CACHE': str(self.cache),
                   '_TAKSERVER_TESTED_LOCK': threading.Lock(), '_takserver_tested_attempt': {'ts': 0.0},
                   'load_settings': lambda: json.loads(json.dumps(self.settings)),
                   'save_settings': lambda s: self.settings.update(s), '_etlcat_cache_write': etl_write,
                   '_git_ls_remote': lambda *a, **k: {'refs/heads/main': 'a' * 40}}
        _exec(self.ns, *self.NAMES[:2])
        self.ns['_takportal_verified_http'] = lambda url, limit, timeout=8: self.files[url.rsplit('/', 1)[-1]]

    def serve(self, raw, sig):
        self.files = {'takserver-tested.json': raw, 'takserver-tested.json.sig': sig.encode()}

    def record(self):
        return self.ns['_takserver_tested_record'](fresh=True)


def test_refresh_keeps_a_good_file_drops_a_forged_one_and_never_goes_back(keys, tmp_path):
    b = Box(tmp_path, keys)
    raw3 = _doc(serial=3, version='5.8-RELEASE110')
    b.serve(raw3, _sign(raw3, keys['key'], keys['dir']))
    assert b.record()['version'] == '5.8-RELEASE110'
    forged = _doc(serial=9, version='5.9-RELEASE9')
    b.serve(forged, _sign(forged, keys['evil'], keys['dir']))
    assert b.record()['version'] == '5.8-RELEASE110'            # forged file ignored
    old = _doc(serial=2, version=V)
    b.serve(old, _sign(old, keys['key'], keys['dir']))
    assert b.record()['version'] == '5.8-RELEASE110'            # older serial: a replay, ignored
    assert b.settings['takserver_tested_serial'] == 3


def test_offline_box_says_nothing(keys, tmp_path):
    b = Box(tmp_path, keys)
    b.ns['_takportal_verified_http'] = lambda *a, **k: (_ for _ in ()).throw(OSError('offline'))
    assert b.record() is None


# ── guards: the wiring cannot drop out unseen ─────────────────────────────────

def test_the_mail_sweep_collects_the_tested_item_and_picks_its_subject():
    body = APP[APP.index('def _collect_pending_updates('):]
    body = body[:body.index('\ndef ')]
    assert '_takserver_tested_items(unknown)' in body
    assert "tested_new" in APP[APP.index('def _update_notify_check_once('):]


def test_the_page_gets_the_tested_state_and_shows_it_with_the_tak_gov_caveat():
    assert 'tak_tested=_tak_tested' in APP
    assert 'tak-tested-row' in PAGE and 'Latest we tested' in PAGE
    assert 'needs a login' in PAGE                       # honest: we cannot read what tak.gov has


def test_the_console_never_asks_tak_gov_for_a_version():
    for m in re.finditer(r'''(urlopen|requests\.(get|post)|urllib\.request\.Request)\(\s*[^)]*tak\.gov''', APP):
        pytest.fail(f'app.py fetches from tak.gov: {m.group(0)[:80]}')


def test_the_card_badge_is_unchanged_the_takserver_row_still_has_no_latest():
    # the cards read _get_takserver_version_info(); this change must not invent an update badge there
    src = ast.get_source_segment(APP, _FNS['_get_takserver_version_info'])
    assert "'latest': None" in src and '_tst' not in src


def test_a_failure_in_the_tested_source_never_hides_the_other_pending_updates():
    # CI, first push: other tests cut _collect_pending_updates out of app.py without this helper and
    # got a NameError for the whole sweep. Every source in that function is shielded; so is this one.
    fn = _FNS['_collect_pending_updates']
    for node in ast.walk(fn):
        if isinstance(node, ast.Try):
            if any(isinstance(c, ast.Call) and getattr(c.func, 'id', '') == '_takserver_tested_items'
                   for b in node.body for c in ast.walk(b)):
                assert any(h.type is not None and getattr(h.type, 'id', '') == 'Exception' for h in node.handlers)
                return
    pytest.fail('_collect_pending_updates calls _takserver_tested_items outside a try/except Exception')
