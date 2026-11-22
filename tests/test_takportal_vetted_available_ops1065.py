# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""TAK Portal page: Vetted next to Available, and a deliberate way to install Available (ops #1065).

The ops #1042 gate makes Update install only the release that passed our Marketplace test. That is
right, but it hid that TAK Portal's maintainers had shipped something newer, and console users (who
do not use SSH) could not get an urgent fix until we signed it. The page now shows both versions and
an admin can install the newer release by hand, knowing it is not vetted.

Pins, each red on dev before this change and green with it:
  * page data shows Vetted and Available, and the state: testing / held (with the reason) / none;
  * the not-vetted install refuses a non-tag ref, a stale or different tag, a release that is not newer
    than Vetted, Beta Mode, a wrong password, and runs only the release GitHub calls the newest;
  * it is audited (who, from, to, "NOT VETTED");
  * Update then goes back to Vetted, and says it is a move back;
  * the badge, deploy and Guard Dog's "Update pending" stay silent for an Available-only release;
  * nothing but the display function asks GitHub for the newest release.
"""
import ast
import json
import os
import pathlib
import re
import shutil
import sys
import threading
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

from test_takportal_verified_gate_ops1042 import (  # noqa: E402  (fixtures and the stubbed box are shared)
    Box, FLOOR, _doc, _pass, _sign, _tpv, _version_info, keys)
from test_takportal_release_version_gh214 import _git, _git_ns as _git_ns_base, portal, upstream  # noqa: E402,F401


def _git_ns(tag='2.0.15'):
    """The update's git step for the vetted release `tag`, with the same per-thread slot the worker sets."""
    n = _git_ns_base(tag=tag)
    n['threading'] = threading
    n['_tpv'] = _tpv()
    n['_takportal_update_ctx'] = threading.local()
    return n

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
_FNS = {n.name: n for n in ast.parse(APP).body if isinstance(n, ast.FunctionDef)}
TPL = (ROOT / 'templates' / 'takportal.html').read_text(encoding='utf-8')

pytestmark = pytest.mark.skipif(shutil.which('openssl') is None, reason='needs the openssl CLI')


def _src(name):
    return ast.get_source_segment(APP, _FNS[name])


# ------------------------------------------------------------------ page data (the module)

def test_available_newer_than_vetted_and_not_held_is_in_the_test_queue():
    rec = _tpv().parse(_doc(5, '2.0.39'))
    s = _tpv().channel_state('2.0.39', '2.0.40', rec)
    assert (s['state'], s['vetted'], s['available'], s['newer'], s['reason']) == ('testing', '2.0.39', '2.0.40', True, '')


def test_a_held_release_carries_its_reason():
    rec = _tpv().parse(_doc(5, '2.0.39', held=('2.0.40',)))
    rec['held'][0]['reason'] = 'Marketplace installs fail at the d4h plugin'
    s = _tpv().channel_state('2.0.39', 'v2.0.40', rec)
    assert s['state'] == 'held' and s['reason'] == 'Marketplace installs fail at the d4h plugin' and s['newer']


def test_equal_or_older_available_says_nothing():
    rec = _tpv().parse(_doc(5, '2.0.39'))
    for avail in ('2.0.39', 'v2.0.39', '2.0.38'):
        s = _tpv().channel_state('2.0.39', avail, rec)
        assert s['state'] == 'none' and s['newer'] is False, avail


def test_when_either_side_is_unknown_the_state_is_unknown_not_a_guess():
    rec = _tpv().parse(_doc(5, '2.0.39'))
    assert _tpv().channel_state('', '2.0.40', rec)['state'] == 'unknown'
    assert _tpv().channel_state('2.0.39', '', rec)['state'] == 'unknown'
    assert _tpv().channel_state('2.0.39', 'main', rec)['state'] == 'unknown'
    assert _tpv().channel_state('2.0.39', '2.0.40', rec)['newer'] is True
    assert _tpv().channel_state('', '2.0.40', rec)['newer'] is False


def test_a_reason_is_one_short_clean_line():
    rec = {'held': [{'tag': '2.0.40', 'reason': 'bad\x00\x1b[31m\nnews ' + 'x' * 400}]}
    r = _tpv().held_reason(rec, '2.0.40')
    assert len(r) <= _tpv().REASON_MAX and '\n' not in r and '\x00' not in r and '\x1b' not in r


@pytest.mark.parametrize('ref', ['main', 'origin/main', 'HEAD', 'a' * 40, '2.0.40; id', '2.0.40\n', '../2.0.40',
                                 'v2.0.40-rc1', '', None, '2', '2.0.40.1.2'])
def test_the_not_vetted_install_takes_no_ref_but_a_plain_release_tag(ref):
    ok, why = _tpv().may_install_unvetted(ref, '2.0.40', '2.0.39')
    assert ok is False and why


def test_the_not_vetted_install_takes_only_the_release_github_calls_newest():
    ok, _ = _tpv().may_install_unvetted('2.0.40', '2.0.40', '2.0.39')
    assert ok is True
    ok, _ = _tpv().may_install_unvetted('v2.0.40', '2.0.40', '2.0.39')       # a 'v' is the same release
    assert ok is True
    assert _tpv().may_install_unvetted('2.0.38', '2.0.40', '2.0.39')[0] is False   # older than Vetted
    assert _tpv().may_install_unvetted('2.0.41', '2.0.40', '2.0.39')[0] is False   # not what GitHub says
    assert _tpv().may_install_unvetted('2.0.39', '2.0.39', '2.0.39')[0] is False   # equal to Vetted
    assert _tpv().may_install_unvetted('2.0.40', '2.0.40', '')[0] is False         # Vetted unknown
    assert _tpv().may_install_unvetted('2.0.40', '', '2.0.39')[0] is False         # GitHub unreachable
    assert _tpv().may_install_unvetted('2.0.40', '2.0.40', '2.0.39', installed='2.0.40')[0] is False
    assert _tpv().may_install_unvetted('2.0.40', '2.0.40', '2.0.39', installed='2.0.41')[0] is False


# ------------------------------------------------------- page data (the console, GitHub stubbed)

class Page(Box):
    """The stubbed box of the ops #1042 test, plus the two new functions."""
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.ns['_takportal_available_cache'] = {'tag': None, 'ts': 0}
        self.ns['urllib'] = __import__('urllib')
        self.ns['time'] = __import__('time')
        self.ns['re'] = __import__('re')
        for n in ('_takportal_available_release', '_takportal_channel_info'):
            if n in _FNS:
                exec(compile(_src(n), 'app.py', 'exec'), self.ns)
        self.ns['_TAKPORTAL_AVAILABLE_URL'] = 'https://github.com/x/TAK-Portal/releases/latest'

    def info(self, installed='2.0.39', fresh=True):
        return self.ns['_takportal_channel_info'](fresh=fresh, installed=installed)


@pytest.fixture
def page(tmp_path, keys, monkeypatch):
    return Page(tmp_path, keys, monkeypatch)


def test_page_data_shows_vetted_2_0_39_and_available_2_0_40_in_testing(page, keys):
    _pass(page, keys, 5, '2.0.39')
    page.github_latest = '2.0.40'
    i = page.info()
    assert (i['vetted'], i['available'], i['state']) == ('2.0.39', '2.0.40', 'testing')
    assert i['available_tag'] == '2.0.40' and i['vetted_tag'] == '2.0.39' and i['on_unvetted'] is False


def test_page_data_for_a_held_release_has_the_reason(page, keys):
    raw = _doc(6, '2.0.39', held=('2.0.40',))
    d = json.loads(raw)
    d['held'][0]['reason'] = 'plugin installs fail'
    raw = (json.dumps(d, indent=2) + '\n').encode()
    page.serve(raw, _sign(raw, keys['key'], keys['dir']))
    page.github_latest = '2.0.40'
    i = page.info()
    assert (i['state'], i['reason'], i['newer']) == ('held', 'plugin installs fail', True)


def test_page_data_when_available_equals_vetted_is_quiet(page, keys):
    _pass(page, keys, 5, '2.0.39')
    page.github_latest = '2.0.39'
    assert page.info()['state'] == 'none'


def test_page_data_with_github_down_does_not_crash_or_invent(page, keys, monkeypatch):
    _pass(page, keys, 5, '2.0.39')
    monkeypatch.setattr(page, '_urlopen', lambda req, timeout=None: (_ for _ in ()).throw(OSError('offline')))
    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen', page._urlopen)
    i = page.info()
    assert i['state'] == 'unknown' and i['available'] == '' and i['newer'] is False and i['vetted'] == '2.0.39'


def test_page_data_with_no_signed_file_has_no_vetted_and_offers_nothing(page):
    page.github_latest = '2.0.40'
    i = page.info()
    assert i['vetted'] == '' and i['state'] == 'unknown' and i['newer'] is False


def test_an_odd_redirect_target_is_never_available(page, keys, monkeypatch):
    """/releases/latest redirects to /releases/tag/<tag>. Anything that is not a plain release version
    (a branch name, an injected string, no release at all) gives no Available."""
    _pass(page, keys, 5, '2.0.39')
    import urllib.request
    for final in ('https://github.com/x/TAK-Portal/releases/tag/main',
                  'https://github.com/x/TAK-Portal/releases/tag/2.0.40%3Bid',
                  'https://github.com/x/TAK-Portal/releases/tag/2.0.40-rc1',
                  'https://github.com/x/TAK-Portal/releases',
                  'https://github.com/x/TAK-Portal/releases/tag/'):
        class R:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def geturl(s, final=final): return final
        monkeypatch.setattr(urllib.request, 'urlopen', lambda req, timeout=None, R=R: R())
        page.ns['_takportal_available_cache'].update(tag=None, ts=0)
        assert page.info()['available'] == '', final


def test_available_is_read_from_the_web_redirect_not_the_rate_limited_api(page, keys):
    """test12 box test: api.github.com answered 403 (60 requests an hour per address) while the web
    redirect kept working, so Available stayed empty. The reader must use the redirect."""
    _pass(page, keys, 5, '2.0.39')
    page.github_latest = 'v2.0.40'
    i = page.info()
    assert i['available'] == '2.0.40' and i['available_tag'] == 'v2.0.40'      # the tag as published
    assert page.ns['_TAKPORTAL_AVAILABLE_URL'].startswith('https://github.com/')
    m = re.search(r"^_TAKPORTAL_AVAILABLE_URL = '([^']+)'", APP, re.M)
    assert m and m.group(1).startswith('https://github.com/') and 'api.github.com' not in m.group(1)
    assert 'method=\'HEAD\'' in _src('_takportal_available_release')


def test_a_box_on_a_newer_release_than_vetted_is_flagged(page, keys):
    _pass(page, keys, 5, '2.0.39')
    page.github_latest = '2.0.40'
    assert page.info(installed='2.0.40')['on_unvetted'] is True
    assert page.info(installed='2.0.39')['on_unvetted'] is False
    assert page.info(installed='')['on_unvetted'] is False


# --------------------------------------------- badge, deploy, Guard Dog: silent for Available-only

def test_badge_and_deploy_ignore_an_available_only_release(page, keys):
    """GitHub says 2.0.40, the gate passed 2.0.39: every reader still says 2.0.39."""
    _pass(page, keys, 5, '2.0.39')
    page.github_latest = '2.0.40'
    assert page.deploy_tag() == '2.0.39'
    assert page.badge() == '2.0.39'
    assert page.update_tag() == '2.0.39'


def test_guard_dog_gets_no_update_pending_for_an_available_only_release(tmp_path, monkeypatch):
    """_get_takportal_version_info feeds Guard Dog's email. With Vetted == installed it is silent,
    however new the Available release is."""
    info = _version_info(tmp_path, monkeypatch, '2.0.39', '2.0.39', '')
    assert info['update_available'] is False
    # and the version helper has no way to learn about Available: it never calls the display reader
    code = '\n'.join(ln for ln in _src('_get_takportal_version_info').splitlines() if not ln.lstrip().startswith('#'))
    assert '_takportal_available_release' not in code and '_takportal_channel_info' not in code


def test_a_box_on_an_unvetted_release_is_never_offered_an_update_back(tmp_path, monkeypatch):
    info = _version_info(tmp_path, monkeypatch, '2.0.40', '2.0.39', '')
    assert info['update_available'] is False          # no badge pushes it back; the Update button does


def test_only_the_display_function_asks_github_for_the_newest_release():
    callers = [n for n, f in _FNS.items()
               if n != '_takportal_available_release'
               and '_takportal_available_release' in re.sub(r'(?m)^\s*#.*$', '', ast.get_source_segment(APP, f))]
    assert sorted(callers) == ['_takportal_channel_info'], callers
    for n in ('_takportal_latest_tag', '_fetch_takportal_latest', '_takportal_release_tag_strict',
              '_get_takportal_version_info', '_takportal_verified_release', '_module_update_info'):
        assert '_takportal_available_release' not in _src(n) and '_takportal_channel_info' not in _src(n), n
    # and only the page, the version API and the install route read the channel info
    users = sorted(n for n, f in _FNS.items() if '_takportal_channel_info(' in ast.get_source_segment(APP, f)
                   and n != '_takportal_channel_info')
    assert users == ['takportal_install_unvetted', 'takportal_page', 'takportal_version_api'], users


# ------------------------------------------------------------------- the install route

class FakeRequest:
    def __init__(self, data):
        self._d = data

    def get_json(self, silent=False):
        return self._d


class Route:
    """takportal_install_unvetted, run for real with the network, git and threads stubbed."""

    def __init__(self, tmp_path, monkeypatch, *, data, password_ok=True, beta=False, installed='2.0.39',
                 vetted='2.0.39', available='2.0.40', state='testing', running=False):
        portal = tmp_path / 'TAK-Portal'
        (portal / '.git').mkdir(parents=True)
        self.audits, self.threads, self.printed = [], [], []
        self.job = {'running': running, 'id': 'OLD', 'result': None, 'code': None}
        ns = {'os': types.SimpleNamespace(path=types.SimpleNamespace(
                  expanduser=lambda p: str(portal) if p == '~/TAK-Portal' else p,
                  isdir=os.path.isdir, join=os.path.join)),
              'request': FakeRequest(data), 'secrets': types.SimpleNamespace(token_hex=lambda n: 'JOB1'),
              'jsonify': lambda d: d, 'threading': types.SimpleNamespace(
                  Thread=lambda **kw: self._thread(kw), Lock=threading.Lock),
              'print': lambda *a, **k: self.printed.append(' '.join(map(str, a))),
              'app': types.SimpleNamespace(route=lambda *a, **k: (lambda f: f)),
              'login_required': lambda f: f, 'audit': lambda e, d='', force=False: self.audits.append((e, d, force)),
              '_require_admin_password': lambda d=None: None if password_ok else (
                  {'success': False, 'error': 'Invalid admin password'}, 403),
              '_takportal_beta_mode': lambda: beta, '_takportal_installed_version': lambda pd: installed,
              '_takportal_channel_info': lambda fresh=False, installed='': dict(
                  _tpv().channel_state(vetted, available, None if state != 'held' else {
                      'held': [{'tag': available, 'reason': 'plugin installs fail'}]}),
                  vetted_tag=vetted, available_tag=available, installed=installed, on_unvetted=False),
              '_tpv': _tpv(), '_TAKPORTAL_UPDATE_LOCK': threading.Lock(), '_takportal_update_job': self.job,
              '_takportal_update_worker': lambda *a: None}
        exec(compile(_src('takportal_install_unvetted'), 'app.py', 'exec'), ns)
        self.fn = ns['takportal_install_unvetted']

    def _thread(self, kw):
        self.threads.append(kw)
        return types.SimpleNamespace(start=lambda: None)

    def call(self):
        rv = self.fn()
        return rv if isinstance(rv, tuple) else (rv, 200)


def test_install_unvetted_starts_a_job_for_the_available_release_and_audits_it(tmp_path, monkeypatch):
    r = Route(tmp_path, monkeypatch, data={'tag': 'v2.0.40', 'password': 'x'})
    body, code = r.call()
    assert code == 202 and body['started'] and body['tag'] == '2.0.40'
    assert len(r.threads) == 1 and r.threads[0]['args'][2] == '2.0.40'      # the worker gets the tag
    assert r.job['running'] is True and r.job['id'] == 'JOB1'
    assert len(r.audits) == 1
    event, detail, force = r.audits[0]
    assert event == 'takportal:install-unvetted' and force is True           # logged even when not Hardened
    assert '2.0.39 -> 2.0.40' in detail and 'NOT VETTED' in detail and 'vetted 2.0.39' in detail


def test_install_unvetted_refuses_a_wrong_password_and_starts_nothing(tmp_path, monkeypatch):
    r = Route(tmp_path, monkeypatch, data={'tag': '2.0.40', 'password': 'nope'}, password_ok=False)
    body, code = r.call()
    assert code == 403 and not r.threads and not r.audits and r.job['running'] is False


@pytest.mark.parametrize('tag', ['main', 'origin/main', 'a' * 40, '2.0.40; rm -rf /', '2.0.41', '2.0.38', '', None])
def test_install_unvetted_refuses_any_ref_that_is_not_the_newest_release(tmp_path, monkeypatch, tag):
    r = Route(tmp_path, monkeypatch, data={'tag': tag, 'password': 'x'})
    body, code = r.call()
    assert code == 409 and body['success'] is False and not r.threads and not r.audits


def test_install_unvetted_refuses_when_available_is_not_newer_than_vetted(tmp_path, monkeypatch):
    r = Route(tmp_path, monkeypatch, data={'tag': '2.0.39', 'password': 'x'}, available='2.0.39')
    assert r.call()[1] == 409 and not r.threads


def test_install_unvetted_refuses_on_beta_mode(tmp_path, monkeypatch):
    r = Route(tmp_path, monkeypatch, data={'tag': '2.0.40', 'password': 'x'}, beta=True)
    body, code = r.call()
    assert code == 409 and 'Beta Mode' in body['error'] and not r.threads


def test_install_unvetted_refuses_while_an_update_runs(tmp_path, monkeypatch):
    r = Route(tmp_path, monkeypatch, data={'tag': '2.0.40', 'password': 'x'}, running=True)
    body, code = r.call()
    assert code == 409 and body['running'] is True and not r.threads and not r.audits


def test_install_unvetted_allows_a_held_release_too(tmp_path, monkeypatch):
    """The dialog shows the reason; the admin decides."""
    r = Route(tmp_path, monkeypatch, data={'tag': '2.0.40', 'password': 'x'}, state='held')
    assert r.call()[1] == 202


def test_the_route_is_login_required_and_password_gated_before_anything_else():
    i = APP.index("@app.route('/api/takportal/install-unvetted'")
    assert '@login_required' in APP[i:i + 150] and "methods=['POST']" in APP[i:i + 100]
    src = _src('takportal_install_unvetted')
    assert src.index('_require_admin_password(') < src.index('_takportal_beta_mode()') < src.index('_takportal_channel_info(')
    assert src.index("audit('takportal:install-unvetted'") < src.index('threading.Thread(')


# ------------------------------------------- the git step: install Available, Update goes back

def test_a_named_release_installs_then_update_goes_back_to_vetted_and_says_so(portal):
    """The box test in miniature, with real git: vetted 2.0.14, GitHub 2.0.15. Install 2.0.15 by hand,
    then the normal Update returns to 2.0.14 and says it is a move back."""
    n = _git_ns(tag='2.0.14')                                   # Update's answer: the vetted release
    n['_takportal_update_ctx'].target_tag = '2.0.15'
    r = n['_takportal_update_git'](str(portal), plog=lambda m: None)
    assert r['ok'] is True and r['to_version'] == '2.0.15' and r['rolled_back'] is False, r
    assert 'has not tested it' in r['message'] and 'press Update' in r['message']
    assert _git(portal, 'rev-parse', 'HEAD') == _git(portal, 'rev-parse', '2.0.15^{commit}')
    n['_takportal_update_ctx'].target_tag = ''                  # the next job, a plain Update
    r = n['_takportal_update_git'](str(portal), plog=lambda m: None)
    assert r['ok'] is True and r['rolled_back'] is True and r['to_version'] == '2.0.14', r
    assert 'Moving back from 2.0.15 to release 2.0.14' in r['message'] and 'takwerx' in r['message']
    assert _git(portal, 'rev-parse', 'HEAD') == _git(portal, 'rev-parse', '2.0.14^{commit}')


@pytest.mark.parametrize('ref', ['main', 'origin/main', 'HEAD', 'a' * 40, '2.0.15; id', '--upload-pack=x'])
def test_the_git_step_never_installs_a_branch_a_commit_or_a_flag(portal, ref):
    before = _git(portal, 'rev-parse', 'HEAD')
    n = _git_ns(tag='2.0.14')
    n['_takportal_update_ctx'].target_tag = ref
    r = n['_takportal_update_git'](str(portal), plog=lambda m: None)
    assert r['ok'] is False and 'plain TAK Portal release tag' in r['error']
    assert _git(portal, 'rev-parse', 'HEAD') == before


def test_a_normal_update_on_another_thread_never_sees_the_named_release(portal):
    n = _git_ns(tag='2.0.15')
    seen = {}

    def other():
        seen['tag'] = getattr(n['_takportal_update_ctx'], 'target_tag', '')
    n['_takportal_update_ctx'].target_tag = '2.0.14'
    t = threading.Thread(target=other)
    t.start()
    t.join()
    assert seen['tag'] == ''


def test_the_worker_names_the_release_for_its_own_thread_only():
    src = _src('_takportal_update_worker')
    assert "target_tag=''" in src.splitlines()[0]
    assert '_takportal_update_ctx.target_tag = str(target_tag' in src
    assert src.index('_takportal_update_ctx.target_tag') < src.index('_takportal_run_update(portal_dir)')


# --------------------------------------------------------------------------- the page

def _render(**ctx):
    jinja2 = pytest.importorskip('jinja2')
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROOT / 'templates')),
                             undefined=jinja2.ChainableUndefined, autoescape=True)
    env.globals['module_last_result'] = lambda name: ''
    env.globals['module_results_failing'] = lambda prefix: []
    env.globals['str'] = str
    env.globals['service_url'] = lambda name: 'https://takportal.example'
    base = dict(portal={'installed': True, 'running': True}, portal_version='2.0.39', settings={},
                container_info={}, portal_port='3000', portal_update_available=False, portal_latest='2.0.39',
                portal_beta_mode=False, portal_channel='release', takportal_deploy_cfg={},
                can_install_unvetted=False)
    base.update(ctx)
    return env.get_template('takportal.html').render(**base)


def _info(**over):
    d = {'vetted': '2.0.39', 'available': '2.0.40', 'state': 'testing', 'reason': '', 'newer': True,
         'vetted_tag': '2.0.39', 'available_tag': '2.0.40', 'installed': '2.0.39', 'on_unvetted': False}
    d.update(over)
    return d


def test_page_shows_both_versions_and_the_not_vetted_button():
    html = _render(channel_info=_info(), can_install_unvetted=True)
    assert 'id="portal-vetted">2.0.39<' in html and 'tested by takwerx with the CloudTAK Marketplace' in html
    assert 'id="portal-available">2.0.40<' in html and 'in our test queue' in html
    assert 'Install 2.0.40 (not vetted yet)' in html and 'id="unvetted-btn"' in html
    assert 'id="portal-unvetted-modal"' in html and 'id="portal-unvetted-password"' in html
    assert 'takwerx has not tested TAK Portal 2.0.40 yet' in html
    assert 'go back to 2.0.39' in html
    assert 'Update installs the TAK Portal release takwerx tested' in html


def test_page_for_a_held_release_shows_the_reason_in_the_row_and_the_dialog():
    html = _render(channel_info=_info(state='held', reason='plugin installs fail'), can_install_unvetted=True)
    assert 'held: plugin installs fail' in html
    assert 'id="portal-unvetted-reason">plugin installs fail<' in html


def test_page_escapes_a_hostile_reason():
    html = _render(channel_info=_info(state='held', reason='<script>alert(1)</script>'), can_install_unvetted=True)
    assert '<script>alert(1)</script>' not in html and '&lt;script&gt;' in html


def test_page_has_no_second_button_when_available_equals_vetted_or_unknown():
    for ci in (_info(state='none', newer=False, available='2.0.39', available_tag='2.0.39'),
               _info(state='unknown', newer=False, vetted='', vetted_tag='')):
        html = _render(channel_info=ci, can_install_unvetted=False)
        assert 'id="unvetted-btn"' not in html and 'id="portal-unvetted-modal"' not in html and \
            'Install 2.0.40 (not vetted yet)' not in html
        assert 'id="portal-available"' not in html


def test_on_beta_mode_the_page_still_shows_available_but_offers_no_install():
    html = _render(channel_info=_info(), can_install_unvetted=False, portal_beta_mode=True)
    assert 'id="portal-available">2.0.40<' in html
    assert 'id="unvetted-btn"' not in html and 'id="portal-unvetted-modal"' not in html


def test_page_on_an_unvetted_release_says_the_update_button_moves_back():
    html = _render(channel_info=_info(on_unvetted=True, installed='2.0.40'), portal_version='2.0.40',
                   portal_update_available=False)
    assert '⬇ Back to 2.0.39' in html and 'moves it back to 2.0.39' in html
    assert 'var PORTAL_ON_UNVETTED=true' in html
    html = _render(channel_info=_info())
    assert '⬆ Update' in html and 'Back to' not in html
    assert 'var PORTAL_ON_UNVETTED=false' in html


def test_the_update_button_asks_before_moving_back_and_the_install_asks_for_the_password():
    assert TPL.count('onclick="portalUpdateClick()"') == 2
    fn = TPL[TPL.index('function portalUpdateClick()'):TPL.index('function portalUnvettedOpen()')]
    assert 'PORTAL_ON_UNVETTED' in fn and 'confirm(' in fn and 'portalUpdate();' in fn
    inst = TPL[TPL.index('async function portalUnvettedInstall()'):TPL.index('async function portalUpdate(){')]
    assert 'portal-unvetted-password' in inst and "'/api/takportal/install-unvetted'" in inst
    assert 'password:pw' in inst and 'tag:PORTAL_AVAILABLE_TAG' in inst
