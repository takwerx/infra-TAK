"""ops #663: Rocky 9 fresh install, Authentik LDAP outpost stuck on 403 Token invalid.

The POST that creates the LDAP provider got a 500 while Authentik was settling. The deploy
only handled 400, so it skipped the application, the outpost and the token. The compose file
kept `AUTHENTIK_TOKEN: placeholder` and the outpost was refused with `403 Token invalid/expired`
for the whole run. The repair code could not help: it stopped at "LDAP outpost not found", and
the deploy's final check only named the problem instead of repairing it.

Fixed: the provider step retries a 5xx, the repair builds a missing provider + outpost, and the
final check runs the token repair when the outpost is refused.
"""
import io
import json
import pathlib
import re
import time as _real_time
import types
import urllib.error
import urllib.request

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py (ops #663 fix missing)'
    return m.group(0)


class Resp:
    def __init__(self, body, code=200):
        self._b, self.code = json.dumps(body).encode(), code

    def read(self):
        return self._b

    def getcode(self):
        return self.code


def http_error(code, body='boom'):
    return urllib.error.HTTPError('http://ak', code, 'err', {}, io.BytesIO(body.encode()))


class FakeAuthentik:
    """Routes urlopen. `provider_posts` is the sequence of answers to POST /providers/ldap/."""

    def __init__(self, provider_posts=(), providers=(), outposts=()):
        self.provider_posts = list(provider_posts)
        self.providers = list(providers)
        self.outposts = list(outposts)
        self.calls = []

    def urlopen(self, req, timeout=None):
        url, method = req.full_url, req.get_method()
        self.calls.append((method, url))
        path = url.split('/api/v3/', 1)[1]
        if method == 'GET':
            if path.startswith('providers/ldap/'):
                return Resp({'results': self.providers})
            if path.startswith('outposts/instances/?search=LDAP'):
                return Resp({'results': self.outposts})
            if path.startswith('flows/instances/?designation=authentication'):
                return Resp({'results': [{'pk': 'auth1', 'slug': 'default-authentication-flow'},
                                         {'pk': 'ldapf', 'slug': 'ldap-authentication-flow'}]})
            if path.startswith('flows/instances/?designation=invalidation'):
                return Resp({'results': [{'pk': 'inv1', 'slug': 'default-invalidation-flow'}]})
            if path.startswith('core/tokens/') and path.endswith('/view_key/'):
                return Resp({'key': 'REALTOKEN123'})
        if method == 'POST':
            if path == 'providers/ldap/':
                a = self.provider_posts.pop(0) if len(self.provider_posts) > 1 else self.provider_posts[0]
                if isinstance(a, int):
                    raise http_error(a)
                self.providers = [{'pk': a, 'name': 'LDAP'}]
                return Resp({'pk': a}, 201)
            if path == 'core/applications/':
                return Resp({}, 201)
            if path == 'outposts/instances/':
                self.outposts = [{'pk': 'op1', 'name': 'LDAP', 'type': 'ldap', 'token_identifier': 'tokid'}]
                return Resp(self.outposts[0], 201)
        raise AssertionError(f'unexpected {method} {path}')


@pytest.fixture
def ak(monkeypatch):
    sleeps = []
    monkeypatch.setattr(_real_time, 'sleep', lambda n: sleeps.append(n))
    f = FakeAuthentik()
    monkeypatch.setattr(urllib.request, 'urlopen', f.urlopen)
    f.sleeps = sleeps
    return f


def _ensure_ns():
    ns = {'json': json, 'time': _real_time}
    exec(_fn('_ak_ldap_provider_ensure'), ns)
    return ns


def test_provider_step_retries_a_500_then_succeeds(ak):
    ak.provider_posts = [500, 502, 'prov-1']
    log = []
    pk = _ensure_ns()['_ak_ldap_provider_ensure']('http://ak', {}, 'bind', 'inv', plog=log.append, delay=1)
    assert pk == 'prov-1'
    assert len(ak.sleeps) == 2


def test_provider_step_uses_the_provider_a_500_created_anyway(ak):
    # The API answered 500 but had created the provider: the next look finds it, no second POST.
    ak.provider_posts = [500]
    posts = []
    real = ak.urlopen

    def urlopen(req, timeout=None):
        if req.get_method() == 'POST':
            ak.providers = [{'pk': 'prov-9', 'name': 'LDAP'}]
            posts.append(1)
        return real(req, timeout)
    urllib.request.urlopen = urlopen
    pk = _ensure_ns()['_ak_ldap_provider_ensure']('http://ak', {}, 'bind', 'inv', delay=1)
    assert pk == 'prov-9' and len(posts) == 1


def test_provider_step_gives_up_after_the_tries_and_does_not_loop_forever(ak):
    ak.provider_posts = [500]
    pk = _ensure_ns()['_ak_ldap_provider_ensure']('http://ak', {}, 'bind', 'inv', attempts=3, delay=1)
    assert pk is None
    assert len(ak.sleeps) == 2


def test_provider_step_does_not_retry_a_real_4xx(ak):
    ak.provider_posts = [403]
    pk = _ensure_ns()['_ak_ldap_provider_ensure']('http://ak', {}, 'bind', 'inv', delay=1)
    assert pk is None and ak.sleeps == []


def test_deploy_uses_the_retrying_helper_not_a_single_post():
    deploy = APP[APP.index('Create LDAP provider (ops #663'):][:900]
    assert '_ak_ldap_provider_ensure(' in deploy
    assert "providers/ldap/'" not in deploy


def _repair_ns(tmp_path, monkeypatch, fake):
    home = tmp_path / 'home'
    (home / 'authentik').mkdir(parents=True)
    compose = home / 'authentik' / 'docker-compose.yml'
    compose.write_text("services:\n  ldap:\n    image: x\n    environment:\n"
                       "      AUTHENTIK_TOKEN: placeholder\n  server:\n    image: y\n")
    monkeypatch.setenv('HOME', str(home))
    import os
    ns = {'json': json, 'os': os, 're': re, 'time': _real_time,
          'load_settings': lambda: {},
          '_get_module_deployment_config': lambda s, k: {},
          '_get_authentik_env_value': lambda s, k: 'bootstrap',
          '_get_authentik_api_url': lambda s: 'http://ak',
          '_sudo_wrap': lambda c: c,
          '_AK_COMPOSE_LOCK_BUSY_RC': 75,
          '_LDAP_TOKEN_LINE_RE': re.compile(
              r'^(?P<indent>\s*)AUTHENTIK_TOKEN:\s*(?P<val>.*)$')}
    recreated = []
    ns['_ak_compose_subprocess'] = lambda *a, **k: (recreated.append(a[0]) or
                                                    types.SimpleNamespace(returncode=0, stdout=b''))
    # the real regex lives in app.py; use it
    m = re.search(r'^_LDAP_TOKEN_LINE_RE = .*$', APP, re.M)
    if m:
        exec(m.group(0), ns)
    for n in ('_set_ldap_outpost_token_in_compose', '_ak_ldap_provider_ensure',
              '_ak_ldap_flow_pks', '_repair_ldap_outpost_token'):
        exec(_fn(n), ns)
    return ns, compose, recreated


def test_repair_builds_the_missing_provider_and_outpost_and_writes_the_token(tmp_path, monkeypatch, ak):
    ak.provider_posts = [500, 'prov-1']
    ns, compose, recreated = _repair_ns(tmp_path, monkeypatch, ak)
    ok, msg = ns['_repair_ldap_outpost_token'](plog_fn=lambda m: None)
    assert ok, msg
    assert 'REALTOKEN123' in compose.read_text()
    assert 'placeholder' not in compose.read_text()
    assert ('POST', 'http://ak/api/v3/outposts/instances/') in ak.calls
    assert recreated, 'the outpost container must be recreated onto the new token'


def test_repair_reports_when_the_provider_cannot_be_created(tmp_path, monkeypatch, ak):
    ak.provider_posts = [500]
    ns, compose, recreated = _repair_ns(tmp_path, monkeypatch, ak)
    ok, msg = ns['_repair_ldap_outpost_token'](plog_fn=lambda m: None)
    assert not ok and 'provider could not be created' in msg
    assert 'placeholder' in compose.read_text() and not recreated


def _final_ns(rejected, repair_ok, binds):
    calls = []
    ns = {'time': types.SimpleNamespace(sleep=lambda n: None),
          '_ensure_ldapsearch': lambda: True,
          '_test_ldap_bind_dn': lambda dn, pw: binds.pop(0) if len(binds) > 1 else binds[0],
          '_ldap_outpost_token_rejected': lambda: rejected,
          '_repair_ldap_outpost_token': lambda plog_fn=None: (calls.append('token') or (repair_ok, 'repaired')),
          '_ensure_authentik_ldap_outpost_on_fqdn': lambda *a, **k: calls.append('routing'),
          '_ensure_authentik_ldap_service_account': lambda: (calls.append('password') or (True, 'ok'))}
    exec(_fn('_authentik_deploy_final_verify_ldap_sa'), ns)
    return ns, calls


def test_final_check_repairs_a_refused_outpost_token():
    # binds fail until the token repair has run, then pass
    seq = [False, False]
    ns, calls = _final_ns(True, True, seq)
    orig = ns['_repair_ldap_outpost_token']

    def repair(plog_fn=None):
        r = orig(plog_fn)
        seq[:] = [True]
        return r
    ns['_repair_ldap_outpost_token'] = repair
    assert ns['_authentik_deploy_final_verify_ldap_sa']('pw', lambda m: None, attempts=6, delay_sec=0)
    assert calls == ['token']


def test_final_check_leaves_the_token_alone_when_it_is_not_refused():
    ns, calls = _final_ns(False, True, [False])
    assert not ns['_authentik_deploy_final_verify_ldap_sa']('pw', lambda m: None, attempts=6, delay_sec=0)
    assert 'token' not in calls
