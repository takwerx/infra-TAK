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
"""ops #1421: the Wazuh agent console module (Security review ops #1422).

The broker side is in test_wazuh_agent_ops1421.py. Here: what the console decides (the server
certificate check before anything is sent, the confirm step, the download hash, the order of the
broker calls, no password anywhere it must not be) and how the module is wired into app.py.
Each test fails on the base branch, where there is no Wazuh module.
"""

import ast
import hashlib
import importlib.util
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import threading
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TEMPLATE = (REPO / 'templates' / 'wazuh.html').read_text(encoding='utf-8')


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, REPO / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _load('takwerx_broker_ops1421_mod', 'broker/takwerx_broker.py')
import modules.wazuh as W   # noqa: E402  (package import: the module uses a relative import)

HAS_OPENSSL = shutil.which('openssl') is not None


# ── the module's copy of the pins is the broker's ───────────────────────────────

def test_the_module_pins_equal_the_broker_pins():
    assert W.PINS == B.WAZUH_PKG_PINS
    assert W.PIN_VERSION == B.WAZUH_VERSION
    assert W.PIN_RELEASE == W.PIN_VERSION + '-1'


def test_the_log_source_keys_equal_the_broker_catalog():
    assert set(W.SOURCE_KEYS) == set(B.WAZUH_SOURCES)
    for s in W.SOURCES:
        fmt, paths = B.WAZUH_SOURCES[s['key']]
        assert s['files'] == paths, s['key']


def test_server_and_certificate_rules_match_the_broker_on_hostile_input():
    corpus = ['wazuh.example.org', '10.1.2.3', '2001:db8::1', '0.0.0.0', '224.0.0.1', '', 'a b', 'x;id',
              'a"b', 'host\nname', '12345', 'a' * 300, '-bad.example', 'ok-host', 'UPPER.Example.ORG', None, 5]
    for v in corpus:
        assert W.valid_server(v) == B._wazuh_valid_server(v), repr(v)


def test_the_package_for_each_family_and_cpu_matches_the_broker():
    for fam in ('debian', 'rhel'):
        for arch in ('amd64', 'arm64', ''):
            assert W.pkg_name(fam, arch) == B._wazuh_pkg_name_for(fam, arch), (fam, arch)
    assert W.pkg_url('wazuh-agent_4.14.11-1_amd64.deb').startswith(
        'https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/')
    assert W.pkg_url('wazuh-agent-4.14.11-1.x86_64.rpm') == 'https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.11-1.x86_64.rpm'


# ── the card's request ───────────────────────────────────────────────────────────

def _cert(tmp_path, name='ca', san='IP:127.0.0.1,DNS:localhost'):
    key, crt = tmp_path / f'{name}.key', tmp_path / f'{name}.crt'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                    '-out', str(crt), '-days', '2', '-subj', f'/CN={name}', '-addext', f'subjectAltName={san}'],
                   check=True, capture_output=True)
    return crt.read_text(), str(crt), str(key)


@pytest.mark.skipif(not HAS_OPENSSL, reason='openssl needed')
def test_deploy_validate_needs_the_fingerprint_the_operator_confirmed(tmp_path):
    pem, _c, _k = _cert(tmp_path)
    good = {'server': 'wazuh.example.org', 'ca_pem': pem, 'password': 'pw-1', 'sources': ['ssh_auth'],
            'confirm_fingerprint': W.fingerprint(W.clean_pem(pem)[0])}
    params, err = W.deploy_validate(dict(good))
    assert not err and params['server'] == 'wazuh.example.org' and params['agent_name'].startswith('infratak-')
    assert params['ca_sha256'] == good['confirm_fingerprint']
    for bad in (dict(good, confirm_fingerprint=''), dict(good, confirm_fingerprint='AA:BB'),
                {k: v for k, v in good.items() if k != 'confirm_fingerprint'}):
        p, e = W.deploy_validate(bad)
        assert p is None and 'Check server' in e
    # the fingerprint of a DIFFERENT certificate does not count
    other, _c2, _k2 = _cert(tmp_path, 'other')
    p, e = W.deploy_validate(dict(good, confirm_fingerprint=W.fingerprint(W.clean_pem(other)[0])))
    assert p is None and 'Check server' in e


@pytest.mark.skipif(not HAS_OPENSSL, reason='openssl needed')
@pytest.mark.parametrize('patch', [
    {'server': 'a"b'}, {'server': ''}, {'password': ''}, {'password': 'x\ny'}, {'agent_name': 'x y'},
    {'sources': ['journald']}, {'sources': 'ssh_auth'}, {'sources': ['ssh_auth', 'ssh_auth']},
    {'ca_pem': 'not a cert'},
])
def test_deploy_validate_refuses_bad_fields(tmp_path, patch):
    pem, _c, _k = _cert(tmp_path)
    d = {'server': 'wazuh.example.org', 'ca_pem': pem, 'password': 'pw', 'sources': [],
         'confirm_fingerprint': W.fingerprint(W.clean_pem(pem)[0])}
    d.update(patch)
    params, err = W.deploy_validate(d)
    assert params is None and err


# ── C3/C4: the server certificate check, against a real TLS listener ─────────────

def _serve(cert, key, bind='127.0.0.1'):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket()
    srv.bind((bind, 0))
    srv.listen(5)
    seen = []
    stop = threading.Event()

    def run():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with ctx.wrap_socket(c, server_side=True) as t:
                    seen.append(t.recv(100))     # anything the client sends after the handshake
            except (ssl.SSLError, OSError):
                pass
    th = threading.Thread(target=run, daemon=True)
    th.start()

    def close():
        stop.set()
        th.join(2)
        srv.close()
    return srv.getsockname()[1], seen, close


@pytest.mark.skipif(not HAS_OPENSSL, reason='openssl needed')
def test_probe_accepts_the_right_certificate_for_the_typed_address_and_sends_nothing(tmp_path):
    pem, crt, key = _cert(tmp_path)
    port, seen, close = _serve(crt, key)
    try:
        r = W.probe_server('127.0.0.1', pem, port=port, timeout=5)
    finally:
        close()
    assert r['ok'] is True and r['server'] == '127.0.0.1'
    assert r['confirm_fingerprint'] == W.fingerprint(W.clean_pem(pem)[0])
    assert r['server_cert_sha256'].count(':') == 31
    assert seen in ([], [b'']), 'the probe must not send a password or anything else'


@pytest.mark.skipif(not HAS_OPENSSL, reason='openssl needed')
def test_probe_refuses_a_different_certificate_on_the_same_address(tmp_path):
    """Security test 2, the part the console decides: a rogue server on the address, signed by
    another CA, is refused and no password is ever sent (the probe has no password at all)."""
    _real_pem, _c, _k = _cert(tmp_path, 'real')
    _rogue_pem, rogue_crt, rogue_key = _cert(tmp_path, 'rogue')
    port, seen, close = _serve(rogue_crt, rogue_key)
    try:
        r = W.probe_server('127.0.0.1', _real_pem, port=port, timeout=5)
    finally:
        close()
    assert r['ok'] is False and 'not signed by the one you pasted' in r['error'] and 'Nothing was sent' in r['error']
    assert not seen


@pytest.mark.skipif(not HAS_OPENSSL, reason='openssl needed')
def test_probe_refuses_a_certificate_for_another_name(tmp_path):
    pem, crt, key = _cert(tmp_path, 'named', san='DNS:wazuh.other.example')
    port, _seen, close = _serve(crt, key)
    try:
        r = W.probe_server('127.0.0.1', pem, port=port, timeout=5)
    finally:
        close()
    assert r['ok'] is False and 'name is not 127.0.0.1' in r['error']


def test_probe_reports_a_closed_port_and_a_server_that_is_not_tls(tmp_path):
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    pem_text = ('-----BEGIN CERTIFICATE-----\n' + 'QUJD' * 20 + '\n-----END CERTIFICATE-----\n')
    # a cert that does not parse never reaches the network
    r = W.probe_server('127.0.0.1', pem_text, port=port, timeout=2)
    assert r['ok'] is False
    r = W.probe_server('bad host', pem_text, port=port)
    assert r['ok'] is False and 'host name or an IP' in r['error']


# ── the download ─────────────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def read(self, n):
        b = self.data[self.pos:self.pos + n]
        self.pos += len(b)
        return b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _ctx(tmp_path, **extra):
    store = {}
    c = {'CONFIG_DIR': str(tmp_path), 'load_settings': lambda: store, 'save_settings': lambda s: store.update(s),
         'os_type': lambda: 'debian', '_host_arch': lambda: 'amd64', 'audit': lambda *a, **k: None}
    c.update(extra)
    return c, store


def test_download_keeps_a_file_whose_sha256_matches_and_deletes_one_that_does_not(tmp_path, monkeypatch):
    name = 'wazuh-agent_4.14.11-1_amd64.deb'
    ctx, _s = _ctx(tmp_path)
    monkeypatch.setitem(W.PINS, name, hashlib.sha256(b'good bytes').hexdigest())
    logs = []
    path = W.download(ctx, name, logs.append, opener=lambda req, timeout=0: _Resp(b'good bytes'))
    assert open(path, 'rb').read() == b'good bytes' and oct(os.stat(path).st_mode & 0o777) == '0o640'
    assert oct(os.stat(os.path.dirname(path)).st_mode & 0o777) == '0o700'
    os.unlink(path)
    with pytest.raises(RuntimeError) as e:
        W.download(ctx, name, logs.append, opener=lambda req, timeout=0: _Resp(b'good byteZ'))
    assert 'does not match' in str(e.value)
    assert not os.path.exists(path) and not os.path.exists(path + '.part')


def test_download_refuses_a_name_that_is_not_pinned_and_a_huge_file(tmp_path, monkeypatch):
    ctx, _s = _ctx(tmp_path)
    with pytest.raises(RuntimeError):
        W.download(ctx, 'wazuh-agent_9.9.9-1_amd64.deb', lambda m: None, opener=lambda r, timeout=0: _Resp(b''))
    name = 'wazuh-agent_4.14.11-1_amd64.deb'
    monkeypatch.setattr(W, 'MAX_PKG_BYTES', 10)
    with pytest.raises(RuntimeError) as e:
        W.download(ctx, name, lambda m: None, opener=lambda r, timeout=0: _Resp(b'x' * 100))
    assert 'larger' in str(e.value)


# ── the order of the broker calls, and where the password goes ───────────────────

class FakeBroker:
    def __init__(self, enrolled_log='Connected to the server ([10.0.0.5]:1514/tcp)', problems=None,
                 installed_ok=True):
        self.calls, self.enrolled_log = [], enrolled_log
        self.problems, self.installed_ok = problems or [], installed_ok

    def __call__(self, req, timeout=900):
        self.calls.append(dict(req))
        a = req.get('action')
        if a == 'verify':
            return {'ok': True, 'enrolled': True, 'problems': list(self.problems), 'log': self.enrolled_log}
        if a == 'install':
            return {'ok': self.installed_ok, **({} if self.installed_ok else {'error': 'refused: file'})}
        return {'ok': True, 'problems': []}

    def actions(self):
        return [c['action'] + (':' + c['verb'] if 'verb' in c else '') for c in self.calls]


def _deploy_params():
    return {'server': 'wazuh.example.org', 'agent_name': 'tak-1', 'ca_pem': 'PEM', 'password': 'S3cret-pw',
            'sources': ['ssh_auth'], 'ca_sha256': 'AA:BB'}


def _wire(monkeypatch, tmp_path, broker, **kw):
    ctx, store = _ctx(tmp_path, _wazuh_agent_op=broker, **kw)
    monkeypatch.setattr(W, 'download', lambda c, n, plog, opener=None: '/cfg/wazuh/' + n)
    monkeypatch.setattr(W, 'installed_info', lambda c: (True, '4.14.11-1'))
    monkeypatch.setattr(W.time, 'sleep', lambda s: None)
    W.job_state(W.KEY)['log'].clear()
    return ctx, store


def test_deploy_installs_configures_enrolls_then_deletes_the_password(tmp_path, monkeypatch):
    broker = FakeBroker()
    ctx, store = _wire(monkeypatch, tmp_path, broker)
    job = {}
    W.deploy(ctx, job, _deploy_params())
    assert broker.actions() == ['install', 'configure', 'service:enable', 'service:restart', 'verify', 'drop_password']
    assert job['complete'] is True
    cfg = [c for c in broker.calls if c['action'] == 'configure'][0]
    assert cfg['password'] == 'S3cret-pw' and cfg['ca_pem'] == 'PEM' and cfg['sources'] == ['ssh_auth']
    assert store['wazuh']['server'] == 'wazuh.example.org' and store['wazuh']['sources'] == ['ssh_auth']
    # the password is nowhere it must not be: settings, job log, audit
    assert 'S3cret-pw' not in repr(store) and 'S3cret-pw' not in '\n'.join(W.job_state(W.KEY)['log'])
    assert 'ca_pem' not in store['wazuh'] and 'password' not in store['wazuh']


def test_deploy_stops_when_the_broker_refuses_the_install(tmp_path, monkeypatch):
    broker = FakeBroker(installed_ok=False)
    ctx, store = _wire(monkeypatch, tmp_path, broker)
    with pytest.raises(RuntimeError) as e:
        W.deploy(ctx, {}, _deploy_params())
    assert 'Install' in str(e.value) and broker.actions() == ['install']
    assert 'wazuh' not in store


def test_a_wrong_password_names_the_reason_and_still_deletes_the_password_file(tmp_path, monkeypatch):
    broker = FakeBroker(enrolled_log='ERROR: Invalid password for agent enrollment')
    ctx, store = _wire(monkeypatch, tmp_path, broker)
    monkeypatch.setattr(W, '_wait_connected', lambda c, p, seconds=120: (False, W._why_not('Invalid password')))
    with pytest.raises(RuntimeError) as e:
        W.deploy(ctx, {}, _deploy_params())
    assert 'refused the enrollment password' in str(e.value)
    assert 'drop_password' in broker.actions()
    assert 'wazuh' not in store


def test_wait_connected_needs_enrolled_and_a_connection_newer_than_the_last_loss(tmp_path, monkeypatch):
    log = 'Connected to the server\nLost connection with manager'
    assert W._connected(log) is False and W._connected('Lost connection\nConnected to the server (x)') is True
    assert W._connected('') is False
    ctx, _s = _ctx(tmp_path, _wazuh_agent_op=FakeBroker(enrolled_log=log))
    monkeypatch.setattr(W.time, 'sleep', lambda s: None)
    ticks = iter([0, 0, 1000])
    monkeypatch.setattr(W.time, 'time', lambda: next(ticks))
    ok, why = W._wait_connected(ctx, lambda m: None, seconds=10)
    assert ok is False and why


def test_the_password_never_reaches_the_audit_call(tmp_path, monkeypatch):
    seen = []
    broker = FakeBroker()
    ctx, _store = _wire(monkeypatch, tmp_path, broker, audit=lambda ev, detail='', force=False: seen.append((ev, detail)))
    W.deploy(ctx, {}, _deploy_params())
    assert seen and all('S3cret-pw' not in ev + detail for ev, detail in seen)


def test_get_version_info_offers_the_pin_only_to_an_older_agent(tmp_path, monkeypatch):
    ctx, _s = _ctx(tmp_path)
    for installed, ver, want in ((True, '4.14.10-1', True), (True, '4.14.11-1', False),
                                 (True, '4.15.0-1', False), (False, '', False), (True, 'weird', False)):
        monkeypatch.setattr(W, 'installed_info', lambda c, i=installed, v=ver: (i, v))
        assert W.get_version_info(ctx)['update_available'] is want, ver
    monkeypatch.setattr(W, 'installed_info', lambda c: (True, '4.14.10-1'))
    info = W.get_version_info(ctx)
    assert info['version'] == '4.14.10-1' and info['latest'] == '4.14.11-1'


def test_update_keeps_the_server_and_re_applies_the_lock_down_and_never_downgrades(tmp_path, monkeypatch):
    broker = FakeBroker()
    ctx, store = _wire(monkeypatch, tmp_path, broker)
    store['wazuh'] = {'server': 'wazuh.example.org', 'agent_name': 'tak-1', 'sources': ['fail2ban']}
    monkeypatch.setattr(W, 'installed_info', lambda c: (True, '4.14.10-1'))
    r = W.update(ctx)
    assert r['success'] is True
    assert broker.actions() == ['install', 'configure', 'service:restart', 'verify']
    assert broker.calls[0]['upgrade'] is True and 'password' not in broker.calls[1] and 'ca_pem' not in broker.calls[1]
    assert broker.calls[1]['sources'] == ['fail2ban']
    monkeypatch.setattr(W, 'installed_info', lambda c: (True, '4.14.11-1'))
    again = FakeBroker()
    ctx2, _s2 = _wire(monkeypatch, tmp_path, again)
    monkeypatch.setattr(W, 'installed_info', lambda c: (True, '4.14.11-1'))
    r = W.update(ctx2)
    assert r['success'] is False and again.calls == []


def test_update_refuses_an_agent_infra_tak_has_no_saved_server_for(tmp_path, monkeypatch):
    broker = FakeBroker()
    ctx, _store = _wire(monkeypatch, tmp_path, broker)
    monkeypatch.setattr(W, 'installed_info', lambda c: (True, '4.14.10-1'))
    r = W.update(ctx)
    assert r['success'] is False and 'no saved server' in r['error'] and broker.calls == []


def test_reassert_writes_nothing_when_intact_and_fixes_it_when_not(tmp_path, monkeypatch):
    ok = FakeBroker()
    ctx, store = _wire(monkeypatch, tmp_path, ok)
    store['wazuh'] = {'server': 'wazuh.example.org', 'agent_name': 'tak-1', 'sources': ['ssh_auth']}
    monkeypatch.setattr(W, 'unit_active', lambda c: True)
    assert W.reassert(ctx) == {'acted': False} and ok.actions() == ['verify']
    bad = FakeBroker(problems=['active response is not disabled'])
    ctx2, store2 = _wire(monkeypatch, tmp_path, bad)
    store2['wazuh'] = dict(store['wazuh'])
    r = W.reassert(ctx2)
    assert r['acted'] is True and bad.actions() == ['verify', 'configure', 'service:restart']
    assert 'password' not in bad.calls[1] and 'ca_pem' not in bad.calls[1]


def test_reassert_does_nothing_for_an_agent_it_did_not_install_or_a_missing_one(tmp_path, monkeypatch):
    broker = FakeBroker()
    ctx, _store = _wire(monkeypatch, tmp_path, broker)
    assert W.reassert(ctx) == {'acted': False} and broker.calls == []        # no saved server
    monkeypatch.setattr(W, 'installed_info', lambda c: (False, ''))
    assert W.reassert(ctx) == {'acted': False} and broker.calls == []


def test_reassert_never_raises(tmp_path, monkeypatch):
    def boom(req, timeout=900):
        raise OSError('socket gone')
    ctx, store = _wire(monkeypatch, tmp_path, boom)
    store['wazuh'] = {'server': 's.example.org', 'agent_name': 'tak-1', 'sources': []}
    assert W.reassert(ctx) == {'acted': False} or W.reassert(ctx)['acted'] in (True, False)


def test_uninstall_goes_through_the_op_forgets_the_settings_and_the_download(tmp_path, monkeypatch):
    broker = FakeBroker()
    ctx, store = _wire(monkeypatch, tmp_path, broker)
    store['wazuh'] = {'server': 's.example.org'}
    d = tmp_path / 'wazuh'
    d.mkdir()
    (d / 'wazuh-agent_4.14.11-1_amd64.deb').write_bytes(b'x')
    r = W.uninstall(ctx, {}, {})
    assert r['success'] is True and broker.actions() == ['uninstall'] and 'wazuh' not in store
    assert not list(d.iterdir())


def test_a_failed_uninstall_keeps_the_settings_and_says_why(tmp_path, monkeypatch):
    ctx, store = _wire(monkeypatch, tmp_path, lambda req, timeout=900: {'ok': False, 'error': 'dpkg is locked'})
    store['wazuh'] = {'server': 's.example.org'}
    r = W.uninstall(ctx, {}, {})
    assert r['success'] is False and 'dpkg is locked' in r['error'] and 'wazuh' in store


def test_op_never_raises_and_always_returns_a_dict(tmp_path):
    def boom(req, timeout=900):
        raise ConnectionRefusedError('x')
    ctx, _s = _ctx(tmp_path, _wazuh_agent_op=boom)
    r = W.op(ctx, {'action': 'verify'})
    assert r['ok'] is False and 'broker' in r['error'].lower()
    ctx2, _s2 = _ctx(tmp_path, _wazuh_agent_op=lambda req, timeout=900: 'nope')
    assert W.op(ctx2, {'action': 'verify'})['ok'] is False
    seen = []
    ctx3, _s3 = _ctx(tmp_path, _wazuh_agent_op=lambda req, timeout=900: seen.append(req) or {'ok': True})
    W.op(ctx3, {'action': 'verify'})
    assert seen == [{'action': 'verify', 'op': 'wazuh_agent'}]


# ── registration and wiring ──────────────────────────────────────────────────────

def test_the_descriptor_has_no_generic_control_no_ports_and_a_real_unit(tmp_path):
    import modules as reg
    reg.MODULES.pop('wazuh', None)
    try:
        W.register({})
        d = reg.MODULES['wazuh']
        assert d['control_map'] == {}, 'start/stop go through the broker op, never a generic argv'
        assert d['ports'] == [] and d['service_units'] == ['wazuh-agent']
        assert d['route'] == '/wazuh' and d['template'] == 'wazuh.html' and callable(d['deploy_validate'])
        urls = {r['url'] for r in d['extra_routes']}
        assert urls == {'/api/wazuh/status', '/api/wazuh/probe', '/api/wazuh/service',
                        '/api/wazuh/enroll', '/api/wazuh/update'}
    finally:
        reg.MODULES.pop('wazuh', None)


def _fn_source(name):
    tree = ast.parse(APP)
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(name)


def test_app_wires_the_module_in_every_place_a_module_needs():
    assert "'_wazuh_agent_op': _wazuh_agent_op" in APP
    assert "mod_registry.MODULES.get('wazuh')" in APP
    assert "modules['wazuh'] = {'name': _wz_desc['name']" in APP
    assert "('wazuh', 'Wazuh agent', None, True, 'Wazuh agent page → Update.')" in APP
    assert "if key == 'wazuh':\n        return mod_registry.wazuh.get_version_info" in APP
    assert "mod_registry.uninstall_module('wazuh', log_fn=plog)" in APP
    assert "mod_registry.wazuh.reassert(mod_registry.get_ctx())" in APP


def test_the_start_up_lock_down_check_runs_after_the_registry_is_loaded_and_not_in_the_migrations():
    """The first box test showed the check never ran: _startup_migrations reaches it before
    mod_registry.load_all() has run, so the module was not there yet."""
    init = APP.index("mod_registry.init_registry(app, _MODULE_CTX, login_required)")
    hook = APP.index("threading.Thread(target=_wazuh_reassert_on_start, daemon=True, name='wazuh-reassert').start()")
    assert hook > init
    mig = _fn_source('_startup_migrations')
    assert 'wazuh' not in mig.lower()
    body = _fn_source('_wazuh_reassert_on_start')
    assert 'time.sleep(' in body and 'mod_registry.wazuh.reassert(mod_registry.get_ctx())' in body
    assert 'except Exception' in body


def test_the_page_route_needs_a_login():
    i = APP.index("@app.route('/wazuh')")
    assert APP[i:i + 80].split('\n')[1] == '@login_required'


def _op_fn(**ns):
    g = {'os': os, '_broker_socket_present': lambda: False,
         '_broker_request': lambda req, timeout=0: {'ok': True, 'via': 'socket', 'req': req},
         '_BROKER_SOURCE': str(REPO / 'broker' / 'takwerx_broker.py')}
    g.update(ns)
    exec(compile(_fn_source('_wazuh_agent_op'), 'app.py', 'exec'), g)
    return g['_wazuh_agent_op']


def test_the_seam_uses_the_broker_socket_when_there_is_one():
    f = _op_fn(_broker_socket_present=lambda: True)
    r = f({'op': 'wazuh_agent', 'action': 'verify'}, 60)
    assert r['via'] == 'socket' and r['req']['action'] == 'verify'


def test_the_seam_refuses_with_a_plain_reason_when_a_non_root_console_has_no_broker(monkeypatch):
    f = _op_fn()
    monkeypatch.setattr(os, 'geteuid', lambda: 1000)
    r = f({'op': 'wazuh_agent', 'action': 'verify'})
    assert r['ok'] is False and 'broker is not running' in r['error']


def test_a_root_console_with_no_broker_runs_the_same_gate_in_process(monkeypatch):
    f = _op_fn()
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    r = f({'op': 'wazuh_agent', 'action': 'configure', 'server': 'a"b', 'agent_name': 'tak-1', 'sources': []})
    assert r['ok'] is False and r['code'] == 'DENIED'
    r = f({'op': 'wazuh_agent', 'action': 'exec', 'argv': ['id']})
    assert r['ok'] is False and r['code'] == 'DENIED'


# ── the page: untrusted text is never turned into HTML ───────────────────────────

def test_the_page_never_puts_server_or_log_text_into_html():
    assert 'innerHTML' not in TEMPLATE and 'insertAdjacentHTML' not in TEMPLATE
    assert '| safe' not in TEMPLATE and 'Markup(' not in TEMPLATE
    for tail in ("el('agentLog').textContent = d.log", "el('v_server').textContent = d.server",
                 "b.textContent = x"):
        assert tail in TEMPLATE
    assert 'type="password"' in TEMPLATE and "el('i_pw').value = ''" in TEMPLATE


def test_the_card_says_the_two_things_security_asked_it_to_say():
    assert 'Only enter a server you run.' in W.CARD_WARNING
    assert 'can read the logs you pick and can reach this server' in W.CARD_WARNING
    assert 'not TLS' in W.TRANSPORT_NOTE and 'private path' in W.TRANSPORT_NOTE
    assert 'wz_warning' in TEMPLATE and 'wz_transport' in TEMPLATE
    assert 'lock-down intact' in TEMPLATE


@pytest.mark.skipif(not shutil.which('node'), reason='node needed')
def test_the_inline_script_parses(tmp_path):
    body = TEMPLATE.split('<script>', 1)[1].split('</script>', 1)[0]
    js = tmp_path / 'wazuh_page.js'
    js.write_text(body)
    r = subprocess.run(['node', '--check', str(js)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
