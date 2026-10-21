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
"""The LDAP outpost's move to FQDN routing backs off on a box whose DNS or certificate is
broken (ops #128).

The move recreates the outpost; when TLS then fails it is rolled back, recreating it again.
On a box with no certificate for the name it could only fail, yet it ran on every Authentik
deploy, update and 10-minute spiral-monitor tick — and TAK clients that connect during an
outpost restart get no groups (ops #126). Now the name's DNS and certificate are checked
before any container is touched, a failed move backs off 1 h, 2 h, 4 h … 24 h (a new FQDN or
certificate starts over; the Resync LDAP button skips the back-off), the monitor logs a
repeated skip once, and an outpost the monitor recreated gets the TAK client heal right away.

app.py cannot be imported in a test, so the functions are cut out of it and run against
stubs: the code under test is the shipped text.
"""

import ast
import pathlib
import ssl
import subprocess
import time
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
FQDN = 'tak.example.org'
CERT = b'leaf-cert-der'
INTERNAL = 'AUTHENTIK_HOST: http://authentik-server-1:9000'
COMPOSE = ('services:\n'
           '  server:\n'
           '    image: ghcr.io/goauthentik/server:2026.2.0\n'
           '  ldap:\n'
           '    image: ghcr.io/goauthentik/ldap:2026.2.0\n'
           '    environment:\n'
           f'      {INTERNAL}\n'
           '      AUTHENTIK_INSECURE: "true"\n'
           '  redis:\n'
           '    image: redis\n')


def _node(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return node
    raise AssertionError(f'{name} not found at module level in app.py')


def _segment(name):
    return ast.get_source_segment(APP, _node(name))


class _Ctx:
    def __init__(self, box):
        self.box = box

    def wrap_socket(self, raw, server_hostname):
        self.box.sni.append(server_hostname)
        if self.box.tls == 'no-cert':
            raise ssl.SSLError(1, '[SSL: TLSV1_ALERT_INTERNAL_ERROR] tlsv1 alert internal error')
        if self.box.tls == 'bad-cert':
            e = ssl.SSLCertVerificationError(1, 'certificate verify failed')
            e.verify_message = 'self-signed certificate'
            raise e
        box = self.box

        class _Tls:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def getpeercert(self, binary_form=False):
                return box.cert

        return _Tls()


class _Raw:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Box:
    """A fake box: ~/authentik with the outpost on internal routing, DNS, Caddy's TLS for the
    FQDN, docker (the outpost's logs after a recreate) and settings.json."""

    def __init__(self, tmp_path, dns='ok', tls='ok', ldap_log='remote error: tls: internal error',
                 settings=None):
        self.home = tmp_path
        ak = tmp_path / 'authentik'
        ak.mkdir(exist_ok=True)
        (ak / '.env').write_text(f'AUTHENTIK_HOST=https://{FQDN}\n')
        (ak / 'docker-compose.yml').write_text(COMPOSE)
        self.compose = ak / 'docker-compose.yml'
        self.dns, self.tls, self.cert = dns, tls, CERT
        self.ldap_log = ldap_log
        self.settings = settings if settings is not None else {}
        self.now = 1_800_000_000.0
        self.sni, self.recreates, self.log, self.recycles = [], [], [], []
        self.ldap_started = 1000.0

    def run(self, cmd, **kw):
        if cmd[:2] == ['docker', 'exec']:
            return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='')
        if cmd[:2] == ['systemctl', 'is-active']:
            return subprocess.CompletedProcess(cmd, 0, stdout='active\n', stderr='')
        if cmd[:3] == ['docker', 'compose', 'up']:
            self.recreates.append(self.compose.read_text())
            self.ldap_started += 60
            return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
        if cmd[:2] == ['docker', 'logs']:
            return subprocess.CompletedProcess(cmd, 0, stdout=self.ldap_log, stderr='')
        raise AssertionError(f'unexpected command {cmd}')

    def resolve(self, host):
        return ([], 'missing') if self.dns == 'missing' else (['203.0.113.7'], None)

    def connect(self, addr, timeout=None):
        assert addr == ('127.0.0.1', 443)
        if self.tls == 'refused':
            raise ConnectionRefusedError(61, 'Connection refused')
        return _Raw()


@pytest.fixture
def load(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setattr(time, 'sleep', lambda s: None)

    def _load(**kw):
        box = Box(tmp_path, **kw)
        fake_time = types.SimpleNamespace(time=lambda: box.now, strftime=time.strftime,
                                          localtime=time.localtime)
        ns = {
            'os': __import__('os'), 'hashlib': __import__('hashlib'), 'time': fake_time,
            'subprocess': types.SimpleNamespace(run=box.run, PIPE=subprocess.PIPE, STDOUT=subprocess.STDOUT,
                                                TimeoutExpired=subprocess.TimeoutExpired),
            'ssl': types.SimpleNamespace(create_default_context=lambda: _Ctx(box),
                                         SSLCertVerificationError=ssl.SSLCertVerificationError,
                                         SSLError=ssl.SSLError),
            'socket': types.SimpleNamespace(create_connection=box.connect),
            '_sudo_wrap': lambda c: c,
            '_dns_resolve_ipv4': box.resolve,
            'load_settings': lambda: box.settings,
            'save_settings': lambda s: box.settings.update(s),
            '_detect_authentik_ldap_spiral': lambda plog: (True, {'reason': 'test'}),
            '_docker_started_epoch': lambda c: box.ldap_started,
            '_tak_recycle_after_ldap_outage': lambda plog, trigger, check_outpost=True, final=False:
                box.recycles.append((trigger, check_outpost)),
        }
        for name in ('_LDAP_FQDN_MOVE_BACKOFF_S', '_LDAP_FQDN_MOVE_BACKOFF_MAX_S', '_ldap_outpost_fqdn_precheck',
                     '_ldap_fqdn_move_backoff', '_ldap_fqdn_move_failed', '_rewrite_ldap_compose_to_fqdn',
                     '_record_spiral_repair_attempt', '_apply_authentik_ldap_routing_repair',
                     '_ensure_authentik_ldap_outpost_on_fqdn', '_spiral_monitor_tak_recycle'):
            exec(compile(_segment(name), 'app.py', 'exec'), ns)
        box.ns = ns
        box.move = lambda **k: ns['_ensure_authentik_ldap_outpost_on_fqdn'](box.log.append, require_tak=False, **k)
        return box
    return _load


def _state(box):
    return box.settings.get('authentik_proactive_routing_migration') or {}


# ── the DNS / certificate check before any container is touched ──

def test_no_dns_record_leaves_the_outpost_alone(load):
    box = load(dns='missing')
    box.move()
    assert box.recreates == [] and INTERNAL in box.compose.read_text()
    assert any(f'{FQDN} has no DNS A record' in l and 'not recreating' in l for l in box.log)
    assert _state(box) == {}   # a check that failed is not a failed move: no back-off


@pytest.mark.parametrize('tls,why', [('no-cert', 'no working certificate'),
                                     ('bad-cert', 'is not valid (self-signed certificate)'),
                                     ('refused', 'no working certificate')])
def test_no_valid_certificate_leaves_the_outpost_alone(load, tls, why):
    box = load(tls=tls)
    box.move()
    assert box.recreates == [] and INTERNAL in box.compose.read_text()
    assert any(why in l for l in box.log), box.log


def test_certificate_is_checked_for_the_fqdn_on_this_hosts_caddy(load):
    box = load(ldap_log='successfully connected websocket')
    box.move()
    assert box.sni == [FQDN]
    assert len(box.recreates) == 1 and f'AUTHENTIK_HOST: https://{FQDN}' in box.compose.read_text()
    assert _state(box)['outcome'] == 'success'


def test_a_resolver_error_on_this_box_does_not_block(load):
    box = load(ldap_log='successfully connected websocket')
    box.resolve = lambda h: ([], 'error: [Errno -3] Temporary failure in name resolution')
    box.ns['_dns_resolve_ipv4'] = box.resolve
    box.move()
    assert len(box.recreates) == 1


# ── back-off after a move that failed anyway ──

def test_failed_move_backs_off_then_doubles(load):
    box = load()
    box.move()
    assert len(box.recreates) == 2                       # the move and its rollback
    assert INTERNAL in box.compose.read_text()
    st = _state(box)
    assert st['outcome'] == 'validation_failed' and st['fails'] == 1
    assert st['retry_after'] == int(box.now) + 3600
    assert any('next automatic try in 1h' in l for l in box.log)

    box.now += 10 * 60                                   # the next monitor tick
    box.move()
    assert len(box.recreates) == 2
    assert any('failed 1x with this certificate — backing off' in l for l in box.log)

    box.now += 3600                                      # back-off over: one more try, then 2 h
    box.move()
    assert len(box.recreates) == 4 and _state(box)['fails'] == 2
    assert _state(box)['retry_after'] == int(box.now) + 2 * 3600


def test_back_off_is_capped_at_a_day(load):
    box = load()
    for _ in range(9):
        box.move()
        box.now = _state(box)['retry_after']
    assert _state(box)['fails'] == 9
    assert _state(box)['retry_after'] - _state(box)['ts'] == 86400


def test_a_new_certificate_or_fqdn_starts_over(load):
    box = load()
    box.move()
    box.now += 60
    box.cert = b'renewed-cert-der'                       # operator fixed the certificate
    box.move()
    assert len(box.recreates) == 4 and _state(box)['fails'] == 1

    box.settings['authentik_proactive_routing_migration'].update(fqdn='old.example.org')
    box.now += 60
    box.move()
    assert len(box.recreates) == 6


def test_resync_button_skips_the_back_off_but_not_the_check(load):
    box = load()
    box.move()
    box.now += 60
    box.move(force=True)
    assert len(box.recreates) == 4 and _state(box)['fails'] == 2
    box.tls = 'no-cert'
    box.move(force=True)
    assert len(box.recreates) == 4


def test_success_clears_the_back_off(load):
    box = load()
    box.move()
    box.ldap_log = 'successfully connected websocket'
    box.move(force=True)
    assert _state(box)['outcome'] == 'success'
    box.compose.write_text(COMPOSE)                      # something put it back on internal
    box.move()
    assert len(box.recreates) == 4


def test_recreate_failure_also_backs_off(load):
    box = load()
    real = box.run

    def run(cmd, **kw):
        r = real(cmd, **kw)
        if cmd[:3] == ['docker', 'compose', 'up'] and len(box.recreates) == 1:
            return subprocess.CompletedProcess(cmd, 1, stdout='Error response from daemon', stderr='')
        return r
    box.ns['subprocess'].run = run
    box.move()
    assert _state(box)['outcome'] == 'recreate_failed' and _state(box)['fails'] == 1
    box.now += 60
    box.move()
    assert len(box.recreates) == 2


# ── the 10-minute monitor logs a repeated skip once ──

def test_monitor_logs_a_repeated_skip_once(load):
    box = load(tls='no-cert')
    for _ in range(6):
        box.move(quiet_repeats=True)
    assert len(box.log) == 1
    box.tls = 'bad-cert'                                 # a different reason is news
    box.move(quiet_repeats=True)
    assert len(box.log) == 2


def test_monitor_logs_the_back_off_once(load):
    box = load()
    box.move(quiet_repeats=True)
    n = len(box.log)
    for _ in range(5):
        box.now += 600
        box.move(quiet_repeats=True)
    assert len(box.log) == n + 1 and 'backing off until' in box.log[-1]


def test_interactive_callers_always_log_the_reason(load):
    box = load(tls='no-cert')
    box.move()
    box.move()
    assert len(box.log) == 2


# ── the reactive spiral repair checks the name too ──

def test_routing_repair_skips_a_move_that_can_only_fail(load):
    box = load(tls='no-cert')
    box.ns['_apply_authentik_ldap_routing_repair'](str(box.home / 'authentik'), box.log.append)
    assert box.recreates == [] and INTERNAL in box.compose.read_text()
    assert box.settings['authentik_spiral_last_repair']['outcome'] == 'precheck_failed'


# ── TAK client heal after the monitor recreated the outpost ──

def test_monitor_heals_tak_clients_when_it_recreated_the_outpost(load):
    box = load()
    t0 = box.ldap_started
    box.move(quiet_repeats=True)                         # move + rollback
    box.ns['_spiral_monitor_tak_recycle'](t0, box.log.append)
    assert box.recycles == [('spiral monitor LDAP routing', True)]


def test_monitor_does_not_heal_when_nothing_was_recreated(load):
    box = load(tls='no-cert')
    t0 = box.ldap_started
    box.move(quiet_repeats=True)
    box.ns['_spiral_monitor_tak_recycle'](t0, box.log.append)
    assert box.recycles == []


def test_callers_are_wired():
    monitor = _segment('_authentik_spiral_monitor')
    assert 'quiet_repeats=True' in monitor
    assert monitor.count('_spiral_monitor_tak_recycle(') == 2   # after the proactive and the reactive pass
    assert "_ensure_authentik_ldap_outpost_on_fqdn(lambda m: diag.append(m.strip()), force=True)" in APP
