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
"""8446 gets its trusted certificate even when Let's Encrypt is slower than the TAK deploy.

Field 2026-10-15: two fresh installs at once, Let's Encrypt answered "503 Service busy". The TAK
deploy waited its 120 s, logged "Skipping 8446 cert install — cert not yet issued by Caddy" and
finished. install_le_cert_on_8446() is what writes the renewal script/unit, and the daily heal
treated "no script, no unit" as "this box never had LE on 8446" — so nothing ever installed it,
and phones could not enroll by QR. Minutes later Caddy had the cert; 8446 still served TAK's own.
"""

import pathlib
import re
import subprocess
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, name
    return m.group(0)


CADDY_PEM = b'-----BEGIN CERTIFICATE-----\nCADDY\n-----END CERTIFICATE-----\n'


def _heal(files, settings, keystore_fp=None, caddy_has_cert=True, install_result=True):
    """Build _selfheal_takserver_le_cert against a fake box. Returns (fn, installs)."""
    import os as _os
    installs = []

    def exists(p):
        return p in files

    fake_os = types.SimpleNamespace(path=types.SimpleNamespace(exists=exists, basename=_os.path.basename),
                                    fdopen=_os.fdopen, remove=_os.remove)

    def run(cmd, **kw):
        txt = cmd if isinstance(cmd, str) else ' '.join(cmd)
        if txt.startswith('sudo -n cat '):
            return subprocess.CompletedProcess(cmd, 0 if caddy_has_cert else 1,
                                               CADDY_PEM if caddy_has_cert else b'', b'')
        if 'openssl x509 -in' in txt:
            return subprocess.CompletedProcess(cmd, 0, 'sha256 Fingerprint=CADDY\n', '')
        if 'keytool' in txt and '-fingerprint' in txt:
            return subprocess.CompletedProcess(cmd, 0, keystore_fp or '', '')
        if 'keytool' in txt and '-checkend' in txt:
            return subprocess.CompletedProcess(cmd, 0 if keystore_fp else 1, '', '')
        raise AssertionError('unexpected command: ' + txt)

    def install(host, log, wait_for_cert=True):
        installs.append((host, wait_for_cert))
        return install_result

    ns = {'os': fake_os, 'subprocess': types.SimpleNamespace(run=run), 'shlex': __import__('shlex'),
          'load_settings': lambda: dict(settings),
          '_get_service_domain': lambda s, svc: f"takserver.{s['fqdn']}" if s.get('fqdn') else '',
          '_caddy_acme_cert_base': lambda h: '/var/lib/caddy/certs',
          '_custom_cert_paths': lambda: ('/custom.crt', '/custom.key'),
          '_get_tak_cert_password': lambda s: 'atakatak',
          '_tak_is_container': lambda: False,
          '_sudo_wrap': lambda c: ['sudo', '-n'] + c,
          'install_le_cert_on_8446': install}
    exec(compile(_fn('_selfheal_takserver_le_cert'), 'app.py', 'exec'), ns)
    return ns['_selfheal_takserver_le_cert'], installs


CORE = '/opt/tak/CoreConfig.xml'
JKS = '/opt/tak/certs/files/takserver-le.jks'
LE = {'fqdn': 'aws-noble.takwerx.com', 'ssl_mode': 'letsencrypt'}


# ── the trap: a box the deploy skipped ─────────────────────────────────────────────────────────

def test_deploy_skipped_box_gets_the_cert_once_caddy_has_it():
    heal, installs = _heal(files={CORE}, settings=LE, caddy_has_cert=True)
    assert heal(lambda m: None) is True
    assert installs == [('takserver.aws-noble.takwerx.com', False)]


def test_deploy_skipped_box_waits_while_caddy_has_no_cert():
    heal, installs = _heal(files={CORE}, settings=LE, caddy_has_cert=False)
    assert not heal(lambda m: None)
    assert installs == []


def test_no_tak_server_means_nothing_to_set_up():
    heal, installs = _heal(files=set(), settings=LE)
    assert heal(lambda m: None) is None and installs == []


def test_no_domain_means_nothing_to_set_up():
    heal, installs = _heal(files={CORE}, settings={'ssl_mode': 'self-signed'})
    assert heal(lambda m: None) is None and installs == []


# ── unchanged behavior on boxes that already have LE on 8446 ───────────────────────────────────

RENEW = {'/opt/tak/renew-letsencrypt.sh', '/etc/systemd/system/takserver-cert-renewal.service', CORE, JKS}


def test_matching_keystore_is_left_alone_and_reports_true():
    heal, installs = _heal(files=RENEW, settings=LE, keystore_fp='sha256 Fingerprint=CADDY\n')
    assert heal(lambda m: None) is True
    assert installs == []


def test_stale_keystore_is_reinstalled():
    heal, installs = _heal(files=RENEW, settings=LE, keystore_fp='sha256 Fingerprint=OLD\n')
    assert heal(lambda m: None) is True
    assert installs == [('takserver.aws-noble.takwerx.com', False)]


def test_failed_install_reports_false():
    heal, installs = _heal(files={CORE}, settings=LE, install_result=False)
    assert heal(lambda m: None) is False
    assert len(installs) == 1


# ── deploy hands off instead of giving up ──────────────────────────────────────────────────────

def _retrier(results):
    started = []

    class _T:
        def __init__(self, target, daemon, name):
            started.append((target, daemon, name))

        def start(self):
            pass

    ns = {'time': types.SimpleNamespace(sleep=lambda s: None),
          'threading': types.SimpleNamespace(Thread=_T),
          '_selfheal_takserver_le_cert': None}
    exec(compile(_fn('_le8446_install_when_issued'), 'app.py', 'exec'), ns)
    calls, logs, sleeps = [], [], []
    seq = list(results)

    def heal(log):
        calls.append(1)
        return seq.pop(0) if seq else None

    ns['_le8446_install_when_issued'](logs.append, interval=60, max_s=1800,
                                      sleep=sleeps.append, heal=heal)
    assert len(started) == 1 and started[0][1] is True and started[0][2] == 'le8446-when-issued'
    return started[0][0], calls, logs, sleeps


def test_retry_stops_as_soon_as_8446_serves_the_cert():
    run, calls, logs, sleeps = _retrier([None, None, True])
    assert run() is True
    assert len(calls) == 3 and sleeps == [60, 60, 60]
    assert 'installed once it was issued (3 min after deploy)' in logs[-1]


def test_retry_gives_up_after_30_min_and_says_who_takes_over():
    run, calls, logs, sleeps = _retrier([])
    assert run() is False
    assert len(calls) == 30 and sum(sleeps) == 1800
    assert 'daily console heal' in logs[-1]


def test_retry_survives_a_heal_error():
    ns_calls = []

    def boom(log):
        ns_calls.append(1)
        if len(ns_calls) == 1:
            raise RuntimeError('keytool hiccup')
        return True
    started = []

    class _T:
        def __init__(self, target, daemon, name):
            started.append(target)

        def start(self):
            pass
    ns = {'time': types.SimpleNamespace(sleep=lambda s: None), 'threading': types.SimpleNamespace(Thread=_T),
          '_selfheal_takserver_le_cert': None}
    exec(compile(_fn('_le8446_install_when_issued'), 'app.py', 'exec'), ns)
    out = []
    ns['_le8446_install_when_issued'](out.append, sleep=lambda s: None, heal=boom)
    assert started[0]() is True
    assert any('keytool hiccup' in m for m in out)


def _at_deploy(install_ok, ssl_mode):
    handed = []
    ns = {'install_le_cert_on_8446': lambda h, log, wait_for_cert=True: install_ok,
          'load_settings': lambda: {'ssl_mode': ssl_mode},
          '_le8446_install_when_issued': lambda log: handed.append(1)}
    exec(compile(_fn('_install_le_cert_on_8446_at_deploy'), 'app.py', 'exec'), ns)
    logs = []
    ok = ns['_install_le_cert_on_8446_at_deploy']('takserver.x.example', logs.append)
    return ok, handed, logs


def test_deploy_hands_off_when_the_cert_is_late():
    ok, handed, logs = _at_deploy(False, 'letsencrypt')
    assert ok is False and handed == [1]
    assert any('automatically as soon as it arrives' in m for m in logs)


def test_deploy_does_not_hand_off_when_installed_or_custom():
    assert _at_deploy(True, 'letsencrypt')[1] == []
    assert _at_deploy(False, 'custom')[1] == []     # custom: nothing to wait for — upload a cert


def test_both_deploy_paths_use_the_handoff():
    assert APP.count("_install_le_cert_on_8446_at_deploy(_get_service_domain(settings, 'takserver'), log_step)") == 2
    # the only waiting install left is the one inside the hand-off itself
    assert re.findall(r'(?<!def )install_le_cert_on_8446\([^)]*wait_for_cert=True\)', APP) == \
        ['install_le_cert_on_8446(host, log_step, wait_for_cert=True)']
