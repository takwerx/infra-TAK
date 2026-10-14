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
"""Container TAK: the 8446 LE-cert self-heal restarts TAK only when the cert actually changed (v10.2.13).

aws-arm, 2026-10-12 (v10.2.12 T&E) — every console start logged

    takserver LE-cert self-heal: 8446 keystore cert stale/expired vs Caddy — re-syncing and restarting TAK Server...

and restarted the TAK container, although the keystore already held Caddy's cert. A container
host has no Java: keytool lives only in the TAK image, so the host-side `keytool -list` always
came back empty and the keystore always looked stale. The keystore is now read with keytool
inside the TAK container (docker exec), the way the container renewal script reads it.
"""

import ast
import os
import pathlib
import shlex
import shutil
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

pytestmark = pytest.mark.skipif(shutil.which('openssl') is None, reason='openssl not installed')

JKS = '/opt/tak/certs/files/takserver-le.jks'


def _src(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _mkcert(d, name):
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', f'{d}/{name}.key',
                    '-out', f'{d}/{name}.pem', '-days', '2', '-subj', f'/CN={name}.example.com'],
                   capture_output=True, check=True)
    return (d / f'{name}.pem').read_text()


@pytest.fixture(scope='module')
def certs(tmp_path_factory):
    d = tmp_path_factory.mktemp('le')
    return {'caddy': _mkcert(d, 'caddy'), 'old': _mkcert(d, 'old')}


class _Box:
    """Host seams for _selfheal_takserver_le_cert: Caddy's cert, the TAK container, and a host
    with no keytool when TAK runs in a container."""

    def __init__(self, caddy_pem, keystore_pem, container=True, running=True, exec_rc=0):
        self.caddy_pem, self.keystore_pem = caddy_pem, keystore_pem
        self.container, self.running, self.exec_rc = container, running, exec_rc
        self.runs, self.installs, self.logs = [], [], []

    def _ok(self, stdout='', rc=0):
        return types.SimpleNamespace(returncode=rc, stdout=stdout, stderr='')

    def _fp(self, pem):
        return subprocess.run(['openssl', 'x509', '-noout', '-fingerprint', '-sha256'],
                              input=pem, capture_output=True, text=True).stdout.strip()

    def run(self, cmd, **kw):
        self.runs.append(cmd)
        if kw.get('shell'):
            if 'keytool' in cmd:
                if self.container:
                    return self._ok('', 127)              # no Java on a container host
                if '-fingerprint' in cmd:
                    return self._ok(self._fp(self.keystore_pem))
                return self._ok('', 0)                    # -checkend 0: still valid
            return subprocess.run(cmd, **kw)              # openssl on Caddy's staged cert
        if cmd[0] == 'cat':
            return types.SimpleNamespace(returncode=0, stdout=self.caddy_pem.encode(), stderr=b'')
        if cmd[:2] == ['docker', 'inspect']:
            return self._ok('true\n' if self.running else 'false\n')
        if cmd[:2] == ['docker', 'exec']:
            return self._ok(self.keystore_pem if self.exec_rc == 0 else '', self.exec_rc)
        if cmd[0] == 'openssl':
            return subprocess.run(cmd, **kw)
        raise AssertionError(f'unexpected command: {cmd}')

    def heal(self):
        ns = {
            'os': types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: True),
                                        fdopen=os.fdopen, remove=os.remove),
            'shlex': shlex,
            'subprocess': types.SimpleNamespace(run=self.run),
            'load_settings': lambda: {},
            '_get_service_domain': lambda s, k: 'tak.example.com',
            '_caddy_acme_cert_base': lambda h: '/var/lib/caddy/certificates/acme',
            '_get_tak_cert_password': lambda s: 'atakatak',
            '_tak_is_container': lambda: self.container,
            '_sudo_wrap': lambda argv: argv,
            'install_le_cert_on_8446': lambda host, log, wait_for_cert=True: self.installs.append(host),
        }
        exec(compile(_src('TAK_CONTAINER') + '\n\n' + _src('_selfheal_takserver_le_cert'), 'app.py', 'exec'), ns)
        ns['_selfheal_takserver_le_cert'](plog=self.logs.append)

    @property
    def execs(self):
        return [c for c in self.runs if isinstance(c, list) and c[:2] == ['docker', 'exec']]


def test_container_unchanged_cert_does_not_restart_tak(certs):
    box = _Box(certs['caddy'], certs['caddy'])
    box.heal()
    assert box.installs == [], 'keystore already holds Caddy\'s cert: re-importing restarts TAK for nothing'
    assert box.execs == [['docker', 'exec', 'takserver', 'keytool', '-list', '-rfc',
                          '-keystore', JKS, '-storepass', 'atakatak']]
    assert not any('error' in m for m in box.logs), box.logs


def test_container_changed_cert_is_resynced(certs):
    box = _Box(certs['caddy'], certs['old'])
    box.heal()
    assert box.installs == ['tak.example.com']


def test_container_unreadable_keystore_is_resynced(certs):
    box = _Box(certs['caddy'], certs['caddy'], exec_rc=1)
    box.heal()
    assert box.installs == ['tak.example.com']


def test_container_not_running_is_left_alone(certs):
    """A stopped TAK can't be read; restarting it from here would be the self-heal deciding to start TAK."""
    box = _Box(certs['caddy'], certs['old'], running=False)
    box.heal()
    assert box.installs == [] and box.execs == []


@pytest.mark.parametrize('keystore,want', [('caddy', []), ('old', ['tak.example.com'])])
def test_native_still_reads_the_host_keystore(certs, keystore, want):
    box = _Box(certs['caddy'], certs[keystore], container=False)
    box.heal()
    assert box.installs == want
    assert box.execs == []
