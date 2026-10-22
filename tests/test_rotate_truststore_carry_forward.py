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
"""Rotate Intermediate CA keeps every CA the live truststore trusts (infra-TAK #204).

The new truststore used to get only the root, the new CA and the CA being replaced. After two
rotations the CA from two rotations back was gone, and every client cert it signed (ATAK
enrollments, bridges, TAKX) was refused without warning: test8 lost INT-CA-08 with 82 live certs.

keytool is faked (no JDK needed); openssl is real, on real certs made per test.
"""

import ast
import html
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

pytestmark = pytest.mark.skipif(not shutil.which('openssl'), reason='needs openssl')


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


HELPERS = ('_rotate_coreconfig_truststore', '_pem_key', '_rotate_truststore_entries', '_pem_cn_and_expiry',
           '_tak_live_certs_by_issuer', '_live_count_text', '_rotate_carry_forward_truststore',
           '_rotate_log_dropped_cas')


@pytest.fixture(scope='module')
def ns():
    ns = {'os': os, 're': re, 'shlex': shlex, 'subprocess': subprocess, 'tempfile': tempfile,
          'datetime': datetime, 'html': html}
    for name in HELPERS:
        exec(compile(_func(name), 'app.py', 'exec'), ns)
    return ns


# ── real certs ──────────────────────────────────────────────────────────────

class PKI:
    def __init__(self, d):
        self.d = d
        self.pem = {}
        self._mk('root-ca', None, 3650, ca=True)

    def _ssl(self, *args):
        subprocess.run(['openssl', *args], check=True, capture_output=True, cwd=self.d)

    def _mk(self, cn, issuer, days, ca):
        ext = self.d / f'{cn}.ext'
        ext.write_text('basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n' if ca
                       else 'basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n')
        if issuer is None:
            self._ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', f'{cn}.key',
                      '-subj', f'/O=TAK/CN={cn}', '-days', str(days), '-out', f'{cn}.pem')
        else:
            self._ssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', f'{cn}.key',
                      '-subj', f'/O=TAK/OU=TAK/CN={cn}', '-out', f'{cn}.csr')
            self._ssl('x509', '-req', '-in', f'{cn}.csr', '-CA', f'{issuer}.pem', '-CAkey', f'{issuer}.key',
                      '-CAcreateserial', '-days', str(days), '-extfile', ext.name, '-out', f'{cn}.pem')
        self.pem[cn] = (self.d / f'{cn}.pem').read_text()
        return self.pem[cn]

    def ca(self, cn, days=730):
        return self._mk(cn, 'root-ca', days, ca=True)

    def leaf(self, cn, issuer):
        return self._mk(cn, issuer, 365, ca=False)


@pytest.fixture(scope='module')
def pki(tmp_path_factory):
    p = PKI(tmp_path_factory.mktemp('pki'))
    p.ca('INT-CA-08')
    p.ca('INT-CA-09')
    p.ca('INT-CA-10')
    p.ca('INT-CA-11')
    p.ca('INT-CA-OLD', days=1)
    for i in range(3):
        p.leaf(f'bridge{i}', 'INT-CA-08')
    p.leaf('atak1', 'INT-CA-10')
    p.leaf('stale1', 'INT-CA-OLD')
    return p


# ── fake keytool over in-memory stores ─────────────────────────────────────

class Keytool:
    """keytool -list -rfc / -importkeystore / -import, as the rotation calls them."""

    def __init__(self):
        self.stores = {}      # path -> (password, {alias: pem})
        self.cmds = []

    def store(self, path, password, entries):
        self.stores[path] = (password, {a.lower(): p for a, p in entries.items()})

    def aliases(self, path):
        return sorted(self.stores[path][1])

    def _argv(self, cmd):
        assert cmd.startswith('runuser -u tak -- keytool '), cmd
        return self._opts(shlex.split(cmd[len('runuser -u tak -- '):].replace('2>&1', '')))

    def _opts(self, argv):
        opts, i = {}, 2
        while i < len(argv):
            if argv[i] in ('-noprompt', '-trustcacerts', '-rfc'):
                i += 1
            else:
                opts[argv[i]] = argv[i + 1]
                i += 2
        return argv[1], opts

    def _open(self, path, password):
        if path not in self.stores or self.stores[path][0] != password:
            return None
        return self.stores[path][1]

    def sh(self, argv):
        # _rotate_sh takes an argv list (ops #163), never a shell string
        assert isinstance(argv, list) and argv[0] == 'keytool', argv
        self.cmds.append(argv)
        op, o = self._opts(argv)
        assert op == '-list'
        st = self._open(o['-keystore'], o['-storepass'])
        if st is None:
            return False, 'keytool error: java.io.IOException: Keystore was tampered with, or password was incorrect'
        out = f'Keystore type: JKS\nKeystore provider: SUN\n\nYour keystore contains {len(st)} entries\n\n'
        for a, p in st.items():
            out += (f'Alias name: {a}\nCreation date: Oct 21, 2026\nEntry type: trustedCertEntry\n\n{p}'
                    '\n\n*******************************************\n*******************************************\n\n\n')
        return True, out

    def run(self, cmd, desc=None, check=True):
        self.cmds.append(cmd)
        op, o = self._argv(cmd)
        if op == '-importkeystore':
            src = self._open(o['-srckeystore'], o['-srcstorepass'])
            dst = self._open(o['-destkeystore'], o['-deststorepass'])
            if src is None or dst is None or o['-srcalias'].lower() not in src:
                return False
            dst[o['-destalias'].lower()] = src[o['-srcalias'].lower()]
            return True
        if op == '-import':
            dst = self._open(o['-keystore'], o['-deststorepass'])
            if dst is None:
                return False
            dst[o['-alias'].lower()] = pathlib.Path(o['-file']).read_text()
            return True
        raise AssertionError(f'unexpected keytool op {cmd!r}')


NEW_TS = '/opt/tak/certs/files/truststore-INT-CA-11.jks'
PREV_TS = '/opt/tak/certs/files/truststore-INT-CA-10.jks'


def _carry(ns, kt, pki, tmp_path, live=None, prev_ts=PREV_TS, prev_pass='atakatak', cert_pass='atakatak',
           old='INT-CA-10', old_pem_exists=True, now=None):
    old_pem = tmp_path / f'{old}.pem'
    if old_pem_exists:
        old_pem.write_text(pki.pem[old])
    logs = []
    trusted = ns['_rotate_carry_forward_truststore'](NEW_TS, prev_ts, prev_pass, cert_pass, old, str(old_pem),
                                                    live, kt.run, kt.sh, logs.append, now=now)
    return trusted, logs


def _new_store(kt, pki, password='atakatak'):
    # makeCert.sh ca made it with the new CA; Step 5 then imported the root.
    kt.store(NEW_TS, password, {'INT-CA-11': pki.pem['INT-CA-11'], 'root-ca': pki.pem['root-ca']})


def test_two_rotations_later_the_oldest_ca_is_still_trusted(ns, pki, tmp_path):
    """test8: INT-CA-08 signed 82 live certs; after 09 → 10 → 11 it must still be there."""
    kt = Keytool()
    kt.store(PREV_TS, 'atakatak', {'root-ca': pki.pem['root-ca'], 'INT-CA-10': pki.pem['INT-CA-10'],
                                   'INT-CA-09': pki.pem['INT-CA-09'], 'INT-CA-08': pki.pem['INT-CA-08']})
    _new_store(kt, pki)
    trusted, logs = _carry(ns, kt, pki, tmp_path)
    assert kt.aliases(NEW_TS) == ['int-ca-08', 'int-ca-09', 'int-ca-10', 'int-ca-11', 'root-ca']
    assert {'int-ca-08', 'int-ca-09', 'int-ca-10', 'int-ca-11', 'root-ca'} <= trusted
    assert not any('⚠' in m for m in logs), logs


def test_the_root_already_in_the_new_store_is_not_copied_twice(ns, pki, tmp_path):
    kt = Keytool()
    kt.store(PREV_TS, 'atakatak', {'root-ca': pki.pem['root-ca'], 'INT-CA-10': pki.pem['INT-CA-10']})
    _new_store(kt, pki)
    _carry(ns, kt, pki, tmp_path)
    assert not [c for c in kt.cmds if '-srcalias root-ca' in c]
    assert kt.aliases(NEW_TS) == ['int-ca-10', 'int-ca-11', 'root-ca']


def test_an_expired_ca_is_dropped_and_logged_with_its_live_certs(ns, pki, tmp_path):
    kt = Keytool()
    kt.store(PREV_TS, 'atakatak', {'root-ca': pki.pem['root-ca'], 'INT-CA-10': pki.pem['INT-CA-10'],
                                   'INT-CA-OLD': pki.pem['INT-CA-OLD']})
    _new_store(kt, pki)
    trusted, logs = _carry(ns, kt, pki, tmp_path, live={'int-ca-old': 4, 'int-ca-10': 1},
                           now=datetime.utcnow() + timedelta(days=30))
    assert 'int-ca-old' not in kt.aliases(NEW_TS)
    assert 'int-ca-10' in kt.aliases(NEW_TS)
    assert any('Dropped int-ca-old' in m and '4 live client certs' in m for m in logs), logs


def test_the_previous_store_is_opened_with_its_own_password(ns, pki, tmp_path):
    """Rotate with a new cert password: the old truststore still has the old one."""
    kt = Keytool()
    kt.store(PREV_TS, 'oldpass', {'root-ca': pki.pem['root-ca'], 'INT-CA-10': pki.pem['INT-CA-10'],
                                  'INT-CA-08': pki.pem['INT-CA-08']})
    _new_store(kt, pki, password='newpass')
    _carry(ns, kt, pki, tmp_path, prev_pass='oldpass', cert_pass='newpass')
    assert kt.aliases(NEW_TS) == ['int-ca-08', 'int-ca-10', 'int-ca-11', 'root-ca']


def test_an_unreadable_previous_store_still_keeps_the_ca_being_replaced(ns, pki, tmp_path):
    kt = Keytool()
    _new_store(kt, pki)
    trusted, logs = _carry(ns, kt, pki, tmp_path, prev_ts='/opt/tak/certs/files/missing.jks')
    assert 'int-ca-10' in kt.aliases(NEW_TS)
    assert any('Could not read the current truststore' in m for m in logs)


def test_the_ca_being_replaced_is_added_even_if_the_old_store_lacked_it(ns, pki, tmp_path):
    kt = Keytool()
    kt.store(PREV_TS, 'atakatak', {'root-ca': pki.pem['root-ca'], 'INT-CA-09': pki.pem['INT-CA-09']})
    _new_store(kt, pki)
    trusted, logs = _carry(ns, kt, pki, tmp_path)
    assert kt.aliases(NEW_TS) == ['int-ca-09', 'int-ca-10', 'int-ca-11', 'root-ca']


def test_a_missing_old_ca_is_warned_about_with_its_live_certs(ns, pki, tmp_path):
    kt = Keytool()
    _new_store(kt, pki)
    trusted, logs = _carry(ns, kt, pki, tmp_path, prev_ts='/nope.jks', old_pem_exists=False,
                           live={'int-ca-10': 7})
    assert any('INT-CA-10 is NOT in the new truststore' in m and '7 live client certs' in m for m in logs), logs


def test_live_certs_from_a_ca_not_in_the_truststore_are_warned_not_resurrected(ns, pki, tmp_path):
    """test12: 43 live INT-CA-01 certs, INT-CA-01 long gone. Revoke Old CA may have removed it on
    purpose, so rotation must not quietly re-trust it, but it must say so."""
    kt = Keytool()
    kt.store(PREV_TS, 'atakatak', {'root-ca': pki.pem['root-ca'], 'INT-CA-10': pki.pem['INT-CA-10']})
    _new_store(kt, pki)
    trusted, logs = _carry(ns, kt, pki, tmp_path, live={'int-ca-01': 43, 'int-ca-10': 2})
    assert 'int-ca-01' not in kt.aliases(NEW_TS)
    warn = [m for m in logs if 'int-ca-01' in m]
    assert warn and '43 live client certs' in warn[0] and 'not in the truststore' in warn[0]
    assert not [m for m in logs if 'int-ca-10' in m and '⚠' in m]


def test_makecerts_mykey_alias_clash_carries_the_old_ca_under_its_cn(ns, pki, tmp_path):
    """makeCert.sh `ca` stores each new CA as `mykey` (seen on test6), so old and new clash."""
    kt = Keytool()
    kt.store(PREV_TS, 'atakatak', {'root-ca': pki.pem['root-ca'], 'mykey': pki.pem['INT-CA-10'],
                                   'int-ca-09': pki.pem['INT-CA-09']})
    kt.store(NEW_TS, 'atakatak', {'mykey': pki.pem['INT-CA-11'], 'root-ca': pki.pem['root-ca']})
    trusted, logs = _carry(ns, kt, pki, tmp_path)
    st = kt.stores[NEW_TS][1]
    assert st['mykey'] == pki.pem['INT-CA-11']
    assert st['int-ca-10'] == pki.pem['INT-CA-10']
    assert st['int-ca-09'] == pki.pem['INT-CA-09']
    assert not [c for c in kt.cmds if '-file' in c], 'INT-CA-10 was imported twice'
    assert not any('⚠' in m for m in logs), logs


def test_an_alias_clash_on_the_cn_too_still_keeps_both(ns, pki, tmp_path):
    kt = Keytool()
    kt.store(PREV_TS, 'atakatak', {'root-ca': pki.pem['root-ca'], 'INT-CA-10': pki.pem['INT-CA-10'],
                                   'int-ca-11': pki.pem['INT-CA-09']})
    kt.store(NEW_TS, 'atakatak', {'int-ca-11': pki.pem['INT-CA-11'], 'int-ca-09': pki.pem['INT-CA-08'],
                                  'root-ca': pki.pem['root-ca']})
    _carry(ns, kt, pki, tmp_path)
    st = kt.stores[NEW_TS][1]
    assert st['int-ca-11'] == pki.pem['INT-CA-11']
    assert st['int-ca-09-prev'] == pki.pem['INT-CA-09']


def test_a_failed_copy_is_logged_with_its_live_certs(ns, pki, tmp_path):
    kt = Keytool()
    kt.store(PREV_TS, 'atakatak', {'root-ca': pki.pem['root-ca'], 'INT-CA-10': pki.pem['INT-CA-10'],
                                   'INT-CA-08': pki.pem['INT-CA-08']})
    _new_store(kt, pki)
    real_run = kt.run
    kt.run = lambda cmd, **kw: False if '-srcalias int-ca-08' in cmd else real_run(cmd, **kw)
    trusted, logs = _carry(ns, kt, pki, tmp_path, live={'int-ca-08': 82})
    assert any('Could not carry int-ca-08 forward' in m and '82 live client certs' in m for m in logs), logs


def test_aliases_and_paths_are_shell_quoted(ns, pki, tmp_path):
    kt = Keytool()
    kt.store(PREV_TS, 'pa ss', {'root-ca': pki.pem['root-ca'], 'INT-CA-10': pki.pem['INT-CA-10'],
                                "odd 'alias": pki.pem['INT-CA-08']})
    _new_store(kt, pki)
    _carry(ns, kt, pki, tmp_path, prev_pass='pa ss')
    assert "odd 'alias" in kt.aliases(NEW_TS)


# ── live certs from TAK's certificate table ─────────────────────────────────

def _rows(pems):
    """What psql -t -A prints for SELECT replace(replace(certificate, ...)): one cert per line."""
    return '\n'.join(p.replace('\r', '').replace('\n', '') for p in pems)


def test_live_certs_are_counted_per_issuer(ns, pki):
    sqls = []
    rows = _rows([pki.pem['bridge0'], pki.pem['bridge1'], pki.pem['bridge2'], pki.pem['atak1']])
    got = ns['_tak_live_certs_by_issuer'](lambda sql: (sqls.append(sql), (True, rows))[1])
    assert got == {'int-ca-08': 3, 'int-ca-10': 1}
    assert 'revocation_date IS NULL' in sqls[0] and 'expiration_date > now()' in sqls[0]


def test_certs_stored_without_pem_headers_are_counted(ns, pki):
    body = re.sub(r'-----[A-Z ]+-----|\s', '', pki.pem['bridge0'])
    assert ns['_tak_live_certs_by_issuer'](lambda sql: (True, body + '\n')) == {'int-ca-08': 1}


def test_an_unreadable_table_gives_none_and_an_empty_one_gives_nothing(ns):
    assert ns['_tak_live_certs_by_issuer'](lambda sql: (False, 'relation "certificate" does not exist')) is None
    assert ns['_tak_live_certs_by_issuer'](lambda sql: (True, '')) == {}


def test_pem_cn_and_expiry(ns, pki):
    cn, end = ns['_pem_cn_and_expiry'](pki.pem['INT-CA-OLD'])
    assert cn == 'INT-CA-OLD'
    assert datetime.utcnow() < end < datetime.utcnow() + timedelta(days=2)


# ── CoreConfig + Root CA rotation ──────────────────────────────────────────

CORECONFIG = '''<Configuration>
  <network><input _name="stdssl" protocol="tls" port="8089"/></network>
  <federation><federation-server port="9000"><tls keystore="JKS" keystoreFile="certs/files/takserver.jks"
    truststore="JKS" truststoreFile="certs/files/fed-truststore.jks" truststorePass="fed"/></federation-server></federation>
  <security>
    <tls keymanager="SunX509" keystore="JKS" keystoreFile="certs/files/takserver.jks" keystorePass="atakatak"
         truststore="JKS" truststoreFile="certs/files/truststore-INT-CA-10.jks" truststorePass="a&amp;b" context="TLSv1.2"/>
  </security>
  <federation><federation-server port="9000" truststoreFile="certs/files/fed-truststore.jks" truststorePass="x"/></federation>
</Configuration>'''


def test_the_live_truststore_comes_from_the_tls_element(ns):
    assert ns['_rotate_coreconfig_truststore'](CORECONFIG) == ('/opt/tak/certs/files/truststore-INT-CA-10.jks', 'a&b')
    assert ns['_rotate_coreconfig_truststore']('<Configuration/>') == ('', '')


def test_root_rotation_names_every_ca_it_drops_with_live_counts(ns, pki):
    kt = Keytool()
    kt.store(PREV_TS, 'atakatak', {'root-ca': pki.pem['root-ca'], 'INT-CA-10': pki.pem['INT-CA-10'],
                                   'INT-CA-08': pki.pem['INT-CA-08']})
    logs = []
    ns['_rotate_log_dropped_cas'](PREV_TS, 'atakatak', {'int-ca-08': 82, 'int-ca-10': 1}, kt.sh, logs.append)
    assert any('int-ca-08: 82 live client certs' in m for m in logs), logs
    assert any('int-ca-10: 1 live client cert' in m for m in logs), logs
    assert any('root-ca: 0 live client certs' in m for m in logs), logs


def test_rotate_intca_step5_uses_the_carry_forward():
    body = _func('takserver_rotate_intca')
    s5, s6 = body.index('Step 5/7'), body.index('Step 6/7')
    step5 = body[s5:s6]
    assert '_rotate_carry_forward_truststore(' in step5
    assert '_rotate_coreconfig_truststore(' in step5
    assert '_rotate_tak_live_certs_by_issuer()' in step5
    assert 'transition period' not in body, 'the one-old-CA import came back'


def test_rotate_rootca_logs_what_it_drops_before_wiping():
    body = _func('takserver_rotate_rootca')
    assert body.index('_rotate_log_dropped_cas(') < body.index('Step 1/8')


# ── _rotate_sh runs an argv list, not a host shell (ops #163) ──────────────

HOSTILE = "x'; touch /tmp/pwned; echo '$(id)`id`"


def _cert_ns(container):
    ns = {'os': os, 'shlex': shlex, 'TAK_CONTAINER': 'takserver',
          '_tak_is_container': lambda: container}
    for name in ('_rotate_tak_cert_cmd', '_rotate_tak_cert_argv'):
        exec(compile(_func(name), 'app.py', 'exec'), ns)
    return ns


@pytest.mark.parametrize('container', [False, True])
def test_the_argv_is_the_command_the_shell_string_ran(container):
    """Same command as the old `runuser -u tak -- keytool ... 2>&1` string, on both paths."""
    cns = _cert_ns(container)
    argv = ['keytool', '-list', '-rfc', '-keystore', '/opt/tak/certs/files/truststore-INT CA.jks',
            '-storepass', HOSTILE]
    old = cns['_rotate_tak_cert_cmd']('runuser -u tak -- ' + shlex.join(argv) + ' 2>&1')
    old_argv = shlex.split(old)
    assert old_argv[-1] == '2>&1'          # the outer redirect, now stderr=STDOUT
    assert cns['_rotate_tak_cert_argv'](argv) == old_argv[:-1]


def test_the_container_argv_quotes_every_value_as_one_word():
    got = _cert_ns(True)['_rotate_tak_cert_argv'](['keytool', '-storepass', HOSTILE])
    assert got[:7] == ['docker', 'run', '--rm', '-v', f'{os.path.realpath("/opt/tak")}:/opt/tak:z',
                       '--entrypoint', 'bash']
    inner = got[got.index('-c') + 1]
    assert shlex.split(inner) == ['keytool', '-storepass', HOSTILE, '2>&1']


def test_rotate_sh_never_uses_a_shell():
    calls = []

    class R:
        returncode, stdout = 0, 'Alias name: x\n'

    class Sub:
        PIPE, STDOUT = subprocess.PIPE, subprocess.STDOUT

        @staticmethod
        def run(argv, **kw):
            calls.append((argv, kw))
            return R()

    sns = {'subprocess': Sub, '_rotate_tak_cert_argv': lambda a: ['runuser', '-u', 'tak', '--'] + a}
    exec(compile(_func('_rotate_sh'), 'app.py', 'exec'), sns)
    assert sns['_rotate_sh'](['keytool', '-list', '-storepass', HOSTILE]) == (True, 'Alias name: x\n')
    argv, kw = calls[0]
    assert argv == ['runuser', '-u', 'tak', '--', 'keytool', '-list', '-storepass', HOSTILE]
    assert not kw.get('shell')
    assert kw['stderr'] == subprocess.STDOUT


def test_a_hostile_truststore_password_reaches_keytool_as_one_word(ns):
    seen = []
    ns['_rotate_truststore_entries']('/opt/tak/certs/files/truststore-INT-CA-10.jks', HOSTILE,
                                     lambda argv: (seen.append(argv), (False, ''))[1])
    assert seen == [['keytool', '-list', '-rfc', '-keystore', '/opt/tak/certs/files/truststore-INT-CA-10.jks',
                     '-storepass', HOSTILE]]
