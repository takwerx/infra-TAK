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
"""Rotate Intermediate CA to a name that is already in the certificate folder (ops #942).

Before: the rotation ended "ROTATION COMPLETE" but ca.pem stayed on the ROOT CA. TAK's
makeCert.sh ca NAME does not fail for a name that has files already: keytool asks "Existing
entry alias ... exists, overwrite? [no]" and takes the one `y` the console pipes in, so the
script's own "make this the working CA? [y/n]" reads end-of-file, prints "Ok, not overwriting
existing keys", skips the three cp lines and exits 0. A client enrolled afterwards got a
certificate from the new CA while the server's working CA said ROOT: chain check failed.
(Seen on a Docker TAK Server, ARM, dev c2604e4; read in makeCert.sh on an Ubuntu 22.04 box.)

The tests run the real route (takserver_rotate_intca, taken from app.py) in a Flask test client
with a stand-in makeCert.sh that does what the real one does with stdin (see FAKE_MAKECERT).
"""

import ast
import os
import pathlib
import re
import shlex
import subprocess
import threading
import time as _time
import types

import flask
import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

PASSWORD = 'console-pw'

# makeCert.sh `ca NAME`, reduced to what matters here. Everything about stdin is the real
# script's: keytool -importkeystore asks "overwrite? [no]" when NAME-signing.jks exists (one line
# of stdin gone), then `read MVREQ` decides whether the new CA becomes ca.pem. Exit status 0 both
# ways. Self-signed certs stand in for the intermediate (only the subject CN is read back).
FAKE_MAKECERT = r'''#!/bin/bash
cd "$CERTS_DIR/files" || exit 1
[ -e ca.pem ] || { echo "ca.pem does not exist!"; exit 255; }
N="$2"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$N.key" -out "$N.pem" -subj "/CN=$N" -days 3 2>/dev/null
if [ -e "$N-signing.jks" ]; then
  read _overwrite
  echo "Existing entry alias $N exists, overwrite? [no]:  Enter new alias name (RETURN to cancel import for this entry):  keytool error: java.lang.NullPointerException: invalid null input"
fi
touch "$N-signing.jks" "$N-signing.p12" "truststore-$N.jks" "truststore-$N.p12" "$N.crl" "$N-trusted.pem"
echo "Do you want me to move files around so that future server and client certificates are signed by this new CA? [y/n]"
read MVREQ
if [[ "$MVREQ" == "y" || "$MVREQ" == "Y" ]]; then
  cp "$N.pem" ca.pem
  cp "$N.key" ca-do-not-share.key
  cp "$N-trusted.pem" ca-trusted.pem
  echo "Files moved successfully."
else
  echo "Ok, not overwriting existing keys. To manually change the CA later, execute these commands from the 'files' directory:"
fi
exit 0
'''


def _func(name, required=True):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    if required:
        raise AssertionError(f'{name} was renamed or removed')
    return None


def coreconfig_naming(ca):
    """The parts of CoreConfig.xml that name the CA: the enforced truststore, the enrollment
    signing keystore, and a Federation <tls> with a truststore of its own."""
    return (
        '<Configuration xmlns="http://bbn.com/marti/xml/config">\n'
        '<security><tls keystore="JKS" keystoreFile="certs/files/takserver.jks" keystorePass="atakatak" '
        f'truststore="JKS" truststoreFile="certs/files/truststore-{ca}.jks" truststorePass="atakatak" '
        'context="TLSv1.2" keymanager="SunX509"/></security>\n'
        '<certificateSigning CA="TAKServer"><certificateConfig><nameEntries>'
        '<nameEntry name="O" value="TAK"/></nameEntries></certificateConfig>'
        f'<TAKServerCAConfig keystore="JKS" keystoreFile="certs/files/{ca}-signing.jks" keystorePass="atakatak" '
        'validityDays="730" signatureAlg="SHA256WithRSA"/></certificateSigning>\n'
        '<federation><tls keystore="JKS" keystoreFile="certs/files/takserver.jks" keystorePass="atakatak" '
        'truststore="JKS" truststoreFile="certs/files/fed-truststore.jks" truststorePass="atakatak"/></federation>\n'
        '</Configuration>\n')


def _make_ca_files(files, name, signing=True):
    """What an earlier makeCert.sh ca NAME left in the folder."""
    for ext in ('.pem', '.key', '.csr', '.crl', '-trusted.pem'):
        (files / f'{name}{ext}').write_text('x')
    if signing:
        for f in (f'{name}-signing.jks', f'{name}-signing.p12', f'truststore-{name}.jks', f'truststore-{name}.p12'):
            (files / f).write_text('x')


def _self_signed(files, name, stem):
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(files / f'{stem}.key'),
                    '-out', str(files / f'{stem}.pem'), '-subj', f'/CN={name}', '-days', '3'],
                   check=True, capture_output=True)


class Box:
    """A box whose working CA is INT-CA-B2 (rotated B1 then B2 before), root in root-ca.pem."""

    def __init__(self, tmp_path):
        self.tak = tmp_path          # stands in for /opt/tak
        self.certs = tmp_path / 'certs'
        self.files = self.certs / 'files'
        self.files.mkdir(parents=True)
        # ops #986: Step 6 reads CoreConfig.xml back and fails when it names another CA
        (self.tak / 'CoreConfig.xml').write_text(coreconfig_naming('INT-CA-B2'))
        (self.tak / 'CoreConfig.example.xml').write_text(coreconfig_naming('INT-CA-B2'))
        (self.certs / 'makeCert.sh').write_text(FAKE_MAKECERT)
        os.chmod(self.certs / 'makeCert.sh', 0o755)
        _self_signed(self.files, 'ROOT-CA-01', 'root-ca')
        (self.files / 'root-ca-do-not-share.key').write_text('rootkey')
        (self.files / 'root-ca-trusted.pem').write_text('roottrusted')
        for older in ('INT-CA-B1', 'INT-CA-B2'):
            _make_ca_files(self.files, older)
            _self_signed(self.files, older, older)
        for f in ('pem', 'key'):   # B2 is the working CA
            (self.files / ('ca.' + f if f == 'pem' else 'ca-do-not-share.key')).write_bytes(
                (self.files / f'INT-CA-B2.{f}').read_bytes())
        (self.files / 'ca-trusted.pem').write_text('b2trusted')
        self.steps_after_ca = []     # what the rotation did after Step 2
        self.build()

    def build(self):
        steps = self.steps_after_ca
        certs = self.certs
        ns = {
            'os': os, 're': re, 'subprocess': subprocess, 'threading': threading, 'shlex': shlex,
            'jsonify': flask.jsonify, 'request': flask.request, 'login_required': lambda f: f,
            'time': types.SimpleNamespace(sleep=lambda s: None, time=_time.time),
            '_CERT_FILES_DIR': str(self.files),
            '_CA_NAME_RE': re.compile(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$'),
            'CA_ROTATION_WINDOW_DAYS': 30,
            'rotate_intca_log': [], 'rotate_intca_status': {'running': False, 'complete': False, 'error': False},
            'mod_registry': types.SimpleNamespace(_check_admin_password=lambda *a, **k: None),
            'load_auth': lambda: {}, 'verify_password': lambda *a, **k: True,
            'load_settings': lambda: {}, 'save_settings': lambda s: None,
            '_get_tak_cert_password': lambda s: 'atakatak',
            '_tak_cert_job_busy': lambda: False,
            '_read_priv': lambda p: open(self._real(p)).read(),
            '_write_priv': lambda p, t: open(self._real(p), 'w').write(t),
            # the box's own commands, run in the scratch folder; the TAK account's chown/chmod are no-ops
            '_rotate_tak_cert_cmd': lambda cmd: ('true' if 'chown tak:tak' in cmd or 'systemctl' in cmd else
                                                 cmd.replace('runuser -u tak -- ', '')
                                                    .replace('/opt/tak/certs', str(certs))),
            # steps after the CA is made: record that they ran, succeed
            '_patch_openssl_string_mask': lambda *a, **k: None,
            '_patch_cert_metadata_password': lambda *a, **k: None,
            '_tak_ca_private_lockdown': lambda *a, **k: steps.append('lockdown'),
            '_tak_server_cert_signer_or_default': lambda d: 'intermediate',
            '_tak_server_cert_issue': lambda *a, **k: steps.append('server-cert') or True,
            '_rotate_client_cert_names': lambda *a, **k: [],
            '_rotate_reissue_cert': lambda *a, **k: True,
            '_rotate_tak_live_certs_by_issuer': lambda: {},
            '_rotate_carry_forward_truststore': lambda *a, **k: None,
            '_rotate_sh': lambda *a, **k: None,
            '_tak_root_signed_dependents': lambda *a, **k: ([], 0),
            '_tak_truststore_drop_roots': lambda *a, **k: None,
            '_coreconfig_clamp_issued_validity': lambda t, d: (t, None),
            '_patch_coreconfig_passwords': lambda *a, **k: None,
            '_takportal_sync_certs': lambda **k: (True, 'ok'),
            '_sanitize_coreconfig_name_entries': lambda: (False, ''),
            '_resync_ldap_credential_to_coreconfig': lambda: (False, ''),
            '_rotate_refresh_integrations': lambda log: None,
            '_ca_rotation_state_save': lambda s: steps.append('state-saved'),
            '_ca_rotation_day0_text': lambda *a, **k: 'notice',
            '_ca_rotation_date': lambda t: 'date',
            '_ca_rotation_send': lambda *a, **k: {'sent': False, 'message': 'not sent'},
        }
        for name in ('_validate_ca_name', '_pem_cn_and_expiry', '_ca_name_in_cert_folder', '_tak_working_ca_cn',
                     '_rotate_coreconfig_truststore', '_coreconfig_signing_ca', '_coreconfig_truststore_ca',
                     '_coreconfig_point_at_ca', '_coreconfig_ca_mismatch'):
            src = _func(name, required=name in ('_validate_ca_name', '_pem_cn_and_expiry',
                                                '_rotate_coreconfig_truststore'))
            if src:   # a fix that adds these on top of an older app.py has them; the base does not
                exec(compile(src, 'app.py', 'exec'), ns)
        ns['datetime'] = __import__('datetime').datetime
        ns['html'] = __import__('html')
        src = _func('takserver_rotate_intca').replace("'/opt/tak/certs/files'", '_CERT_FILES_DIR')
        exec(compile(src, 'app.py', 'exec'), ns)
        self.ns = ns
        # the route pipes through `cd /opt/tak/certs && echo y | ... makeCert.sh`: point it at the stand-in
        env = dict(os.environ, CERTS_DIR=str(self.certs))
        real_run = subprocess.run
        ns['subprocess'] = types.SimpleNamespace(
            run=lambda *a, **k: real_run(*a, **dict(k, env=env)) if k.get('shell') else real_run(*a, **k),
            TimeoutExpired=subprocess.TimeoutExpired)
        app = flask.Flask('ops942')
        app.add_url_rule('/rotate', view_func=ns['takserver_rotate_intca'], methods=['POST'])
        self.client = app.test_client()

    def _real(self, path):
        """/opt/tak/... on the box is under tmp_path here."""
        return str(self.tak / path[len('/opt/tak/'):]) if path.startswith('/opt/tak/') else path

    def corecfg(self):
        return (self.tak / 'CoreConfig.xml').read_text()

    def rotate(self, name):
        r = self.client.post('/rotate', json={'new_ca_name': name, 'password': PASSWORD})
        done = None
        if r.status_code == 200:
            deadline = _time.time() + 60
            while _time.time() < deadline:
                st = self.ns['rotate_intca_status']
                if not st['running'] and st['complete']:
                    done = dict(st)
                    break
                _time.sleep(0.1)
        return r, done

    def working_ca(self):
        r = subprocess.run(['openssl', 'x509', '-noout', '-subject', '-in', str(self.files / 'ca.pem')],
                           capture_output=True, text=True)
        return re.search(r'CN\s*=\s*([^,/\n]+)', r.stdout).group(1).strip()


@pytest.fixture
def box(tmp_path):
    return Box(tmp_path)


def _log(box):
    return '\n'.join(box.ns['rotate_intca_log'])


# ── the bug, as the admin met it ─────────────────────────────────────────────────────────────

def test_a_name_with_files_in_the_folder_never_ends_complete_with_root_as_the_working_ca(box):
    """Rotate to INT-CA-B1 again (B1 then B2 were rotated before): the exact steps of the report."""
    assert box.working_ca() == 'INT-CA-B2'
    r, done = box.rotate('INT-CA-B1')
    if r.status_code == 200:
        # it was accepted, so it must either be done for real or say it failed: never both complete and wrong
        assert done is not None, 'the rotation never finished'
        reads_complete = done['complete'] and not done['error']
        assert not (reads_complete and box.working_ca() != 'INT-CA-B1'), (
            f'ROTATION COMPLETE, error={done["error"]}, but ca.pem is {box.working_ca()}')
    else:
        assert r.status_code == 400


def test_the_name_is_refused_up_front_and_nothing_changes(box):
    before = {p.name: p.read_bytes() for p in box.files.iterdir()}
    r, done = box.rotate('INT-CA-B1')
    assert r.status_code == 400, f'HTTP {r.status_code}: {r.get_data(as_text=True)[:200]}'
    msg = r.get_json()['error']
    assert 'INT-CA-B1' in msg and 'already' in msg and 'choose another' in msg.lower()
    assert {p.name: p.read_bytes() for p in box.files.iterdir()} == before, 'a refused name must change no file'
    assert box.steps_after_ca == []
    assert box.ns['rotate_intca_status']['running'] is False


@pytest.mark.parametrize('name', ['int-ca-b1', 'admin', 'takserver', 'root-ca', 'ca', 'user'])
def test_names_that_belong_to_other_files_are_refused_too(box, name):
    for n in ('admin', 'user', 'takserver'):
        for ext in ('.pem', '.key', '.p12', '.jks'):
            (box.files / f'{n}{ext}').write_text('x')
    (box.files / 'ca.crl').write_text('x')
    r, _ = box.rotate(name)
    assert r.status_code == 400, f'{name}: HTTP {r.status_code}'
    assert 'already in the certificate folder' in r.get_json()['error']


def test_a_new_name_still_rotates_and_becomes_the_working_ca(box):
    r, done = box.rotate('INT-CA-B3')
    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert done and done['complete'] and not done['error'], _log(box)
    assert box.working_ca() == 'INT-CA-B3'
    assert 'ROTATION COMPLETE' in _log(box)


# ── the second line of defence: a stop that makes no noise ────────────────────────────────────

def test_a_makecert_that_leaves_root_as_the_working_ca_fails_the_rotation(box):
    """Even if the name check misses a case, makeCert.sh exits 0 with ca.pem still on the root."""
    box.ns['_ca_name_in_cert_folder'] = lambda d, n: []
    r, done = box.rotate('INT-CA-B1')
    assert r.status_code == 200
    assert done is not None
    assert done['error'] is True, f'read complete with ca.pem = {box.working_ca()}\n' + _log(box)
    log = _log(box)
    assert 'ROTATION COMPLETE' not in log and 'ROTATION FAILED' in log
    assert 'ROOT-CA-01' in log and 'INT-CA-B1' in log, 'the failure must name both CAs'
    assert box.steps_after_ca == [], f'steps after Step 2 still ran: {box.steps_after_ca}'


def test_the_check_reads_the_file_not_the_exit_status(box):
    """An unreadable ca.pem after makeCert.sh is a failure, not a pass."""
    box.ns['_ca_name_in_cert_folder'] = lambda d, n: []
    box.ns['_tak_working_ca_cn'] = lambda d='': ''
    r, done = box.rotate('INT-CA-B7')
    assert done and done['error'] is True and 'unreadable' in _log(box)


# ── the helper ─────────────────────────────────────────────────────────────────────────────────

def _helper():
    ns = {'os': os}
    src = _func('_ca_name_in_cert_folder', required=False)
    if not src:
        pytest.fail('_ca_name_in_cert_folder does not exist')
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns['_ca_name_in_cert_folder']


def test_helper_lists_the_files_that_carry_the_name(tmp_path):
    _make_ca_files(tmp_path, 'INT-CA-01')
    (tmp_path / 'unrelated.pem').write_text('x')
    got = _helper()(str(tmp_path), 'INT-CA-01')
    assert 'INT-CA-01.pem' in got and 'INT-CA-01-signing.jks' in got and 'truststore-INT-CA-01.jks' in got
    assert 'unrelated.pem' not in got


def test_helper_ignores_case_and_a_free_name_and_a_missing_folder(tmp_path):
    _make_ca_files(tmp_path, 'INT-CA-01')
    assert _helper()(str(tmp_path), 'int-ca-01')
    assert _helper()(str(tmp_path), 'INT-CA-02') == []
    assert _helper()(str(tmp_path / 'nope'), 'INT-CA-01') == []


def test_a_name_that_only_prefixes_another_is_free(tmp_path):
    _make_ca_files(tmp_path, 'INT-CA-01')
    assert _helper()(str(tmp_path), 'INT-CA-0') == []
    assert _helper()(str(tmp_path), 'INT-CA-011') == []
