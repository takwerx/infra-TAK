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
"""Federation Hub Rotate CA works when the hub already has certificates (ops #865).

The vendor's makeRootCa.sh stops with "ca.pem file already exists!  Please delete it before
trying again" when certs/files/ca.pem exists. run_fedhub_remote_rotate_ca never moved the old
files, so a hub that already had certificates (every deployed hub) could not rotate: the log said
"Certificate rotation failed" and the old CA stayed.

This test runs the real run_fedhub_remote_rotate_ca against a folder that stands in for
/opt/tak/federation-hub. The two cert scripts are stand-ins that keep the vendor's own guard
verbatim (read from TAK Server's makeRootCa.sh / makeCert.sh on a fleet box, Nov 16 2026) and
create small files instead of keys. The licensed Federation Hub package is not used; that its
certs folder holds the same scripts is Assumed (the vendor guide names the same two scripts).
"""

import ast
import os
import pathlib
import re
import shlex
import stat
import subprocess
import tempfile
from datetime import datetime

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='runs shell scripts')

MAKE_ROOT_CA = r'''#!/bin/bash
. cert-metadata.sh
mkdir -p "$DIR"
cd "$DIR"
if [ -e ca.pem ]; then
  echo "ca.pem file already exists!  Please delete it before trying again"
  exit -1
fi
CA_NAME=""
for (( i=1; i <= "$#"; i++ )); do
  if [ "${!i}" == "--ca-name" ];then
    NEXT_VAL=$(($i + 1))
    CA_NAME=${!NEXT_VAL}
  fi
done
echo "root $CA_NAME" > ca.pem
echo "key $CA_NAME" > ca-do-not-share.key
echo "root $CA_NAME" > root-ca.pem
echo "store $CA_NAME" > truststore-root.jks
'''

MAKE_CERT = r'''#!/bin/bash
. cert-metadata.sh
mkdir -p "$DIR"
cd "$DIR"
if [ ! -e ca.pem ]; then
  echo "ca.pem does not exist!  Please make a CA before trying to make server certficiates"
  exit -1
fi
if [ "$1" == "server" ] && [ -e ../fail-server ]; then
  echo "server cert failed on purpose"
  exit 1
fi
SNAME=$2
if [ "$1" == "ca" ]; then
  read MVREQ
  echo "int $SNAME" > "$SNAME.pem"
  echo "int-key $SNAME" > "$SNAME.key"
  echo "truststore $SNAME" > "truststore-$SNAME.jks"
  echo "$SNAME-signing" > "$SNAME-signing.jks"
  if [ "$MVREQ" == "y" ]; then
    cp "$SNAME.pem" ca.pem
    cp "$SNAME.key" ca-do-not-share.key
  fi
else
  echo "$1 $SNAME" > "$SNAME.pem"
  echo "$1 $SNAME" > "$SNAME.jks"
  echo "$1 $SNAME" > "$SNAME.p12"
fi
'''

CERT_METADATA = 'DIR=files\nCAPASS=atakatak\nPASS=atakatak\nCOUNTRY=US\nSTATE=ST\nCITY=CT\nORGANIZATION=O\nORGANIZATIONAL_UNIT=OU\n'

FAKE_SUDO = '''#!/bin/bash
# stands in for sudo: drops "-u USER", skips chown (no tak account here), runs the rest as is
if [ "$1" == "-u" ]; then shift; shift; fi
if [ "$1" == "chown" ]; then exit 0; fi
exec "$@"
'''


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _write(path, text, mode=0o644):
    path.write_text(text, encoding='utf-8')
    path.chmod(mode)


class Hub:
    """A folder standing in for /opt/tak/federation-hub plus a runner for the real rotate function."""

    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.fh = self.root / 'federation-hub'
        self.certs = self.fh / 'certs'
        self.files = self.certs / 'files'
        self.bin = self.root / 'bin'
        for d in (self.certs, self.fh / 'configs', self.fh / 'jars', self.bin):
            d.mkdir(parents=True, exist_ok=True)
        _write(self.certs / 'makeRootCa.sh', MAKE_ROOT_CA, 0o755)
        _write(self.certs / 'makeCert.sh', MAKE_CERT, 0o755)
        _write(self.certs / 'cert-metadata.sh', CERT_METADATA)
        _write(self.bin / 'sudo', FAKE_SUDO, 0o755)
        _write(self.bin / 'systemctl', '#!/bin/bash\n[ "$1" == "is-active" ] && echo active\nexit 0\n', 0o755)
        _write(self.bin / 'java', '#!/bin/bash\nexit 0\n', 0o755)
        _write(self.fh / 'configs' / 'federation-hub-broker.yml', 'keystore: certs/files/takserver.jks\n')
        _write(self.fh / 'configs' / 'federation-hub-ui.yml', 'truststore: certs/files/truststore-x.jks\n')
        self.settings = {}
        self.log = []
        self.status = {'running': True, 'complete': False, 'error': False}

    def deploy_certs(self, root='FEDHUB-ROOT-CA', inter='FEDHUB-INT-CA'):
        """What the deploy step does: root CA, intermediate (answer y), server and client certs."""
        env = dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}')
        steps = [
            f'./makeRootCa.sh --ca-name {root}',
            f'echo y | ./makeCert.sh ca {inter}',
            './makeCert.sh server fedhub',
            'echo y | ./makeCert.sh client webadmin-fed',
        ]
        for s in steps:
            r = subprocess.run(['bash', '-c', s], cwd=self.certs, env=env, capture_output=True, text=True)
            assert r.returncode == 0, (s, r.stdout, r.stderr)

    def _module_run(self, cfg, cmd, timeout=120, log_fn=None):
        env = dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}')
        r = subprocess.run(['bash', '-c', cmd], env=env, capture_output=True, text=True, timeout=60)
        return r.returncode == 0, (r.stdout or '') + (r.stderr or '')

    def rotate(self, remote=False):
        src = _func('run_fedhub_remote_rotate_ca').replace(
            "fh_dir = '/opt/tak/federation-hub'", f'fh_dir = {str(self.fh)!r}')
        assert str(self.fh) in src
        ns = {
            're': re, 'shlex': shlex, 'datetime': datetime,
            'fedhub_rotate_log': self.log, 'fedhub_rotate_status': self.status,
            'load_settings': lambda: self.settings, 'save_settings': lambda s: self.settings.update(s),
            '_get_fedhub_deployment_config': lambda s: (
                {'deployed': True, 'target_mode': 'remote', 'remote': {'host': 'hub.example'}} if remote
                else {'deployed': True, 'target_mode': 'local', 'remote': {}}),
            '_module_run': self._module_run,
            '_get_fedhub_cert_password': lambda s: 'atakatak',
            '_fedhub_cert_dn': lambda s: {'country': 'US', 'state': 'ST', 'city': 'CT', 'org': 'O', 'ou': 'OU'},
            '_fedhub_ca_lockdown': lambda *a, **k: None,
        }
        for node in TREE.body:  # gh #666: the sudo-refusal pattern the function uses
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == '_FEDHUB_SUDO_REFUSED_RE' for t in node.targets):
                exec(ast.get_source_segment(APP, node), ns)
        for name in ('_fedhub_next_numbered_ca_name', '_fedhub_rotate_stash_cmd', '_fedhub_rotate_unstash_cmd',
                     '_fedhub_sudo_refused', '_fedhub_sudo_refusal_lines'):
            try:
                exec(_func(name), ns)
            except AssertionError:
                pass  # the base code has no such helpers
        exec(src, ns)
        self.status.update({'running': True, 'complete': False, 'error': False})
        ns['run_fedhub_remote_rotate_ca']()

    def text(self, name):
        return (self.files / name).read_text(encoding='utf-8').strip()

    def stashed(self):
        return sorted((self.certs / 'backups').glob('pre-rotate-*-files'))


@pytest.fixture()
def hub():
    with tempfile.TemporaryDirectory() as d:
        yield Hub(d)


def test_second_rotation_on_a_hub_with_certificates_completes(hub):
    hub.deploy_certs()
    assert hub.text('ca.pem') == 'int FEDHUB-INT-CA'
    hub.rotate()
    assert hub.status['error'] is False, '\n'.join(hub.log)
    assert hub.status['complete'] is True
    assert hub.text('ca.pem') == 'int FEDHUB-INT-CA-01'
    assert hub.text('root-ca.pem') == 'root FEDHUB-ROOT-CA-01'
    # and once more straight after: the case the issue is about
    hub.rotate()
    assert hub.status['error'] is False, '\n'.join(hub.log)
    assert hub.text('ca.pem') == 'int FEDHUB-INT-CA-02'
    assert 'already exists' not in '\n'.join(hub.log)


def test_old_certificate_files_are_kept_in_the_backup_folder(hub):
    hub.deploy_certs()
    hub.rotate()
    kept = hub.stashed()
    assert len(kept) == 1, '\n'.join(hub.log)
    assert (kept[0] / 'ca.pem').read_text().strip() == 'int FEDHUB-INT-CA'
    assert (kept[0] / 'root-ca.pem').read_text().strip() == 'root FEDHUB-ROOT-CA'
    assert (kept[0] / 'FEDHUB-INT-CA-signing.jks').exists()
    # the new folder holds only the new set
    assert not (hub.files / 'FEDHUB-INT-CA-signing.jks').exists()
    assert (hub.files / 'FEDHUB-INT-CA-01-signing.jks').exists()


def test_backup_folder_is_root_only_and_certs_folder_keeps_its_mode(hub):
    hub.deploy_certs()
    hub.files.chmod(0o750)
    hub.rotate()
    assert stat.S_IMODE((hub.certs / 'backups').stat().st_mode) == 0o700
    assert stat.S_IMODE(hub.files.stat().st_mode) == 0o750


def test_failed_rotation_puts_the_old_certificates_back(hub):
    hub.deploy_certs()
    before = {p.name: p.read_text() for p in hub.files.iterdir()}
    (hub.certs / 'fail-server').write_text('x')  # makeCert.sh server looks for ../fail-server from files/
    hub.rotate()
    assert hub.status['error'] is True
    after = {p.name: p.read_text() for p in hub.files.iterdir()}
    assert after == before, 'old files must be back exactly as they were'
    assert hub.stashed() == []
    assert 'put back' in '\n'.join(hub.log)


def test_first_rotation_on_an_empty_certificate_folder_still_works(hub):
    hub.rotate()
    assert hub.status['error'] is False, '\n'.join(hub.log)
    assert hub.text('ca.pem') == 'int FEDHUB-INT-CA-01'
    assert hub.stashed() == []


def test_stash_runs_before_the_cert_scripts_in_the_function():
    src = _func('run_fedhub_remote_rotate_ca')
    assert src.index('_fedhub_rotate_stash_cmd(') < src.index('makeRootCa.sh')
    assert src.index('makeRootCa.sh') < src.index('_fedhub_rotate_unstash_cmd(')


def _ui_yml(hub):
    return (hub.fh / 'configs' / 'federation-hub-ui.yml').read_text(encoding='utf-8')


def test_ui_truststore_name_keeps_its_jks_after_each_rotation(hub):
    # Box test (Nov 17 2026): the old pattern turned truststore-X.jks into truststore-Y, no extension, so the hub
    # UI config named a file that does not exist after the first Rotate CA.
    hub.deploy_certs()
    hub.rotate()
    assert 'truststore: certs/files/truststore-FEDHUB-INT-CA-01.jks\n' == _ui_yml(hub), _ui_yml(hub)
    assert (hub.files / 'truststore-FEDHUB-INT-CA-01.jks').exists()
    hub.rotate()
    assert 'truststore: certs/files/truststore-FEDHUB-INT-CA-02.jks\n' == _ui_yml(hub), _ui_yml(hub)


def test_ui_truststore_name_left_without_jks_by_an_older_rotation_is_repaired(hub):
    _write(hub.fh / 'configs' / 'federation-hub-ui.yml', 'truststore: certs/files/truststore-FEDHUB-INT-CA-01\nother: 1\n')
    hub.rotate()
    assert _ui_yml(hub) == 'truststore: certs/files/truststore-FEDHUB-INT-CA-01.jks\nother: 1\n', _ui_yml(hub)
