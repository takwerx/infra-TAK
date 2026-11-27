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
"""Federation Hub Update keeps the hub's certificates, its OAuth setting, and copies them aside (ops #1339).

Before: the Update (the full deploy, run again) made the hub's CA anew unless certs/files held
<hostname>.jks. A hub installed by hand keeps the vendor keystore name takserver.jks, a renamed host
keeps its old name: both looked like "no certificates", so makeRootCa.sh, makeCert.sh ca and
makeCert.sh server ran and the hub's CA was replaced (or, when ca.pem was there, the vendor script
stopped the update after the package had already stopped the hub). Update also set allowOauth: true
on every run and took no backup.

These tests run the real _fedhub_run_remote_package_install against a folder that stands in for
/opt/tak (every /opt/tak path in the function is pointed at it). The two certificate scripts keep
the vendor guard (refuse when ca.pem exists, read from TAK Server's scripts, ops #865) and write
small files. apt-get, systemctl, mongod and java are stand-ins. What is NOT covered here: the real
takserver-fed-hub package and a real hub start (the box test does that).
"""

import ast
import os
import pathlib
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import types
from datetime import datetime

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import test_fedhub_rotate_ca_twice_ops865 as base  # noqa: E402

APP = base.APP
TREE = base.TREE

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='runs shell scripts')

# sudo with VAR=value words (apt-get is run as `sudo DEBIAN_FRONTEND=noninteractive apt-get ...`)
SUDO = '''#!/bin/bash
[ "$1" == "-n" ] && shift
if [ "$1" == "-u" ]; then shift; shift; fi
if [ "$1" == "chown" ]; then exit 0; fi
case "$1" in *=*) exec env "$@";; esac
exec "$@"
'''

# macOS sed needs -i '' ; GNU sed must not get it
SED = '''#!/bin/bash
args=()
for a in "$@"; do args+=("$a"); [ "$a" = "-i" ] && args+=(""); done
exec /usr/bin/sed "${args[@]}"
'''


def _funcs():
    out = {}
    for n in ('_fedhub_cert_files_present', '_fedhub_read_state', '_fedhub_backup_cmd',
              '_fedhub_run_remote_package_install', '_fedhub_sudo_refused', '_fedhub_sudo_refusal_lines'):
        try:
            out[n] = base._func(n)
        except AssertionError:
            pass
    return out


def _assigns(*names):
    out = []
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets):
            out.append(ast.get_source_segment(APP, node))
    return out


class Update(base.Hub):
    def __init__(self, root):
        super().__init__(root)
        self.opt = self.root          # stands in for /opt/tak (federation-hub lives in self.fh)
        base._write(self.bin / 'sudo', SUDO, 0o755)
        if sys.platform == 'darwin':
            base._write(self.bin / 'sed', SED, 0o755)
        for n in ('mongod', 'ufw', 'java'):
            base._write(self.bin / n, '#!/bin/bash\nexit 0\n', 0o755)
        base._write(self.bin / 'hostname', '#!/bin/bash\necho fedhub\n', 0o755)
        base._write(self.bin / 'apt-get', f'#!/bin/bash\necho "$@" >> {self.root}/apt.log\nexit 0\n', 0o755)
        base._write(self.bin / 'ss', '#!/bin/bash\necho "LISTEN :9100"\n', 0o755)
        (self.fh / 'logs').mkdir(exist_ok=True)
        (self.fh / 'logs' / 'federation-hub-ui.log').write_text('Started FederationHubUIServer\n')
        (self.fh / 'policies').mkdir(exist_ok=True)
        (self.fh / 'policies' / 'policy.json').write_text('{"groups": 1}\n')
        self.restarts = 0
        self.settings = {'fqdn': 'example.org'}
        self.deployed = True
        self.authentik = True
        self.oauth_calls = 0

    # -- state a customer box can be in -------------------------------------------------------
    def configs(self, keystore='takserver.jks', oauth='false'):
        _ks = f'/opt/tak/federation-hub/certs/files/{keystore}'
        base._write(self.fh / 'configs' / 'federation-hub-broker.yml',
                    f'keystoreType: JKS\nkeystoreFile: {_ks}\n')
        ui = f'keystoreType: JKS\nkeystoreFile: {_ks}\n'
        if oauth is not None:
            ui += f'allowOauth: {oauth}\n'
        base._write(self.fh / 'configs' / 'federation-hub-ui.yml', ui)

    def manual_certs(self, with_ca=True, keystore='takserver.jks'):
        """A hub set up by hand from the vendor guide: files named by the guide, not by the host."""
        self.files.mkdir(parents=True, exist_ok=True)
        (self.files / keystore).write_text('ORIGINAL server keystore\n')
        (self.files / 'truststore-root.jks').write_text('ORIGINAL truststore\n')
        (self.files / 'webadmin.p12').write_text('ORIGINAL admin cert\n')
        if with_ca:
            (self.files / 'ca.pem').write_text('ORIGINAL CA\n')
            (self.files / 'ca-do-not-share.key').write_text('ORIGINAL CA key\n')

    def snapshot(self):
        return {p.name: p.read_text() for p in sorted(self.files.iterdir())} if self.files.exists() else {}

    def make_fake_systemctl(self):
        base._write(self.bin / 'systemctl',
                    f'#!/bin/bash\n[ "$1" == "restart" ] && echo r >> {self.root}/restarts.log\n'
                    f'[ "$1" == "is-active" ] && echo active\nexit 0\n', 0o755)

    def restart_count(self):
        p = self.root / 'restarts.log'
        return len(p.read_text().splitlines()) if p.exists() else 0

    def apt_calls(self):
        p = self.root / 'apt.log'
        return p.read_text().splitlines() if p.exists() else []

    def break_tar_and_cp(self):
        base._write(self.bin / 'cp', '#!/bin/bash\necho "cp: cannot write: No space left on device" >&2\nexit 1\n', 0o755)

    def backups(self):
        d = self.fh / 'backups'
        return sorted(p for p in d.glob('pre-update-*')) if d.exists() else []

    # -- the real function --------------------------------------------------------------------
    def run(self, phase='Update'):
        self.make_fake_systemctl()
        funcs = _funcs()
        src = funcs['_fedhub_run_remote_package_install']
        src = src.replace('/opt/tak', str(self.opt))
        assert str(self.fh) in src
        ns = {
            're': re, 'os': os, 'shlex': shlex, 'datetime': datetime,
            'time': types.SimpleNamespace(sleep=lambda s: None),
            'load_settings': lambda: self.settings,
            'save_settings': lambda s: self.settings.update(s),
            '_get_fedhub_deployment_config': lambda s: {
                'deployed': self.deployed, 'target_mode': 'local', 'remote': {}},
            '_takserver_installed_local': lambda: False,
            '_find_fedhub_deb_in_uploads': lambda: ('takserver-fed-hub_5.8-RELEASE105_all.deb', '/tmp/x.deb'),
            '_fedhub_copy_file': lambda cfg, src, dst, timeout=300: (True, 'ok'),
            '_module_run': self._module_run,
            '_get_fedhub_cert_password': lambda s: 'atakatak',
            '_fedhub_cert_dn': lambda s: {'country': 'US', 'state': 'ST', 'city': 'CT', 'org': 'O', 'ou': 'OU'},
            '_fedhub_ca_lockdown': lambda *a, **k: None,
            '_fedhub_harden_ui_ports': lambda *a, **k: None,
            '_fedhub_caddy_source_ip': lambda s: '',
            '_normalize_module_deployment_config': lambda c: c,
            'detect_modules': lambda fresh=False: {'authentik': {'installed': self.authentik}},
            '_check_authentik_api_reachable': lambda s: (True, ''),
            '_ensure_authentik_fedhub_oauth_app': self._oauth_app,
            '_get_service_domain': lambda s, n: '',
            '_get_authentik_host': lambda s: 'authentik.example.org',
            '_pub_hostport': lambda h: h,
            '_caddy_https_port': lambda s: 443,
            '_get_authentik_env_value': lambda s, k: None,
            '_caddy_regenerate_if_fqdn': lambda: None,
        }
        for seg in _assigns('_FEDHUB_SUDO_REFUSED_RE', '_FEDHUB_KEEP_UPDATE_BACKUPS'):
            exec(seg, ns)
        for n, f in funcs.items():
            if n != '_fedhub_run_remote_package_install':
                exec(f, ns)
        exec(src, ns)
        self.status.update({'running': True, 'complete': False, 'error': False})
        ns['_fedhub_run_remote_package_install'](self.log, self.status, phase_label=phase)

    def _oauth_app(self, settings, plog=None):
        self.oauth_calls += 1
        return 'client-id', 'client-secret', '', ''

    def oauth_value(self):
        m = re.search(r'^allowOauth:\s*(\S+)', (self.fh / 'configs' / 'federation-hub-ui.yml').read_text(), re.M)
        return m.group(1) if m else None


@pytest.fixture()
def hub():
    with tempfile.TemporaryDirectory() as d:
        yield Update(d)


# ---- point 1: certificates ----------------------------------------------------------------------

def test_update_keeps_the_ca_of_a_hub_set_up_by_hand(hub):
    """PROOF: files named by the vendor guide (takserver.jks), no ca.pem. Before the fix the update
    ran makeRootCa.sh and made a new CA and a new webadmin-fed; now nothing in files/ changes."""
    hub.configs()
    hub.manual_certs(with_ca=False)
    before = hub.snapshot()
    hub.run()
    assert hub.status['error'] is False, '\n'.join(hub.log)
    assert hub.snapshot() == before, 'the update must not make or change any certificate file'
    assert not (hub.files / 'ca.pem').exists()
    assert not (hub.files / 'webadmin-fed.pem').exists()


def test_update_of_a_hub_with_a_ca_does_not_end_in_a_certificate_error(hub):
    """PROOF: with ca.pem present the vendor script refuses (ca.pem file already exists!), the old
    update stopped there with the package installed and the hub not restarted."""
    hub.configs()
    hub.manual_certs(with_ca=True)
    before = hub.snapshot()
    hub.run()
    log = '\n'.join(hub.log)
    assert hub.status['error'] is False, log
    assert 'Certificate generation failed' not in log
    assert hub.snapshot() == before
    assert hub.restart_count() >= 1, 'the hub must be restarted so it comes back after the package stopped it'


def test_a_renamed_host_keeps_its_old_keystore(hub):
    hub.configs(keystore='oldhost.jks')
    hub.manual_certs(with_ca=False, keystore='oldhost.jks')
    before = hub.snapshot()
    hub.run()
    assert hub.status['error'] is False, '\n'.join(hub.log)
    assert hub.snapshot() == before


def test_keystore_named_in_the_config_but_missing_is_warned_not_rebuilt(hub):
    hub.configs(keystore='gone.jks')
    hub.manual_certs(with_ca=False, keystore='takserver.jks')
    before = hub.snapshot()
    hub.run()
    log = '\n'.join(hub.log)
    assert hub.snapshot() == before
    assert 'gone.jks' in log and 'Rotate CA' in log, log


def test_fresh_hub_still_gets_its_certificates_made(hub):
    """No hub folder content, no certificates: generation runs as it always did."""
    hub.deployed = False
    (hub.fh / 'configs' / 'federation-hub-broker.yml').unlink()
    (hub.fh / 'configs' / 'federation-hub-ui.yml').unlink()
    hub.run(phase='Deploy')
    assert hub.status['error'] is False, '\n'.join(hub.log)
    assert (hub.files / 'ca.pem').exists()
    assert (hub.files / 'fedhub.jks').exists()
    assert (hub.files / 'webadmin-fed.pem').exists()


def test_hub_with_a_config_but_no_certificates_gets_them_made(hub):
    hub.configs()
    hub.run()
    assert hub.status['error'] is False, '\n'.join(hub.log)
    assert (hub.files / 'ca.pem').exists() and (hub.files / 'fedhub.jks').exists()


def test_unreadable_certs_folder_stops_before_any_change(hub):
    hub.configs()
    hub.manual_certs()
    before = hub.snapshot()
    base._write(hub.bin / 'ls', '#!/bin/bash\ncase "$*" in *certs/files*) echo "ls: cannot open directory: Permission denied" >&2; exit 2;; esac\nexec /bin/ls "$@"\n', 0o755)
    hub.run()
    log = '\n'.join(hub.log)
    assert hub.status['error'] is True and hub.status['complete'] is True
    assert 'Stopped before any change' in log, log
    assert hub.apt_calls() == [], 'the package must not be installed when the hub could not be read'
    assert hub.snapshot() == before
    assert hub.backups() == []


# ---- point 2: OAuth -------------------------------------------------------------------------------

def test_oauth_set_off_by_the_operator_stays_off(hub):
    hub.configs(oauth='false')
    hub.manual_certs()
    hub.run()
    assert hub.status['error'] is False, '\n'.join(hub.log)
    assert hub.oauth_value() == 'false'
    assert hub.oauth_calls == 0, 'no Authentik client may be made for a hub that has OAuth off'
    assert 'left as it was set' in '\n'.join(hub.log)


def test_oauth_on_stays_on_and_is_resynced(hub):
    hub.configs(oauth='true')
    hub.manual_certs()
    hub.run()
    assert hub.status['error'] is False, '\n'.join(hub.log)
    assert hub.oauth_value() == 'true'
    assert hub.oauth_calls == 1


def test_registered_hub_with_no_allowoauth_line_is_left_alone(hub):
    hub.configs(oauth=None)
    hub.manual_certs()
    hub.run()
    assert hub.oauth_calls == 0
    assert hub.oauth_value() is None


def test_first_deploy_still_turns_oauth_on_when_authentik_is_installed(hub):
    hub.deployed = False
    hub.configs(oauth='false')          # the vendor default
    hub.run(phase='Deploy')
    assert hub.status['error'] is False, '\n'.join(hub.log)
    assert hub.oauth_calls == 1
    assert hub.oauth_value() == 'true'


# ---- point 3: backup ------------------------------------------------------------------------------

def test_update_copies_certs_config_and_policies_aside_first(hub):
    hub.configs()
    hub.manual_certs()
    hub.run()
    assert hub.status['error'] is False, '\n'.join(hub.log)
    (b,) = hub.backups()
    assert (b / 'certs' / 'files' / 'takserver.jks').read_text() == 'ORIGINAL server keystore\n'
    assert (b / 'certs' / 'files' / 'ca-do-not-share.key').read_text() == 'ORIGINAL CA key\n'
    assert (b / 'certs' / 'cert-metadata.sh').exists()
    assert (b / 'configs' / 'federation-hub-ui.yml').exists()
    assert (b / 'policies' / 'policy.json').read_text() == '{"groups": 1}\n'
    # copied BEFORE the package ran and before cert-metadata.sh was patched
    assert 'COUNTRY=US' in (b / 'certs' / 'cert-metadata.sh').read_text()
    assert stat.S_IMODE(b.stat().st_mode) == 0o700
    assert stat.S_IMODE((hub.fh / 'backups').stat().st_mode) == 0o700


def test_backup_does_not_copy_old_rotate_ca_sets(hub):
    hub.configs()
    hub.manual_certs()
    (hub.certs / 'backups' / 'pre-rotate-1-files').mkdir(parents=True)
    (hub.certs / 'backups' / 'pre-rotate-1-files' / 'ca.pem').write_text('older\n')
    hub.run()
    (b,) = hub.backups()
    assert not (b / 'certs' / 'backups').exists()


def test_only_the_newest_three_backups_are_kept(hub):
    hub.configs()
    hub.manual_certs()
    for ts in ('20250101-000001', '20250101-000002', '20250101-000003', '20250101-000004'):
        (hub.fh / 'backups' / f'pre-update-{ts}').mkdir(parents=True)
    hub.run()
    names = [p.name for p in hub.backups()]
    assert len(names) == 3, names
    assert 'pre-update-20250101-000001' not in names and 'pre-update-20250101-000002' not in names


def test_failed_backup_stops_the_update_before_the_package_is_installed(hub):
    hub.configs()
    hub.manual_certs()
    before = hub.snapshot()
    hub.break_tar_and_cp()
    hub.run()
    log = '\n'.join(hub.log)
    assert hub.status['error'] is True and hub.status['complete'] is True
    assert 'Could not copy the hub certificates' in log, log
    assert hub.apt_calls() == [], 'no package install after a failed backup'
    assert hub.snapshot() == before


def test_fresh_install_has_nothing_to_back_up_and_does_not_fail(hub):
    import shutil
    hub.deployed = False
    shutil.copytree(hub.fh, hub.root / 'template')      # what the vendor package lays down
    shutil.rmtree(hub.fh)                               # no hub folder at all before the install
    base._write(hub.bin / 'apt-get', (
        f'#!/bin/bash\necho "$@" >> {hub.root}/apt.log\n'
        f'mkdir -p {hub.fh} && cp -R {hub.root}/template/. {hub.fh}/\nexit 0\n'), 0o755)
    hub.run(phase='Deploy')
    assert hub.status['error'] is False, '\n'.join(hub.log)
    assert hub.backups() == []
    assert (hub.files / 'ca.pem').exists()


# ---- the pure helpers ----------------------------------------------------------------------------

def test_cert_file_names_that_count():
    ns = {}
    exec(base._func('_fedhub_cert_files_present'), ns)
    f = ns['_fedhub_cert_files_present']
    assert f([]) == []
    assert f(['takserver.jks']) == ['takserver.jks']
    assert f(['ca.pem']) == ['ca.pem']
    assert f(['WebAdmin.P12']) == ['WebAdmin.P12']
    assert f(['readme.txt', 'notes']) == []


def test_ui_log_shows_what_was_found_and_kept(hub):
    hub.configs()
    hub.manual_certs()
    hub.run()
    log = '\n'.join(hub.log)
    assert 'Certificates found on the hub' in log and 'stay as they are' in log, log
    assert 'saved in' in log and 'pre-update-' in log, log
