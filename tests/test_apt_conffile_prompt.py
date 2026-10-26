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
"""apt installs never stop at dpkg's conffile prompt (found by TEST-MATRIX-v10.3.0 row 5).

The console wrote /etc/caddy/Caddyfile, then `apt-get install -y caddy` died at
"end of file on stdin at conffile prompt" and left caddy half-configured (iU).
DEBIAN_FRONTEND=noninteractive does not answer that prompt; DPKG_FORCE does.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
BROKER = (REPO / 'broker' / 'takwerx_broker.py').read_text(encoding='utf-8')


def test_pkg_install_keeps_existing_conffiles_on_root_boxes():
    body = re.search(r'^def _pkg_install\(.*?(?=^def )', APP, re.S | re.M).group(0)
    assert "DPKG_FORCE='confdef,confold'" in body


def test_broker_keeps_existing_conffiles_for_apt_and_only_apt():
    i = BROKER.index("if os.path.basename(argv[0]) in ('apt', 'apt-get'):\n        env = dict(os.environ)")
    block = BROKER[i:BROKER.index('proc = subprocess.run(argv', i)]
    assert "env.setdefault('DPKG_FORCE', 'confdef,confold')" in block


def test_broker_still_denies_dpkg_options_on_the_command_line():
    assert "raise Denied(f'{argv[0]}: -o/--setopt option not allowed')" in BROKER


# --- remote SSH user can run docker (same row-5 finding class: a test-box shape no fleet box has) ---
def test_remote_deploys_join_the_ssh_user_to_docker():
    assert APP.count('_remote_docker_group(deploy_cfg, plog)') == 3     # webodm, nodered, authentik
    assert '+ _REMOTE_DOCKER_GROUP_SH + "; "' in APP                    # cloudtak step 2


def test_docker_group_snippet_is_noop_for_root_and_never_prompts():
    sh = APP[APP.index('_REMOTE_DOCKER_GROUP_SH = ('):APP.index('\n)\n', APP.index('_REMOTE_DOCKER_GROUP_SH = ('))]
    assert '[ "$(id -u)" = 0 ] ||' in sh and 'sudo -n usermod -aG docker' in sh


# --- remote MediaMTX checksum line matching (shipped broken in v10.1.34, found by row 5) ---
def test_remote_mediamtx_checksum_grep_matches_upstream_binary_mode_lines(tmp_path):
    import shutil
    import subprocess
    tarball = 'mediamtx_v1.21.1_linux_amd64.tar.gz'
    src = APP[APP.index('def _run_mediamtx_deploy_remote('):]
    line = re.search(r"f'(grep -E [^']*checksums\.sha256)", src).group(1)
    cmd = eval("f'" + line + "'", {'re': re, 'tarball': tarball})
    # upstream's real format (v1.17 .. v1.21): '<hash> *<file>' — plus the text-mode form
    (tmp_path / 'checksums.sha256').write_text(
        'be40' + '0' * 60 + ' *mediamtx_v1.21.1_darwin_amd64.tar.gz\n'
        '653a' + '0' * 60 + ' *' + tarball + '\n'
        '1111' + '0' * 60 + ' *' + tarball + '.sig\n')
    if not shutil.which('bash'):
        return
    out = subprocess.run(['bash', '-c', cmd], cwd=tmp_path, capture_output=True, text=True).stdout
    assert out.splitlines() == ['653a' + '0' * 60 + ' *' + tarball]
    (tmp_path / 'checksums.sha256').write_text('653a' + '0' * 60 + '  ' + tarball + '\n')
    out = subprocess.run(['bash', '-c', cmd], cwd=tmp_path, capture_output=True, text=True).stdout
    assert out.strip().endswith(tarball)


# --- remote MediaMTX runs as takwerx: it must be able to read its TLS cert/key (row 5) ---
def test_remote_mediamtx_cert_and_key_are_readable_by_the_service_user_only():
    perms = APP[APP.index('_MEDIAMTX_REMOTE_CERT_PERMS = ('):APP.index('\n)\n', APP.index('_MEDIAMTX_REMOTE_CERT_PERMS = ('))]
    assert 'chown root:takwerx' in perms and 'chmod 640' in perms
    body = APP[APP.index('def _run_mediamtx_deploy_remote('):]
    body = body[:body.index('\ndef ')]
    assert body.count('_MEDIAMTX_REMOTE_CERT_PERMS') == 2          # deploy + renewal sync script
    assert "chmod 600 /etc/mediamtx/certs/stream.key" not in body
