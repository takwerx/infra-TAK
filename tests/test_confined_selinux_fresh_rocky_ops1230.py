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
"""A fresh Rocky 9 install gets the confined SELinux console module (ops #1230).

selinux/takwerx_console_confined.te names `container_runtime_exec_t`, a type that
container-selinux defines. On Rocky/RHEL that package comes with Docker, and start.sh
installs Docker AFTER it installs the SELinux modules. So on a fresh box `semodule -i`
failed with "Failed to resolve typeattributeset statement", the failure was sent to
/dev/null, and the console ran in unconfined_service_t on every fresh Rocky install
(4 of 4 fresh-install runs, Nov 24). It was proved in a rockylinux:9 container with
selinux-policy-targeted 38.1.86 and checkpolicy 3.6: the module fails to link without
container-selinux and links the moment the package is there.

This test runs the real `_install_selinux_module`, `_ensure_container_selinux` and
`install_selinux_console_policy` from start.sh under bash, against the real shipped
.te, with fake `semodule`, `checkmodule`, `semodule_package`, `rpm`, `dnf` and
`getenforce`. The fake `semodule -i` refuses any module that names
container_runtime_exec_t while the fake container-selinux package is absent, the way the
real policy store does.
"""

import os
import pathlib
import shutil
import stat
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
START_SH = (REPO / 'start.sh').read_text(encoding='utf-8')
BASH = shutil.which('bash')

pytestmark = pytest.mark.skipif(BASH is None, reason='bash not available')


def _functions():
    """The three SELinux functions of start.sh, as shipped."""
    start = START_SH.index('_install_selinux_module() {')
    end = START_SH.index('# ==========================================\n# Main')
    text = START_SH[start:end]
    # The version stamp lives in /etc/selinux on a real box; the test keeps it in its scratch folder.
    return text.replace('/etc/selinux/.takwerx-', '$STATE/.takwerx-')


FAKE_TOOLS = {
    'getenforce': '#!/bin/bash\necho Enforcing\n',
    # checkmodule -M -m -o OUT TE : "compile" = copy the source
    'checkmodule': '#!/bin/bash\nwhile [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; -M|-m) shift;; *) te="$1"; shift;; esac; done\ncp "$te" "$out"\n',
    # semodule_package -o PP -m MOD
    'semodule_package': '#!/bin/bash\nwhile [ $# -gt 0 ]; do case "$1" in -o) pp="$2"; shift 2;; -m) mod="$2"; shift 2;; *) shift;; esac; done\ncp "$mod" "$pp"\n',
    'semodule': (
        '#!/bin/bash\n'
        'case "$1" in\n'
        '  -l) cat "$STATE/modules" 2>/dev/null; exit 0;;\n'
        '  -i) pp="$2"; name=$(basename "$pp" .pp)\n'
        '      if grep -q "container_runtime_exec_t" "$pp" && [ ! -e "$STATE/container-selinux" ]; then\n'
        '          echo "Failed to resolve typeattributeset statement at /var/lib/selinux/targeted/tmp/modules/400/$name/cil:28"\n'
        '          echo "Failed to resolve AST"; echo "semodule:  Failed!"; exit 1\n'
        '      fi\n'
        '      echo "$name" >> "$STATE/modules"; exit 0;;\n'
        'esac\n'
    ),
    'rpm': '#!/bin/bash\n[ "$1 $2" = "-q container-selinux" ] && [ -e "$STATE/container-selinux" ]\n',
    'dnf': (
        '#!/bin/bash\n'
        'echo "dnf $*" >> "$STATE/dnf.log"\n'
        '[ "${DNF_FAIL:-0}" = 1 ] && exit 1\n'
        'case "$*" in *container-selinux*) touch "$STATE/container-selinux";; esac\n'
        'exit 0\n'
    ),
}


def _run(tmp_path, *, pkg_mgr='dnf', born_nonroot='1', container_selinux=False, dnf_fail=False):
    state = tmp_path / 'state'
    stubs = tmp_path / 'bin'
    install = tmp_path / 'infratak'
    for d in (state, stubs, install / 'selinux'):
        d.mkdir(parents=True, exist_ok=True)
    for name, body in FAKE_TOOLS.items():
        p = stubs / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    for te in ('takwerx_console.te', 'takwerx_console_confined.te'):
        shutil.copy(REPO / 'selinux' / te, install / 'selinux' / te)
    if container_selinux:
        (state / 'container-selinux').touch()
    script = tmp_path / 'run.sh'
    script.write_text(
        'YELLOW=""; GREEN=""; NC=""\n'
        f'PKG_MGR={pkg_mgr}\nBORN_NONROOT={born_nonroot}\nINSTALL_DIR="{install}"\n'
        + _functions()
        + '\ninstall_selinux_console_policy\n'
        'echo "CONFINED_POLICY_OK=$CONFINED_POLICY_OK"\n'
    )
    env = dict(os.environ, PATH=f'{stubs}:{os.environ["PATH"]}', STATE=str(state),
               DNF_FAIL='1' if dnf_fail else '0')
    r = subprocess.run([BASH, str(script)], env=env, capture_output=True, text=True, timeout=60)
    out = r.stdout + r.stderr
    modules = (state / 'modules').read_text().split() if (state / 'modules').exists() else []
    dnf_log = (state / 'dnf.log').read_text() if (state / 'dnf.log').exists() else ''
    return out, modules, dnf_log, state


def test_shipped_module_really_needs_container_selinux():
    """The fix is only needed because the .te names a container-selinux type. If that
    ever stops being true, this test says so and the package install can go."""
    te = (REPO / 'selinux' / 'takwerx_console_confined.te').read_text()
    assert 'type container_runtime_exec_t;' in te


def test_fresh_rocky_without_docker_installs_the_confined_module(tmp_path):
    """Proof test (ops #1230): Docker (container-selinux) is not on the box yet, as on a
    fresh install. The confined module must still go in and the unit must get it."""
    out, modules, dnf_log, state = _run(tmp_path, container_selinux=False)
    assert 'CONFINED_POLICY_OK=1' in out, out
    assert 'takwerx_console_confined' in modules, (modules, out)
    assert 'confined console domain installed' in out
    assert 'install container-selinux' in dnf_log
    assert (state / '.takwerx-takwerx_console_confined.ver').exists()   # the stamp the broker reads


def test_when_the_package_cannot_be_installed_the_reason_is_printed(tmp_path):
    """No silent fallback: if the module cannot link, the install output says why."""
    out, modules, _, _ = _run(tmp_path, container_selinux=False, dnf_fail=True)
    assert 'CONFINED_POLICY_OK=0' in out, out
    assert 'takwerx_console_confined' not in modules
    assert 'Failed to resolve typeattributeset statement' in out      # semodule's own words
    assert 'container-selinux is not installed' in out
    assert 'was not installed' in out and 'unconfined_service_t' in out
    assert 'takwerx_console' in modules                               # the first module is unaffected


def test_box_that_already_has_the_package_does_not_run_dnf(tmp_path):
    out, modules, dnf_log, _ = _run(tmp_path, container_selinux=True)
    assert 'CONFINED_POLICY_OK=1' in out, out
    assert dnf_log == ''


def test_root_install_does_not_install_the_confined_module_or_the_package(tmp_path):
    out, modules, dnf_log, _ = _run(tmp_path, born_nonroot='0')
    assert 'CONFINED_POLICY_OK=0' in out
    assert 'takwerx_console_confined' not in modules
    assert 'container-selinux' not in dnf_log


def test_apt_host_never_asks_for_the_rpm_package(tmp_path):
    """Ubuntu has no getenforce, but if a host does report SELinux the dnf-only step stays out."""
    out, _, dnf_log, _ = _run(tmp_path, pkg_mgr='apt', container_selinux=True)
    assert dnf_log == ''
    assert 'CONFINED_POLICY_OK=1' in out


def test_package_install_comes_before_the_module_in_start_sh():
    """The order is the fix: container-selinux first, then the confined module."""
    body = START_SH[START_SH.index('install_selinux_console_policy() {'):]
    assert body.index('_ensure_container_selinux') < body.index('_install_selinux_module takwerx_console_confined')
