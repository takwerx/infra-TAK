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
"""Federation Hub certificate steps do not probe `sudo -n true` (GitHub issue #666).

The old pre-flight ran `sudo -n true` on the Federation Hub host and read the answer as "this
account has passwordless sudo". It answers only "may this account run /usr/bin/true as root without
a password". An account whose sudoers list the real commands (and not `true`) failed the probe, the
step stopped, and the log told the admin to grant `NOPASSWD: ALL`. Each refused probe also made
sudo mail a "password required" notice to root.

Now the first privileged step is the check. These tests run the real run_fedhub_remote_rotate_ca
as a REMOTE hub (target_mode remote), with a stand-in `sudo` that follows a command-scoped policy:
it refuses `true` and allows what the steps really run.
"""

import ast
import os
import re

import pytest

import test_fedhub_rotate_ca_twice_ops865 as base

APP = base.APP
TREE = base.TREE

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='runs shell scripts')

# `true` is not granted; everything else is. NONE means the account has no passwordless sudo at all.
SCOPED_SUDO = '''#!/bin/bash
# stands in for sudo under a command-scoped sudoers: -n accepted, `true` refused, the rest runs
echo "$@" >> "$(dirname "$0")/sudo-calls.log"
if [ -e "$(dirname "$0")/NONE" ]; then echo "sudo: a password is required" >&2; exit 1; fi
[ "$1" == "-n" ] && shift
if [ "$1" == "true" ] || [ "$1" == "/usr/bin/true" ]; then echo "sudo: a password is required" >&2; exit 1; fi
if [ "$1" == "-u" ]; then shift; shift; fi
if [ "$1" == "chown" ]; then exit 0; fi
exec "$@"
'''


def _assign(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            return ast.get_source_segment(APP, n)
    return None


class RemoteHub(base.Hub):
    def __init__(self, root):
        super().__init__(root)
        base._write(self.bin / 'sudo', SCOPED_SUDO, 0o755)

    def no_sudo_at_all(self):
        (self.bin / 'NONE').write_text('x')

    def sudo_calls(self):
        p = self.bin / 'sudo-calls.log'
        return p.read_text().splitlines() if p.exists() else []

    def rotate_remote(self):
        self.rotate(remote=True)


@pytest.fixture()
def hub():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        yield RemoteHub(d)


def test_rotate_on_a_remote_hub_runs_when_sudo_allows_the_real_commands_but_not_true(hub):
    hub.deploy_certs()
    hub.rotate_remote()
    log = '\n'.join(hub.log)
    assert hub.status['error'] is False, log
    assert hub.text('ca.pem') == 'int FEDHUB-INT-CA-01'
    assert 'requires a sudo password' not in log


def test_no_step_runs_sudo_on_true(hub):
    hub.deploy_certs()
    hub.rotate_remote()
    assert hub.status['error'] is False, '\n'.join(hub.log)
    calls = hub.sudo_calls()
    assert calls, 'the stand-in sudo was never used'
    assert not [c for c in calls if re.match(r'^(-n )?(/usr/bin/)?true$', c.strip())], calls


def test_refused_sudo_stops_before_any_certificate_file_is_touched(hub):
    hub.deploy_certs()
    before = {p.name: p.read_text() for p in hub.files.iterdir()}
    hub.no_sudo_at_all()
    hub.rotate_remote()
    log = '\n'.join(hub.log)
    assert hub.status['error'] is True and hub.status['complete'] is True
    assert 'asked for a password' in log, log
    assert 'No certificate file was changed' in log, log
    assert {p.name: p.read_text() for p in hub.files.iterdir()} == before
    assert hub.stashed() == []


def test_refusal_text_never_tells_the_admin_to_grant_all_commands(hub):
    hub.deploy_certs()
    hub.no_sudo_at_all()
    hub.rotate_remote()
    log = '\n'.join(hub.log)
    assert 'NOPASSWD' not in log, log
    assert 'infra-tak-nopasswd' not in log, log


def test_no_sudo_true_probe_is_left_in_the_app():
    for m in re.finditer(r'sudo\s+-n\s+(?:/usr/bin/)?true\b', APP):
        line = APP.count('\n', 0, m.start()) + 1
        text = APP.splitlines()[line - 1].strip()
        # comments that explain why the probe is gone are fine
        assert text.startswith('#'), f'app.py:{line}: {text}'


def test_deploy_checks_for_a_refusal_at_its_first_privileged_certificate_step():
    src = base._func('_fedhub_run_remote_package_install')
    i_meta = src.index("_module_run(cfg, meta_cmds")
    i_check = src.index('_fedhub_sudo_refused(meta_out)')
    i_certs = src.index('makeRootCa.sh')
    assert i_meta < i_check < i_certs
    assert 'NOPASSWD' not in src


@pytest.mark.parametrize('text', [
    'sudo: a password is required',
    'sudo: a terminal is required to read the password; either use the -S option to read from standard input '
    'or configure an askpass helper',
    'sudo: no tty present and no askpass program specified',
    'alice is not in the sudoers file.  This incident will be reported.',
])
def test_refusal_matcher_sees_sudo_refusals(text):
    ns = {'re': re}
    exec(_assign('_FEDHUB_SUDO_REFUSED_RE'), ns)
    exec(base._func('_fedhub_sudo_refused'), ns)
    assert ns['_fedhub_sudo_refused'](text) is True


@pytest.mark.parametrize('text', [
    '',
    None,
    'sed: can\'t read cert-metadata.sh: No such file or directory',
    'cp: cannot stat cert-metadata.sh',
    'sudo: unable to resolve host hub: Name or service not known',
])
def test_refusal_matcher_ignores_other_failures(text):
    ns = {'re': re}
    exec(_assign('_FEDHUB_SUDO_REFUSED_RE'), ns)
    exec(base._func('_fedhub_sudo_refused'), ns)
    assert ns['_fedhub_sudo_refused'](text) is False
