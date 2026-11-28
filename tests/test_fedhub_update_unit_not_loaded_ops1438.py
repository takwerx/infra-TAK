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
"""Federation Hub Update does not dead-end when systemd has not loaded the hub's unit (ops #1438).

Before: a hub installed by hand has init scripts in /etc/init.d, but systemd had not reloaded since
they appeared, so `federation-hub.service` was "not loaded". The package's preinst runs
`systemctl stop federation-hub` under `set -e`, got "Unit federation-hub.service not loaded"
(exit 5), and dpkg refused the new package. The console log ended with `apt-get install failed` and
pressing Update again failed the same way.

These tests run the real _fedhub_run_remote_package_install (the harness of ops #1339). The stand-in
systemctl keeps one fact, "is the unit loaded", that only `daemon-reload` changes; the stand-in
apt-get runs the package's preinst stop first and fails with dpkg's message and exit 100 when that
stop answers 5. What is NOT covered here: the real takserver-fed-hub package and a real systemd
(the box test does that).
"""

import os
import sys
import tempfile
import pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import test_fedhub_update_keeps_certs_ops1339 as upd  # noqa: E402
import test_fedhub_rotate_ca_twice_ops865 as base  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='runs shell scripts')


class UnitHub(upd.Update):
    """An Update harness where systemd's view of the unit is a file: root/unit-loaded."""

    def __init__(self, root, loaded, reload_fails=False):
        super().__init__(root)
        self.loaded_flag = self.root / 'unit-loaded'
        self.events = self.root / 'events.log'
        self.reload_fails = reload_fails
        if loaded:
            self.loaded_flag.write_text('1')
        # the package's preinst, as it behaves in the field: stop the hub under set -e
        base._write(self.bin / 'apt-get',
                    '#!/bin/bash\n'
                    f'echo apt >> {self.events}\n'
                    f'echo "$@" >> {self.root}/apt.log\n'
                    'if [ "$1" = update ]; then exit 0; fi\n'
                    'systemctl stop federation-hub || {\n'
                    '  echo "dpkg: error processing archive ./takserver-fed-hub.deb (--install):" >&2\n'
                    '  echo " new takserver-fed-hub package pre-installation script subprocess returned error exit status 5" >&2\n'
                    '  exit 100; }\n'
                    f'echo installed >> {self.root}/installed.log\n'
                    'exit 0\n', 0o755)

    def make_fake_systemctl(self):
        flag, ev = self.loaded_flag, self.events
        # a refused reload: only the FIRST one (the new step before apt-get); the later ones, in the
        # existing start-services step, work, so the rest of the update is not what this test is about
        denied = self.root / 'reload-denied'
        reload_branch = (f'if [ ! -f {denied} ]; then touch {denied}; '
                         'echo "Failed to connect to bus: Access denied" >&2; exit 1; fi; '
                         f'touch {flag}' if self.reload_fails else f'touch {flag}')
        base._write(self.bin / 'systemctl',
                    '#!/bin/bash\n'
                    f'[ "$1" == "daemon-reload" ] && {{ echo reload >> {ev}; {reload_branch}; exit 0; }}\n'
                    f'[ "$1" == "restart" ] && echo r >> {self.root}/restarts.log\n'
                    '[ "$1" == "is-active" ] && echo active\n'
                    # a stop of a unit systemd has not loaded: the answer the package's preinst met
                    f'if [ "$1" == "stop" ] && [ ! -f {flag} ]; then\n'
                    '  echo "Failed to stop federation-hub.service: Unit federation-hub.service not loaded." >&2\n'
                    '  exit 5; fi\n'
                    'exit 0\n', 0o755)

    def installed(self):
        return (self.root / 'installed.log').exists()

    def event_list(self):
        return self.events.read_text().split() if self.events.exists() else []


@pytest.fixture()
def tmp():
    with tempfile.TemporaryDirectory() as d:
        yield d


def _ready(hub):
    hub.configs()
    hub.manual_certs(with_ca=True)


def test_update_of_a_hub_whose_unit_is_not_loaded_ends_complete(tmp):
    """PROOF: unit not loaded, package preinst stop answers 5. Without the reload before apt-get the
    update ended `error` with the hub left on the old package; now it completes on the new one."""
    hub = UnitHub(tmp, loaded=False)
    _ready(hub)
    hub.run()
    log = '\n'.join(hub.log)
    assert hub.status['error'] is False, log
    assert hub.installed(), 'the new package must have been installed\n' + log
    assert 'apt-get install failed' not in log


def test_the_reload_comes_before_the_package_install(tmp):
    hub = UnitHub(tmp, loaded=False)
    _ready(hub)
    hub.run()
    ev = hub.event_list()
    assert 'reload' in ev and 'apt' in ev, ev
    assert ev.index('reload') < ev.index('apt'), f'daemon-reload must run before apt-get: {ev}'


def test_update_of_a_hub_whose_unit_is_loaded_is_unchanged(tmp):
    """What a hand install normally leaves: the update completed before and must still."""
    hub = UnitHub(tmp, loaded=True)
    _ready(hub)
    hub.run()
    assert hub.status['error'] is False, '\n'.join(hub.log)
    assert hub.installed()


def test_a_refused_reload_warns_and_the_install_still_runs(tmp):
    """Best effort: a sudoers list that does not allow the reload must not add a new way to fail.
    The unit is loaded here, so apt-get succeeds; the log carries one warning line."""
    hub = UnitHub(tmp, loaded=True, reload_fails=True)
    _ready(hub)
    hub.run()
    log = '\n'.join(hub.log)
    assert hub.status['error'] is False, log
    assert hub.installed()
    assert 'systemctl daemon-reload failed before the package install' in log, log


def test_when_the_reload_cannot_help_the_log_says_what_to_do(tmp):
    """Unit not loaded AND the reload refused: the update still ends in error (nothing else can
    fix it), but the log now names the cause and the command, not only `apt-get install failed`."""
    hub = UnitHub(tmp, loaded=False, reload_fails=True)
    _ready(hub)
    hub.run()
    log = '\n'.join(hub.log)
    assert hub.status['error'] is True and hub.status['complete'] is True
    assert not hub.installed()
    assert 'sudo systemctl daemon-reload' in log and 'press Update again' in log, log


def test_nothing_changes_on_the_hub_when_the_install_fails_before_the_package(tmp):
    """The reload sits after the backup and the .deb copy, so a hub that cannot be read still stops
    before any change (ops #1339) and never reaches the reload."""
    hub = UnitHub(tmp, loaded=False)
    _ready(hub)
    base._write(hub.bin / 'ls', '#!/bin/bash\ncase "$*" in *certs/files*) echo "ls: cannot open directory: Permission denied" >&2; exit 2;; esac\nexec /bin/ls "$@"\n', 0o755)
    hub.run()
    assert hub.status['error'] is True
    assert hub.event_list() == [], 'neither reload nor apt-get may run'
