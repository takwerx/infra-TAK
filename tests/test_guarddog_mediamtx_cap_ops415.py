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
"""Guard Dog MediaMTX watcher stops restarting forever (ops #415).

A customer box logged "MediaMTX not active - restarting" (and sent an alert email) every
~15 min for hours. The watcher runs for real here with systemctl, date and the alert
sender stubbed and its fixed paths pointed at a temp dir.
"""

import os
import pathlib
import stat
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = (REPO / 'scripts' / 'guarddog' / 'tak-mediamtx-watch.sh').read_text()


class Box:
    def __init__(self, tmp, enabled='enabled'):
        self.tmp = tmp
        self.state = tmp / 'state'
        self.log = tmp / 'log'
        self.bin = tmp / 'bin'
        self.opt = tmp / 'opt'
        for d in (self.state, self.log, self.bin, self.opt):
            d.mkdir()
        (tmp / 'uptime').write_text('99999.0 1\n')
        (tmp / 'now').write_text('1000000')
        (tmp / 'calls').write_text('')
        self._stub('systemctl', f'''#!/bin/bash
echo "systemctl $*" >> {tmp}/calls
case "$1" in
  list-unit-files) [ "$2" = mediamtx.service ] && echo "$2 enabled"; exit 0 ;;
  is-active) exit 3 ;;
  is-enabled) echo {enabled}; exit 1 ;;
esac
exit 0
''')
        self._stub('date', f'''#!/bin/bash
case "$*" in
  "+%s") cat {tmp}/now ;;
  *) /bin/date "$@" ;;
esac
''')
        self._stub('journalctl', '#!/bin/bash\nexit 0\n')
        self._stub('usermod', '#!/bin/bash\nexit 0\n')
        sender = self.opt / 'send-alert-email.sh'
        sender.write_text(f'#!/bin/bash\necho "$1" >> {tmp}/alerts\ncat >/dev/null\n')
        sender.chmod(0o755)
        script = SCRIPT.replace('/var/lib/takguard', str(self.state)) \
                       .replace('/var/log/takguard', str(self.log)) \
                       .replace('/opt/tak-guarddog', str(self.opt)) \
                       .replace('/proc/uptime', str(tmp / 'uptime'))
        self.script = tmp / 'watch.sh'
        self.script.write_text(script)

    def _stub(self, name, body):
        p = self.bin / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)

    def tick(self, advance=60):
        now = int((self.tmp / 'now').read_text()) + advance
        (self.tmp / 'now').write_text(str(now))
        env = dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}')
        subprocess.run(['bash', str(self.script)], env=env, check=True,
                       capture_output=True, timeout=30)

    def run_for(self, hours):
        for _ in range(hours * 60):
            self.tick(60)

    def restarts(self):
        return sum(1 for l in (self.tmp / 'calls').read_text().splitlines()
                   if l == 'systemctl restart mediamtx')

    def alerts(self):
        p = self.tmp / 'alerts'
        return p.read_text().splitlines() if p.exists() else []

    def log_lines(self):
        p = self.log / 'restarts.log'
        return p.read_text().splitlines() if p.exists() else []


def test_enabled_but_never_starting_is_capped_at_three_restarts_a_day(tmp_path):
    box = Box(tmp_path)
    box.run_for(20)
    assert box.restarts() == 3
    assert len([l for l in box.log_lines() if '| restart |' in l]) == 3
    # three restart emails plus exactly one "giving up" email, not one every 15 min
    assert len(box.alerts()) == 4
    assert 'will not stay up' in box.alerts()[-1]


def test_cap_window_rolls_over_after_24_hours(tmp_path):
    box = Box(tmp_path)
    box.run_for(20)
    assert box.restarts() == 3
    box.run_for(2)          # still inside the same 24 h window
    assert box.restarts() == 3
    box.tick(24 * 3600)     # window over
    box.run_for(1)
    assert box.restarts() > 3


def test_disabled_unit_is_left_alone(tmp_path):
    box = Box(tmp_path, enabled='disabled')
    box.run_for(5)
    assert box.restarts() == 0
    assert box.alerts() == []
    assert box.log_lines() == []


def test_masked_unit_is_left_alone(tmp_path):
    box = Box(tmp_path, enabled='masked')
    box.run_for(5)
    assert box.restarts() == 0
    assert box.alerts() == []
