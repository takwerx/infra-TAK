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
"""At the 80% disk warning, the reclaim frees everything it safely can (GH #165).

Field (Ubuntu 22.04, 124 GB root): Guard Dog warned at 80-81% for hours while every
hourly run logged "size-cap reclaimed 0B" and "Reclaimed 0B ... cache older than 168h".
16 GB of young build cache, 13 GB of image tags left behind by upgrades and a 3.9 GB
uncapped journal were all reclaimable; nothing between 80% and 85% touched them.

The REAL script runs here with its absolute paths pointed into a sandbox and
docker/df/journalctl/systemctl/pgrep stubbed; every docker call is recorded.
"""

import os
import pathlib
import re
import subprocess
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
RECLAIM = (REPO / 'scripts' / 'guarddog' / 'tak-buildcache-reclaim.sh').read_text()
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-disk-watch.sh').read_text()

DOCKER_STUB = r'''#!/bin/bash
echo "$*" >> "%(dir)s/docker_calls"
case "$*" in
  info*) exit 0 ;;
  "builder prune --help") echo "      --max-used-space bytes" ;;
  "image prune"*) echo "Total reclaimed space: 13GB" ;;
  "builder prune -af"*) echo "Total:	16.1GB" ;;
  "builder prune"*) echo "Total:	0B" ;;
esac
exit 0
'''


@pytest.fixture
def box(tmp_path):
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    gd = tmp_path / 'gd'
    gd.mkdir()
    (stubs / 'docker').write_text(DOCKER_STUB % {'dir': tmp_path})
    (stubs / 'df').write_text('#!/bin/sh\necho "Use%%"\necho " $(cat %s/pct)%%"\n' % tmp_path)
    (stubs / 'journalctl').write_text(
        '#!/bin/sh\necho "journalctl $*" >> %s/sys_calls\n'
        'echo "Vacuuming done, freed 3.7G of archived journals from /var/log/journal." >&2\n' % tmp_path)
    (stubs / 'systemctl').write_text('#!/bin/sh\necho "systemctl $*" >> %s/sys_calls\n' % tmp_path)
    (stubs / 'logger').write_text('#!/bin/sh\nshift 2\necho "$*" >> %s/syslog\n' % tmp_path)
    (stubs / 'pgrep').write_text('#!/bin/sh\n[ -f %s/busy ]\n' % tmp_path)
    for f in stubs.iterdir():
        f.chmod(0o755)
    script = (RECLAIM.replace('/var/lib/takguard', str(tmp_path / 'state'))
                     .replace('/var/log/takguard', str(tmp_path / 'log'))
                     .replace('/opt/tak-guarddog/', str(gd) + '/')
                     .replace('/etc/systemd/journald.conf.d', str(tmp_path / 'journald.conf.d'))
                     .replace('/var/lib/takwerx-console', str(tmp_path / 'console')))
    assert '/var/lib/takguard' not in script and '/etc/systemd' not in script
    sp = tmp_path / 'tak-buildcache-reclaim.sh'
    sp.write_text(script)

    def run(pct):
        (tmp_path / 'pct').write_text(str(pct))
        for f in ('docker_calls', 'sys_calls'):
            (tmp_path / f).write_text('')
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        docker = (tmp_path / 'docker_calls').read_text().splitlines()
        return {
            'docker': [c for c in docker if c not in ('info', 'builder prune --help')],
            'sys': (tmp_path / 'sys_calls').read_text(),
            'last': (tmp_path / 'log' / 'buildcache_reclaim_last.txt').read_text(),
            'dropin': tmp_path / 'journald.conf.d' / 'takwerx-size.conf',
        }
    run.tmp = tmp_path
    return run


def test_at_the_warning_all_unused_cache_images_and_journal_are_reclaimed(box):
    r = box(81)                                             # the field box
    assert 'builder prune -af' in r['docker']
    assert 'image prune -af' in r['docker']
    assert 'journalctl --vacuum-size=500M' in r['sys']
    assert 'unused images reclaimed 13GB' in r['last'] and 'freed 3.7G' in r['last']


def test_never_volumes_or_system_prune(box):
    r = box(95)
    for c in r['docker']:
        assert 'volume' not in c and 'system' not in c and 'container' not in c, c


def test_below_the_warning_only_old_cache_goes(box):
    box(75)                                                  # first run applies the journald cap
    r = box(75)
    assert 'builder prune -f --filter until=168h' in r['docker']
    assert not any('image prune' in c or c.startswith('builder prune -af') for c in r['docker'])
    assert '--vacuum-size' not in r['sys']


def test_image_prune_waits_while_images_are_being_pulled_or_built(box):
    (box.tmp / 'busy').write_text('')
    r = box(85)
    assert 'image prune -af' not in r['docker']
    assert 'builder prune -af' in r['docker']               # cache still goes
    assert 'image prune skipped (docker compose/pull/build running)' in r['last']


def test_image_prune_waits_during_console_update(box):
    lock = box.tmp / 'console' / 'update-now.lock'
    lock.parent.mkdir()
    lock.write_text('version=x\n')
    r = box(85)
    assert 'image prune -af' not in r['docker']
    assert 'console update in progress' in r['last']
    old = time.time() - 21 * 60                              # past the 20-min TTL: stale
    os.utime(lock, (old, old))
    assert 'image prune -af' in box(85)['docker']


def test_journald_cap_converges_once_and_restarts_journald(box):
    r = box(40)
    assert r['dropin'].read_text() == '[Journal]\nSystemMaxUse=500M\n'
    assert 'systemctl restart systemd-journald' in r['sys']
    assert 'systemctl restart' not in box(40)['sys']         # already converged: no restart
    r['dropin'].write_text('[Journal]\nSystemMaxUse=4G\n')   # drifted: back to the fleet value
    assert 'systemctl restart systemd-journald' in box(40)['sys']
    assert r['dropin'].read_text() == '[Journal]\nSystemMaxUse=500M\n'


def test_full_reclaim_starts_exactly_at_the_disk_warning():
    full = int(re.search(r'^FULL_RECLAIM_PCT=(\d+)', RECLAIM, re.M).group(1))
    alert = int(re.search(r'^ALERT_THRESHOLD=(\d+)', WATCH, re.M).group(1))
    assert full == alert
