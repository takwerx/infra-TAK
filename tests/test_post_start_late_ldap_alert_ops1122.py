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
"""Guard Dog's boot script does not cry "LDAP outpost cannot resolve groups" too early (ops #1122).

tak-post-start.sh used to send the alert email 150 s after Authentik came up
(120 s of probing, a recreate, 30 s more). On a slow VPS (test6: 18 ms disk commits,
load 10 to 20) Authentik's provider tree needs minutes, so the box mailed "every client
sees nobody" on every reboot and healed itself a few minutes later. The released boot
heal for ops #1015 is in the console and did not touch this script.

Now the script remembers the failed check and asks again at the end of its run, until
LDAP_LATE_WINDOW seconds have passed. Only a box that is STILL broken then gets the email.

The REAL tak-post-start.sh and _gd-tak-lib.sh run here in a sandbox. Docker, ldapsearch,
timeout and sleep are stubs; sleep moves a fake clock, so ten "minutes" cost no time.
"""

import os
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
GD = REPO / 'scripts' / 'guarddog'
POST = (GD / 'tak-post-start.sh').read_text()
LIB = (GD / '_gd-tak-lib.sh').read_text()

DOCKER_STUB = '''#!/bin/sh
echo "docker $*" >> %(calls)s
case "$*" in
  "ps --filter"*) echo "Up 2 minutes (healthy)" ;;
  inspect*) exit 1 ;;
esac
exit 0
'''

# sleep only moves the fake clock.
SLEEP_STUB = '''#!/bin/sh
n=$(cat %(clock)s); echo $((n + ${1:-0})) > %(clock)s
'''

# `timeout 20 ldapsearch ...` runs the stub; every other timeout (the TCP probes) says down.
TIMEOUT_STUB = '''#!/bin/sh
if [ "$2" = ldapsearch ]; then shift; exec "$@"; fi
exit 1
'''

# Groups resolve once the fake clock has reached the number in the `ok_after` file.
LDAPSEARCH_STUB = '''#!/bin/sh
n=$(cat %(clock)s); a=$(cat %(ok_after)s)
echo "ldapsearch $n" >> %(calls)s
if [ "$n" -ge "$a" ]; then echo "dn: cn=group,dc=example,dc=com"; exit 0; fi
echo "ldap_search: Operations error (1)"; exit 1
'''

# Records the clock and the body of every alert email.
ALERT_STUB = '''#!/bin/sh
echo "ALERT-EMAIL clock=$(cat %(clock)s) subject=$1 body=$(cat)" >> %(calls)s
'''


@pytest.fixture
def box(tmp_path):
    calls = tmp_path / 'calls.log'
    clock = tmp_path / 'clock'
    ok_after = tmp_path / 'ok_after'
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    home = tmp_path / 'home'
    (home / 'authentik').mkdir(parents=True)
    (home / 'authentik' / 'docker-compose.yml').write_text('services: {}\n')
    (home / 'authentik' / '.env').write_text(
        'AUTHENTIK_BOOTSTRAP_LDAPSERVICE_USERNAME=ldapservice\n'
        'AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD=not-a-real-password\n'
        'AUTHENTIK_BOOTSTRAP_LDAP_BASEDN=dc=example,dc=com\n')
    gd = tmp_path / 'gd'
    gd.mkdir()

    def sandbox(src):
        return (src.replace('/opt/tak-guarddog/', str(gd) + '/')
                   .replace('/opt/tak/', str(tmp_path / 'absent-tak') + '/')
                   .replace('/proc/uptime', str(tmp_path / 'uptime'))
                   .replace('/run/takguard-boot-sequenced', str(tmp_path / 'boot-sequenced'))
                   .replace('/tmp/', str(tmp_path) + '/')
                   .replace('/home/*/', str(tmp_path / 'nohome') + '/*/')
                   .replace('/root/', str(tmp_path / 'noroot') + '/')
                   # the fake clock replaces bash's $SECONDS
                   .replace('_now() { echo "$SECONDS"; }', '_now() { cat %s; }' % clock))

    fmt = {'calls': calls, 'clock': clock, 'ok_after': ok_after}
    (gd / '_gd-tak-lib.sh').write_text(sandbox(LIB))
    (gd / 'send-alert-email.sh').write_text(ALERT_STUB % fmt)
    (stubs / 'docker').write_text(DOCKER_STUB % fmt)
    (stubs / 'sleep').write_text(SLEEP_STUB % fmt)
    (stubs / 'timeout').write_text(TIMEOUT_STUB)
    (stubs / 'ldapsearch').write_text(LDAPSEARCH_STUB % fmt)
    (stubs / 'ss').write_text('#!/bin/sh\necho "LISTEN 0 4096 *:8089 *:*"\n')
    (stubs / 'id').write_text('#!/bin/sh\nexit 1\n')
    (stubs / 'systemctl').write_text('#!/bin/sh\nexit 1\n')
    (stubs / 'flock').write_text('#!/bin/sh\nexit 0\n')
    (stubs / 'logger').write_text('#!/bin/sh\nexit 0\n')
    for f in list(stubs.iterdir()) + [gd / 'send-alert-email.sh']:
        f.chmod(0o755)
    (tmp_path / 'uptime').write_text('26.42 99.00\n')

    def run(groups_ok_after, edits=()):
        """Run the script; groups resolve from fake-clock second `groups_ok_after` on."""
        clock.write_text('0\n')
        ok_after.write_text('%d\n' % groups_ok_after)
        if calls.exists():
            calls.unlink()
        src = sandbox(POST)
        for old, new in edits:
            assert old in src, old
            src = src.replace(old, new)
        sp = tmp_path / 'post.sh'
        sp.write_text(src)
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs, 'HOME': str(home),
               'JAVA_HOME': str(tmp_path / 'nojava'), 'GD_STACK_OWNER': str(os.getuid())}
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        text = calls.read_text() if calls.exists() else ''
        alerts = [l for l in text.splitlines() if l.startswith('ALERT-EMAIL')]
        return r.stdout, alerts, int(clock.read_text())

    return run


def _clock_of(alert):
    return int(alert.split('clock=')[1].split()[0])


def test_alert_waits_for_a_slow_box_that_heals_itself(box):
    # Groups resolve at fake second 400. The old code gave up at about 150 and mailed.
    out, alerts, _ = box(groups_ok_after=400)
    assert 'force-recreating' in out                      # the boot recreate still happens
    assert alerts == [], alerts                           # but a box that heals gets no email
    assert 'recovered on its own' in out
    assert 'ALERT |' not in out
    assert 'Boot sequence complete' in out


def test_alert_is_sent_only_after_the_window_when_groups_never_come_back(box):
    out, alerts, _ = box(groups_ok_after=10 ** 9)
    assert len(alerts) == 1, alerts
    assert 'Guard Dog: LDAP outpost cannot resolve groups' in alerts[0]
    assert 'still cannot resolve groups' in alerts[0]
    # The failed check is at about 150 s; the alert may not leave before 600 s more.
    failed_at = int(out.split('WARN | LDAP outpost still cannot resolve groups 30s after the recreate (')[1].split('s')[0])
    assert _clock_of(alerts[0]) - failed_at >= 600
    assert 'ALERT | LDAP outpost still cannot resolve groups' in out
    assert out.rindex('Boot sequence complete') > out.index('ALERT |')   # judged at the end, not step 1


def test_alert_is_not_sent_from_the_recreate_step_any_more(box):
    out, alerts, _ = box(groups_ok_after=10 ** 9)
    first_alert_clock = _clock_of(alerts[0])
    failed_at = int(out.split('WARN | LDAP outpost still cannot resolve groups 30s after the recreate (')[1].split('s')[0])
    assert first_alert_clock > failed_at + 30             # not right after the 30 s re-check


def test_late_check_stops_at_the_cap_so_systemd_never_kills_the_alert(box):
    out, alerts, end = box(groups_ok_after=10 ** 9, edits=[('LDAP_LATE_WINDOW=600', 'LDAP_LATE_WINDOW=100000')])
    assert len(alerts) == 1, alerts
    assert 1080 <= _clock_of(alerts[0]) < 1080 + 20
    assert end < 1200                                     # inside TimeoutStartSec=1200


def test_a_box_that_resolves_groups_at_once_is_untouched(box):
    out, alerts, _ = box(groups_ok_after=0)
    assert 'force-recreating' not in out
    assert alerts == []
    assert 'WARN |' not in out and 'recovered on its own' not in out
    assert 'Boot sequence complete' in out


def test_a_box_that_heals_after_the_recreate_is_quiet(box):
    # Fails the 120 s loop, passes the check 30 s after the recreate (clock 150).
    out, alerts, _ = box(groups_ok_after=150)
    assert 'LDAP outpost recovered after recreate' in out
    assert alerts == []
    assert 'WARN |' not in out


def test_script_still_parses_and_keeps_the_gate_release():
    assert 'trap release_client_gate EXIT' in POST
    assert POST.rindex('Late LDAP group check') < POST.rindex('Boot sequence complete')
