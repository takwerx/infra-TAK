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
"""A slow Authentik core must not make Guard Dog recreate the LDAP outpost at boot (ops #1039).

T&E for 10.4.4 (ops #1033), cloud Ubuntu 22.04, Authentik's core CPU-limited so it was not ready
until ~10.5 min after boot: tak-post-start.sh gave the LDAP group check 120 s, force-recreated the
outpost into the same not-ready core (it still could not resolve groups: ALERT mail), and TAK's
API had no groups for 23+ min afterwards, until the console's last-resort TAK restart.

The REAL tak-post-start.sh runs here with the REAL _gd-tak-lib.sh, paths pointed into a sandbox and
docker, curl, ldapsearch, ss and timeout stubbed. A stateful curl stub answers the core's
/-/health/ready/ with 503 until it has been asked N times; ldapsearch only finds groups once the
core has answered 200 (an outpost resolves groups only against a ready core).
"""

import os
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
GD = REPO / 'scripts' / 'guarddog'
POST = (GD / 'tak-post-start.sh').read_text()
LIB = (GD / '_gd-tak-lib.sh').read_text()

# `docker ps --filter ...` says healthy unless state/unhealthy exists (a server still starting)
DOCKER_STUB = '''#!/bin/sh
echo "docker $*" >> %(calls)s
case "$*" in
  "ps --filter"*) if [ -e %(state)s/unhealthy ]; then echo "Up 10 seconds (health: starting)"; else echo "Up 2 minutes (healthy)"; fi ;;
  inspect*) exit 1 ;;
esac
exit 0
'''

# 503 for the first THRESH asks, then 200 (and the core stays ready). 'never' = THRESH of 100000.
CURL_STUB = '''#!/bin/sh
echo "curl $*" >> %(calls)s
n=$(cat %(state)s/count 2>/dev/null || echo 0); n=$((n + 1)); echo $n > %(state)s/count
if [ -e %(state)s/noport ]; then printf 000; exit 7; fi    # the port answers nothing (refused / not published)
if [ "$n" -gt "$(cat %(state)s/thresh)" ]; then touch %(state)s/ready; printf 200; else printf 503; fi
exit 0
'''

# groups only once the core has answered ready; `groups-never` keeps the outpost broken for good
LDAPSEARCH_STUB = '''#!/bin/sh
echo "ldapsearch" >> %(calls)s
if [ -e %(state)s/ready ] && [ ! -e %(state)s/groups-never ]; then echo "dn: cn=Alpha Crew,ou=groups,dc=takldap"; exit 0; fi
echo "ldap_search: Operations error (1)"; exit 1
'''

# `timeout N ldapsearch ...` runs it; every TCP probe (`timeout N bash -c exec 3<>/dev/tcp/..`) says down
TIMEOUT_STUB = '''#!/bin/sh
shift
case "$1" in ldapsearch) exec "$@" ;; *) exit 1 ;; esac
'''


@pytest.fixture
def box(tmp_path):
    calls = tmp_path / 'calls.log'
    state = tmp_path / 'state'
    state.mkdir()
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    home = tmp_path / 'home'
    (home / 'authentik').mkdir(parents=True)
    (home / 'authentik' / 'docker-compose.yml').write_text('services: {}\n')
    (home / 'authentik' / '.env').write_text(
        'AUTHENTIK_BOOTSTRAP_LDAPSERVICE_USERNAME=adm_ldapservice\n'
        'AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD=x\n'
        'AUTHENTIK_BOOTSTRAP_LDAP_BASEDN=dc=takldap\n')
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
                   # the wall-clock budget, short: the sleep stub does not sleep
                   .replace('_CORE_WAIT=420', '_CORE_WAIT=3'))

    (gd / '_gd-tak-lib.sh').write_text(sandbox(LIB))
    (gd / 'send-alert-email.sh').write_text('#!/bin/sh\necho "alert-mail $*" >> %s\ncat >/dev/null\n' % calls)
    (stubs / 'docker').write_text(DOCKER_STUB % {'calls': calls, 'state': state})
    (stubs / 'curl').write_text(CURL_STUB % {'calls': calls, 'state': state})
    (stubs / 'ldapsearch').write_text(LDAPSEARCH_STUB % {'calls': calls, 'state': state})
    (stubs / 'timeout').write_text(TIMEOUT_STUB)
    (stubs / 'flock').write_text('#!/bin/sh\nexit 0\n')
    (stubs / 'ss').write_text('#!/bin/sh\necho "LISTEN 0 4096 *:8089 *:*"\n')
    (stubs / 'id').write_text('#!/bin/sh\nexit 1\n')                 # no local postgres
    (stubs / 'systemctl').write_text('#!/bin/sh\nexit 1\n')          # no MediaMTX
    for name in ('sleep', 'logger'):
        (stubs / name).write_text('#!/bin/sh\nexit 0\n')
    for f in list(stubs.iterdir()) + [gd / 'send-alert-email.sh']:
        f.chmod(0o755)
    (tmp_path / 'uptime').write_text('26.42 99.00\n')

    def run(core_ready_after=0, groups_never=False, noport=False, unhealthy=False, hard_end=None):
        """core_ready_after: how many /-/health/ready/ asks answer 503 first (None = never ready).
        noport: the probe gets no answer at all; unhealthy: Docker does not call authentik-server healthy.
        hard_end: seconds after the script start past which the core wait never goes (default 960)."""
        (state / 'thresh').write_text(str(100000 if core_ready_after is None else core_ready_after))
        if groups_never:
            (state / 'groups-never').write_text('')
        if noport:
            (state / 'noport').write_text('')
            (state / 'ready').write_text('')          # the outpost works; only the probe cannot see the port
        if unhealthy:
            (state / 'unhealthy').write_text('')
        sp = tmp_path / 'post.sh'
        src = sandbox(POST).replace('ALERT_EMAIL_PLACEHOLDER', 'ops@example.invalid')
        if hard_end is not None:
            src = src.replace('_CORE_HARD_END=960', '_CORE_HARD_END=%d' % hard_end)
        sp.write_text(src)
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs, 'HOME': str(home),
               'JAVA_HOME': str(tmp_path / 'nojava'), 'GD_STACK_OWNER': str(os.getuid())}
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=120)
        assert r.returncode == 0, r.stderr
        return r.stdout, calls.read_text() if calls.exists() else ''

    return run


def _recreates(calls):
    return [l for l in calls.splitlines() if l == 'docker compose up -d --force-recreate ldap']


def test_a_core_that_is_ready_at_boot_changes_nothing(box):
    out, calls = box(core_ready_after=0)
    assert 'core not ready' not in out
    assert 'LDAP outpost resolving groups' in out
    assert _recreates(calls) == []
    assert 'Boot sequence complete' in out


def test_a_slow_core_is_waited_for_and_the_outpost_is_not_recreated(box):
    """The 10.4.4 T&E case: the core answers 503 for a while. The outpost resolves groups the moment
    it is ready, so nothing may be recreated into the not-ready core."""
    out, calls = box(core_ready_after=3)
    assert 'Authentik core not ready yet' in out
    assert 'Authentik core ready (' in out
    assert 'LDAP outpost resolving groups' in out
    assert _recreates(calls) == [], calls
    assert 'ALERT' not in out
    assert 'alert-mail' not in calls
    assert 'Boot sequence complete' in out


def test_the_group_check_starts_only_after_the_core_is_ready(box):
    out, calls = box(core_ready_after=3)
    lines = calls.splitlines()
    ready = max(i for i, l in enumerate(lines) if l.startswith('curl '))
    first_search = lines.index('ldapsearch')
    assert ready < first_search, lines


def test_a_core_that_never_gets_ready_does_not_get_the_outpost_recreated_and_says_so(box):
    out, calls = box(core_ready_after=None)
    assert _recreates(calls) == [], calls
    assert 'outpost NOT recreated' in out
    assert 'ALERT' in out
    assert 'alert-mail' in calls and 'Authentik is slow to start' in calls
    assert 'Boot sequence complete' in out        # fails open: the rest of the boot still runs


def test_a_ready_core_with_a_broken_outpost_is_still_recreated(box):
    """GH #64 stays fixed: the outpost bound before the provider tree existed. Once the core IS
    ready and the outpost still cannot resolve groups, the recreate runs, after the core check."""
    out, calls = box(core_ready_after=3, groups_never=True)
    assert 'force-recreating' in out
    assert len(_recreates(calls)) == 1, calls
    lines = calls.splitlines()
    ready = max(i for i, l in enumerate(lines) if l.startswith('curl '))
    assert ready < lines.index('docker compose up -d --force-recreate ldap')
    assert 'Boot sequence complete' in out


def test_a_port_that_answers_nothing_falls_back_to_dockers_health_and_does_not_hold_the_boot(box):
    """The probe cannot reach 9090 (not published here). Docker says authentik-server is healthy: the
    boot goes on at once instead of waiting out the whole budget."""
    out, calls = box(noport=True)
    assert 'core not ready' not in out
    assert 'LDAP outpost resolving groups' in out
    assert _recreates(calls) == []
    assert 'Boot sequence complete' in out


def test_a_port_that_answers_nothing_and_a_starting_server_is_still_waited_for(box):
    out, calls = box(noport=True, unhealthy=True, groups_never=True)
    assert 'Authentik core not ready yet' in out
    assert 'outpost NOT recreated' in out
    assert _recreates(calls) == [], calls


def test_the_wait_never_runs_past_the_hard_end_even_when_compose_used_the_time(box):
    """On a slow core `docker compose up -d` itself blocks until the server is healthy. If that used up
    the budget, there is no wait left (the unit stops at 1200 s) and the script goes on."""
    out, calls = box(core_ready_after=None, hard_end=-5)
    assert 'Authentik core not ready yet' in out
    assert 'outpost NOT recreated' in out
    assert 'Boot sequence complete' in out
    assert calls.count('curl ') <= 3, calls               # no polling loop: asked once, then once after the (empty) wait
