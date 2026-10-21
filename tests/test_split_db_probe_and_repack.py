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
"""Split (two_server) box: the remote-DB probe and the weekly repack (ops #74).

Field (10.2.17-alpha, split install, 107 clients on the remote DB):
  * restarts.log: "mgmt channel degraded (DB reachable) — pg_isready rc=1 — no restart"
    every 2 minutes, 3,900+ lines, while the same probe's `sudo -u postgres psql` passed.
    pg_isready ran with no -h/-p, so it asked the SSH user's DEFAULT target, not the
    database TAK uses. rc 1 is a server saying "cannot connect now": some other cluster.
  * takdbrepack.service sat `failed`.

The REAL scripts run here. ssh is a stub that runs the remote command locally, against
a fake Server One: pg_isready answers per target, sudo/psql/apt-get/pg_repack are fakes.
"""

import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
GD = REPO / 'scripts' / 'guarddog'

# ssh: run the last argument (the remote command) here, on the fake Server One.
SSH_STUB = '#!/bin/bash\ncmd="${@: -1}"\nexec bash -c "$cmd"\n'

# pg_isready: rc per target. -h <DB_HOST> = the endpoint TAK uses; no -h = the default socket.
PG_ISREADY_STUB = r'''#!/bin/bash
read -r TCP SOCK < "%(dir)s/pg_mode"
case " $* " in
  *" -h "*) rc=$TCP; where="db1:5432" ;;
  *)        rc=$SOCK; where="/var/run/postgresql:5432" ;;
esac
case $rc in 0) echo "$where - accepting connections" ;; 1) echo "$where - rejecting connections" ;;
            2) echo "$where - no response" ;; esac
exit $rc
'''

# sudo: `-n -u postgres X` runs X; `-n X` runs X as "root"; a restart is recorded.
SUDO_STUB = r'''#!/bin/bash
echo "sudo $*" >> "%(dir)s/sudo_calls"
root=1
while [ "${1#-}" != "$1" ]; do
  case "$1" in -u) root=0; shift 2 ;; *) shift ;; esac
done
case "$*" in *pg_ctlcluster*) echo RESTART >> "%(dir)s/restarts" ;; esac
case "$*" in *restart*) echo "Job for postgresql.service failed."; exit 1 ;; esac
FAKE_ROOT=$root exec "$@"
'''


def _stub(path, text):
    path.write_text(text)
    path.chmod(0o755)


def _sandbox(text, tmp_path, gd):
    return (text.replace('/var/lib/takguard', str(tmp_path / 'state'))
                .replace('/var/log/takguard', str(tmp_path / 'log'))
                .replace('/opt/tak-guarddog/', str(gd) + '/')
                .replace('/opt/tak-guarddog', str(gd)))


# ─── tak-remotedb-watch.sh ────────────────────────────────────────────────────

@pytest.fixture
def watch(tmp_path):
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    gd = tmp_path / 'gd'
    gd.mkdir()
    _stub(stubs / 'ssh', SSH_STUB)
    _stub(stubs / 'pg_isready', PG_ISREADY_STUB % {'dir': tmp_path})
    _stub(stubs / 'sudo', SUDO_STUB % {'dir': tmp_path})
    _stub(stubs / 'psql', '#!/bin/sh\nexit 0\n')
    _stub(stubs / 'timeout', '#!/bin/sh\n[ "$(cat %s/tcp)" = up ]\n' % tmp_path)
    _stub(stubs / 'sleep', '#!/bin/sh\nexit 0\n')
    _stub(gd / 'send-alert-email.sh', '#!/bin/sh\necho "$1" >> %s/alerts\n' % tmp_path)
    key = tmp_path / 'key'
    key.write_text('k')
    script = (_sandbox((GD / 'tak-remotedb-watch.sh').read_text(), tmp_path, gd)
              .replace('DB_HOST_PLACEHOLDER', 'db1')
              .replace('DB_PORT_PLACEHOLDER', '5432')
              .replace('SSH_KEY_PLACEHOLDER', str(key))
              .replace('SSH_USER_PLACEHOLDER', 'takdb')
              .replace('EXTERNAL_DB_PLACEHOLDER', '')
              .replace('ALERT_EMAIL_PLACEHOLDER', ''))
    sp = tmp_path / 'tak-remotedb-watch.sh'
    sp.write_text(script)

    def run(tcp, tcp_rc, sock_rc, times=1):
        (tmp_path / 'tcp').write_text(tcp)
        (tmp_path / 'pg_mode').write_text(f'{tcp_rc} {sock_rc}\n')
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        for _ in range(times):
            r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
            assert r.returncode == 0, r.stderr
        log = tmp_path / 'log' / 'restarts.log'
        rs = tmp_path / 'restarts'
        al = tmp_path / 'alerts'
        return ((log.read_text() if log.exists() else ''),
                (len(rs.read_text().split()) if rs.exists() else 0),
                (al.read_text().count('\n') if al.exists() else 0))
    return run


def test_field_signature_default_socket_rejecting_is_not_the_db_tak_uses(watch):
    # The nctak box: the endpoint TAK uses accepts; the SSH user's default target says 57P03.
    log, restarts, alerts = watch('up', 0, 1, times=5)
    assert log == '' and restarts == 0 and alerts == 0         # was: 5 lines + an alert


def test_db_host_that_does_not_route_back_to_itself_falls_back_to_the_local_socket(watch):
    log, _, alerts = watch('up', 2, 0, times=3)
    assert log == '' and alerts == 0


def test_a_real_rejecting_db_is_logged_once_not_every_two_minutes(watch):
    log, restarts, alerts = watch('up', 1, 1, times=30)        # an hour of runs
    lines = [l for l in log.splitlines() if 'mgmt channel degraded' in l]
    assert len(lines) == 1                                     # was: 30
    assert 'pg_isready rc=1 on db1:5432' in lines[0] and 'rejecting connections' in lines[0]
    assert restarts == 0 and alerts == 1


def test_recovery_writes_one_healthy_again_line_and_rearms(watch):
    watch('up', 1, 1, times=3)
    log, _, _ = watch('up', 0, 0, times=3)
    assert log.count('checks healthy again') == 1
    log, _, alerts = watch('up', 1, 1, times=2)               # a new episode logs and alerts again
    assert log.count('— no restart') == 2 and alerts == 2


def test_a_different_failing_leg_is_logged(watch):
    log, _, _ = watch('up', 1, 1, times=2)
    log, _, _ = watch('up', 2, 2, times=2)
    assert 'rc=1' in log and 'rc=2' in log
    assert log.count('mgmt channel degraded') == 2


def test_restart_still_needs_server_one_to_say_no_response_on_both_targets(watch):
    _, restarts, _ = watch('down', 2, 1, times=6)              # socket says starting up
    assert restarts == 0
    log, restarts, _ = watch('down', 2, 2, times=30)
    assert restarts == 3
    assert log.count("restart FAILED") == 3                    # every restart attempt is logged
    assert log.count('daily restart cap (3) reached') == 1     # the cap is logged once, not 20x


# ─── tak-db-repack.sh (two_server) ────────────────────────────────────────────

# psql: answers the three queries the script makes. Size is 20 GB (over the 10 GB threshold).
PSQL_STUB = r'''#!/bin/bash
sql="${@: -1}"
case "$sql" in
  *server_version_num*) echo 15 ;;
  *pg_database_size*)   echo 21474836480 ;;
  *) echo "CREATE EXTENSION" ;;
esac
'''

# apt-get: works only as root (sudo), and only has the package for the SERVER's major (15).
APT_STUB = r'''#!/bin/bash
echo "apt-get $* root=${FAKE_ROOT:-0}" >> "%(dir)s/apt_calls"
if [ "${FAKE_ROOT:-0}" != 1 ] && [ "$(id -u)" != 0 ]; then
  echo "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)"; exit 100
fi
case "$*" in
  *install*) case "$*" in *"%(pkg)s"*) printf '#!/bin/sh\necho "INFO: repacking table public.cot_router"\n' > "%(bin)s/pg_repack"
                                       chmod 755 "%(bin)s/pg_repack" ;;
                          *) echo "E: Unable to locate package"; exit 100 ;; esac ;;
esac
'''


# docker: `exec [-u USER] <container> cmd...` runs cmd here. With no -u it is the image's
# USER, which for takserver-db is postgres (ops #76), so only `-u root` is root.
DOCKER_STUB = r'''#!/bin/bash
echo "docker $*" >> "%(dir)s/docker_calls"
[ "$1" = exec ] || exit 0
shift
user=postgres
while [ "${1#-}" != "$1" ]; do
  case "$1" in -u) user=$2; shift 2 ;; *) shift ;; esac
done
shift
[ "$user" = root ] && export FAKE_ROOT=1 || export FAKE_ROOT=0
exec "$@"
'''


@pytest.fixture
def repack(tmp_path):
    def make(ssh_user='takdb', pkg='postgresql-15-repack', container=False):
        stubs = tmp_path / 'bin'
        stubs.mkdir()
        gd = tmp_path / 'gd'
        gd.mkdir()
        (tmp_path / 'state').mkdir()
        _stub(stubs / 'ssh', SSH_STUB)
        _stub(stubs / 'sudo', SUDO_STUB % {'dir': tmp_path})
        _stub(stubs / 'docker', DOCKER_STUB % {'dir': tmp_path})
        _stub(stubs / 'psql', PSQL_STUB)
        # Debian: pg_config reports the newest CLIENT (16), not the server (15).
        _stub(stubs / 'pg_config', '#!/bin/sh\necho "PostgreSQL 16.4"\n')
        _stub(stubs / 'apt-get', APT_STUB % {'dir': tmp_path, 'pkg': pkg, 'bin': stubs})
        _stub(gd / 'send-alert-email.sh', '#!/bin/sh\necho "$1" >> %s/alerts\n' % tmp_path)
        key = tmp_path / 'key'
        key.write_text('k')
        if container:
            (gd / '_gd-tak-lib.sh').write_text(_sandbox((GD / '_gd-tak-lib.sh').read_text(), tmp_path, gd))
            (gd / 'guarddog.conf').write_text('{"tak_mode": "container"}')
        else:
            (gd / 'guarddog.conf').write_text('{"two_server": true, "db_host": "db1"}')
        script = (_sandbox((GD / 'tak-db-repack.sh').read_text(), tmp_path, gd)
                  .replace('DB_HOST_PLACEHOLDER', 'db1')
                  .replace('SSH_KEY_PLACEHOLDER', str(key))
                  .replace('SSH_USER_PLACEHOLDER', ssh_user)
                  .replace('ALERT_EMAIL_PLACEHOLDER', ''))
        sp = tmp_path / 'tak-db-repack.sh'
        sp.write_text(script)

        def run(force=False):
            if force:
                (tmp_path / 'state' / 'repack_force').write_text('')
            env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
            r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
            log = tmp_path / 'log' / 'restarts.log'
            apt = tmp_path / 'apt_calls'
            return (r.returncode, log.read_text() if log.exists() else '',
                    apt.read_text() if apt.exists() else '')
        return run
    return make


def test_non_root_ssh_user_installs_pg_repack_through_sudo_and_repacks(repack):
    rc, log, apt = repack(ssh_user='takdb')()
    assert 'install -y -qq postgresql-15-repack root=1' in apt   # was: root=0 -> Permission denied
    assert rc == 0, log
    assert 'pg_repack installed successfully' in log and 'DB-REPACK: completed' in log


def test_extension_package_matches_the_server_major_not_the_newest_client(repack):
    _, _, apt = repack()()
    assert 'postgresql-15-repack' in apt and 'postgresql-16-repack' not in apt


def test_weekly_timer_skips_cleanly_when_pg_repack_cannot_be_installed(repack):
    rc, log, _ = repack(pkg='no-such-package')()
    assert rc == 0                                              # was: 1 -> unit `failed` for good
    assert 'weekly repack skipped (clean)' in log and 'Unable to locate package' in log


def test_operator_online_compact_still_fails_loudly_when_pg_repack_is_unavailable(repack):
    rc, log, _ = repack(pkg='no-such-package')(force=True)
    assert rc == 1
    assert 'Online Compact cannot run here' in log and 'Unable to locate package' in log


def test_root_ssh_user_is_not_wrapped_in_sudo_for_the_install(repack):
    _, _, apt = repack(ssh_user='root')()
    # A root login runs apt-get directly (the test runner is not root, so the fake refuses
    # it; check the call, not the outcome).
    assert 'apt-get update -qq root=0' in apt


def test_container_mode_installs_pg_repack_as_root_inside_takserver_db(repack):
    # aws-arm, container TAK: the install ran as the image's USER (postgres) and was refused.
    rc, log, apt = repack(container=True)(force=True)
    assert 'install -y -qq postgresql-15-repack root=1' in apt
    assert rc == 0, log
    assert 'pg_repack installed successfully' in log and 'DB-REPACK: completed' in log


def test_container_mode_runs_pg_repack_and_psql_as_postgres_not_root(repack, tmp_path):
    repack(container=True)(force=True)
    calls = (tmp_path / 'docker_calls').read_text().splitlines()
    assert any('-u postgres takserver-db psql' in c for c in calls)
    assert any('-u postgres takserver-db' in c and 'pg_repack -d cot' in c for c in calls)
    assert all('-u ' in c for c in calls if c.startswith('docker exec'))   # never the image default


def test_install_refused_for_lack_of_root_is_not_reported_as_unsupported_platform(repack):
    rc, log, _ = repack(ssh_user='root')(force=True)              # root login, runner is not root
    assert rc == 1
    assert 'refused for lack of root' in log and 'Permission denied' in log
    assert 'not available on this platform' not in log


def test_two_server_postgres_commands_never_prompt_for_a_password():
    import re
    src = re.sub(r'(?m)^\s*#.*$', '', (GD / 'tak-db-repack.sh').read_text())
    assert 'sudo -u postgres' not in src
    assert src.count('sudo -n -u postgres') >= 3


# ─── diagnostics: the repack's reason reaches the report ─────────────────────

def test_diagnostics_guard_dog_section_shows_the_last_repack_lines(tmp_path):
    import os
    import re
    app = (REPO / 'app.py').read_text(encoding='utf-8')

    def cut(name):
        return re.search(rf'^def {name}\(.*?(?=^\S)', app, re.S | re.M).group(0)
    gd = tmp_path / 'gd'
    gd.mkdir()
    log = tmp_path / 'restarts.log'
    log.write_text('Sun Oct 11 04:00:09 UTC 2026: DB-REPACK: pg_repack failed (rc=1): ERROR: x\n'
                   + 'Sun Oct 18 00:50:43 UTC 2026: mgmt channel degraded (DB reachable) — no restart\n' * 40)
    ns = {'os': os, 're': re, '_DIAG_TAIL_BYTES': 1 << 20,
          '_diag_cmd': lambda *a, **k: 'tak-a.timer'}
    for n in ('_diag_tail', '_diag_unreadable'):
        exec(compile(cut(n), n, 'exec'), ns)
    src = cut('_diag_section_guarddog').replace("'/opt/tak-guarddog'", repr(str(gd))) \
                                       .replace("'/var/log/takguard/restarts.log'", repr(str(log)))
    exec(compile(src, 'gd', 'exec'), ns)
    out = ns['_diag_section_guarddog']({})
    assert any('pg_repack failed (rc=1)' in l for l in out)
