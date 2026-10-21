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
"""Split (two_server) box: Guard Dog's PostgreSQL probes on Server One connect as a real role (ops #132).

Field (10.2.24-alpha, split install): Server One's PostgreSQL log carried
  * `FATAL:  role "root" does not exist` twice every ~30 s: the health agent (a root service)
    ran a bare `pg_isready -q` on every /health poll, so it connected as role "root";
  * `FATAL:  no pg_hba.conf entry for host "<Server One>", user "root", database "root"`
    every 2 min: the remote-DB watcher ran `pg_isready -h DB_HOST` as the SSH user (root).
pg_isready still answered "accepting", so nothing looked wrong except the log.

The REAL scripts run here. ssh runs the remote command locally against a fake Server One
whose pg_isready records who asked and how.
"""

import hashlib
import importlib.util
import os
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
GD = REPO / 'scripts' / 'guarddog'
APP = (REPO / 'app.py').read_text(encoding='utf-8')

SSH_STUB = '#!/bin/bash\ncmd="${@: -1}"\nexec bash -c "$cmd"\n'

# pg_isready: records "<as> <args>"; rc per target: -h = TCP, else the local socket.
PG_ISREADY_STUB = r'''#!/bin/bash
echo "${PG_AS:-sshuser} $*" >> "%(dir)s/pg_calls"
read -r TCP SOCK < "%(dir)s/pg_mode"
case " $* " in
  *" -h "*) rc=$TCP; where="db1:5432" ;;
  *)        rc=$SOCK; where="/var/run/postgresql:5432" ;;
esac
case $rc in 0) echo "$where - accepting connections" ;; 1) echo "$where - rejecting connections" ;;
            2) echo "$where - no response" ;; esac
exit $rc
'''

# sudo: `-n -u postgres X` runs X as postgres, unless sudo_mode says this user may not.
SUDO_STUB = r'''#!/bin/bash
as=root
while [ "${1#-}" != "$1" ]; do
  case "$1" in -u) as=$2; shift 2 ;; *) shift ;; esac
done
if [ "$(cat "%(dir)s/sudo_mode")" = refuse ]; then
  echo "sudo: a password is required" >&2; exit 1
fi
case "$*" in *pg_ctlcluster*|*restart*) echo RESTART >> "%(dir)s/restarts"; exit 1 ;; esac
PG_AS=$as exec "$@"
'''


def _stub(path, text):
    path.write_text(text)
    path.chmod(0o755)


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
    _stub(gd / 'send-alert-email.sh', '#!/bin/sh\nexit 0\n')
    key = tmp_path / 'key'
    key.write_text('k')
    script = ((GD / 'tak-remotedb-watch.sh').read_text()
              .replace('/var/lib/takguard', str(tmp_path / 'state'))
              .replace('/var/log/takguard', str(tmp_path / 'log'))
              .replace('/opt/tak-guarddog/', str(gd) + '/')
              .replace('/opt/tak-guarddog', str(gd))
              .replace('DB_HOST_PLACEHOLDER', 'db1')
              .replace('DB_PORT_PLACEHOLDER', '5432')
              .replace('SSH_KEY_PLACEHOLDER', str(key))
              .replace('SSH_USER_PLACEHOLDER', 'root')
              .replace('EXTERNAL_DB_PLACEHOLDER', '')
              .replace('ALERT_EMAIL_PLACEHOLDER', ''))
    sp = tmp_path / 'tak-remotedb-watch.sh'
    sp.write_text(script)

    def run(tcp, tcp_rc, sock_rc, sudo='allow', times=1):
        (tmp_path / 'tcp').write_text(tcp)
        (tmp_path / 'pg_mode').write_text(f'{tcp_rc} {sock_rc}\n')
        (tmp_path / 'sudo_mode').write_text(sudo)
        calls = tmp_path / 'pg_calls'
        if calls.exists():
            calls.unlink()
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        for _ in range(times):
            r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
            assert r.returncode == 0, r.stderr
        log = tmp_path / 'log' / 'restarts.log'
        rs = tmp_path / 'restarts'
        return ((calls.read_text().splitlines() if calls.exists() else []),
                (log.read_text() if log.exists() else ''),
                (len(rs.read_text().split()) if rs.exists() else 0))
    return run


def _args(call):
    return call.split()[1:]


def test_healthy_db_is_asked_once_as_postgres_over_the_socket(watch):
    calls, log, _ = watch('up', 0, 0, times=3)
    assert len(calls) == 3
    for c in calls:
        assert c.startswith('postgres ')                        # was: root, over TCP
        assert '-h' not in _args(c) and _args(c)[-2:] == ['-p', '5432']
    assert log == ''


def test_socket_not_up_still_asks_the_endpoint_tak_uses(watch):
    # PostgreSQL in a container / DB_HOST not local: no socket, TCP answers.
    calls, log, _ = watch('up', 0, 2)
    assert [c.split()[0] for c in calls] == ['postgres', 'sshuser']
    assert '-h' in _args(calls[1])
    assert log == ''


def test_a_sudo_refusal_is_not_read_as_rejecting(watch):
    # sudo exits 1 — the same number as pg_isready "rejecting". It must not count as an answer.
    calls, log, _ = watch('up', 0, 0, sudo='refuse')
    assert calls and all(c.startswith('sshuser ') for c in calls)
    assert 'pg_isready rc=1' not in log


def test_without_sudo_the_old_socket_fallback_still_guards_the_restart(watch):
    # TCP from here is down and DB_HOST does not route back to itself, but the socket says up.
    _, log, restarts = watch('down', 2, 0, sudo='refuse', times=6)
    assert restarts == 0
    assert 'network path' in log


def test_confirmed_down_is_still_restarted(watch):
    _, log, restarts = watch('down', 2, 2, times=6)
    assert restarts >= 1
    assert 'confirmed down' in log


# ─── tak-db-health-agent.py ───────────────────────────────────────────────────

def test_health_agent_runs_pg_isready_as_postgres(monkeypatch):
    spec = importlib.util.spec_from_file_location('tak_db_health_agent_t', GD / 'tak-db-health-agent.py')
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    seen = []

    class R:
        returncode = 0
        stdout = ' cot | postgres | UTF8\n'

    def fake_run(argv, **kw):
        seen.append(argv)
        r = R()
        if argv[0] == 'df':
            r.stdout = 'Use%\n 12%\n'
        return r
    monkeypatch.setattr(agent.subprocess, 'run', fake_run)
    checks = agent.DBHealthHandler._check(None)
    assert checks['healthy'] is True
    pg = [a for a in seen if a[-1] == '-q']
    assert pg == [['sudo', '-u', 'postgres', agent._PG_ISREADY, '-q']]


# ─── delivery: Guard Dog Update refreshes an installed agent ─────────────────

def _refresh_fn(remote_sha, scp_ok=True):
    src = re.search(r'^def _refresh_health_agent_on_server_one\(.*?(?=^def )', APP, re.S | re.M).group(0)
    cmds, scps = [], []

    def probe(cfg, cmd, timeout=15):
        cmds.append(cmd)
        if cmd.startswith('sha256sum'):
            if remote_sha is None:
                return True, 'NOT_INSTALLED'
            return True, f'{remote_sha}  /opt/tak-guarddog/tak-db-health-agent.py'
        return True, 'AGENT_OK'

    def scp(cfg, local, remote, timeout=120):
        scps.append((local, remote))
        return scp_ok, ''
    ns = {'os': os, 'hashlib': hashlib, 'BASE_DIR': str(REPO), '_ssh_probe': probe, '_scp_to_host': scp}
    exec(compile(src, 'app.py:refresh', 'exec'), ns)
    return ns['_refresh_health_agent_on_server_one'], cmds, scps


CURRENT = hashlib.sha256((GD / 'tak-db-health-agent.py').read_bytes()).hexdigest()


def test_update_replaces_an_out_of_date_agent_and_restarts_it():
    fn, cmds, scps = _refresh_fn('0' * 64)
    changed, _ = fn({'host': 'db1'})
    assert changed and len(scps) == 1
    assert 'systemctl restart tak-db-health.service' in cmds[-1]
    assert not any(('ufw' in c or 'firewall-cmd' in c) for c in cmds)   # no firewall churn


def test_update_leaves_a_current_agent_alone():
    fn, cmds, scps = _refresh_fn(CURRENT)
    changed, msg = fn({'host': 'db1'})
    assert not changed and scps == [] and len(cmds) == 1 and msg == 'already current'


def test_update_does_not_install_an_agent_that_was_never_deployed():
    fn, _, scps = _refresh_fn(None)
    changed, _ = fn({'host': 'db1'})
    assert not changed and scps == []


def test_guarddog_update_route_calls_the_refresh_for_two_server():
    body = re.search(r'^def guarddog_update\(\):.*?(?=^@app\.route)', APP, re.S | re.M).group(0)
    assert '_refresh_health_agent_on_server_one(' in body
    assert "== 'two_server'" in body
