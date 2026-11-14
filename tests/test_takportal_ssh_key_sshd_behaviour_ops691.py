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
"""ops #691: prove what the TAK Portal key line DOES, against a real sshd.

10.3.12 shipped a portal key line (`restrict,from="..."`) that every string-match test agreed
with, and every TAK Portal Marketplace install failed: `restrict` also turns off the terminal
that TAK Portal's plugin worker asks for (ops #644, ops #687). This test does not compare
strings. It takes the line app.py's own writer produces, puts it in a real OpenSSH server, and
connects the way TAK Portal does:

  * from a container on a Docker network (TAK Portal reaches the host from its own network),
  * SFTP upload of a job script to /tmp with mode 600 (TAK Portal's sftpWriteUtf8),
  * run it with a terminal (TAK Portal's execOverSsh asks for a pty; `ssh -tt` is the same),
    then delete it, the way runBashScript does.

It also proves the line still does its security job: no port forwarding, and a source outside
from= is refused. The 10.3.12 line must FAIL the same check (the canary): if it ever passes,
the check has gone blind.

Needs Docker. GitHub's runners have it; on a machine without Docker the test is skipped, but in
CI (GITHUB_ACTIONS=true) a missing Docker is a failure, never a silent skip.
"""

import ast
import os
import pathlib
import re
import shutil
import subprocess
import uuid

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

# Alpine 3.20, pinned to the multi-arch index digest (amd64 CI runners, arm64 Macs).
BASE_IMAGE = 'alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc'
IMAGE = 'infratak-ci-portal-sshd:ops691'
USER = 'takwerx'          # the console user TAK Portal logs in as
KEY = '/root/portal_key'  # the portal's private key, inside the client container
SFTP_SERVER = '/usr/lib/ssh/sftp-server'  # an external sftp-server, as on Ubuntu and Rocky

DOCKERFILE = f'''FROM {BASE_IMAGE}
RUN apk add --no-cache bash openssh-client openssh-server openssh-sftp-server \\
 && adduser -D -s /bin/bash {USER} \\
 && sed -i 's/^{USER}:!/{USER}:*/' /etc/shadow \\
 && install -d -m 700 -o {USER} -g {USER} /home/{USER}/.ssh \\
 && ssh-keygen -A
COPY sshd_config /etc/ssh/sshd_config
'''

# Forwarding and terminals are left ON at the server (OpenSSH's defaults, as on our boxes), so
# anything that stops them here is the key line's own options.
SSHD_CONFIG = f'''Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AuthorizedKeysFile .ssh/authorized_keys
AllowTcpForwarding yes
PermitTTY yes
Subsystem sftp {SFTP_SERVER}
LogLevel VERBOSE
'''

# What a Marketplace job does on the host, cut down: it prints progress to the terminal it was
# given. The marker proves the script ran; `tty` proves it had a terminal.
JOB_SCRIPT = '#!/bin/bash\nset -e\necho "job-tty:$(tty)"\necho MARKETPLACE-JOB-OK\n'
REMOTE_JOB = '/tmp/ctak-mp-ops691.sh'


# ------------------------------------------------------------------ app.py's own writer
def _src(kind, name):
    for n in ast.walk(TREE):
        if (kind == 'def' and isinstance(n, ast.FunctionDef) and n.name == name) or \
           (kind == 'const' and isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets)):
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} is missing from app.py')


def _writer():
    ns = {'os': os, 're': re}
    src = '\n\n'.join([_src('const', c) for c in ('TAKPORTAL_SSH_KEY_COMMENT', '_AUTHKEY_TYPE_RE')]
                      + [_src('def', f) for f in ('_authorized_keys_split', '_takportal_ssh_key_options',
                                                   '_takportal_authorized_keys_text')])
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns['_takportal_authorized_keys_text']


# --------------------------------------------------------------------------- docker helpers
def _run(cmd, input_text=None, timeout=60):
    return subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout)


def _need_docker():
    why = None
    if not shutil.which('docker'):
        why = 'docker is not installed'
    else:
        try:
            r = _run(['docker', 'info', '--format', '{{.ServerVersion}}'], timeout=30)
            if r.returncode != 0:
                why = 'docker daemon is not reachable: ' + (r.stderr.strip() or r.stdout.strip())[:200]
        except subprocess.TimeoutExpired:
            why = 'docker info timed out'
    if why:
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            pytest.fail(f'ops #691 behaviour test needs Docker in CI and {why}')
        pytest.skip(f'needs Docker ({why})')


class Lab:
    """One sshd container (the host) and one client container (TAK Portal) on a Docker network."""

    def __init__(self, tmp):
        tag = uuid.uuid4().hex[:10]
        self.net = f'ops691-net-{tag}'
        self.srv = f'ops691-sshd-{tag}'
        self.cli = f'ops691-portal-{tag}'
        ctx = tmp / 'ctx'
        ctx.mkdir()
        (ctx / 'Dockerfile').write_text(DOCKERFILE)
        (ctx / 'sshd_config').write_text(SSHD_CONFIG)
        b = _run(['docker', 'build', '-q', '-t', IMAGE, str(ctx)], timeout=600)
        assert b.returncode == 0, 'image build failed:\n' + b.stdout + b.stderr
        self._ok(['docker', 'network', 'create', self.net])
        insp = self._ok(['docker', 'network', 'inspect', self.net,
                         '--format', '{{range .IPAM.Config}}{{.Subnet}} {{end}}'])
        self.subnets = [s for s in insp.split() if ':' not in s]
        assert self.subnets, f'no IPv4 subnet on {self.net}: {insp!r}'
        self._ok(['docker', 'run', '-d', '--rm', '--name', self.srv, '--network', self.net,
                  IMAGE, '/usr/sbin/sshd', '-D', '-e'])
        self._ok(['docker', 'run', '-d', '--rm', '--name', self.cli, '--network', self.net,
                  IMAGE, 'sleep', '1800'])
        self._ok(['docker', 'exec', self.cli, 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                  '-C', 'tak-portal-auto', '-f', KEY])
        self.pub = self._ok(['docker', 'exec', self.cli, 'cat', KEY + '.pub']).strip()
        self._ok(['docker', 'exec', '-i', self.cli, 'sh', '-c', 'cat > /root/job.sh'], JOB_SCRIPT)
        for _ in range(60):
            if _run(['docker', 'exec', self.cli, 'sh', '-c', f'nc -z -w 1 {self.srv} 22']).returncode == 0:
                break
        else:
            raise AssertionError('sshd never listened:\n' + self.logs())

    def _ok(self, cmd, input_text=None):
        r = _run(cmd, input_text)
        assert r.returncode == 0, f'{cmd} failed:\n{r.stdout}{r.stderr}'
        return r.stdout

    def logs(self):
        return _run(['docker', 'logs', '--tail', '40', self.srv]).stderr

    def trust(self, authorized_keys_text):
        """Install the console user's authorized_keys exactly as given (owner, mode 600)."""
        ak = f'/home/{USER}/.ssh/authorized_keys'
        self._ok(['docker', 'exec', '-i', self.srv, 'sh', '-c',
                  f'cat > {ak} && chown {USER}:{USER} {ak} && chmod 600 {ak}'], authorized_keys_text)

    def ssh(self, *args, input_text=None, timeout=60):
        base = ['docker', 'exec', '-i', self.cli, 'ssh', '-i', KEY, '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'ConnectTimeout=10']
        return _run(base + list(args), input_text, timeout)

    def sftp_put(self, local, remote):
        batch = f'put {local} {remote}\nchmod 600 {remote}\n'
        return _run(['docker', 'exec', '-i', self.cli, 'sftp', '-b', '-', '-i', KEY,
                     '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                     '-o', 'UserKnownHostsFile=/dev/null', f'{USER}@{self.srv}'], batch)

    def close(self):
        for c in (self.cli, self.srv):
            _run(['docker', 'rm', '-f', c])
        _run(['docker', 'network', 'rm', self.net])


@pytest.fixture(scope='module')
def lab(tmp_path_factory):
    _need_docker()
    lab = Lab(tmp_path_factory.mktemp('ops691'))
    try:
        yield lab
    finally:
        lab.close()


# ---------------------------------------------------------------- what TAK Portal needs
def _portal_marketplace_job(lab):
    """TAK Portal's Marketplace path. Returns (ok, transcript)."""
    out = []
    t = lab.ssh('-tt', f'{USER}@{lab.srv}', 'tty')
    out.append(f'$ ssh -tt tty -> rc {t.returncode}\n{t.stdout}{t.stderr}')
    if t.returncode != 0 or '/dev/pts/' not in t.stdout:
        return False, '\n'.join(out)
    up = lab.sftp_put('/root/job.sh', REMOTE_JOB)
    out.append(f'$ sftp put {REMOTE_JOB} -> rc {up.returncode}\n{up.stdout}{up.stderr}')
    if up.returncode != 0:
        return False, '\n'.join(out)
    run = lab.ssh('-tt', f'{USER}@{lab.srv}',
                  f'bash {REMOTE_JOB}; ec=$?; rm -f {REMOTE_JOB}; exit $ec')
    out.append(f'$ ssh -tt bash job -> rc {run.returncode}\n{run.stdout}{run.stderr}')
    if run.returncode != 0 or 'MARKETPLACE-JOB-OK' not in run.stdout or 'job-tty:/dev/pts/' not in run.stdout:
        return False, '\n'.join(out)
    gone = lab.ssh(f'{USER}@{lab.srv}', f'test ! -e {REMOTE_JOB}')
    out.append(f'$ job file removed -> rc {gone.returncode}')
    return gone.returncode == 0, '\n'.join(out)


def _line_for(lab, existing, sources):
    text, _, _ = _writer()(existing, lab.pub, sources)
    return text


# ------------------------------------------------------------------------------- tests
def test_writer_line_runs_a_marketplace_job(lab):
    """The line the console writes on a fresh install lets TAK Portal run a Marketplace job."""
    text = _line_for(lab, '', lab.subnets)
    lab.trust(text)
    ok, transcript = _portal_marketplace_job(lab)
    assert ok, f'TAK Portal could not run a Marketplace job with this line:\n{text}\n{transcript}\n{lab.logs()}'


def test_heal_of_a_10_3_12_box_runs_a_marketplace_job(lab):
    """A box updated from 10.3.12: the console-start rewrite of the old line must work too."""
    old = f'restrict,from="127.0.0.1,::1,{",".join(lab.subnets)}" {lab.pub}\n'
    text = _line_for(lab, old, lab.subnets)
    lab.trust(text)
    ok, transcript = _portal_marketplace_job(lab)
    assert ok, f'the healed line still breaks TAK Portal:\n{text}\n{transcript}'


def test_canary_the_10_3_12_line_is_caught(lab):
    """The exact line 10.3.12 shipped must FAIL the check. If it passes, the check is blind."""
    lab.trust(f'restrict,from="127.0.0.1,::1,{",".join(lab.subnets)}" {lab.pub}\n')
    ok, transcript = _portal_marketplace_job(lab)
    assert not ok, 'the 10.3.12 line passed the Marketplace check: the check no longer sees the bug\n' + transcript


def test_writer_line_still_blocks_port_forwarding(lab):
    """`pty` is the only thing turned back on: the key still cannot be used as a tunnel."""
    lab.trust(_line_for(lab, '', lab.subnets))
    r = lab.ssh('-W', f'{lab.srv}:22', f'{USER}@{lab.srv}', input_text='', timeout=30)
    assert r.returncode != 0 and 'SSH-2.0-' not in r.stdout, f'port forwarding worked:\n{r.stdout}{r.stderr}'


def test_canary_forwarding_works_without_restrict(lab):
    """Control for the test above: a bare key line DOES forward, so the -W check can see it."""
    lab.trust(lab.pub + '\n')
    r = lab.ssh('-W', f'{lab.srv}:22', f'{USER}@{lab.srv}', input_text='', timeout=30)
    assert 'SSH-2.0-' in r.stdout, f'the forwarding check is blind:\n{r.stdout}{r.stderr}'


def test_writer_line_refuses_a_source_outside_from(lab):
    """from= still limits who can use the key: a portal network that is not listed gets nothing."""
    text = _line_for(lab, '', ['192.0.2.0/24'])      # TEST-NET-1, never the lab's network
    assert '192.0.2.0/24' in text
    lab.trust(text)
    r = lab.ssh(f'{USER}@{lab.srv}', 'true')
    assert r.returncode == 255 and 'Permission denied' in r.stderr, f'login from outside from= worked:\n{r.stdout}{r.stderr}'
