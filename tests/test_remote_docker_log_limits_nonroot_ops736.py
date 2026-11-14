"""Remote Docker log limits for a non-root SSH user (ops #736).

Before: `_ensure_docker_log_limits_remote()` copied a python script to /tmp and ran
`python3 /tmp/... 2>&1; rm -f /tmp/...` as the SSH user. For a non-root user (for example `ubuntu` or
`rocky`) python could not write /etc/docker/daemon.json. The trailing `rm` made the whole command
exit 0, so the deploy treated it as a success, printed nothing, and the host kept unlimited container
logs (the disk fills slowly).

These tests run the REAL function and the REAL script against a fake host: a fake `id` (the SSH
user's uid), a fake `sudo` that accepts only `sudo -n`, a fake `python3` that refuses to write
/etc/docker unless it ran as root, and a fake `systemctl`. "Refuses unless root" stands in for the
file permission the real host enforces, so the tests behave the same when run as root or not.
"""
import ast
import json
import pathlib
import shutil
import stat
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

CONST = '_DOCKER_LOG_LIMITS_REMOTE_PY'
HELPER = '_docker_log_limits_remote_cmd'
FUNC = '_ensure_docker_log_limits_remote'


def _node(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return node
    return None


def _load_function_under_test(fake_ssh_probe, fake_module_copy):
    """Compile the real function (and, once it exists, its constant and helper) out of app.py."""
    import base64 as _b64
    import os
    import shlex
    ns = {'os': os, 'shlex': shlex, '_b64': _b64, 'json': json,
          '_ssh_probe': fake_ssh_probe, '_module_copy': fake_module_copy}
    for name in (CONST, HELPER, FUNC):
        node = _node(name)
        if node is None:
            assert name != FUNC, f'{FUNC} not found at module level in app.py'
            continue
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py', 'exec'), ns)
    return ns[FUNC]


class FakeHost:
    """A remote host in a temp folder. `uid` is the SSH user; `sudo_ok` says if passwordless sudo works."""

    def __init__(self, tmp_path, uid, sudo_ok=True, daemon_json=None):
        self.tmp = tmp_path
        self.uid = uid
        self.etc_docker = tmp_path / 'etc' / 'docker'
        self.etc_docker.mkdir(parents=True)
        if daemon_json is not None:
            (self.etc_docker / 'daemon.json').write_text(json.dumps(daemon_json))
        (tmp_path / 'tmp').mkdir()
        (tmp_path / 'readonly.py').write_text(
            'import builtins\n'
            '_real_open = builtins.open\n'
            'def _ro(path, mode="r", *a, **k):\n'
            '    if any(c in mode for c in "wax+"):\n'
            '        raise PermissionError(13, "Permission denied", str(path))\n'
            '    return _real_open(path, mode, *a, **k)\n'
            'builtins.open = _ro\n')
        self.calls = tmp_path / 'calls.log'
        self.bindir = tmp_path / 'bin'
        self.bindir.mkdir()
        fakes = {
            'id': f'echo {uid}',
            # `sudo -n CMD...`: only the -n (never ask for a password) form is accepted.
            'sudo': ('[ "$1" = "-n" ] || { echo "sudo: a password is required" >&2; exit 1; }\n'
                     + ('shift\nSUDO_USED=1 exec "$@"' if sudo_ok else
                        'echo "sudo: a password is required" >&2; exit 1')),
            # What the file system does to a non-root user: reading /etc/docker is fine, writing is
            # refused. Root (uid 0 or through sudo) is not refused. The real script is run, with
            # /etc/docker pointed at the fake host's folder.
            'python3': ('src="$FAKE_TMP/script.$$.py"\n'
                        'if [ "$1" = "-" ]; then cat > "$src.in"; else cp "$1" "$src.in"; fi\n'
                        ': > "$src"\n'
                        'if [ "$SUDO_USED" != 1 ] && [ "$(id -u)" != 0 ]; then cat "$FAKE_TMP/readonly.py" > "$src"; fi\n'
                        'sed "s#/etc/docker#$FAKE_TMP/etc/docker#g" "$src.in" >> "$src"\n'
                        'exec "$REAL_PYTHON" "$src"'),
            'systemctl': f'echo "systemctl $*" >> {self.calls}',
            'rm': 'exec /bin/rm "$@"',
        }
        for name, body in fakes.items():
            f = self.bindir / name
            f.write_text('#!/bin/sh\n' + body + '\n')
            f.chmod(f.stat().st_mode | stat.S_IEXEC)

    # What the function under test sees as "the SSH session" and "scp".
    def ssh_probe(self, cfg, cmd, timeout=15):
        cmd = cmd.replace('/tmp/', f'{self.tmp}/tmp/')
        env = {'PATH': f'{self.bindir}:/usr/bin:/bin', 'FAKE_TMP': str(self.tmp),
               'REAL_PYTHON': sys.executable}
        r = subprocess.run(['/bin/sh', '-c', cmd], capture_output=True, text=True, env=env)
        if r.returncode == 0:
            return True, (r.stdout or '').strip()
        return False, ((r.stderr or '') + '\n' + (r.stdout or '')).strip()

    def module_copy(self, deploy_cfg, local_path, remote_path, timeout=30, log_fn=None):
        dest = pathlib.Path(remote_path.replace('/tmp/', f'{self.tmp}/tmp/'))
        shutil.copy2(local_path, dest)
        return True, 'ok'

    def daemon_json(self):
        p = self.etc_docker / 'daemon.json'
        return json.loads(p.read_text()) if p.exists() else None

    def restarts(self):
        return self.calls.read_text().count('systemctl restart docker') if self.calls.exists() else 0


def _run(host):
    logs = []
    fn = _load_function_under_test(host.ssh_probe, host.module_copy)
    result = fn({'host': '10.0.0.5', 'ssh_user': 'ubuntu'}, log_fn=logs.append)
    return result, '\n'.join(logs)


# --------------------------------------------------------------------------- the bug

def test_non_root_ssh_user_gets_log_limits_through_sudo(tmp_path):
    host = FakeHost(tmp_path, uid=1000)
    (ok, restarted), log = _run(host)
    assert host.daemon_json() == {'log-driver': 'json-file',
                                  'log-opts': {'max-size': '50m', 'max-file': '3'}}
    assert (ok, restarted) == (True, True)
    assert host.restarts() == 1
    assert 'Docker log limits set on remote (50 MB × 3)' in log


def test_non_root_ssh_user_keeps_the_other_daemon_json_keys(tmp_path):
    host = FakeHost(tmp_path, uid=1000, daemon_json={'live-restore': True, 'log-driver': 'local'})
    _run(host)
    d = host.daemon_json()
    assert d['live-restore'] is True
    assert d['log-driver'] == 'local'
    assert d['log-opts'] == {'max-size': '50m', 'max-file': '3'}


def test_non_root_ssh_user_without_sudo_is_told_why(tmp_path):
    """A failure is never silent: the deploy log says what to fix, and the function says it failed."""
    host = FakeHost(tmp_path, uid=1000, sudo_ok=False)
    (ok, restarted), log = _run(host)
    assert (ok, restarted) == (False, False)
    assert host.daemon_json() is None
    assert 'could not be applied' in log
    assert 'passwordless sudo' in log


def test_a_refused_write_is_never_reported_as_success(tmp_path):
    """The old command ended in `; rm -f`, so a failed python run still exited 0. python3's own exit
    code must decide the result."""
    host = FakeHost(tmp_path, uid=1000, sudo_ok=False)
    (ok, _), log = _run(host)
    assert ok is False
    assert 'Docker log limits set' not in log
    assert 'already set' not in log


# --------------------------------------------------------------------------- regression: what worked still works

def test_root_ssh_user_still_works_without_sudo(tmp_path):
    host = FakeHost(tmp_path, uid=0, sudo_ok=False)
    (ok, restarted), log = _run(host)
    assert (ok, restarted) == (True, True)
    assert host.daemon_json()['log-opts'] == {'max-size': '50m', 'max-file': '3'}
    assert 'Docker log limits set on remote' in log


@pytest.mark.parametrize('uid', [0, 1000])
def test_limits_already_set_changes_nothing(tmp_path, uid):
    present = {'log-driver': 'json-file', 'log-opts': {'max-size': '50m', 'max-file': '3'}}
    host = FakeHost(tmp_path, uid=uid, daemon_json=present)
    (ok, restarted), log = _run(host)
    assert (ok, restarted) == (True, False)
    assert host.restarts() == 0
    assert host.daemon_json() == present
    assert 'already set on remote' in log


def test_no_remote_host_is_a_no_op(tmp_path):
    host = FakeHost(tmp_path, uid=1000)
    fn = _load_function_under_test(host.ssh_probe, host.module_copy)
    assert fn({}, log_fn=None) == (True, False)
    assert fn({'host': '  '}, log_fn=None) == (True, False)


# --------------------------------------------------------------------------- the command itself

def test_command_leaves_no_file_in_tmp_for_another_user_to_swap():
    """Root runs this script, so it must not come from a predictable path in /tmp."""
    segment = ast.get_source_segment(APP, _node(FUNC))
    assert "/tmp/" not in segment
    assert '_module_copy' not in segment
    helper = _node(HELPER)
    assert helper is not None, f'{HELPER} is missing'
    assert '/tmp/' not in ast.get_source_segment(APP, helper)
