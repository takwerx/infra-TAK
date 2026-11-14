"""Remote deploys install Docker for a non-root SSH user (ops #735).

Before: the remote WebODM, Node-RED and Authentik deploys sent the Docker install command with no
`sudo -n` in front of it. As a non-root SSH user on a host with no Docker, dnf/apt-get answered "This
command has to be run with superuser privileges" and the deploy stopped with "Failed to install
Docker". Only the CloudTAK remote deploy passed `sudo_fallback=True`.

Two kinds of test:
  * `_docker_install_cmd()` calls: every call that is sent to a remote host must pass
    `sudo_fallback=True`. The only call allowed without it is the local root one in
    `_install_docker_engine`.
  * Behaviour: take the argument each remote deploy really passes, build the command from it, and run
    that command as a non-root user (fake `id` = 1000, fake `sudo -n`, and a fake `dnf` that refuses
    unless it ran through sudo). The install must succeed.
"""
import ast
import pathlib
import shlex
import stat
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

REMOTE_DEPLOYS = ['_run_webodm_deploy_remote', '_run_nodered_deploy_remote', '_run_authentik_deploy_remote']
LOCAL_ROOT_ONLY = '_install_docker_engine'


def _func(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f'{name} not found at module level in app.py')


def _segment(name):
    return ast.get_source_segment(APP, _func(name))


def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found at module level in app.py')


def _install_cmd_calls(func_node):
    return [n for n in ast.walk(func_node)
            if isinstance(n, ast.Call) and getattr(n.func, 'id', None) == '_docker_install_cmd']


def _call_kwargs(call):
    """The keyword arguments a call passes, read from the source (they are all literals)."""
    return {k.arg: ast.literal_eval(k.value) for k in call.keywords}


# --------------------------------------------------------------------------- call sites

@pytest.mark.parametrize('name', REMOTE_DEPLOYS)
def test_remote_deploy_asks_for_the_sudo_form_of_the_docker_install(name):
    calls = _install_cmd_calls(_func(name))
    assert calls, f'{name} no longer installs Docker with _docker_install_cmd()'
    for call in calls:
        assert _call_kwargs(call).get('sudo_fallback') is True, (
            f'{name} line {call.lineno}: the remote Docker install must pass sudo_fallback=True, or it '
            f'fails for a non-root SSH user')


def test_only_the_local_root_install_may_skip_sudo_fallback():
    """A new remote deploy that copies the old pattern fails here."""
    for node in TREE.body:
        if not isinstance(node, ast.FunctionDef) or node.name == LOCAL_ROOT_ONLY:
            continue
        for call in _install_cmd_calls(node):
            assert _call_kwargs(call).get('sudo_fallback') is True, (
                f'{node.name} line {call.lineno}: _docker_install_cmd() without sudo_fallback=True is '
                f'only for the local root install in {LOCAL_ROOT_ONLY}')


# --------------------------------------------------------------------------- behaviour as a non-root user

def _run_as_non_root(cmd, tmp_path):
    """Run a Docker install command as uid 1000 on a fake RHEL-family host (no /etc/debian_version).
    Returns (completed process, calls that really reached dnf/systemctl)."""
    for sub in ('etc/yum.repos.d',):
        (tmp_path / sub).mkdir(parents=True)
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    log = tmp_path / 'calls.log'
    fakes = {
        'id': 'echo 1000',
        # `sudo -n CMD...`: only the -n (never ask for a password) form is accepted.
        'sudo': '[ "$1" = "-n" ] || { echo "sudo: a password is required" >&2; exit 1; }\n'
                'shift\nSUDO_USED=1 exec "$@"',
        # The same refusal the box gave in ops #735.
        'dnf': '[ "$SUDO_USED" = 1 ] || { echo "Error: This command has to be run with superuser '
               'privileges" >&2; exit 1; }\n'
               f'echo "dnf $*" >> {log}',
        'systemctl': '[ "$SUDO_USED" = 1 ] || { echo "Failed to connect to bus" >&2; exit 1; }\n'
                     f'echo "systemctl $*" >> {log}',
    }
    for name, body in fakes.items():
        f = bindir / name
        f.write_text('#!/bin/sh\n' + body + '\n')
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    cmd = cmd.replace('/etc/', f'{tmp_path}/etc/')
    r = subprocess.run(['/bin/sh', '-c', cmd + ' 2>&1'], capture_output=True, text=True,
                       env={'PATH': f'{bindir}:/usr/bin:/bin'})
    return r, (log.read_text() if log.exists() else '')


def _command_a_deploy_sends(name):
    """_docker_install_cmd(**kwargs) with the kwargs the named deploy really passes."""
    ns = {'shlex': shlex, 'DOCKER_APT_KEY_FPR': _const('DOCKER_APT_KEY_FPR')}
    exec(compile(_segment('_docker_install_script'), 'app.py', 'exec'), ns)
    exec(compile(_segment('_docker_install_cmd'), 'app.py', 'exec'), ns)
    calls = _install_cmd_calls(_func(name))
    assert len(calls) == 1, f'{name}: expected one _docker_install_cmd() call, found {len(calls)}'
    return ns['_docker_install_cmd'](**_call_kwargs(calls[0]))


@pytest.mark.parametrize('name', REMOTE_DEPLOYS)
def test_the_command_a_remote_deploy_sends_installs_docker_for_a_non_root_user(name, tmp_path):
    r, calls = _run_as_non_root(_command_a_deploy_sends(name), tmp_path)
    assert r.returncode == 0, f'{name}: {r.stdout}'
    assert 'superuser privileges' not in r.stdout
    assert 'dnf -y install docker-ce docker-ce-cli containerd.io' in calls
    assert 'systemctl enable --now docker' in calls


def test_the_root_form_still_has_no_sudo_in_it_for_a_root_ssh_user():
    """With sudo_fallback, a root SSH user must still run the script directly (no sudo needed)."""
    ns = {'shlex': shlex, 'DOCKER_APT_KEY_FPR': _const('DOCKER_APT_KEY_FPR')}
    exec(compile(_segment('_docker_install_script'), 'app.py', 'exec'), ns)
    exec(compile(_segment('_docker_install_cmd'), 'app.py', 'exec'), ns)
    cmd = ns['_docker_install_cmd'](sudo_fallback=True)
    assert cmd.startswith('if [ "$(id -u)" = 0 ]; then ')
    assert '; else sudo -n ' in cmd
    assert 'sudo' not in ns['_docker_install_cmd']()
