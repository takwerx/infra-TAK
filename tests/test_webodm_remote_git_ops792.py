"""Remote WebODM deploy installs `git` on the remote host before it clones the overlay plugin (ops #792).

Before: `_run_webodm_deploy_remote` ran `git clone` on the remote host and never installed git. A stock
Rocky Linux 9 server image has no git, so the deploy stopped at "Installing TAK overlay plugin (remote)"
with `bash: line 1: git: command not found`. Ubuntu cloud images ship git, so only RHEL-family hosts hit it.

Two kinds of test:
  * Call order: the remote deploy must call `_remote_ensure_git` before the `git clone` command.
  * Behaviour: run the real command text (`_REMOTE_GIT_ENSURE_SH`) on fake hosts (RHEL family, Debian
    family, root and non-root SSH user, git present and missing) and check git ends up installed
    through the right package manager, with `sudo -n` for a non-root user.
"""
import ast
import pathlib
import stat
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _func(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f'{name} not found at module level in app.py')


def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found at module level in app.py')


# --------------------------------------------------------------------------- call order

def test_remote_webodm_deploy_ensures_git_before_it_clones():
    src = ast.get_source_segment(APP, _func('_run_webodm_deploy_remote'))
    assert '_remote_ensure_git(' in src, 'the remote WebODM deploy never makes sure git is on the host'
    assert src.index('_remote_ensure_git(') < src.index('git clone'), \
        'git must be installed before the remote deploy runs git clone'


def test_remote_ensure_git_stops_the_deploy_when_git_cannot_be_installed():
    src = ast.get_source_segment(APP, _func('_run_webodm_deploy_remote'))
    after = src[src.index('_remote_ensure_git('):src.index('git clone')]
    assert "'error': True" in after and 'return' in after, \
        'a failed git install must end the deploy with an error, not carry on to git clone'


def test_remote_ensure_git_does_nothing_for_a_local_target():
    ns = {}
    exec(compile(ast.get_source_segment(APP, _func('_remote_ensure_git')), 'app.py', 'exec'), ns)
    assert ns['_remote_ensure_git']({'target_mode': 'local'}) == (True, '')


# --------------------------------------------------------------------------- behaviour on fake hosts

def _fake_host(tmp_path, *, uid, family, git_present):
    """Build a bin dir that is the host's whole PATH. `family` is 'rhel' (dnf) or 'debian' (apt-get).
    The package manager refuses unless it ran through `sudo -n` (as for a non-root user) or the user is
    root, and a successful `install ... git` creates a working `git`. Returns (bindir, log)."""
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    log = tmp_path / 'calls.log'
    refuse = ('[ "$SUDO_USED" = 1 ] || [ "$(id -u)" = 0 ] || '
              '{ echo "Error: This command has to be run with superuser privileges" >&2; exit 1; }\n')
    make_git = f'printf "#!/bin/sh\\necho git version 2.43.0\\n" > {bindir}/git; chmod +x {bindir}/git\n'
    fakes = {
        'id': f'echo {uid}',
        'sudo': '[ "$1" = "-n" ] || { echo "sudo: a password is required" >&2; exit 1; }\n'
                'shift\nSUDO_USED=1 exec "$@"',
        'env': 'while [ "${1#*=}" != "$1" ]; do export "$1"; shift; done\nexec "$@"',
    }
    if family == 'rhel':
        fakes['dnf'] = refuse + f'echo "dnf $*" >> {log}\n' + make_git
    else:
        fakes['apt-get'] = (refuse + f'echo "apt-get $*" >> {log}\n' +
                            '[ "$1" = update ] || { ' + make_git + '}')
    (bindir / 'chmod').symlink_to('/bin/chmod')   # the fake package managers need it to make git runnable
    if git_present:
        fakes['git'] = 'echo git version 2.43.0'
    for name, body in fakes.items():
        f = bindir / name
        f.write_text('#!/bin/sh\n' + body + '\n')
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    return bindir, log


def _run(tmp_path, **kw):
    bindir, log = _fake_host(tmp_path, **kw)
    r = subprocess.run(['/bin/sh', '-c', _const('_REMOTE_GIT_ENSURE_SH')],
                       capture_output=True, text=True, env={'PATH': str(bindir)})
    return r, (log.read_text() if log.exists() else '')


@pytest.mark.parametrize('uid', [0, 1000])
def test_rhel_host_without_git_gets_git_through_dnf(tmp_path, uid):
    r, calls = _run(tmp_path, uid=uid, family='rhel', git_present=False)
    assert r.returncode == 0, r.stdout
    assert 'git: command not found' not in r.stdout
    assert 'dnf install -y git' in calls
    assert 'git version' in r.stdout, 'the command must end by proving git runs'


@pytest.mark.parametrize('uid', [0, 1000])
def test_debian_host_without_git_gets_git_through_apt(tmp_path, uid):
    r, calls = _run(tmp_path, uid=uid, family='debian', git_present=False)
    assert r.returncode == 0, r.stdout
    assert 'apt-get update' in calls
    assert 'apt-get install -y git' in calls
    assert 'git version' in r.stdout


def test_host_that_already_has_git_runs_no_package_manager(tmp_path):
    r, calls = _run(tmp_path, uid=1000, family='rhel', git_present=True)
    assert r.returncode == 0, r.stdout
    assert calls == '', 'git is already there: nothing should be installed'
    assert 'git version' in r.stdout


def test_a_failed_install_fails_the_command_with_a_reason(tmp_path):
    """A package manager that cannot install git must make the command fail, never pass silently."""
    bindir, _ = _fake_host(tmp_path, uid=1000, family='rhel', git_present=False)
    (bindir / 'dnf').write_text('#!/bin/sh\necho "Error: no space left on device" >&2\nexit 1\n')
    r = subprocess.run(['/bin/sh', '-c', _const('_REMOTE_GIT_ENSURE_SH')],
                       capture_output=True, text=True, env={'PATH': str(bindir)})
    assert r.returncode != 0
    assert 'no space left on device' in r.stdout


def test_host_with_no_package_manager_fails_with_a_clear_message(tmp_path):
    bindir, _ = _fake_host(tmp_path, uid=0, family='rhel', git_present=False)
    (bindir / 'dnf').unlink()
    r = subprocess.run(['/bin/sh', '-c', _const('_REMOTE_GIT_ENSURE_SH')],
                       capture_output=True, text=True, env={'PATH': str(bindir)})
    assert r.returncode != 0
    assert 'install git by hand' in r.stdout
