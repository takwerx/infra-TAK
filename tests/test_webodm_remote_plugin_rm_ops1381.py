"""Remote WebODM Reapply removes the old overlay plugin folder as root (ops #1381).

Before: `_run_webodm_deploy_remote` ran `rm -rf ~/webodm/plugins/webodm-tak-overlay` as the SSH user. The
running WebODM container is root and writes `__pycache__/*.pyc` into that bind-mounted folder, so for a
non-root SSH user (ubuntu, rocky, azureuser) the second Deploy or Reapply stopped at
"Plugin clone failed: ... __pycache__/__init__.cpython-314.pyc: Permission denied". Root SSH users never
failed. The local deploy already removes the folder through the broker.

Two kinds of test:
  * Structure: the remote deploy no longer runs a plain `rm -rf` in its clone command; it clears the folder
    through `_webodm_plugin_clear_sh` (root wrapper) before `git clone`, and a failed clear ends the deploy.
  * Behaviour: run the real command text on a fake host where `rm` refuses unless it runs as root or under
    `sudo -n` (like a root-owned `__pycache__` for a non-root user).
"""
import ast
import pathlib
import shlex
import stat
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _func(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f'{name} not found at module level in app.py')


def _src(name):
    return ast.get_source_segment(APP, _func(name))


# --------------------------------------------------------------------------- structure

def test_remote_deploy_clone_command_has_no_plain_rm():
    src = _src('_run_webodm_deploy_remote')
    clone_cmd = src[src.index("f'git clone --depth=1"):src.index("timeout=90")]
    assert 'rm -rf' not in clone_cmd, 'the clone command must not delete the plugin folder as the SSH user'


def test_remote_deploy_clears_the_plugin_folder_as_root_before_it_clones():
    src = _src('_run_webodm_deploy_remote')
    assert '_webodm_plugin_clear_sh(' in src, 'the remote deploy never clears the old plugin folder as root'
    assert src.index('_webodm_plugin_clear_sh(') < src.index('git clone'), \
        'the old folder must be gone before git clone runs'


def test_a_failed_clear_ends_the_deploy_with_an_error():
    src = _src('_run_webodm_deploy_remote')
    after = src[src.index('_webodm_plugin_clear_sh('):src.index('git clone')]
    assert "'error': True" in after and 'return' in after, \
        'if the old folder cannot be removed the deploy must stop, not carry on to git clone'


def test_the_clear_command_goes_through_the_root_wrapper():
    src = _src('_webodm_plugin_clear_sh')
    assert '_as_root_sh(' in src


# --------------------------------------------------------------------------- behaviour on a fake host

def _helpers():
    ns = {'shlex': shlex}
    for name in ('_as_root_sh', '_webodm_plugin_clear_sh'):
        exec(compile(_src(name), 'app.py', 'exec'), ns)
    return ns


def _fake_host(tmp_path, *, uid, sudo_works=True):
    """A bin dir that is the host's whole PATH. `rm` refuses unless the user is root or it ran under
    `sudo -n` (the root-owned __pycache__ case); `id` reports `uid`. Returns (bindir, log)."""
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    log = tmp_path / 'calls.log'
    fakes = {
        'id': f'echo {uid}',
        'sudo': (f'echo "sudo $*" >> {log}\n'
                 + ('[ "$1" = "-n" ] || { echo "sudo: a password is required" >&2; exit 1; }\n'
                    'shift\nSUDO_USED=1 exec "$@"' if sudo_works else
                    'echo "sudo: a password is required" >&2; exit 1')),
        'rm': ('[ "$SUDO_USED" = 1 ] || [ "$(id -u)" = 0 ] || '
               '{ echo "rm: cannot remove: Permission denied" >&2; exit 1; }\n'
               'exec /bin/rm "$@"'),
    }
    for name, body in fakes.items():
        f = bindir / name
        f.write_text('#!/bin/sh\n' + body + '\n')
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    (bindir / 'sh').symlink_to('/bin/sh')
    return bindir, log


def _run(tmp_path, cmd, **kw):
    bindir, log = _fake_host(tmp_path, **kw)
    r = subprocess.run(['/bin/sh', '-c', cmd], capture_output=True, text=True, env={'PATH': str(bindir)})
    return r, (log.read_text() if log.exists() else '')


def _plugin_dir(tmp_path):
    d = tmp_path / 'webodm' / 'plugins' / 'webodm-tak-overlay'
    (d / '__pycache__').mkdir(parents=True)
    (d / '__pycache__' / '__init__.cpython-314.pyc').write_text('x')
    return d


def test_non_root_user_removes_the_folder_with_root_owned_files_through_sudo(tmp_path):
    d = _plugin_dir(tmp_path)
    r, calls = _run(tmp_path, _helpers()['_webodm_plugin_clear_sh'](str(d)), uid=1000)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not d.exists(), 'the old plugin folder is still there'
    assert 'sudo -n' in calls, 'a non-root user must remove the folder under sudo -n'


def test_the_old_plain_rm_fails_on_the_same_host(tmp_path):
    """The command before the fix: proves the fake host reproduces the report."""
    d = _plugin_dir(tmp_path)
    r, _ = _run(tmp_path, f'rm -rf {d}', uid=1000)
    assert r.returncode != 0
    assert 'Permission denied' in r.stderr
    assert d.exists()


def test_root_user_removes_the_folder_with_no_sudo(tmp_path):
    d = _plugin_dir(tmp_path)
    r, calls = _run(tmp_path, _helpers()['_webodm_plugin_clear_sh'](str(d)), uid=0)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not d.exists()
    assert calls == '', 'root needs no sudo'


def test_first_deploy_has_no_folder_and_runs_no_sudo(tmp_path):
    d = tmp_path / 'webodm' / 'plugins' / 'webodm-tak-overlay'   # never created
    r, calls = _run(tmp_path, _helpers()['_webodm_plugin_clear_sh'](str(d)), uid=1000, sudo_works=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert calls == '', 'a first deploy must not need sudo for this step'


def test_non_root_user_without_sudo_fails_with_the_reason(tmp_path):
    d = _plugin_dir(tmp_path)
    r, _ = _run(tmp_path, _helpers()['_webodm_plugin_clear_sh'](str(d)), uid=1000, sudo_works=False)
    assert r.returncode != 0
    assert 'password is required' in (r.stdout + r.stderr)
    assert d.exists(), 'nothing may be deleted when sudo is refused'


def test_a_path_with_spaces_or_shell_characters_stays_one_argument(tmp_path):
    d = tmp_path / 'we b;odm' / 'plugins' / 'webodm-tak-overlay'
    (d / '__pycache__').mkdir(parents=True)
    r, _ = _run(tmp_path, _helpers()['_webodm_plugin_clear_sh'](str(d)), uid=1000)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not d.exists()
    assert (tmp_path / 'we b;odm' / 'plugins').exists(), 'only the plugin folder may be removed'
