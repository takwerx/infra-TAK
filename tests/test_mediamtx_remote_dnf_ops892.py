"""ops #892: the remote MediaMTX deploy had no dnf branch.

Step 1 of _run_mediamtx_deploy_remote ran a bare `apt-get update && apt-get install ...`, so a
Rocky/RHEL 9 remote host (no apt-get) stopped at Step 1 with "apt install failed".

These tests run the real shell string (_MEDIAMTX_REMOTE_DEPS_SH) with `sh`, against fake
`dnf`, `apt-get`, `rpm`, `id` and `sudo` programs on a private PATH, so they show which package
manager the remote host's own tools pick and what they are asked to install.
"""
import ast
import os
import pathlib
import re
import stat
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _deps_sh():
    tree = ast.parse(APP)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == '_MEDIAMTX_REMOTE_DEPS_SH' for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError('_MEDIAMTX_REMOTE_DEPS_SH not found in app.py')


def _write(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _host(tmp_path, tools, uid='0', fail=(), rhel='9', has_epel=True):
    """A fake remote host: only the named package managers exist. Every call is logged."""
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    log = tmp_path / 'calls.log'
    log.write_text('')
    fail_list = '|'.join(fail)
    for name in tools:
        _write(bindir / name,
               '#!/bin/sh\n'
               f'echo "{name} $*" >> "{log}"\n'
               # a failing install, by a word in its arguments
               f'case "$*" in *{fail_list or "NEVERMATCHES-xyz"}*) echo "Error: no match for $*"; exit 1;; esac\n'
               'exit 0\n')
    _write(bindir / 'id', f'#!/bin/sh\necho {uid}\n')
    _write(bindir / 'sudo', f'#!/bin/sh\necho "sudo $*" >> "{log}"\nshift; exec "$@"\n')
    _write(bindir / 'rpm',
           '#!/bin/sh\n'
           f'case "$1" in -E) echo {rhel}; exit 0;; -q) {"exit 0" if has_epel else "exit 1"};; esac\n'
           'exit 0\n')
    # Only these programs: no host apt-get / dnf can leak in. /bin and /usr/bin supply sh, env, grep.
    # The real ones in them are shadowed by ours, and dnf / apt-get are removed from the rest.
    return bindir, log


def _run(tmp_path, tools, **kw):
    bindir, log = _host(tmp_path, tools, **kw)
    # A PATH with our fakes first and a scratch copy of the basics, with no real dnf or apt-get.
    basics = tmp_path / 'basics'
    basics.mkdir()
    for prog in ('sh', 'env', 'grep', 'cat', 'echo', 'printf', 'test'):
        for d in ('/bin', '/usr/bin'):
            src = pathlib.Path(d) / prog
            if src.exists():
                (basics / prog).symlink_to(src)
                break
    env = {'PATH': f'{bindir}:{basics}', 'HOME': str(tmp_path)}
    r = subprocess.run(['/bin/sh', '-c', _deps_sh()], capture_output=True, text=True, env=env, timeout=30)
    return r, log.read_text().splitlines()


def test_rocky_host_with_only_dnf_installs_the_packages_with_dnf(tmp_path):
    r, calls = _run(tmp_path, ['dnf', 'rpm'])
    assert r.returncode == 0, r.stdout + r.stderr
    assert not any(c.startswith('apt-get') for c in calls)
    core = [c for c in calls if c.startswith('dnf install -y wget')]
    assert core, calls
    for pkg in ('wget', 'tar', 'curl', 'openssl', 'python3', 'python3-pip'):
        assert pkg in core[0].split(), core[0]
    # full ffmpeg comes from RPM Fusion, never the apt package name list
    assert any('rpmfusion-free-release-9.noarch.rpm' in c for c in calls), calls
    assert 'dnf install -y ffmpeg' in calls
    assert 'INFRATAK-FFMPEG-MISSING' not in r.stdout


def test_ubuntu_host_with_only_apt_get_still_uses_apt_get(tmp_path):
    r, calls = _run(tmp_path, ['apt-get'])
    assert r.returncode == 0, r.stdout + r.stderr
    assert any(c.startswith('apt-get update') for c in calls)
    inst = [c for c in calls if 'apt-get install' in c]
    assert inst and 'ffmpeg' in inst[0] and 'python3-pip' in inst[0], calls
    assert not any(c.startswith('dnf') for c in calls)


def test_a_failed_core_install_fails_step_one(tmp_path):
    r, calls = _run(tmp_path, ['dnf', 'rpm'], fail=('python3-pip',))
    assert r.returncode != 0
    assert 'Error: no match' in r.stdout


def test_missing_ffmpeg_warns_and_does_not_fail(tmp_path):
    r, calls = _run(tmp_path, ['dnf', 'rpm'], fail=('ffmpeg',))
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'INFRATAK-FFMPEG-MISSING' in r.stdout
    assert 'dnf install -y ffmpeg-free' in calls, 'ffmpeg-free is the fallback'


def test_genuine_rhel_without_epel_release_uses_the_fedora_rpm(tmp_path):
    r, calls = _run(tmp_path, ['dnf', 'rpm'], has_epel=False, fail=('epel-release',))
    assert r.returncode == 0, r.stdout + r.stderr
    assert any('epel-release-latest-9.noarch.rpm' in c for c in calls), calls


def test_non_root_ssh_user_goes_through_sudo_n(tmp_path):
    r, calls = _run(tmp_path, ['dnf', 'rpm'], uid='1000')
    assert r.returncode == 0, r.stdout + r.stderr
    assert any(c.startswith('sudo -n dnf install -y wget') for c in calls) or \
        any(c.startswith('sudo') and 'wget' in c for c in calls), calls


def test_host_with_neither_package_manager_says_so(tmp_path):
    r, calls = _run(tmp_path, [])
    assert r.returncode != 0
    assert 'no dnf or apt-get' in r.stdout


def test_remote_deploy_step_one_uses_the_branching_command_not_a_bare_apt_get():
    m = re.search(r'^def _run_mediamtx_deploy_remote\(.*?(?=^\S)', APP, re.S | re.M)
    body = m.group(0)
    step1 = body[body.index('Step 1/7'):body.index('Step 2/7')]
    assert '_MEDIAMTX_REMOTE_DEPS_SH' in step1
    assert 'apt-get' not in step1


# ── second cause (found on the Rocky 9 box, SELinux enforcing): files moved from /tmp keep the tmp label ──

def _const(name):
    tree = ast.parse(APP)
    consts = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            consts[node.targets[0].id] = node.value
    def ev(n):
        if isinstance(n, ast.Name):
            return ev(consts[n.id])
        if isinstance(n, ast.BinOp):
            return ev(n.left) + ev(n.right)
        return ast.literal_eval(n)
    return ev(consts[name])


def _fake_bin(tmp_path, programs):
    b = tmp_path / 'fb'
    b.mkdir()
    log = tmp_path / 'fcalls.log'
    log.write_text('')
    for name, body in programs.items():
        _write(b / name, f'#!/bin/sh\necho "{name} $*" >> "{log}"\n{body}\n')
    basics = tmp_path / 'fbasics'
    basics.mkdir()
    for prog in ('sh', 'sleep', 'echo', 'id', 'true'):
        for d in ('/bin', '/usr/bin'):
            if (pathlib.Path(d) / prog).exists():
                (basics / prog).symlink_to(pathlib.Path(d) / prog)
                break
    return {'PATH': f'{b}:{basics}'}, log


def test_relabel_runs_restorecon_on_everything_the_deploy_moves_in(tmp_path):
    env, log = _fake_bin(tmp_path, {'restorecon': 'exit 0', 'sudo': 'shift; exec "$@"'})
    r = subprocess.run(['/bin/sh', '-c', _const('_MEDIAMTX_REMOTE_RELABEL_SH')], capture_output=True, text=True, env=env)
    assert r.returncode == 0
    call = log.read_text()
    for path in ('/usr/local/bin/mediamtx', '/usr/local/etc/mediamtx.yml', '/etc/systemd/system/mediamtx.service',
                 '/etc/systemd/system/mediamtx-webeditor.service', '/opt/mediamtx-webeditor'):
        assert path in call, path


def test_relabel_is_harmless_on_a_host_without_restorecon(tmp_path):
    env, log = _fake_bin(tmp_path, {})
    r = subprocess.run(['/bin/sh', '-c', _const('_MEDIAMTX_REMOTE_RELABEL_SH')], capture_output=True, text=True, env=env)
    assert r.returncode == 0


def test_active_check_passes_for_a_running_service_and_fails_for_a_dead_one(tmp_path):
    env, _ = _fake_bin(tmp_path, {'systemctl': 'exit 0'})
    sh = _const('_MEDIAMTX_REMOTE_ACTIVE_SH')
    assert subprocess.run(['/bin/sh', '-c', sh], capture_output=True, text=True, env=env, timeout=30).returncode == 0
    env2, _ = _fake_bin(tmp_path / 'dead', {'systemctl': 'echo inactive; exit 3', 'journalctl': 'echo "Failed to open mediamtx.service: Permission denied"'}) \
        if (tmp_path / 'dead').mkdir() is None else (None, None)
    r = subprocess.run(['/bin/sh', '-c', sh], capture_output=True, text=True, env=env2, timeout=30)
    assert r.returncode == 1
    assert 'Permission denied' in r.stdout


def test_deploy_relabels_before_daemon_reload_and_checks_mediamtx_is_up():
    i0 = APP.index('\ndef _run_mediamtx_deploy_remote(')
    body = APP[i0:APP.index('\ndef ', i0 + 1)]
    i_relabel = body.index('_MEDIAMTX_REMOTE_RELABEL_SH')
    i_reload = body.index('systemctl daemon-reload')
    i_check = body.index('_MEDIAMTX_REMOTE_ACTIVE_SH')
    i_ok = body.index('✓ Services started')
    assert i_relabel < i_reload < i_check < i_ok
    assert '✗ MediaMTX did not start on the remote host' in body
