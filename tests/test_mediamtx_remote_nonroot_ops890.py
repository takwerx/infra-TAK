"""Remote MediaMTX deploy works when the SSH user is not root but has sudo (ops #890).

Before: `_run_mediamtx_deploy_remote` ran `apt-get update && apt-get install ...` (and every later
step: `mv` into /usr/local/bin, `mkdir /opt/...`, `systemctl`, `pip3`, `useradd`) as the SSH user. A
cloud image's sudo user (azureuser, ubuntu, rocky) is not root, so Step 1 stopped with
`apt install failed ... /var/lib/apt/lists/lock - Permission denied`. The same deploy as root worked.

After: those commands run through `_module_run_root` / `_as_root_sh`: root runs the text as it is, any
other user runs the WHOLE string under `sudo -n sh -c`.

Three kinds of test:
  * Behaviour: run the real wrapper text on a fake non-root host whose `apt-get` refuses unless it was
    started through `sudo -n`, and drive the real `_run_mediamtx_deploy_remote` through Step 1.
  * Structure: in every remote MediaMTX function, no `_module_run` / `_ssh_probe` call may carry a
    command that needs root unless it goes through the root wrapper (or the older `$S` prefix).
  * Local targets are unchanged.
"""
import ast
import os
import pathlib
import re
import stat
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

# Every remote MediaMTX code path that runs a command on the SSH target.
REMOTE_MEDIAMTX_FUNCS = (
    '_run_mediamtx_deploy_remote',
    '_mediamtx_remote_clear_staging',
    '_ensure_takwerx_system_user_remote',
    '_mediamtx_editor_remote_py_deps',
    'mediamtx_recovery',
    'mediamtx_control',
    'mediamtx_logs',
    'mediamtx_uninstall',
)


def _func(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f'{name} not found at module level in app.py')


def _src(name):
    return ast.get_source_segment(APP, _func(name))


# --------------------------------------------------------------------------- structure

# A command that touches only the SSH user's own view of the host, or only reads.
_READ_ONLY = re.compile(r"^\s*(uname -m|getent passwd takwerx[^;&|]*|systemctl is-active [\w -]+(2>/dev/null)?)\s*$")


def _command_arg(call):
    """The command expression of a `_module_run(deploy_cfg, CMD, ...)` or `_ssh_probe(remote, CMD, ...)`."""
    return call.args[1] if len(call.args) > 1 else None


def _calls_to(fn_node, names):
    for node in ast.walk(fn_node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in names:
            yield node


@pytest.mark.parametrize('fname', REMOTE_MEDIAMTX_FUNCS)
def test_no_remote_mediamtx_command_runs_unprivileged_when_it_needs_root(fname):
    bad = []
    for call in _calls_to(_func(fname), {'_module_run', '_ssh_probe'}):
        arg = _command_arg(call)
        if arg is None:
            continue
        text = ast.get_source_segment(APP, arg)
        if '_as_root_sh(' in text or '_REMOTE_SUDO_SH' in text:
            continue
        # Resolve a plain string literal; anything else (a variable, a call) must use the wrapper.
        literal = None
        try:
            literal = ast.literal_eval(arg)
        except Exception:
            pass
        if literal is not None and _READ_ONLY.match(literal):
            continue
        bad.append(f'line {call.lineno}: {text[:110]}')
    assert not bad, (f'{fname}: these remote commands run as the SSH user, not root; a non-root SSH '
                     f'user (azureuser, ubuntu, rocky) gets "Permission denied":\n  ' + '\n  '.join(bad))


def test_step_one_apt_install_uses_the_root_wrapper():
    # ops #892: Step 1 is now one command that picks dnf or apt-get on the remote host
    # (_MEDIAMTX_REMOTE_DEPS_SH). It still runs through the root wrapper, and still holds the apt branch.
    src = _src('_run_mediamtx_deploy_remote')
    assert re.search(r"_module_run_root\(deploy_cfg, _MEDIAMTX_REMOTE_DEPS_SH", src), \
        'the remote package install must run through _module_run_root (ops #890)'
    deps = _const('_MEDIAMTX_REMOTE_DEPS_SH')
    assert 'apt-get update -qq' in deps and 'apt-get install -y' in deps


# --------------------------------------------------------------------------- behaviour on a fake host

def _fake_host(tmp_path, uid):
    """A bin dir that is the fake host's whole PATH (plus /usr/bin:/bin for sh itself).

    `id` reports `uid`. `sudo` needs `-n` and marks the child as privileged (SUDO_USED=1). `apt-get`
    refuses with the real apt message unless the user is root or it came through `sudo -n`."""
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    log = tmp_path / 'calls.log'
    fakes = {
        'id': f'echo {uid}',
        'sudo': (f'echo "sudo $*" >> {log}\n'
                 '[ "$1" = "-n" ] || { echo "sudo: a password is required" >&2; exit 1; }\n'
                 'shift\nSUDO_USED=1 exec "$@"'),
        'apt-get': (f'echo "apt-get $*" >> {log}\n'
                    '[ "$SUDO_USED" = 1 ] || [ "$(id -u)" = 0 ] || { '
                    'echo "E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)" >&2; '
                    'exit 100; }\n'
                    'exit 0'),
    }
    for name, body in fakes.items():
        p = bindir / name
        p.write_text('#!/bin/sh\n' + body + '\n')
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return bindir, log


def _run_on_host(bindir, cmd):
    env = {'PATH': f'{bindir}:/usr/bin:/bin', 'HOME': str(bindir)}
    r = subprocess.run(['sh', '-c', cmd], env=env, capture_output=True, text=True, timeout=30)
    return r.returncode == 0, ((r.stdout or '') + (r.stderr or '')).strip()


def _helpers_ns(tmp_path, bindir):
    """Namespace with the real `_module_run`, and the root helpers when they exist, over a `_ssh_probe`
    that runs the remote text on the fake host."""
    ns = {'shlex': __import__('shlex'), 're': re, 'subprocess': subprocess, 'os': os}
    ns['_ssh_probe'] = lambda host_cfg, cmd='echo ok', timeout=15: _run_on_host(bindir, cmd)
    for name in ('_module_run', '_as_root_sh', '_module_run_root'):
        try:
            node = _func(name)
        except AssertionError:
            continue
        exec(compile(ast.get_source_segment(APP, node), 'app.py', 'exec'), ns)
    return ns


REMOTE_CFG = {'target_mode': 'remote', 'remote': {'host': '203.0.113.9', 'ssh_user': 'azureuser'}}


def test_as_root_sh_runs_the_whole_chain_as_root_for_a_non_root_user(tmp_path):
    bindir, log = _fake_host(tmp_path, uid=1000)
    ns = _helpers_ns(tmp_path, bindir)
    ok, out = _run_on_host(bindir, ns['_as_root_sh']('apt-get update -qq && apt-get install -y curl 2>&1'))
    assert ok, out
    assert 'sudo -n sh -c' in log.read_text()
    # BOTH apt-get calls ran privileged, not just the first one.
    calls = [l for l in log.read_text().splitlines() if l.startswith('apt-get ')]
    assert len(calls) == 2, calls


def test_as_root_sh_does_not_use_sudo_for_root(tmp_path):
    bindir, log = _fake_host(tmp_path, uid=0)
    ns = _helpers_ns(tmp_path, bindir)
    ok, out = _run_on_host(bindir, ns['_as_root_sh']('apt-get update -qq'))
    assert ok, out
    assert 'sudo' not in log.read_text(), 'root must not need sudo (a minimal root image has none)'


def test_as_root_sh_keeps_quotes_and_dollar_signs_intact(tmp_path):
    payload = "printf '%s|%s' \"it's\" \"$(echo $((6*7)))\""
    for uid in (1000, 0):
        host = tmp_path / f'uid{uid}'
        host.mkdir()
        bindir, _ = _fake_host(host, uid)
        ns = _helpers_ns(host, bindir)
        ok, out = _run_on_host(bindir, ns['_as_root_sh'](payload))
        assert ok and out == "it's|42", out


def test_a_non_root_user_without_passwordless_sudo_gets_a_clear_failure(tmp_path):
    bindir, _ = _fake_host(tmp_path, uid=1000)
    (bindir / 'sudo').write_text('#!/bin/sh\necho "sudo: a password is required" >&2\nexit 1\n')
    ns = _helpers_ns(tmp_path, bindir)
    ok, out = _run_on_host(bindir, ns['_as_root_sh']('apt-get update -qq'))
    assert not ok and 'a password is required' in out


def test_module_run_root_leaves_a_local_target_unchanged():
    seen = []
    ns = {'_module_run': lambda cfg, cmd, timeout=120, log_fn=None: seen.append(cmd) or (True, ''),
          'shlex': __import__('shlex')}
    for name in ('_as_root_sh', '_module_run_root'):
        exec(compile(ast.get_source_segment(APP, _func(name)), 'app.py', 'exec'), ns)
    ns['_module_run_root']({'target_mode': 'local'}, 'systemctl restart mediamtx')
    assert seen == ['systemctl restart mediamtx']


class _StopAfterStepOne(Exception):
    pass


def _drive_remote_deploy_through_step_one(tmp_path, uid):
    bindir, log = _fake_host(tmp_path, uid)
    ns = _helpers_ns(tmp_path, bindir)
    plog_lines = []

    def _stop(*a, **k):
        raise _StopAfterStepOne()

    ns.update({
        'mediamtx_deploy_status': {},
        '_ensure_takwerx_system_user_remote': _stop,   # Step 1b: not under test here
        '_MEDIAMTX_REMOTE_DEPS_SH': _const('_MEDIAMTX_REMOTE_DEPS_SH'),   # Step 1 (ops #892)
        're': re,
    })
    exec(compile(_src('_run_mediamtx_deploy_remote'), 'app.py', 'exec'), ns)
    cfg = {'target_mode': 'remote', 'remote': dict(REMOTE_CFG['remote'])}
    try:
        ns['_run_mediamtx_deploy_remote']({}, cfg, plog_lines.append)
    except _StopAfterStepOne:
        pass
    return plog_lines, ns['mediamtx_deploy_status'], log


def test_remote_deploy_step_one_passes_for_a_non_root_sudo_user(tmp_path):
    plog_lines, status, log = _drive_remote_deploy_through_step_one(tmp_path, uid=1000)
    text = '\n'.join(plog_lines)
    assert 'apt install failed' not in text, text
    assert status.get('error') is not True, text
    assert '✓ Dependencies installed' in text, text
    assert 'apt-get install -y wget tar curl ffmpeg openssl python3 python3-pip' in log.read_text()


def test_remote_deploy_step_one_still_passes_for_root(tmp_path):
    plog_lines, status, log = _drive_remote_deploy_through_step_one(tmp_path, uid=0)
    text = '\n'.join(plog_lines)
    assert '✓ Dependencies installed' in text, text
    assert 'sudo' not in log.read_text()


# --------------------------------------------------------------------------- staging files in /tmp
# Found on the real two-VM box: the deploy ran the tar extract as root in /tmp, which left a
# root-owned mediamtx.yml (upstream's 39 KB default) and LICENSE behind, and the copy of our own
# mediamtx.yml as the non-root SSH user then died at Step 4 with "Permission denied".

def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found at module level in app.py')


def test_step_three_extracts_only_the_binary():
    src = _src('_run_mediamtx_deploy_remote')
    assert 'tar -xzf {tarball} mediamtx &&' in src, \
        'extract only the mediamtx binary: the tarball also holds mediamtx.yml and LICENSE, which a root run leaves in /tmp'
    assert 'tar -xzf {tarball} &&' not in src


def _tmp_copy_targets(fname):
    targets = []
    for call in _calls_to(_func(fname), {'_module_copy'}):
        if len(call.args) > 2:
            try:
                t = ast.literal_eval(call.args[2])
            except Exception:
                continue
            if isinstance(t, str) and t.startswith('/tmp/'):
                targets.append(t)
    return targets


@pytest.mark.parametrize('fname', ('_run_mediamtx_deploy_remote', 'mediamtx_recovery'))
def test_every_tmp_copy_target_is_cleared_first(fname):
    staging = _const('_MEDIAMTX_REMOTE_STAGING')
    targets = _tmp_copy_targets(fname)
    assert targets, f'{fname} copies nothing to /tmp? the test lost its target list'
    missing = [t for t in targets if t not in staging]
    assert not missing, f'{fname} copies to {missing} in /tmp but _MEDIAMTX_REMOTE_STAGING does not clear them'


@pytest.mark.parametrize('fname', ('_run_mediamtx_deploy_remote', 'mediamtx_recovery'))
def test_staging_is_cleared_before_the_first_copy(fname):
    src = _src(fname)
    assert '_mediamtx_remote_clear_staging(' in src
    assert src.index('_mediamtx_remote_clear_staging(') < src.index('_module_copy('), \
        'clear the root-owned leftovers BEFORE the first copy into /tmp'


def test_clear_staging_removes_every_name_as_root():
    seen = []
    ns = {'_module_run_root': lambda cfg, cmd, timeout=120, log_fn=None: seen.append(cmd) or (True, ''),
          '_MEDIAMTX_REMOTE_STAGING': _const('_MEDIAMTX_REMOTE_STAGING')}
    exec(compile(_src('_mediamtx_remote_clear_staging'), 'app.py', 'exec'), ns)
    ns['_mediamtx_remote_clear_staging']({'target_mode': 'remote'})
    assert len(seen) == 1 and seen[0].startswith('rm -f ')
    for name in ns['_MEDIAMTX_REMOTE_STAGING']:
        assert name in seen[0]
