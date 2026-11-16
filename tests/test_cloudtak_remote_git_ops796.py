"""Remote CloudTAK deploy installs `git` on the remote host before it clones CloudTAK (ops #796).

Before: `run_cloudtak_deploy` (remote target) ran `_cloudtak_remote_reclone_sh` on the remote host, which
calls `git -C` and `git clone`, and never installed git. A stock Rocky Linux 9 server image has no git, so
the deploy stopped at Step 3/6 with `✗ CloudTAK repo prep failed on remote: bash: line 1: git: command not
found` (seen on a real Rocky 9.8 host, fresh-install run fi-20261116-001011). Same gap as the remote WebODM
deploy (ops #792), which added `_remote_ensure_git`; the CloudTAK deploy now reuses it.

Two kinds of test:
  * Call order: the remote deploy must call `_remote_ensure_git` before the repo-prep command, and a
    failed git install must end the deploy.
  * Behaviour: on a fake RHEL host with no git, the real repo-prep text fails with `git: command not found`
    on its own, and succeeds after the real git-ensure text ran first.
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


def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found at module level in app.py')


def _reclone_sh(tag):
    ns = {'shlex': shlex, 'CLOUDTAK_CUSTOM_COMPOSE': _const('CLOUDTAK_CUSTOM_COMPOSE')}
    exec(compile(ast.get_source_segment(APP, _func('_cloudtak_remote_reclone_sh')), 'app.py', 'exec'), ns)
    return ns['_cloudtak_remote_reclone_sh'](tag)


def _remote_branch():
    """The part of run_cloudtak_deploy that handles a remote target (up to the config-writing step)."""
    src = ast.get_source_segment(APP, _func('run_cloudtak_deploy'))
    start = src.index("if target_mode == 'remote':")
    return src[start:src.index('Step 4/6', start)]


# --------------------------------------------------------------------------- call order

def test_remote_cloudtak_deploy_ensures_git_before_the_repo_prep():
    seg = _remote_branch()
    assert '_remote_ensure_git(' in seg, 'the remote CloudTAK deploy never makes sure git is on the host'
    assert seg.index('_remote_ensure_git(') < seg.index('_cloudtak_remote_reclone_sh('), \
        'git must be installed before the repo prep runs git clone'


def test_a_failed_git_install_ends_the_remote_cloudtak_deploy():
    seg = _remote_branch()
    after = seg[seg.index('_remote_ensure_git('):seg.index('_cloudtak_remote_reclone_sh(')]
    assert "'error': True" in after and 'return' in after, \
        'a failed git install must end the deploy with an error, not carry on to git clone'


def test_the_git_install_runs_on_the_remote_target_config():
    """_remote_ensure_git reads target_mode and remote from the config it is given: it must get the deploy's."""
    seg = _remote_branch()
    call = seg[seg.index('_remote_ensure_git('):].split('\n', 1)[0]
    assert '(cfg,' in call, f'_remote_ensure_git must be given the deploy config (cfg): {call.strip()}'


# --------------------------------------------------------------------------- behaviour on a fake host

def _fake_rhel_host(tmp_path):
    """A host whose whole PATH is one bin dir: root user, dnf that installs a fake git, no git yet.
    The fake git says `not a repository` for -C ... rev-parse and makes the folder for `clone`."""
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    for tool in ('rm', 'cp', 'mv', 'mkdir', 'chmod', 'touch', 'cat'):
        for d in ('/bin', '/usr/bin'):
            if (pathlib.Path(d) / tool).exists():
                (bindir / tool).symlink_to(pathlib.Path(d) / tool)
                break
    fake_git = (
        '#!/bin/sh\n'
        'case "$*" in\n'
        '  "--version") echo git version 2.52.0 ;;\n'
        '  *rev-parse*) exit 128 ;;\n'
        '  clone*) for a; do dest="$a"; done; mkdir -p "$dest"; touch "$dest/docker-compose.yml" ;;\n'
        'esac\n')
    fakes = {
        'id': '#!/bin/sh\necho 0\n',
        'dnf': f'#!/bin/sh\nprintf "%s" "$GIT_BODY" > {bindir}/git; chmod +x {bindir}/git\n',
    }
    for name, body in fakes.items():
        f = bindir / name
        f.write_text(body)
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    return bindir, fake_git


def _run_on_host(tmp_path, script, fake_git):
    bindir = tmp_path / 'bin'
    home = tmp_path / 'home'
    home.mkdir(exist_ok=True)
    return subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True,
                          env={'PATH': str(bindir), 'HOME': str(home), 'GIT_BODY': fake_git}), home


def test_repo_prep_alone_fails_on_a_host_with_no_git(tmp_path):
    """The bug: the repo-prep command on a stock Rocky 9 host."""
    _, fake_git = _fake_rhel_host(tmp_path)
    r, home = _run_on_host(tmp_path, _reclone_sh('v13.122.8'), fake_git)
    assert r.returncode != 0
    assert 'git: command not found' in r.stderr + r.stdout or 'git: not found' in r.stderr + r.stdout
    assert not (home / 'CloudTAK' / 'docker-compose.yml').exists()


def test_repo_prep_succeeds_after_the_git_install_ran(tmp_path):
    """The fix: the same host, with the real git-install text run first, as the deploy now does."""
    _, fake_git = _fake_rhel_host(tmp_path)
    r, home = _run_on_host(tmp_path, _const('_REMOTE_GIT_ENSURE_SH'), fake_git)
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'git version' in r.stdout
    r, home = _run_on_host(tmp_path, _reclone_sh('v13.122.8'), fake_git)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (home / 'CloudTAK' / 'docker-compose.yml').exists(), 'CloudTAK was not cloned onto the host'
