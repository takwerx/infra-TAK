"""Remote WebODM Uninstall removes the old database folder as root and reports a failure (ops #1445).

Before: the remote branch of `webodm_uninstall` ran `rm -rf <dir>/db 2>/dev/null; true` as the SSH user.
The database folder (`db/18`) belongs to the Postgres container's user (uid 999, mode 700), so for a
non-root SSH user (ubuntu, rocky, azureuser) the command printed nothing, exited 0 and left the old data.
The next Deploy then started on the old database and its old admin login. The local uninstall already
removes it through the broker as root.

Three kinds of test:
  * Structure: the remote branch has no plain `rm -rf` and goes through `_webodm_db_clear_sh`.
  * Behaviour of the command text on a fake host where `rm` refuses unless it runs as root or under `sudo -n`.
  * Behaviour of the route with stubs: a failed clear returns an error and does NOT save "uninstalled".
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


def _func(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f'{name} not found at module level in app.py')


def _src(name):
    return ast.get_source_segment(APP, _func(name))


def _remote_branch_src():
    src = _src('webodm_uninstall')
    return src[src.index("if deploy_cfg.get('target_mode') == 'remote':"):src.index('    else:\n        import shutil')]


# --------------------------------------------------------------------------- structure

def test_remote_branch_has_no_plain_rm_of_the_db_folder():
    body = _remote_branch_src()
    assert 'rm -rf {wo_dir_remote}/db' not in body, 'the SSH user must not delete the db folder itself'
    assert '2>/dev/null; true' not in body.split('docker compose')[-1].split('\n', 1)[-1], \
        'the db removal must not hide its errors'


def test_remote_branch_clears_the_db_folder_through_the_root_helper():
    body = _remote_branch_src()
    assert '_webodm_db_clear_sh(' in body
    assert body.index('_webodm_db_clear_sh(') > body.index('compose'), 'containers go down before the data goes'


def test_the_helper_goes_through_the_root_wrapper():
    assert '_as_root_sh(' in _src('_webodm_db_clear_sh')


# --------------------------------------------------------------------------- behaviour on a fake host

def _helpers(optional=False):
    """The real helper functions from app.py. `optional`: skip one that does not exist yet, so the route
    tests below fail on the base code for the real reason (behaviour), not because a helper is missing."""
    ns = {'shlex': shlex}
    for name in ('_as_root_sh', '_webodm_db_clear_sh'):
        if optional and not any(isinstance(n, ast.FunctionDef) and n.name == name for n in TREE.body):
            continue
        exec(compile(_src(name), 'app.py', 'exec'), ns)
    return ns


def _fake_host(tmp_path, *, uid, sudo_works=True):
    """A bin dir that is the host's whole PATH. `rm` refuses unless the user is root or it ran under
    `sudo -n` (the container-owned db folder); `id` reports `uid`. Returns (bindir, log)."""
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


def _db_dir(tmp_path, name='webodm'):
    d = tmp_path / name / 'db'
    (d / '18' / 'base').mkdir(parents=True)
    (d / '18' / 'PG_VERSION').write_text('18')
    return d


def test_non_root_user_removes_the_db_folder_through_sudo(tmp_path):
    d = _db_dir(tmp_path)
    r, calls = _run(tmp_path, _helpers()['_webodm_db_clear_sh'](str(d)), uid=1000)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not d.exists(), 'the old database folder is still there'
    assert 'sudo -n' in calls, 'a non-root user must remove the folder under sudo -n'
    assert d.parent.exists(), 'only db/ may go: media/ and the compose file stay'


def test_the_old_plain_rm_fails_quietly_on_the_same_host(tmp_path):
    """The command before the fix: the fake host reproduces the report (exit 0, no message, data left)."""
    d = _db_dir(tmp_path)
    r, _ = _run(tmp_path, f'rm -rf {d} 2>/dev/null; true', uid=1000)
    assert r.returncode == 0 and r.stdout == '' and r.stderr == ''
    assert d.exists(), 'the fake host should leave the data behind, like the real one'


def test_root_user_removes_the_db_folder_with_no_sudo(tmp_path):
    d = _db_dir(tmp_path)
    r, calls = _run(tmp_path, _helpers()['_webodm_db_clear_sh'](str(d)), uid=0)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not d.exists()
    assert calls == '', 'root needs no sudo'


def test_no_db_folder_runs_no_sudo(tmp_path):
    d = tmp_path / 'webodm' / 'db'   # never created
    r, calls = _run(tmp_path, _helpers()['_webodm_db_clear_sh'](str(d)), uid=1000, sudo_works=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert calls == ''


def test_non_root_user_without_sudo_fails_with_the_reason_and_deletes_nothing(tmp_path):
    d = _db_dir(tmp_path)
    r, _ = _run(tmp_path, _helpers()['_webodm_db_clear_sh'](str(d)), uid=1000, sudo_works=False)
    assert r.returncode != 0
    assert 'password is required' in (r.stdout + r.stderr)
    assert d.exists()


def test_a_path_with_spaces_or_shell_characters_stays_one_argument(tmp_path):
    d = _db_dir(tmp_path, name='we b;odm')
    r, _ = _run(tmp_path, _helpers()['_webodm_db_clear_sh'](str(d)), uid=1000)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not d.exists()
    assert (tmp_path / 'we b;odm').exists(), 'only the db folder may be removed'


@pytest.mark.parametrize('bad', ['', '~/webodm/db', 'webodm/db', '/db', '/', '/home/u/webodm', '/home/u/webodm/db/18',
                                 '/home/u/webodm/dbx'])
def test_the_helper_refuses_anything_but_an_absolute_db_folder(bad):
    with pytest.raises(ValueError):
        _helpers()['_webodm_db_clear_sh'](bad)


def test_a_trailing_slash_is_fine():
    assert 'rm -rf /home/u/webodm/db' in _helpers()['_webodm_db_clear_sh']('/home/u/webodm/db/')


# --------------------------------------------------------------------------- the route, with stubs

class _Req:
    def __init__(self, data):
        self.json = data


def _route(monkeypatch_ns):
    """The real webodm_uninstall body, without its decorators, with stubbed seams."""
    src = _src('webodm_uninstall')
    src = src[src.index('def webodm_uninstall'):]
    exec(compile(src, 'app.py', 'exec'), monkeypatch_ns)
    return monkeypatch_ns['webodm_uninstall']


def _ns(cmds, *, home='/home/ubuntu', resolved='/home/ubuntu/webodm', clear_ok=True, clear_out=''):
    saved = []
    ns = {
        'shlex': shlex,
        'request': _Req({'password': 'pw'}),
        'load_auth': lambda: {'password_hash': 'h'},
        'check_password_hash': lambda h, p: True,
        'load_settings': lambda: {},
        '_get_module_deployment_config': lambda s, k: {
            'target_mode': 'remote', 'remote': {'_resolved_wo_dir': resolved} if resolved else {}},
        '_normalize_module_deployment_config': lambda c: c,
        'save_settings': lambda s: saved.append(dict(s)),
        'generate_caddyfile': lambda s: None,
        '_caddy_reload': lambda *a, **k: True,
        'jsonify': lambda *a, **k: (a[0] if a else k),
        'saved': saved,
    }

    def _module_run(cfg, cmd, timeout=120, log_fn=None):
        cmds.append(cmd)
        if cmd.strip() == 'echo $HOME':
            return True, home + '\n'
        if 'docker compose' in cmd:
            return True, ''
        return clear_ok, clear_out

    ns['_module_run'] = _module_run
    ns.update(_helpers(optional=True))
    return ns


def test_route_failed_clear_returns_an_error_and_keeps_webodm_marked_installed():
    cmds = []
    ns = _ns(cmds, clear_ok=False, clear_out='sudo: a password is required')
    resp = _route(ns)()
    body, code = resp
    assert code == 500
    assert 'password is required' in body['error'] and '/home/ubuntu/webodm/db' in body['error']
    assert ns['saved'] == [], 'WebODM must stay installed (settings untouched) so the operator can press Uninstall again'


def test_route_success_removes_the_db_as_root_then_marks_webodm_uninstalled():
    cmds = []
    ns = _ns(cmds)
    resp = _route(ns)()
    assert resp == {'success': True}
    clear = [c for c in cmds if 'rm -rf' in c]
    assert len(clear) == 1 and 'sudo -n sh -c' in clear[0] and '/home/ubuntu/webodm/db' in clear[0]
    assert ns['saved'] and ns['saved'][0]['webodm_enabled'] is False


def test_route_resolves_a_tilde_dir_to_the_ssh_users_home_not_roots():
    cmds = []
    ns = _ns(cmds, resolved='', home='/home/rocky')
    resp = _route(ns)()
    assert resp == {'success': True}
    clear = [c for c in cmds if 'rm -rf' in c][0]
    assert '/home/rocky/webodm/db' in clear and '~' not in clear


def test_route_unreadable_home_stops_before_deleting_anything():
    cmds = []
    ns = _ns(cmds, resolved='', home='')
    body, code = _route(ns)()
    assert code == 500
    assert not [c for c in cmds if 'rm -rf' in c]
    assert ns['saved'] == []
