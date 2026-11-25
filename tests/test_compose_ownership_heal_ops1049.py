# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1049: a root-owned module compose file breaks a redeploy on a non-root console.

Found on test12 (2026-11-21): ~/authentik/docker-compose.yml was root:root 644 while the
rest of ~/authentik was takwerx. The console writes that file as itself (no broker call),
so the Authentik redeploy stopped at "Patching Docker Compose" with
`FATAL ERROR: [Errno 13] Permission denied`. The startup heal re-owned `.env` files only.

`_heal_module_compose_ownership` re-owns module compose files (and overrides) in the
console's OWN home. These tests run the real function out of app.py. A test cannot create
a root-owned file without root, so `os.lstat` reports uid 0 for the paths under test and
`chown` goes to a recording stub.
"""
import ast
import os
import pathlib
import pwd
import stat as stat_mod
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_NAMES = {'_COMPOSE_HEAL_MODULE_DIRS', '_COMPOSE_HEAL_FILE_GLOBS',
          '_heal_module_compose_ownership'}
FAKE_UID = 4242


def _segments():
    out = {}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _NAMES:
            out[node.name] = ast.get_source_segment(APP, node)
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
              and getattr(node.targets[0], 'id', None) in _NAMES):
            out[node.targets[0].id] = ast.get_source_segment(APP, node)
    return out


def _fn_src(name):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


class Env:
    """A console home in tmp_path. Files listed in `root_owned` report uid 0."""

    def __init__(self, tmp_path, monkeypatch, chown_rc=0):
        self.home = tmp_path / 'home' / 'takwerx'
        self.home.mkdir(parents=True)
        self.root_owned = set()
        self.chowns = []
        self.chown_rc = chown_rc
        real_lstat = os.lstat

        def fake_lstat(path, *a, **kw):
            st = real_lstat(path, *a, **kw)
            uid = 0 if os.fspath(path) in self.root_owned else FAKE_UID
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                                   uid, st.st_gid, st.st_size,
                                   int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))

        monkeypatch.setattr(os, 'lstat', fake_lstat)
        monkeypatch.setattr(os, 'getuid', lambda: FAKE_UID)
        monkeypatch.setattr(pwd, 'getpwuid', lambda uid: types.SimpleNamespace(
            pw_name='takwerx', pw_uid=FAKE_UID, pw_dir=str(self.home)))

        def fake_run(cmd, **kw):
            self.chowns.append(list(cmd))
            return types.SimpleNamespace(returncode=self.chown_rc, stdout=b'', stderr=b'')

        stub_subprocess = types.SimpleNamespace(run=fake_run, TimeoutExpired=subprocess.TimeoutExpired)
        self.ns = {'os': os, 'subprocess': stub_subprocess, '_sudo_wrap': lambda c: list(c)}
        exec(compile('\n\n'.join(_segments().values()), 'app.py', 'exec'), self.ns)

    def write(self, rel, root=True):
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('services: {}\n')
        if root:
            self.root_owned.add(str(p))
        return p

    def heal(self, **kw):
        return self.ns['_heal_module_compose_ownership'](plog=lambda m: None, **kw)

    def chowned_paths(self):
        return [c[-1] for c in self.chowns]


@pytest.fixture
def env(tmp_path, monkeypatch):
    return Env(tmp_path, monkeypatch)


def test_function_is_in_app():
    assert set(_segments()) == _NAMES, 'a name under test was renamed or removed'


def test_root_owned_authentik_compose_is_reowned(env):
    """The exact test12 case: ~/authentik/docker-compose.yml owned by root."""
    p = env.write('authentik/docker-compose.yml')
    fixed = env.heal()
    assert fixed == [str(p)]
    assert env.chowns == [['chown', 'takwerx:takwerx', str(p)]]


def test_override_and_other_modules_are_reowned(env):
    a = env.write('authentik/docker-compose.override.yml')
    b = env.write('CloudTAK/docker-compose.yml')
    c = env.write('TAK-Portal/compose.yaml')
    assert sorted(env.heal()) == sorted([str(a), str(b), str(c)])


def test_nested_atlas_deployment_is_reowned(env):
    p = env.write('atlas/redlands/docker-compose.yml')
    assert env.heal() == [str(p)]


def test_file_already_owned_by_console_is_left_alone(env):
    env.write('authentik/docker-compose.yml', root=False)
    assert env.heal() == []
    assert env.chowns == []


def test_symlink_is_never_followed(env, tmp_path):
    target = tmp_path / 'elsewhere.yml'
    target.write_text('x')
    link = env.home / 'authentik' / 'docker-compose.yml'
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    env.root_owned.add(str(link))
    assert env.heal() == []
    assert env.chowns == []


def test_dirs_outside_the_console_home_are_not_touched(env, tmp_path):
    """/root/<mod> copies on a flipped box stay as the migration left them."""
    outside = tmp_path / 'root' / 'authentik' / 'docker-compose.yml'
    outside.parent.mkdir(parents=True)
    outside.write_text('x')
    env.root_owned.add(str(outside))
    assert env.heal(only_dirs=[str(outside.parent)]) == []
    assert env.chowns == []


def test_only_dirs_limits_the_heal(env):
    mine = env.write('authentik/docker-compose.yml')
    env.write('CloudTAK/docker-compose.yml')
    assert env.heal(only_dirs=[str(env.home / 'authentik')]) == [str(mine)]


def test_unrelated_files_are_not_touched(env):
    env.write('authentik/.env')
    env.write('authentik/notes.yml')
    env.write('some-other-dir/docker-compose.yml')
    assert env.heal() == []


def test_refused_chown_does_not_crash_and_reports_nothing_fixed(tmp_path, monkeypatch):
    e = Env(tmp_path, monkeypatch, chown_rc=1)
    e.write('authentik/docker-compose.yml')
    assert e.heal() == []


def test_root_console_does_nothing(env, monkeypatch):
    env.write('authentik/docker-compose.yml')
    monkeypatch.setattr(os, 'getuid', lambda: 0)
    assert env.heal() == []
    assert env.chowns == []


def test_runs_at_startup_next_to_the_env_heal():
    src = _fn_src('_startup_migrations')
    assert '_heal_module_compose_ownership(' in src
    assert src.index('_harden_sensitive_permissions()') < src.index('_heal_module_compose_ownership(')


def test_authentik_deploy_heals_before_it_writes_the_compose_file():
    """The redeploy must not wait for a console restart to get its file back."""
    src = _fn_src('run_authentik_deploy')
    heal = src.index('_heal_module_compose_ownership(')
    assert 'only_dirs=[ak_dir]' in src[heal:heal + 120]
    assert heal < src.index("open(compose_path, 'w')")
    assert heal < src.index('_ensure_authentik_compose_patches(compose_path')
