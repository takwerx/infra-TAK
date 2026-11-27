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
"""Update Now checks the new release before it moves the console's tree (ops #1329).

The real `update_apply` (and the helpers it calls) is cut out of app.py and run against a real
git repository: an "upstream" with two release tags and a console clone sitting on the older tag.
Only the outside world is faked: the GitHub tag lookup, the systemd restart, the venv's pip, and
the settings file. Every test names the item of the ops issue it proves and fails on the code
before the fix (HEAD moves, pip is never asked, the wrong tag is kept, and so on).
"""

import ast
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

OLD, NEW = 'v1.0.0-alpha', 'v1.0.1-alpha'

_FUNCS = [
    'update_apply', '_git_fetch_retry', '_update_console_python', '_update_safe_extract',
    '_update_preflight_tree', '_update_clear_stale_git_locks', '_update_plain_git_error',
    '_update_rollback_snapshot', '_post_update_in_progress', '_detached_console_restart',
    '_tag_version_tuple', '_main_commit_shas', '_select_latest_release_tag',
    '_fetch_latest_tag_name',
]
_ASSIGNS = ['_UPDATE_PIP_TIMEOUT_S', '_UPDATE_RESTART_DELAY_S', '_UPDATE_RESTART_WAIT_S', '_UPDATE_REQ_CHECK_PY',
            '_UPDATE_TREE_CHECK_PY', '_UPDATE_TREE_CHECK_TIMEOUT_S', '_GIT_FETCH_TIMEOUTS_S', '_GIT_FETCH_PAUSE_S',
            '_GIT_TRANSIENT_RE']


def _lift(names=None, assigns=None):
    want_f = set(_FUNCS if names is None else names)
    want_a = set(_ASSIGNS if assigns is None else assigns)
    found_f, found_a, parts = set(), set(), []
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name in want_f:
            parts.append(ast.get_source_segment(APP, node))
            found_f.add(node.name)
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
              and getattr(node.targets[0], 'id', None) in want_a):
            parts.append(ast.get_source_segment(APP, node))
            found_a.add(node.targets[0].id)
    return '\n\n'.join(parts), want_f - found_f, want_a - found_a


SRC, _MISSING_F, _MISSING_A = _lift()


def _git(cwd, *args):
    r = subprocess.run(['git', '-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'tag.gpgSign=false',
                        '-c', 'commit.gpgSign=false', *args], cwd=cwd,
                       capture_output=True, text=True)
    assert r.returncode == 0, (args, r.stderr)
    return r.stdout.strip()


def _installed(dist):
    from importlib import metadata
    return metadata.version(dist)


APP_PY = 'VERSION = "{v}"\nimport os\n'


class Box:
    """A console clone on OLD, an upstream with NEW, a fake venv, and the stand-ins."""

    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.up = self.root / 'upstream'
        self.console = self.root / 'console'
        self.log = self.root / 'pip.log'
        self.pip_rc = self.root / 'pip.rc'
        self.pip_sleep = self.root / 'pip.sleep'
        self.restarts = []
        self.settings = {}
        self.post_lock = self.root / 'post-update.lock'
        self.update_lock = self.root / 'update-now.lock'
        self.restart_argv = ['sleep', '1']
        self.tags_on_main = None
        self._build_upstream()
        self._build_console()

    def _build_upstream(self):
        self.up.mkdir(parents=True)
        _git(self.up, 'init', '-q', '-b', 'main')
        self.write_release(OLD, app=APP_PY.format(v='1.0.0-alpha'),
                           req=f'pytest=={_installed("pytest")}\n')

    def write_release(self, tag, app, req, extra=None, branch=None):
        if branch:
            _git(self.up, 'checkout', '-q', '-B', branch)
        (self.up / 'app.py').write_text(app)
        (self.up / 'requirements.txt').write_text(req)
        for rel, text in (extra or {}).items():
            p = self.up / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        _git(self.up, 'add', '-A')
        _git(self.up, 'commit', '-q', '-m', tag)
        _git(self.up, 'tag', '-a', '-m', tag, tag)  # annotated, like a release
        if branch:
            _git(self.up, 'checkout', '-q', 'main')

    def _build_console(self):
        _git(self.root, 'clone', '-q', str(self.up), str(self.console))
        _git(self.console, 'checkout', '-q', '--detach', OLD)
        bindir = self.console / '.venv' / 'bin'
        bindir.mkdir(parents=True)
        py = bindir / 'python'
        py.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        pip = bindir / 'pip'
        pip.write_text(
            '#!/bin/sh\n'
            f'echo "$@" >> "{self.log}"\n'
            f'[ -f "{self.pip_sleep}" ] && sleep "$(cat "{self.pip_sleep}")"\n'
            f'if [ -f "{self.pip_rc}" ] && [ "$(cat "{self.pip_rc}")" != 0 ]; then\n'
            '  echo "ERROR: No matching distribution found for newlib==9.9" >&2\n'
            f'  exit "$(cat "{self.pip_rc}")"\nfi\nexit 0\n')
        for f in (py, pip):
            f.chmod(0o755)
        # the console tree is clean: the venv is ignored, as on a real box
        (self.console / '.git' / 'info' / 'exclude').write_text('.venv\n')

    # --- what the tests read back ---
    def head_tag(self):
        r = subprocess.run(['git', 'describe', '--tags', '--exact-match'], cwd=self.console,
                           capture_output=True, text=True)
        return r.stdout.strip()

    def pip_calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def pip_installs(self):
        return [c for c in self.pip_calls() if c.startswith('install')]

    # --- running the click ---
    def ns(self, **over):
        flask_app = flask.Flask('ops1329')
        box = self

        def load_settings():
            return json.loads(json.dumps(box.settings))

        def save_settings(s):
            box.settings = json.loads(json.dumps(s))

        def fake_wrap(argv):
            box.restarts.append(list(argv))
            return list(box.restart_argv)

        n = {
            '__file__': str(self.console / 'app.py'),
            'os': os, 're': re, 'json': json, 'time': time, 'subprocess': subprocess,
            'threading': threading, 'shutil': shutil, 'tempfile': tempfile, '_sys': sys,
            'datetime': __import__('datetime').datetime, 'urllib': urllib,
            'jsonify': flask.jsonify, 'VERSION': '1.0.0-alpha', 'GITHUB_REPO': 'takwerx/infra-TAK',
            'load_settings': load_settings, 'save_settings': save_settings,
            'update_cache': {}, '_FREE_SPACE_BACKUPS_HINT': '',
            '_fetch_latest_tag_name_from_git': lambda: None,
            '_repo_ownership_selfheal': lambda trigger='': [],
            '_ensure_gunicorn_upgrade': lambda console_dir=None: None,
            '_sudo_wrap': fake_wrap,
            'print': lambda *a, **k: None,
            'login_required': lambda f: f,
            'app': type('A', (), {'route': lambda self, *a, **k: (lambda f: f)})(),
        }
        src = SRC.replace("'/var/lib/takwerx-console/update-now.lock'", repr(str(self.update_lock)))
        src = src.replace("'/tmp/takwerx-post-update.lock'", repr(str(self.post_lock)))
        src = re.sub(r"^@app\.route\(.*\)\n", '', src, flags=re.M)
        src = re.sub(r"^@login_required\n", '', src, flags=re.M)
        exec(compile(src, 'app.py', 'exec'), n)
        # stand-ins that must replace the real definitions (and the timings), applied after exec
        n['_fetch_latest_tag_name'] = lambda: NEW
        n['_UPDATE_RESTART_DELAY_S'] = 0.1
        n['_UPDATE_RESTART_WAIT_S'] = 3
        n.update(over)
        self._flask = flask_app
        return n

    def click(self, **over):
        n = self.ns(**over)
        with self._flask.test_request_context('/api/update/apply', method='POST'):
            resp = n['update_apply']()
        status = 200
        if isinstance(resp, tuple):
            resp, status = resp
        return resp.get_json(), status, n


@pytest.fixture
def box(tmp_path):
    b = Box(tmp_path)
    b.write_release(NEW, app=APP_PY.format(v='1.0.1-alpha'),
                    req=f'pytest=={_installed("pytest")}\n')
    return b


def test_the_lifted_names_exist():
    assert not _MISSING_F and not _MISSING_A, (_MISSING_F, _MISSING_A)


# --- items 1 and 2: the new pins are installed BEFORE HEAD moves; a pip failure changes nothing

def test_item1_a_new_pin_is_installed_before_the_restart(box):
    box.write_release('v1.0.2-alpha', app=APP_PY.format(v='1.0.2-alpha'),
                      req=f'pytest=={_installed("pytest")}\nnewlib==9.9 \\\n    --hash=sha256:{"0" * 64}\n')
    out, _, _ = box.click(_fetch_latest_tag_name=lambda: 'v1.0.2-alpha')
    assert out['success'] is True, out
    installs = box.pip_installs()
    assert len(installs) == 1 and '-r' in installs[0], installs
    assert box.head_tag() == 'v1.0.2-alpha'
    assert box.restarts, 'a restart was asked for'


def test_item2_a_pip_error_stops_before_head_moves(box):
    box.write_release('v1.0.2-alpha', app=APP_PY.format(v='1.0.2-alpha'),
                      req='newlib==9.9\n')
    box.pip_rc.write_text('1')
    out, _, _ = box.click(_fetch_latest_tag_name=lambda: 'v1.0.2-alpha')
    assert out['success'] is False
    assert 'before anything was changed' in out['error'] and 'newlib' in out['error']
    assert box.head_tag() == OLD, 'HEAD moved although the new pins could not be installed'
    assert not box.restarts
    assert not box.update_lock.exists(), 'the lock must not outlive a refused click'


def test_item2_a_pip_timeout_stops_before_head_moves(box):
    box.write_release('v1.0.2-alpha', app=APP_PY.format(v='1.0.2-alpha'), req='newlib==9.9\n')
    box.pip_sleep.write_text('5')
    out, _, _ = box.click(_fetch_latest_tag_name=lambda: 'v1.0.2-alpha', _UPDATE_PIP_TIMEOUT_S=1)
    assert out['success'] is False and 'did not finish' in out['error'], out
    assert box.head_tag() == OLD and not box.restarts


def test_pins_that_are_already_installed_need_no_pip_and_no_network(box):
    out, _, _ = box.click()
    assert out['success'] is True, out
    assert box.pip_installs() == [], 'every pin was already met: pip must not run'
    assert box.head_tag() == NEW


# --- item 3: a tree that cannot start is refused before the restart ---------------------------

def test_item3_a_syntax_error_in_the_new_tree_is_refused(box):
    box.write_release('v1.0.2-alpha', app='VERSION = "1.0.2-alpha"\ndef broken(:\n',
                      req=f'pytest=={_installed("pytest")}\n')
    out, _, _ = box.click(_fetch_latest_tag_name=lambda: 'v1.0.2-alpha')
    assert out['success'] is False and 'safety check' in out['error'] and 'app.py' in out['error']
    assert box.head_tag() == OLD and not box.restarts


def test_item3_a_library_nobody_installed_is_refused(box):
    box.write_release('v1.0.2-alpha',
                      app='VERSION = "1.0.2-alpha"\nimport os\nimport newlib_ops1329_xyz\n',
                      req=f'pytest=={_installed("pytest")}\n')
    out, _, _ = box.click(_fetch_latest_tag_name=lambda: 'v1.0.2-alpha')
    assert out['success'] is False and 'newlib_ops1329_xyz' in out['error']
    assert box.head_tag() == OLD and not box.restarts


def test_item3_optional_and_late_imports_are_not_a_failure(box):
    box.write_release('v1.0.2-alpha', app=(
        'VERSION = "1.0.2-alpha"\nimport os\n'
        'try:\n    import optional_ops1329_xyz\nexcept ImportError:\n    optional_ops1329_xyz = None\n'
        'def later():\n    import late_ops1329_xyz\n'
        'from modules import thing\n'),
        req=f'pytest=={_installed("pytest")}\n',
        extra={'modules/__init__.py': '', 'modules/thing.py': 'x = 1\n'})
    out, _, _ = box.click(_fetch_latest_tag_name=lambda: 'v1.0.2-alpha')
    assert out['success'] is True, out
    assert box.head_tag() == 'v1.0.2-alpha'


def test_a_broken_check_does_not_block_an_update(box):
    """The check can only add protection: if it cannot run, the update goes ahead as before."""
    out, _, _ = box.click(_update_preflight_tree=lambda *a, **k: (True, ''))
    assert out['success'] is True and box.head_tag() == NEW
    n = box.ns()
    r = n['_update_preflight_tree'](str(box.console), 'refs/tags/does-not-exist',
                                    log=lambda m: None)
    assert r == (True, '')


# --- item 4: the first rollback tag survives an interrupted update ----------------------------

def test_item4_second_click_keeps_the_first_rollback_tag(box):
    box.restart_argv = ['false']          # click one moves HEAD, the restart never comes
    out1, _, _ = box.click()
    assert out1['success'] is False and out1.get('restart_failed') is True
    assert box.head_tag() == NEW
    assert box.settings['console_rollback']['tag'] == OLD
    out2, _, _ = box.click()              # still the OLD code running: VERSION unchanged
    assert box.settings['console_rollback']['tag'] == OLD, (
        'click two read the NEW tag from HEAD and made it the rollback target')
    assert box.settings['console_rollback']['version'] == '1.0.0-alpha'


def test_item4_a_finished_update_gets_a_new_snapshot():
    n = {}
    exec(compile(_lift(['_update_rollback_snapshot'], [])[0], 'app.py', 'exec'), n)
    snap = n['_update_rollback_snapshot']
    prev = {'available': True, 'version': '1.0.0-alpha', 'tag': OLD, 'snapshot_at': 'x'}
    assert snap(prev, '1.0.0-alpha', NEW, 'now') is prev
    fresh = snap(prev, '1.0.1-alpha', NEW, 'now')           # the update finished: new version runs
    assert fresh['tag'] == NEW and fresh['version'] == '1.0.1-alpha'
    assert snap({'available': False}, '1.0.1-alpha', '', 'now')['tag'] == 'v1.0.1-alpha'
    assert snap(None, '1.0.1-alpha', NEW, 'now')['tag'] == NEW
    assert snap({'available': True, 'tag': OLD}, '1.0.1-alpha', NEW, 'now')['tag'] == NEW


# --- item 5: a stale .git/index.lock is cleared ------------------------------------------------

def test_item5_a_stale_index_lock_is_cleared(box):
    lock = box.console / '.git' / 'index.lock'
    lock.write_text('')
    old = time.time() - 3600
    os.utime(lock, (old, old))
    out, _, _ = box.click()
    assert out['success'] is True, out
    assert box.head_tag() == NEW and not lock.exists()


def test_item5_a_fresh_index_lock_is_kept_and_explained_in_plain_words(box):
    lock = box.console / '.git' / 'index.lock'
    lock.write_text('')
    out, _, _ = box.click()
    assert out['success'] is False
    assert 'Another git command is still running' in out['error'] and 'Unable to create' not in out['error']
    assert lock.exists(), 'a lock a live git may hold must stay'
    assert box.head_tag() == OLD


# --- item 6: the check and Update Now take the same release ------------------------------------

class _Resp:
    def __init__(self, body):
        self._b = json.dumps(body).encode()

    def read(self, *a):
        return self._b


def _gh(monkeypatch, tags, main_shas):
    def fake(req, timeout=None):
        url = req.full_url if hasattr(req, 'full_url') else req
        if url.endswith('/tags'):
            return _Resp(tags)
        if 'commits?sha=main' in url:
            if main_shas is None:
                raise OSError('refused')
            return _Resp([{'sha': s} for s in main_shas])
        raise AssertionError(url)
    monkeypatch.setattr(urllib.request, 'urlopen', fake)


TAGS = [
    {'name': 'v10.5.0-alpha', 'commit': {'sha': 'devonly'}},
    {'name': 'v10.4.9-alpha', 'commit': {'sha': 'onmain1'}},
    {'name': 'v10.4.8-alpha', 'commit': {'sha': 'onmain0'}},
]


def _fetcher():
    n = {'urllib': urllib, 'json': json, 'GITHUB_REPO': 'takwerx/infra-TAK',
         '_fetch_latest_tag_name_from_git': lambda: 'GIT-FALLBACK'}
    exec(compile(_lift(['_tag_version_tuple', '_main_commit_shas', '_select_latest_release_tag',
                        '_fetch_latest_tag_name'], [])[0], 'app.py', 'exec'), n)
    return n


def test_item6_a_dev_only_tag_is_not_installed_on_the_main_channel(monkeypatch):
    _gh(monkeypatch, TAGS, ['onmain1', 'onmain0'])
    assert _fetcher()['_fetch_latest_tag_name']() == 'v10.4.9-alpha'


def test_item6_apply_and_check_pick_the_same_tag(monkeypatch):
    _gh(monkeypatch, TAGS, ['onmain1', 'onmain0'])
    n = _fetcher()
    check = n['_select_latest_release_tag'](TAGS, n['_main_commit_shas']())
    assert check['name'] == n['_fetch_latest_tag_name']() == 'v10.4.9-alpha'
    # update_check itself calls the shared helpers (no second copy of the rule)
    chk = ast.get_source_segment(APP, next(x for x in ast.parse(APP).body
                                           if isinstance(x, ast.FunctionDef) and x.name == 'update_check'))
    assert '_select_latest_release_tag(' in chk and '_main_commit_shas(' in chk


def test_item6_main_unreadable_trusts_the_list_like_the_check_always_did(monkeypatch):
    _gh(monkeypatch, TAGS, None)
    assert _fetcher()['_fetch_latest_tag_name']() == 'v10.5.0-alpha'


def test_item6_no_tag_found_refuses_instead_of_installing_the_tip_of_main(box):
    out, _, _ = box.click(_fetch_latest_tag_name=lambda: None)
    assert out['success'] is False and 'newest release' in out['error']
    assert box.head_tag() == OLD, 'Update Now installed whatever main points at'


# --- item 7: a restart that fails is told, not hidden ------------------------------------------

def test_item7_a_failed_restart_is_returned_and_frees_the_lock(box):
    box.restart_argv = ['sh', '-c', 'echo "Failed to connect to bus" >&2; exit 1']
    out, _, _ = box.click()
    assert out['success'] is False and out['restart_failed'] is True
    assert 'Failed to connect to bus' in out['error']
    assert not box.update_lock.exists(), 'a retry must not wait 20 minutes'


def test_item7_a_restart_that_works_still_answers_success(box):
    box.restart_argv = ['sleep', '2']     # systemctl restart blocks while it bounces the console
    out, _, _ = box.click(_UPDATE_RESTART_WAIT_S=0.5)
    assert out['success'] is True and out['restart_required'] is True
    assert box.update_lock.exists(), 'the success path keeps the lock for the post-update deploy'


# --- item 8: no second click while the post-update deploy runs --------------------------------

def test_item8_a_click_during_post_update_is_refused(box):
    box.post_lock.write_text(f'{os.getpid()} 1.0.1-alpha\n')
    out, status, _ = box.click()
    assert status == 409 and out['in_progress'] is True
    assert 'still finishing its setup' in out['error']
    assert box.head_tag() == OLD and not box.update_lock.exists()


def test_item8_a_dead_or_old_post_update_lock_does_not_block(box):
    box.post_lock.write_text('999999 1.0.1-alpha\n')       # no such process
    out, _, _ = box.click(); assert out['success'] is True
    old = Box(box.root / 'second')
    old.write_release(NEW, app=APP_PY.format(v='1.0.1-alpha'), req=f'pytest=={_installed("pytest")}\n')
    old.post_lock.write_text(f'{os.getpid()} 1.0.1-alpha\n')
    t = time.time() - 3600                                   # alive pid but older than 30 min
    os.utime(old.post_lock, (t, t))
    out, _, _ = old.click(); assert out['success'] is True


# --- the scripts run against the real repo files ----------------------------------------------

def test_the_pin_reader_understands_the_real_requirements_file(tmp_path):
    n = {}
    exec(compile(_lift([], ['_UPDATE_REQ_CHECK_PY'])[0], 'app.py', 'exec'), n)
    r = subprocess.run([sys.executable, '-I', '-c', n['_UPDATE_REQ_CHECK_PY'], str(REPO / 'requirements.txt')],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert isinstance(json.loads(r.stdout.strip().splitlines()[-1]), list)


def test_an_unmet_and_a_met_pin_are_told_apart(tmp_path):
    n = {}
    exec(compile(_lift([], ['_UPDATE_REQ_CHECK_PY'])[0], 'app.py', 'exec'), n)
    req = tmp_path / 'r.txt'
    req.write_text(
        f'pytest=={_installed("pytest")} \\\n    --hash=sha256:{"a" * 64}\n'
        'pytest==0.0.1 ; python_full_version < "2.0"\n'
        'nolib-ops1329==1.2.3 \\\n    --hash=sha256:' + 'b' * 64 + '\n')
    r = subprocess.run([sys.executable, '-I', '-c', n['_UPDATE_REQ_CHECK_PY'], str(req)],
                       capture_output=True, text=True)
    assert json.loads(r.stdout.strip().splitlines()[-1]) == ['nolib-ops1329 (missing)']


def test_the_real_tree_compiles_under_the_checker():
    n = {}
    exec(compile(_lift([], ['_UPDATE_TREE_CHECK_PY'])[0], 'app.py', 'exec'), n)
    r = subprocess.run([sys.executable, '-I', '-c', n['_UPDATE_TREE_CHECK_PY']], cwd=REPO,
                       capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr[-500:]
    res = json.loads(r.stdout.strip().splitlines()[-1])
    assert res['compile_errors'] == []
    # libraries the CI test environment may not carry are not a verdict on the repo; the names must
    # at least be real top-level imports, never one of our own packages
    assert not {'modules', 'broker'} & set(res['missing_imports'])
