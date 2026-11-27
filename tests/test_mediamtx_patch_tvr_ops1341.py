# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1341: three ways a working MediaMTX / TAK Video Restreamer box was put back or left behind.

1. "Patch web editor" overwrote the editor with the console's pinned release without looking at
   the version, so an editor moved up through its own Upgrade (v2.1.20) went back to v2.1.17.
   Its remote path was `curl -sL ... -o editor.py` (no -f, no temp file): a 404 page became the
   editor. Its local path kept going on a failed download without saying so.
2. `/api/mediamtx/deploy` ran a whole deploy over an installed MediaMTX when POSTed directly.
3. TAK Video Restreamer said "up to date" after an update whose checkout moved to the pin but
   whose image build failed.

The app.py code is run for real, against a fake host (no network, no root).
"""
import ast
import os
import pathlib
import posixpath
import re
import shlex
import stat
import subprocess
import sys
import types
import urllib.error
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(APP)

EDITOR_PATH = '/opt/mediamtx-webeditor/mediamtx_config_editor.py'
PIN = 'v2.1.17'
RAW_URL = 'https://raw.githubusercontent.com/takwerx/mediamtx-installer/abc/config-editor/mediamtx_config_editor.py'


def _fn(name):
    for node in _TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    return None


def _const(name):
    for node in _TREE.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    return None


def editor_text(version, port=5000):
    """A small stand-in for the real editor: it has what the checks look for."""
    return ('import os\nfrom flask import Flask\n'
            f'CURRENT_VERSION = "v{version}"\n'
            'app = Flask(__name__)\n\n@app.route("/")\ndef index():\n    return "ok"\n\n'
            'if __name__ == "__main__":\n'
            f"    app.run(host='0.0.0.0', port={port})  # MediaMTX API 9997\n")


PINNED = editor_text('2.1.17')


# ── a fake host that runs the real app.py functions ─────────────────────────────────────

class Host:
    """Local or remote MediaMTX box. Loads the real functions from app.py into a namespace."""

    HELPERS = ('_mediamtx_editor_installed_version', '_mediamtx_version_tuple',
               '_mediamtx_editor_newer_than_pin', '_mediamtx_editor_body_problem',
               '_mediamtx_editor_remote_fetch_cmd', '_mediamtx_editor_refresh')

    def __init__(self, monkeypatch, editor=None, remote=False, download=PINNED, download_error=None):
        self.files = {} if editor is None else {EDITOR_PATH: editor}
        self.writes, self.root_cmds, self.run_cmds = [], [], []
        self.ensure_deps_calls = 0
        host = self
        self.cfg = {'target_mode': 'remote', 'remote': {'host': '10.0.0.9'}} if remote else {}

        class Resp:
            def __enter__(s):
                return s

            def __exit__(s, *a):
                return False

            def read(s):
                return download.encode() if isinstance(download, str) else download

        def urlopen(url, timeout=0):
            host.fetched = url
            if download_error:
                raise download_error
            return Resp()

        monkeypatch.setattr(urllib.request, 'urlopen', urlopen)

        def module_run(cfg, cmd, timeout=0, log_fn=None):
            host.run_cmds.append(cmd)
            if 'CURRENT_VERSION' in cmd and 'grep' in cmd:        # the remote version read
                text = host.files.get(EDITOR_PATH, '')
                m = re.search(r'CURRENT_VERSION = "[^"]+"', text)
                return True, (m.group(0) + '\n') if m else ''
            if 'is-active' in cmd:
                return True, 'active\n'
            return True, ''

        def module_run_root(cfg, cmd, timeout=0, log_fn=None):
            host.root_cmds.append(cmd)
            return True, ''

        def write_priv(path, content, **kw):
            host.writes.append((path, content))
            host.files[path] = content

        def ensure_deps():
            host.ensure_deps_calls += 1
            return True, 'ok'

        fake_os = types.SimpleNamespace(
            path=types.SimpleNamespace(isfile=lambda p: p in host.files, exists=lambda p: p in host.files,
                                       dirname=posixpath.dirname, abspath=lambda p: p, join=posixpath.join),
            unlink=lambda p: None)
        self.ns = {
            'os': fake_os, 're': re, 'shlex': shlex, '__file__': '/opt/infratak/app.py',
            'subprocess': types.SimpleNamespace(run=lambda *a, **k: None),
            'jsonify': lambda d: d,
            'load_settings': lambda: {}, '_get_module_deployment_config': lambda s, k: host.cfg,
            '_mediamtx_editor_reclaim': lambda plog=None: [], '_mediamtx_hand_over_files': lambda o: None,
            '_mediamtx_owner': lambda: 'takwerx', '_sudo_wrap': lambda c: c,
            '_mediamtx_remote_clear_staging': lambda c: None,
            '_module_run': module_run, '_module_run_root': module_run_root,
            '_module_copy': lambda *a, **k: (True, ''),
            '_write_priv': write_priv, '_read_priv': lambda p: host.files.get(p),
            '_read_own_or_priv': lambda p: host.files.get(p),
            '_mediamtx_editor_endpoint_patch': lambda s: s,
            '_mediamtx_editor_broker_deps_patch': lambda s: s,
            '_mediamtx_editor_logstream_patch': lambda s: s,
            '_mediamtx_editor_unit_with_prestart': lambda t: t,
            '_mediamtx_editor_trusted_proxies': lambda s, c: '',
            '_MEDIAMTX_TRUSTED_PROXIES_KEY': 'K', 'MEDIAMTX_ENSURE_OVERLAY_SCRIPT': '# overlay\n',
            'MEDIAMTX_REMOTE_EP_PATCH_SCRIPT': '# patch\n', '_MEDIAMTX_EDITOR_PY_PKGS': ('Flask',),
            '_mediamtx_editor_ensure_py_deps': ensure_deps,
            '_mediamtx_editor_remote_py_deps': lambda c: (True, 'ok'),
            'MEDIAMTX_EDITOR_REF': PIN, 'MEDIAMTX_EDITOR_RAW_URL': RAW_URL,
        }
        for name in ('_MEDIAMTX_EDITOR_REMOTE_CHECK',):
            src = _const(name)
            if src:
                exec(compile(src, 'app.py', 'exec'), self.ns)
        for name in self.HELPERS:
            src = _fn(name)
            if src:                                           # absent on the base branch
                exec(compile(src, 'app.py', 'exec'), self.ns)
        exec(compile(_fn('mediamtx_recovery'), 'app.py', 'exec'), self.ns)

    def patch(self):
        return self.ns['mediamtx_recovery']()

    def editor_writes(self):
        return [w for w in self.writes if w[0] == EDITOR_PATH]

    def editor_changes(self, original):
        """Writes that put DIFFERENT text in the editor file. Patch step 2 rewrites the file with
        the endpoint patches applied (unchanged text when there is nothing to patch): not a refresh."""
        return [w for w in self.editor_writes() if w[1] != original]


# ── the version and download checks ─────────────────────────────────────────────────────

def _helpers():
    ns = {'re': re, 'MEDIAMTX_EDITOR_REF': PIN}
    for name in ('_mediamtx_version_tuple', '_mediamtx_editor_newer_than_pin', '_mediamtx_editor_body_problem'):
        src = _fn(name)
        assert src, f'{name} is missing from app.py'
        exec(compile(src, 'app.py', 'exec'), ns)
    return ns


@pytest.mark.parametrize('installed,newer', [
    ('2.1.18', True), ('v2.1.20', True), ('2.2.0', True), ('3.0.0', True), ('V2.1.18', True),
    ('2.1.17', False), ('v2.1.17', False), ('2.1.16', False), ('2.1.14', False), ('2.0.99', False),
    ('', False), (None, False), ('main', False), ('2.1', False), ('2.1.18-rc1', False), ('latest', False)])
def test_only_a_plainly_newer_editor_is_kept(installed, newer):
    assert _helpers()['_mediamtx_editor_newer_than_pin'](installed) is newer


def test_a_pin_that_is_not_a_version_keeps_nothing():
    ns = _helpers()
    ns['MEDIAMTX_EDITOR_REF'] = 'main'
    assert ns['_mediamtx_editor_newer_than_pin']('9.9.9') is False


def test_a_whole_editor_passes_the_download_check():
    assert _helpers()['_mediamtx_editor_body_problem'](PINNED) is None


@pytest.mark.parametrize('body', [
    '', '   \n', '404: Not Found', '<html><body>Sign in to the guest network</body></html>',
    PINNED[:-30],                                               # a link cut mid-line: not valid Python
    'x = 1\nCURRENT_VERSION = "v2.1.17"\n',                     # valid Python, no Flask app
    'from flask import Flask\napp = Flask(__name__)\n',         # a Flask app that is not the editor
    PINNED + '\x00',
])
def test_anything_that_is_not_a_whole_editor_is_refused(body):
    assert _helpers()['_mediamtx_editor_body_problem'](body) is not None


def test_non_text_is_refused():
    assert _helpers()['_mediamtx_editor_body_problem'](None) is not None


# ── Patch web editor, local ─────────────────────────────────────────────────────────────

def test_patch_keeps_an_editor_that_is_newer_than_the_pin(monkeypatch):
    """The bug: an editor on v2.1.20 (editor's own Upgrade) went back to the console's v2.1.17."""
    original = editor_text('2.1.20', port=5080)
    h = Host(monkeypatch, editor=original)
    out = h.patch()
    assert h.editor_changes(original) == [], 'the newer editor was overwritten'
    assert 'CURRENT_VERSION = "v2.1.20"' in h.files[EDITOR_PATH]
    assert out['success'] is True and out['editor_refreshed'] is False and out['editor_version'] == '2.1.20'
    assert 'v2.1.20' in out['message'] and 'v2.1.17' in out['message']


def test_patch_still_repairs_everything_else_on_a_newer_editor(monkeypatch):
    """The button is also how a box with no Flask is repaired: only the file download is skipped."""
    h = Host(monkeypatch, editor=editor_text('2.1.20'))
    out = h.patch()
    assert h.ensure_deps_calls == 1
    assert any('systemctl restart mediamtx-webeditor' in c for c in h.root_cmds)
    assert any(p == '/opt/mediamtx-webeditor/ensure_overlay.py' for p, _c in h.writes)
    assert out['webeditor_running'] is True


@pytest.mark.parametrize('installed', ['2.1.17', '2.1.16', '2.1.15', '2.1.14', '2.0.9'])
def test_patch_still_refreshes_an_editor_that_is_not_newer(monkeypatch, installed):
    h = Host(monkeypatch, editor=editor_text(installed))
    out = h.patch()
    writes = h.editor_changes(editor_text(installed))
    assert writes and all('CURRENT_VERSION = "v2.1.17"' in w[1] for w in writes)
    assert "host='127.0.0.1'" in writes[0][1] and 'port=5080' in writes[0][1] and '9898' in writes[0][1]
    assert out['editor_refreshed'] is True and 'left at' not in out['message']


@pytest.mark.parametrize('current', [None, 'import os\n# hand edited, no version\n'])
def test_patch_refreshes_an_editor_it_cannot_read_a_version_from(monkeypatch, current):
    h = Host(monkeypatch, editor=current)
    out = h.patch()
    assert 'CURRENT_VERSION = "v2.1.17"' in h.files[EDITOR_PATH] and out['editor_refreshed'] is True


@pytest.mark.parametrize('body', ['404: Not Found', '<html>captive portal</html>', PINNED[:-30], ''])
def test_patch_keeps_the_file_when_the_download_is_not_an_editor(monkeypatch, body):
    original = editor_text('2.1.15')
    h = Host(monkeypatch, editor=original, download=body)
    out = h.patch()
    assert h.editor_changes(original) == []
    assert 'CURRENT_VERSION = "v2.1.15"' in h.files[EDITOR_PATH]
    assert out['success'] is True and out['editor_refreshed'] is False
    assert 'not refreshed' in out['message']
    assert h.ensure_deps_calls == 1                       # the rest of the repair still ran


def test_patch_says_so_when_the_download_fails(monkeypatch):
    original = editor_text('2.1.15')
    h = Host(monkeypatch, editor=original, download_error=urllib.error.URLError('offline'))
    out = h.patch()
    assert h.editor_changes(original) == []
    assert out['editor_refreshed'] is False and 'could not be downloaded' in out['message']


# ── Patch web editor, remote host ───────────────────────────────────────────────────────

def test_remote_patch_downloads_to_a_temp_file_and_checks_before_replacing(monkeypatch):
    h = Host(monkeypatch, editor=editor_text('2.1.15'), remote=True)
    h.patch()
    fetch = [c for c in h.root_cmds if 'curl' in c]
    assert len(fetch) == 1
    cmd = fetch[0]
    assert 'curl -fsSL' in cmd and 'mktemp' in cmd and 'ast.parse' in cmd
    assert '-o /opt/mediamtx-webeditor' not in cmd, 'curl wrote straight into the live editor file'
    assert cmd.index('ast.parse') < cmd.index('cat "$t" >'), 'the file is replaced before it is checked'


def test_remote_patch_keeps_a_newer_editor_and_still_hardens_and_restarts(monkeypatch):
    h = Host(monkeypatch, editor=editor_text('2.1.20'), remote=True)
    out = h.patch()
    assert not [c for c in h.root_cmds if 'curl' in c]
    assert any("sed -i 's/port=5000/port=5080/'" in c for c in h.root_cmds)
    assert any('systemctl restart mediamtx-webeditor' in c for c in h.root_cmds)
    assert out['editor_refreshed'] is False and out['editor_version'] == '2.1.20'


def test_remote_patch_reports_a_failed_download(monkeypatch):
    h = Host(monkeypatch, editor=editor_text('2.1.15'), remote=True)
    real = h.ns['_module_run_root']
    h.ns['_module_run_root'] = lambda cfg, cmd, **k: ((False, 'curl: (22) The requested URL returned error: 404')
                                                      if 'curl' in cmd else real(cfg, cmd, **k))
    out = h.patch()
    assert out['success'] is True and out['editor_refreshed'] is False
    assert 'kept' in out['message'] and '404' in out['message']


@pytest.fixture
def shell_box(tmp_path):
    """A real shell with a stand-in `curl` that serves FIXTURE (or fails like curl -f does)."""
    shim = tmp_path / 'bin'
    shim.mkdir()
    curl = shim / 'curl'
    curl.write_text(
        '#!/bin/sh\nout=""\nwhile [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done\n'
        '[ -n "$CURL_FAIL" ] && exit "$CURL_FAIL"\ncat "$FIXTURE" > "$out"\n')
    curl.chmod(curl.stat().st_mode | stat.S_IXUSR)
    live = tmp_path / 'webeditor' / 'mediamtx_config_editor.py'
    live.parent.mkdir()
    live.write_text(editor_text('2.1.15'))
    ns = {'os': os, 'shlex': shlex, 'MEDIAMTX_EDITOR_RAW_URL': RAW_URL}
    exec(compile(_const('_MEDIAMTX_EDITOR_REMOTE_CHECK'), 'app.py', 'exec'), ns)
    exec(compile(_fn('_mediamtx_editor_remote_fetch_cmd'), 'app.py', 'exec'), ns)

    def run(body, curl_fail=''):
        fixture = tmp_path / 'fixture'
        fixture.write_text(body)
        env = {'PATH': f'{shim}:{os.environ["PATH"]}', 'FIXTURE': str(fixture), 'CURL_FAIL': curl_fail,
               'TMPDIR': str(tmp_path)}
        cmd = ns['_mediamtx_editor_remote_fetch_cmd'](str(live))
        return subprocess.run(['sh', '-c', cmd], env=env, capture_output=True, text=True, timeout=60)
    return run, live


def test_remote_command_replaces_the_file_with_a_whole_editor(shell_box):
    run, live = shell_box
    assert run(PINNED).returncode == 0
    assert live.read_text() == PINNED


@pytest.mark.parametrize('body', ['404: Not Found\n', '<html>captive portal</html>\n', PINNED[:-30], ''])
def test_remote_command_never_replaces_the_file_with_a_bad_download(shell_box, body):
    run, live = shell_box
    before = live.read_text()
    assert run(body).returncode != 0
    assert live.read_text() == before


def test_remote_command_leaves_the_file_when_curl_fails(shell_box):
    run, live = shell_box
    before = live.read_text()
    assert run(PINNED, curl_fail='22').returncode == 22
    assert live.read_text() == before


def test_remote_command_keeps_the_files_owner_and_mode(shell_box):
    run, live = shell_box
    live.chmod(0o640)
    ino = live.stat().st_ino
    assert run(PINNED).returncode == 0
    assert stat.S_IMODE(live.stat().st_mode) == 0o640 and live.stat().st_ino == ino


def test_no_temp_file_is_left_behind(shell_box, tmp_path):
    run, _live = shell_box
    run('404: Not Found\n')
    run(PINNED)
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith('tmp')] == []


# ── Deploy refuses an installed MediaMTX ────────────────────────────────────────────────

class DeployBox:
    def __init__(self, mods, detect_raises=False, running=False):
        self.saved, self.started = [], []
        box = self

        class Thread:
            def __init__(s, target=None, daemon=None):
                s.target = target

            def start(s):
                box.started.append(s.target)

        def detect_modules(fresh=False):
            if detect_raises:
                raise RuntimeError('probe failed')
            return mods

        self.ns = {
            'mediamtx_deploy_status': {'running': running, 'complete': False, 'error': False},
            'mediamtx_deploy_log': [], 'jsonify': lambda d: d, 'detect_modules': detect_modules,
            'request': types.SimpleNamespace(get_json=lambda: {'config': {'target_mode': 'local'}}),
            'load_settings': lambda: {}, 'save_settings': lambda s: box.saved.append(dict(s)),
            '_normalize_module_deployment_config': lambda c: c, 'run_mediamtx_deploy': lambda: None,
            'threading': types.SimpleNamespace(Thread=Thread),
        }
        exec(compile(_fn('mediamtx_deploy_api'), 'app.py', 'exec'), self.ns)

    def post(self):
        r = self.ns['mediamtx_deploy_api']()
        return r if isinstance(r, tuple) else (r, 200)


def test_deploy_is_refused_when_mediamtx_is_already_installed():
    box = DeployBox({'mediamtx': {'installed': True}})
    body, code = box.post()
    assert code == 409 and 'already installed' in body['error'] and 'Patch web editor' in body['error']
    assert box.saved == [], 'the deployment config was saved before the refusal'
    assert box.started == []
    assert box.ns['mediamtx_deploy_status']['running'] is False


def test_first_deploy_still_runs():
    box = DeployBox({'mediamtx': {'installed': False}, 'tak_video_restreamer': {'installed': False}})
    body, code = box.post()
    assert code == 200 and body == {'success': True}
    assert len(box.saved) == 1 and len(box.started) == 1


def test_an_unreadable_probe_never_blocks_a_first_deploy():
    box = DeployBox({}, detect_raises=True)
    body, code = box.post()
    assert code == 200 and len(box.started) == 1


def test_the_tvr_conflict_refusal_is_unchanged():
    box = DeployBox({'mediamtx': {'installed': False}, 'tak_video_restreamer': {'installed': True}})
    body, code = box.post()
    assert code == 409 and 'TAK Video Restreamer' in body['error'] and box.started == []


def test_a_deploy_already_running_is_still_refused_first():
    body, code = DeployBox({'mediamtx': {'installed': True}}, running=True).post()
    assert code == 409 and 'already in progress' in body['error']


def test_deploy_guard_asks_for_fresh_data():
    src = re.sub(r'#.*', '', _fn('mediamtx_deploy_api'))
    assert 'detect_modules(fresh=True)' in src and 'detect_modules()' not in src


# ── The editor version reader is shared, and reads what it read before ──────────────────

def test_version_info_uses_the_shared_reader_and_nothing_else_changed():
    info = _fn('_get_mediamtx_editor_version_info')
    assert "out['version'] = _mediamtx_editor_installed_version(deploy_cfg)" in info
    assert 'grep -oE' not in info                       # the read moved; the page shows the same text


@pytest.mark.parametrize('text,expected', [
    ('CURRENT_VERSION = "v2.1.17"\n', '2.1.17'), ("CURRENT_VERSION = '2.1.20'\n", '2.1.20'),
    ('x = 1\n', ''), ('', '')])
def test_installed_version_reader_local(text, expected, monkeypatch):
    files = {EDITOR_PATH: text}
    ns = {'os': types.SimpleNamespace(path=types.SimpleNamespace(isfile=lambda p: p in files)),
          '_read_own_or_priv': lambda p: files.get(p)}
    exec(compile(_fn('_mediamtx_editor_installed_version'), 'app.py', 'exec'), ns)
    assert ns['_mediamtx_editor_installed_version']({}) == expected


def test_installed_version_reader_remote():
    ns = {'os': types.SimpleNamespace(path=types.SimpleNamespace(isfile=lambda p: False)),
          '_module_run': lambda cfg, cmd, timeout=0: (True, 'CURRENT_VERSION = "v2.1.20"\n')}
    exec(compile(_fn('_mediamtx_editor_installed_version'), 'app.py', 'exec'), ns)
    cfg = {'target_mode': 'remote', 'remote': {'host': 'h'}}
    assert ns['_mediamtx_editor_installed_version'](cfg) == '2.1.20'


# ── TAK Video Restreamer: an update whose build failed is not "up to date" ───────────────

import modules.tvr as tvr  # noqa: E402

OLD = 'a' * 40
CURRENT = {'tak_video_restreamer_publish_password': 'p',
           'tak_video_restreamer_mediamtx_version': tvr.TVR_MEDIAMTX_VERSION,
           'tak_video_restreamer_py_pins': tvr.TVR_PY_PINS_REV}

UPSTREAM_DOCKERFILE = (
    'FROM python:3.11-slim\nWORKDIR /opt/app\n\n# Download and install MediaMTX\n'
    'RUN MEDIAMTX_VERSION=v1.19.2 && \\\n'
    '    wget https://github.com/bluenviron/mediamtx/releases/download/${MEDIAMTX_VERSION}/'
    'mediamtx_${MEDIAMTX_VERSION}_linux_amd64.tar.gz && \\\n'
    '    tar -xzf mediamtx_${MEDIAMTX_VERSION}_linux_amd64.tar.gz && \\\n'
    '    rm mediamtx_${MEDIAMTX_VERSION}_linux_amd64.tar.gz && \\\n'
    '    chmod +x mediamtx\n\n# Copy MediaMTX configuration\nCOPY mediaMTX.yml /opt/app/mediamtx.yml\n')


class TvrBox:
    """A TVR box: the clone's HEAD, the recorded settings and whether the image build works."""

    def __init__(self, head=OLD, settings=None, build_ok=True):
        self.head, self.settings, self.build_ok = head, dict(settings or {}), build_ok
        box = self

        def module_git(d, *a, **k):
            if a[:2] == ('checkout', '-q') and a[2] == tvr.TVR_SHA:
                box.head = tvr.TVR_SHA
            elif a[:2] == ('checkout', '-q'):
                box.head = 'f' * 40                        # back on the branch tip
            out = box.head + '\n' if a[:1] == ('rev-parse',) else ''
            return subprocess.CompletedProcess(a, 0, out, '')

        def compose(dirpath, action, timeout=0):
            ok = box.build_ok or 'build' not in action
            return subprocess.CompletedProcess([], 0 if ok else 1, 'built\n' if ok else '',
                                               '' if ok else 'ERROR: failed to solve')

        reqs = '\n'.join(f'{n}=={v[0]}' for n, v in tvr.TVR_PY_PINS.items()) + '\n'
        files = {'Dockerfile': UPSTREAM_DOCKERFILE, 'requirements.txt': reqs}
        self.ctx = {
            '_module_git': module_git, '_sudo_wrap': lambda argv: ['false'],
            'load_settings': lambda: dict(box.settings),
            'save_settings': lambda s: box.settings.update(s),
            '_write_priv': lambda p, c, **k: None,
            '_read_priv': lambda p: next(v for k2, v in files.items() if p.endswith(k2)),
            '_host_arch': lambda: 'amd64', '_broker_compose': compose,
        }

    def info(self):
        return tvr.get_version_info(self.ctx)

    def update(self):
        tvr._update_status = {'running': True, 'complete': False, 'error': False, 'log': []}
        tvr._run_update(self.ctx)
        return tvr._update_status


def test_failed_build_after_the_checkout_still_offers_the_update():
    """The bug. Image built from an older commit; the update moves HEAD to the pin, the build fails."""
    box = TvrBox(head=OLD, settings=dict(CURRENT, tak_video_restreamer_commit_sha=OLD[:7]), build_ok=False)
    assert box.info()['update_available'] is True                       # before: HEAD is off the pin
    status = box.update()
    assert status['error'] and box.head == tvr.TVR_SHA                  # checkout moved, build failed
    after = box.info()
    assert after['update_available'] is True and after['unfinished_update'] is True
    assert after['security_update'] is False


def test_a_good_update_clears_it():
    box = TvrBox(head=OLD, settings=dict(CURRENT, tak_video_restreamer_commit_sha=OLD[:7]), build_ok=False)
    box.update()
    assert box.info()['update_available'] is True
    box.build_ok = True
    assert box.update()['complete'] is True
    after = box.info()
    assert after['update_available'] is False and after['unfinished_update'] is False
    assert box.settings['tak_video_restreamer_commit_sha'] == tvr.TVR_SHA[:7]


def test_a_box_built_at_the_pin_is_up_to_date():
    box = TvrBox(head=tvr.TVR_SHA, settings=dict(CURRENT, tak_video_restreamer_commit_sha=tvr.TVR_SHA[:7]))
    assert box.info()['update_available'] is False


def test_a_box_that_never_recorded_its_build_says_nothing_extra():
    """Installs from before the commit was recorded: unchanged (no new 'update available')."""
    box = TvrBox(head=tvr.TVR_SHA, settings=dict(CURRENT))
    info = box.info()
    assert info['update_available'] is False and info['unfinished_update'] is False


def test_a_failed_first_update_keeps_the_recorded_build_untouched():
    box = TvrBox(head=OLD, settings=dict(CURRENT, tak_video_restreamer_commit_sha=OLD[:7]), build_ok=False)
    box.update()
    assert box.settings['tak_video_restreamer_commit_sha'] == OLD[:7]


def test_tvr_data_folder_is_not_in_the_checkout_scope():
    """Upstream tracks nothing under data/ at the pin (checked with git ls-tree), and the clone
    is only ever moved with checkout of tracked files: no step in the module deletes data/."""
    src = (ROOT / 'modules' / 'tvr.py').read_text(encoding='utf-8')
    assert not re.search(r"'(clean|rm|reset)'", src.split('def checkout_pin', 1)[1].split('def tvr_dir', 1)[0])
