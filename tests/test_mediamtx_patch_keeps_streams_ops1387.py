# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1387: "Patch web editor" stopped MediaMTX itself even when it had nothing to write.

On a box where MediaMTX and its editor run as the `mediamtx` account (ops #643) the Patch route
first stopped BOTH services, took the editor folder back, then started them again. A live stream
dropped for a few seconds and its publisher had to reconnect, although an editor that was kept
(newer than the pin, ops #1341) and an overlay and prestart script that were already current left
nothing to write.

Now the route looks first. When no file in the folder needs writing it leaves MediaMTX alone and
restarts only the editor. The first file that does need writing sends it back to the top on the
old path (stop, take the folder back, write), so the ops #643 rule "nothing is written into the
folder while the account that owns it can plant links" is unchanged.

The app.py code is run for real against a real temporary folder (links, modes) and a fake host.
"""
import ast
import functools
import os
import pathlib
import re
import shlex
import stat
import sys
import types
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(APP)

PIN = 'v2.1.17'
OVERLAY_SRC = '# overlay from the infra-TAK repo\n'
ENSURE = '# ensure_overlay script\n'
REAL_DIR = '/opt/mediamtx-webeditor'


def _node(name, kind):
    for node in _TREE.body:
        if isinstance(node, kind) and node.name == name:
            return ast.get_source_segment(APP, node)
    return None


def _fn(name):
    return _node(name, ast.FunctionDef)


def _cls(name):
    return _node(name, ast.ClassDef)


def editor_text(version):
    return ('import os\nfrom flask import Flask\n'
            f'CURRENT_VERSION = "v{version}"\n'
            'app = Flask(__name__)\n\n@app.route("/")\ndef index():\n    return "ok"\n\n'
            "if __name__ == '__main__':\n"
            "    app.run(host='127.0.0.1', port=5080)  # MediaMTX API 9898\n")


class Box:
    """A local MediaMTX box: a real folder for the editor, everything else faked and recorded."""

    def __init__(self, tmp_path, monkeypatch, *, editor_version='2.1.20', overlay=OVERLAY_SRC, ensure=ENSURE,
                 ensure_mode=0o755, patch_changes=False, remote=False, migrated=True, deps_ok=True,
                 run_root_ok=True):
        self.ed = tmp_path / 'ed'
        self.ed.mkdir()
        self.events = []
        self.writes = []
        text = editor_text(editor_version) if editor_version is not None else \
            editor_text('2.1.20').replace('CURRENT_VERSION = "v2.1.20"\n', '')
        (self.ed / 'mediamtx_config_editor.py').write_text(text)
        if overlay is not None:
            (self.ed / 'mediamtx_ldap_overlay.py').write_text(overlay)
        if ensure is not None:
            p = self.ed / 'ensure_overlay.py'
            p.write_text(ensure)
            os.chmod(p, ensure_mode)
        (self.ed / 'users.json').write_text('{"admin": "hash"}')
        repo = tmp_path / 'repo'
        repo.mkdir()
        (repo / 'mediamtx_ldap_overlay.py').write_text(OVERLAY_SRC)
        self.app_file = str(repo / 'app.py')
        self.remote = remote
        box = self
        self.cfg = {'target_mode': 'remote', 'remote': {'host': '10.0.0.9'}} if remote else {}

        def swap(text):
            return text.replace(REAL_DIR, str(self.ed))

        def run(argv, **kw):
            argv = list(argv)
            box.events.append(('run', ' '.join(argv)))
            return types.SimpleNamespace(stdout='active\n', returncode=0)

        def reclaim(plog=None):
            box.events.append(('reclaim',))
            return ['mediamtx-webeditor', 'mediamtx'] if migrated else []

        def write_priv(path, content, mode='w', perm=None):
            box.events.append(('write', pathlib.Path(path).name))
            box.writes.append((pathlib.Path(path).name, content))
            pathlib.Path(path).write_text(content)
            if perm is not None:
                os.chmod(path, perm)

        def read_priv(path):
            box.events.append(('read', pathlib.Path(path).name))
            return pathlib.Path(path).read_text()

        def run_root(cfg, cmd, timeout=0, log_fn=None):
            box.events.append(('root', cmd))
            return run_root_ok, ''

        def run_plain(cfg, cmd, timeout=0, log_fn=None):
            return True, 'active\n'

        def urlopen(url, timeout=0):          # a download must never be needed on the kept path
            box.events.append(('download',))
            raise OSError('offline')

        monkeypatch.setattr(urllib.request, 'urlopen', urlopen)

        def endpoint_patch(s):
            return s + '# patched\n' if patch_changes else s

        ns = {
            'os': os, 're': re, 'shlex': shlex, '_stat': stat, '__file__': self.app_file, 'wraps': functools.wraps,
            'subprocess': types.SimpleNamespace(run=run), 'jsonify': lambda d: d,
            'load_settings': lambda: {}, '_get_module_deployment_config': lambda s, k: box.cfg,
            '_MEDIAMTX_EDITOR_DIR': str(self.ed), '_MEDIAMTX_CONF_DIR': str(tmp_path / 'etc'),
            '_mediamtx_owner': lambda: 'mediamtx' if migrated else 'takwerx',
            '_mediamtx_account_ready': lambda: migrated,
            '_mediamtx_editor_reclaim': reclaim,
            '_mediamtx_hand_over_files': lambda o: box.events.append(('hand_over', o)),
            '_sudo_wrap': lambda c: c, '_mediamtx_remote_clear_staging': lambda c: None,
            '_module_run': run_plain, '_module_run_root': run_root, '_module_copy': lambda *a, **k: (True, ''),
            '_write_priv': write_priv, '_read_priv': read_priv, '_read_own_or_priv': read_priv,
            '_mediamtx_editor_endpoint_patch': endpoint_patch,
            '_mediamtx_editor_broker_deps_patch': lambda s: s,
            '_mediamtx_editor_logstream_patch': lambda s: s,
            '_mediamtx_editor_unit_with_prestart': lambda t: t,
            '_mediamtx_editor_trusted_proxies': lambda s, c: '',
            '_MEDIAMTX_TRUSTED_PROXIES_KEY': 'K', 'MEDIAMTX_ENSURE_OVERLAY_SCRIPT': ENSURE,
            'MEDIAMTX_REMOTE_EP_PATCH_SCRIPT': '# patch\n', '_MEDIAMTX_EDITOR_PY_PKGS': ('Flask',),
            '_mediamtx_editor_ensure_py_deps': lambda: (deps_ok, 'ok'),
            '_mediamtx_editor_remote_py_deps': lambda c: (True, 'ok'),
            'MEDIAMTX_EDITOR_REF': PIN,
            'MEDIAMTX_EDITOR_RAW_URL': 'https://example.invalid/editor.py',
        }
        for name in ('_MEDIAMTX_EDITOR_REMOTE_CHECK',):
            for node in _TREE.body:
                if isinstance(node, ast.Assign) and any(getattr(t, 'id', '') == name for t in node.targets):
                    exec(compile(ast.get_source_segment(APP, node), 'app.py', 'exec'), ns)
        exec(compile(_cls('_MtxReclaimNeeded'), 'app.py', 'exec'), ns)
        for name in ('_mediamtx_version_tuple', '_mediamtx_editor_newer_than_pin', '_mediamtx_editor_body_problem',
                     '_mediamtx_editor_remote_fetch_cmd', '_mediamtx_editor_refresh',
                     '_mediamtx_editor_installed_version', '_mediamtx_editor_reclaim_applies',
                     '_mediamtx_editor_dir_has_links', '_mediamtx_editor_put',
                     '_mediamtx_patch_try_quiet_first', 'mediamtx_recovery'):
            exec(compile(swap(_fn(name)), 'app.py', 'exec'), ns)
        # as app.py decorates it: the first pass leaves MediaMTX running, the retry is the old path
        ns['mediamtx_recovery'] = ns['_mediamtx_patch_try_quiet_first'](ns['mediamtx_recovery'])
        self.ns = ns

    def patch(self):
        return self.ns['mediamtx_recovery']()

    def kinds(self):
        return [e[0] for e in self.events]

    def stopped_mediamtx(self):
        return any(e[0] == 'reclaim' for e in self.events)

    def writes_to_folder(self):
        return [e for e in self.events if e[0] == 'write']


# ── the headline: nothing to write, so MediaMTX is not stopped ─────────────────────────────

def test_kept_editor_and_current_files_leave_mediamtx_running(tmp_path, monkeypatch):
    box = Box(tmp_path, monkeypatch)
    before = {p.name: p.read_bytes() for p in box.ed.iterdir()}
    out = box.patch()
    assert out['success'] is True
    assert not box.stopped_mediamtx(), 'MediaMTX must not be stopped when nothing needs writing'
    assert out['mediamtx_stopped'] is False
    assert not box.writes_to_folder(), 'nothing may be written into the folder while MediaMTX runs'
    assert 'MediaMTX was not stopped' in out['message']
    assert out['editor_refreshed'] is False and out['editor_version'] == '2.1.20'
    # the editor is still restarted (that is what the button is for), and the files are untouched
    assert any(e[0] == 'root' and 'systemctl restart mediamtx-webeditor' in e[1] for e in box.events)
    assert {p.name: p.read_bytes() for p in box.ed.iterdir()} == before
    assert ('hand_over', 'mediamtx') in box.events      # ownership is still put right


@pytest.mark.skipif(os.geteuid() == 0, reason='root can open a folder of mode 000')
def test_the_kept_path_works_on_a_box_shaped_folder(tmp_path, monkeypatch):
    """A real box: __pycache__ 750 mediamtx (not listable by the console), users.json 600 and a
    share-links file next to the editor. The red-on-aws-arm case: the scan counted the unreadable
    __pycache__ and the route always stopped MediaMTX."""
    box = Box(tmp_path, monkeypatch)
    cache = box.ed / '__pycache__'
    cache.mkdir()
    (cache / 'x.pyc').write_text('x')
    os.chmod(cache, 0o000)
    os.chmod(box.ed / 'users.json', 0o600)
    try:
        out = box.patch()
    finally:
        os.chmod(cache, 0o755)
    assert out['success'] is True
    assert not box.stopped_mediamtx()
    assert out['mediamtx_stopped'] is False
    assert not box.writes_to_folder()


def test_nothing_in_the_kept_path_needs_a_download(tmp_path, monkeypatch):
    box = Box(tmp_path, monkeypatch)
    box.patch()
    assert ('download',) not in box.events


# ── every file that does need writing sends the route to the old, stopping path ────────────

@pytest.mark.parametrize('kw,what', [
    ({'overlay': '# a stale overlay\n'}, 'mediamtx_ldap_overlay.py'),
    ({'overlay': None}, 'mediamtx_ldap_overlay.py'),
    ({'ensure': '# an old prestart script\n'}, 'ensure_overlay.py'),
    ({'ensure': None}, 'ensure_overlay.py'),
    ({'ensure_mode': 0o644}, 'ensure_overlay.py'),       # same text, lost +x: still a write
    ({'patch_changes': True}, 'mediamtx_config_editor.py'),   # the patch chain would change the editor
    ({'editor_version': '2.1.17'}, 'mediamtx_config_editor.py'),   # equal to the pin: refreshed, as always
    ({'editor_version': '2.1.14'}, 'mediamtx_config_editor.py'),   # older than the pin
    ({'editor_version': None}, 'mediamtx_config_editor.py'),       # version unreadable: not "newer", refreshed
])
def test_a_needed_write_takes_the_old_path(tmp_path, monkeypatch, kw, what):
    box = Box(tmp_path, monkeypatch, **kw)
    out = box.patch()
    assert out['success'] is True
    assert box.kinds().count('reclaim') == 1, 'the folder is taken back exactly once'
    assert out['mediamtx_stopped'] is True
    assert 'MediaMTX was not stopped' not in out['message']
    # the order that ops #643 depends on: take the folder back, THEN write into it
    first_write = box.kinds().index('write')
    assert box.kinds().index('reclaim') < first_write
    # and the editor text that gets written was read after the take-back, never carried over from
    # a read made while MediaMTX could still plant a link
    reclaim_at = box.kinds().index('reclaim')
    editor_write = next((i for i, e in enumerate(box.events) if e == ('write', 'mediamtx_config_editor.py')), None)
    if editor_write is not None:
        assert any(e == ('read', 'mediamtx_config_editor.py') and reclaim_at < i < editor_write
                   for i, e in enumerate(box.events))
    assert what in [n for n, _ in box.writes]


def test_stale_overlay_is_written_even_though_the_step_swallows_errors(tmp_path, monkeypatch):
    """The overlay step sits inside `except Exception: pass`. The signal must get through it."""
    box = Box(tmp_path, monkeypatch, overlay='# a stale overlay\n')
    box.patch()
    assert (box.ed / 'mediamtx_ldap_overlay.py').read_text() == OVERLAY_SRC
    assert box.stopped_mediamtx()


def test_the_signal_is_not_an_exception():
    ns = {}
    exec(compile(_cls('_MtxReclaimNeeded'), 'app.py', 'exec'), ns)
    assert not issubclass(ns['_MtxReclaimNeeded'], Exception)
    assert issubclass(ns['_MtxReclaimNeeded'], BaseException)


def test_a_link_in_the_folder_takes_the_old_path_and_is_cleaned(tmp_path, monkeypatch):
    box = Box(tmp_path, monkeypatch)
    (box.ed / 'planted').symlink_to('/etc/hostname')
    out = box.patch()
    assert box.kinds().count('reclaim') == 1
    assert out['mediamtx_stopped'] is True
    assert 'read' not in box.kinds()[:box.kinds().index('reclaim')], 'nothing is read before the take-back'


def test_a_planted_editor_link_is_never_read_before_the_take_back(tmp_path, monkeypatch):
    """The broker reads through links. The scan sees a link at the editor's path, so the route
    takes the full path first and reads only after the take-back has dropped it."""
    box = Box(tmp_path, monkeypatch)
    secret = tmp_path / 'secret'
    secret.write_text('CURRENT_VERSION = "9.9.9"\nroot-only secret\n')
    (box.ed / 'mediamtx_config_editor.py').unlink()
    (box.ed / 'mediamtx_config_editor.py').symlink_to(secret)
    box.patch()
    first_read = next((i for i, e in enumerate(box.events) if e[0] == 'read'), None)
    reclaim_at = box.kinds().index('reclaim')
    assert first_read is None or reclaim_at < first_read


# ── boxes where the old path is the only path ──────────────────────────────────────────────

def test_a_box_that_never_moved_to_the_account_behaves_as_before(tmp_path, monkeypatch):
    box = Box(tmp_path, monkeypatch, migrated=False)
    out = box.patch()
    assert out['success'] is True
    # the reclaim has nothing to do there, but it is still the route's first step, as before
    assert box.kinds().count('reclaim') == 1
    assert 'MediaMTX was not stopped' not in out['message']
    assert out['mediamtx_stopped'] is False             # it stopped nothing: nothing was running as the account
    assert box.writes_to_folder(), 'the old path writes as it always did'


def test_a_remote_host_behaves_as_before(tmp_path, monkeypatch):
    box = Box(tmp_path, monkeypatch, remote=True)
    out = box.patch()
    assert out['success'] is True
    assert not box.stopped_mediamtx()
    assert 'MediaMTX was not stopped' not in out['message']
    assert not box.writes_to_folder()


def test_a_failure_on_the_kept_path_stops_nothing(tmp_path, monkeypatch):
    box = Box(tmp_path, monkeypatch, run_root_ok=False)
    out, status = box.patch()
    assert status == 500 and 'Failed to install or restart web editor' in out['error']
    assert not box.stopped_mediamtx()
    assert not [e for e in box.events if e[0] == 'run' and 'start' in e[1]]


def test_a_broken_package_install_is_still_reported_on_the_kept_path(tmp_path, monkeypatch):
    box = Box(tmp_path, monkeypatch, deps_ok=False)
    out = box.patch()
    assert out['webeditor_running'] is False and 'could not be installed' in out['message']


# ── the helpers, on a real folder ──────────────────────────────────────────────────────────

def _helpers(tmp_path, reads=None):
    ed = tmp_path / 'ed'
    ed.mkdir(exist_ok=True)
    ns = {'os': os, '_stat': stat, '_MEDIAMTX_EDITOR_DIR': str(ed), '_MEDIAMTX_CONF_DIR': str(tmp_path / 'etc'),
          '_read_priv': lambda p: pathlib.Path(p).read_text()}
    exec(compile(_cls('_MtxReclaimNeeded'), 'app.py', 'exec'), ns)
    for name in ('_mediamtx_editor_dir_has_links', '_mediamtx_editor_put'):
        exec(compile(_fn(name), 'app.py', 'exec'), ns)
    return ed, ns


def test_put_accepts_only_an_identical_regular_file(tmp_path):
    ed, ns = _helpers(tmp_path)
    f = ed / 'a.py'
    f.write_text('same')
    os.chmod(f, 0o755)
    assert ns['_mediamtx_editor_put'](str(f), 'same') is None
    assert ns['_mediamtx_editor_put'](str(f), 'same', 0o755) is None
    with pytest.raises(BaseException) as e:
        ns['_mediamtx_editor_put'](str(f), 'different')
    assert type(e.value).__name__ == '_MtxReclaimNeeded'
    with pytest.raises(BaseException):
        ns['_mediamtx_editor_put'](str(f), 'same', 0o644)
    assert f.read_text() == 'same', 'the guarded put never writes'


def test_put_refuses_a_link_even_when_its_target_has_the_same_text(tmp_path):
    ed, ns = _helpers(tmp_path)
    target = tmp_path / 'elsewhere'
    target.write_text('same')
    (ed / 'a.py').symlink_to(target)
    with pytest.raises(BaseException):
        ns['_mediamtx_editor_put'](str(ed / 'a.py'), 'same')


def test_put_refuses_a_missing_file(tmp_path):
    ed, ns = _helpers(tmp_path)
    with pytest.raises(BaseException):
        ns['_mediamtx_editor_put'](str(ed / 'nope.py'), 'x')


def test_link_scan(tmp_path):
    ed, ns = _helpers(tmp_path)
    (ed / 'sub').mkdir()
    (ed / 'a.py').write_text('x')
    (ed / 'sub' / 'b.json').write_text('{}')
    assert ns['_mediamtx_editor_dir_has_links']() is False
    (ed / 'sub' / 'evil').symlink_to(tmp_path)
    assert ns['_mediamtx_editor_dir_has_links']() is True
    (ed / 'sub' / 'evil').unlink()
    os.mkfifo(ed / 'fifo')
    assert ns['_mediamtx_editor_dir_has_links']() is True
    os.unlink(ed / 'fifo')
    assert ns['_mediamtx_editor_dir_has_links']() is False
    etc = tmp_path / 'etc'
    etc.mkdir()
    (etc / 'mediamtx.yml').symlink_to(tmp_path / 'a')
    assert ns['_mediamtx_editor_dir_has_links']() is True


def test_link_scan_says_yes_when_it_cannot_look(tmp_path):
    ed, ns = _helpers(tmp_path)
    (ed / 'a.py').write_text('x')
    assert ns['_mediamtx_editor_dir_has_links']() is False
    ns['_MEDIAMTX_EDITOR_DIR'] = str(tmp_path / 'not-there')
    assert ns['_mediamtx_editor_dir_has_links']() is True


@pytest.mark.skipif(os.geteuid() == 0, reason='root can open a folder of mode 000')
def test_a_subfolder_the_console_cannot_open_does_not_count(tmp_path):
    """aws-arm, ops #1387: the editor's __pycache__ is 750 `mediamtx`, so the console cannot list
    it. Counting that as 'cannot tell' sent every real box down the stopping path."""
    ed, ns = _helpers(tmp_path)
    (ed / 'a.py').write_text('x')
    cache = ed / '__pycache__'
    cache.mkdir()
    (cache / 'x.pyc').write_text('x')
    os.chmod(cache, 0o000)
    try:
        assert ns['_mediamtx_editor_dir_has_links']() is False
    finally:
        os.chmod(cache, 0o755)


def test_the_reclaim_guard_matches_what_the_reclaim_used_to_check(tmp_path):
    ed = tmp_path / 'ed'
    ns = {'os': os, '_MEDIAMTX_EDITOR_DIR': str(ed), '_mediamtx_owner': lambda: 'mediamtx',
          '_mediamtx_account_ready': lambda: True}
    exec(compile(_fn('_mediamtx_editor_reclaim_applies'), 'app.py', 'exec'), ns)
    assert ns['_mediamtx_editor_reclaim_applies']() is False          # no folder
    ed.mkdir()
    assert ns['_mediamtx_editor_reclaim_applies']() is True
    ns['_mediamtx_owner'] = lambda: 'takwerx'
    ns['_mediamtx_account_ready'] = lambda: False
    assert ns['_mediamtx_editor_reclaim_applies']() is False          # never moved
    ns['_mediamtx_account_ready'] = lambda: True
    assert ns['_mediamtx_editor_reclaim_applies']() is True           # about to move


# ── source-level guards on the route ───────────────────────────────────────────────────────

def test_every_write_into_the_folder_goes_through_put():
    rec = _fn('mediamtx_recovery')
    body = rec[rec.index('def _put('):]
    # the only direct _write_priv calls left in the route are the ones inside _put and the unit file
    direct = [m.group(0) for m in re.finditer(r"_write_priv\([^)]*\)", rec)]
    assert all('_tp_unit' in d or d.startswith('_write_priv(path') for d in direct), direct
    for target in ("editor_path, src", "'/opt/mediamtx-webeditor/mediamtx_ldap_overlay.py'",
                   "'/opt/mediamtx-webeditor/ensure_overlay.py'"):
        assert '_put(' + target in body, target
    assert "_mediamtx_editor_reclaim_applies()" in rec and "_mediamtx_editor_dir_has_links()" in rec


def test_the_retry_runs_the_full_path_and_is_not_swallowed():
    rec = _fn('mediamtx_recovery')
    dec = _fn('_mediamtx_patch_try_quiet_first')
    assert 'except _MtxReclaimNeeded:' in dec
    assert 'view(_try_guarded=True)' in dec and 'view(_try_guarded=False)' in dec
    assert dec.index('view(_try_guarded=True)') < dec.index('view(_try_guarded=False)')
    # the route's own `except Exception` comes after the signal can leave it (it is no Exception)
    assert 'except _MtxReclaimNeeded' not in rec
    # the refresh (which writes the editor file) is never reached on the quiet pass unless the editor is newer
    assert rec.index('raise _MtxReclaimNeeded') < rec.index('_mediamtx_editor_refresh(')
    # decorator order: the route is login-protected, the quiet-first wrapper sits directly on the view
    assert re.search(r"@app\.route\('/api/mediamtx/recovery', methods=\['POST'\]\)\n@login_required\n"
                     r"@_mediamtx_patch_try_quiet_first\ndef mediamtx_recovery\(_try_guarded=False\):", APP)
    # the default is the old path, so a caller that does not know about the flag changes nothing
    assert 'def mediamtx_recovery(_try_guarded=False):' in APP


def test_no_route_is_called_by_name():
    """redteam-selfaudit route-bound-to-helper: the retry must not call the view by name."""
    calls = [n for n in ast.walk(_TREE) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == 'mediamtx_recovery']
    assert calls == []
