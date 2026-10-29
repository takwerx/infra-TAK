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
"""The MediaMTX web editor keeps its port after its own Update (GH #330).

Upstream's editor binds 0.0.0.0:5000; Caddy sends stream.<domain> to 127.0.0.1:5080.
ensure_overlay.py (the unit's ExecStartPre) re-applies that patch after the editor's
Versions-tab Update, but the deploy only wrote the line when Authentik was installed
first, and the script quit when the LDAP overlay file was absent. Such a box got a 502
on stream.<domain> after updating the editor, with no way back in.
"""

import ast
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

UPSTREAM = '''import os
from flask import Flask
app = Flask(__name__)

def paths():
    return 'http://localhost:9997/v3/paths/list'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
'''

UNIT = '''[Unit]
Description=MediaMTX Web Configuration Editor
After=network.target mediamtx.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/mediamtx-webeditor/mediamtx_config_editor.py
WorkingDirectory=/opt/mediamtx-webeditor
Environment=PORT=5080
Restart=always
User=takwerx

[Install]
WantedBy=multi-user.target
'''


def _const(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError(f'{name} was renamed or removed')


def _fn(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    raise AssertionError(f'{name} was renamed or removed')


def _src(name):
    return ast.get_source_segment(APP, _fn(name))


def _load(name, ns):
    exec(compile(_src(name), 'app.py', 'exec'), ns)
    return ns[name]


def _run_ensure_overlay(tmp_path, with_overlay):
    d = tmp_path / 'webeditor'
    d.mkdir()
    (d / 'mediamtx_config_editor.py').write_text(UPSTREAM)
    if with_overlay:
        (d / 'mediamtx_ldap_overlay.py').write_text('def apply_ldap_overlay(app):\n    pass\n')
    script = _const('MEDIAMTX_ENSURE_OVERLAY_SCRIPT').replace('/opt/mediamtx-webeditor', str(d))
    (tmp_path / 'ensure_overlay.py').write_text(script)
    r = subprocess.run([sys.executable, '-I', str(tmp_path / 'ensure_overlay.py')],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return (d / 'mediamtx_config_editor.py').read_text()


# ── ensure_overlay.py ──────────────────────────────────────────────────────

def test_port_and_bind_patched_without_the_ldap_overlay(tmp_path):
    out = _run_ensure_overlay(tmp_path, with_overlay=False)
    assert "app.run(host='127.0.0.1', port=int(os.environ.get(\"PORT\", 5080)), debug=False)" in out
    assert '9997' not in out and 'localhost:9898' in out
    assert '# --- infra-TAK LDAP overlay ---' not in out       # nothing to import
    assert '# --- infra-TAK no-cache ---' in out
    ast.parse(out)


def test_ldap_overlay_still_injected_when_present(tmp_path):
    out = _run_ensure_overlay(tmp_path, with_overlay=True)
    assert '# --- infra-TAK LDAP overlay ---' in out and 'port=int(os.environ.get("PORT", 5080))' in out
    ast.parse(out)


def test_ensure_overlay_is_idempotent(tmp_path):
    once = _run_ensure_overlay(tmp_path, with_overlay=True)
    d = tmp_path / 'webeditor'
    r = subprocess.run([sys.executable, '-I', str(tmp_path / 'ensure_overlay.py')],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0 and (d / 'mediamtx_config_editor.py').read_text() == once


# ── the unit line ──────────────────────────────────────────────────────────

def _with_prestart():
    return _load('_mediamtx_editor_unit_with_prestart',
                 {'_MEDIAMTX_EDITOR_PRESTART': _const('_MEDIAMTX_EDITOR_PRESTART')})


def test_prestart_goes_right_before_execstart_once():
    f = _with_prestart()
    out = f(UNIT)
    lines = out.split('\n')
    i = lines.index('ExecStart=/usr/bin/python3 /opt/mediamtx-webeditor/mediamtx_config_editor.py')
    assert lines[i - 1] == 'ExecStartPre=-/usr/bin/python3 /opt/mediamtx-webeditor/ensure_overlay.py'
    assert f(out) == out and out.count('ensure_overlay.py') == 1


def test_prestart_leaves_odd_or_current_units_alone():
    f = _with_prestart()
    assert f('') == ''
    assert f('[Service]\nType=simple\n') == '[Service]\nType=simple\n'
    current = UNIT.replace('ExecStart=', _const('_MEDIAMTX_EDITOR_PRESTART') + '\nExecStart=')
    assert f(current) == current


# ── startup heal ───────────────────────────────────────────────────────────

class Box:
    def __init__(self, unit=UNIT, src=UPSTREAM, ov_exists=False, installed=True):
        self.files = {'/etc/systemd/system/mediamtx-webeditor.service': unit,
                      '/opt/mediamtx-webeditor/mediamtx_config_editor.py': src}
        if ov_exists:
            self.files['/opt/mediamtx-webeditor/ensure_overlay.py'] = 'old'
        self.installed = installed
        self.writes, self.runs, self.logs = [], [], []
        box = self

        class _P:
            @staticmethod
            def exists(p):
                return box.installed and p in box.files

        class _OS:
            path = _P

        def _write(p, c, perm=None):
            box.writes.append((p, perm))
            box.files[p] = c

        ns = {
            'os': _OS, '_read_priv': lambda p: box.files.get(p, ''), '_write_priv': _write,
            '_sudo_wrap': lambda c: c,
            'subprocess': type('S', (), {'run': staticmethod(lambda argv, **kw: box.runs.append(argv))}),
            'print': lambda *a, **k: box.logs.append(' '.join(map(str, a))),
            '_MEDIAMTX_EDITOR_UNIT': '/etc/systemd/system/mediamtx-webeditor.service',
            '_MEDIAMTX_EDITOR_SRC': '/opt/mediamtx-webeditor/mediamtx_config_editor.py',
            'MEDIAMTX_ENSURE_OVERLAY_SCRIPT': 'SCRIPT',
            '_mediamtx_editor_unit_with_prestart': _with_prestart(),
        }
        self.fn = _load('_startup_heal_mediamtx_editor_prestart', ns)


def test_heal_adds_prestart_and_restarts_a_502_editor():
    b = Box()
    assert b.fn() is True
    assert 'ensure_overlay.py' in b.files['/etc/systemd/system/mediamtx-webeditor.service']
    assert ('/opt/mediamtx-webeditor/ensure_overlay.py', 0o755) in b.writes
    assert b.files['/opt/mediamtx-webeditor/ensure_overlay.py'] == 'SCRIPT'
    assert b.runs == [['systemctl', 'daemon-reload'], ['systemctl', 'restart', 'mediamtx-webeditor']]


def test_heal_keeps_an_existing_script_and_a_working_editor_running():
    patched = UPSTREAM.replace("host='0.0.0.0', port=5000", "host='127.0.0.1', port=5080")
    b = Box(src=patched, ov_exists=True)
    assert b.fn() is True
    assert b.files['/opt/mediamtx-webeditor/ensure_overlay.py'] == 'old'   # container-ports heal refreshes it
    assert b.runs == [['systemctl', 'daemon-reload']]                      # no restart


def test_heal_is_a_no_op_on_current_or_absent_units():
    current = UNIT.replace('ExecStart=', _const('_MEDIAMTX_EDITOR_PRESTART') + '\nExecStart=')
    b = Box(unit=current)
    assert b.fn() is False and b.writes == [] and b.runs == []
    b = Box(installed=False)
    assert b.fn() is False and b.writes == [] and b.runs == []


# ── wiring ─────────────────────────────────────────────────────────────────

def test_deploy_writes_prestart_with_or_without_authentik():
    deploy = _src('run_mediamtx_deploy')
    assert "exec_start_pre = f'{_MEDIAMTX_EDITOR_PRESTART}\\n'" in deploy
    i = deploy.index("heal_path = f'{webeditor_dir}/ensure_overlay.py'")
    assert 'if ldap_available:' not in deploy[i - 200:i]


def test_patch_button_and_console_update_add_the_line():
    assert '_mediamtx_editor_unit_with_prestart(_ut)' in _src('mediamtx_recovery')
    assert '_startup_heal_mediamtx_editor_prestart()' in _src('_startup_migrations')
