# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1400: "Patch web editor" on Rocky (SELinux) logged four denials on every press.

1. The editor's package folder (made by `pip --target`) kept the `tmp_t` label on its compiled
   files, and the console's own import check `execute`d them: two denials. Fix: give the folder
   its policy label (`restorecon -R`) before the check loads anything.
2. The local unit edit used `sed -i` (it asks SELinux for a file-create label, `setfscreate`):
   two denials. Fix: edit the unit text in Python. A remote host keeps `sed` over SSH.

The app.py code runs for real, against a fake host (no root, no SELinux).
"""
import pathlib
import re
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
APP = (ROOT / 'app.py').read_text(encoding='utf-8')

from test_mediamtx_patch_tvr_ops1341 import Host, editor_text, _fn  # noqa: E402

PYLIB = '/opt/mediamtx-webeditor-pylib'
UNIT = '/etc/systemd/system/mediamtx-webeditor.service'
KEY = 'INFRATAK_TRUSTED_PROXIES'
TP = f'Environment={KEY}=127.0.0.1,::1'


def _load(*names, **ns_extra):
    ns = {'re': re, '_MEDIAMTX_TRUSTED_PROXIES_KEY': KEY, '_MEDIAMTX_EDITOR_PYLIB': PYLIB}
    ns.update(ns_extra)
    for n in names:
        exec(compile(_fn(n), 'app.py', 'exec'), ns)
    return ns


# ── the unit edit: the same text the three sed lines gave ───────────────────────────────

BASE_UNIT = ('[Unit]\nDescription=ed\n\n[Service]\nUser=mediamtx\n'
             'ExecStartPre=/usr/bin/python3 /opt/mediamtx-webeditor/ensure_overlay.py\n'
             'ExecStart=/usr/bin/python3 /opt/mediamtx-webeditor/mediamtx_config_editor.py\n\n'
             '[Install]\nWantedBy=multi-user.target\n')


def _edit(txt, tp=TP):
    return _load('_mediamtx_editor_unit_for_patch')['_mediamtx_editor_unit_for_patch'](txt, tp)


def test_old_unit_gets_the_dash_and_the_proxies_line():
    out = _edit(BASE_UNIT)
    assert 'ExecStartPre=-/usr/bin/python3 /opt/mediamtx-webeditor/ensure_overlay.py\n' in out
    assert 'ExecStartPre=/usr/bin/python3' not in out
    lines = out.split('\n')
    assert lines[lines.index('[Service]') + 1] == TP          # sed's `/^\[Service\]/a`
    assert out.count(TP) == 1
    # nothing else moved or went missing
    assert [l for l in lines if l != TP] == [l.replace('ExecStartPre=/', 'ExecStartPre=-/') for l in BASE_UNIT.split('\n')]


def test_an_existing_proxies_line_is_replaced_not_duplicated():
    unit = BASE_UNIT.replace('User=mediamtx\n', f'User=mediamtx\nEnvironment={KEY}=10.9.9.9\n')
    out = _edit(unit)
    assert out.count(f'Environment={KEY}=') == 1 and TP in out and '10.9.9.9' not in out


def test_every_stale_proxies_line_is_replaced_like_sed_did():
    unit = BASE_UNIT.replace('User=mediamtx\n', f'User=mediamtx\nEnvironment={KEY}=a\nEnvironment={KEY}=b\n')
    assert _edit(unit).count(TP) == 2


@pytest.mark.parametrize('unit', [BASE_UNIT, BASE_UNIT.replace('ExecStartPre=/', 'ExecStartPre=-/')])
def test_second_pass_changes_nothing(unit):
    once = _edit(unit)
    assert _edit(once) == once


def test_other_lines_are_kept_byte_for_byte():
    unit = BASE_UNIT.replace('User=mediamtx\n', 'User=mediamtx\nUMask=0027\nEnvironment=PYTHONPATH=/opt/mediamtx-webeditor-pylib\n'
                             'Environment=OPERATOR_SETTING=keep me\n')
    out = _edit(unit)
    for keep in ('UMask=0027', 'Environment=PYTHONPATH=/opt/mediamtx-webeditor-pylib',
                 'Environment=OPERATOR_SETTING=keep me', 'WantedBy=multi-user.target'):
        assert keep in out.split('\n')


@pytest.mark.parametrize('unit', ['', '[Unit]\nDescription=x\n'])
def test_a_unit_without_a_service_section_is_left_alone(unit):
    assert _edit(unit) == unit and _edit(None) == ''


def test_the_value_is_written_as_text_not_as_a_pattern():
    """sed's replacement treats & and \\ as special; the Python edit must not."""
    tp = f'Environment={KEY}=10.0.0.1,&,\\1'
    assert tp in _edit(BASE_UNIT, tp).split('\n')


# ── the relabel: only RHEL with SELinux on, never breaks Patch ──────────────────────────

class Box:
    def __init__(self, family='rhel', mode='Enforcing', isdir=True, restorecon_rc=0, boom=False):
        self.family, self.mode, self.isdir, self.rc, self.boom = family, mode, isdir, restorecon_rc, boom
        self.calls = []

    def run(self, argv, **kw):
        self.calls.append(list(argv))
        if self.boom and argv[:1] == ['restorecon']:
            raise OSError('broker gone')
        if argv == ['getenforce']:
            return types.SimpleNamespace(returncode=0, stdout=self.mode + '\n')
        return types.SimpleNamespace(returncode=self.rc, stdout='', stderr='')

    def relabel(self):
        ns = _load('_mediamtx_editor_relabel_pylib',
                   os=types.SimpleNamespace(path=types.SimpleNamespace(isdir=lambda p: self.isdir)),
                   subprocess=types.SimpleNamespace(run=self.run),
                   _distro_family=lambda: self.family, _sudo_wrap=lambda c: list(c))
        return ns['_mediamtx_editor_relabel_pylib']()

    def restorecons(self):
        return [c for c in self.calls if c[:1] == ['restorecon']]


def test_rhel_with_selinux_on_relabels_the_package_folder():
    b = Box()
    assert b.relabel() is True
    assert b.restorecons() == [['restorecon', '-R', PYLIB]]


@pytest.mark.parametrize('kw', [
    dict(family='debian'),                      # Ubuntu, ARM Ubuntu: no SELinux
    dict(mode='Disabled'),                      # RHEL with SELinux off
    dict(mode=''),                              # getenforce says nothing
    dict(isdir=False),                          # no package folder (editor on the old layout)
])
def test_everything_else_runs_no_restorecon(kw):
    b = Box(**kw)
    assert b.relabel() is False
    assert b.restorecons() == []


def test_a_failing_restorecon_never_breaks_patch():
    assert Box(restorecon_rc=1).relabel() is False
    assert Box(boom=True).relabel() is False


def test_debian_does_not_even_ask_getenforce():
    b = Box(family='debian')
    b.relabel()
    assert b.calls == []


def test_the_check_relabels_before_it_loads_a_single_file():
    """The two denials were `execute` of the tmp_t .so: the label must be right BEFORE python runs."""
    order = []
    ns = _load('_mediamtx_editor_pylib_ok',
               os=types.SimpleNamespace(path=types.SimpleNamespace(isdir=lambda p: True)),
               subprocess=types.SimpleNamespace(
                   run=lambda argv, **k: order.append(('python', argv[0])) or types.SimpleNamespace(returncode=0)),
               _mediamtx_editor_relabel_pylib=lambda: order.append(('relabel',)),
               _MEDIAMTX_EDITOR_PY_IMPORTS='import flask')
    assert ns['_mediamtx_editor_pylib_ok']() is True
    assert order == [('relabel',), ('python', '/usr/bin/python3')]


def test_no_folder_means_no_relabel_and_not_ok():
    order = []
    ns = _load('_mediamtx_editor_pylib_ok',
               os=types.SimpleNamespace(path=types.SimpleNamespace(isdir=lambda p: False)),
               subprocess=types.SimpleNamespace(run=lambda *a, **k: order.append('run')),
               _mediamtx_editor_relabel_pylib=lambda: order.append('relabel'))
    assert ns['_mediamtx_editor_pylib_ok']() is False
    assert order == []


# ── Patch web editor, through the real route ────────────────────────────────────────────

def _host(monkeypatch, remote, unit=BASE_UNIT):
    h = Host(monkeypatch, editor=editor_text('2.1.17'), remote=remote)
    h.files[UNIT] = unit
    exec(compile(_fn('_mediamtx_editor_unit_for_patch'), 'app.py', 'exec'), h.ns)
    exec(compile(_fn('_mediamtx_editor_unit_with_prestart'), 'app.py', 'exec'), h.ns)
    h.ns.update({'_MEDIAMTX_TRUSTED_PROXIES_KEY': KEY, '_MEDIAMTX_EDITOR_PRESTART':
                 'ExecStartPre=-/usr/bin/python3 /opt/mediamtx-webeditor/ensure_overlay.py',
                 '_mediamtx_editor_trusted_proxies': lambda s, c: '127.0.0.1,::1'})
    return h


def test_local_patch_edits_the_unit_in_python_and_runs_no_sed(monkeypatch):
    h = _host(monkeypatch, remote=False)
    out = h.patch()
    assert out['success'] is True
    unit = h.files[UNIT]
    assert 'ExecStartPre=-/usr/bin/python3' in unit and TP in unit.split('\n')
    assert (UNIT, unit) in h.writes                                       # written through the broker path
    assert not any(re.search(r'\bsed\b', c) for c in h.root_cmds), h.root_cmds   # the proof: no sed on the box
    assert any('systemctl restart mediamtx-webeditor' in c for c in h.root_cmds)
    assert any('systemctl daemon-reload' in c for c in h.root_cmds)


def test_local_patch_leaves_a_unit_that_is_already_right_alone(monkeypatch):
    right = _edit(BASE_UNIT)
    h = _host(monkeypatch, remote=False, unit=right)
    h.patch()
    assert not [w for w in h.writes if w[0] == UNIT]
    assert h.files[UNIT] == right


def test_remote_patch_still_edits_the_unit_with_sed_over_ssh(monkeypatch):
    h = _host(monkeypatch, remote=True)
    out = h.patch()
    assert out['success'] is True
    cmd = [c for c in h.root_cmds if 'systemctl restart mediamtx-webeditor' in c]
    assert len(cmd) == 1
    assert "sed -i 's|^ExecStartPre=/usr/bin/python3|ExecStartPre=-/usr/bin/python3|'" in cmd[0]
    assert f"^Environment={KEY}=" in cmd[0] and cmd[0].startswith('mv /tmp/ensure_overlay.py')
    assert not [w for w in h.writes if w[0] == UNIT]                      # nothing written by the console


def test_the_route_still_calls_the_package_check_that_relabels():
    """Patch -> _mediamtx_editor_ensure_py_deps -> _mediamtx_editor_pylib_ok (which relabels)."""
    ensure = _fn('_mediamtx_editor_ensure_py_deps')
    assert '_mediamtx_editor_pylib_ok()' in ensure
    assert '_mediamtx_editor_ensure_py_deps()' in _fn('mediamtx_recovery')
