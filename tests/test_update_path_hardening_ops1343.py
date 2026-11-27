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
"""Update-path hardening bundle (ops #1343, found by the stack audit, ops #1311).

Ten small places where an update or a restart could throw away something an operator owned,
or skip work after one failure. One proof test per item, each red on dev before the fix.

app.py cannot be imported in a test, so the helpers are cut out of it and run against stubs:
the code under test is the shipped text.
"""

import ast
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _node(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return node
    raise AssertionError(f'{name} not found at module level in app.py')


def _segment(name):
    return ast.get_source_segment(APP, _node(name))


def _load(names, ns=None):
    ns = {} if ns is None else ns
    for mod in (os, re, json, subprocess):
        ns.setdefault(mod.__name__, mod)
    exec(compile('\n\n'.join(_segment(n) for n in names), 'app.py:' + names[-1], 'exec'), ns)
    return ns


def _order(src, *needles):
    pos = [src.index(n) for n in needles]
    return pos == sorted(pos)


# ── 1. Caddyfile: a copy of the file we are about to replace ────────────────────────────────

class _Disk:
    def __init__(self, files=None):
        self.files = dict(files or {})
        self.writes = []

    def read(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def write(self, path, content, mode='w', perm=None):
        self.writes.append(path)
        self.files[path] = content


def _caddy_ns(disk):
    return _load(['CADDYFILE_PATH', 'CADDYFILE_FIRST_COPY_PATH', 'CADDYFILE_USER_BLOCKS_MARKER',
                  '_caddy_save_first_copy'],
                 {'_read_priv': disk.read, '_write_priv': disk.write})


COPY = '/etc/caddy/Caddyfile.infratak-prev'
MARK = '# --- User-added blocks (do not remove) ---'


def test_caddy_a_hand_written_file_with_no_marker_is_kept_before_it_is_replaced():
    disk = _Disk()
    ns = _caddy_ns(disk)
    hand = 'example.com {\n    respond "hand written"\n}\n'
    assert ns['_caddy_save_first_copy'](hand) is True
    assert disk.files[COPY] == hand


def test_caddy_an_edit_above_the_marker_is_kept_once_and_never_replaced_after():
    disk = _Disk()
    ns = _caddy_ns(disk)
    first = f'# generated\nexample.com {{\n    header X-Mine 1\n}}\n{MARK}\n'
    assert ns['_caddy_save_first_copy'](first) is True
    assert ns['_caddy_save_first_copy'](first.replace('X-Mine 1', 'X-Mine 2')) is False
    assert disk.files[COPY] == first           # still the oldest file we saw


def test_caddy_a_new_hand_written_file_replaces_an_older_copy():
    disk = _Disk({COPY: f'old\n{MARK}\n'})
    ns = _caddy_ns(disk)
    assert ns['_caddy_save_first_copy']('brand new hand file\n') is True
    assert disk.files[COPY] == 'brand new hand file\n'


def test_caddy_nothing_to_keep_and_a_failing_write_never_raise():
    disk = _Disk()
    ns = _caddy_ns(disk)
    assert ns['_caddy_save_first_copy']('') is False
    assert ns['_caddy_save_first_copy'](None) is False
    ns['_write_priv'] = lambda *a, **k: (_ for _ in ()).throw(OSError('denied'))
    assert ns['_caddy_save_first_copy']('x {\n}\n') is False


def test_caddy_the_copy_is_made_before_the_file_is_written():
    gen = _segment('generate_caddyfile')
    assert _order(gen, '_caddy_save_first_copy(_caddy_prev)', '_write_priv(CADDYFILE_PATH, caddyfile)')


# ── 2. Email Relay: operator lines in main.cf and /etc/postfix/generic ──────────────────────

import modules.emailrelay as er  # noqa: E402

OPS_LINES = 'smtp_header_checks = regexp:/etc/postfix/header_checks\nmessage_size_limit = 20480000\n'


def test_email_main_cf_lines_below_our_block_survive_the_strip():
    block = er.render_main_cf_block('smtp.example.org', '587')
    cf = 'myhostname = tak.example.org\n' + block + OPS_LINES
    out = er.strip_main_cf_block(cf)
    assert 'smtp_header_checks' in out and 'message_size_limit' in out
    assert 'relayhost' not in out and 'TAKWERX Email Relay' not in out
    assert 'myhostname = tak.example.org' in out


def test_email_the_strip_is_stable_over_repeated_deploys():
    cf = 'myhostname = a\n'
    for _ in range(3):
        cf = er.strip_main_cf_block(cf).rstrip() + '\n' + er.render_main_cf_block('h', '587')
        cf += OPS_LINES if 'smtp_header_checks' not in cf else ''
    assert cf.count('# TAKWERX Email Relay') == 1
    assert cf.count('smtp_header_checks') == 1


def test_email_the_alias_line_added_after_our_block_is_not_ours_to_strip():
    cf = 'a = 1\n' + er.render_main_cf_block('h', '587') + 'virtual_alias_maps = hash:/etc/postfix/virtual_root\n'
    assert 'virtual_alias_maps = hash:/etc/postfix/virtual_root' in er.strip_main_cf_block(cf)


def test_email_generic_keeps_an_operator_entry_and_replaces_our_own_line():
    ours = 'root@tak.example.org    noreply@example.org\n'
    existing = ('# mine\nroot@tak.example.org    OLD@example.org\nbob@x.example    bob@y.example\n')
    out = er.merge_generic_map(existing, ours)
    assert out.startswith(ours)
    assert 'bob@x.example    bob@y.example' in out and '# mine' in out
    assert 'OLD@example.org' not in out


def test_email_generic_with_nothing_else_in_the_file_is_exactly_what_it_was_before():
    ours = 'root@a    f@x\nroot@b    f@x\n'
    assert er.merge_generic_map('', ours) == ours
    assert er.merge_generic_map(ours, ours) == ours


def _relay_deploy(main_cf, generic):
    written = {}
    files = {'/etc/postfix/main.cf': main_cf, '/etc/postfix/generic': generic}

    def run(cmd, *a, **k):
        return subprocess.CompletedProcess(cmd, 0, stdout='tak.example.org\n', stderr='')

    ctx = {
        'load_settings': lambda: {'fqdn': 'tak.example.org'}, 'save_settings': lambda s: None,
        'os_type': lambda: 'rhel', '_pkg_install': lambda *a, **k: (True, ''),
        '_sudo_wrap': lambda c: list(c), '_read_priv': lambda p: files.get(p, ''),
        '_write_priv': lambda p, text, perm=None, **k: (written.__setitem__(p, text), files.__setitem__(p, text)),
        '_safe_alert_emails': lambda v: [t for t in (v or '').split() if '@' in t],
        '_takportal_push_settings': lambda plog: False,
    }
    old = er.subprocess.run
    er.subprocess.run = run
    try:
        job = {'log': [], 'running': True}
        er.deploy(ctx, job, {'provider': 'custom', 'smtp_user': 'u', 'smtp_pass': 'p',
                             'from_addr': 'noreply@example.org', 'from_name': 'T',
                             'relay_host': 'smtp.example.org', 'relay_port': '587'})
        assert job.get('complete') is True, job
    finally:
        er.subprocess.run = old
    return written


def test_email_deploy_keeps_what_an_operator_added_to_both_files(monkeypatch):
    monkeypatch.setattr(er, '_read_name_file', lambda p: '', raising=False)
    block = er.render_main_cf_block('smtp.old.example', '587')
    written = _relay_deploy('myhostname = tak.example.org\n' + block + OPS_LINES,
                            'bob@x.example    bob@y.example\n')
    cf = written['/etc/postfix/main.cf']
    assert 'smtp_header_checks' in cf and 'relayhost = [smtp.example.org]:587' in cf
    assert cf.count('relayhost') == 1
    assert 'bob@x.example    bob@y.example' in written['/etc/postfix/generic']
    assert 'root@tak.example.org    noreply@example.org' in written['/etc/postfix/generic']


# ── 3. cfd-remote-assist: never delete the Remote Assist database volume at start-up ────────

def _fn_src(name):
    return _segment(name)


def test_the_start_up_migration_no_longer_runs_docker_compose_down_v():
    src = _fn_src('_startup_migrations')
    assert "'down', '-v'" not in src and '"down", "-v"' not in src
    assert 'shutil.rmtree(_ra_old_dir' not in src
    assert 'legacy_remote_assist_notice' in src


def test_a_bar_tells_the_operator_the_old_install_was_left_alone():
    ns = _load(['_legacy_remote_assist_bar'])
    assert ns['_legacy_remote_assist_bar']({}) is None
    spec = ns['_legacy_remote_assist_bar']({'legacy_remote_assist_notice': True})
    assert spec and 'cfd-remote-assist' in spec['html'] and spec['key']
    assert '_legacy_remote_assist_bar(settings)' in _fn_src('_render_notice_bars_inner')


# ── 4. _startup_migrations: one failing step must not skip the rest ─────────────────────────

_SAFE_CALLS = {'get', 'print', 'str', 'int', 'bool', 'len', 'strip', 'expanduser', 'exists', 'isdir',
               'isfile', 'join', 'format', 'items', 'keys', 'values', 'lower', 'startswith',
               'endswith', 'isinstance', 'dict', 'list', 'set', 'float', 'split', 'append', 'pop',
               'setdefault', 'copy', '_distro_family'}


def _broad(h):
    return h.type is None or (isinstance(h.type, ast.Name) and h.type.id in ('Exception', 'BaseException'))


def _unprotected_calls(node):
    out = []

    def walk(n):
        if isinstance(n, ast.Try) and any(_broad(h) for h in n.handlers):
            for h in n.handlers:
                for y in h.body:
                    walk(y)
            for y in n.orelse + n.finalbody:
                walk(y)
            return
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return
        if isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, 'id', '?')
            if name not in _SAFE_CALLS:
                out.append(name)
        for c in ast.iter_child_nodes(n):
            walk(c)
    walk(node)
    return out


def test_every_start_up_migration_step_that_can_raise_has_its_own_try():
    """Before: 24 top-level steps (the Fed Hub block, _get_tak_deployment_config, the Caddy
    converges, ...) sat directly under ONE outer try, so one exception skipped every
    security migration after it for that boot. Allowed bare: the broker wait loop and the
    first load_settings(), which the whole function needs."""
    fn = _node('_startup_migrations')
    outer = fn.body[0]
    assert isinstance(outer, ast.Try)
    bare = []
    for st in outer.body:
        if isinstance(st, ast.Try) and any(_broad(h) for h in st.handlers):
            continue
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant):
            continue
        calls = _unprotected_calls(st)
        if calls:
            bare.append((st.lineno, ast.unparse(st).split('\n')[0][:70], calls[:3]))
    allowed = ('if _broker_should_route():', 's = load_settings()')
    bare = [b for b in bare if not b[1].startswith(allowed)]
    assert not bare, bare


# ── 5. JDK 17 pin: only for the TAK Server line it is known to suit ─────────────────────────

def _pin_ns():
    return _load(['_os_upgrade_tak_version_tuple', '_TAK_JVM_PIN_MAX_MAJOR', '_tak_jvm_pin_applies'])


@pytest.mark.parametrize('ver', ['5.8-RELEASE84', '5.7-RELEASE-43', 'hardened-5.8-RELEASE75', '4.10-RELEASE', ''])
def test_jvm_pin_still_applies_to_5x_and_to_an_unreadable_version(ver):
    assert _pin_ns()['_tak_jvm_pin_applies'](ver)[0] is True


@pytest.mark.parametrize('ver', ['6.0-RELEASE1', '7.2-RELEASE5'])
def test_jvm_pin_is_left_alone_for_a_newer_major(ver):
    ok, why = _pin_ns()['_tak_jvm_pin_applies'](ver)
    assert ok is False and why


def test_jvm_pin_asks_before_it_looks_for_a_jdk():
    src = _segment('_pin_takserver_jvm')
    assert _order(src, '_tak_jvm_pin_applies(', '_resolve_java17_home()')


# ── 6. Stack restore: refuse a backup newer than this console ───────────────────────────────

def _restore_ns():
    return _load(['_console_version_tuple', '_stack_restore_too_new'], {'VERSION': '10.4.9-alpha'})


def test_restore_refuses_a_newer_backup_and_says_what_to_do():
    why = _restore_ns()['_stack_restore_too_new']('10.5.0-alpha')
    assert why and '10.5.0-alpha' in why and 'Update the console' in why


@pytest.mark.parametrize('made', ['10.4.9-alpha', '10.4.8-alpha', '10.3.12-alpha', '', None, 'weird'])
def test_restore_allows_same_older_and_unreadable(made):
    assert _restore_ns()['_stack_restore_too_new'](made) == ''


def test_restore_checks_the_version_before_anything_is_verified_or_stopped():
    src = _segment('_stack_restore')
    assert _order(src, '_stack_restore_too_new(manifest.get', '# 1. Verify everything', '_stack_restore_standdown(True')


# ── 7. Guard Dog: say so when an older console re-renders newer scripts ─────────────────────

def _gd_ns(disk, version='10.4.9-alpha'):
    logs = []
    ns = _load(['_console_version_tuple', '_GD_VERSION_STAMP', '_gd_console_downgrade',
                '_gd_stamp_console_version'],
               {'VERSION': version, '_read_priv': disk.read, '_write_priv': disk.write,
                'print': lambda *a, **k: logs.append(' '.join(str(x) for x in a))})
    return ns, logs


def test_guarddog_a_downgrade_is_logged_and_the_stamp_follows_this_console():
    disk = _Disk({'/opt/tak-guarddog/.console-version': '10.5.1-alpha\n'})
    ns, logs = _gd_ns(disk)
    ns['_gd_stamp_console_version']()
    assert any('10.5.1-alpha' in m and 'older' in m for m in logs), logs
    assert disk.files['/opt/tak-guarddog/.console-version'] == '10.4.9-alpha\n'


def test_guarddog_same_version_or_first_boot_is_silent_and_a_failed_stamp_never_raises():
    disk = _Disk()
    ns, logs = _gd_ns(disk)
    ns['_gd_stamp_console_version']()
    assert not logs
    ns['_gd_stamp_console_version']()
    assert disk.writes == ['/opt/tak-guarddog/.console-version']        # written once
    ns['_write_priv'] = lambda *a, **k: (_ for _ in ()).throw(OSError('x'))
    ns['_read_priv'] = lambda p: (_ for _ in ()).throw(OSError('x'))
    ns['_gd_stamp_console_version']()


def test_guarddog_startup_refresh_stamps_after_the_scripts_are_installed():
    assert _order(_segment('_auto_update_guarddog'), '_gd_install_script(name, template, vals)',
                  '_gd_stamp_console_version()')


# ── 8. CloudTAK icon heal: keep the rows, and stop when too many look bad ───────────────────

def test_icon_heal_copies_rows_before_deleting_and_has_a_cap():
    ns = _load(['_CLOUDTAK_ICON_HEAL_MAX_ROWS', '_CLOUDTAK_ICON_HEAL_SQL'])
    sql = ns['_CLOUDTAK_ICON_HEAL_SQL']
    assert '__MAX_BAD_ROWS__' not in sql and f"cap integer := {ns['_CLOUDTAK_ICON_HEAL_MAX_ROWS']};" in sql
    assert _order(sql, 'INSERT INTO icons_corrupt_backup', 'DELETE FROM icons')
    assert _order(sql, 'IF n > cap THEN', 'RETURN;', 'INSERT INTO icons_corrupt_backup')
    assert 'corrupt row(s) deleted' in sql          # the line the heal log is read for


# ── 9. Node-RED settings.js: a key never lands in front of the wrong `};` ───────────────────

OPERATOR_SETTINGS = '''var helper = {
  a: 1
};
function f() { return { x: 1 }; };
module.exports = {
  uiPort: 1880,
  logging: { console: { level: "info" } }
};
'''


def _nr_add(content, prop):
    return _load(['_nr_settings_add_property'])['_nr_settings_add_property'](content, prop)


def test_nodered_a_key_is_appended_not_pushed_in_front_of_the_first_close_brace():
    out = _nr_add(OPERATOR_SETTINGS, "  httpStatic: '/data/public'")
    assert out.startswith(OPERATOR_SETTINGS.rstrip('\n'))              # the operator's text is untouched
    assert out.rstrip().endswith('});')
    assert out.index('httpStatic') > out.index('uiPort')


@pytest.mark.skipif(not shutil.which('node'), reason='node not installed')
def test_nodered_the_result_loads_and_has_every_key(tmp_path):
    out = OPERATOR_SETTINGS
    for prop in ("  editorTheme: { header: { title: 'x' } }", "  httpStatic: '/data/public'",
                 "  functionGlobalContext: { nodeHttps: require('https') }",
                 "  contextStorage: { default: { module: 'localfilesystem', config: { flushInterval: 0 } } }"):
        out = _nr_add(out, prop)
    f = tmp_path / 'settings.js'
    f.write_text(out)
    r = subprocess.run(['node', '-e', f"const s=require({json.dumps(str(f))});"
                        "console.log(JSON.stringify(Object.keys(s)), s.contextStorage.default.module)"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    keys, module = r.stdout.strip().rsplit(' ', 1)
    assert module == 'localfilesystem'
    assert set(json.loads(keys)) >= {'uiPort', 'logging', 'editorTheme', 'httpStatic',
                                     'functionGlobalContext', 'contextStorage'}


def test_nodered_no_replace_of_the_first_close_brace_is_left_in_the_function():
    src = ast.get_source_segment(APP, next(
        n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name == '_auto_nodered_settings'))
    assert ".replace(\n                            '};'" not in src and ".replace('};'" not in src
    assert src.count('_nr_settings_add_property(') == 4


# ── 10. Cesium re-home: an unreadable folder is not an empty one ────────────────────────────

def test_cesium_a_tree_with_an_unreadable_folder_is_not_called_empty(tmp_path):
    if os.getuid() == 0:
        pytest.skip('root can read every folder')
    ns = _load(['_tree_has_files_or_unreadable'])
    tiles = tmp_path / 'cesium-tiles'
    (tiles / 'locked').mkdir(parents=True)
    (tiles / 'locked' / 'tile.b3dm').write_text('x')
    (tiles / 'locked').chmod(0)
    try:
        assert ns['_tree_has_files_or_unreadable'](str(tiles)) is True
    finally:
        (tiles / 'locked').chmod(0o755)


def test_cesium_an_empty_stub_is_still_empty_and_a_file_still_counts(tmp_path):
    ns = _load(['_tree_has_files_or_unreadable'])
    (tmp_path / 'stub' / 'sub').mkdir(parents=True)
    assert ns['_tree_has_files_or_unreadable'](str(tmp_path / 'stub')) is False
    (tmp_path / 'stub' / 'sub' / 't.b3dm').write_text('x')
    assert ns['_tree_has_files_or_unreadable'](str(tmp_path / 'stub')) is True


def test_cesium_rehome_uses_the_helper():
    assert '_tree_has_files_or_unreadable(home)' in _segment('_startup_rehome_cesium')
