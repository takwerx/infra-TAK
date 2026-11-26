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
"""Caddy can roll the TAK Portal access log on Rocky/RHEL (ops #1299).

On a Rocky 9.8 box (nuc, SELinux Enforcing) Caddy runs as httpd_t and /var/log/caddy is
httpd_log_t. The stock policy lets httpd_t write a log it already has, but not rename or
delete one. At 10 MiB (`roll_size`) Caddy's own roll failed with

    write error: can't rename log file ... permission denied      (Caddy journal)
    SELinux is preventing /usr/bin/caddy from remove_name access  (setroubleshoot)

and from then on every access line was dropped: takportal-access.log stopped at
10,485,194 bytes on Sep 10 and the TAK Portal fail2ban jail, which reads it, saw nothing.
The fix is a rule in the shipped module selinux/takwerx_console.te (1.1) and a console-start
check that gets the new module version onto a box whose broker source did not change.

Nothing here touches SELinux: the .te is read as text and the start-up check runs from the
shipped app.py text with stubbed tools.
"""

import ast
import pathlib
import re
import threading
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
TE = (REPO / 'selinux' / 'takwerx_console.te').read_text(encoding='utf-8')
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _perms(blob):
    return set(re.findall(r'[a-z_0-9]+', blob))


def _rules(cls, source='httpd_t', target='httpd_log_t'):
    """Union of the permissions the .te allows `source` on `target` for class `cls`."""
    out = set()
    pat = re.compile(r'^allow\s+%s\s+%s:%s\s+(\{[^}]*\}|[a-z_0-9]+)\s*;' % (source, target, cls),
                     re.M)
    for m in pat.finditer(TE):
        out |= _perms(m.group(1))
    return out


def _required(cls):
    """Permissions the require { } block declares for class `cls`."""
    block = re.search(r'^require\s*\{(.*?)^\}', TE, re.M | re.S).group(1)
    out = set()
    for m in re.finditer(r'class\s+%s\s+(\{[^}]*\}|[a-z_0-9]+)\s*;' % cls, block, re.S):
        out |= _perms(m.group(1))
    return out


# What one Caddy roll does to the files (Caddy 2.11 file writer, `roll_gzip` on by default):
# rename the full log to a dated name, create a new log, gzip the old one (read it, write
# the .gz, copy its owner and mode, delete the plain copy), and delete the oldest roll
# beyond roll_keep. It also lists the folder to find the old ones.
ROLL_DIR = {'search', 'getattr', 'open', 'read', 'write', 'add_name', 'remove_name'}
ROLL_FILE = {'open', 'read', 'getattr', 'write', 'append', 'create', 'setattr', 'rename',
             'unlink'}


# ── 1. The shipped policy lets httpd_t do a whole roll ───────────────────────────────

def test_policy_lets_caddy_rename_create_and_delete_its_log_files():
    """Proof test: on the base branch the .te has no httpd_t rule at all."""
    assert _rules('dir') >= ROLL_DIR, sorted(ROLL_DIR - _rules('dir'))
    assert _rules('file') >= ROLL_FILE, sorted(ROLL_FILE - _rules('file'))


def test_the_denied_permission_from_the_field_is_granted():
    """setroubleshoot said: caddy remove_name on the directory (nuc, Nov 26)."""
    assert 'remove_name' in _rules('dir')
    assert 'add_name' in _rules('dir')       # the rename's other half
    assert 'rename' in _rules('file')


def test_every_permission_the_rules_use_is_declared_in_require():
    """checkmodule refuses a module that uses a permission its require block does not
    list ("permission X is not defined for class Y"), and then no rule lands at all."""
    assert _rules('dir') <= _required('dir'), sorted(_rules('dir') - _required('dir'))
    assert _rules('file') <= _required('file'), sorted(_rules('file') - _required('file'))
    block = re.search(r'^require\s*\{(.*?)^\}', TE, re.M | re.S).group(1)
    assert re.search(r'type\s+httpd_t\s*;', block) and re.search(r'type\s+httpd_log_t\s*;', block)


def test_the_grant_stays_on_log_files_and_is_not_widened():
    """Only httpd_t on httpd_log_t. No attribute, no other target type, no ownership or
    relabel power, no permissive flag."""
    for line in TE.splitlines():
        if line.lstrip().startswith('#') or 'httpd_t' not in line or not line.startswith('allow'):
            continue
        assert re.match(r'allow\s+httpd_t\s+httpd_log_t:(dir|file)\s', line), line
    allowed = _rules('dir') | _rules('file')
    for forbidden in ('relabelfrom', 'relabelto', 'execute', 'entrypoint', 'mounton',
                      'link', 'rmdir', 'create_dir'):
        assert forbidden not in allowed
    assert not re.search(r'^\s*permissive\b', TE, re.M)


def test_module_version_was_bumped_so_existing_boxes_refresh_it():
    """The broker and start.sh refresh a module only when its stamp differs from the
    `module NAME X.Y;` line, so the rule reaches boxes only with a new version."""
    m = re.match(r'^module\s+takwerx_console\s+([0-9.]+);', TE)
    assert m, TE.splitlines()[0]
    major, minor = (int(x) for x in m.group(1).split('.')[:2])
    assert (major, minor) >= (1, 1)


# ── 2. The new version reaches an existing box with no other trigger ─────────────────

class _Run:
    def __init__(self, getenforce='Enforcing', modules='takwerx_console\n', rc=0):
        self.calls = []
        self.getenforce = getenforce
        self.modules = modules
        self.rc = rc

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        out = ''
        if argv[:1] == ['getenforce']:
            out = self.getenforce + '\n'
        elif 'semodule' in argv:
            out = self.modules

        class R:
            returncode = self.rc
            stdout = out
            stderr = ''
        return R()


def _env(tmp_path, *, shipped='1.1', stamp='1.0', getenforce='Enforcing',
         modules='takwerx_console\n'):
    """Run the shipped functions with stubbed tools. The stamp is a mutable cell."""
    (tmp_path / 'selinux').mkdir(exist_ok=True)
    (tmp_path / 'selinux' / 'takwerx_console.te').write_text(f'module takwerx_console {shipped};\n')
    state = {'stamp': stamp}
    run = _Run(getenforce=getenforce, modules=modules)

    Sub = types.SimpleNamespace(run=run)
    Shutil = types.SimpleNamespace(which=lambda n: '/usr/sbin/' + n)

    def fake_open(path, *a, **kw):
        if str(path).startswith('/etc/selinux/.takwerx-takwerx_console.ver'):
            if state['stamp'] is None:
                raise OSError('absent')
            import io
            return io.StringIO(state['stamp'] + '\n')
        return open(path, *a, **kw)

    import os
    ns = {'os': os, 'subprocess': Sub, 'shutil': Shutil, 'open': fake_open,
          '__file__': str(tmp_path / 'app.py'),
          '_sudo_wrap': lambda argv: list(argv)}
    exec(_func('_selinux_helper_module_pending'), ns)
    exec(_func('_startup_selinux_helper_module_nudge'), ns)
    return ns, state, run


def test_pending_when_installed_module_is_behind_the_shipped_te(tmp_path):
    ns, _, _ = _env(tmp_path, shipped='1.1', stamp='1.0')
    assert ns['_selinux_helper_module_pending']() == ('1.1', '1.0')


def test_pending_when_the_stamp_file_is_missing(tmp_path):
    ns, _, _ = _env(tmp_path, shipped='1.1', stamp=None)
    assert ns['_selinux_helper_module_pending']() == ('1.1', '')


def test_nothing_pending_when_current(tmp_path):
    ns, _, run = _env(tmp_path, shipped='1.1', stamp='1.1')
    assert ns['_selinux_helper_module_pending']() is None
    assert ns['_startup_selinux_helper_module_nudge']() is False
    assert not any('restart' in c for c in run.calls)


def test_a_box_that_never_had_the_module_is_left_alone(tmp_path):
    """Refresh-only, like the broker: no first install from here."""
    ns, _, run = _env(tmp_path, stamp='1.0', modules='some_other_module\n')
    assert ns['_selinux_helper_module_pending']() is None
    assert ns['_startup_selinux_helper_module_nudge']() is False
    assert not any('restart' in c for c in run.calls)


def test_selinux_off_is_a_no_op(tmp_path):
    ns, _, run = _env(tmp_path, stamp='1.0', getenforce='Disabled')
    assert ns['_selinux_helper_module_pending']() is None
    assert ns['_startup_selinux_helper_module_nudge']() is False
    assert not any('semodule' in c for c in run.calls)


def test_ubuntu_has_no_selinux_tools_and_nothing_happens(tmp_path):
    """No getenforce on Ubuntu: the check must return before it runs any command."""
    ns, _, run = _env(tmp_path, stamp='1.0')
    ns['shutil'] = types.SimpleNamespace(which=lambda n: None)
    assert ns['_selinux_helper_module_pending']() is None
    assert ns['_startup_selinux_helper_module_nudge']() is False
    assert run.calls == []


def _join_watchers():
    for t in threading.enumerate():
        if t.name == 'selinux-helper-module-nudge':
            t.join(timeout=10)


def test_behind_box_gets_one_broker_restart_after_the_wait(tmp_path):
    """No refresh landed in the wait: ask for exactly one broker restart (the broker's
    startup pass refreshes both modules), and never block the boot."""
    ns, _, run = _env(tmp_path, shipped='1.1', stamp='1.0')
    assert ns['_startup_selinux_helper_module_nudge'](wait=1, step=1) is True
    _join_watchers()
    restarts = [c for c in run.calls if c[-2:] == ['restart', 'takwerx-broker']]
    assert len(restarts) == 1, run.calls
    assert '--no-block' in restarts[0]


def test_no_restart_when_the_refresh_lands_during_the_wait(tmp_path):
    """A broker that was just restarted by the source converge is already refreshing:
    do not restart it a second time and cut that pass short."""
    ns, state, run = _env(tmp_path, shipped='1.1', stamp='1.0')
    assert ns['_startup_selinux_helper_module_nudge'](wait=2, step=1) is True
    state['stamp'] = '1.1'
    _join_watchers()
    assert not any(c[-2:] == ['restart', 'takwerx-broker'] for c in run.calls), run.calls


def test_the_check_runs_at_console_start_after_the_policy_canary():
    """It must be called at module level, after the canary (which may already have
    restarted the broker and made the stamp current), and never raise into the boot."""
    canary = APP.index('_startup_selinux_policy_canary()\nexcept')
    nudge = APP.index('_startup_selinux_helper_module_nudge()\nexcept')
    migrations = APP.index('\n_startup_migrations()\n_post_update_auto_deploy()')
    assert canary < nudge < migrations
    assert 'selinux helper module check skipped (non-fatal)' in APP
