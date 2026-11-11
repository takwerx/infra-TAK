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
"""start.sh on RHEL keeps firewalld rules scoped on re-run.

The firewalld block in start.sh used to seed a blanket `--add-port` from `ss` on every
run, which also caught internal listeners (Guard Dog health 8080, Postfix 25, PostgreSQL
5432, Fed Hub UI 9100, TAK 8444/9000/9001) that their modules scope by source. Now
start.sh seeds only public-by-design ports, only when firewalld is first turned on, and
the console start removes any blanket allow an older start.sh left on the internal ports.

The start.sh half runs the real block under bash against stateful fake `ss`,
`firewall-cmd` and `systemctl`; the app.py half runs the real function against a fake
firewalld.
"""

import ast
import os
import pathlib
import re
import shutil
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
START_SH = (REPO / 'start.sh').read_text(encoding='utf-8')
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(APP)

BASH = shutil.which('bash')
INTERNAL = {25, 5432, 8080, 9100, 8444, 9000, 9001, 111, 53, 1880}

# `ss -ltnH` lines. sshd is moved to 2222 (and still on 22); everything else is a
# module listener. -p adds the users:(...) column.
SS_ROWS = [
    ('0.0.0.0:22', 'sshd'),
    ('0.0.0.0:2222', 'sshd'),
    ('0.0.0.0:25', 'master'),
    ('*:5432', 'postgres'),
    ('0.0.0.0:8080', 'python3'),
    ('0.0.0.0:9100', 'java'),
    ('[::]:8444', 'java'),
    ('*:9000', 'java'),
    ('*:9001', 'java'),
    ('0.0.0.0:111', 'rpcbind'),
    ('127.0.0.53%lo:53', 'systemd-resolve'),
    ('127.0.0.1:1880', 'docker-proxy'),
    ('0.0.0.0:443', 'caddy'),
    ('*:8089', 'java'),
    ('0.0.0.0:5001', 'gunicorn'),
]


def _firewall_block():
    """The RHEL firewalld branch of start.sh (`if [ "$PKG_MGR" = "dnf" ]` ... `fi`)."""
    i = START_SH.index('# Host firewall:')
    j = START_SH.index('if [ "$PKG_MGR" = "dnf" ]; then', i)
    lines = START_SH[j:].splitlines()
    out = []
    for ln in lines:
        out.append(ln)
        if ln == 'fi':
            break
    return '\n'.join(out) + '\n'


def _stub(d, name, body):
    p = d / name
    p.write_text('#!/bin/sh\n' + body)
    p.chmod(0o755)


def _run_block(tmp_path, *, active, rich=''):
    """Run the block. Returns (ports added, every firewall-cmd call)."""
    bin_ = tmp_path / 'bin'
    bin_.mkdir()
    st = tmp_path / 'state'
    st.mkdir()
    (st / 'active').write_text('1' if active else '0')
    (st / 'rich').write_text(rich)
    (st / 'calls').write_text('')
    plain = '\n'.join(f'LISTEN 0 128 {a} 0.0.0.0:*' for a, _ in SS_ROWS) + '\n'
    withp = '\n'.join(f'LISTEN 0 128 {a} 0.0.0.0:* users:(("{p}",pid=1,fd=3))'
                      for a, p in SS_ROWS) + '\n'
    (st / 'ss_plain').write_text(plain)
    (st / 'ss_p').write_text(withp)
    _stub(bin_, 'ss', f'case "$1" in *p*) cat "{st}/ss_p";; *) cat "{st}/ss_plain";; esac\n')
    _stub(bin_, 'systemctl', f'''
case "$*" in
  *is-active*) [ "$(cat "{st}/active")" = 1 ] ;;
  *enable*--now*firewalld*) echo 1 > "{st}/active" ;;
esac
''')
    _stub(bin_, 'firewall-cmd', f'''
[ "$(cat "{st}/active")" = 1 ] || {{ echo "FirewallD is not running" >&2; exit 252; }}
echo "$*" >> "{st}/calls"
case "$*" in
  *--list-rich-rules*) cat "{st}/rich" ;;
esac
exit 0
''')
    _stub(bin_, 'dnf', 'exit 0\n')
    script = tmp_path / 'block.sh'
    script.write_text('PKG_MGR=dnf\n' + _firewall_block())
    env = {'PATH': f'{bin_}{os.pathsep}/usr/bin{os.pathsep}/bin', 'HOME': str(tmp_path)}
    r = subprocess.run([BASH, str(script)], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    calls = [c for c in (st / 'calls').read_text().splitlines() if c]
    added = set()
    for c in calls:
        m = re.search(r'--add-port=(\d+)/tcp', c)
        if m:
            added.add(int(m.group(1)))
    return added, calls


pytestmark = pytest.mark.skipif(BASH is None, reason='bash not available')


def test_first_activation_opens_no_internal_port(tmp_path):
    added, _ = _run_block(tmp_path, active=False)
    assert not added & INTERNAL, f'internal ports seeded:{sorted(added & INTERNAL)}'


def test_first_activation_keeps_public_module_ports_ssh_and_console(tmp_path):
    added, calls = _run_block(tmp_path, active=False)
    assert added == {443, 8089, 5001, 2222}
    assert any('--add-service=ssh' in c for c in calls)
    assert calls[-1] == '--reload'


def test_rerun_with_firewalld_running_seeds_nothing(tmp_path):
    """A re-run (repair, reinstall) must not widen anything: the permanent rules already
    hold what the modules opened. Only SSH and the console are re-asserted."""
    added, calls = _run_block(tmp_path, active=True)
    assert added == {5001, 2222}
    assert calls[-1] == '--reload'


def test_source_scoped_console_port_is_not_widened(tmp_path):
    rich = 'rule family="ipv4" source address="203.0.113.7" port port="5001" protocol="tcp" accept\n'
    added, _ = _run_block(tmp_path, active=True, rich=rich)
    assert 5001 not in added


def test_seed_list_is_public_by_design_only():
    m = re.search(r'for _p in ((?:\d+ )+\d+); do\n\s+printf', START_SH)
    assert m, 'seed allow-list loop not found in start.sh'
    seed = {int(p) for p in m.group(1).split()}
    assert not seed & INTERNAL
    assert not seed & {p for p, _ in _console_only_ports()}


def test_firewall_runs_before_the_console_starts():
    """So the console's startup convergence (hardening posture, 8080 scope, cleanup)
    runs after it and has the last word."""
    fw = START_SH.index('if [ "$PKG_MGR" = "dnf" ]; then', START_SH.index('# Host firewall:'))
    start = START_SH.index('\nsystemctl start takwerx-console\n')
    assert fw < start


# ── app.py: existing boxes heal on console start ─────────────────────────────

def _fn(name):
    for n in _TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} not found in app.py')


def _assign(name):
    for n in _TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} not found in app.py')


def _console_only_ports():
    ns = {}
    exec(_assign('_FW_CONSOLE_ONLY_TCP'), ns)
    return ns['_FW_CONSOLE_ONLY_TCP']


class FakeFirewalld:
    def __init__(self, zones, default='public'):
        self.zones = {z: set(p) for z, p in zones.items()}
        self.default = default
        self.calls = []

    def run(self, argv, **_kw):
        self.calls.append(list(argv))
        args = argv[1:]
        out, rc = '', 0
        zone = next((a.split('=', 1)[1] for a in args if a.startswith('--zone=')), self.default)
        if args == ['--get-default-zone']:
            out = self.default + '\n'
        elif '--list-ports' in args:
            out = ' '.join(sorted(self.zones.get(zone, ()))) + '\n'
        elif any(a.startswith('--remove-port=') for a in args):
            p = next(a for a in args if a.startswith('--remove-port=')).split('=', 1)[1]
            self.zones.get(zone, set()).discard(p)
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr='')


def _cleanup(fake, backend='firewalld'):
    logs = []
    ns = {'re': re, 'subprocess': types.SimpleNamespace(run=fake.run),
          '_sudo_wrap': lambda a: a, '_fw_backend': lambda: backend}
    exec(_assign('_FW_CONSOLE_ONLY_TCP'), ns)
    exec(_fn('_fw_remove_blanket_internal_ports'), ns)
    closed = ns['_fw_remove_blanket_internal_ports'](log=logs.append)
    return closed, logs


SEEDED = {'5001/tcp', '25/tcp', '5432/tcp', '8080/tcp', '9100/tcp', '443/tcp', '8089/tcp',
          '8444/tcp', '9001/tcp', '2222/tcp'}


def test_update_removes_blanket_internal_ports():
    fake = FakeFirewalld({'public': SEEDED})
    closed, logs = _cleanup(fake)
    assert sorted(closed) == ['public:25/tcp', 'public:5432/tcp', 'public:8080/tcp', 'public:9100/tcp']
    assert fake.zones['public'] == {'5001/tcp', '443/tcp', '8089/tcp', '8444/tcp', '9001/tcp', '2222/tcp'}
    assert len(logs) == 4 and all('removed blanket allow' in m for m in logs)
    assert fake.calls[-1] == ['firewall-cmd', '--reload']
    assert not any('rich-rule' in ' '.join(c) for c in fake.calls), 'scoped rules must be kept'


def test_update_also_cleans_a_non_public_default_zone():
    fake = FakeFirewalld({'public': {'5001/tcp'}, 'internal': {'8080/tcp', '22/tcp'}}, default='internal')
    closed, _ = _cleanup(fake)
    assert closed == ['internal:8080/tcp']
    assert fake.zones['internal'] == {'22/tcp'}


def test_nothing_to_close_means_no_change_and_no_reload():
    fake = FakeFirewalld({'public': {'5001/tcp', '443/tcp'}})
    closed, logs = _cleanup(fake)
    assert closed == [] and logs == []
    assert not any('--remove-port' in ' '.join(c) or c[-1] == '--reload' for c in fake.calls)


def test_ufw_boxes_are_left_alone():
    fake = FakeFirewalld({'public': SEEDED})
    closed, _ = _cleanup(fake, backend='ufw')
    assert closed == [] and fake.calls == []


def test_cleanup_never_raises():
    def boom(*_a, **_k):
        raise OSError('broker down')
    logs = []
    ns = {'re': re, 'subprocess': types.SimpleNamespace(run=boom),
          '_sudo_wrap': lambda a: a, '_fw_backend': lambda: 'firewalld'}
    exec(_assign('_FW_CONSOLE_ONLY_TCP'), ns)
    exec(_fn('_fw_remove_blanket_internal_ports'), ns)
    assert ns['_fw_remove_blanket_internal_ports'](log=logs.append) == []
    assert logs and 'non-fatal' in logs[0]


def test_cleanup_runs_at_console_start_before_the_8080_scope():
    calls = [n.value.func.id for n in _TREE.body
             if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
             and isinstance(n.value.func, ast.Name)]
    assert '_fw_remove_blanket_internal_ports' in calls
    assert calls.index('_fw_remove_blanket_internal_ports') < calls.index('_auto_harden_guarddog_8080')
