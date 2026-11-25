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
"""ops #1229: a Rocky box with the confined console unit could not restart its console
after the broker made /opt/infratak and /home/takwerx nosuid (ops #645 W2.5).

Cause (verified on nuc, Rocky 9.9, Enforcing): the kernel has the policy capability
nnp_nosuid_transition=1. systemd (init_t) starting gunicorn from a nosuid mount, into
takwerx_console_t, then needs `process2 nosuid_transition`. takwerx_console_confined
2.1 did not allow it: status 203/EXEC, "Permission denied", restart counter above 100.

Fix: the module (2.2) allows it, and the broker applies the nosuid mounts only after the
module refresh pass and never while the console unit is confined and the module is older
than 2.2.

Nothing here touches a real mount or SELinux: the broker is loaded as a module, the
kernel capability, the unit and the stamp are temp files, and mount is a stub.
"""

import importlib.util
import pathlib
import re
import shutil
import subprocess
import threading
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
TE = REPO / 'selinux' / 'takwerx_console_confined.te'


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_1229',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _broker()

CONFINED_UNIT = ('[Service]\nUser=takwerx\n'
                 'SELinuxContext=system_u:system_r:takwerx_console_t:s0\n'
                 'ExecStart=/opt/infratak/.venv/bin/gunicorn app:app\n')
UNCONFINED_UNIT = CONFINED_UNIT.replace('takwerx_console_t', 'unconfined_service_t')


@pytest.fixture
def files(tmp_path, monkeypatch):
    """The three files the gate reads, pointed at temp copies. raising=False: on the
    base commit these names do not exist yet, and the tests must then fail on the
    behaviour (mounts applied), not on a missing attribute."""
    cap, unit, stamp = tmp_path / 'cap', tmp_path / 'unit', tmp_path / 'stamp'
    cap.write_text('1\n')
    unit.write_text(CONFINED_UNIT)
    stamp.write_text('2.1\n')
    monkeypatch.setattr(B, 'NOSUID_SELINUX_CAP', str(cap), raising=False)
    monkeypatch.setattr(B, 'CONSOLE_UNIT_FILE', str(unit), raising=False)
    monkeypatch.setattr(B, 'CONFINED_MODULE_STAMP', str(stamp), raising=False)
    return cap, unit, stamp


class _Run:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        return type('R', (), {'returncode': 0, 'stderr': ''})()


def _apply_with_one_target(monkeypatch):
    monkeypatch.setattr(B, '_nosuid_targets', lambda: ['/opt/infratak'])
    monkeypatch.setattr(B, '_mountinfo', lambda text=None: {})
    run = _Run()
    ok, log = B._apply_nosuid_mounts(run=run)
    return ok, log, run


# ---------------------------------------------------------------------------
# 1. The module allows what systemd needs
# ---------------------------------------------------------------------------
def test_module_allows_init_to_start_the_console_from_a_nosuid_mount():
    text = TE.read_text()
    assert re.match(r'module takwerx_console_confined 2\.(2|[3-9]|\d\d+);', text.splitlines()[0])
    assert re.search(r'^allow init_t takwerx_console_t:process2 nosuid_transition;', text, re.M)
    # the class and permission are declared in the require block, or the module will not link
    assert re.search(r'^\s*class process2 [^;]*nosuid_transition[^;]*;', text, re.M)


def test_module_grants_nothing_wider_than_nosuid_transition_on_process2():
    grants = re.findall(r'^allow \S+ \S+:process2 ([^;]+);', TE.read_text(), re.M)
    assert grants == ['nosuid_transition']


@pytest.mark.skipif(not shutil.which('checkmodule'), reason='checkpolicy is not installed')
def test_module_compiles(tmp_path):
    r = subprocess.run(['checkmodule', '-M', '-m', '-o', str(tmp_path / 'm.mod'), str(TE)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


# ---------------------------------------------------------------------------
# 2. The broker keeps the folders as they are until the module is new enough
# ---------------------------------------------------------------------------
def test_mounts_are_not_applied_while_the_confined_module_is_2_1(files, monkeypatch):
    ok, log, run = _apply_with_one_target(monkeypatch)
    assert run.calls == []                      # no mount command ran
    assert ok is True                           # the boot unit must not end failed
    assert len(log) == 1 and 'skipped' in log[0] and '2.1' in log[0]


def test_mounts_are_not_applied_when_the_module_has_no_stamp(files, monkeypatch):
    files[2].unlink()
    ok, log, run = _apply_with_one_target(monkeypatch)
    assert run.calls == [] and 'not stamped' in log[0]


def test_mounts_are_applied_once_the_module_is_2_2(files, monkeypatch):
    files[2].write_text('2.2\n')
    ok, log, run = _apply_with_one_target(monkeypatch)
    assert ok is True
    assert [c[1:] for c in run.calls] == [
        ['--rbind', '/opt/infratak', '/opt/infratak'],
        ['-o', 'remount,bind,nosuid,nodev', '/opt/infratak'],
    ]


@pytest.mark.parametrize('stamp,blocked', [
    ('2.1', True), ('2.0', True), ('1.9', True), ('1.0', True), ('', True),
    ('2.2', False), ('2.2\n', False), ('2.10', False), ('2.3', False), ('3.0', False),
])
def test_version_compare_is_numeric_not_text(files, stamp, blocked):
    files[2].write_text(stamp)
    assert (B._nosuid_selinux_block() is not None) is blocked


def test_no_block_when_the_kernel_does_not_check_nosuid_transitions(files, monkeypatch):
    files[0].write_text('0\n')
    ok, log, run = _apply_with_one_target(monkeypatch)
    assert len(run.calls) == 2                  # old module, but nothing in the way


def test_no_block_without_selinux(files, monkeypatch):
    files[0].unlink()                           # Ubuntu: no such file
    ok, log, run = _apply_with_one_target(monkeypatch)
    assert len(run.calls) == 2


def test_no_block_when_the_console_unit_is_not_confined(files, monkeypatch):
    files[1].write_text(UNCONFINED_UNIT)
    ok, log, run = _apply_with_one_target(monkeypatch)
    assert len(run.calls) == 2


def test_no_block_when_there_is_no_console_unit(files, monkeypatch):
    files[1].unlink()
    ok, log, run = _apply_with_one_target(monkeypatch)
    assert len(run.calls) == 2


# ---------------------------------------------------------------------------
# 3. At broker start the module refresh finishes before the mounts are applied
# ---------------------------------------------------------------------------
def test_nosuid_converge_waits_for_the_selinux_refresh(monkeypatch):
    ev = threading.Event()
    monkeypatch.setattr(B, '_SELINUX_CONVERGED', ev, raising=False)
    seen = []
    monkeypatch.setattr(B, '_converge_nosuid_unit', lambda run=None: seen.append('nosuid') or False)
    t = threading.Thread(target=B._converge_nosuid_logged, daemon=True)
    t.start()
    time.sleep(0.3)
    assert seen == [], 'the mounts were applied before the SELinux refresh ended'
    ev.set()
    t.join(5)
    assert seen == ['nosuid']


def test_the_refresh_signals_even_when_it_fails(monkeypatch):
    ev = threading.Event()
    monkeypatch.setattr(B, '_SELINUX_CONVERGED', ev, raising=False)

    def boom():
        raise RuntimeError('semodule exploded')
    monkeypatch.setattr(B, '_selinux_policy_converge', boom)
    with pytest.raises(RuntimeError):
        B._selinux_policy_converge_signalled()
    assert ev.is_set()


def test_serve_starts_the_signalling_refresh():
    src = (REPO / 'broker' / 'takwerx_broker.py').read_text()
    assert 'target=_selinux_policy_converge_signalled' in src
    assert 'target=_selinux_policy_converge,' not in src
