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
"""CPU check before TAK Portal / CloudTAK deploy and in Diagnostics (ops #360).

A VM whose hypervisor presents a CPU below x86-64-v2 (no SSE4.2 / POPCNT) makes TAK Portal
restart-loop and CloudTAK's build die on the sharp image library. The deploy must stop first
with a plain message; a normal CPU and ARM must go through untouched.
"""

import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

V2 = 'fpu vme sse sse2 pni ssse3 cx16 sse4_1 sse4_2 popcnt lahf_lm avx avx2'
BASIC = 'fpu vme sse sse2 pni ssse3 cx16 lahf_lm'          # qemu64-style: no SSE4.x, no POPCNT
INFO = 'processor\t: 0\nmodel name\t: Test CPU\nflags\t\t: {}\n'


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _ns(**extra):
    ns = {'os': __import__('os'), 're': re}
    exec(re.search(r'^_CPU_V2_FLAGS = .*?\n(?=\n)', APP, re.S | re.M).group(0), ns)
    exec(re.search(r'^_CPU_TOO_BASIC_FIX = .*?\n(?=\n)', APP, re.S | re.M).group(0), ns)
    ns['_arch_normalize'] = lambda m: 'arm64' if (m or '').strip().lower() in ('aarch64', 'arm64') else 'amd64'
    ns.update(extra)
    for n in ('_cpu_v2_missing', '_cpu_too_basic_message', '_cpu_preflight_local',
              '_cpu_preflight_remote', '_diag_cpu_line'):
        exec(compile(_cut(n), 'app.py:' + n, 'exec'), ns)
    return ns


def test_normal_cpu_has_nothing_missing():
    assert _ns()['_cpu_v2_missing'](INFO.format(V2), 'x86_64') == []


def test_basic_cpu_reports_what_is_missing():
    assert _ns()['_cpu_v2_missing'](INFO.format(BASIC), 'x86_64') == ['popcnt', 'sse4_1', 'sse4_2']


def test_arm_and_unreadable_never_block():
    f = _ns()['_cpu_v2_missing']
    assert f(INFO.format(BASIC), 'aarch64') == []        # ARM skips the check
    assert f('Features\t: fp asimd\n', 'x86_64') == []   # no x86 flags line: can't judge
    assert f('', 'x86_64') == [] and f(None, '') == []


def test_message_is_plain_and_names_the_fix():
    msg = _ns()['_cpu_too_basic_message']('TAK Portal')
    assert msg.startswith("This server's virtual CPU is too basic for TAK Portal.")
    assert 'host passthrough' in msg and 'TrueNAS' in msg and 'Proxmox' in msg


def _local(tmp_path, flags, machine='x86_64', arch='amd64', unreadable=False):
    import builtins
    cpu = tmp_path / 'cpuinfo'
    cpu.write_text(INFO.format(flags))
    real_open = builtins.open

    def fake_open(p, *a, **k):
        if p == '/proc/cpuinfo':
            if unreadable:
                raise OSError('nope')
            return real_open(cpu, *a, **k)
        return real_open(p, *a, **k)
    os_stub = types.SimpleNamespace(uname=lambda: types.SimpleNamespace(machine=machine), path=__import__('os').path)
    ns = _ns(os=os_stub, open=fake_open, _host_arch=lambda: arch)
    log = []
    return ns, log


def test_local_preflight_stops_a_basic_cpu_with_the_plain_message(tmp_path):
    ns, log = _local(tmp_path, BASIC)
    assert ns['_cpu_preflight_local']('CloudTAK', log.append) is False
    assert "too basic for CloudTAK" in log[0] and 'host passthrough' in log[0]
    assert 'sse4_2' in log[1]


def test_local_preflight_lets_a_normal_box_through(tmp_path):
    ns, log = _local(tmp_path, V2)
    assert ns['_cpu_preflight_local']('TAK Portal', log.append) is True and log == []


def test_local_preflight_skips_arm_even_with_x86_looking_flags(tmp_path):
    ns, log = _local(tmp_path, BASIC, machine='aarch64', arch='arm64')
    assert ns['_cpu_preflight_local']('TAK Portal', log.append) is True and log == []


def test_local_preflight_unreadable_cpuinfo_goes_on(tmp_path):
    ns, log = _local(tmp_path, BASIC, unreadable=True)
    assert ns['_cpu_preflight_local']('TAK Portal', log.append) is True and log == []


def _remote(out, ok=True):
    log = []
    ns = _ns(_ssh_probe=lambda cfg, cmd, timeout=0: (ok, out))
    return ns['_cpu_preflight_remote']({}, 'CloudTAK', log.append), log


def test_remote_preflight():
    assert _remote('ARCH=x86_64\nflags\t\t: ' + BASIC + '\n')[0] is False
    assert _remote('ARCH=x86_64\nflags\t\t: ' + V2 + '\n')[0] is True
    assert _remote('ARCH=aarch64\n')[0] is True
    assert _remote('', ok=False)[0] is True              # SSH hiccup is the SSH step's problem


def _diag(tmp_path, flags, machine='x86_64'):
    import builtins
    cpu = tmp_path / 'cpuinfo'
    cpu.write_text(INFO.format(flags))
    real_open = builtins.open
    ns = _ns(os=types.SimpleNamespace(uname=lambda: types.SimpleNamespace(machine=machine)),
             open=lambda p, *a, **k: real_open(cpu if p == '/proc/cpuinfo' else p, *a, **k))
    return ns['_diag_cpu_line']()


def test_diagnostics_line(tmp_path):
    assert 'OK' in _diag(tmp_path, V2) and 'Test CPU' in _diag(tmp_path, V2)
    bad = _diag(tmp_path, BASIC)
    assert 'TOO BASIC' in bad and 'sse4_2' in bad and 'host passthrough' in bad
    assert 'not needed on ARM' in _diag(tmp_path, BASIC, machine='aarch64')


def test_wired_into_both_deploys_and_the_report():
    tp = _cut('run_takportal_deploy')
    assert tp.index("_cpu_preflight_local('TAK Portal'") < tp.index('Step 1/6: Checking Docker')
    ct = _cut('run_cloudtak_deploy')
    assert ct.count('_cpu_preflight_local(') == 1 and ct.count('_cpu_preflight_remote(') == 1
    assert ct.index('_cpu_preflight_local(') < ct.index('Step 1/7: Checking Docker')
    assert ct.index('_cpu_preflight_remote(') < ct.index('Step 2/6: Ensuring Docker on remote')
    assert '_diag_cpu_line()' in _cut('_diag_section_box')
