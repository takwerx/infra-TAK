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
"""The JVM pin never asks the broker for the box-wide java alternative (v10.2.8 W5a).

Broker audit logs, 2026-10-08:

    test8   64 x WOULD-DENY  update-alternatives --set java /usr/lib/jvm/java-17-openjdk-amd64/bin/java
    test12  44 x WOULD-DENY  update-alternatives --set java ...
    daily:  broker staying PERMISSIVE: ... WOULD-DENY seen 11.9h ago (need 72h clean)

_pin_takserver_jvm() ran that `--set` through the broker on every console start. ENFORCE needs
72 h with no WOULD-DENY and the console restarts at least daily, so no permissive native-TAK box
could ever enforce. Now the alternative is READ unprivileged first; a broker-mediated console
never asks to change it (TAK is pinned by /opt/tak/setenv.sh regardless); a root console still
sets it when it has drifted.
"""

import ast
import os as _real_os
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

JBIN = '/usr/lib/jvm/java-17-openjdk-amd64/bin/java'


def _load(names, ns):
    parts = [ast.get_source_segment(APP, n) for n in ast.parse(APP).body
             if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(parts) == len(names), 'a function under test was renamed or removed'
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


class _Run:
    def __init__(self, stdout=''):
        self.calls, self.stdout = [], stdout

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout=self.stdout, stderr='')


def _pin(state, routed):
    run = _Run()
    logs = []
    fake_path = types.SimpleNamespace(exists=lambda p: True, isfile=lambda p: False,
                                      realpath=_real_os.path.realpath)
    ns = {
        'os': types.SimpleNamespace(path=fake_path),
        're': re,
        'subprocess': types.SimpleNamespace(run=run),
        '_tak_is_container': lambda: False,
        '_resolve_java17_home': lambda: ('/usr/lib/jvm/java-17-openjdk-amd64', JBIN),
        '_distro_family': lambda: 'debian',
        '_read_priv': lambda p: '',
        '_write_priv': lambda p, c, **k: None,
        '_makedirs_priv': lambda p: None,
        '_sudo_wrap': lambda cmd: ['BROKER'] + list(cmd),
        '_host_arch': lambda: 'amd64',
        '_broker_should_route': lambda: routed,
        '_broker_available': lambda: routed,
        '_java_alternative_state': lambda fam=None: state,
        '_TAK_JVM_DROPIN': '/etc/systemd/system/takserver.service.d/jvm-pin.conf',
        '_TAK_JVM_DROPIN_DIR': '/etc/systemd/system/takserver.service.d',
        '_TAK_SETENV': '/opt/tak/setenv.sh',
        '_TAK_SETENV_JVM_A': '# >>> infra-TAK managed JVM >>>',
        '_TAK_SETENV_JVM_B': '# <<< infra-TAK managed JVM <<<',
    }
    _load(['_pin_takserver_jvm'], ns)
    ns['_pin_takserver_jvm'](plog=logs.append)
    sets = [c for c in run.calls if '--set' in c]
    return sets, logs


def test_broker_console_with_drift_never_asks_the_broker():
    sets, logs = _pin(('auto', '/usr/lib/jvm/java-21-openjdk-amd64/bin/java'), routed=True)
    assert sets == []
    assert any('not managed on a broker-mediated console' in l for l in logs)
    assert any('setenv.sh' in l for l in logs)


def test_broker_console_already_pinned_makes_no_call():
    sets, logs = _pin(('manual', JBIN), routed=True)
    assert sets == []
    assert not any('not managed' in l for l in logs)


def test_root_console_with_drift_still_sets_the_alternative():
    sets, _ = _pin(('auto', '/usr/lib/jvm/java-21-openjdk-amd64/bin/java'), routed=False)
    assert sets and sets[0][-3:] == ['--set', 'java', JBIN]


def test_root_console_already_pinned_makes_no_call():
    sets, _ = _pin(('manual', JBIN), routed=False)
    assert sets == []


def _state(fam, stdout):
    run = _Run(stdout)
    ns = {'re': re, 'subprocess': types.SimpleNamespace(run=run),
          '_distro_family': lambda: fam}
    _load(['_java_alternative_state'], ns)
    return ns['_java_alternative_state'](fam), run.calls


def test_state_debian_reads_query_unprivileged():
    out = ('Name: java\nLink: /usr/bin/java\nStatus: manual\n'
           f'Best: {JBIN}\nValue: {JBIN}\n')
    (st, val), calls = _state('debian', out)
    assert (st, val) == ('manual', JBIN)
    assert calls == [['update-alternatives', '--query', 'java']]     # no sudo, no broker


def test_state_rhel_reads_display_unprivileged():
    # verbatim from nuc (Rocky 9), 2026-10-08
    path = '/usr/lib/jvm/java-17-openjdk-17.0.20.1.1-1.2.el9_8.x86_64/bin/java'
    out = ('java - status is auto.\n'
           f' link currently points to {path}\n'
           f'{path} - family java-17-openjdk.x86_64 priority 17002021\n')
    (st, val), calls = _state('rhel', out)
    assert (st, val) == ('auto', path)
    assert calls == [['alternatives', '--display', 'java']]


def test_state_unreadable_is_empty_not_an_exception():
    (st, val), _ = _state('debian', '')
    assert (st, val) == ('', '')
