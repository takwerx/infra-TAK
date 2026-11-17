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
"""ops #845: a Guard Dog script fix reaches a box on the FIRST restart after Update Now.

_auto_update_guarddog() runs at module load, before _broker_converge_running_source() has
installed the new commit in root's broker. gd_render fills a script from the broker's own
copy of the repo, so the first restart after an update rendered every Guard Dog script from
the PREVIOUS release; the new one landed only on the second restart. The converge now goes
through _startup_broker_converge(), which refreshes Guard Dog again when the broker changed.

Fails on dev 65ec764 (there is no _startup_broker_converge; the converge was a bare try).
"""
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _func():
    start = APP.index('def _startup_broker_converge():')
    end = APP.index('\n_startup_broker_converge()', start)
    return APP[start:end]


def _load(converge, refresh):
    ns = {'_broker_converge_running_source': converge, '_auto_update_guarddog': refresh}
    exec(_func(), ns)
    return ns['_startup_broker_converge']


def test_refresh_runs_again_once_the_broker_changed():
    calls = []
    f = _load(lambda: calls.append('converge') or True, lambda: calls.append('refresh'))
    f()
    assert calls == ['converge', 'refresh']


def test_no_second_refresh_when_the_broker_did_not_change():
    calls = []
    f = _load(lambda: calls.append('converge') or False, lambda: calls.append('refresh'))
    f()
    assert calls == ['converge']


def test_a_failed_converge_never_stops_startup_or_triggers_a_refresh(capsys):
    calls = []

    def boom():
        raise RuntimeError('broker socket gone')

    f = _load(boom, lambda: calls.append('refresh'))
    f()    # must not raise
    assert calls == []
    assert 'broker source convergence skipped' in capsys.readouterr().out


def test_a_failed_second_refresh_never_stops_startup(capsys):
    def boom():
        raise RuntimeError('gd_render refused')

    f = _load(lambda: True, boom)
    f()    # must not raise
    assert 'Guard Dog refresh after broker convergence skipped' in capsys.readouterr().out


def test_first_restart_after_an_update_installs_the_new_script():
    """The customer path, in the order app.py runs it. The broker holds release 1's template;
    the console is on release 2. The module-load refresh renders release 1 (stale); only a
    refresh after the broker converges installs release 2."""
    broker_copy = {'tak-disk-watch.sh': 'release 1'}
    installed = {}

    def refresh():      # what gd_render does: fill from the broker's own copy
        installed.update(broker_copy)

    def converge():     # the broker installs the console's commit
        broker_copy['tak-disk-watch.sh'] = 'release 2'
        return True

    refresh()                               # module load, line ~107366 of app.py
    assert installed['tak-disk-watch.sh'] == 'release 1'
    _load(converge, refresh)()              # line ~117703 of app.py
    assert installed['tak-disk-watch.sh'] == 'release 2'


def test_app_runs_the_refresh_before_the_converge_and_has_no_bare_converge_left():
    """Pins the premise (the refresh really is first) and that nothing calls the converge
    without the follow-up refresh."""
    refresh_call = APP.index('\n_auto_update_guarddog()\n')
    converge_call = APP.index('\n_startup_broker_converge()\n')
    assert refresh_call < converge_call
    assert APP.count('_broker_converge_running_source()') == 1    # only inside _startup_broker_converge
    assert '    changed = _broker_converge_running_source()' in _func()
