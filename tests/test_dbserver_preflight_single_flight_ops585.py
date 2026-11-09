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
"""One database server preflight at a time (infra-TAK #442, ops #585).

Since 10.3.9 the database server card runs the preflight on every dashboard load. Each one
is an SSH probe that a slow database server holds for up to 4 minutes, and the console has
8 request threads. Test pair, Mon Nov 9, 2026 (PostgreSQL frozen on the database server):
9 parallel preflights left the console answering nothing, not even its login page, for about
3.5 minutes. A caller that finds a preflight already running must get an answer at once.
"""

import pathlib
import re
import threading

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
CONSOLE = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


def _ns(preflight):
    ns = {'_dbserver_preflight_lock': threading.Lock(), '_dbserver_preflight': preflight}
    exec(compile(_fn('_dbserver_preflight_once'), 'app.py:_dbserver_preflight_once', 'exec'), ns)
    return ns


def test_one_preflight_answers_200_with_the_checks():
    ns = _ns(lambda: {'ok': True, 'checks': [], 'pending_count': 0})
    assert ns['_dbserver_preflight_once']() == (200, {'ok': True, 'checks': [], 'pending_count': 0})
    assert not ns['_dbserver_preflight_lock'].locked()


def test_second_caller_gets_busy_at_once_while_a_probe_hangs():
    entered, release = threading.Event(), threading.Event()
    calls = []

    def slow_probe():
        calls.append(1)
        entered.set()
        release.wait(30)
        return {'ok': True, 'checks': []}

    ns = _ns(slow_probe)
    first = {}
    t = threading.Thread(target=lambda: first.update(r=ns['_dbserver_preflight_once']()))
    t.start()
    try:
        assert entered.wait(5)
        done = threading.Event()
        second = {}

        def call():
            second['r'] = ns['_dbserver_preflight_once']()
            done.set()
        threading.Thread(target=call, daemon=True).start()
        assert done.wait(2), 'the second preflight waited on the first instead of answering'
        code, payload = second['r']
        assert code == 429 and payload['busy'] and not payload['ok']
        assert 'checks' not in payload   # the dialog shows .error only when there are no checks
        assert 'already checking the database server' in payload['error']
        assert len(calls) == 1, 'a second SSH probe was started'
    finally:
        release.set()
        t.join(10)
    assert first['r'][0] == 200
    assert not ns['_dbserver_preflight_lock'].locked()
    assert ns['_dbserver_preflight_once']()[0] == 200   # free again once the first is done


def test_lock_is_released_when_the_probe_raises():
    def boom():
        raise RuntimeError('ssh exploded')
    ns = _ns(boom)
    try:
        ns['_dbserver_preflight_once']()
    except RuntimeError:
        pass
    assert not ns['_dbserver_preflight_lock'].locked()


def test_route_goes_through_the_single_flight_helper():
    decl = "@app.route('/api/console/dbserver/preflight')\n@login_required\ndef "
    body = APP[APP.index(decl):]
    body = body[:body.index('\n\n\n')]
    assert '_dbserver_preflight_once()' in body
    assert 'jsonify(_dbserver_preflight())' not in body
    assert re.search(r'^_dbserver_preflight_lock = threading\.Lock\(\)$', APP, re.M)


def test_page_shows_the_busy_answer_as_a_reason():
    # the card's line falls back to d.error, the dialog shows d.error when there are no checks
    assert "err=(bad&&bad.detail)||(d&&d.error)||'no answer'" in CONSOLE
    assert "if(!r.ok&&!d.checks){ if(err)err.textContent=d.error" in CONSOLE
