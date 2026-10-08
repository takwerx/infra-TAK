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
"""Every TAK Server update leaves a record Help → Diagnostics can read (v10.2.2 W9).

Field 2026-10-01: a customer's 5.8 upgrade failed and the only evidence was a
screenshot of three lines — the update log lived in the console's memory and in
one browser tab. The recorder and the Diagnostics section are cut out of app.py
and run against a temp file.
"""

import datetime as _dt
import json
import os
import pathlib
import re
import stat
import threading
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


@pytest.fixture
def ns(tmp_path):
    n = {'os': os, 'json': json, 'time': time, 'threading': threading,
         'datetime': _dt.datetime, 'TAK_UPDATE_HISTORY': str(tmp_path / 'takserver_update_history.json'),
         '_TAK_UPDATE_HISTORY_KEEP': 5, '_TAK_UPDATE_HISTORY_LINES': 400,
         '_TAK_UPDATE_HISTORY_LOCK': threading.Lock(),
         'upgrade_status': {'running': False}, 'tak58_status': {'running': False}}
    # v10.2.8 W10: the factory also records the outcome for the card + Diagnostics
    n['w10'] = []
    n['_mod_result_start'] = lambda *a, **k: n['w10'].append(('start',) + a)
    n['_tracked_finish'] = lambda module, status, log, exc=None, kind='update': n['w10'].append(
        ('finish', module, bool(status.get('error')) or exc is not None))
    for f in ('_tak_update_history', '_tak_update_record', '_tak_update_job', '_diag_tak_update_history'):
        exec(compile(_cut(f), 'app.py:' + f, 'exec'), n)
    return n


def _worker(lines, status, end=None, raises=None):
    def w(pkg, log=None, status_=None):
        log.extend(lines)
        if end:
            status.update(end)
        if raises:
            raise raises
    return w


def run(ns, lines, end=None, raises=None, pkg='/var/www/uploads/takserver_5.8-RELEASE84_all.deb'):
    log, status = [], {'running': True, 'complete': False, 'error': False}
    job = ns['_tak_update_job']('5.8 migration', _worker(lines, status, end, raises), log, status)
    job(pkg, log=log, status_=status)
    return ns['_tak_update_history']()


def test_failed_update_is_saved_with_its_log_and_mode_600(ns):
    h = run(ns, ['Checking this server is ready to migrate…',
                 'snapshot: pg_dump FAILED (exit 1): could not connect',
                 'Backup failed — refusing to migrate without one.'],
            end={'running': False, 'error': True})
    assert h[0]['result'] == 'FAILED'
    assert h[0]['package'] == 'takserver_5.8-RELEASE84_all.deb'
    assert 'pg_dump FAILED (exit 1)' in h[0]['lines'][1]
    assert stat.S_IMODE(os.stat(ns['TAK_UPDATE_HISTORY']).st_mode) == 0o600


def test_mid_upgrade_and_crash_and_success_are_told_apart(ns):
    run(ns, ['x', '*** THIS SERVER IS MID-UPGRADE AND TAK IS NOT RUNNING. ***'], end={'error': True})
    with pytest.raises(RuntimeError):
        run(ns, ['y'], raises=RuntimeError('boom'))
    h = run(ns, ['z'], end={'running': False, 'complete': True})
    assert [e['result'] for e in h] == ['ok', 'CRASHED (RuntimeError: boom)', 'FAILED (left mid-upgrade)']


def test_history_keeps_the_last_five_runs_and_the_log_tail(ns):
    for i in range(7):
        run(ns, ['line %d' % j for j in range(1000)], end={'complete': True})
    h = ns['_tak_update_history']()
    assert len(h) == 5
    assert len(h[0]['lines']) == 400 and h[0]['lines'][-1] == 'line 999' and h[0]['total_lines'] == 1000


def test_diagnostics_lists_runs_and_shows_the_latest_failure(ns):
    assert 'none' in ns['_diag_tak_update_history']()[0]
    run(ns, ['Backing up before anything is changed…', 'snapshot: pg_dump did not finish within 10 min'],
        end={'error': True})
    run(ns, ['all good'], end={'complete': True})
    out = ns['_diag_tak_update_history']()
    assert out[0].startswith('TAK Server updates recorded by this console')
    assert ' ok ' in out[1] and ' FAILED ' in out[2]
    assert out[3].startswith('log of the latest update that did not succeed')
    assert any('did not finish within 10 min' in l for l in out[4:])


def test_diagnostics_says_when_an_update_is_running(ns):
    ns['upgrade_status']['running'] = True
    assert 'RUNNING right now' in ns['_diag_tak_update_history']()[0]


def test_a_broken_history_file_never_breaks_diagnostics(ns):
    open(ns['TAK_UPDATE_HISTORY'], 'w').write('{not json')
    assert ns['_tak_update_history']() == []
    run(ns, ['a'], end={'complete': True})              # and recording recovers
    assert ns['_tak_update_history']()[0]['result'] == 'ok'


# --- wiring ---------------------------------------------------------------------
def test_no_tak_update_worker_is_launched_without_the_recorder():
    assert not re.search(r'threading\.Thread\(target=run_takserver_(upgrade|58)', APP)
    launched = set(re.findall(r"_tak_update_job\('[^']+', (run_takserver_\w+)", APP))
    workers = set(re.findall(r'^def (run_takserver_(?:upgrade\w*|58\w*))\(', APP, re.M))
    assert workers and workers <= launched, workers - launched


def test_history_is_in_the_redacted_report():
    body = _cut('_diag_section_takserver')
    assert 'out.extend(_diag_tak_update_history())' in body            # installed boxes
    assert "['TAK Server not installed on this box'] + _diag_tak_update_history()" in body
    assert re.search(r"return _diag_redact\('\\n'\.join\(parts\), settings\)", APP)


def test_the_factory_also_feeds_the_w10_record(ns):
    """v10.2.8 W10: every TAK update variant lands on the card and in Diagnostics too."""
    status, log = {'running': True}, []
    job = ns['_tak_update_job']('5.8 migration', _worker(['✗ pg_upgrade failed'], status,
                                                         {'running': False, 'error': True}), log, status)
    job('takserver-5.8.zip', log=log, status_=status)
    assert ns['w10'][0][:2] == ('start', 'takserver')
    assert ns['w10'][-1] == ('finish', 'takserver', True)
