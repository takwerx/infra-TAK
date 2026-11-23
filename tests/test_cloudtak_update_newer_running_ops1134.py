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
"""ops #1134: Update on a CloudTAK newer than the version we test is not an error.

A customer who got CloudTAK 14.0.0 from 10.4.4 and presses Update after 10.4.5 (which pins
13.x) used to end with a red `v13.128.0 is older than the 14.0.0 already running; not
downgrading`. Nothing was wrong and nothing changed. Now the log says, in plain words,
"CloudTAK 14.0.0 is newer than the version we test. Nothing to do." and the job ends with
error False. The refusal itself (no downgrade, nothing checked out) is unchanged.

run_cloudtak_update is cut out of app.py and run for real up to its first return; every
other name it reaches is a stub that fails the test if it is called after the refusal.
"""

import ast
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _run(running, target):
    tree = ast.parse(APP)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_cloudtak_update')
    log, status, later = [], {'running': True, 'complete': False, 'error': False}, []

    def _boom(name):
        def f(*a, **k):
            later.append(name)
            raise AssertionError(f'{name} reached after the refusal')
        return f

    class _DT:
        @staticmethod
        def now():
            import datetime
            return datetime.datetime(2026, 11, 23, 8, 0, 0)

    ns = {
        're': re, 'os': __import__('os'), 'datetime': _DT,
        'cloudtak_deploy_log': log, 'cloudtak_deploy_status': status,
        'load_settings': lambda: {},
        '_get_cloudtak_deployment_config': lambda s: {'target_mode': 'local'},
        '_get_cloudtak_target_release_tag': lambda *a, **k: target,
        '_cloudtak_running_version': lambda *a, **k: running,
        '_cloudtak_update_space_problem': _boom('_cloudtak_update_space_problem'),
        '_mod_result_versions': _boom('_mod_result_versions'),
        '_cloudtak_git_prep': _boom('_cloudtak_git_prep'),
        'subprocess': type('S', (), {'run': staticmethod(_boom('subprocess.run'))}),
    }
    exec(compile(ast.Module(body=[fn], type_ignores=[]), 'app.py', 'exec'), ns)
    ns['run_cloudtak_update']()
    return log, status, later


def test_running_14_with_13_pin_ends_without_error_in_plain_words():
    log, status, later = _run('14.0.0', 'v13.128.0')
    text = '\n'.join(log)
    assert 'CloudTAK 14.0.0 is newer than the version we test. Nothing to do.' in text
    assert 'older than' not in text and 'not downgrading' not in text and '✗' not in text
    assert status['running'] is False
    assert status['error'] is False
    assert later == []          # nothing was built, checked out or measured after the refusal


def test_a_newer_patch_release_is_also_not_an_error():
    log, status, later = _run('13.130.1', 'v13.128.0')
    assert status['error'] is False and later == []
    assert 'CloudTAK 13.130.1 is newer than the version we test.' in '\n'.join(log)


def test_lookup_failure_is_still_an_error():
    log, status, later = _run('14.0.0', None)
    assert status['error'] is True
    assert 'Could not look up the latest CloudTAK release' in '\n'.join(log)


def test_refusal_stays_before_checkout():
    src = APP[APP.index('def run_cloudtak_update'):]
    src = src[:src.index('\ndef ', 10)]
    assert src.index('is newer than the version we test') < src.index('Step 2/3')
    assert 'not downgrading' not in src
