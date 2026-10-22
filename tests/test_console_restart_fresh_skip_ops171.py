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
"""The daily console restart leaves a freshly started console alone (ops #171).

Found in T&E (2026-10-22): a box powered on after missing the 04:00 run got the
Persistent=true catch-up 2 s into the console's boot. The console was still
importing app.py and running startup migrations, so it did not answer :5001
within 5 s; the script called that "likely wedged" and restarted it, killing a
CloudTAK container recreate half way.

The REAL script is cut out of app.py and run under bash with systemctl / ps /
curl / logger stubbed on PATH, so what is checked is what a box runs.
"""

import ast
import os
import pathlib
import stat
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / 'app.py').read_text(encoding='utf-8')


def _script_from_app():
    tree = ast.parse(APP)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                getattr(t, 'id', None) == '_CONSOLE_RESTART_SCRIPT' for t in node.targets):
            return node.value.value
    raise AssertionError('_CONSOLE_RESTART_SCRIPT not found in app.py')


SCRIPT = _script_from_app()


@pytest.fixture
def box(tmp_path):
    """A fake box: stub bin dir + a calls log. Returns run(uptime_s, main_pid, safe)."""
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    calls = tmp_path / 'calls'
    script = tmp_path / 'tak-console-restart.sh'
    script.write_text(SCRIPT)
    script.chmod(0o755)

    def stub(name, body):
        p = bindir / name
        p.write_text('#!/bin/bash\n' + body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR)

    stub('systemctl',
         'echo "systemctl $*" >> "$CALLS"\n'
         'if [ "$1" = show ]; then echo "$FAKE_MAIN_PID"; fi\n'
         'exit 0\n')
    stub('ps',
         'echo "ps $*" >> "$CALLS"\n'
         '[ -n "$FAKE_UPTIME" ] && printf "  %s\\n" "$FAKE_UPTIME"\n'
         'exit 0\n')
    stub('curl',
         'echo "curl $*" >> "$CALLS"\n'
         'printf "%s" "$FAKE_SAFE"\n'
         'exit 0\n')
    stub('logger', 'exit 0\n')

    def run(uptime_s, main_pid='4242', safe=''):
        if calls.exists():
            calls.unlink()
        env = dict(os.environ,
                   PATH=f'{bindir}:{os.environ["PATH"]}',
                   CALLS=str(calls),
                   FAKE_MAIN_PID=main_pid,
                   FAKE_UPTIME='' if uptime_s is None else str(uptime_s),
                   FAKE_SAFE=safe)
        r = subprocess.run(['bash', str(script)], env=env,
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        log = calls.read_text() if calls.exists() else ''
        return r.stdout, log

    return run


def _restarted(log):
    return 'systemctl restart takwerx-console.service' in log


def test_console_seconds_into_boot_is_not_restarted(box):
    # The ops #171 case: catch-up run 2 s after the console started.
    out, log = box(uptime_s=2)
    assert 'skipped' in out and 'started 2s ago' in out
    assert not _restarted(log)
    assert 'curl' not in log   # never even probed, so never misread as wedged


def test_console_up_just_under_the_window_is_still_skipped(box):
    out, log = box(uptime_s=1799)
    assert not _restarted(log)


def test_wedged_console_that_has_been_up_for_days_is_still_restarted(box):
    # The failure mode the timer exists for must keep working.
    out, log = box(uptime_s=5 * 86400, safe='')
    assert 'likely wedged' in out
    assert _restarted(log)


def test_idle_console_past_the_window_is_restarted(box):
    out, log = box(uptime_s=1800, safe='{"safe": true, "reason": null}')
    assert 'console idle' in out
    assert _restarted(log)


def test_busy_console_past_the_window_is_deferred(box):
    out, log = box(uptime_s=86400, safe='{"safe": false, "reason": "atlas update running"}')
    assert 'deferred' in out
    assert not _restarted(log)


@pytest.mark.parametrize('main_pid,uptime', [('0', None), ('', None), ('4242', None)])
def test_unknown_uptime_falls_through_to_the_probe(box, main_pid, uptime):
    # Console not running, or ps can't say: behave exactly as before the skip.
    out, log = box(uptime_s=uptime, main_pid=main_pid, safe='')
    assert 'curl' in log
    assert _restarted(log)


def test_timer_has_no_persistent_catch_up():
    i = APP.index('def _ensure_console_restart_timer')
    body = APP[i:APP.index('\ndef ', i + 1)]
    timer = body[body.index('tmr_content = ('):body.index('changed = False')]
    assert 'OnCalendar=*-*-* 04:00:00' in timer
    assert 'Persistent=true' not in timer


def test_committed_script_copy_matches_the_canonical_one():
    # scripts/tak-console-restart.sh is the operator-visible copy; its extra
    # header aside, the code must be what app.py installs.
    copy = (ROOT / 'scripts' / 'tak-console-restart.sh').read_text(encoding='utf-8')
    assert copy[copy.index('set -u\n'):] == SCRIPT[SCRIPT.index('set -u\n'):]
