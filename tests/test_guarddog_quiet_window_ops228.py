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
"""Guard Dog quiet window (ops #228).

25 of the 27 Guard Dog emails the dev fleet sent on 2026-10-24/25 came from our own T&E
plugin rounds, an update/rollback drill and dev deploys. A quiet window holds delivery
while planned work runs, ends by itself, and must not hide a fault that outlives it.

The console functions are cut out of app.py (it cannot be imported in a test) and run with
their seams stubbed; gd-quiet.sh and send-alert-email.sh run for real with curl/id/logger
stubbed.
"""

import ast
import json
import os
import pathlib
import re
import subprocess
import tempfile
import threading
import time
from datetime import datetime

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
GD = REPO / 'scripts' / 'guarddog'
QUIET_SH = (GD / 'gd-quiet.sh').read_text()
SEND_SH = (GD / 'send-alert-email.sh').read_text()

QUIET_FNS = ('_gd_quiet_held_path', '_gd_quiet_state', '_gd_quiet_held_load',
             '_gd_quiet_held_save', '_gd_quiet_hold', '_gd_quiet_failing',
             '_gd_quiet_review_once')


def _fn(name):
    return ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name))


def _const(name):
    node = next(n for n in TREE.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return eval(compile(ast.Expression(node.value), 'app.py', 'eval'), {})   # literals and 4 * 3600


class Console:
    """The quiet-window functions over a temp state dir, with the send path recorded."""

    def __init__(self, tmp, health=None, recipient='ops@example.com'):
        self.tmp = tmp
        self.cfg = tmp / 'config'
        self.cfg.mkdir()
        self.marker = tmp / 'takguard' / 'quiet_window'
        self.marker.parent.mkdir()
        self.lock = tmp / 'update-now.lock'
        self.ak = tmp / 'takguard' / 'authentik_update_in_progress'
        self.health = dict(health or {})
        self.sent = []
        self.refreshed = 0
        self.settings = {'guarddog_alert_email': recipient}
        self.paused = False
        self.ns = {
            'os': os, 'json': json, 'time': time, 'tempfile': tempfile,
            'threading': threading, 'datetime': datetime, 'socket': __import__('socket'),
            'CONFIG_DIR': str(self.cfg),
            'GD_QUIET_MARKER': str(self.marker),
            'GD_QUIET_MAX_S': _const('GD_QUIET_MAX_S'),
            '_GD_QUIET_UPDATE_LOCK': str(self.lock),
            '_GD_QUIET_UPDATE_LOCK_TTL_S': _const('_GD_QUIET_UPDATE_LOCK_TTL_S'),
            '_GD_QUIET_AK_MARKER': str(self.ak),
            '_GD_QUIET_AK_MAX_S': _const('_GD_QUIET_AK_MAX_S'),
            'GD_QUIET_SETTLE_S': _const('GD_QUIET_SETTLE_S'),
            '_gd_quiet_lock': threading.Lock(),
            '_guarddog_page_cache': {'health': None},
            '_guarddog_refresh_page_cache': self._refresh,
            'load_settings': lambda: dict(self.settings),
            '_guarddog_server_identifier': lambda s: 'test-box (10.0.0.1)',
            '_guarddog_send_alert_email_via_relay': self._send,
        }
        for name in QUIET_FNS:
            exec(compile(_fn(name), 'app.py', 'exec'), self.ns)

    def _refresh(self):
        self.refreshed += 1
        self.ns['_guarddog_page_cache']['health'] = dict(self.health)

    def _send(self, to, subj, body, force=False):
        if self.paused:
            return False
        self.sent.append((to, subj, body))
        return True

    def window(self, start_off, end_off, reason='T&E ops #220'):
        now = int(time.time())
        self.marker.write_text(f'{now + start_off} {now + end_off} {reason}\n')

    def __getattr__(self, name):
        return self.ns[name]


@pytest.fixture
def box(tmp_path):
    return Console(tmp_path, health={'takserver': 'ok', 'cloudtak': 'ok'})


# ── when is a box quiet ───────────────────────────────────────────────────────

def test_no_signal_is_not_quiet(box):
    assert box._gd_quiet_state() == (False, 0, '')


def test_marker_opens_a_window_with_its_reason(box):
    box.window(-60, 3600, 'T&E ops #220 round 2')
    on, until, why = box._gd_quiet_state()
    assert on and why == 'T&E ops #220 round 2'
    assert abs(until - (time.time() + 3600)) < 5


@pytest.mark.parametrize('content', [
    'garbage\n', '', 'abc def reason\n', '123\n',
])
def test_unreadable_marker_is_noise_not_silence(box, content):
    box.marker.write_text(content)
    assert box._gd_quiet_state()[0] is False


def test_expired_marker_ends_by_itself(box):
    box.window(-7200, -1)
    assert box._gd_quiet_state()[0] is False


def test_over_long_marker_is_ignored_outright(box):
    # A window asking for more than four hours is not shortened to four hours: it is not a
    # window at all. Otherwise a hand-written "mute forever" would still mute for 4 h.
    box.window(-60, box.GD_QUIET_MAX_S + 60)
    assert box._gd_quiet_state()[0] is False


def test_future_dated_marker_does_not_start_early(box):
    box.window(3600, 7200)
    assert box._gd_quiet_state()[0] is False


def test_update_now_lock_holds_alerts_until_its_ttl(box):
    box.lock.write_text('version=x\n')
    on, until, why = box._gd_quiet_state()
    assert on and why == 'Update Now in progress'
    old = time.time() - box._GD_QUIET_UPDATE_LOCK_TTL_S - 5
    os.utime(box.lock, (old, old))
    assert box._gd_quiet_state()[0] is False


def test_authentik_update_marker_holds_alerts_until_its_cap(box):
    box.ak.write_text(f'{int(time.time())} 2026.8.5\n')
    assert box._gd_quiet_state()[2] == 'Authentik update in progress'
    old = time.time() - box._GD_QUIET_AK_MAX_S - 5
    os.utime(box.ak, (old, old))
    assert box._gd_quiet_state()[0] is False


def test_latest_ending_signal_wins(box):
    box.lock.write_text('x')
    box.window(-60, 3 * 3600, 'drill')
    assert box._gd_quiet_state()[2] == 'drill'


# ── the close-out review ──────────────────────────────────────────────────────

def test_review_waits_while_the_window_is_open(box):
    box.window(-60, 600)
    box._gd_quiet_hold('Guard Dog: CloudTAK restarted on test-box')
    assert box._gd_quiet_review_once() == 'open'
    assert box.refreshed == 0 and box.sent == []


def test_nothing_held_nothing_done(box):
    assert box._gd_quiet_review_once() == 'none'
    assert box.refreshed == 0


def test_held_alerts_that_cleared_are_dropped_quietly(box):
    box.window(-600, 600)
    box._gd_quiet_hold('Guard Dog: CloudTAK repaired automatically on test-box')
    box._gd_quiet_hold('Guard Dog: TAK Portal restarted on test-box')
    box.marker.unlink()                      # T&E: gd-quiet.sh off
    assert box._gd_quiet_review_once() == 'clear'   # all OK at the close: done at once
    assert box.refreshed == 1 and box.sent == []
    assert box._gd_quiet_held_load() == {}
    assert box._gd_quiet_review_once() == 'none'   # once only


SETTLE = _const('GD_QUIET_SETTLE_S')


def test_transient_failure_at_the_close_is_not_mailed(box):
    # nuc, 2026-10-25: the window closed 60 s after a console restart and a check was not
    # OK yet. Update Now ends like that on every box. Ten minutes later it was fine.
    box.health['cloudtak'] = 'caution'
    box._gd_quiet_hold('Guard Dog: CloudTAK restarted on test-box')
    t0 = time.time()
    assert box._gd_quiet_review_once(t0) == 'settling'
    assert box._gd_quiet_review_once(t0 + SETTLE - 5) == 'settling'
    assert box.refreshed == 1                 # no re-check before the settle is up
    box.health['cloudtak'] = 'ok'
    assert box._gd_quiet_review_once(t0 + SETTLE + 1) == 'clear'
    assert box.sent == [] and box._gd_quiet_held_load() == {}


def test_fault_that_outlives_the_window_is_mailed_once(box):
    box.health['cloudtak'] = 'fail'
    box.window(-600, 600, 'Update drill')
    box._gd_quiet_hold('Guard Dog: CloudTAK restarted on test-box')
    box.window(-1200, -1, 'Update drill')    # expired: the run died
    t0 = time.time()
    assert box._gd_quiet_review_once(t0) == 'settling'
    assert box.sent == []
    assert box._gd_quiet_review_once(t0 + SETTLE + 1) == 'sent'
    assert len(box.sent) == 1
    to, subj, body = box.sent[0]
    assert to == 'ops@example.com'
    assert subj == 'Guard Dog: still failing after planned work on test-box (10.0.0.1)'
    assert '• cloudtak: fail' in body and 'takserver' not in body
    assert 'Guard Dog: CloudTAK restarted on test-box' in body
    assert 'Update drill' in body and 'ended 10 min ago' in body
    assert box._gd_quiet_review_once(t0 + SETTLE + 60) == 'none'


def test_a_new_fault_after_the_close_is_not_blamed_on_the_window(box):
    box.health['cloudtak'] = 'fail'
    box._gd_quiet_hold('x')
    t0 = time.time()
    box._gd_quiet_review_once(t0)
    box.health['cloudtak'] = 'ok'
    box.health['takserver'] = 'fail'          # not held: its own watcher reports it
    assert box._gd_quiet_review_once(t0 + SETTLE + 1) == 'clear'
    assert box.sent == []


def test_reopening_while_settling_restarts_the_settle(box):
    box.health['cloudtak'] = 'fail'
    box._gd_quiet_hold('first')
    t0 = time.time()
    assert box._gd_quiet_review_once(t0) == 'settling'
    box.window(-10, 600)                      # next T&E round starts
    assert box._gd_quiet_review_once() == 'open'
    assert 'closed_at' not in box._gd_quiet_held_load()
    box.marker.unlink()
    assert box._gd_quiet_review_once(t0 + SETTLE + 1) == 'settling'   # a fresh first look


def _settled(box):
    t0 = time.time()
    first = box._gd_quiet_review_once(t0)
    return first if first != 'settling' else box._gd_quiet_review_once(t0 + SETTLE + 1)


def test_close_out_respects_the_operator_pause(box):
    box.health['cloudtak'] = 'fail'
    box.paused = True
    box._gd_quiet_hold('x')
    assert _settled(box) == 'not-sent'
    assert box.sent == []


def test_close_out_without_a_recipient_sends_nothing(tmp_path):
    b = Console(tmp_path, health={'cloudtak': 'fail'}, recipient='')
    b._gd_quiet_hold('x')
    assert _settled(b) == 'not-sent' and b.sent == []


def test_a_hold_recorded_during_the_review_is_kept(box):
    box.health['cloudtak'] = 'fail'
    box._gd_quiet_hold('first')
    t0 = time.time()
    box._gd_quiet_review_once(t0)
    real_refresh = box.ns['_guarddog_refresh_page_cache']

    def _refresh_and_new_hold():
        real_refresh()
        box._gd_quiet_hold('second, from the next window')
    box.ns['_guarddog_refresh_page_cache'] = _refresh_and_new_hold
    box._gd_quiet_review_once(t0 + SETTLE + 1)
    left = box._gd_quiet_held_load()['held']
    assert [h['subject'] for h in left] == ['second, from the next window']


def test_held_file_is_private_and_bounded(box):
    box.window(-60, 600)
    for i in range(80):
        box._gd_quiet_hold(f'alert {i}')
    p = pathlib.Path(box._gd_quiet_held_path())
    assert oct(p.stat().st_mode & 0o777) == '0o600'
    held = box._gd_quiet_held_load()['held']
    assert len(held) == 50 and held[-1]['subject'] == 'alert 79'


# ── the send helpers hold instead of sending ──────────────────────────────────

def _relay(box, smtp_calls):
    ns = dict(box.ns)
    ns.update({
        '_gd_alerts_pause_state': lambda s=None: (False, ''),
        '_safe_alert_emails': lambda a: [x for x in (a or '').split(',') if x],
        'load_settings': lambda: {'email_relay': {}},
    })

    class _SMTP:
        def __init__(self, *a, **k):
            smtp_calls.append('connect')

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def sendmail(self, *a):
            smtp_calls.append('send')
    import smtplib
    orig = smtplib.SMTP
    smtplib.SMTP = _SMTP
    try:
        exec(compile(_fn('_guarddog_send_alert_email_via_relay'), 'app.py', 'exec'), ns)
        return ns, orig
    except Exception:
        smtplib.SMTP = orig
        raise


def test_relay_holds_inside_a_window_and_sends_outside(box):
    import smtplib
    calls = []
    ns, orig = _relay(box, calls)
    try:
        box.window(-60, 600)
        assert ns['_guarddog_send_alert_email_via_relay']('a@b.co', 'S1', 'b') is False
        assert calls == []
        assert [h['subject'] for h in box._gd_quiet_held_load()['held']] == ['S1']
        # The Test button (force=True) is never held — a silent test looks like a broken relay.
        assert ns['_guarddog_send_alert_email_via_relay']('a@b.co', 'T', 'b', force=True) is True
        box.marker.unlink()
        assert ns['_guarddog_send_alert_email_via_relay']('a@b.co', 'S2', 'b') is True
        assert calls.count('send') == 2
    finally:
        smtplib.SMTP = orig


def test_sms_is_held_too_without_a_second_record():
    src = _fn('_guarddog_send_sms_now')
    i_pause = src.index('_gd_alerts_pause_state()')
    i_quiet = src.index('_gd_quiet_state()')
    i_send = src.index("sms.get('provider') == 'twilio'")
    assert i_pause < i_quiet < i_send
    assert "'held': True" in src and '_gd_quiet_hold' not in src


def test_route_reports_held_separately_from_suppressed():
    src = _fn('guarddog_send_alert_email')
    assert "'held': True" in src
    assert re.search(r"held = _gd_quiet_state\(\)\[0\] and not _gd_alerts_pause_state\(\)\[0\]", src)


def test_update_notices_are_deferred_not_marked_sent():
    src = _fn('_update_notify_check_once')
    i_quiet = src.index('_gd_quiet_state()')
    assert i_quiet < src.index('_update_notify_state_load()')
    assert "'quiet_until'" in src
    loop = _fn('_update_notify_loop')
    assert "r.get('quiet_until')" in loop


# ── send-alert-email.sh: held is NOT delivered ────────────────────────────────

def _run_send(tmp_path, reply, code='200'):
    bin_ = tmp_path / 'bin'
    bin_.mkdir(exist_ok=True)
    (tmp_path / 'reply.json').write_text(reply)
    (bin_ / 'curl').write_text(
        '#!/bin/bash\nout=""\nwhile [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; esac; shift; done\n'
        f'cat {tmp_path / "reply.json"} > "$out"\nprintf %s {code}\n')
    log = tmp_path / 'logger.out'
    (bin_ / 'logger').write_text(f'#!/bin/bash\necho "$@" >> {log}\n')
    for f in bin_.iterdir():
        f.chmod(0o755)
    r = subprocess.run(['bash', str(GD / 'send-alert-email.sh'), 'Guard Dog: CloudTAK restarted on x', ''],
                       input='body', capture_output=True, text=True,
                       env={**os.environ, 'PATH': f'{bin_}:{os.environ["PATH"]}'})
    return r.returncode, log.read_text() if log.exists() else ''


@pytest.mark.parametrize('reply', [
    {'success': True, 'suppressed': True, 'held': True, 'reason': 'quiet window'},
])
@pytest.mark.parametrize('compact', [True, False])
def test_held_reply_exits_3_so_the_episode_stays_open(tmp_path, reply, compact):
    body = json.dumps(reply, separators=(',', ':') if compact else (', ', ': '))
    rc, log = _run_send(tmp_path, body)
    assert rc == 3
    assert 'HELD by Guard Dog quiet window' in log and 'SUPPRESSED' not in log


def test_plain_suppressed_still_exits_0(tmp_path):
    rc, log = _run_send(tmp_path, json.dumps({'success': True, 'suppressed': True}))
    assert rc == 0 and 'SUPPRESSED' in log


def test_delivered_still_exits_0(tmp_path):
    rc, log = _run_send(tmp_path, json.dumps({'success': True, 'suppressed': False}))
    assert rc == 0 and 'sent:' in log


# ── gd-quiet.sh writes what the console reads ─────────────────────────────────

def _quiet_sh(tmp_path, *args, uid='0'):
    bin_ = tmp_path / 'qbin'
    bin_.mkdir(exist_ok=True)
    (bin_ / 'id').write_text(f'#!/bin/bash\necho {uid}\n')
    (bin_ / 'logger').write_text('#!/bin/bash\nexit 0\n')
    for f in bin_.iterdir():
        f.chmod(0o755)
    marker = tmp_path / 'state' / 'quiet_window'
    script = tmp_path / 'gd-quiet.sh'
    script.write_text(QUIET_SH.replace('/var/lib/takguard/quiet_window', str(marker))
                      .replace('/var/log/takguard', str(tmp_path / 'log')))
    r = subprocess.run(['bash', str(script), *args], capture_output=True, text=True,
                       env={**os.environ, 'PATH': f'{bin_}:{os.environ["PATH"]}'})
    return r, marker


def test_gd_quiet_on_status_off_round_trip(tmp_path):
    r, marker = _quiet_sh(tmp_path, 'on', '90', 'T&E', 'ops', '#220')
    assert r.returncode == 0, r.stderr
    assert oct(marker.stat().st_mode & 0o777) == '0o644'
    (tmp_path / 'c').mkdir()
    b = Console(tmp_path / 'c')
    b.ns['GD_QUIET_MARKER'] = str(marker)
    on, until, why = b._gd_quiet_state()
    assert on and why == 'T&E ops #220'
    assert abs(until - (time.time() + 90 * 60)) < 10
    r, _ = _quiet_sh(tmp_path, 'status')
    assert 'quiet window on' in r.stdout and 'T&E ops #220' in r.stdout
    r, _ = _quiet_sh(tmp_path, 'off')
    assert r.returncode == 0 and not marker.exists()
    assert b._gd_quiet_state()[0] is False


@pytest.mark.parametrize('minutes', ['0', '241', 'abc', '-5', ''])
def test_gd_quiet_refuses_bad_durations(tmp_path, minutes):
    r, marker = _quiet_sh(tmp_path, 'on', minutes, 'x')
    assert r.returncode == 2 and not marker.exists()


def test_gd_quiet_is_root_only(tmp_path):
    r, marker = _quiet_sh(tmp_path, 'on', '30', 'x', uid='1000')
    assert r.returncode == 1 and not marker.exists()


def test_gd_quiet_strips_control_characters_from_the_reason(tmp_path):
    r, marker = _quiet_sh(tmp_path, 'on', '5', 'a\nb\x07c')
    assert r.returncode == 0
    assert marker.read_text().count('\n') == 1
    assert marker.read_text().split(None, 2)[2].strip() == 'abc'


# ── the three copies of each number agree ─────────────────────────────────────

def test_script_and_console_agree_on_path_and_cap():
    assert re.search(r'^MARKER="/var/lib/takguard/quiet_window"$', QUIET_SH, re.M)
    assert _const('GD_QUIET_MARKER') == '/var/lib/takguard/quiet_window'
    cap = int(re.search(r'^MAX_MIN=(\d+)$', QUIET_SH, re.M).group(1))
    assert cap * 60 == _const('GD_QUIET_MAX_S')


def test_update_lock_and_authentik_marker_match_their_owners():
    upd = _fn('update_apply')
    assert f"_update_lock = '{_const('_GD_QUIET_UPDATE_LOCK')}'" in upd
    assert f"_update_lock_ttl_s = {_const('_GD_QUIET_UPDATE_LOCK_TTL_S')}" in upd
    assert _const('_GD_QUIET_AK_MARKER') == _const('_GD_AUTHENTIK_UPDATE_MARKER')
    assert _const('_GD_QUIET_AK_MAX_S') == _const('_GD_AUTHENTIK_UPDATE_MAX_S')


def test_gd_quiet_is_deployed_with_guard_dog():
    assert "'gd-quiet.sh'," in APP
    # the startup sync copies every *.sh in scripts/guarddog, so existing boxes get it on update
    assert (GD / 'gd-quiet.sh').exists()
