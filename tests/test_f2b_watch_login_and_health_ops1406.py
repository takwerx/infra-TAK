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
"""Guard Dog mails for a login that worked after failed guesses, and for fail2ban failing
(ops #1406, follow-up of #1395).

`infratak-f2b-notify --watch` runs from a timer. It mails once per cause per day and at most
3 times a day per box, and never for routine bans or for fail2ban switched off on purpose.
The script runs from the shipped app.py text with its logs, state file, systemctl answers
and SMTP replaced.
"""

import ast
import datetime
import email
import json
import os
import pathlib
import re
import time
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (REPO / 'templates' / 'fail2ban.html').read_text(encoding='utf-8')


def _const(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError(f'{name} was renamed or removed')


def _text(raw):
    return email.message_from_string(raw).get_payload(decode=True).decode('utf-8')


def _subject(raw):
    return email.message_from_string(raw)['Subject']


def _iso_local(t):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(t))


def _utc(t):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(t))


class _Box:
    """One fake box: settings, logs, jail files, systemctl answers, state file, SMTP."""

    def __init__(self, tmp_path, settings=None):
        tmp_path.mkdir(parents=True, exist_ok=True)
        self.tmp = tmp_path
        self.sent = []
        self.smtp_down = False
        self.smtp_calls = 0
        self.ssh_log = ''
        self.enabled = 'enabled'
        self.active = 'active'
        self.status_rc = 0
        self.jail_list = 'sshd, authentik'
        self.uptime = 100000.0
        self.f2b_log = tmp_path / 'fail2ban.log'
        self.f2b_log.write_text('')
        self.jail_dir = tmp_path / 'jail.d'
        self.jail_dir.mkdir()
        self.quiet = tmp_path / 'quiet_window'
        base = {'guarddog_alert_email': 'owner@example.org', 'server_nickname': 'box1'}
        base.update(settings or {})
        self.settings_path = tmp_path / 'settings.json'
        self.settings_path.write_text(json.dumps(base))
        self.now = time.time()

    def jail(self, name, enabled='true', fname=None):
        (self.jail_dir / (fname or f'infratak-{name}.conf')).write_text(
            f'[{name}]\nenabled = {enabled}\nignoreip = 127.0.0.1/8 192.168.50.0/24\n')

    def ssh(self, kind, user, ip, ago, method='password', invalid=False):
        t = _utc(self.now - ago).replace(' ', 'T')
        if kind == 'fail':
            who = f'invalid user {user}' if invalid else user
            self.ssh_log += f'{t}.1+00:00 box sshd[1]: Failed {method} for {who} from {ip} port 5000 ssh2\n'
        else:
            self.ssh_log += f'{t}.1+00:00 box sshd[1]: Accepted {method} for {user} from {ip} port 5000 ssh2\n'

    def ssh_pam_fail(self, user, ip, ago, also_failed_line=False):
        stamp = _utc(self.now - ago).replace(' ', 'T') + '.1+00:00'
        self.ssh_log += f'{stamp} box sshd[1]: error: PAM: Authentication failure for {user} from {ip}\n'
        if also_failed_line:
            self.ssh_log += (f'{stamp} box sshd[1]: Failed keyboard-interactive/pam for {user} '
                             f'from {ip} port 5000 ssh2\n')

    def console(self, kind, ip, ago):
        txt = 'failed login' if kind == 'fail' else 'login ok'
        with open(self.tmp / 'console-auth.log', 'a') as f:
            f.write(f'{_utc(self.now - ago)} console: {txt} from {ip}\n')

    def authentik(self, kind, ip, ago, user='alice'):
        txt = 'login_failed' if kind == 'fail' else 'login ok'
        with open(self.tmp / 'authentik-logins.log', 'a') as f:
            f.write(f'{_utc(self.now - ago)} authentik: {txt} from {ip} user={user} pk={ago}{ip}\n')

    def f2b_error(self, ago, jail='sshd', action='ufw'):
        t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.now - ago))
        with open(self.f2b_log, 'a') as f:
            f.write(f"{t},123 fail2ban.actions        [1003]: ERROR   Failed to execute ban jail "
                    f"'{jail}' action '{action}' info 'ActionInfo()': Error banning 1.2.3.4\n")

    def run(self, argv=None):
        mod = types.ModuleType('infratak_f2b_notify')
        exec(compile(_const('_F2B_NOTIFY_SCRIPT'), 'infratak-f2b-notify', 'exec'), mod.__dict__)
        box = self

        class SMTP:
            def __init__(self, *a, **k):
                box.smtp_calls += 1

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def sendmail(self, frm, to, text):
                if box.smtp_down:
                    raise OSError('connection refused')
                box.sent.append((frm, to, text))

        def run_text(cmd, timeout=15):
            if cmd[:2] == ['systemctl', 'is-enabled']:
                return 0, box.enabled
            if cmd[:2] == ['systemctl', 'is-active']:
                return 0, box.active
            if cmd[0] == 'fail2ban-client':
                return box.status_rc, ('Status\n|- Number of jail:\t2\n`- Jail list:\t'
                                       + box.jail_list)
            return 1, ''

        mod.smtplib = types.SimpleNamespace(SMTP=SMTP)
        mod._find_settings = lambda: str(self.settings_path)
        mod.STATE_PATH = str(self.tmp / 'takguard' / 'state.json')
        mod.F2B_LOG = str(self.f2b_log)
        mod.JAIL_DIR = str(self.jail_dir)
        mod.QUIET_MARKER = str(self.quiet)
        mod._ssh_watch_text = lambda: self.ssh_log
        mod._run_text = run_text
        mod._uptime = lambda: self.uptime
        mod.time = types.SimpleNamespace(time=lambda: self.now, mktime=time.mktime,
                                         localtime=time.localtime, strptime=time.strptime,
                                         strftime=time.strftime, gmtime=time.gmtime)
        mod.sys = types.SimpleNamespace(argv=argv or ['x', '--watch'],
                                        stderr=open(os.devnull, 'w'),
                                        exit=lambda c=0: (_ for _ in ()).throw(SystemExit(c)))
        try:
            mod.main()
        except SystemExit:
            pass
        return mod

    def tick(self, minutes=5, runs=1):
        for _ in range(runs):
            self.now += minutes * 60
            self.run()


# ── proof tests ──────────────────────────────────────────────────────────────

def test_ssh_login_that_worked_after_failed_guesses_sends_one_email(tmp_path):
    box = _Box(tmp_path)
    for i in range(4):
        box.ssh('fail', 'jsmith', '198.51.100.9', 300 - i * 10)
    box.ssh('ok', 'jsmith', '198.51.100.9', 200)
    box.run()
    assert len(box.sent) == 1
    text = _text(box.sent[0][2])
    assert '198.51.100.9' in text and 'jsmith' in text and '4 failed guesses' in text
    assert 'SSH' in _subject(box.sent[0][2])
    assert box.sent[0][1] == ['owner@example.org']
    box.tick(runs=3)                                   # same cause, same day: no second mail
    assert len(box.sent) == 1


def test_pam_keyboard_interactive_failures_count_once_each(tmp_path):
    """Seen on a real Ubuntu 22.04 box: a PAM login that fails logs only
    `error: PAM: Authentication failure for USER from IP`."""
    box = _Box(tmp_path)
    for i in range(3):
        box.ssh_pam_fail('jsmith', '198.51.100.9', 300 - i * 10)
    box.ssh('ok', 'jsmith', '198.51.100.9', 200, method='keyboard-interactive/pam')
    box.run()
    assert len(box.sent) == 1 and '3 failed guesses' in _text(box.sent[0][2])
    # the same failure written twice (PAM line and Failed line) is ONE failure: 2 of them are not enough
    twice = _Box(tmp_path / 'twice')
    for i in range(2):
        twice.ssh_pam_fail('jsmith', '198.51.100.9', 300 - i * 10, also_failed_line=True)
    twice.ssh('ok', 'jsmith', '198.51.100.9', 200, method='keyboard-interactive/pam')
    twice.run()
    assert twice.sent == []


def test_an_empty_auth_log_does_not_hide_the_real_ssh_log(tmp_path):
    """Found on a real Rocky 9 box: an empty /var/log/auth.log (left by an operator or a script)
    came first in the list, so the watch read nothing and never saw /var/log/secure."""
    mod = types.ModuleType('infratak_f2b_notify')
    exec(compile(_const('_F2B_NOTIFY_SCRIPT'), 'infratak-f2b-notify', 'exec'), mod.__dict__)
    auth, secure = tmp_path / 'auth.log', tmp_path / 'secure'
    auth.write_text('')
    secure.write_text('Nov 27 20:10:08 h sshd[1]: Accepted password for bob from 198.51.100.4 port 1 ssh2\n')
    real_exists = os.path.exists
    paths = {'/var/log/auth.log': str(auth), '/var/log/secure': str(secure)}
    real_getsize, real_open = os.path.getsize, open
    mod.os = types.SimpleNamespace(**{k: getattr(os, k) for k in dir(os) if not k.startswith('__')})
    mod.os.path = types.SimpleNamespace(exists=lambda p: real_exists(paths.get(p, p)),
                                        getsize=lambda p: real_getsize(paths.get(p, p)),
                                        join=os.path.join)
    mod.open = lambda p, *a, **k: real_open(paths.get(p, p), *a, **k)
    assert 'Accepted password for bob' in mod._ssh_watch_text()
    auth.write_text('Nov 27 20:11:00 h sshd[1]: Accepted password for amy from 198.51.100.5 port 1 ssh2\n')
    assert 'for amy' in mod._ssh_watch_text()          # a log with content still wins, as before


def test_console_and_authentik_logins_after_failures_each_send_one(tmp_path):
    box = _Box(tmp_path)
    for i in range(3):
        box.console('fail', '203.0.113.20', 120 - i)
        box.authentik('fail', '203.0.113.21', 120 - i)
    box.console('ok', '203.0.113.20', 60)
    box.authentik('ok', '203.0.113.21', 60)
    box.run()
    subjects = sorted(_subject(m[2]) for m in box.sent)
    assert len(box.sent) == 2, subjects
    assert any('console' in s for s in subjects) and any('Authentik' in s for s in subjects)


def test_stopped_fail2ban_sends_one_email_after_two_looks(tmp_path):
    box = _Box(tmp_path)
    box.active = 'failed'
    box.run()
    assert box.sent == [], 'one failing look is a restart, not a fault'
    box.tick()
    assert len(box.sent) == 1
    assert 'not running' in _subject(box.sent[0][2])
    box.tick(runs=5)
    assert len(box.sent) == 1, 'one mail per cause per day'


def test_50_routine_bans_and_failed_guesses_send_no_email(tmp_path):
    box = _Box(tmp_path)
    for i in range(50):
        ip = f'203.0.113.{i + 1}'
        for k in range(5):
            box.ssh('fail', ('root', 'admin', 'postgres')[k % 3], ip, 600 - k, invalid=k % 3 == 1)
        box.console('fail', ip, 500)
        box.authentik('fail', ip, 400)
        box.f2b_log.write_text(box.f2b_log.read_text() +
                               f'{time.strftime("%Y-%m-%d %H:%M:%S")},1 fail2ban.actions [1]: NOTICE  [sshd] Ban {ip}\n')
    box.run()
    box.tick(runs=3)
    assert box.sent == []


# ── what must NOT mail ───────────────────────────────────────────────────────

def test_too_few_failures_old_events_and_public_key_noise_send_nothing(tmp_path):
    box = _Box(tmp_path)
    box.ssh('fail', 'jsmith', '198.51.100.1', 300)
    box.ssh('fail', 'jsmith', '198.51.100.1', 290)
    box.ssh('ok', 'jsmith', '198.51.100.1', 200)             # only 2 failures
    for i in range(6):                                       # an agent trying keys, then a login
        box.ssh('fail', 'mary', '198.51.100.2', 300 - i, method='publickey')
    box.ssh('ok', 'mary', '198.51.100.2', 200)
    for i in range(4):                                       # 3 hours ago: not news
        box.ssh('fail', 'ann', '198.51.100.3', 11000 - i)
    box.ssh('ok', 'ann', '198.51.100.3', 10900)
    for i in range(4):                                       # failures 2 hours before the login
        box.ssh('fail', 'bob', '198.51.100.4', 7300 - i)
    box.ssh('ok', 'bob', '198.51.100.4', 100)
    box.run()
    assert box.sent == []


def test_failures_from_one_address_and_a_login_from_another_send_nothing(tmp_path):
    box = _Box(tmp_path)
    for i in range(5):
        box.ssh('fail', 'root', '198.51.100.7', 300 - i)
    box.ssh('ok', 'jsmith', '198.51.100.8', 100)
    box.run()
    assert box.sent == []


def test_the_operators_own_trusted_address_is_never_mailed(tmp_path):
    box = _Box(tmp_path)
    box.jail('sshd')                                          # ignoreip carries 192.168.50.0/24
    for i in range(4):
        box.ssh('fail', 'jsmith', '192.168.50.10', 300 - i)
    box.ssh('ok', 'jsmith', '192.168.50.10', 100)
    for i in range(4):
        box.console('fail', '127.0.0.1', 300 - i)
    box.console('ok', '127.0.0.1', 100)
    box.run()
    assert box.sent == []


def test_fail2ban_switched_off_on_purpose_or_not_installed_sends_nothing(tmp_path):
    for state in ('disabled', 'masked', 'not-found', ''):
        box = _Box(tmp_path / state.replace('-', '_') if state else tmp_path / 'blank')
        box.enabled = state
        box.active = 'inactive'
        box.jail('sshd')
        box.tick(runs=6)
        assert box.sent == [], state


def test_a_restart_or_a_booting_box_is_not_a_fault(tmp_path):
    box = _Box(tmp_path)
    box.active = 'activating'
    box.run()
    box.active = 'active'
    box.tick()                                               # back: the count starts over
    box.active = 'activating'
    box.tick()
    assert box.sent == []
    booting = _Box(tmp_path / 'boot')
    booting.uptime = 120
    booting.active = 'failed'
    booting.tick(runs=4)
    assert booting.sent == []


def test_a_jail_that_is_set_up_but_not_running_sends_one_email(tmp_path):
    box = _Box(tmp_path)
    box.jail('sshd')
    box.jail('authentik')
    box.jail('takserver')
    box.jail('mediamtx', fname='infratak-mediamtx.conf.parked-missing-log')   # parked: off
    box.jail('console', enabled='false')                                       # off on purpose
    box.jail_list = 'sshd, authentik'
    box.run()
    assert box.sent == []
    box.tick()
    assert len(box.sent) == 1
    assert 'takserver' in _subject(box.sent[0][2])
    assert 'mediamtx' not in _text(box.sent[0][2]) and 'console' not in _subject(box.sent[0][2])


def test_all_jails_running_and_a_dead_client_answer(tmp_path):
    box = _Box(tmp_path)
    box.jail('sshd')
    box.jail('authentik')
    box.tick(runs=4)
    assert box.sent == []
    box.status_rc = 1                                        # service active, client gets no answer
    box.tick(runs=2)
    assert len(box.sent) == 1 and 'not answering' in _subject(box.sent[0][2])


def test_a_failing_ban_action_sends_one_email_only_for_repeated_recent_errors(tmp_path):
    box = _Box(tmp_path)
    box.f2b_error(600)
    box.tick(runs=3)
    assert box.sent == [], 'one error is not a pattern'
    box = _Box(tmp_path / 'old')
    for i in range(5):
        box.f2b_error(7200 + i)                               # two hours ago
    box.tick(runs=3)
    assert box.sent == []
    box = _Box(tmp_path / 'now')
    box.f2b_error(300)
    box.f2b_error(200)
    box.tick(runs=2)
    assert len(box.sent) == 1
    assert 'ban action failing' in _subject(box.sent[0][2]) and 'sshd / ufw' in _subject(box.sent[0][2])


def test_pause_quiet_window_and_missing_address_hold_every_mail(tmp_path):
    for name, settings in (('paused', {'guarddog_alerts_paused': True}),
                           ('noaddr', {'guarddog_alert_email': ''})):
        box = _Box(tmp_path / name, settings)
        box.active = 'failed'
        for i in range(4):
            box.ssh('fail', 'jsmith', '198.51.100.9', 300 - i)
        box.ssh('ok', 'jsmith', '198.51.100.9', 100)
        box.tick(runs=3)
        assert box.sent == [], name
    box = _Box(tmp_path / 'quiet')
    box.active = 'failed'
    box.quiet.write_text(f'{int(box.now)} {int(box.now) + 3600} Update Now\n')
    box.tick(runs=3)
    assert box.sent == []
    box.quiet.unlink()                                       # the window closes: still failing, so one mail
    box.tick()
    assert len(box.sent) == 1


def test_no_mail_relay_does_not_crash_and_does_not_use_up_the_day(tmp_path):
    box = _Box(tmp_path)
    box.smtp_down = True
    for i in range(4):
        box.ssh('fail', 'jsmith', '198.51.100.9', 300 - i)
    box.ssh('ok', 'jsmith', '198.51.100.9', 100)
    box.run()
    assert box.sent == [] and box.smtp_calls == 1
    box.tick(minutes=5, runs=3)
    assert box.smtp_calls == 1, 'backs off for an hour instead of trying every 5 minutes'
    box.smtp_down = False
    box.tick(minutes=62)
    assert len(box.sent) == 0, 'the login is older than 30 minutes by now: it is not news'
    box2 = _Box(tmp_path / 'b')
    box2.smtp_down = True
    box2.active = 'failed'
    box2.tick(runs=2)
    box2.smtp_down = False
    box2.tick(minutes=62)
    assert len(box2.sent) == 1, 'the failure is still there, and the day slot was not used up'


def test_three_a_day_cap_is_shared_and_health_comes_first(tmp_path):
    box = _Box(tmp_path)
    for n in range(5):
        ip = f'198.51.100.{20 + n}'
        for i in range(3):
            box.ssh('fail', 'jsmith', ip, 400 - i)
        box.ssh('ok', 'jsmith', ip, 100)
    box.run()
    assert len(box.sent) == 3
    box.active = 'failed'
    box.tick(runs=3)
    assert len(box.sent) == 3, 'cap reached for the day'


def test_a_damaged_or_newer_state_file_is_read_tolerantly(tmp_path):
    box = _Box(tmp_path)
    (tmp_path / 'takguard').mkdir()
    (tmp_path / 'takguard' / 'state.json').write_text('{not json')
    box.active = 'failed'
    box.tick(runs=2)
    assert len(box.sent) == 1
    st = json.loads((tmp_path / 'takguard' / 'state.json').read_text())
    st['written_by_a_newer_version'] = {'x': 1}
    (tmp_path / 'takguard' / 'state.json').write_text(json.dumps(st))
    box.tick()
    assert json.loads((tmp_path / 'takguard' / 'state.json').read_text())['written_by_a_newer_version'] == {'x': 1}


def test_syslog_style_stamps_and_user_text_in_subjects(tmp_path):
    box = _Box(tmp_path)
    t = time.localtime(box.now - 300)
    stamp = time.strftime('%b %e %H:%M:%S', t)
    lines = ''.join(f'{stamp} box sshd[1]: Failed password for jsmith from 198.51.100.9 port 22 ssh2\n'
                    for _ in range(3))
    lines += f'{stamp} box sshd[1]: Accepted password for jsmith from 198.51.100.9 port 22 ssh2\n'
    box.ssh_log = lines                                      # Rocky /var/log/secure format
    box.run()
    assert len(box.sent) == 1
    hostile = _Box(tmp_path / 'h')
    for i in range(3):
        hostile.authentik('fail', '203.0.113.9', 300 - i)
    hostile.authentik('ok', '203.0.113.9', 100, user='x\nBcc:evil@example.com')
    hostile.run()
    raw = hostile.sent[0][2]
    assert 'Bcc:' not in raw.split('\n\n')[0]


# ── the same script still does its #1395 job ─────────────────────────────────

def test_ban_mode_is_unchanged_a_ban_for_a_bot_still_sends_nothing(tmp_path):
    box = _Box(tmp_path)
    box.run(argv=['x', '203.0.113.99', 'authentik'])
    assert box.sent == []


# ── the pieces around it ─────────────────────────────────────────────────────

def test_timer_units_run_the_script_every_5_minutes_after_10_minutes_of_uptime():
    svc, tmr = _const('_F2B_WATCH_SERVICE'), _const('_F2B_WATCH_TIMER')
    assert 'ExecStart=/usr/bin/env python3 /usr/local/sbin/infratak-f2b-notify --watch' in svc
    assert 'Type=oneshot' in svc
    assert 'OnBootSec=10min' in tmr and 'OnUnitActiveSec=5min' in tmr
    assert 'WantedBy=timers.target' in tmr and 'Unit=infratak-f2b-watch.service' in tmr
    assert ' ;' not in svc and ' #' not in svc


def test_the_timer_is_made_on_install_on_every_start_and_removed_on_uninstall():
    assert 'def _f2b_watch_ensure' in APP and 'def _startup_converge_f2b_watch' in APP
    hook = APP[APP.index('def _fail2ban_add_guarddog_hook'):]
    hook = hook[:hook.index('# Guard Dog\'s log line + the ban e-mail for the takserver jail')]
    assert '_f2b_watch_ensure()' in hook
    startup = APP[APP.index('_startup_converge_tak_banaction()\n        except'):]
    assert '_startup_converge_f2b_watch()' in startup[:900]
    unins = APP[APP.index('def fail2ban_uninstall_api'):]
    unins = unins[:unins.index('\n@app.route')]
    assert 'infratak-f2b-watch.timer' in unins and 'infratak-f2b-watch.service' in unins


def test_ensure_does_nothing_on_a_box_without_the_notifier_and_does_not_restart_fail2ban():
    fn = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == '_f2b_watch_ensure')
    src = ast.get_source_segment(APP, fn)
    assert "os.path.exists('/usr/local/sbin/infratak-f2b-notify')" in src
    assert 'fail2ban-client' not in src and "'restart'" not in src and "'reload'" not in src


def test_console_good_login_line_is_written_by_both_login_routes_and_the_jail_ignores_it():
    assert APP.count('_console_log_login_ok()') >= 3          # def + /login + /
    m = re.search(r'failregex = (\^\\\\s\*\(\?:\\\\S\+ \\\\S\+ \)\?console: failed login from <HOST>)',
                  APP)
    assert m, 'the console jail filter changed: check it still cannot match the new line'
    rx = re.compile(r'^\s*(?:\S+ \S+ )?console: failed login from (\S+)\s*$')
    assert not rx.match('2026-11-27 10:00:00 console: login ok from 1.2.3.4')
    assert rx.match('2026-11-27 10:00:00 console: failed login from 1.2.3.4')


def test_page_text_names_the_new_mails():
    assert 'worked right after 3 or more failed guesses' in TEMPLATE
    assert 'fail2ban itself stopped working' in TEMPLATE


# ── Authentik: the console copies the events the watch needs ────────────────

def _ak_namespace(tmp_path, monkeypatch, events):
    names = ('_ak_login_clean', '_ak_login_outside', '_ak_login_load_seen', '_ak_login_watch_once')
    ns = {'os': os, 're': re, 'json': json, 'time': time, 'datetime': datetime.datetime,
          'ipaddress': __import__('ipaddress'), 'print': print,
          'AK_LOGIN_LOG': str(tmp_path / 'authentik-logins.log'), 'AK_LOGIN_LOG_MAX': 1048576,
          'AK_LOGIN_LOOKBACK_S': 1800, 'AK_LOGIN_MAX_ADDRESSES': 10,
          '_AK_LOGIN_SEEN': set(), '_AK_LOGIN_SEEN_LOADED': False,
          'load_settings': lambda: {}, '_get_module_deployment_config': lambda s, k: {},
          '_get_authentik_env_value': lambda s, k: 'tok',
          '_get_authentik_api_url': lambda s: 'http://127.0.0.1:9090'}

    def fake_events(base, token, query):
        if query['action'] == 'login_failed':
            return events['fail']
        return [e for e in events['ok'] if e['client_ip'] == query['client_ip']]
    ns['_ak_login_events'] = fake_events
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name in names:
            exec(compile(ast.Module([n], []), 'app.py', 'exec'), ns)
    home = tmp_path / 'home'
    (home / 'authentik').mkdir(parents=True)
    (home / 'authentik' / 'docker-compose.yml').write_text('x')
    monkeypatch.setenv('HOME', str(home))
    return ns


def _ev(pk, ip, ago, now, user='alice', ctx_user=None):
    return {'pk': pk, 'client_ip': ip, 'user': {'username': user},
            'context': {'username': ctx_user or user},
            'created': time.strftime('%Y-%m-%dT%H:%M:%S.123456Z', time.gmtime(now - ago))}


def test_console_copies_outside_failures_and_good_logins_for_those_addresses_only(tmp_path, monkeypatch):
    now = time.time()
    fails = [_ev(f'f{i}', '45.33.32.5', 300 - i, now, ctx_user='alice') for i in range(3)]
    fails += [_ev('p1', '10.0.0.5', 200, now), _ev('p2', '172.18.0.4', 200, now)]   # LDAP outpost, containers
    fails += [_ev('old', '45.33.32.6', 7200, now)]
    oks = [_ev('o1', '45.33.32.5', 100, now), _ev('o2', '45.33.32.77', 100, now)]  # 2nd: no failures
    ns = _ak_namespace(tmp_path, monkeypatch, {'fail': fails, 'ok': oks})
    assert ns['_ak_login_watch_once'](now) == 4
    text = (tmp_path / 'authentik-logins.log').read_text()
    assert text.count('login_failed from 45.33.32.5') == 3
    assert 'login ok from 45.33.32.5 user=alice' in text
    assert '10.0.0.5' not in text and '172.18' not in text and '45.33.32.77' not in text
    assert '45.33.32.6' not in text
    assert ns['_ak_login_watch_once'](now) == 0, 'the same events are not copied twice'
    ns['_AK_LOGIN_SEEN'].clear()
    ns['_AK_LOGIN_SEEN_LOADED'] = False
    assert ns['_ak_login_watch_once'](now) == 0, 'nor after a console restart'


def test_copied_authentik_events_reach_the_watch_end_to_end(tmp_path, monkeypatch):
    now = time.time()
    fails = [_ev(f'f{i}', '45.33.32.5', 300 - i, now) for i in range(3)]
    ns = _ak_namespace(tmp_path, monkeypatch, {'fail': fails, 'ok': [_ev('o1', '45.33.32.5', 100, now)]})
    ns['_ak_login_watch_once'](now)
    box = _Box(tmp_path)
    box.run()
    assert len(box.sent) == 1 and 'Authentik' in _subject(box.sent[0][2])


def test_no_authentik_or_a_remote_one_copies_nothing(tmp_path, monkeypatch):
    ns = _ak_namespace(tmp_path, monkeypatch, {'fail': [], 'ok': []})
    os.remove(tmp_path / 'home' / 'authentik' / 'docker-compose.yml')
    assert ns['_ak_login_watch_once']() == 0
    (tmp_path / 'home' / 'authentik' / 'docker-compose.yml').write_text('x')
    ns['_get_module_deployment_config'] = lambda s, k: {'target_mode': 'remote'}
    assert ns['_ak_login_watch_once']() == 0
    ns['_get_module_deployment_config'] = lambda s, k: {}
    ns['_get_authentik_env_value'] = lambda s, k: None
    assert ns['_ak_login_watch_once']() == 0
    assert not (tmp_path / 'authentik-logins.log').exists()
