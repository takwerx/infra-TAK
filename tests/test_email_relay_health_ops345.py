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
"""A box whose mail relay cannot deliver says so, loudly, in plain words (ops #345).

Postfix takes mail on localhost:25 even when the smarthost refuses it, so a rejected login
(one customer: 1,378 stuck messages after Google refused it) never failed anywhere visible
and Guard Dog's update and security emails silently never arrived. The queue and its
deferral reasons are read with `postqueue -p`. Functions are cut out of app.py.
"""

import pathlib
import re
import time
import types

import jinja2

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


CONSTS = APP[APP.index('EMAIL_RELAY_STUCK_MIN ='):APP.index('def _parse_postqueue')]

AUTH = ('(SASL authentication failed; server smtp.gmail.com[142.250.1.109] said: '
        '535-5.7.8 Username and Password not accepted. For more information, go to)')
GMAIL_Q = ('-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------\n'
           'A1B2C3D4E5*   1203 Tue Oct 27 07:37:01  noreply@tak.example.com\n'
           + AUTH + '\n'
           '                                         ops@example.com\n\n'
           'F6A7B8C9D0    1203 Tue Oct 27 08:47:01  noreply@tak.example.com\n'
           + AUTH + '\n'
           '                                         ops@example.com\n\n'
           '-- 2 Kbytes in 2 Requests.\n')
OFFLINE_Q = ''.join(
    f'ABCDE{i:05d}   900 Tue Oct 27 07:37:01  noreply@tak.example.com\n'
    '(connect to smtp.gmail.com[142.250.1.109]:587: Connection timed out)\n'
    '                                         ops@example.com\n\n' for i in range(7)
) + '-- 6 Kbytes in 7 Requests.\n'


def _ns(postfix='active', queue='Mail queue is empty\n', relay=None, rc=0):
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        return types.SimpleNamespace(returncode=rc, stdout=queue, stderr='')
    n = {
        're': re, 'time': time, 'subprocess': types.SimpleNamespace(run=run),
        'load_settings': lambda: {'email_relay': relay if relay is not None else
                                  {'relay_host': 'smtp.gmail.com', 'smtp_user': 'u@gmail.com'}},
        '_diag_cmd': lambda argv, **k: postfix,
        'print': lambda *a, **k: None,
    }
    exec(CONSTS, n)
    for f in ('_parse_postqueue', '_email_relay_problem', '_email_relay_health'):
        exec(_cut(f), n)
    return n, calls


def test_parse_postqueue_counts_and_reasons():
    n, _ = _ns()
    count, reasons = n['_parse_postqueue'](GMAIL_Q)
    assert count == 2 and len(reasons) == 2 and 'SASL authentication failed' in reasons[0]
    assert n['_parse_postqueue']('Mail queue is empty\n') == (0, [])
    assert n['_parse_postqueue']('')[0] == 0
    assert n['_parse_postqueue'](OFFLINE_Q)[0] == 7


def test_rejected_login_is_flagged_with_the_fix_in_plain_words():
    n, _ = _ns(queue=GMAIL_Q)
    h = n['_email_relay_health'](force=True)
    assert h['ok'] is False and h['kind'] == 'login' and h['queued'] == 2
    assert 'rejecting' in h['headline']
    assert '2 messages are stuck' in h['detail'] and 'Username and Password not accepted' in h['detail']
    assert 'Switch Provider' in h['fix'] and 'Email Relay page' in h['fix']


def test_one_stuck_message_with_a_rejected_login_is_enough():
    n, _ = _ns(queue=GMAIL_Q.split('F6A7B8C9D0')[0] + '-- 1 Kbytes in 1 Request.\n')
    h = n['_email_relay_health'](force=True)
    assert h['kind'] == 'login' and '1 message is stuck' in h['detail']


def test_unreachable_relay_with_a_growing_queue_is_flagged():
    n, _ = _ns(queue=OFFLINE_Q)
    h = n['_email_relay_health'](force=True)
    assert h['ok'] is False and h['kind'] == 'unreachable' and h['queued'] == 7
    assert 'cannot reach' in h['headline'] and 'Retry stuck mail' in h['fix']


def test_a_few_slow_messages_are_not_an_alarm():
    q = OFFLINE_Q.replace('7 Requests', '3 Requests')
    n, _ = _ns(queue=q)
    assert n['_email_relay_health'](force=True)['ok'] is True


def test_empty_queue_and_unconfigured_relay_are_quiet():
    n, calls = _ns()
    assert n['_email_relay_health'](force=True)['ok'] is True
    n, calls = _ns(relay={})
    h = n['_email_relay_health'](force=True)
    assert h == {'configured': False, 'ok': True, 'queued': 0} and calls == []


def test_stopped_postfix_is_flagged_without_reading_the_queue():
    n, calls = _ns(postfix='inactive')
    h = n['_email_relay_health'](force=True)
    assert h['ok'] is False and h['kind'] == 'stopped' and 'Start' in h['fix'] and calls == []


def test_fixed_login_clears_the_flag():
    n, _ = _ns(queue=GMAIL_Q)
    assert n['_email_relay_health'](force=True)['ok'] is False
    n['subprocess'] = types.SimpleNamespace(run=lambda a, **k: types.SimpleNamespace(
        returncode=0, stdout='Mail queue is empty\n', stderr=''))
    assert n['_email_relay_health'](force=True)['ok'] is True


def test_a_failed_look_does_not_cry_wolf_or_forget_the_last_answer():
    n, _ = _ns(queue=GMAIL_Q)
    assert n['_email_relay_health'](force=True)['ok'] is False
    n['subprocess'] = types.SimpleNamespace(run=lambda a, **k: types.SimpleNamespace(
        returncode=1, stdout='', stderr='postqueue: fatal: Queue report unavailable'))
    assert n['_email_relay_health'](force=True)['kind'] == 'login'
    n2, _ = _ns(queue='', rc=1)
    assert n2['_email_relay_health'](force=True)['ok'] is True


def test_result_is_cached_for_the_polling_banner():
    n, calls = _ns(queue=GMAIL_Q)
    n['_email_relay_health'](force=True)
    n['_email_relay_health']()
    assert len(calls) == 1


def test_banner_is_on_console_guarddog_and_email_relay_pages_and_renders():
    for page in ('console', 'guarddog', 'email_relay'):
        t = (REPO / 'templates' / f'{page}.html').read_text(encoding='utf-8')
        assert "import relay_health_banner" in t and '{{ relay_health_banner() }}' in t
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(REPO / 'templates')), autoescape=True)
    html = env.from_string("{% from '_relay_health_banner.html' import relay_health_banner %}"
                           "{{ relay_health_banner() }}").render()
    assert 'id="relay-health-banner"' in html and '/api/system/email-relay-health' in html
    assert "display:none" in html.split('id="relay-health-banner"')[1][:60]


def test_routes_exist_and_need_login():
    assert re.search(r"@app\.route\('/api/system/email-relay-health'\)\n@login_required", APP)
    assert re.search(r"@app\.route\('/api/emailrelay/retry-queue', methods=\['POST'\]\)\n@login_required", APP)


def test_deploy_flushes_the_queue_after_restarting_postfix():
    src = (REPO / 'modules' / 'emailrelay.py').read_text(encoding='utf-8')
    assert src.index("'systemctl', 'restart', 'postfix'") < src.index("['postqueue', '-f']")
