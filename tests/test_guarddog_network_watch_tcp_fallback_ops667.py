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
"""Guard Dog network watcher falls back to TCP when ping is blocked (ops #667, GH #474).

Field: Azure blocks outbound ICMP by default. A box there has working DNS, TCP and
HTTPS, yet tak-network-watch.sh (ping only) failed both pings every minute and sent
"Server cannot reach the internet" every hour; one box counted 215072 failures. The
console's own network monitor already had the TCP fallback (v0.9.57), so its card was
green while the shell watcher kept emailing.

The REAL script runs here with its absolute paths pointed into a sandbox. `ping` and
`timeout` (the TCP probe's wrapper) are stubbed: ping always fails unless PING_UP is
set, and the TCP probe succeeds only for the host:port pairs listed in TCP_UP. Every
TCP probe is logged to tcp_calls so a test can prove the ping fast path never reaches it.
"""

import pathlib
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-network-watch.sh').read_text()

PING = '#!/bin/sh\n[ -n "$PING_UP" ]\n'
# `timeout 4 bash -c "exec 3<>/dev/tcp/HOST/PORT"` -> succeed if HOST:PORT is in $TCP_UP.
TIMEOUT = '''#!/bin/sh
hp=$(echo "$4" | sed 's#.*/dev/tcp/##; s#/#:#')
echo "$hp" >> "$TCP_CALLS"
case " $TCP_UP " in *" $hp "*) exit 0 ;; esac
exit 1
'''


def make_box(tmp_path, script_text=WATCH):
    gd, state, stubs = tmp_path / 'gd', tmp_path / 'state', tmp_path / 'bin'
    for d in (gd, state, stubs):
        d.mkdir()
    (gd / 'server_identifier').write_text('box\n')
    alert = gd / 'send-alert-email.sh'
    alert.write_text('#!/bin/sh\necho "$1" >> %s\ncat >> %s\n'
                     % (tmp_path / 'alerts', tmp_path / 'bodies'))
    (stubs / 'ping').write_text(PING)
    (stubs / 'timeout').write_text(TIMEOUT)
    for f in list(stubs.iterdir()) + [alert]:
        f.chmod(0o755)
    script = (script_text.replace('/opt/tak-guarddog/', str(gd) + '/')
                         .replace('/var/lib/takguard', str(state))
                         .replace('/var/log/takguard', str(tmp_path / 'log')))
    assert '/var/lib/takguard' not in script and '/opt/tak-guarddog' not in script
    sp = tmp_path / 'watch.sh'
    sp.write_text(script)

    def run(ping=False, tcp=()):
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs,
               'TCP_UP': ' '.join(tcp), 'TCP_CALLS': str(tmp_path / 'tcp_calls')}
        if ping:
            env['PING_UP'] = '1'
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True,
                           timeout=60, env=env)
        assert r.returncode == 0, r.stderr

    def read(name):
        p = tmp_path / name
        return p.read_text() if p.exists() else ''

    run.state, run.read = state, read
    return run


def test_icmp_blocked_but_tcp_works_sends_nothing(tmp_path):
    box = make_box(tmp_path)
    for _ in range(4):
        box(ping=False, tcp=['1.1.1.1:443', '8.8.8.8:53'])
    assert box.read('alerts') == ''
    assert not (box.state / 'network_fail_count').exists()
    assert not (box.state / 'network_alert_sent').exists()


def test_one_tcp_target_is_enough(tmp_path):
    for name, up in (('cf', ['1.1.1.1:443']), ('g', ['8.8.8.8:53'])):
        (tmp_path / name).mkdir()
        box = make_box(tmp_path / name)
        for _ in range(4):
            box(ping=False, tcp=up)
        assert box.read('alerts') == ''
        assert not (box.state / 'network_fail_count').exists()


def test_real_outage_still_alerts_after_three_runs(tmp_path):
    box = make_box(tmp_path)
    box(ping=False, tcp=[])
    box(ping=False, tcp=[])
    assert box.read('alerts') == ''
    assert (box.state / 'network_fail_count').read_text().strip() == '2'
    box(ping=False, tcp=[])
    assert box.read('alerts').startswith('TAK Server Network Alert on box')
    body = box.read('bodies')
    assert 'Server cannot reach the internet' in body
    assert 'Cloudflare DNS (1.1.1.1): ping FAILED, TCP port 443 FAILED' in body
    assert 'Google DNS (8.8.8.8): ping FAILED, TCP port 53 FAILED' in body
    # A ping block alone no longer explains this alert.
    assert 'Firewall blocking ICMP' not in body
    assert 'both ping and TCP failed' in body


def test_ping_fast_path_never_tries_tcp(tmp_path):
    box = make_box(tmp_path)
    box(ping=True, tcp=[])
    assert box.read('tcp_calls') == ''
    assert box.read('alerts') == ''


def test_first_good_tcp_check_clears_a_stale_failure_count(tmp_path):
    """The box in the report held a count of 215072 and an old alert-sent marker."""
    box = make_box(tmp_path)
    (box.state / 'network_fail_count').write_text('215072\n')
    (box.state / 'network_alert_sent').write_text('')
    box(ping=False, tcp=['1.1.1.1:443'])
    assert not (box.state / 'network_fail_count').exists()
    assert not (box.state / 'network_alert_sent').exists()
    assert box.read('alerts') == ''
