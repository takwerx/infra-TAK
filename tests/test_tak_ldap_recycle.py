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
"""TAK's clients get their LDAP groups back after an LDAP outage under a running TAK Server,
without a TAK restart where possible (ops #126, GH #189).

After v10.2.22 → v10.2.23 a field box (TAK 5.8) kept ATAK/CloudTAK connected with no CoT:
clients that connected while the outpost was down held empty groups until `systemctl restart
takserver`. A cert client's groups come from one LDAP lookup at connect and nothing repeats
it, so the fix re-authenticates named sessions and drops the ones still empty so the client
reconnects; TAK is restarted only if a client comes back empty again (or the CoreConfig
credential changed).

_tak_recycle_after_ldap_outage() and its helpers are cut out of app.py and run against a fake
box: docker, systemctl, ldapsearch, TAK's Marti API, the ports and the clock are stubbed.
"""

import datetime
import os
import re
import subprocess
import threading
import types
import urllib.parse

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(REPO, 'app.py'), encoding='utf-8') as _f:
    APP = _f.read()
SA_PASS = 'sa-secret-do-not-log'
T0 = 1_800_000_000.0          # fake "now" at the start of each test
BOOT = T0 - 400_000           # the box booted ~4.6 days earlier
HOUR = 3600
API = 'https://127.0.0.1:8443/Marti/api'
UAF = ('<UserAuthenticationFile><User identifier="admin" role="ROLE_ADMIN"/>'
       '<User identifier="cloudtak-svc-bootstrap" role="ROLE_ADMIN"/></UserAuthenticationFile>')


def _src(name):
    return re.search(r'^def %s\(.*?(?=^def |^# |^_[A-Z_]+ = |\Z)' % name, APP, re.S | re.M).group(0)


def _const(name):
    return int(re.search(r'^%s = (\d+)' % name, APP, re.M).group(1))


def _rfc3339(epoch):
    return datetime.datetime.utcfromtimestamp(int(epoch)).strftime('%Y-%m-%dT%H:%M:%S') + '.123456789Z'


def _ldif(groups):
    out = []
    for i in range(4):
        out.append(f'dn: cn=user{i},ou=users,dc=takldap')
        if i < groups:
            out.append('memberOf: cn=tak_OPS,ou=groups,dc=takldap')
        out.append('')
    return '\n'.join(out) + '\nresult: 0 Success\n'


def sess(n, cn, groups=('OPS',), username='same', client=None, unmapped=False):
    """One live 8089 connection the way /subscriptions/all shows it. `unmapped` = TAK could
    not match the cert to a user (its lookup failed): no DN and no username at all (test6)."""
    return {'subscriptionUid': f'tls:{n}', 'dn': None if unmapped else f'OU=TAK, O=PUBLIC SAFETY, CN={cn}',
            'username': None if unmapped else (cn if username == 'same' else username), 'callsign': cn.upper(),
            'clientUid': client if client is not None else f'ANDROID-{cn}', '_cn': cn,
            'groups': [{'name': g, 'direction': d} for g in groups for d in ('IN', 'OUT')]}


class Box:
    """A fake single box: TAK (native or container) with its live clients, the LDAP outpost,
    the clock. `ldap_users` is what LDAP says ({cn: number of tak_ groups}); `tak_ldap_ok`
    is whether TAK's OWN lookups work (False = TAK's LDAP path is broken); `dead_pool`
    lookups fail first (dead pooled connections, each discarded after its failure)."""

    def __init__(self, tak_start, ldap_start=None, container=False, ldap=lambda box: (0, 3),
                 settings=None, coreconfig=True, update_in_progress=False, restart_rc=0, tak_running=True,
                 subs=None, ldap_users=None, tak_ldap_ok=True, dead_pool=0, online=True, api_ok=True,
                 history=None):
        self.t = T0
        self.tak_start = tak_start
        self.ldap_start = ldap_start
        self.container = container
        self.ldap = ldap
        self.settings = settings if settings is not None else {}
        self.coreconfig = coreconfig
        self.update_in_progress = update_in_progress
        self.restart_rc = restart_rc
        self.tak_running = tak_running
        self.ports_up_at = 0.0
        self.subs = list(subs or [])
        self.ldap_users = dict(ldap_users or {})
        self.tak_ldap_ok = tak_ldap_ok
        self.dead_pool = dead_pool
        self.online = online
        self.api_ok = api_ok
        # TAK's client history: device uid → last username (every device seen with a user)
        self.history = history if history is not None else {'ANDROID-takdev-emu': 'takdev-emu',
                                                             'ANDROID-aj5cacor': 'aj5cacor'}
        self.reconnects = []           # (at, session) still to come
        self.next_uid = 100            # TAK numbers new connections upward
        self.calls, self.api, self.log = [], [], []

    # ── TAK's own LDAP lookup for a cert user (X509Authenticator) ──
    def _tak_lookup(self, cn):
        """None = the lookup failed (silently); [] = it worked, LDAP gives the user no groups
        (TAK still names the connection, with __ANON__ only)."""
        if self.dead_pool:
            self.dead_pool -= 1
            return None
        if not self.tak_ldap_ok:
            return None
        return ['OPS'] if self.ldap_users.get(cn, 0) else []

    def _materialize(self):
        for at, s in list(self.reconnects):
            if self.t >= at:
                self.reconnects.remove((at, s))
                self.subs.append(s)

    def marti(self, url, timeout=12, method='GET', json_body=None):
        self.api.append((method, url, json_body))
        if not self.api_ok:
            return None, 'curl_exit_7'
        if method == 'GET' and url == f'{API}/subscriptions/all':
            self._materialize()
            return {'data': [dict(s) for s in self.subs]}, None
        if method == 'GET' and url.startswith(f'{API}/clientEndPoints?'):
            return {'data': [{'uid': u, 'username': n, 'callsign': u, 'lastStatus': 'Disconnected'}
                             for u, n in self.history.items()]}, None
        if method == 'POST' and url == f'{API}/groups/update':
            for s in self.subs:
                if s['username'] in json_body:
                    g = self._tak_lookup(s['username'])
                    if g:                  # a failed lookup leaves the groups as they were
                        s['groups'] = sess(0, 'x', g)['groups']
            return True, None
        if method == 'DELETE' and url.startswith(f'{API}/subscriptions/delete/'):
            uid = urllib.parse.unquote(url.rsplit('/', 1)[1])
            gone = [s for s in self.subs if s['subscriptionUid'] == uid]
            if not gone:
                return None, 'http_400'
            self.subs.remove(gone[0])
            if self.online:
                old = gone[0]
                cn = old['_cn']
                g = self._tak_lookup(cn)
                new = dict(sess(self.next_uid, cn, g or (), client=old['clientUid'], unmapped=g is None),
                           callsign=f'tls:{self.next_uid}')     # no callsign before its first SA
                if g == []:
                    new['groups'] = [{'name': '__ANON__', 'direction': d} for d in ('IN', 'OUT')]
                self.next_uid += 1
                self.reconnects.append((self.t + 15, new))
            return {'data': f'Successfully deleted subscription with uid: {uid}'}, None
        raise AssertionError((method, url))

    def run(self, cmd, **kw):
        self.calls.append(list(cmd))
        ok = lambda out='': subprocess.CompletedProcess(cmd, 0, stdout=out, stderr='')
        if cmd[:3] == ['systemctl', 'show', 'takserver']:
            assert not self.container
            if not self.tak_running:
                return ok('ActiveState=inactive\nActiveEnterTimestampMonotonic=0\n')
            mono = int((self.tak_start - BOOT) * 1e6)
            return ok(f'ActiveState=active\nActiveEnterTimestampMonotonic={mono}\n')
        if cmd[:2] == ['docker', 'inspect']:
            name = cmd[-1]
            start = {'takserver': self.tak_start if self.tak_running else None,
                     'authentik-ldap-1': self.ldap_start}.get(name)
            if start is None:
                return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='No such object')
            return ok(f'true {_rfc3339(start)}\n')
        if cmd in (['systemctl', 'restart', 'takserver'], ['docker', 'restart', 'takserver']):
            self.t += 20
            if self.restart_rc == 0:
                self.tak_start = self.t
                self.ports_up_at = self.t + 120
            return subprocess.CompletedProcess(cmd, self.restart_rc, stdout='', stderr='boom' if self.restart_rc else '')
        if cmd[0] == 'ldapsearch':
            flt = [a for a in cmd if a.startswith('(')][0]
            if flt.startswith('(|'):       # the per-user memberOf lookup
                out = []
                for cn in re.findall(r'\(cn=([^)]*)\)', flt):
                    if cn in self.ldap_users:
                        out.append(f'dn: cn={cn},ou=users,dc=takldap')
                        out += ['memberOf: cn=tak_OPS,ou=groups,dc=takldap'] * self.ldap_users[cn]
                        out.append('')
                return ok('\n'.join(out) + '\n')
            rc, groups = self.ldap(self)
            if rc == 49:
                return subprocess.CompletedProcess(cmd, 49, stdout='', stderr='ldap_bind: Invalid credentials (49)\n')
            return ok(_ldif(groups))
        raise AssertionError(cmd)

    def sleep(self, s):
        self.t += s

    def restarts(self):
        return [c for c in self.calls if c[1:2] == ['restart']]

    def drops(self):
        return [urllib.parse.unquote(u.rsplit('/', 1)[1]) for m, u, _ in self.api if m == 'DELETE']

    def reauths(self):
        return [b for m, u, b in self.api if m == 'POST']

    def live(self, cn):
        self._materialize()
        return [s for s in self.subs if s['_cn'] == cn]

    def ns(self):
        box = self
        ns = {
            'os': types.SimpleNamespace(path=types.SimpleNamespace(
                exists=lambda p: box.coreconfig if p == '/opt/tak/CoreConfig.xml' else os.path.exists(p),
                join=os.path.join)),
            'subprocess': types.SimpleNamespace(run=self.run, TimeoutExpired=subprocess.TimeoutExpired),
            'time': types.SimpleNamespace(time=lambda: box.t, monotonic=lambda: box.t - BOOT, sleep=self.sleep),
            'datetime': datetime.datetime,
            're': re,
            'urllib': urllib,
            'threading': threading,
            '_sudo_wrap': lambda c: c,
            '_tak_is_container': lambda: box.container,
            'TAK_CONTAINER': 'takserver',
            '_coreconfig_has_ldap': lambda: box.coreconfig,
            'load_settings': lambda: box.settings,
            'save_settings': lambda s: box.settings.update(s),
            '_get_authentik_env_value': lambda s, k: SA_PASS if k == 'AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD' else None,
            '_ensure_ldapsearch': lambda: True,
            '_console_update_in_progress': lambda: box.update_in_progress,
            '_tcp_accepts': lambda port, host='127.0.0.1': box.t >= box.ports_up_at,
            '_tak_admin_marti_req': box.marti,
            '_tak_admin_marti_get': lambda url, timeout=12: box.marti(url, timeout),
            '_read_priv': lambda p: UAF if p == '/opt/tak/UserAuthenticationFile.xml' else None,
            '_TAK_MARTI_API': API,
        }
        for c in ('_PGB_SWAP_LDAP_WINDOW_S', '_PGB_SWAP_LDAP_STABLE_S', '_PGB_SWAP_LDAP_EVERY_S',
                  '_TAK_LDAP_RECYCLE_MIN_TAK_UPTIME_S', '_TAK_RECYCLE_8089_TIMEOUT_S', '_TAK_RECYCLE_API_TIMEOUT_S',
                  '_TAK_LDAP_HEAL_WAIT_S', '_TAK_LDAP_HEAL_ROUNDS'):
            ns[c] = _const(c)
        ns['_tak_ldap_recycle_lock'] = threading.Lock()
        for name in ('_epoch_from_rfc3339', '_docker_started_epoch', '_tak_started_epoch', '_tak_wait_ready',
                     '_tak_ldap_recycle_request', '_tak_recycle_after_ldap_outage',
                     '_authentik_ldap_sa_group_probe', '_authentik_ldap_sa_groups_settle',
                     '_ldap_filter_escape', '_ldap_users_tak_group_counts', '_subscription_num',
                     '_tak_device_usernames', '_tak_client_sessions', '_tak_heal_ldap_sessions'):
            exec(compile(_src(name), f'app.py:{name}', 'exec'), ns)
        return ns

    def recycle(self, trigger='end of console update', check_outpost=True, final=True):
        return self.ns()['_tak_recycle_after_ldap_outage'](self.log.append, trigger,
                                                           check_outpost=check_outpost, final=final)

    def request(self, reason, need_groups=True, restart=False):
        self.ns()['_tak_ldap_recycle_request'](reason, need_groups, restart=restart)


def healthy_box(**kw):
    """Field-like: the admin + CloudTAK service certs, a user with groups, an IN-only feeder."""
    kw.setdefault('subs', [sess(1, 'admin', ('A', 'B')), sess(2, 'cloudtak-svc-bootstrap', ('A',)),
                           sess(13, 'aj5cacor'), sess(12, 'ADSB_PS', ())])
    kw['subs'][-1]['groups'] = [{'name': 'ADSB-PS', 'direction': 'IN'}]
    kw.setdefault('ldap_users', {'aj5cacor': 1, 'ADSB_PS': 1, 'takdev-emu': 1, 'nogroups': 0})
    return Box(**kw)


def outage_box(**kw):
    """test6 2026-10-20: takdev-emu reconnected while the outpost was down → dn/user None, 0 groups."""
    box = healthy_box(**kw)
    box.subs.append(sess(16, 'takdev-emu', (), unmapped=True))
    return box


# ── heal without a restart ──────────────────────────────────────────────────────────

def test_empty_client_is_dropped_and_reconnects_with_its_groups_no_restart():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR)
    box.request('PgBouncer image swap')
    assert box.recycle() is False                      # False = TAK was not restarted
    assert box.restarts() == []
    assert box.drops() == ['tls:16']                   # only the empty one
    [now] = box.live('takdev-emu')
    assert now['subscriptionUid'] != 'tls:16' and now['username'] == 'takdev-emu' and now['groups']
    assert any('got their groups back: TAKDEV-EMU (takdev-emu)' in l for l in box.log)
    assert any('no TAK Server restart needed' in l for l in box.log)
    st = box.settings['tak_ldap_recycle']
    assert 'pending' not in st and st['last_outcome'] == 'clients healed, no restart'


def test_heal_waits_for_ldap_to_settle_first():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR)
    box.request('PgBouncer image swap')
    box.recycle()
    first_api = box.calls.index(next(c for c in box.calls if c[0] == 'ldapsearch' and '(|' in ''.join(c)))
    probes_before = [c for c in box.calls[:first_api] if c[0] == 'ldapsearch']
    assert len(probes_before) >= _const('_PGB_SWAP_LDAP_STABLE_S') // _const('_PGB_SWAP_LDAP_EVERY_S')
    assert any('held' in l and 'before healing TAK clients' in l for l in box.log)


def test_named_session_with_no_groups_is_fixed_by_reauth_without_a_drop():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR)
    box.subs.append(sess(20, 'takdev-emu', ()))        # TAK knows the user, lookup had failed
    assert box.recycle() is False
    assert box.drops() == [] and box.restarts() == []
    assert box.live('takdev-emu')[0]['groups']
    assert box.reauths() and 'takdev-emu' in box.reauths()[0]


def test_everyone_named_is_reauthenticated_but_file_users_never():
    # The re-authenticate also cycles TAK's pooled LDAP connections, so it runs even when
    # every client already has its groups.
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR)
    assert box.recycle() is False
    [names] = box.reauths()
    assert names == ['ADSB_PS', 'aj5cacor']
    assert box.drops() == [] and box.restarts() == []
    assert box.settings['tak_ldap_recycle']['last_outcome'] == 'clients fine, no restart'


def test_users_ldap_gives_no_groups_and_file_users_are_never_dropped():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR)
    box.subs += [sess(30, 'nogroups', ()), sess(31, 'admin', ())]
    box.subs[-2]['groups'] = [{'name': '__ANON__', 'direction': 'IN'}]   # TAK's anon fallback
    assert box.recycle() is False
    assert box.drops() == [] and box.restarts() == []


# ── ops #131: a client that reconnected during the outage, which client history hides ──

def test_reconnect_during_outage_hidden_from_client_history_is_found_and_healed():
    # test12 2026-10-21: the emulator reconnected while the outpost was down (no DN, no
    # username, 0 groups) and TAK's client history doesn't list its device. v10.2.24's heal
    # said "all clients have their groups"; the live connection list alone must find it.
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, history={})
    assert box.recycle() is False
    assert box.restarts() == []
    assert box.drops() == ['tls:16']
    [now] = box.live('takdev-emu')
    assert now['username'] == 'takdev-emu' and now['groups']
    assert any('1 with no groups' in l and '1 with no user at all' in l for l in box.log)
    assert any('dropped 1 connection(s)' in l and 'TAKDEV-EMU (no user)' in l for l in box.log)
    assert any('got their groups back: TAKDEV-EMU (takdev-emu)' in l for l in box.log)
    assert box.settings['tak_ldap_recycle']['last_outcome'] == 'clients healed, no restart'


def test_reconnect_is_judged_by_its_device_uid_when_nothing_named_it():
    # Another client's new connection must not be taken for the dropped one.
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, history={}, online=False)
    box.reconnects.append((T0 + 20, sess(200, 'aj5cacor')))
    assert box.recycle() is False
    assert box.restarts() == []
    assert any("1 didn't reconnect within" in l for l in box.log)
    assert not any('got their groups back' in l for l in box.log)


def test_no_user_connection_is_dropped_even_if_history_names_a_user_without_groups():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR,
                     history={'ANDROID-takdev-emu': 'nogroups'})
    assert box.recycle() is False
    assert box.drops() == ['tls:16'] and box.restarts() == []
    assert box.live('takdev-emu')[0]['groups']


def test_no_user_connection_that_comes_back_as_a_user_without_ldap_groups_is_left_alone():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, history={})
    box.subs.append(sess(32, 'stranger', (), unmapped=True))    # lookup failed during the outage
    assert box.recycle() is False
    assert box.drops() == ['tls:32'] and box.restarts() == []   # one drop, no second round
    [now] = box.live('stranger')
    assert now['username'] == 'stranger'
    assert any("reconnected as user(s) LDAP gives no TAK groups, left as is: STRANGER" in l for l in box.log)


def test_no_user_connection_back_with_no_user_twice_falls_back_to_one_restart():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, history={}, tak_ldap_ok=False)
    assert box.recycle() is True
    assert box.restarts() == [['systemctl', 'restart', 'takserver']]
    assert len(box.drops()) == _const('_TAK_LDAP_HEAL_ROUNDS')
    assert any('still with no groups although LDAP is healthy' in l and '(no user)' in l for l in box.log)


def test_unmapped_connection_is_identified_by_its_device_history():
    # test6: the empty connection has dn=None and username=None; TAK's client history says
    # that device (ANDROID-…) last connected as takdev-emu, who is in tak_TAKDEV-EMU.
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR)
    assert box.recycle() is False
    assert box.drops() == ['tls:16']
    assert any(u.startswith(f'{API}/clientEndPoints?') for _, u, _ in box.api)


def test_client_history_is_read_only_when_a_connection_has_no_user():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR)
    box.recycle()
    assert not any('clientEndPoints' in u for _, u, _ in box.api)


def test_in_only_feeder_counts_as_having_groups():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR)
    box.recycle()
    assert 'tls:12' not in box.drops()


def test_dead_pooled_connection_heals_in_the_second_round():
    # No named LDAP users to cycle the pool first: the reconnect's lookup hits the dead
    # pooled connection, the pool drops it, round 2 gets a good one.
    box = Box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, dead_pool=1,
              subs=[sess(16, 'takdev-emu', (), unmapped=True)], ldap_users={'takdev-emu': 1})
    assert box.recycle() is False
    assert box.restarts() == []
    assert len(box.drops()) == 2
    assert any('round 1: 1 client(s) reconnected still with no groups' in l for l in box.log)
    assert box.live('takdev-emu')[0]['groups']


def test_reauth_cycles_a_dead_pooled_connection_before_the_reconnect():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, dead_pool=1)
    assert box.recycle() is False
    assert box.drops() == ['tls:16'] and box.restarts() == []
    assert box.live('aj5cacor')[0]['groups']           # its failed re-lookup changed nothing


def test_client_that_stays_offline_is_not_a_failure():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, online=False)
    assert box.recycle() is False
    assert box.restarts() == []
    assert any("didn't reconnect within" in l for l in box.log)


# ── fallback: TAK restart ───────────────────────────────────────────────────────────

def test_client_back_empty_twice_falls_back_to_one_restart_and_waits_for_the_ports():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, tak_ldap_ok=False)
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    assert box.restarts() == [['systemctl', 'restart', 'takserver']]
    assert len(box.drops()) == _const('_TAK_LDAP_HEAL_ROUNDS')
    assert any('still with no groups although LDAP is healthy' in l and 'falling back to restarting' in l
               for l in box.log)
    assert any('8089 accepting connections' in l for l in box.log)
    assert any('API (8443) up' in l for l in box.log)
    assert any('✓ TAK LDAP recycle: TAK Server restarted after LDAP settled' in l for l in box.log)
    st = box.settings['tak_ldap_recycle']
    assert 'pending' not in st and st['last_outcome'] == 'restarted'


def test_tak_api_unreadable_falls_back_to_restart():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, api_ok=False)
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    assert any("can't read TAK Server's client connections" in l for l in box.log)


def test_changed_credential_restarts_tak_without_trying_a_heal():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR)
    box.request('PgBouncer image swap', restart=True)
    assert box.recycle() is True
    assert box.api == [] and len(box.restarts()) == 1
    assert any("LDAP credential changed" in l for l in box.log)
    assert 'restart' not in box.settings['tak_ldap_recycle']


def test_memberof_zero_window_delays_the_heal_until_groups_are_back():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap=lambda b: (0, 0) if b.t < T0 + 30 else (0, 3))
    box.request('PgBouncer image swap')
    assert box.recycle() is False
    assert any('NO tak_ groups' in l for l in box.log)
    assert box.drops() == ['tls:16']


def test_ldap_still_broken_means_no_heal_no_restart_and_the_request_stays():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap=lambda b: (49, 0))
    box.request('PgBouncer image swap', restart=True)
    assert box.recycle() is False
    assert box.restarts() == [] and box.api == []
    st = box.settings['tak_ldap_recycle']
    assert st['pending'] == ['PgBouncer image swap'] and st['restart'] is True
    assert any('NOT restarted' in l for l in box.log)
    # ...and the next console start carries it out once LDAP is good again
    box.ldap = lambda b: (0, 3)
    assert box.recycle(trigger='console start', check_outpost=False) is True
    assert len(box.restarts()) == 1


def test_box_without_tak_groups_needs_only_the_bind():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap=lambda b: (0, 0))
    box.request('PgBouncer image swap', need_groups=False)
    box.recycle()
    assert box.drops() == ['tls:16']


# ── no double work ──────────────────────────────────────────────────────────────────

def test_tak_already_restarted_after_the_request_is_reused():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR)
    box.request('PgBouncer image swap')
    box.tak_start = box.t + 5          # e.g. run_authentik_deploy restarted TAK later in the run
    box.t += 600
    assert box.recycle() is False
    assert box.restarts() == [] and box.api == []
    assert any('reusing that restart' in l for l in box.log)
    assert 'pending' not in box.settings['tak_ldap_recycle']


def test_two_callers_heal_once():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - 2 * HOUR)
    box.request('PgBouncer image swap')
    assert box.recycle() is False
    n = len(box.api)
    assert box.recycle(trigger='boot LDAP service-account heal') is False
    assert box.recycle(trigger='Resync LDAP to TAK Server') is False
    assert len(box.api) == n and box.drops() == ['tls:16']


def test_two_callers_restart_once_on_the_fallback():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - 2 * HOUR, tak_ldap_ok=False)
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    assert box.recycle(trigger='boot LDAP service-account heal') is False
    assert box.recycle(trigger='Resync LDAP to TAK Server') is False
    assert len(box.restarts()) == 1


def test_outside_an_update_the_boot_heal_does_it_itself_but_during_one_it_defers():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - 60, update_in_progress=True)
    assert box.recycle(trigger='boot LDAP service-account heal', final=False) is False
    assert box.api == [] and box.restarts() == []
    assert any('deferred to the end of the console update' in l for l in box.log)
    assert box.settings['tak_ldap_recycle']['pending']
    # the update's own final call heals once
    box.t += 300
    assert box.recycle(final=True) is False
    assert box.drops() == ['tls:16'] and box.restarts() == []
    assert 'pending' not in box.settings['tak_ldap_recycle']


def test_request_made_while_healing_is_not_lost():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR)
    box.request('PgBouncer image swap')
    orig = box.ldap

    def ldap_and_a_new_request(b):
        if b.t > T0 and not b.settings.get('_late'):     # mid-settle, after the first probe
            b.settings['_late'] = True
            b.request('late step')
        return orig(b)
    box.ldap = ldap_and_a_new_request
    box.recycle()
    assert box.settings['tak_ldap_recycle'].get('pending') == ['PgBouncer image swap', 'late step']


# ── the outpost check (item 5: automatic one-time heal for boxes already on v10.2.23) ──

def test_outpost_recreated_under_a_running_tak_heals_its_clients_on_update():
    # Amos: outpost recreated by v10.2.22 a day ago; TAK running since before that.
    box = outage_box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=T0 - 24 * HOUR)
    assert box.recycle() is False
    assert box.drops() == ['tls:16'] and box.restarts() == []
    assert any('LDAP outpost restarted while TAK Server was running' in l for l in box.log)
    # one-time: the next update finds that outpost start already healed
    box.t += 7 * 24 * HOUR
    n = len(box.api)
    assert box.recycle() is False
    assert len(box.api) == n
    # ...but a NEW outpost restart under TAK is checked again
    box.ldap_start = box.t - HOUR
    box.recycle()
    assert len(box.api) > n


def test_box_boot_order_never_touches_tak():
    # Boot: TAK and Authentik come up together; the boot heal recreates the outpost ~100 s in.
    for gap in (-30, 0, 100, _const('_TAK_LDAP_RECYCLE_MIN_TAK_UPTIME_S') - 1):
        box = outage_box(tak_start=T0 - 200, ldap_start=T0 - 200 + gap)
        assert box.recycle(trigger='boot LDAP service-account heal', final=False) is False, gap
        assert box.restarts() == [] and box.api == []


def test_outpost_check_off_ignores_the_outpost():
    box = outage_box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=T0 - HOUR)
    assert box.recycle(trigger='console start', check_outpost=False) is False
    assert box.restarts() == [] and box.api == []


def test_no_local_outpost_container_does_nothing():
    # Remote Authentik: nothing local to compare against.
    box = outage_box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=None)
    assert box.recycle() is False
    assert box.restarts() == [] and box.api == []


# ── nothing to do / can't do ────────────────────────────────────────────────────────

def test_tak_not_running_or_not_on_ldap_does_nothing():
    for kw in ({'tak_running': False}, {'coreconfig': False}):
        box = outage_box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=T0 - HOUR, **kw)
        box.request('PgBouncer image swap')
        assert box.recycle() is False, kw
        assert box.restarts() == [] and box.api == []
        assert 'pending' not in box.settings['tak_ldap_recycle']


def test_failed_restart_is_logged_and_kept():
    box = outage_box(tak_start=T0 - 4 * 24 * HOUR, restart_rc=1, tak_ldap_ok=False)
    box.request('PgBouncer image swap')
    assert box.recycle() is False
    assert any('TAK Server restart failed' in l for l in box.log)
    assert box.settings['tak_ldap_recycle']['pending']


def test_sa_password_is_never_logged():
    for ldap in (lambda b: (49, 0), lambda b: (0, 3)):
        box = outage_box(tak_start=T0 - 4 * 24 * HOUR, ldap=ldap, tak_ldap_ok=False)
        box.request('x')
        box.recycle()
        assert not [l for l in box.log if SA_PASS in l]


def test_ldap_filter_values_are_escaped():
    box = Box(tak_start=T0)
    esc = box.ns()['_ldap_filter_escape']
    assert esc('a*b(c)d\\e') == 'a\\2ab\\28c\\29d\\5ce'
    box.ns()['_ldap_users_tak_group_counts'](SA_PASS, ['x)(cn=*'])
    flt = [a for a in box.calls[-1] if a.startswith('(|')][0]
    assert flt == '(|(cn=x\\29\\28cn=\\2a))'


# ── where TAK runs: container, native, split (two_server) ───────────────────────────

def test_container_tak_is_restarted_with_docker_on_the_fallback():
    box = outage_box(tak_start=T0 - 4 * 24 * HOUR, container=True, tak_ldap_ok=False)
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    assert box.restarts() == [['docker', 'restart', 'takserver']]


def test_split_box_heals_and_restarts_tak_locally_and_never_touches_the_db_host():
    # two_server: Server One is the database only; TAK core runs here (Server Two).
    settings = {'tak_deployment': {'mode': 'two_server', 'server_one': {'host': '10.0.0.9'}}}
    box = outage_box(tak_start=T0 - 4 * 24 * HOUR, settings=settings, tak_ldap_ok=False)
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    assert box.restarts() == [['systemctl', 'restart', 'takserver']]
    assert not [c for c in box.calls if c[0] in ('ssh', 'scp') or '10.0.0.9' in ' '.join(c)]
    assert all(u.startswith('https://127.0.0.1:8443/') for _, u, _ in box.api)


def test_native_start_time_uses_the_monotonic_clock():
    box = Box(tak_start=T0 - 12345.0)
    assert box.ns()['_tak_started_epoch']() == pytest.approx(T0 - 12345.0, abs=0.01)


def test_docker_timestamps_parse():
    f = Box(tak_start=T0).ns()['_epoch_from_rfc3339']
    assert f('1970-01-01T00:00:10.5Z') == pytest.approx(10.5)
    assert f('2026-10-21T01:41:16.534837635Z') == pytest.approx(1792546876.534837635, abs=1e-3)
    assert f('2026-10-21T03:41:16+02:00') == pytest.approx(1792546876, abs=1e-3)
    assert f('garbage') is None and f('') is None


def test_request_merges_reasons_and_keeps_need_groups_and_restart():
    box = Box(tak_start=T0)
    box.request('a', need_groups=True, restart=True)
    box.request('b', need_groups=False)
    box.request('a', need_groups=False)
    st = box.settings['tak_ldap_recycle']
    assert st['pending'] == ['b', 'a'] and st['need_groups'] is True and st['restart'] is True


# ── wiring ──────────────────────────────────────────────────────────────────────────

def test_update_run_heals_last_with_the_outpost_check():
    i = APP.index("_tak_recycle_after_ldap_outage(lambda m: print(f\"Post-update:{m}\"")
    before = APP[:i]
    assert before.rindex('_post_update_service_recovery_sweep(') > before.rindex('def _run_post_update')
    call = APP[i:i + 300]
    assert 'check_outpost=True' in call and 'final=True' in call
    assert APP.index('print("Post-update: auto-deploy complete")') > i


def test_same_version_start_only_carries_out_pending_requests():
    i = APP.index("'console start', check_outpost=False, final=True")
    branch_start = APP.index('if last_ver == VERSION and (cur_sha', APP.index('def _post_update_auto_deploy'))
    branch_end = APP.index("lock_path = '/tmp/takwerx-post-update.lock'", branch_start)
    assert branch_start < i < branch_end                  # the same-version (no update run) branch
    assert ".get('pending')" in APP[i - 600:i]


def test_boot_sa_heal_uses_the_helper_not_its_own_restart():
    src = _src('_startup_resync_ldap_service_account')
    assert "'boot LDAP service-account heal', check_outpost=True" in src
    assert 'final=True' not in src.split("'boot LDAP service-account heal'")[1][:80]


def test_resync_ldap_button_heals_in_the_background():
    src = APP[APP.index('def takserver_connect_ldap'):]
    src = src[:src.index("return jsonify({'success': overall_ok")]
    assert "'Resync LDAP to TAK Server', check_outpost=True" in src
    assert 'threading.Thread(' in src[-1200:]


def test_restart_and_ldapsearch_are_argv_not_shell():
    for name in ('_tak_recycle_after_ldap_outage', '_ldap_users_tak_group_counts', '_tak_heal_ldap_sessions'):
        assert 'shell=True' not in _src(name), name
    src = _src('_tak_recycle_after_ldap_outage')
    assert "['systemctl', 'restart', 'takserver']" in src and "['docker', 'restart', TAK_CONTAINER]" in src
