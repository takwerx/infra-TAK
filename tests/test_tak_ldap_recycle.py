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
import json
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
                 history=None, https='ok', https_after_restart='ok', https_flaky=0, api_busy=0,
                 gd_restart=None, ghosts=(), ghosts_leave=False, outpost='user', api_back_after=None):
        self.t = T0
        # What the local outpost's log shows of TAK's lookups during HTTPS logins (ops #158):
        # 'user' = each login is looked up; 'others' = TAK looks the console's admin cert up on
        # every login but never the user (test8, TAK up 12 h); 'blind' = no outpost log.
        # `api_back_after` = a TAK in its window after an outpost restart: no lookups for anyone
        # and no groups for that many seconds from the first HTTPS login, then looked up and
        # fine (fresh test8 TAK, 54 s). `first_login` = when the HTTPS check began.
        self.outpost, self.api_back_after, self.searches = outpost, api_back_after, []
        self.api_back_at = self.first_login = None
        # ops #172: connections TAK still lists but refuses to drop (HTTP 400); with
        # `ghosts_leave` they are off the list right after the refused delete
        self.ghosts, self.ghosts_leave = set(ghosts), ghosts_leave
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
        self.api_busy = api_busy       # that many client-list reads time out first (GH #207)
        self.gd_restart = gd_restart   # Guard Dog's last Authentik restart (epoch), or None
        # TAK's client history: device uid → last username (every device seen with a user)
        self.history = history if history is not None else {'ANDROID-takdev-emu': 'takdev-emu',
                                                             'ANDROID-aj5cacor': 'aj5cacor'}
        self.reconnects = []           # (at, session) still to come
        self.next_uid = 100            # TAK numbers new connections upward
        self.calls, self.api, self.log = [], [], []
        # TAK's HTTPS/API side (ops #139), apart from the 8089 connections above: 'ok', 'no_groups'
        # (test8: groups/all empty, so missions empty and create 403), 'create_403', 'down' (no
        # answer). `https_flaky` = that many logins give no groups first (dead pooled connections
        # in the API's own LDAP pool, each dropped after its failure; ops #158).
        self.https, self.https_after_restart, self.https_flaky = https, https_after_restart, https_flaky
        self.leaf_certs, self.user_api, self.workdirs, self.missions = [], [], [], set()

    # ── TAK's HTTPS side, as a throwaway leaf cert for a user ──
    def leaf_cert(self, cn, workdir):
        self.leaf_certs.append(cn)
        self.leaf_cn = cn
        return f'{workdir}/user.pem', f'{workdir}/user.key'

    def user_req(self, cert, key, url, method='GET', timeout=20):
        self.user_api.append((self.leaf_cn, method, url))
        assert url.startswith(f'{API}/') and cert.endswith('user.pem')
        path = url[len(API) + 1:]
        state = self.https
        if path == 'groups/all':
            if self.first_login is None:
                self.first_login = self.t
                if self.api_back_after is not None:
                    self.api_back_at = self.t + self.api_back_after
            if self.api_back_at is not None:
                if self.t < self.api_back_at:
                    state = 'no_groups'
                else:
                    self.searches += [(self.t, 'admin'), (self.t, self.leaf_cn)]
            elif self.outpost == 'others':
                self.searches.append((self.t, 'admin'))
            else:
                self.searches.append((self.t, self.leaf_cn))
        if self.https_flaky:
            if path == 'groups/all':
                self.https_flaky -= 1
            state = 'no_groups'
        if state == 'down':
            return 0, None
        groups = [] if state == 'no_groups' else ['OPS']
        if method == 'GET' and path == 'groups/all':
            return 200, {'data': [{'name': g, 'direction': d} for g in groups for d in ('IN', 'OUT')]}
        if method == 'GET' and path == 'missions':
            return 200, {'data': [{'name': 'ops-feed'}] if groups else []}
        name = urllib.parse.urlsplit(path).path.split('/', 1)[1]
        if method == 'PUT':
            if not groups or state == 'create_403':
                return 403, {'message': 'Illegal attempt to set groupVector for Mission!'}
            self.missions.add(name)
            return 201, {'data': [{'name': name}]}
        if method == 'DELETE':
            self.missions.discard(name)
            return 200, {'data': []}
        raise AssertionError((method, url))

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
            if self.api_busy:
                self.api_busy -= 1
                self.t += 20
                return None, 'curl_exit_28'
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
            if uid in self.ghosts:
                if self.ghosts_leave:
                    self.subs = [s for s in self.subs if s['subscriptionUid'] != uid]
                return None, 'http_400'
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
        if cmd[:2] == ['docker', 'logs'] and cmd[-1] == 'authentik-ldap-1':
            if self.ldap_start is None or self.outpost == 'blind':
                return subprocess.CompletedProcess(cmd, 1, stdout='Error: No such container\n', stderr='')
            since = int(cmd[cmd.index('--since') + 1])
            out = []
            for t, cn in self.searches:
                if t >= since:
                    stamp = _rfc3339(t)[:19] + 'Z'
                    base = f'cn={cn},ou=users,dc=takldap'
                    out.append(json.dumps({'attributes': [], 'baseDN': base, 'event': 'Search request',
                                           'filter': '(objectClass=*)', 'timestamp': stamp}))
                    out.append(json.dumps({'attributes': ['memberOf', 'ntUserWorkstations'], 'baseDN': base,
                                           'event': 'Search request', 'filter': '(objectClass=*)',
                                           'timestamp': stamp}))
            # the console's own ldapsearch reads the users OU: never a TAK lookup
            out.append(json.dumps({'attributes': ['memberOf'], 'baseDN': 'ou=users,dc=takldap',
                                   'event': 'Search request', 'timestamp': _rfc3339(self.t)[:19] + 'Z'}))
            return ok('\n'.join(out) + '\n')
        if cmd in (['systemctl', 'restart', 'takserver'], ['docker', 'restart', 'takserver']):
            self.t += 20
            if self.restart_rc == 0:
                self.tak_start = self.t
                self.ports_up_at = self.t + 120
                self.https = self.https_after_restart
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
            'json': json,
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
            '_guarddog_authentik_restart_epoch': lambda: box.gd_restart,
            '_tak_user_leaf_cert': box.leaf_cert,
            '_tak_user_marti_req': box.user_req,
            'tempfile': types.SimpleNamespace(
                mkdtemp=lambda prefix='': box.workdirs.append(f'/tmp/{prefix}{len(box.workdirs)}') or box.workdirs[-1]),
            'shutil': types.SimpleNamespace(rmtree=lambda p, ignore_errors=False: box.workdirs.remove(p)),
            '_TAK_API_CHECK_TOOL': 'infratak-check',
        }
        for c in ('_PGB_SWAP_LDAP_WINDOW_S', '_PGB_SWAP_LDAP_STABLE_S', '_PGB_SWAP_LDAP_EVERY_S',
                  '_TAK_LDAP_RECYCLE_MIN_TAK_UPTIME_S', '_TAK_RECYCLE_8089_TIMEOUT_S', '_TAK_RECYCLE_API_TIMEOUT_S',
                  '_TAK_LDAP_HEAL_WAIT_S', '_TAK_LDAP_HEAL_ROUNDS', '_TAK_API_CHECK_TRIES',
                  '_TAK_API_CHECK_WAIT_S', '_TAK_API_CHECK_RETRY_S', '_TAK_API_CHECK_RETRY_MAX_S',
                  '_TAK_MARTI_READ_WAIT_S', '_TAK_MARTI_READ_RETRY_MAX_S', '_TAK_API_CHECK_STUCK_S'):
            ns[c] = _const(c)
        ns['_tak_ldap_recycle_lock'] = threading.Lock()
        for name in ('_epoch_from_rfc3339', '_docker_started_epoch', '_tak_started_epoch', '_tak_wait_ready',
                     '_tak_ldap_recycle_request', '_tak_recycle_after_ldap_outage',
                     '_authentik_ldap_sa_group_probe', '_authentik_ldap_sa_groups_settle',
                     '_ldap_filter_escape', '_ldap_users_tak_groups', '_ldap_users_tak_group_counts',
                     '_tak_file_users', '_subscription_num',
                     '_tak_device_usernames', '_tak_client_sessions', '_tak_client_sessions_wait',
                     '_tak_heal_ldap_sessions',
                     '_tak_api_user_check_once', '_tak_api_user_check',
                     '_ldap_outpost_tak_searches', '_tak_api_check_stuck'):
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


# ── ops #172: a connection TAK won't drop, which a newer one from the client replaced ──

def ghost_box(newer=None, **kw):
    """test6 2026-10-22: the emulator's tls:29 was added and removed in the same ms, TAK still
    listed it 3 min later with no user and no groups, and its delete got HTTP 400; the real
    connection was tls:30, with groups."""
    kw.setdefault('ghosts', {'tls:29'})
    box = healthy_box(**kw)
    box.subs.append(sess(29, 'takdev-emu', (), unmapped=True))
    if newer is not None:
        box.subs.append(newer)
    return box


def test_ops172_ghost_replaced_by_a_newer_connection_with_groups_is_not_a_restart():
    box = ghost_box(sess(30, 'takdev-emu'), tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR)
    assert box.recycle() is False
    assert box.restarts() == []
    assert box.drops() == ['tls:29']
    assert any("couldn't drop TAKDEV-EMU (takdev-emu) (tls:29): http_400" in l for l in box.log)
    assert any("1 connection(s) TAK couldn't drop are gone or replaced" in l and 'TAKDEV-EMU' in l
               for l in box.log)
    assert not any('still with no groups although LDAP is healthy' in l for l in box.log)
    assert box.settings['tak_ldap_recycle']['last_outcome'] == 'clients healed, no restart'


def test_ops172_refused_drop_of_a_connection_that_left_the_list_is_not_a_restart():
    box = ghost_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, ghosts_leave=True)
    assert box.recycle() is False
    assert box.restarts() == []
    assert any("1 connection(s) TAK couldn't drop are gone or replaced" in l for l in box.log)


def test_ops172_ghost_reconnect_that_heals_in_the_same_run_counts_as_its_replacement():
    # The newer connection also came in empty: it is dropped, comes back with groups, and
    # then stands in for the ghost too.
    box = ghost_box(sess(30, 'takdev-emu', (), unmapped=True), tak_start=T0 - 3 * 24 * HOUR,
                    ldap_start=T0 - HOUR)
    assert box.recycle() is False
    assert box.restarts() == []
    assert box.drops() == ['tls:29', 'tls:30']
    assert box.live('takdev-emu')[-1]['groups']


def test_ops172_undroppable_with_no_replacement_still_restarts_tak_once():
    box = ghost_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR)
    assert box.recycle() is True
    assert box.restarts() == [['systemctl', 'restart', 'takserver']]
    assert any('still with no groups although LDAP is healthy' in l and 'TAKDEV-EMU' in l for l in box.log)
    assert not any("TAK couldn't drop are gone or replaced" in l for l in box.log)


@pytest.mark.parametrize('newer', [
    sess(30, 'takdev-emu', client='ANDROID-other-device'),   # same user, another device
    sess(30, 'takdev-emu', ()),                              # same client, but no groups either
    sess(28, 'takdev-emu'),                                  # older, not a reconnect
], ids=['other-device', 'no-groups', 'older'])
def test_ops172_only_a_newer_connection_of_the_same_client_with_groups_replaces_it(newer):
    box = ghost_box(newer, tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, tak_ldap_ok=False)
    assert box.recycle() is True
    assert len(box.restarts()) == 1
    assert not any("TAK couldn't drop are gone or replaced" in l for l in box.log)


def test_ops172_unreadable_list_after_a_refused_drop_keeps_the_restart_fallback():
    box = ghost_box(sess(30, 'takdev-emu'), tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR)
    marti = box.marti

    def no_reads_after_the_drop(url, timeout=12, method='GET', json_body=None):
        if method == 'GET' and url == f'{API}/subscriptions/all' and box.drops():
            return None, 'curl_exit_28'
        return marti(url, timeout, method, json_body)
    box.marti = no_reads_after_the_drop
    assert box.recycle() is True
    assert len(box.restarts()) == 1


# ── ops #139: TAK's HTTPS/API side, which the 8089 connections say nothing about ─────

def test_healthy_box_checks_https_as_a_live_non_admin_user_and_cleans_up():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR)
    assert box.recycle() is False
    assert box.restarts() == []
    # a connected LDAP user with groups; never admin / cloudtak-svc-bootstrap (file users)
    assert box.leaf_certs == ['ADSB_PS']
    calls = [(m, u.split('?')[0].rsplit('/Marti/api/', 1)[1]) for _, m, u in box.user_api]
    name = calls[2][1].split('/', 1)[1]
    assert calls == [('GET', 'groups/all'), ('GET', 'missions'), ('PUT', f'missions/{name}'),
                     ('DELETE', f'missions/{name}')]
    put = box.user_api[2][2]
    assert 'group=OPS' in put and 'tool=infratak-check' in put and name.startswith('infratak-ldap-check-')
    assert box.missions == set() and box.workdirs == []         # mission deleted, temp dir removed
    line = [l for l in box.log if 'no TAK Server restart needed' in l][0]
    assert 'have their groups' in line and 'HTTPS as ADSB_PS: 1 group(s), 1 mission(s) listed' in line
    assert 'mission create + delete in OPS OK' in line
    assert box.settings['tak_ldap_recycle']['last_outcome'] == 'clients fine, no restart'


def test_test8_streaming_fine_but_https_gives_no_groups_restarts_tak_once():
    # test8 2026-10-21: every ATAK had its 8089 groups, but over HTTPS TAK gave cert users 0
    # groups (empty mission list, 403 on create). The old check said "all clients have their
    # groups" eight times. Now: one TAK restart, only after the HTTPS check has kept failing
    # for _TAK_API_CHECK_WAIT_S, and the check repeated after it.
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https='no_groups')
    t0 = box.t
    assert box.recycle() is True
    assert box.restarts() == [['systemctl', 'restart', 'takserver']]
    assert box.drops() == []                       # the 8089 clients were fine, none dropped
    assert not any('no TAK Server restart needed' in l for l in box.log)
    assert any(l.startswith('  ✗ TAK LDAP recycle:') and "HTTPS/API side is broken" in l
               and "gave ADSB_PS no groups on groups/all, while LDAP gives 1 (OPS)" in l for l in box.log)
    assert any('falling back to restarting TAK Server' in l for l in box.log)
    assert any('✓ TAK LDAP recycle: after the restart: HTTPS as ADSB_PS' in l for l in box.log)
    rounds = [l for l in box.log if 'HTTPS check round' in l]
    tries = _const('_TAK_API_CHECK_TRIES')
    assert rounds and all(f'({tries} login(s))' in l for l in rounds)
    assert len(box.leaf_certs) == (len(rounds) + 1) * tries + 1     # + the one after the restart
    restart_at = next(i for i, c in enumerate(box.calls) if c[1:2] == ['restart'])
    assert box.t - t0 >= _const('_TAK_API_CHECK_WAIT_S') and restart_at
    st = box.settings['tak_ldap_recycle']
    assert st['last_outcome'] == 'restarted' and 'healed_ldap_start' not in st
    assert box.workdirs == []


def test_ops158_tak_that_never_asks_ldap_for_the_user_is_restarted_early():
    # test8 2026-10-22, TAK up 12 h: after the update's outpost restart TAK looked other users
    # up again within 15 s but sent not one search for aj1cacor in 48 logins over 5 min; only
    # the restart fixed it. Now TAK is restarted as soon as that is plain, not after 5 min.
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https='no_groups', outpost='others')
    assert box.recycle() is True
    assert box.restarts() == [['systemctl', 'restart', 'takserver']]
    waited = box.t - 20 - 120 - box.first_login    # less the restart command and the ports, see Box.run
    stuck = _const('_TAK_API_CHECK_STUCK_S')
    assert stuck <= waited < 2 * _const('_TAK_API_CHECK_RETRY_MAX_S') + stuck
    assert any('HTTPS check round 2' in l and 'TAK is looking other users up in LDAP again, not yet ADSB_PS' in l
               and 'keeping the 300s wait' in l for l in box.log)
    [early] = [l for l in box.log if 'not waiting the rest of the' in l]
    assert ('HTTPS check round 3: TAK looks other users up in LDAP' in early and 'but sent none for ADSB_PS' in early
            and 'TAK Server needs a restart' in early)
    assert any('falling back to restarting TAK Server' in l and 'but sent none for ADSB_PS' in l for l in box.log)
    assert any('✓ TAK LDAP recycle: after the restart: HTTPS as ADSB_PS' in l for l in box.log)
    assert box.settings['tak_ldap_recycle']['last_outcome'] == 'restarted' and box.workdirs == []


def test_ops158_fresh_tak_still_reconnecting_to_ldap_heals_without_a_restart():
    # test8 2026-10-22, fresh TAK: after the outpost restart TAK looked nobody up for 54 s,
    # then its API reconnected and the user's next login passed. No lookups at all is not
    # "TAK won't ask for the user": the check keeps its wait and heals.
    box = healthy_box(tak_start=T0 - HOUR, ldap_start=T0 - 60, api_back_after=54)
    assert box.recycle() is False
    assert box.restarts() == []
    assert any("HTTPS check round 2" in l and "TAK hasn't looked anyone up in LDAP since the check began" in l
               for l in box.log)
    assert any('HTTPS check passed on login 1 of round 4' in l for l in box.log)
    assert not any('not waiting the rest of the' in l for l in box.log)
    assert any('no TAK Server restart needed' in l for l in box.log)


def test_ops158_tak_asking_ldap_for_the_user_keeps_the_full_wait():
    # TAK looks the user up and still gives no groups: the old timing, restart after 5 min.
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https='no_groups')
    assert box.recycle() is True
    assert box.t - 20 - 120 - box.first_login >= _const('_TAK_API_CHECK_WAIT_S')
    said = [l for l in box.log if 'TAK is looking ADSB_PS up in LDAP' in l]
    assert len(said) == 1 and 'HTTPS check round 2' in said[0] and 'keeping the 300s wait' in said[0]
    assert any('still no groups for ADSB_PS after the full 300s wait' in l for l in box.log)
    assert not any('not waiting the rest of the' in l for l in box.log)


def test_ops158_no_local_outpost_log_keeps_the_full_wait():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https='no_groups', outpost='blind')
    assert box.recycle() is True
    assert box.t - 20 - 120 - box.first_login >= _const('_TAK_API_CHECK_WAIT_S')
    assert any("can't read the local LDAP outpost's log" in l and 'keeping the 300s wait' in l for l in box.log)


def test_ops158_early_restart_only_before_the_restart_not_while_the_api_warms_up_after():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https='no_groups',
                      https_after_restart='no_groups', outpost='others')
    assert box.recycle() is True
    assert len(box.restarts()) == 1
    assert len([l for l in box.log if 'not waiting the rest of the' in l]) == 1
    after = box.log[next(i for i, l in enumerate(box.log) if 'TAK Server restarted after LDAP settled' in l):]
    assert any('STILL BROKEN after the TAK Server restart' in l for l in after)
    assert not any('outpost' in l or 'looks other users up' in l for l in after)


def test_ops158_outpost_log_reader_counts_only_tak_user_lookups():
    box = healthy_box(tak_start=T0 - HOUR, ldap_start=T0 - HOUR)
    box.searches = [(T0 - 5, 'old'), (T0 + 1, 'Aj1Cacor'), (T0 + 2, 'admin')]
    seen = box.ns()['_ldap_outpost_tak_searches'](T0)
    assert seen == [(T0 + 1, 'aj1cacor'), (T0 + 2, 'admin')]    # one per lookup, users OU search left out
    assert box.calls[-1] == ['docker', 'logs', '--since', str(int(T0)), 'authentik-ldap-1']
    box.ldap_start = None                                       # remote Authentik: no local outpost
    assert box.ns()['_ldap_outpost_tak_searches'](T0) is None


def test_ops158_dead_pooled_connections_on_the_api_side_heal_without_a_restart():
    # test8 2026-10-21 (v10.2.25 T&E): the update restarted the outpost under TAK; TAK's API
    # held 4 pooled LDAP connections, all dead. Two logins 15 s apart both hit one and TAK
    # was restarted. Logging in again with a fresh cert gets past them.
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https_flaky=4)
    assert box.recycle() is False
    assert box.restarts() == []
    assert len(box.leaf_certs) == 5 and box.workdirs == []      # a fresh cert each, all removed
    assert not any('trying again in' in l for l in box.log)               # no wait: the same round
    assert any('HTTPS check passed on login 5 of round 1' in l for l in box.log)
    assert any('no TAK Server restart needed' in l for l in box.log)
    assert box.settings['tak_ldap_recycle']['last_outcome'] == 'clients fine, no restart'


def test_more_dead_connections_than_one_round_heal_in_a_later_round():
    tries = _const('_TAK_API_CHECK_TRIES')
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https_flaky=tries + 2)
    t0 = box.t
    assert box.recycle() is False
    assert box.restarts() == []
    assert any(f'HTTPS check round 1 ({tries} login(s))' in l and 'trying again in 15s' in l for l in box.log)
    assert any('HTTPS check passed on login 3 of round 2' in l for l in box.log)
    assert box.t - t0 < _const('_TAK_API_CHECK_WAIT_S')


def test_https_check_backs_off_and_is_bounded():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https='no_groups')
    waits = []
    real_sleep = box.sleep

    def sleep(s):
        if any('HTTPS check round' in l for l in box.log[-1:]):
            waits.append(s)
        real_sleep(s)
    box.sleep = sleep
    box.recycle()
    assert waits[:4] == [15, 30, 60, 60] and max(waits) == _const('_TAK_API_CHECK_RETRY_MAX_S')
    assert sum(waits) == _const('_TAK_API_CHECK_WAIT_S')


def test_https_403_on_create_restarts_tak():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https='create_403')
    assert box.recycle() is True
    assert len(box.restarts()) == 1
    assert any('got HTTP 403 creating a mission in OPS over HTTPS' in l for l in box.log)
    assert box.missions == set()


def test_https_still_broken_after_the_restart_is_logged_and_not_restarted_again():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https='no_groups',
                      https_after_restart='no_groups')
    assert box.recycle() is True
    assert len(box.restarts()) == 1
    assert any('✗ TAK LDAP recycle: STILL BROKEN after the TAK Server restart' in l for l in box.log)
    assert box.settings['tak_ldap_recycle']['last_outcome'] == 'restarted, HTTPS still broken'
    # ...and the next caller doesn't restart again for the same outpost start
    assert box.recycle(trigger='console start') is False
    assert len(box.restarts()) == 1


def test_one_bad_https_login_is_retried_before_any_restart():
    # The API's first lookup can hit a dead pooled LDAP connection, like the streaming side.
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https_flaky=1)
    assert box.recycle() is False
    assert box.restarts() == []
    assert len(box.leaf_certs) == 2                # a fresh cert for the second login
    assert any('HTTPS check passed on login 2 of round 1' in l for l in box.log)
    assert any('no TAK Server restart needed' in l for l in box.log)


def test_api_that_does_not_answer_is_not_logged_into_again_within_a_round():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https='down')
    assert box.recycle() is False
    rounds = [l for l in box.log if 'HTTPS check round' in l]
    assert rounds and all('(1 login(s))' in l for l in rounds)
    assert len(box.leaf_certs) == len(rounds) + 1


def test_streaming_restart_fallback_also_checks_https_after():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, tak_ldap_ok=False)
    box.request('PgBouncer image swap')
    assert box.recycle() is True
    assert box.leaf_certs                          # only after the restart: the heal failed first
    assert any('✓ TAK LDAP recycle: after the restart: HTTPS as' in l for l in box.log)


def test_https_check_retries_while_the_api_warms_up_after_a_restart():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https='no_groups',
                      https_after_restart='down')
    orig = box.user_req
    down = []

    def warming(cert, key, url, method='GET', timeout=20):
        if box.https == 'down':
            down.append(url)
            if len(down) > 4:
                box.https = 'ok'                   # the API serves a few rounds after 8443 opens
        return orig(cert, key, url, method, timeout)
    box.user_req = warming
    assert box.recycle() is True
    assert box.settings['tak_ldap_recycle']['last_outcome'] == 'restarted'
    assert any("didn't answer" in l and 'trying again' in l for l in box.log)


def test_no_live_user_falls_back_to_a_user_from_ldap():
    box = Box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR,
              subs=[sess(1, 'admin', ('A',))], ldap_users={})
    assert box.recycle() is False
    assert box.leaf_certs == ['user0']             # the first LDAP user with a tak_ group
    assert any('HTTPS as user0' in l for l in box.log)


def test_admins_file_users_and_odd_names_are_never_used_for_the_check():
    box = Box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR,
              subs=[sess(1, 'admin', ('A',)), sess(2, 'boss'), sess(3, 'we/ird'), sess(4, 'zed')],
              ldap_users={'admin': 1, 'boss': 1, 'we/ird': 1, 'zed': 1})
    real = box.run

    def run(cmd, **kw):                            # boss is in tak_ROLE_ADMIN as well
        r = real(cmd, **kw)
        if cmd[0] == 'ldapsearch' and r.stdout:
            r.stdout = r.stdout.replace('dn: cn=boss,ou=users,dc=takldap\n',
                                        'dn: cn=boss,ou=users,dc=takldap\n'
                                        'memberOf: cn=tak_ROLE_ADMIN,ou=groups,dc=takldap\n')
        return r
    box.run = run
    assert box.recycle() is False
    assert box.leaf_certs == ['zed']


def test_no_user_to_check_with_is_said_and_does_not_restart():
    box = Box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, subs=[sess(1, 'admin', ('A',))],
              ldap=lambda b: (0, 0))
    box.request('PgBouncer image swap', need_groups=False)
    assert box.recycle() is False
    assert box.restarts() == [] and box.leaf_certs == []
    assert any('HTTPS/API side NOT checked: no non-admin LDAP user with TAK groups' in l for l in box.log)
    assert not any('no TAK Server restart needed' in l for l in box.log)
    assert box.settings['tak_ldap_recycle']['last_outcome'] == 'clients fine, no restart (HTTPS not checked)'


def test_https_no_answer_is_unknown_not_a_restart():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, https='down')
    assert box.recycle() is False
    assert box.restarts() == []
    assert any("HTTPS/API side NOT checked: TAK's API didn't answer" in l for l in box.log)


def test_cert_that_cant_be_made_is_unknown_not_a_restart():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR)

    failed_at = []

    def no_ca(cn, workdir):
        failed_at.append(box.t)
        raise RuntimeError('CoreConfig has no enrollment CA (TAKServerCAConfig)')
    box.leaf_cert = no_ca
    assert box.recycle() is False
    t0 = failed_at[0]                              # not before: the recycle holds LDAP 45 s first
    assert box.restarts() == [] and box.workdirs == []
    assert any("couldn't make a test cert for ADSB_PS: CoreConfig has no enrollment CA" in l for l in box.log)
    assert not any('HTTPS check round' in l for l in box.log)   # no cert won't change by waiting
    assert box.t - t0 < _const('_TAK_API_CHECK_RETRY_S')


def test_group_tak_already_reports_is_used_so_a_fresh_portal_add_cannot_restart_tak():
    # Matt 2026-10-21: a group added in TAK Portal reaches TAK's group cache later. Creating
    # in a group TAK already gives the user keeps that lag from looking like a broken TAK.
    box = Box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR, subs=[sess(1, 'matt')], ldap_users={'matt': 1})
    real = box.run

    def run(cmd, **kw):                            # LDAP: matt is in AAA-NEW (just added) and OPS
        r = real(cmd, **kw)
        if cmd[0] == 'ldapsearch' and 'dn: cn=matt,' in (r.stdout or ''):
            r.stdout = r.stdout.replace('memberOf: cn=tak_OPS', 'memberOf: cn=tak_AAA-NEW,ou=groups,dc=takldap\n'
                                        'memberOf: cn=tak_OPS')
        return r
    box.run = run
    assert box.recycle() is False
    assert box.restarts() == []
    assert 'group=OPS' in [u for _, m, u in box.user_api if m == 'PUT'][0]


def test_test_mission_left_by_a_failed_user_delete_is_deleted_as_admin():
    box = healthy_box(tak_start=T0 - 3 * 24 * HOUR, ldap_start=T0 - HOUR)
    orig = box.user_req
    box.user_req = lambda c, k, u, m='GET', t=20: (403, None) if m == 'DELETE' else orig(c, k, u, m, t)
    real_marti = box.marti
    admin_deletes = []

    def marti(url, timeout=12, method='GET', json_body=None):
        if method == 'DELETE' and '/missions/' in url:
            admin_deletes.append(url)
            return True, None
        return real_marti(url, timeout, method, json_body)
    box.marti = marti
    assert box.recycle() is False
    assert len(admin_deletes) == 1 and 'infratak-ldap-check-' in admin_deletes[0]
    assert not any("couldn't delete test mission" in l for l in box.log)


def test_leaf_cert_is_signed_by_the_enrollment_ca_with_no_password_in_argv(tmp_path):
    cc = ('<Configuration><certificateSigning CA="TAKServer"/><TAKServerCAConfig keystore="JKS" '
          'keystoreFile="certs/files/INT-CA-14-signing.jks" keystorePass="ca-secret" validityDays="30"/>'
          '</Configuration>')
    reads, runs = [], []

    def run(cmd, **kw):
        runs.append((list(cmd), kw.get('env', {}).get('TAK_CA_PASS')))
        return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
    ns = {'re': re, 'os': os, 'subprocess': types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired),
          'secrets': types.SimpleNamespace(randbits=lambda n: 12345),
          '_read_priv': lambda p: cc if p == '/opt/tak/CoreConfig.xml' else None,
          '_read_priv_bytes': lambda p: reads.append(p) or b'PEM',
          '_get_tak_cert_password': lambda s: 'wrong', 'load_settings': dict,
          '_TAK_API_CHECK_EKU': 'clientAuth,1.2.840.113549.1.9.7'}
    exec(compile(_src('_tak_user_leaf_cert'), 'app.py:_tak_user_leaf_cert', 'exec'), ns)
    crt, key = ns['_tak_user_leaf_cert']('aj5cacor', str(tmp_path))
    assert reads == ['/opt/tak/certs/files/INT-CA-14.pem', '/opt/tak/certs/files/INT-CA-14.key']
    assert crt.startswith(str(tmp_path)) and key.startswith(str(tmp_path))
    for f in ('ca.pem', 'ca.key', 'ext.cnf'):
        assert (tmp_path / f).stat().st_mode & 0o777 == 0o600
    assert 'extendedKeyUsage=clientAuth,1.2.840.113549.1.9.7' in (tmp_path / 'ext.cnf').read_text()
    (req, _), (sign, pw) = runs
    assert req[:2] == ['openssl', 'req'] and '/CN=aj5cacor/O=infra-TAK/OU=LDAP check' in req
    assert sign[:3] == ['openssl', 'x509', '-req'] and sign[sign.index('-passin') + 1] == 'env:TAK_CA_PASS'
    assert pw == 'ca-secret' and not any('ca-secret' in a for c, _ in runs for a in c)
    assert sign[sign.index('-days') + 1] == '1'
    for bad in ('x/CN=admin', 'a b', '', '-rf', 'é'):
        with pytest.raises(RuntimeError):
            ns['_tak_user_leaf_cert'](bad, str(tmp_path))


def test_https_check_code_is_argv_not_shell():
    for name in ('_tak_user_leaf_cert', '_tak_user_marti_req', '_tak_api_user_check_once', '_tak_api_user_check'):
        assert 'shell=True' not in _src(name), name


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
    t_heal = []
    real = box.marti

    def marti(url, timeout=12, method='GET', json_body=None):
        if url.endswith('/subscriptions/all') and not box.restarts():
            t_heal.append(box.t)
        return real(url, timeout, method, json_body)
    box.marti = marti
    assert box.recycle() is True
    # GH #207: only after the client list stayed unreadable for the whole wait, and the
    # reason says why it couldn't be read
    assert t_heal[-1] - t_heal[0] >= _const('_TAK_MARTI_READ_WAIT_S')
    assert any("can't read TAK Server's client connections (Marti API: curl_exit_7) for 5 min" in l
               and 'falling back to restarting' in l for l in box.log)


def test_gh207_briefly_busy_marti_api_is_retried_not_a_restart():
    # Amos, v10.2.23 → v10.2.24: LDAP had settled, the client-list read didn't answer in
    # time once, and TAK Server was restarted for it. Now it is read again, backing off.
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR, api_busy=2)
    box.request('PgBouncer image swap')
    assert box.recycle() is False
    assert box.restarts() == []
    assert box.drops() == ['tls:16']
    tries = [l for l in box.log if "can't read TAK Server's client connections yet (Marti API: curl_exit_28)" in l]
    assert len(tries) == 2 and 'trying again in 10s' in tries[0] and 'trying again in 20s' in tries[1]
    assert any("Marti API answered after" in l for l in box.log)
    assert box.settings['tak_ldap_recycle']['last_outcome'] == 'clients healed, no restart'


def test_marti_read_backoff_is_capped_and_the_wait_bounded():
    box = Box(tak_start=T0)
    ns = box.ns()
    box.api_ok = False
    t0 = box.t
    sessions, err = ns['_tak_client_sessions_wait'](box.log.append, 'tag')
    assert sessions is None and err == 'curl_exit_7'
    waits = [int(re.search(r'trying again in (\d+)s', l).group(1)) for l in box.log]
    assert waits[:4] == [10, 20, 40, 60] and max(waits) == _const('_TAK_MARTI_READ_RETRY_MAX_S')
    assert sum(waits) == _const('_TAK_MARTI_READ_WAIT_S') and box.t - t0 == sum(waits)


def test_changed_credential_restarts_tak_without_trying_a_heal():
    box = outage_box(tak_start=T0 - 3 * 24 * HOUR)
    box.request('PgBouncer image swap', restart=True)
    assert box.recycle() is True
    # no heal: nothing re-authenticated or dropped, only the HTTPS check after the restart reads TAK
    assert [m for m, _, _ in box.api] == ['GET'] and len(box.restarts()) == 1
    assert box.drops() == [] and box.reauths() == []
    assert any("LDAP credential changed" in l for l in box.log)
    assert any('✓ TAK LDAP recycle: after the restart: HTTPS as' in l for l in box.log)
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


# ── ops #184: Authentik Reconfigure, and a heal cut short by a console restart ──────

def reconfigure_heal(box, ns=None):
    """What the end of an Authentik Reconfigure runs."""
    ns = ns or box.ns()
    exec(compile(_src('_authentik_reconfigure_heal_tak_clients'), 'app.py', 'exec'), ns)
    ns['_authentik_reconfigure_heal_tak_clients'](box.log.append)


def test_ops184_reconfigure_soon_after_tak_started_heals_the_client_it_left_empty():
    # test12 (ops #180): TAK started 17:44:18Z; the post-update Reconfigure's flow fix
    # recreated the outpost at 17:48:21Z and the emulator reconnected 11 s later: no user,
    # no groups. Outpost started under 5 min after TAK, so the start-time check (the boot
    # guard) never counts it and nothing would ever heal that client.
    gap = _const('_TAK_LDAP_RECYCLE_MIN_TAK_UPTIME_S') - 60
    box = outage_box(tak_start=T0 - gap - 30, ldap_start=T0 - 30)
    assert box.recycle(trigger='periodic LDAP outage check', final=False) is False
    assert box.api == []                                 # the gap: nothing heals it
    reconfigure_heal(box)
    assert box.restarts() == []
    assert box.drops() == ['tls:16']
    [now] = box.live('takdev-emu')
    assert now['username'] == 'takdev-emu' and now['groups']
    assert any('(end of Authentik Reconfigure): TAK Server ran through an LDAP outage — '
               'Authentik Reconfigure recreated the LDAP outpost' in l for l in box.log)
    st = box.settings['tak_ldap_recycle']
    assert 'pending' not in st and st['last_outcome'] == 'clients healed, no restart'


def test_ops184_reconfigure_inside_a_console_update_leaves_it_to_the_update_end():
    box = outage_box(tak_start=T0 - 200, ldap_start=T0 - 30, update_in_progress=True)
    reconfigure_heal(box)
    assert box.api == [] and box.restarts() == []
    assert box.settings['tak_ldap_recycle']['pending'] == ['Authentik Reconfigure recreated the LDAP outpost']
    assert any('client check deferred to the end of the console update' in l for l in box.log)
    box.t += 300
    box.update_in_progress = False
    assert box.recycle(final=True) is False           # the update's last step
    assert box.drops() == ['tls:16'] and box.restarts() == []
    assert box.live('takdev-emu')[0]['groups']


def test_ops184_tak_started_after_the_reconfigure_request_is_left_alone():
    # TAK (re)started after the request (e.g. it was still coming up): it looked every
    # client up against the healed LDAP already.
    box = outage_box(tak_start=T0 + 5, ldap_start=T0 - 30)
    reconfigure_heal(box)
    assert box.api == [] and box.restarts() == []
    assert any('reusing that restart' in l for l in box.log)
    assert 'pending' not in box.settings['tak_ldap_recycle']


def test_ops184_reconfigure_with_tak_not_on_ldap_does_nothing():
    box = outage_box(tak_start=T0 - 200, ldap_start=T0 - 30, coreconfig=False)
    reconfigure_heal(box)
    assert box.api == [] and box.restarts() == []
    assert 'pending' not in box.settings['tak_ldap_recycle']


class ConsoleRestarted(BaseException):
    """systemctl restart takwerx-console: the heal's thread just stops."""


def test_ops184_heal_killed_by_a_console_restart_is_finished_by_the_next_console_start():
    # test12 (ops #180): the update's final heal started at 17:53:35Z for an outpost
    # restarted under TAK; the console was restarted at 17:53:38Z. That reason was never
    # saved, and the restarted console carries out only pending requests.
    box = outage_box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=T0 - 120)
    marti = box.marti

    def killed(url, timeout=12, method='GET', json_body=None):
        raise ConsoleRestarted()
    box.marti = killed
    with pytest.raises(ConsoleRestarted):
        box.recycle()
    st = box.settings['tak_ldap_recycle']
    assert st['last_outcome'] == 'in progress'
    assert st['pending'] == ['LDAP outpost restarted while TAK Server was running (TAK up 95h58m at the time)']
    box.marti = marti
    box.t += 60
    assert box.recycle(trigger='console start', check_outpost=False, final=True) is False
    assert box.drops() == ['tls:16'] and box.restarts() == []
    assert box.live('takdev-emu')[0]['groups']
    st = box.settings['tak_ldap_recycle']
    assert 'pending' not in st and st['last_outcome'] == 'clients healed, no restart'


def test_ops184_saving_the_reason_first_does_not_swallow_a_newer_request():
    box = outage_box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=T0 - 120)
    box.request('PgBouncer image swap')
    req = box.settings['tak_ldap_recycle']['requested_epoch']
    real_load = box.ns

    def ns_with_a_late_request():
        ns = real_load()
        load = ns['load_settings']
        state = {'n': 0}

        def load_settings():
            state['n'] += 1
            if state['n'] == 2:                        # between the first read and the save
                box.t += 1
                box.request('late step')
            return load()
        ns['load_settings'] = load_settings
        return ns
    box.ns = ns_with_a_late_request
    box.recycle()
    st = box.settings['tak_ldap_recycle']
    assert st['requested_epoch'] > req and st['pending'] == ['PgBouncer image swap', 'late step']


def test_ops184_both_reconfigure_paths_heal_last():
    local = APP[APP.index('def run_authentik_deploy('):]
    local = local[:local.index('_authentik_reconfigure_finish(plog, issues, "Reconfigure", notes)')]
    tail = local[local.rindex('_sync_webadmin_after_authentik_reconfigure(plog)'):].split('\n')
    assert [l.strip() for l in tail if l.strip() and not l.strip().startswith('#')] == [
        '_sync_webadmin_after_authentik_reconfigure(plog)', '_authentik_reconfigure_heal_tak_clients(plog)', 'plog("")']
    remote = _src('_run_authentik_reconfigure_remote')
    tail = remote[remote.index('_sync_webadmin_after_authentik_reconfigure(plog)'):]
    assert tail.index('_authentik_reconfigure_heal_tak_clients(plog)') < tail.index('_authentik_reconfigure_finish(')
    src = _src('_authentik_reconfigure_heal_tak_clients')
    assert src.index('_tak_ldap_recycle_request(') < src.index('_tak_recycle_after_ldap_outage(')
    assert 'final=True' not in src                     # inside an update it must defer


# ── GH #207: Guard Dog restarting Authentik under a running TAK ─────────────────────

def nodered_feed(n, cn):
    """A Node-RED feed that connected while LDAP was down: no DN, no user, no device uid."""
    return sess(n, cn, (), unmapped=True, client='')


def test_gh207_guard_dog_authentik_restart_is_healed_by_the_periodic_check():
    # Amos: TAK restarted 18:16 by the update; Guard Dog's authentik-watch restarted
    # Authentik at 18:51 (server+worker first, so the outpost start may not move); Node-RED
    # feeds and devices that connected meanwhile stayed on __ANON__ until Node-RED was
    # restarted by hand. The console's 10-min check now heals them without a TAK restart.
    box = outage_box(tak_start=T0 - 40 * 60, ldap_start=T0 - 5 * HOUR, gd_restart=T0 - 5 * 60)
    box.subs.append(nodered_feed(17, 'nodered-global-earthquake'))
    box.ldap_users['nodered-global-earthquake'] = 1
    assert box.recycle(trigger='periodic LDAP outage check', final=False) is False
    assert box.restarts() == []
    assert sorted(box.drops()) == ['tls:16', 'tls:17']
    assert any('Guard Dog restarted Authentik while TAK Server was running (TAK up 0h35m' in l for l in box.log)
    assert box.live('takdev-emu')[0]['groups'] and box.live('nodered-global-earthquake')[0]['groups']
    # the feed can't be matched to its next connection: said as such, not as "offline?"
    assert any('1 dropped with no user and no device id (feeds such as Node-RED' in l for l in box.log)
    assert not any("didn't reconnect" in l for l in box.log)
    st = box.settings['tak_ldap_recycle']
    assert st['healed_gd_restart'] == T0 - 5 * 60 and st['last_trigger'] == 'periodic LDAP outage check'
    # the next tick finds that restart already healed: silent, no Marti calls
    n, logs = len(box.api), len(box.log)
    box.t += 600
    assert box.recycle(trigger='periodic LDAP outage check', final=False) is False
    assert len(box.api) == n and len(box.log) == logs
    # ...a NEW Guard Dog restart is healed again
    box.gd_restart = box.t - 60
    box.recycle(trigger='periodic LDAP outage check', final=False)
    assert len(box.api) > n


def test_guard_dog_restart_before_tak_started_or_at_its_start_is_ignored():
    for gap in (-HOUR, 0, _const('_TAK_LDAP_RECYCLE_MIN_TAK_UPTIME_S') - 1):
        box = outage_box(tak_start=T0 - 2 * HOUR, ldap_start=T0 - 3 * HOUR, gd_restart=T0 - 2 * HOUR + gap)
        assert box.recycle(trigger='periodic LDAP outage check', final=False) is False, gap
        assert box.api == [] and box.restarts() == []


def test_guard_dog_history_is_ignored_with_remote_authentik():
    box = outage_box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=None, gd_restart=T0 - HOUR)
    assert box.recycle(trigger='periodic LDAP outage check', final=False) is False
    assert box.api == [] and box.restarts() == []


def test_guard_dog_restart_during_a_console_update_waits_for_its_end():
    box = outage_box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=T0 - 5 * 24 * HOUR, gd_restart=T0 - 60,
                     update_in_progress=True)
    assert box.recycle(trigger='periodic LDAP outage check', final=False) is False
    assert box.api == [] and box.settings['tak_ldap_recycle']['pending']
    box.t += 300
    assert box.recycle(final=True) is False
    assert box.drops() == ['tls:16'] and box.restarts() == []
    # the kept reason and the same Guard Dog restart, found again, are one reason
    line = [l for l in box.log if 'TAK Server ran through an LDAP outage' in l][-1]
    assert line.count('Guard Dog restarted Authentik') == 1


def test_ldap_not_checkable_is_said_once_per_outage():
    box = outage_box(tak_start=T0 - 4 * 24 * HOUR, ldap_start=T0 - HOUR, gd_restart=T0 - HOUR)
    ns = box.ns()
    ns['_ensure_ldapsearch'] = lambda: False
    ns['_tak_recycle_after_ldap_outage'](box.log.append, 'periodic LDAP outage check', check_outpost=True)
    said = [l for l in box.log if "can't check LDAP" in l]
    ns['_tak_recycle_after_ldap_outage'](box.log.append, 'periodic LDAP outage check', check_outpost=True)
    assert len(said) == 1 and len([l for l in box.log if "can't check LDAP" in l]) == 1
    assert box.restarts() == []


def test_guard_dog_restart_history_is_read_from_its_file(tmp_path):
    ns = {'_GD_AUTHENTIK_RESTART_HIST': str(tmp_path / 'authentik_restart_history')}
    exec(compile(_src('_guarddog_authentik_restart_epoch'), 'app.py', 'exec'), ns)
    f = ns['_guarddog_authentik_restart_epoch']
    assert f() is None                                   # no Guard Dog / never restarted
    (tmp_path / 'authentik_restart_history').write_text('1792546000\n1792549600\n\ngarbage\n1792548000\n')
    assert f() == 1792549600.0
    (tmp_path / 'authentik_restart_history').write_text('')
    assert f() is None
    # the path Guard Dog writes (tak-authentik-watch.sh RESTART_HIST under STATE_DIR)
    assert re.search(r"^_GD_AUTHENTIK_RESTART_HIST = '/var/lib/takguard/authentik_restart_history'$", APP, re.M)
    with open(os.path.join(REPO, 'scripts', 'guarddog', 'tak-authentik-watch.sh')) as g:
        watch = g.read()
    assert 'STATE_DIR="/var/lib/takguard"' in watch and 'RESTART_HIST="$STATE_DIR/authentik_restart_history"' in watch
    assert '{ awk -v c="$cutoff"' in watch and 'echo "$now"; } > "$RESTART_HIST.tmp"' in watch


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
