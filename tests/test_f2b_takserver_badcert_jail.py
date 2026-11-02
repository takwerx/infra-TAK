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
"""The takserver-badcert jail and the help-desk view (v10.3.4, W2–W6).

A phone TAK refuses after a CA rotation/revoke is a real device: it is banned only for a
flood, only for 10 min, and never from enrollment (8446). recidive doesn't escalate it, the
Fail2ban page and ban e-mail say it can re-enroll, every box converges at start, and the
page names the device (callsign, user, the cert's issuer). The functions run from the
shipped app.py text.
"""

import ast
import os
import pathlib
import re
import time
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (REPO / 'templates' / 'fail2ban.html').read_text(encoding='utf-8')

BC_JAIL = '/etc/fail2ban/jail.d/infratak-takserver-badcert.conf'
BC_FILTER = '/etc/fail2ban/filter.d/takserver-badcert.conf'
BC_ACT = '/etc/fail2ban/action.d/infratak-guarddog-takserver-badcert.conf'
TAK_JAIL = '/etc/fail2ban/jail.d/infratak-takserver.conf'
TAK_ACT = '/etc/fail2ban/action.d/infratak-guarddog-takserver.conf'

BC_CONSTS = ('_F2B_TAK_BADCERT_PORTS_TCP', '_F2B_TAK_BADCERT_JAIL_PATH', '_F2B_TAK_BADCERT_FILTER_PATH',
             '_F2B_TAK_BADCERT_ACTION_PATH', '_F2B_TAK_BADCERT_MAXRETRY', '_F2B_TAK_BADCERT_FINDTIME',
             '_F2B_TAK_BADCERT_BANTIME', '_F2B_TAK_BADCERT_GUARDDOG_ACTION', '_F2B_OWNED_FILTERS')
BC_FUNCS = ('_f2b_banaction_tak_badcert', '_f2b_tak_badcert_jail_text', '_f2b_tak_badcert_prereqs',
            '_f2b_write_tak_badcert_jail_config')


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _consts(*names):
    out = [ast.get_source_segment(APP, n) for n in TREE.body
           if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in names for t in n.targets)]
    assert len(out) == len(names), names
    return '\n'.join(out)


def _ns(consts=(), funcs=(), **extra):
    ns = {'re': re, 'os': os, 'time': time}
    ns.update(extra)
    exec(_consts(*consts) if consts else '', ns)
    for f in funcs:
        exec(_func(f), ns)
    return ns


class _Box:
    """A fake /etc/fail2ban: files, and the commands run against it, in order."""

    def __init__(self, files=None, loaded=None):
        self.files = dict(files or {})
        self.order = []
        self.cmds = []
        self.loaded = loaded or []

    def read(self, path):
        return self.files.get(path)

    def write(self, path, content, **_k):
        self.files[path] = content
        self.order.append(path)

    def exists(self, path):
        return path in self.files

    def run(self, cmd, **_k):
        self.cmds.append(cmd)


def _box_ns(box, consts=(), funcs=(), **extra):
    fake_os = types.SimpleNamespace(path=types.SimpleNamespace(exists=box.exists))
    return _ns(consts=BC_CONSTS + tuple(consts), funcs=BC_FUNCS + tuple(funcs),
               _makedirs_priv=lambda *a, **k: None, _write_priv=box.write, _f2b_read_text=box.read,
               _f2b_trusted_ignoreip=lambda extra='': ('127.0.0.1/8 ::1 ' + extra).strip(),
               _sudo_wrap=lambda c: c, subprocess=types.SimpleNamespace(run=box.run), os=fake_os, **extra)


# ── W2: the jail ─────────────────────────────────────────────────────────────────────

def test_badcert_ban_never_blocks_enrollment():
    ns = _ns(consts=('_F2B_TAK_PORTS_TCP', '_F2B_TAK_BADCERT_PORTS_TCP'), funcs=('_f2b_banaction_tak_badcert',))
    action = ns['_f2b_banaction_tak_badcert']()
    ports = set(re.search(r'port="([^"]+)"', action).group(1).split(','))
    assert '8446' not in ports
    assert ports == set(ns['_F2B_TAK_PORTS_TCP'].split(',')) - {'8446'}
    assert action.startswith('iptables-multiport[name=takserver-badcert,')


def test_badcert_jail_is_a_flood_guard_with_fleet_constants():
    box = _Box({TAK_ACT: 'x'})
    ns = _box_ns(box)
    ns['_f2b_write_tak_badcert_jail_config']('198.51.100.50')
    conf = box.files[BC_JAIL]
    assert re.search(r'^maxretry = 600$', conf, re.M)
    assert re.search(r'^findtime = 300$', conf, re.M)
    assert re.search(r'^bantime  = 600$', conf, re.M)
    assert re.search(r'^filter   = takserver-badcert$', conf, re.M)
    assert re.search(r'^backend  = auto$', conf, re.M)
    assert 'ignoreip = 127.0.0.1/8 ::1 198.51.100.50' in conf
    assert 'infratak-guarddog-takserver-badcert' in conf


def test_filter_and_action_go_down_before_the_jail():
    box = _Box({TAK_ACT: 'x'})
    ns = _box_ns(box)
    ns['_f2b_write_tak_badcert_jail_config']('')
    assert box.order == [BC_FILTER, BC_ACT, BC_JAIL]
    assert box.files[BC_FILTER] == ns['_F2B_OWNED_FILTERS']['takserver-badcert']
    assert 'infratak-f2b-notify <ip> takserver-badcert' in box.files[BC_ACT]


def test_no_guarddog_action_when_the_takserver_jail_has_none():
    box = _Box()
    ns = _box_ns(box)
    ns['_f2b_write_tak_badcert_jail_config']('')
    assert BC_ACT not in box.files and 'guarddog' not in box.files[BC_JAIL]


def test_an_operator_edited_badcert_filter_is_left_alone():
    box = _Box({BC_FILTER: '# mine\n'})
    ns = _box_ns(box)
    ns['_f2b_write_tak_badcert_jail_config']('')
    assert box.files[BC_FILTER] == '# mine\n'


def test_every_takserver_jail_write_writes_badcert_with_the_same_whitelist():
    src = _func('_f2b_write_tak_jail_config')
    assert '_f2b_write_tak_badcert_jail_config(ignoreip)' in src


def test_disabling_the_tak_jail_removes_both():
    src = _func('fail2ban_tak_config_api')
    assert "for jail_path in ('/etc/fail2ban/jail.d/infratak-takserver.conf', _F2B_TAK_BADCERT_JAIL_PATH)" in src


def test_uninstall_removes_the_badcert_files():
    src = _func('fail2ban_uninstall_api')
    for name in ('_F2B_TAK_BADCERT_JAIL_PATH', '_F2B_TAK_BADCERT_FILTER_PATH', '_F2B_TAK_BADCERT_ACTION_PATH'):
        assert name in src


# ── W3: recidive ─────────────────────────────────────────────────────────────────────

def test_recidive_ignores_badcert_bans():
    written = {}
    ns = _ns(consts=('_F2B_RECIDIVE_BANTIME',), funcs=('_f2b_banaction', '_f2b_write_recidive_config'),
             _distro_family=lambda: 'debian', _makedirs_priv=lambda *a, **k: None,
             _write_priv=lambda p, c, **k: written.__setitem__(p, c),
             _read_priv=lambda p: '[Definition]\ndbfile = x\n', _sudo_wrap=lambda c: c,
             _f2b_trusted_ignoreip=lambda extra='': '127.0.0.1/8',
             subprocess=types.SimpleNamespace(run=lambda *a, **k: None))
    ns['_f2b_write_recidive_config'](3, 86400)
    ign = re.compile(re.search(r'^ignoreregex = (.*)$', written['/etc/fail2ban/jail.d/infratak-recidive.conf'],
                               re.M).group(1))
    line = '2026-11-01 20:59:50,001 fail2ban.actions        [811]: NOTICE  [%s] Ban 203.0.113.9'
    assert ign.search(line % 'takserver-badcert') and ign.search(line % 'takserver')
    assert not ign.search(line % 'sshd')


def test_recidive_converge_reaches_boxes_that_already_exempt_takserver():
    box = _Box({'/etc/fail2ban/jail.d/infratak-recidive.conf': 'ignoreregex = \\[(?:mediamtx-rtsp|takserver)\\] Ban\n'})
    rewrites = []
    ns = _ns(funcs=('_startup_converge_recidive_tak_exempt',), _f2b_recidive_enabled=lambda: True,
             _f2b_read_text=box.read, _f2b_read_recidive_config=lambda: {'maxretry': 3, 'findtime': 86400},
             _f2b_write_recidive_config=lambda m, f: rewrites.append((m, f)), _sudo_wrap=lambda c: c,
             subprocess=types.SimpleNamespace(run=box.run))
    ns['_startup_converge_recidive_tak_exempt']()
    assert rewrites == [(3, 86400)]


# ── W4: wording, e-mail, status, unban ───────────────────────────────────────────────

def _notify_module():
    ns = _ns(consts=('_F2B_NOTIFY_SCRIPT',))
    mod = types.ModuleType('infratak_f2b_notify')
    exec(compile(ns['_F2B_NOTIFY_SCRIPT'], 'infratak-f2b-notify', 'exec'), mod.__dict__)
    return mod


def test_badcert_ban_says_it_can_still_re_enroll_on_the_page_and_in_the_email():
    ns = _ns(funcs=('_f2b_tak_ban_explain',))
    mod = _notify_module()
    msg = ns['_f2b_tak_ban_explain']('203.0.113.9', 'bad_cert', '', '10 min', 'takserver-badcert')
    assert msg == ("A device at 203.0.113.9 kept failing TAK's certificate check, so it's blocked from "
                   "TAK streaming for 10 min. It can still re-enroll: scan a fresh QR.")
    for kind in ('bad_cert', 'no_cert', 'not_tak', 'other'):
        for subject in ('', 'CN=x'):
            for jail in ('takserver', 'takserver-badcert'):
                assert ns['_f2b_tak_ban_explain']('203.0.113.9', kind, subject, '10 min', jail) == \
                    mod._tak_explain('203.0.113.9', kind, subject, '10 min', jail)


def test_badcert_ban_email_reads_the_badcert_jail_and_says_8446_is_open(tmp_path):
    mod = _notify_module()
    log = tmp_path / 'm.log'
    log.write_text('2026-11-01-09:56:23.112 [x] ERROR y - NioNettyServerHandler error. Cause: '
                   'javax.net.ssl.SSLHandshakeException: General OpenSslEngine problem. Additional info: '
                   'Remote address: 203.0.113.9; Remote port: 1; Local port: 8089; '
                   'Certificate error: peer not verified; \n')
    jail = tmp_path / 'bc.conf'
    jail.write_text('[takserver-badcert]\nbantime  = 600\n')
    mod.TAK_LOG, mod.TAK_BADCERT_JAIL, mod.TAK_JAIL = str(log), str(jail), str(tmp_path / 'none')
    text = mod._tak_reason('203.0.113.9', 'takserver-badcert')
    assert text.startswith("A device at 203.0.113.9 kept failing TAK's certificate check, so it's blocked "
                           "from TAK streaming for 10 min. It can still re-enroll: scan a fresh QR.")
    assert 'Enrollment (8446)' in text


def test_status_merges_both_jails_and_tags_each_ban():
    src = _func('fail2ban_tak_status_api')
    assert "'fail2ban-client', 'status', 'takserver-badcert'" in src
    assert "status['ban_jail']" in src
    assert "'takserver-badcert', lines)" in src


def test_unban_releases_both_jails():
    src = _func('fail2ban_tak_unban_api')
    assert "jails.append('takserver-badcert')" in src
    assert "'set', jail, 'unbanip', ip" in src
    assert '_VALID_IP_RE.match(ip)' in src


def test_page_tags_badcert_bans_and_says_enrollment_stays_open():
    assert "streaming only · can re-enroll" in TEMPLATE
    assert "never from enrollment (8446)" in TEMPLATE
    assert "window._takBanJail = d.ban_jail || {};" in TEMPLATE


# ── W5: Devices TAK is refusing ──────────────────────────────────────────────────────

PFX = '2026-11-01-%s.112 [x] ERROR y - NioNettyServerHandler error. Cause: '
REFUSED = PFX + ('javax.net.ssl.SSLHandshakeException: General OpenSslEngine problem. Additional info: '
                 'Remote address: 172.56.182.200; Remote port: 1; Local port: 8089; Certificate error: peer not verified; ')
SCANNER = PFX + ('io.netty.handler.ssl.NotSslRecordException: not an SSL/TLS record. Additional info: '
                 'Remote address: 198.51.100.7; Remote port: 2; Local port: 8089; Certificate error: peer not verified; ')
SUB = ('2026-11-01-%s.399 [CallsignAssignmentExecutor-0] INFO c.b.m.s.DistributedSubscriptionManager - '
       'Set client for subscription: tls:12 to %s (%s) source=%s:48545')


def _refused_ns():
    return _ns(consts=('_F2B_TAK_FAIL_RE', '_F2B_TAK_SUBJECT_RE', '_F2B_TAK_TS_RE', '_F2B_TAK_SUB_RE',
                       '_F2B_TAK_REFUSED_WINDOW'),
               funcs=('_f2b_tak_failure_kind', '_f2b_tak_log_epoch', '_f2b_tak_refused'))


def _t(hms):
    return time.mktime(time.strptime('2026-11-01-' + hms, '%Y-%m-%d-%H:%M:%S'))


def test_a_refused_address_is_named_by_its_last_subscription_before_the_first_refusal():
    ns = _refused_ns()
    lines = [SUB % ('17:21:58', 'CA-COR-E5-P', 'ANDROID-e41b59dc273cb019', '172.56.182.200'),
             SUB % ('17:30:00', 'SOMEONE-ELSE', 'ANDROID-other', '172.56.182.200')]
    lines += [REFUSED % f'17:51:{s:02d}' for s in range(24, 44)]
    lines += [SUB % ('17:55:00', 'LATER-DEVICE', 'ANDROID-later', '172.56.182.200'), SCANNER % '17:52:00']
    refused, _subs, uid_ip = ns['_f2b_tak_refused'](lines, _t('17:58:00'))
    rec = refused['172.56.182.200']
    assert (rec['count'], rec['kind'], rec['callsign'], rec['uid']) == (20, 'bad_cert', 'SOMEONE-ELSE', 'ANDROID-other')
    assert rec['first'] == _t('17:51:24') and rec['last'] == _t('17:51:43')
    assert refused['198.51.100.7']['kind'] == 'not_tak' and refused['198.51.100.7']['uid'] == ''
    assert uid_ip['ANDROID-e41b59dc273cb019'] == '172.56.182.200'


def test_only_the_last_30_minutes_count_but_identity_uses_the_whole_tail():
    ns = _refused_ns()
    lines = [SUB % ('16:00:00', 'CA-COR-E5-P', 'ANDROID-e41b59dc273cb019', '172.56.182.200'),
             REFUSED % '16:10:00', REFUSED % '17:50:00']
    refused, _s, _u = ns['_f2b_tak_refused'](lines, _t('18:00:00'))
    assert refused['172.56.182.200']['count'] == 1
    assert refused['172.56.182.200']['callsign'] == 'CA-COR-E5-P'
    assert ns['_f2b_tak_refused']([REFUSED % '16:10:00'], _t('18:00:00'))[0] == {}


def test_refused_route_is_read_only_behind_login_and_device_text_never_reaches_sql():
    i = APP.index("@app.route('/api/fail2ban/takserver/refused')")
    assert APP[i:i + 200].split('\n')[1] == '@login_required'
    src = _func('_f2b_tak_cert_rows')
    sql = src[src.index('sql = ('):src.index('r = _cot_pg_exec(')]
    assert '_cot_pg_exec(' in src and '{' not in sql and 'f"' not in sql and "f'" not in sql and '%' not in sql
    assert '_cot_pg_exec' not in _func('fail2ban_tak_refused_api')       # only via the fixed-SQL helper


def test_a_failed_cert_lookup_is_surfaced_not_swallowed():
    ns = _ns(consts=('_F2B_TAK_CERT_ROWS_TTL', '_F2B_TAK_CERT_ROWS_CACHE'), funcs=('_f2b_tak_cert_rows',),
             _cot_pg_exec=lambda a, timeout=30: types.SimpleNamespace(returncode=2, stdout='',
                                                                       stderr='psql: connection refused'))
    rows, err = ns['_f2b_tak_cert_rows']()
    assert rows is None and 'connection refused' in err


def test_cert_rows_keep_each_uids_newest_row():
    out = 'ANDROID-e41b\ttest2bse\t2108913716\tf\t-----BEGIN CERTIFICATE-----QUJD-----END CERTIFICATE-----\n'
    ns = _ns(consts=('_F2B_TAK_CERT_ROWS_TTL', '_F2B_TAK_CERT_ROWS_CACHE'), funcs=('_f2b_tak_cert_rows',),
             _cot_pg_exec=lambda a, timeout=30: types.SimpleNamespace(returncode=0, stdout=out, stderr=''))
    rows, err = ns['_f2b_tak_cert_rows']()
    assert err == '' and rows['ANDROID-e41b']['user'] == 'test2bse'
    assert rows['ANDROID-e41b']['pem'] == '-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n'
    assert 'DISTINCT ON (client_uid)' in _func('_f2b_tak_cert_rows')


def test_page_lists_refused_devices_escaped_with_unban():
    assert 'id="tak-refused-panel"' in TEMPLATE
    assert "/api/fail2ban/takserver/refused" in TEMPLATE
    assert "_takEsc(r.callsign || r.uid)" in TEMPLATE
    assert "(no longer trusted)" in TEMPLATE
    assert "/^[0-9a-fA-F:.]+$/.test(r.ip)" in TEMPLATE        # the onclick never carries device text


# ── W6: converge ─────────────────────────────────────────────────────────────────────

def _converge(box):
    healed = []
    ns = _box_ns(box, funcs=('_startup_converge_tak_badcert',),
                 _f2b_tak_jail_enabled=lambda: TAK_JAIL in box.files,
                 _f2b_read_tak_jail_config=lambda: {'ignoreip': '127.0.0.1/8 ::1 198.51.100.50'},
                 _f2b_operator_extra=lambda s: '198.51.100.50',
                 _f2b_selfheal_filters=lambda plog=None: healed.append(1),
                 _f2b_loaded_jails=lambda: list(box.loaded))
    return ns, healed


def test_converge_adds_the_jail_on_a_box_with_the_takserver_jail():
    box = _Box({TAK_JAIL: 'x', TAK_ACT: 'x'}, loaded=['takserver'])
    ns, healed = _converge(box)
    ns['_startup_converge_tak_badcert']()
    assert 'ignoreip = 127.0.0.1/8 ::1 198.51.100.50' in box.files[BC_JAIL]
    assert BC_FILTER in box.files and BC_ACT in box.files and healed == [1]
    assert box.cmds == [['fail2ban-client', 'reload']]
    box.loaded.append('takserver-badcert')
    ns['_startup_converge_tak_badcert']()                     # second start: nothing to do
    assert box.cmds == [['fail2ban-client', 'reload']]


def test_converge_restarts_an_existing_jail_whose_file_changed():
    box = _Box({TAK_JAIL: 'x', BC_FILTER: 'f', BC_JAIL: 'old'}, loaded=['takserver', 'takserver-badcert'])
    ns, _h = _converge(box)
    ns['_startup_converge_tak_badcert']()
    assert box.cmds == [['fail2ban-client', 'reload', '--restart', 'takserver-badcert']]


def test_converge_loads_a_jail_written_but_not_loaded():
    box = _Box({TAK_JAIL: 'x', BC_FILTER: 'f'}, loaded=['takserver'])
    ns, _h = _converge(box)
    box.files[BC_JAIL] = ns['_f2b_tak_badcert_jail_text']('198.51.100.50')
    ns['_startup_converge_tak_badcert']()
    assert box.cmds == [['fail2ban-client', 'reload']]


def test_converge_never_creates_anything_without_the_takserver_jail():
    box = _Box({TAK_ACT: 'x'})
    ns, healed = _converge(box)
    ns['_startup_converge_tak_badcert']()
    assert set(box.files) == {TAK_ACT} and box.cmds == [] and healed == []


def test_converge_runs_after_the_broker_gate_before_recidive():
    body = APP[APP.index('def _startup_migrations('):]
    assert body.index('_startup_converge_tak_banaction()') < body.index('_startup_converge_tak_badcert()') \
        < body.index('_startup_converge_recidive_tak_exempt()')


# ── Added in T&E (operator, 2026-11-01) ──────────────────────────────────────────────

def test_callsigns_also_come_from_yesterdays_rotated_log(tmp_path):
    import gzip
    logs = tmp_path / 'logs'
    logs.mkdir()
    for day, cs in (('2026-10-31', 'OLDER'), ('2026-11-01', 'CA-COR-E5-P')):
        with gzip.open(logs / f'takserver-messaging.{day}.log.gz', 'wt') as f:
            f.write('2026-11-01-17:00:00.000 [x] INFO y - unrelated line\n')
            f.write(SUB % ('17:21:58', cs, 'ANDROID-e41b59dc273cb019', '172.56.182.200') + '\n')
    src = _func('_f2b_tak_prev_sub_lines').replace("'/opt/tak/logs/", repr(str(logs) + '/')[:-1])
    ns = _ns(consts=('_F2B_TAK_PREV_SUBS_CACHE',))
    exec(src, ns)
    lines = ns['_f2b_tak_prev_sub_lines']()
    assert len(lines) == 1 and 'CA-COR-E5-P' in lines[0]          # newest file, sub lines only
    assert 'lines = _f2b_tak_prev_sub_lines() + (_diag_tail(' in _func('fail2ban_tak_refused_api')


def test_containers_and_whitelisted_addresses_are_named_not_unknown():
    src = _func('fail2ban_tak_refused_api')
    assert "'container': containers.get(rec['ip'], '')" in src and "'whitelisted': _f2b_ip_in(rec['ip'], nets)" in src
    runs = []

    def run(cmd, **k):
        runs.append(cmd)
        out = 'nodered\ncloudtak-api-1\n' if cmd[1] == 'ps' else '/nodered 172.21.0.2 \n/cloudtak-api-1 172.20.0.7 172.22.0.6 \n'
        return types.SimpleNamespace(returncode=0, stdout=out, stderr='')
    ns = _ns(consts=('_F2B_CONTAINER_IPS_CACHE',), funcs=('_f2b_container_ip_names',),
             _sudo_wrap=lambda c: c, subprocess=types.SimpleNamespace(run=run))
    m = ns['_f2b_container_ip_names']()
    assert m == {'172.21.0.2': 'nodered', '172.20.0.7': 'cloudtak-api-1', '172.22.0.6': 'cloudtak-api-1'}
    ns['_f2b_container_ip_names']()
    assert len(runs) == 2                                   # cached
    assert "(a container on this box)" in TEMPLATE and "whitelisted, never banned" in TEMPLATE


def test_refused_search_box_is_cyan_so_it_is_seen():
    i = TEMPLATE.index('id="tak-refused-search"')
    tag = TEMPLATE[i:TEMPLATE.index('>', i)]
    assert 'border:1px solid var(--cyan)' in tag and 'color:var(--cyan)' in tag


def test_jail_cards_collapse_to_their_header():
    for card in ('recidive-card', 'f2b-manual-card', 'auth-jail-card', 'ssh-jail-card',
                 'mediamtx-jail-card', 'takportal-jail-card', 'tak-jail-card'):
        assert f'id="{card}"' in TEMPLATE and f"'{card}'" in TEMPLATE, card
    assert '.f2b-collapsed > :not(.card-title){display:none !important}' in TEMPLATE
    assert "ev.target.closest('label, button, input, a, select, .toggle-wrap')" in TEMPLATE   # toggle still works
    assert "localStorage.setItem(k, open ? '1' : '0')" in TEMPLATE
