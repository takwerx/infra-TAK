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
"""Manual bans on the Fail2ban page (infra-TAK #313).

An operator keeps a list of addresses and ranges to block, with a note, permanent or for a
number of days, and can edit and remove them. The list is the source of truth; a dedicated
fail2ban jail enforces it. The functions run from the shipped app.py text.
"""

import ast
import ipaddress
import os
import pathlib
import re
import secrets
import threading
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (REPO / 'templates' / 'fail2ban.html').read_text(encoding='utf-8')

FUNCS = ('_f2b_manual_jail_text', '_f2b_manual_net', '_f2b_manual_label', '_f2b_manual_overlap',
         '_f2b_manual_protected_reason', '_f2b_manual_load', '_f2b_manual_save',
         '_f2b_manual_active', '_f2b_manual_banned', '_f2b_manual_reconcile',
         '_f2b_manual_view', '_f2b_manual_days', '_f2b_manual_clean_note')
CONSTS = ('_F2B_MANUAL_JAIL', '_F2B_MANUAL_JAIL_PATH', '_F2B_MANUAL_FILTER_PATH',
          '_F2B_MANUAL_MAX_NOTE', '_F2B_MANUAL_MAX_DAYS', '_F2B_MANUAL_MIN_PREFIX',
          '_F2B_MANUAL_FILTER')


def _seg(node):
    return ast.get_source_segment(APP, node)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return _seg(n)
    raise AssertionError(f'{name} was renamed or removed')


def _consts(*names):
    out = [_seg(n) for n in TREE.body
           if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in names for t in n.targets)]
    assert len(out) == len(names), names
    return '\n'.join(out)


class Box:
    """A fake box: settings in memory, a fake fail2ban-client, a trusted list."""

    def __init__(self, trusted='127.0.0.1/8 ::1 10.0.0.0/24 192.0.2.50', jail_loaded=True):
        self.settings = {}
        self.trusted = trusted
        self.banned = {}           # text -> True
        self.calls = []
        self.files = {}
        self.jail_loaded = jail_loaded
        self.jail_file = True      # the jail file is written the first time a ban lands
        fake_os = types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: self.jail_file))
        ns = {'re': re, 'os': fake_os, 'time': time, 'secrets': secrets, 'ipaddress': ipaddress,
              'threading': threading, '_F2B_MANUAL_LOCK': threading.RLock(), 'subprocess': types.SimpleNamespace(run=self._run)}
        exec(_consts(*CONSTS), ns)
        for f in FUNCS:
            exec(_func(f), ns)
        ns.update(
            load_settings=lambda: dict(self.settings),
            save_settings=lambda s: self.settings.update(s),
            _sudo_wrap=lambda c: c,
            _f2b_is_available=lambda: True,
            _f2b_trusted_ignoreip=lambda extra='': self.trusted,
            _f2b_banaction=lambda: 'ufw',
            _f2b_loaded_jails=lambda: ['sshd', 'infratak-manual'] if self.jail_loaded else ['sshd'],
            _f2b_parse_status=self._parse,
            _f2b_manual_ensure_jail=lambda: '',
        )
        self.ns = ns

    @staticmethod
    def _parse(raw):
        return {'banned_ips': raw.split()}

    def _run(self, cmd, **kw):
        self.calls.append(list(cmd))
        r = types.SimpleNamespace(returncode=0, stdout='', stderr='')
        if cmd[:2] == ['fail2ban-client', 'status']:
            r.stdout = ' '.join(self.banned)
        elif 'banip' in cmd:
            self.banned[cmd[-1]] = True
        elif 'unbanip' in cmd:
            self.banned.pop(cmd[-1], None)
        return r

    def __getattr__(self, name):
        return self.__dict__['ns'][name]

    def add(self, target, days=None, note=''):
        self.settings.setdefault('fail2ban_manual_bans', []).append({
            'id': secrets.token_hex(4), 'target': target, 'note': note,
            'created': int(time.time()),
            'expires': None if days is None else int(time.time()) + days * 86400})


# ── 1. What can be typed ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize('text,label', [
    ('203.0.113.7', '203.0.113.7'),
    (' 203.0.113.7 ', '203.0.113.7'),
    ('203.0.113.0/24', '203.0.113.0/24'),
    ('203.0.113.7/32', '203.0.113.7'),
    ('2001:db8::/32', '2001:db8::/32'),
    ('2001:db8::1', '2001:db8::1'),
])
def test_accepts_addresses_and_ranges(text, label):
    b = Box()
    assert b.ns['_f2b_manual_label'](b.ns['_f2b_manual_net'](text)) == label


@pytest.mark.parametrize('text', [
    '', '   ', 'hello', '203.0.113', '203.0.113.256', '1.2.3.4; reboot', '1.2.3.4 5.6.7.8',
    '$(id)', '../etc', '203.0.113.0/33', '203.0.113.0/-1', '203.0.113.0/', 'a' * 100,
    '0.0.0.0/0', '10.0.0.0/7', '::/0', '2001:db8::/16',
])
def test_refuses_junk_and_ranges_too_wide(text):
    b = Box()
    with pytest.raises(ValueError):
        b.ns['_f2b_manual_net'](text)


def test_range_with_host_bits_set_suggests_the_real_range():
    b = Box()
    with pytest.raises(ValueError, match=r'203\.0\.113\.0/24'):
        b.ns['_f2b_manual_net']('203.0.113.9/24')


# ── 2. Nobody locks themselves out ───────────────────────────────────────────────────

def test_refuses_your_own_address_and_any_range_containing_it():
    b = Box()
    for t in ('198.51.100.20', '198.51.100.0/24', '198.51.100.0/24'):
        why = b.ns['_f2b_manual_protected_reason'](b.ns['_f2b_manual_net'](t), '198.51.100.20')
        assert why and 'your own address' in why


def test_refuses_the_boxs_own_and_trusted_networks_and_anything_inside_or_around_them():
    b = Box()
    net = b.ns['_f2b_manual_net']
    for t in ('127.0.0.1', '10.0.0.0/24', '10.0.0.77', '10.0.0.0/16', '192.0.2.50', '192.0.2.0/24', '::1'):
        assert b.ns['_f2b_manual_protected_reason'](net(t)), t


def test_other_addresses_are_allowed():
    b = Box()
    net = b.ns['_f2b_manual_net']
    for t in ('203.0.113.7', '203.0.113.0/24', '10.0.1.0/24', '2001:db8::/32'):
        assert b.ns['_f2b_manual_protected_reason'](net(t), '198.51.100.20') is None, t


def test_ipv4_entry_is_not_compared_with_an_ipv6_trusted_entry():
    b = Box(trusted='::1 2001:db8::/32')
    assert b.ns['_f2b_manual_protected_reason'](b.ns['_f2b_manual_net']('203.0.113.7')) is None


# ── 3. Ban length and notes ──────────────────────────────────────────────────────────

def test_days_blank_or_zero_means_permanent():
    b = Box()
    for v in (None, 0, '0', ''):
        assert b.ns['_f2b_manual_days'](v) is None


def test_days_counts_from_now():
    b = Box()
    exp = b.ns['_f2b_manual_days'](7)
    assert abs(exp - (time.time() + 7 * 86400)) < 5


@pytest.mark.parametrize('v', [-1, 3651, 'x', 1.5e12, [], {}])
def test_bad_days_are_refused(v):
    b = Box()
    with pytest.raises(ValueError):
        b.ns['_f2b_manual_days'](v)


def test_note_has_control_characters_removed_and_is_capped():
    b = Box()
    assert b.ns['_f2b_manual_clean_note']('scanner\r\n\tseen\x00 Oct 27 ') == 'scanner seen Oct 27'
    with pytest.raises(ValueError):
        b.ns['_f2b_manual_clean_note']('x' * 201)


# ── 4. The list is what the jail enforces ────────────────────────────────────────────

def test_reconcile_bans_what_is_missing_and_lifts_what_is_gone():
    b = Box()
    b.add('203.0.113.7', note='scanner')
    b.add('203.0.113.0/24', days=30)
    b.banned['198.51.100.1'] = True        # left behind by a removed entry
    res = b.ns['_f2b_manual_reconcile']()
    assert res['errors'] == []
    assert set(b.banned) == {'203.0.113.7', '203.0.113.0/24'}


def test_a_ban_that_ran_out_is_lifted():
    b = Box()
    b.add('203.0.113.7', days=-1)
    b.banned['203.0.113.7'] = True
    b.ns['_f2b_manual_reconcile']()
    assert b.banned == {}


def test_permanent_entry_never_expires():
    b = Box()
    b.add('203.0.113.7')
    b.ns['_f2b_manual_reconcile']()
    assert '203.0.113.7' in b.banned
    assert b.ns['_f2b_manual_view'](b.ns['_f2b_manual_load']()[0], b.ns['_f2b_manual_banned'](),
                                    now=time.time() + 10 * 365 * 86400)['state'] == 'banned'


def test_address_added_to_the_trusted_list_later_wins_over_an_older_entry():
    b = Box()
    b.add('203.0.113.7')
    b.ns['_f2b_manual_reconcile']()
    assert '203.0.113.7' in b.banned
    b.trusted += ' 203.0.113.0/24'
    b.ns['_f2b_manual_reconcile']()
    assert b.banned == {}
    state = b.ns['_f2b_manual_view'](b.ns['_f2b_manual_load']()[0], {}, )['state']
    assert state == 'protected'


def test_reconcile_is_quiet_when_already_in_sync():
    b = Box()
    b.add('203.0.113.7')
    b.ns['_f2b_manual_reconcile']()
    b.calls.clear()
    b.ns['_f2b_manual_reconcile']()
    assert not [c for c in b.calls if 'banip' in c or 'unbanip' in c]


def test_ban_commands_use_the_manual_jail_with_the_address_as_one_argument():
    b = Box()
    b.add('203.0.113.0/24')
    b.ns['_f2b_manual_reconcile']()
    ban = [c for c in b.calls if 'banip' in c]
    assert ban == [['fail2ban-client', 'set', 'infratak-manual', 'banip', '203.0.113.0/24']]


def test_nothing_happens_on_a_box_that_never_used_the_feature():
    b = Box()
    b.jail_file = False
    assert b.ns['_f2b_manual_reconcile']() == {'errors': [], 'banned': {}}
    assert b.calls == []


def test_a_stored_entry_that_is_not_an_address_is_ignored_not_run():
    b = Box()
    b.settings['fail2ban_manual_bans'] = [
        {'id': 'a', 'target': '1.2.3.4; rm -rf /', 'note': '', 'created': 1, 'expires': None},
        {'id': 'b', 'target': '203.0.113.7', 'note': 'ok', 'created': 1, 'expires': None},
        'junk', 7, None]
    assert [e['target'] for e in b.ns['_f2b_manual_load']()] == ['203.0.113.7']


def test_view_states():
    b = Box()
    ban = b.ns['_f2b_manual_view']
    net = b.ns['_f2b_manual_net']
    live = {'id': 'x', 'target': '203.0.113.7', 'note': '', 'created': 1, 'expires': None}
    assert ban(live, {net('203.0.113.7'): '203.0.113.7'})['state'] == 'banned'
    assert ban(live, {})['state'] == 'pending'
    assert ban(live, None)['state'] == 'pending'
    assert ban(dict(live, expires=int(time.time()) - 5), {})['state'] == 'expired'
    assert ban(dict(live, target='10.0.0.9'), {})['state'] == 'protected'


# ── 5. The jail ──────────────────────────────────────────────────────────────────────

def test_jail_is_permanent_on_every_port_and_never_fed_by_a_log():
    b = Box()
    conf = b.ns['_f2b_manual_jail_text']()
    assert re.search(r'^bantime\s*=\s*-1$', conf, re.M)
    assert re.search(r'^action\s*=\s*ufw$', conf, re.M)
    assert 'ignoreip = 127.0.0.1/8 ::1 10.0.0.0/24 192.0.2.50' in conf
    filt = b.ns['_F2B_MANUAL_FILTER']
    regex = re.search(r'^failregex = (.*)$', filt, re.M).group(1).replace('<HOST>', r'\S+')
    for line in ('2026-10-27 10:00:00,000 fail2ban.actions [1]: NOTICE  [sshd] Ban 203.0.113.7',
                 'Failed password for root from 203.0.113.7', ''):
        assert not re.search(regex, line)


def test_recidive_does_not_re_ban_manual_bans():
    m = re.search(r'"ignoreregex = (.*?)\\n"', _func('_f2b_write_recidive_config'))
    ign = re.compile(m.group(1).encode().decode('unicode_escape'))
    assert ign.search('NOTICE  [infratak-manual] Ban 203.0.113.7')
    assert ign.search('NOTICE  [takserver] Ban 203.0.113.7')
    assert not ign.search('NOTICE  [sshd] Ban 203.0.113.7')


def test_jail_is_kept_in_step_when_the_trusted_list_changes_and_removed_on_uninstall():
    assert "_F2B_MANUAL_JAIL_PATH" in _func('_f2b_rewrite_all_jails')
    assert '_F2B_MANUAL_JAIL_PATH' in _func('fail2ban_uninstall_api')
    assert '_F2B_MANUAL_FILTER_PATH' in _func('fail2ban_uninstall_api')


def test_recidive_conf_is_updated_before_the_first_manual_ban_lands():
    fn = _func('_f2b_manual_ensure_jail')
    assert '_f2b_write_recidive_config' in fn and '_F2B_MANUAL_JAIL not in _rec' in fn


# ── 6. Routes ────────────────────────────────────────────────────────────────────────

def _route_decorators(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return [ast.unparse(d) for d in n.decorator_list]
    raise AssertionError(name)


def test_every_manual_ban_route_needs_a_login():
    for fn, paths in (('fail2ban_manual_bans_api', "'/api/fail2ban/manual-bans'"),
                      ('fail2ban_manual_ban_item_api', "'/api/fail2ban/manual-bans/<ban_id>'")):
        decos = _route_decorators(fn)
        assert 'login_required' in decos, fn
        assert any(paths in d for d in decos), fn


def test_routes_refuse_a_ban_that_includes_the_callers_own_address():
    add = _func('fail2ban_manual_bans_api')
    edit = _func('fail2ban_manual_ban_item_api')
    assert '_f2b_manual_protected_reason(net, client_ip)' in add
    assert '_f2b_manual_protected_reason(net, client_ip)' in edit
    # the caller's address is read from the connection, never taken from the request body
    assert 'client_ip = _f2b_console_client_ip()' in add and "data.get('client" not in add


def test_a_ban_fail2ban_did_not_apply_is_not_kept():
    add = _func('fail2ban_manual_bans_api')
    assert '_f2b_manual_save(entries)' in add        # rolled back
    assert "'ok': False" in add and '500' in add


# ── 7. The card ──────────────────────────────────────────────────────────────────────

def _manual_js():
    start = TEMPLATE.index('// Manual bans')
    end = TEMPLATE.index('async function fail2banUninstall')
    return TEMPLATE[start:end]


def test_card_is_on_the_page_with_its_fields():
    for ident in ('f2b-manual-card', 'f2b-manual-target', 'f2b-manual-note', 'f2b-manual-days',
                  'f2b-manual-save', 'f2b-manual-list'):
        assert f'id="{ident}"' in TEMPLATE, ident


def test_page_text_from_the_list_is_never_put_in_as_html():
    js = _manual_js()
    assert 'innerHTML' not in js and 'insertAdjacentHTML' not in js
    assert 'b.note' in js and 'textContent' in js


def test_card_talks_to_the_manual_ban_routes():
    js = _manual_js()
    assert "'/api/fail2ban/manual-bans'" in js
    assert "method:editingId?'PUT':'POST'" in js and "method:'DELETE'" in js
