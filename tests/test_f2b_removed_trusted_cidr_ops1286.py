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
"""An address removed from Fail2ban "Trusted networks" leaves every jail (ops #1286).

A jail file does not say where an ignoreip entry came from. `_f2b_operator_extra` kept
only what is NOT in the trusted list NOW, so a CIDR the operator had just removed looked
like an entry typed into that one jail, and every jail writer put it straight back.
The console-login jail (and authentik, takserver, sshd, mediamtx, takportal) kept an
address the operator had taken off on purpose, so it could never be banned.

The fix remembers removed addresses (settings `fail2ban_ignore_retired`) and strips them
too. The functions run from the shipped app.py text.
"""

import ast
import ipaddress
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

REMOVED = '198.51.100.99'


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _has(name):
    return any(isinstance(n, ast.FunctionDef) and n.name == name for n in TREE.body)


def _const(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


class Box:
    """Settings in memory, plus the real trusted-list functions from app.py."""

    def __init__(self, cidrs='', retired=None):
        self.settings = {'fail2ban_ignore_cidrs': cidrs}
        if retired is not None:
            self.settings['fail2ban_ignore_retired'] = retired
        ns = {'ipaddress': ipaddress, 're': re,
              'load_settings': lambda: dict(self.settings),
              'save_settings': lambda s: self.settings.update(s),
              '_f2b_local_subnets': lambda: ['10.0.0.0/24'],
              '_f2b_mgmt_tunnel_subnets': lambda: [],
              '_f2b_container_subnets': lambda: ['172.18.0.0/16'],
              '_f2b_own_addresses': lambda: ['10.0.0.5']}
        # The helpers that did not exist before the fix are loaded only when present, so
        # this file also runs against the old app.py and fails there for the real reason
        # (the removed address stays in the jail), not for a missing name.
        if _has('_f2b_retired_cidrs'):
            exec(_const('_F2B_RETIRED_MAX'), ns)
        for f in ('_f2b_fleet_ignore_cidrs', '_f2b_retired_cidrs', '_f2b_set_fleet_cidrs',
                  '_f2b_unretire', '_f2b_trusted_ignoreip', '_f2b_operator_extra'):
            if _has(f):
                exec(_func(f), ns)
        ns.setdefault('_f2b_retired_cidrs', lambda: [])
        ns.setdefault('_f2b_unretire', lambda text: None)
        self.ns = ns

    def post_trusted(self, cidrs):
        """What POST /api/fail2ban/trusted-cidrs does to settings."""
        s = dict(self.settings)
        if '_f2b_set_fleet_cidrs' in self.ns:
            self.ns['_f2b_set_fleet_cidrs'](s, cidrs)
        else:                                      # the old route: a plain overwrite
            s['fail2ban_ignore_cidrs'] = ' '.join(cidrs)
        self.settings.update(s)

    def jail_after_rewrite(self, stored):
        """The ignoreip line a jail writer produces from the jail's stored line."""
        return self.ns['_f2b_trusted_ignoreip'](self.ns['_f2b_operator_extra'](stored)).split()


def test_removed_address_is_stripped_from_the_stored_jail_line():
    # The issue's unit test: stored ignoreip ends in the address, the trusted list is empty,
    # and the box remembers the address was on it.
    box = Box(cidrs='', retired=REMOVED)
    stored = '127.0.0.1/8 ::1 10.0.0.0/24 ' + REMOVED
    assert REMOVED not in box.ns['_f2b_operator_extra'](stored).split()
    assert REMOVED not in box.jail_after_rewrite(stored)


def test_trusted_list_removal_reaches_every_jail_rewrite():
    box = Box(cidrs=REMOVED)
    on_disk = box.jail_after_rewrite('127.0.0.1/8 ::1 ' + REMOVED)
    assert REMOVED in on_disk                      # trusted now: every jail has it
    box.post_trusted([])                           # the operator removes it, Save
    assert box.settings['fail2ban_ignore_cidrs'] == ''
    assert REMOVED in box.settings.get('fail2ban_ignore_retired', '').split()
    after = box.jail_after_rewrite(' '.join(on_disk))
    assert REMOVED not in after
    # What must stay: localhost, the box's own network, containers and its own address.
    for keep in ('127.0.0.1/8', '::1', '10.0.0.0/24', '172.18.0.0/16', '10.0.0.5'):
        assert keep in after


def test_other_per_jail_entries_survive_a_removal():
    box = Box(cidrs=REMOVED + ' 203.0.113.0/24')
    box.post_trusted(['203.0.113.0/24'])           # drop one, keep one
    after = box.jail_after_rewrite('127.0.0.1/8 ::1 ' + REMOVED + ' 203.0.113.0/24 192.0.2.77')
    assert REMOVED not in after
    assert '203.0.113.0/24' in after               # still trusted
    assert '192.0.2.77' in after                   # a per-jail entry the operator typed


def test_adding_it_back_trusts_it_again_and_forgets_the_removal():
    box = Box(cidrs=REMOVED)
    box.post_trusted([])
    box.post_trusted([REMOVED])
    assert REMOVED not in box.settings.get('fail2ban_ignore_retired', '').split()
    assert REMOVED in box.jail_after_rewrite('127.0.0.1/8 ::1')


def test_saving_the_same_list_remembers_nothing():
    box = Box(cidrs='')
    box.post_trusted([])                           # the issue's "save the old empty list again"
    assert box.settings.get('fail2ban_ignore_retired', '') == ''


def test_a_jail_save_that_types_the_address_keeps_it():
    # The operator removed it from Trusted networks, then types it into one jail's own
    # whitelist and presses Save. That is a deliberate entry and must survive rewrites.
    box = Box(cidrs='', retired=REMOVED)
    box.ns['_f2b_unretire']('127.0.0.1/8 ::1 ' + REMOVED)
    assert REMOVED not in box.settings.get('fail2ban_ignore_retired', '').split()
    assert REMOVED in box.jail_after_rewrite('127.0.0.1/8 ::1 ' + REMOVED)


def test_retired_list_is_bounded():
    box = Box(cidrs=' '.join(f'192.0.2.{i}' for i in range(1, 251)))
    box.post_trusted([])
    kept = box.settings.get('fail2ban_ignore_retired', '').split()
    assert len(kept) == 200
    assert kept[-1] == '192.0.2.250'               # newest removals are the ones kept


def test_retired_list_never_raises_on_bad_settings():
    box = Box(cidrs='', retired=None)
    box.ns['load_settings'] = lambda: (_ for _ in ()).throw(RuntimeError('settings unreadable'))
    assert box.ns['_f2b_retired_cidrs']() == []
    box.ns['_f2b_unretire'](REMOVED)               # must not raise


# ── wiring: every place that changes the list or writes a jail goes through the helpers ──

def _route_source(fn):
    return _func(fn)


def test_every_writer_of_the_trusted_list_records_removals():
    assert '_f2b_set_fleet_cidrs(s, cleaned)' in _route_source('fail2ban_trusted_cidrs_api')
    assert '_f2b_set_fleet_cidrs(s_cfg, existing)' in _route_source('_f2b_seed_console_client_ignore')
    # No code may assign the setting directly any more (outside the one helper).
    direct = [m.start() for m in re.finditer(r"\[\s*'fail2ban_ignore_cidrs'\s*\]\s*=", APP)]
    helper = _func('_f2b_set_fleet_cidrs')
    assert len(direct) == 1 and "s_cfg['fail2ban_ignore_cidrs'] = ' '.join(new)" in helper, (
        'only _f2b_set_fleet_cidrs may assign fail2ban_ignore_cidrs, so a removal is always remembered')


def test_the_add_my_address_click_goes_through_the_helper():
    click = [n for n in TREE.body if isinstance(n, ast.FunctionDef)
             and '_f2b_set_fleet_cidrs(s_cfg, cidrs)' in ast.get_source_segment(APP, n)]
    assert click, 'the one-click add-my-address route must use _f2b_set_fleet_cidrs'


def test_jail_writers_that_read_the_stored_line_strip_removed_addresses():
    # The guard dog hook rewrite and the authentik enable default used to pass the raw
    # stored line, which carries a removed address straight back into the jail.
    src = APP
    assert re.search(r"_f2b_write_jail_config\(cfg\['maxretry'\], cfg\['findtime'\], cfg\['bantime'\],\s*"
                     r"_f2b_operator_extra\(cfg\.get\('ignoreip', ''\)\)\)", src)
    assert "data.get('ignoreip', _f2b_operator_extra(cfg.get('ignoreip', '')))" in src
    assert "data.get('ignoreip', cfg.get('ignoreip', ''))" not in src


def test_every_per_jail_save_unretires_what_the_operator_typed():
    saves = [n.name for n in TREE.body if isinstance(n, ast.FunctionDef)
             and "data.get('ignoreip'" in ast.get_source_segment(APP, n)]
    assert len(saves) >= 6, saves                  # authentik x2, takserver, sshd, mediamtx, takportal
    for name in saves:
        assert '_f2b_unretire(' in _func(name), f'{name} saves a jail whitelist without _f2b_unretire'
