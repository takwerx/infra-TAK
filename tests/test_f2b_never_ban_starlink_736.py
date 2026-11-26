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
"""'Never ban Starlink addresses' on the Fail2ban page (infra-TAK #736).

Starlink puts many users behind one shared address, so one ban cuts off every drone
and laptop behind it. With the setting on (off by default), the ranges Starlink
publishes are added to every jail's ignoreip and refreshed daily. These tests run the
shipped app.py text against fakes; the real fail2ban check is the box test in the PR.
"""

import ast
import ipaddress
import json
import os
import pathlib
import re
import ssl
import tempfile
import threading
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
PAGE = (REPO / 'templates' / 'fail2ban.html').read_text(encoding='utf-8')

FUNCS = ('_f2b_starlink_state_path', '_f2b_starlink_load', '_f2b_starlink_save',
         '_f2b_starlink_enabled', '_f2b_starlink_cidrs', '_f2b_starlink_known',
         '_f2b_starlink_parse', '_f2b_starlink_fetch', '_f2b_starlink_refresh',
         '_f2b_starlink_status', '_f2b_fleet_ignore_cidrs', '_f2b_trusted_ignoreip',
         '_f2b_operator_extra', '_f2b_hide_starlink', '_f2b_selfheal_trusted_ignoreip')


def _seg(node):
    return ast.get_source_segment(APP, node)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    raise AssertionError(f'{name} not found in app.py (renamed or removed?)')


def _consts():
    out = []
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(
                getattr(t, 'id', '').startswith(('_F2B_STARLINK_', '_f2b_starlink_lock'))
                for t in n.targets):
            out.append(_seg(n))
    return out


def _feed(rows=200, extra=()):
    """A feed shaped like Starlink's real geofeed: /24 v4 and /48 v6 rows."""
    lines = []
    for i in range(rows // 2):
        lines.append(f'98.97.{i}.0/24,US,US-TX,Dallas,')
        lines.append(f'2605:59c8:{i:x}::/48,US,US-TX,Dallas,')
    lines.extend(extra)
    return '\n'.join(lines) + '\n'


class FakeRun:
    """subprocess.run stand-in for fail2ban-client: a fixed jail list and bans."""

    def __init__(self, bans):
        self.bans = bans          # {jail: [ip, ...]}
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(list(cmd))
        out = ''
        if cmd[:2] == ['fail2ban-client', 'status'] and len(cmd) == 2:
            out = 'Status\n|- Number of jail:\t2\n`- Jail list:\t' + ', '.join(self.bans) + '\n'
        elif cmd[:2] == ['fail2ban-client', 'status']:
            out = '`- Banned IP list:\t' + ' '.join(self.bans.get(cmd[2], [])) + '\n'
        return types.SimpleNamespace(returncode=0, stdout=out, stderr='')


@pytest.fixture
def ns(tmp_path):
    """The Starlink helpers and the ignoreip writers from app.py, on a temp config dir
    and a temp jail.d."""
    jaild = tmp_path / 'jail.d'
    jaild.mkdir()
    cfg = tmp_path / 'config'
    cfg.mkdir()
    settings = {}
    src = _consts()
    for name in FUNCS:
        s = _seg(_func(name))
        if name == '_f2b_selfheal_trusted_ignoreip':
            assert "'/etc/fail2ban/jail.d'" in s
            s = s.replace("'/etc/fail2ban/jail.d'", repr(str(jaild)))
        src.append(s)
    run = FakeRun({})
    logs = []
    g = {'os': os, 'json': json, 'time': time, 'tempfile': tempfile, 'ipaddress': ipaddress,
         'threading': threading, 'ssl': ssl, 're': re, 'CONFIG_DIR': str(cfg),
         'load_settings': lambda: dict(settings),
         'save_settings': lambda s: (settings.clear(), settings.update(s)),
         'subprocess': types.SimpleNamespace(run=run), '_sudo_wrap': lambda c: c,
         '_f2b_is_available': lambda: True,
         '_f2b_local_subnets': lambda: ['10.0.0.0/24'],
         '_f2b_mgmt_tunnel_subnets': lambda: [],
         '_f2b_container_subnets': lambda: [],
         '_f2b_own_addresses': lambda: []}

    def _write_priv(path, text, **kw):
        with open(path, 'w') as f:
            f.write(text)
    g['_write_priv'] = _write_priv
    exec('\n\n'.join(src), g)
    fetched = {'text': _feed(), 'calls': 0, 'error': None}

    def _fake_fetch():
        fetched['calls'] += 1
        if fetched['error']:
            raise fetched['error']
        return g['_f2b_starlink_parse'](fetched['text'])
    g['_f2b_starlink_fetch'] = _fake_fetch
    g['_settings'] = settings
    g['_run'] = run
    g['_jaild'] = jaild
    g['_fetched'] = fetched
    g['_logs'] = logs
    return g


def _jail(ns, name, ignoreip):
    p = ns['_jaild'] / f'infratak-{name}.conf'
    p.write_text(f'[{name}]\nenabled = true\nignoreip = {ignoreip}\naction = x\n')
    return p


def _ignoreip(path):
    m = re.search(r'^ignoreip = (.*)$', path.read_text(), re.M)
    return m.group(1).split()


# ── the feed is checked before it can whitelist anything ─────────────────────────────

def test_parse_merges_the_feed(ns):
    cidrs, rows = ns['_f2b_starlink_parse'](_feed(200))
    assert rows == 200
    # 100 adjacent /24s and 100 adjacent /48s merge to a handful of ranges
    assert len(cidrs) < 20
    assert ipaddress.ip_address('98.97.42.7') in ipaddress.ip_network(
        next(c for c in cidrs if c.startswith('98.97.')))
    assert any(':' in c for c in cidrs)


def test_parse_refuses_a_range_wider_than_starlink_holds(ns):
    with pytest.raises(ValueError, match='wider'):
        ns['_f2b_starlink_parse'](_feed(200, extra=['0.0.0.0/0,US,,,']))
    with pytest.raises(ValueError, match='wider'):
        ns['_f2b_starlink_parse'](_feed(200, extra=['2000::/3,US,,,']))


def test_parse_refuses_a_short_or_junk_feed(ns):
    with pytest.raises(ValueError, match='rows'):
        ns['_f2b_starlink_parse'](_feed(20))
    with pytest.raises(ValueError):
        ns['_f2b_starlink_parse']('<html>' + 'x\n' * 500)


def test_parse_drops_private_space(ns):
    cidrs, _ = ns['_f2b_starlink_parse'](_feed(400, extra=['192.168.1.0/24,US,,,']))
    assert not any(c.startswith('192.168.') for c in cidrs)


# ── off by default; on puts the ranges in every jail's ignoreip ──────────────────────

def test_off_by_default_adds_nothing(ns):
    ns['_f2b_starlink_refresh'](force=True)          # a list on disk is not enough
    assert '98.97.' not in ns['_f2b_trusted_ignoreip']()


def test_on_adds_the_ranges(ns):
    ns['_f2b_starlink_refresh'](force=True)
    ns['_settings']['fail2ban_never_ban_starlink'] = True
    got = ns['_f2b_trusted_ignoreip']('203.0.113.5').split()
    assert any(t.startswith('98.97.') for t in got)
    assert '203.0.113.5' in got and '10.0.0.0/24' in got


def test_off_again_strips_them_even_from_a_stored_line(ns):
    ns['_f2b_starlink_refresh'](force=True)
    ns['_settings']['fail2ban_never_ban_starlink'] = True
    stored = ns['_f2b_trusted_ignoreip']('203.0.113.5')
    ns['_settings']['fail2ban_never_ban_starlink'] = False
    # the operator's own entry survives; no Starlink range is kept as if typed
    assert ns['_f2b_operator_extra'](stored).split() == ['203.0.113.5']


def test_page_field_hides_the_ranges(ns):
    ns['_f2b_starlink_refresh'](force=True)
    ns['_settings']['fail2ban_never_ban_starlink'] = True
    stored = ns['_f2b_trusted_ignoreip']('203.0.113.5')
    shown = ns['_f2b_hide_starlink'](stored).split()
    assert '203.0.113.5' in shown and not any(t.startswith('98.97.') for t in shown)


# ── the daily refresh ────────────────────────────────────────────────────────────────

def test_refresh_does_nothing_while_off(ns):
    assert ns['_f2b_starlink_refresh']() == (False, 'off')
    assert ns['_fetched']['calls'] == 0


def test_refresh_skips_a_fresh_list(ns):
    ns['_settings']['fail2ban_never_ban_starlink'] = True
    ns['_f2b_starlink_refresh'](force=True)
    ns['_f2b_starlink_refresh']()
    assert ns['_fetched']['calls'] == 1


def test_failed_download_keeps_the_last_good_list(ns):
    ns['_settings']['fail2ban_never_ban_starlink'] = True
    ns['_f2b_starlink_refresh'](force=True)
    before = ns['_f2b_starlink_cidrs']()
    ns['_fetched']['error'] = OSError('network unreachable')
    ok, detail = ns['_f2b_starlink_refresh'](force=True)
    assert not ok and 'unreachable' in detail
    assert ns['_f2b_starlink_cidrs']() == before and before
    st = ns['_f2b_starlink_status']()
    assert 'unreachable' in st['last_error'] and st['ranges'] == len(before)


def test_tampered_feed_keeps_the_last_good_list(ns):
    ns['_settings']['fail2ban_never_ban_starlink'] = True
    ns['_f2b_starlink_refresh'](force=True)
    before = ns['_f2b_starlink_cidrs']()
    ns['_fetched']['text'] = _feed(200, extra=['0.0.0.0/1,US,,,'])
    assert ns['_f2b_starlink_refresh'](force=True)[0] is False
    assert ns['_f2b_starlink_cidrs']() == before


def test_a_retired_range_leaves_the_jails(ns):
    ns['_settings']['fail2ban_never_ban_starlink'] = True
    ns['_f2b_starlink_refresh'](force=True)
    p = _jail(ns, 'sshd', ns['_f2b_trusted_ignoreip']())
    assert any(t.startswith('98.97.') for t in _ignoreip(p))
    # Starlink stops publishing 98.97.x; the next refresh rewrites the jail without it
    ns['_fetched']['text'] = '\n'.join(f'2605:59c8:{i:x}::/48,US,,,' for i in range(200))
    ok, _ = ns['_f2b_starlink_refresh'](force=True)
    assert ok
    assert not any(t.startswith('98.97.') for t in _ignoreip(p))
    assert any(t.startswith('2605:59c8') for t in _ignoreip(p))


# ── the jails, and bans that already exist ──────────────────────────────────────────

def test_turning_on_rewrites_every_jail_and_releases_starlink_bans(ns):
    ns['_f2b_starlink_refresh'](force=True)
    a = _jail(ns, 'sshd', '127.0.0.1/8 ::1 10.0.0.0/24 203.0.113.5')
    b = _jail(ns, 'recidive', '127.0.0.1/8 ::1 10.0.0.0/24')
    ns['_run'].bans.update({'sshd': ['98.97.3.9', '198.51.100.7'], 'recidive': ['98.97.4.1']})
    ns['_settings']['fail2ban_never_ban_starlink'] = True
    assert ns['_f2b_selfheal_trusted_ignoreip'](force=True) is True
    for p in (a, b):
        assert any(t.startswith('98.97.') for t in _ignoreip(p))
    assert '203.0.113.5' in _ignoreip(a)
    unbans = [c for c in ns['_run'].calls if 'unbanip' in c]
    assert ['fail2ban-client', 'set', 'sshd', 'unbanip', '98.97.3.9'] in unbans
    assert ['fail2ban-client', 'set', 'recidive', 'unbanip', '98.97.4.1'] in unbans
    assert not any('198.51.100.7' in c for c in unbans)     # not Starlink: stays banned
    assert ['fail2ban-client', 'reload'] in ns['_run'].calls


def test_turning_off_removes_them_with_nothing_else_to_trust(ns):
    ns['_f2b_starlink_refresh'](force=True)
    ns['_settings']['fail2ban_never_ban_starlink'] = True
    p = _jail(ns, 'sshd', ns['_f2b_trusted_ignoreip']('203.0.113.5'))
    ns['_settings']['fail2ban_never_ban_starlink'] = False
    # no tunnel, no containers: the startup path would return early; the toggle forces it
    assert ns['_f2b_selfheal_trusted_ignoreip']() is False
    assert ns['_f2b_selfheal_trusted_ignoreip'](force=True) is True
    assert _ignoreip(p) == ['127.0.0.1/8', '::1', '10.0.0.0/24', '203.0.113.5']


# ── wiring: route, login, page, daily thread ────────────────────────────────────────

def test_route_needs_login_and_refuses_without_a_list():
    fn = _func('fail2ban_starlink_api')
    decos = [ast.get_source_segment(APP, d) for d in fn.decorator_list]
    assert "app.route('/api/fail2ban/starlink', methods=['GET', 'POST'])" in decos
    assert 'login_required' in decos
    body = _seg(fn)
    assert '_f2b_starlink_refresh(force=True)' in body
    assert '502' in body                              # no list at all: not turned on
    assert '_f2b_selfheal_trusted_ignoreip(' in body and 'force=True' in body
    assert "isinstance(want, bool)" in body


def test_daily_refresh_thread_is_started():
    assert re.search(r"threading\.Thread\(target=_f2b_starlink_loop, daemon=True", APP)
    loop = _seg(_func('_f2b_starlink_loop'))
    assert '_f2b_starlink_refresh()' in loop


def test_page_has_the_checkbox():
    assert 'id="f2b-starlink-toggle"' in PAGE
    assert "fetch('/api/fail2ban/starlink'" in PAGE
    assert 'Never ban Starlink addresses' in PAGE
    # the trade-off is said on the page
    assert 'nobody on Starlink can be banned' in PAGE
