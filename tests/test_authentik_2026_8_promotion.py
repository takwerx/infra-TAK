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
"""Authentik 2026.5.7 → 2026.8.4 promotion (v10.2.25).

Two upstream 2026.8 changes would have broken boxes on the day the pin moved:

* 2026.8 refuses to start on a database that skipped a release family
  (lifecycle/migrate.py ensure_allowed_version, VERSION_FAMILY_PREVIOUS = "2026.5"). A box
  still on 2026.2.x pressing Update would crash-loop server + worker, and TAK's LDAP with
  them. Update/Reconfigure now go one family at a time via AUTHENTIK_UPGRADE_STEPS.
* 2026.8 honours X-Forwarded-* only from AUTHENTIK_LISTEN__TRUSTED_PROXY_CIDRS. On a REMOTE
  Authentik host, Caddy on the console connects from the console IP, outside our CIDRs, so
  the remote .env now also trusts exactly that IP.

app.py cannot be imported in a test, so the helpers are cut out of the shipped text.
"""

import ast
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TEMPLATE = (REPO / 'templates' / 'authentik.html').read_text(encoding='utf-8')
_FUNCS = {'_ak_ver_tuple', '_ak_upgrade_hop', '_get_authentik_target_release',
          '_authentik_remote_trusted_proxy_cidrs', '_fedhub_caddy_source_ip'}
_CONSTS = {'AUTHENTIK_VETTED_RELEASE', 'AUTHENTIK_DEV_RELEASE', 'AUTHENTIK_UPGRADE_STEPS',
           'AK_TRUSTED_PROXY_CIDRS'}

# Upstream's own rule, from authentik/__init__.py + lifecycle/migrate.py at each tag: a
# release starts only on a database from its own family or VERSION_FAMILY_PREVIOUS.
UPSTREAM_FAMILY_PREVIOUS = {(2026, 8): (2026, 5)}


def _nodes():
    out = {}
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name in _FUNCS:
            out[node.name] = ast.get_source_segment(APP, node)
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
              and getattr(node.targets[0], 'id', None) in _CONSTS):
            out[node.targets[0].id] = ast.get_source_segment(APP, node)
    assert set(out) == _FUNCS | _CONSTS, 'a name under test was renamed or removed'
    return out


NODES = _nodes()


def _ns(settings=None, latest=None):
    ns = {'re': re, 'load_settings': lambda: dict(settings or {}),
          '_get_authentik_latest_release_tag': lambda: latest}
    exec(compile('\n\n'.join(NODES.values()), 'app.py', 'exec'), ns)
    return ns


def _fn_src(name):
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def _family(v):
    return tuple(int(x) for x in re.findall(r'\d+', v))[:2]


def test_pins_promoted_to_2026_8_4():
    ns = _ns()
    assert ns['AUTHENTIK_VETTED_RELEASE'] == '2026.8.4'
    assert ns['AUTHENTIK_DEV_RELEASE'] == '2026.8.4'
    assert ns['AUTHENTIK_UPGRADE_STEPS'] == ('2026.5.7',)


@pytest.mark.parametrize('installed,expected', [
    ('2026.2.7', '2026.5.7'),     # one family behind upstream's floor → step first
    ('2026.2.0', '2026.5.7'),
    ('2025.10.3', '2026.5.7'),
    ('2026.5.6', '2026.8.4'),     # the previous family: straight through, as upstream allows
    ('2026.5.7', '2026.8.4'),
    ('2026.8.1', '2026.8.4'),     # same family
    ('', '2026.8.4'),             # nothing readable → fresh DB, upstream lets it through
    ('latest', '2026.8.4'),
    ('2026', '2026.8.4'),
])
def test_upgrade_hop(installed, expected):
    assert _ns()['_ak_upgrade_hop'](installed, '2026.8.4') == expected


def test_hop_never_overshoots_a_target_inside_the_step_family():
    hop = _ns()['_ak_upgrade_hop']
    assert hop('2026.2.7', '2026.5.7') == '2026.5.7'
    assert hop('2026.2.7', '2026.5.8') == '2026.5.8'


@pytest.mark.parametrize('start', ['2025.10.3', '2026.2.0', '2026.2.7', '2026.5.6', '2026.8.1'])
def test_every_hop_chain_satisfies_upstream_skip_guard(start):
    """Walk Update presses from `start` to the vetted pin: each hop that lands on a family
    with an upstream skip guard must come from that family or its VERSION_FAMILY_PREVIOUS."""
    ns = _ns({'update_channel': 'main'})
    cur, presses = start, 0
    while cur != ns['AUTHENTIK_VETTED_RELEASE']:
        nxt = ns['_get_authentik_target_release'](installed=cur)
        floor = UPSTREAM_FAMILY_PREVIOUS.get(_family(nxt))
        if floor:
            assert _family(cur) in (floor, _family(nxt)), f'{cur} -> {nxt} is a family skip'
        cur, presses = nxt, presses + 1
        assert presses <= 3
    assert presses <= 2


def test_target_release_main_and_dev_channels():
    main = _ns({'update_channel': 'main'})['_get_authentik_target_release']
    assert main() == '2026.8.4'                           # fresh install: the pin itself
    assert main(installed='2026.2.7') == '2026.5.7'
    assert main(installed='2026.5.7') == '2026.8.4'
    dev = _ns({'update_channel': 'dev'}, latest='2026.8.5')['_get_authentik_target_release']
    assert dev() == '2026.8.5'
    assert dev(installed='2026.2.7') == '2026.5.7'
    offline = _ns({'update_channel': 'dev'}, latest=None)['_get_authentik_target_release']
    assert offline() == '2026.8.4'


def test_steps_are_ascending_and_below_the_pin():
    ns = _ns()
    steps = [_family(s) for s in ns['AUTHENTIK_UPGRADE_STEPS']]
    assert steps == sorted(steps)
    assert all(s < _family(ns['AUTHENTIK_VETTED_RELEASE']) for s in steps)


def test_existing_install_paths_pass_the_running_version():
    ctrl = _fn_src('authentik_control')
    # remote + local Update branches both ask for the hop from what is running
    assert ctrl.count("_get_authentik_target_release(") == 2
    assert 'installed=_get_authentik_version_info().get(\'version\')' in ctrl
    assert '_get_authentik_target_release(settings, installed=_inst)' in ctrl
    # local: the running version is read BEFORE the target is chosen
    assert ctrl.index("_inst = (_get_authentik_version_info()") < ctrl.index(
        '_get_authentik_target_release(settings, installed=_inst)')
    # the recorded update outcome names the hop, not the final pin
    assert re.search(r"to_fn=lambda: _get_authentik_target_release\(\s*load_settings\(\), "
                     r"installed=_get_authentik_version_info\(\)\.get\('version'\)\)", APP)
    # Reconfigure: hop for an existing compose, channel target for a fresh download
    assert ("installed=None if _compose_fresh_download else "
            "_get_authentik_version_info().get('version'))") in APP


def test_version_info_offers_the_hop_and_says_so():
    info = _fn_src('_get_authentik_version_info')
    assert "out['final_target'] = _get_authentik_target_release(_s)" in info
    assert "_ak_upgrade_hop(out['version'], out['final_target'])" in info
    assert "out['upgrade_step'] = target != out['final_target']" in info
    assert "out['latest'] = target" in info
    assert TEMPLATE.count('ak_version_info.upgrade_step') == 3      # 2 tooltips + confirm
    assert 'v{{ ak_version_info.final_target }}' in TEMPLATE


# ── trusted proxies on a REMOTE Authentik host ───────────────────────────────

BASE = '172.16.0.0/12,127.0.0.1/32,::1/128'


@pytest.mark.parametrize('server_ip,expected', [
    ('203.0.113.7', BASE + ',203.0.113.7/32'),
    ('10.0.4.20', BASE + ',10.0.4.20/32'),
    ('172.20.0.5', BASE),                 # already inside 172.16/12 — nothing to add
    ('', None),
    ('127.0.0.1', None),
    ('localhost', None),
    ('1.2.3', None),
    ('1.2.3. 4', None),                   # int(' 4') passes the old check; ipaddress does not
    ('1.2.3.4;id', None),
])
def test_remote_trusted_proxy_cidrs(server_ip, expected):
    ns = _ns()
    assert ns['AK_TRUSTED_PROXY_CIDRS'] == BASE
    assert ns['_authentik_remote_trusted_proxy_cidrs']({'server_ip': server_ip}) == expected


def test_remote_deploy_env_and_update_trust_the_console():
    deploy = _fn_src('_run_authentik_deploy_remote')
    assert 'AUTHENTIK_LISTEN__TRUSTED_PROXY_CIDRS={_trusted_cidrs}{cookie_line}' in deploy
    assert '_trusted_cidrs = _authentik_remote_trusted_proxy_cidrs(settings)' in deploy
    ctrl = _fn_src('authentik_control')
    conv = ctrl.index('_tpc = _authentik_remote_trusted_proxy_cidrs(settings)')
    # converged on the remote BEFORE the recreate, so the new image starts with it
    assert conv < ctrl.index("_mod_result_step('authentik', 'pull + recreate (remote)')")
    seg = ctrl[conv:ctrl.index("_mod_result_step('authentik', 'pull + recreate (remote)')")]
    assert 'if _tpc:' in seg and ".env" in seg
    # local fixer keeps writing the shared constant
    assert 'value = AK_TRUSTED_PROXY_CIDRS' in _fn_src('_authentik_fix_trusted_proxy_cidrs')
