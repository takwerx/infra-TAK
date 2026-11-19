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
"""A module on an old Node.js gets the security email and the red card flag (ops #296).

The Node inside a module's image is baked in at build time, so a module on its latest
release can still run a Node from before a Node security release (CVE-2026-111497).
NODE_SECURITY_RELEASES is the one table; the email and the console card both read it.
The functions are cut out of app.py and run with docker faked.
"""

import json
import pathlib
import re
import subprocess as _real_subprocess
import threading
import time
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
CONSOLE = (REPO / 'templates' / 'console.html').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    # the module-level assignment, up to the first blank line (none of these has one inside)
    return re.search(rf'^{name} = .*?\n(?=\n)', APP, re.S | re.M).group(0)


NODE_FUNCS = ('_node_version_tuple', '_node_releases_missing', '_node_container_versions',
              '_node_security_gaps', '_node_security_items', '_node_card_gaps', '_node_card_flag')
NODE_CONSTS = ('NODE_SECURITY_RELEASES', 'NODE_MODULE_CONTAINERS', 'NODE_SECURITY_CACHE_S')

PS = (
    'authentik-server-1||server\n'
    'tak-portal|tak-portal|tak-portal\n'
    'tak-portal-worker|tak-portal|tak-portal-worker\n'
    'tak-portal-postgres|tak-portal|postgres\n'
    'cloudtak-api-1|cloudtak|api\n'
    'cloudtak-events-1|cloudtak|events\n'
    'cloudtak-media-1|cloudtak|media\n'
    'cloudtak-postgis-1|cloudtak|postgis\n'
    'nodered|node-red|node-red\n'
    'eud-remote-assist-server-1|eud-remote-assist|server\n'
    'eud-remote-assist-web-1|eud-remote-assist|web\n'
)
FIXED = {'tak-portal': 'v22.23.5', 'tak-portal-worker': 'v22.23.5', 'cloudtak-api-1': 'v26.13.1',
         'cloudtak-events-1': 'v26.13.1', 'nodered': 'v22.23.5',
         'eud-remote-assist-server-1': 'v22.23.5',
         'cloudtak-media-1': 'v24.22.0'}   # upstream image: must never be looked at


def _ns(node_by_container, ps=PS, ps_rc=0):
    """app.py's Node functions with docker faked. node_by_container: name → 'v22.23.0',
    or an Exception / None for a container whose `node` does not answer."""
    execs = []

    def fake_run(argv, *a, **k):
        argv = list(argv)[1:]   # drop the _sudo_wrap marker
        if argv[:2] == ['docker', 'ps']:
            return _real_subprocess.CompletedProcess(argv, ps_rc, ps, 'daemon down' if ps_rc else '')
        assert argv[:2] == ['docker', 'exec'] and argv[3:] == ['node', '--version']
        execs.append(argv[2])
        v = node_by_container.get(argv[2])
        if isinstance(v, BaseException):
            raise v
        if v is None:
            return _real_subprocess.CompletedProcess(argv, 126, '', 'node: not found')
        return _real_subprocess.CompletedProcess(argv, 0, v + '\n', '')

    n = {
        're': re, 'time': time, 'threading': threading,
        'subprocess': types.SimpleNamespace(run=fake_run),
        '_sudo_wrap': lambda argv: ['BROKER'] + list(argv),
        'print': lambda *a, **k: None,
    }
    src = '\n'.join([_const(c) for c in NODE_CONSTS] + [_cut(f) for f in NODE_FUNCS])
    exec(compile(src, 'app.py', 'exec'), n)
    n['_execs'] = execs
    return n


# ── the version table ─────────────────────────────────────────────────────────

def test_versions_below_the_fix_are_flagged_and_fixed_ones_are_not():
    n = _ns({})
    missing = n['_node_releases_missing']
    for v in ('v22.23.3', '22.23.0', 'v24.22.0', 'v24.21.9', 'v26.12.0', 'v26.11.9'):
        assert [r['id'] for r in missing(v)] == ['CVE-2026-111497', 'CVE-2026-123864'], v
    # ops #824: the 2026-11-11 release is the only one a module on the previous fix is below
    for v in ('v22.23.4', 'v24.22.1', 'v24.22.2', 'v26.12.1', 'v26.13.0'):
        assert [r['id'] for r in missing(v)] == ['CVE-2026-123864'], v
    for v in ('v22.23.5', 'v22.24.0', 'v24.22.3', 'v26.13.1', 'v26.14.0'):
        assert missing(v) == [], v


def test_unknown_major_or_unparseable_version_claims_nothing():
    n = _ns({})
    for v in ('v20.19.0', 'v28.0.0', '', None, 'node: not found', 'v22.23'):
        assert n['_node_releases_missing'](v) == [], v


def test_table_covers_the_fixed_versions_from_the_advisory():
    n = _ns({})
    old, new = n['NODE_SECURITY_RELEASES']
    assert old['id'] == 'CVE-2026-111497'
    assert old['fixed'] == {22: '22.23.4', 24: '24.22.1', 26: '26.12.1'}
    # ops #824: Node 22.23.5 / 24.22.3 / 26.13.1, 2026-11-11 (nodejs.org november-2026-security-releases)
    assert new['id'] == 'CVE-2026-123864' and new['released'] == '2026-11-11'
    assert new['fixed'] == {22: '22.23.5', 24: '24.22.3', 26: '26.13.1'}


def test_node_red_is_claimed_now_that_its_pin_is_on_a_node_22_23_5_image():
    # ops #935: nodered/node-red:4.1.18-22 (pushed 2026-11-17) is on Node 22.23.5, so Update can
    # clear the flag and Node-RED on 22.23.4 is flagged like every other module (it was left out
    # in ops #824 while its upstream had no rebuild). Red when 'nodered' is still upstream_pending.
    n = _ns({})
    assert [r['id'] for r in n['_node_releases_missing']('v22.23.4', 'nodered')] == ['CVE-2026-123864']
    assert [r['id'] for r in n['_node_releases_missing']('v22.23.3', 'nodered')] == [
        'CVE-2026-111497', 'CVE-2026-123864']
    assert n['_node_releases_missing']('v22.23.5', 'nodered') == []
    assert sorted(n['_node_security_gaps']({'nodered': {'nodered': 'v22.23.4'}})) == ['nodered']
    assert n['_node_security_gaps']({'nodered': {'nodered': 'v22.23.5'}}) == {}
    # Print (Node 24, never built by CloudTAK Update) is still the one left out
    assert n['NODE_SECURITY_RELEASES'][-1]['upstream_pending'] == ('cloudtak-print',)


def test_a_module_on_the_previous_fix_is_flagged_for_the_new_release():
    # the proof test for ops #824: red on dev (22.23.4 was "fixed"), green with the new entry
    n = _ns({})
    gaps = n['_node_security_gaps']({'takportal': {'tak-portal': 'v22.23.4', 'tak-portal-worker': 'v22.23.4'},
                                     'remote_assist': {'eud-remote-assist-server-1': 'v22.23.4'}})
    assert sorted(gaps) == ['remote_assist', 'takportal']
    items = n['_node_security_items']({'takportal': {'tak-portal': 'v22.23.4'}})
    assert items[0]['identity'] == 'node-CVE-2026-123864'
    assert 'Newer Node.js fixes CVE-2026-123864:' in items[0]['security'][0]


# ── which containers are looked at ────────────────────────────────────────────

def test_only_the_node_containers_of_the_four_modules_are_probed():
    n = _ns(FIXED)
    got = n['_node_container_versions']()
    assert got == {
        'takportal': {'tak-portal': 'v22.23.5', 'tak-portal-worker': 'v22.23.5'},
        'cloudtak': {'cloudtak-api-1': 'v26.13.1', 'cloudtak-events-1': 'v26.13.1'},
        'nodered': {'nodered': 'v22.23.5'},
        'remote_assist': {'eud-remote-assist-server-1': 'v22.23.5'},
    }
    # not Postgres, nginx, Authentik, or the CloudTAK media helper
    assert set(n['_execs']) == {'tak-portal', 'tak-portal-worker', 'cloudtak-api-1',
                                'cloudtak-events-1', 'nodered', 'eud-remote-assist-server-1'}


def test_docker_not_listable_raises_and_unanswering_container_is_none():
    import pytest
    with pytest.raises(RuntimeError):
        _ns(FIXED, ps_rc=1)['_node_container_versions']()
    got = _ns(dict(FIXED, nodered=None, **{'tak-portal': subprocess_timeout()}))['_node_container_versions']()
    assert got['nodered'] == {'nodered': None} and got['takportal']['tak-portal'] is None


def subprocess_timeout():
    return _real_subprocess.TimeoutExpired('docker', 10)


# ── the email items ───────────────────────────────────────────────────────────

def test_old_node_makes_one_security_item_per_module():
    old = dict(FIXED, **{'tak-portal': 'v22.23.0', 'tak-portal-worker': 'v22.23.4',
                         'cloudtak-api-1': 'v26.12.0', 'nodered': 'v22.23.1'})
    n = _ns(old)
    items = n['_node_security_items'](n['_node_container_versions']())
    assert [i['key'] for i in items] == ['node:cloudtak', 'node:nodered', 'node:takportal']
    tp = items[2]
    assert tp['identity'] == 'node-CVE-2026-111497+CVE-2026-123864'
    assert tp['summary'] == 'Node.js inside TAK Portal is out of date'
    assert tp['security'][0].startswith('TAK Portal is running Node.js v22.23.0. Newer Node.js fixes CVE-2026-111497:')
    assert 'actively attacked' in tp['security'][0] and 'CVE-2026-123864' in tp['security'][0]
    assert tp['how'] == 'Open TAK Portal in infra-TAK and press Update.'


def test_fixed_node_makes_no_items():
    n = _ns(FIXED)
    assert n['_node_security_items'](n['_node_container_versions']()) == []
    assert n['_node_security_gaps']({}) == {}


def test_unanswering_container_is_not_reported_as_old_or_fixed():
    n = _ns(dict(FIXED, nodered=None))
    assert n['_node_security_items'](n['_node_container_versions']()) == []


def test_identity_changes_when_the_next_node_release_ships():
    n = _ns({'tak-portal': 'v22.23.0'})
    versions = n['_node_container_versions']()
    a = n['_node_security_items'](versions)[0]['identity']
    n['NODE_SECURITY_RELEASES'] = n['NODE_SECURITY_RELEASES'] + (
        {'id': 'CVE-2026-999999', 'released': '2026-12-01', 'fixed': {22: '22.24.0'}, 'reason': 'next one'},)
    b = n['_node_security_items'](versions)[0]['identity']
    assert a == 'node-CVE-2026-111497+CVE-2026-123864'
    assert b == 'node-CVE-2026-111497+CVE-2026-123864+CVE-2026-999999'
    # a box that took the first fixes but not the next is flagged for the next only
    n2 = n['_node_security_items']({'takportal': {'tak-portal': 'v22.23.5'}})
    assert n2[0]['identity'] == 'node-CVE-2026-999999'


# ── the sweep: a box on old Node gets the email, a box on fixed Node does not ──

def _sweep(node_by_container, state, ps_rc=0, settings=None):
    sent, saved = [], []
    n = _ns(node_by_container, ps_rc=ps_rc)
    n.update({
        'os': types.SimpleNamespace(path=types.SimpleNamespace(
            isdir=lambda p: False, expanduser=lambda p: p, join=lambda *a: '/'.join(a))),
        'socket': types.SimpleNamespace(gethostname=lambda: 'box'),
        'load_settings': lambda: dict({'guarddog_alert_email': 'ops@example.com', 'fqdn': 'tak.example.com',
                                       'console_port': 5001, 'update_channel': 'main'}, **(settings or {})),
        '_safe_alert_email_list': lambda v: v,
        '_gd_quiet_state': lambda: (False, 0, ''),
        '_guarddog_server_identifier': lambda s: 'tak-prod-1',
        '_update_notify_state_load': lambda: json.loads(json.dumps(state)),
        '_update_notify_state_save': lambda s: saved.append(s),
        '_guarddog_send_alert_email_via_relay': lambda to, subj, body: sent.append((subj, body)),
        '_console_pending_update': lambda s: None,
        '_os_security_items': lambda seen, unknown, now=None: [],
        '_postgres_security_items': lambda unknown: [],   # ops #754
        '_java_restart_items': lambda unknown: [],   # ops #963
        '_postgres_remote_security_items': lambda unknown: [],   # ops #760
        '_detect_cloudtak_plugins': lambda: [],
        '_apply_security_identity': lambda i: i,
        'time': time,
        'PATCH_NOW_REPEAT_S': 24 * 3600,
        '_collect_patch_now_items': lambda feed, unknown, now=None: ([], feed),   # ops #377
    })
    src = '\n'.join(_cut(f) for f in ('_collect_pending_updates', '_carried_by_unknown',
                                       '_update_notify_check_once'))
    exec(compile(src, 'app.py', 'exec'), n)
    return n['_update_notify_check_once'](), sent, saved


def test_box_on_old_node_gets_the_security_email():
    old = dict(FIXED, **{'tak-portal': 'v22.23.0', 'tak-portal-worker': 'v22.23.0'})
    r, sent, saved = _sweep(old, {})
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '🔒 Security update pending on tak-prod-1 — update this machine'
    assert body.startswith('SECURITY UPDATE: you should update this machine (tak-prod-1).')
    assert '  • Node.js inside TAK Portal is out of date' in body
    assert 'CVE-2026-111497' in body and 'v22.23.0' in body
    assert '      Fix it from the infra-TAK console: Open TAK Portal in infra-TAK and press Update.' in body
    assert saved[-1] == {'node:takportal': 'node-CVE-2026-111497+CVE-2026-123864'}


def test_box_on_the_previous_fix_gets_the_email_for_the_new_release():
    # ops #824: TAK Portal and Remote Assist on 22.23.4 (the fix before 22.23.5) are told to press Update
    old = dict(FIXED, **{'tak-portal': 'v22.23.4', 'tak-portal-worker': 'v22.23.4',
                         'eud-remote-assist-server-1': 'v22.23.4'})
    r, sent, saved = _sweep(old, {})
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '🔒 Security update pending on tak-prod-1 — update this machine'
    assert '  • Node.js inside TAK Portal is out of date' in body
    assert '  • Node.js inside Remote Assist is out of date' in body
    assert 'Newer Node.js fixes CVE-2026-123864:' in body and 'v22.23.4' in body
    assert 'Open Remote Assist in infra-TAK and press Update.' in body
    assert saved[-1] == {'node:remote_assist': 'node-CVE-2026-123864', 'node:takportal': 'node-CVE-2026-123864'}


def test_node_red_on_22_23_4_gets_the_email_now_that_its_image_is_rebuilt():
    # ops #935: 4.1.18-22 is on Node 22.23.5, so a box still on 4.1.17-22 (Node 22.23.4) is told to
    # press Update, and Update (the pin move in _auto_nodered) clears it. Was "no email" in ops #824.
    r, sent, saved = _sweep(dict(FIXED, nodered='v22.23.4'), {})
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '🔒 Security update pending on tak-prod-1 — update this machine'
    assert '  • Node.js inside Node-RED is out of date' in body
    assert 'Newer Node.js fixes CVE-2026-123864:' in body and 'v22.23.4' in body
    assert saved[-1] == {'node:nodered': 'node-CVE-2026-123864'}


PS_PRINT = PS + 'cloudtak-print|cloudtak|cloudtak-print\n'


def test_print_plugin_on_node_24_22_2_is_not_flagged_for_the_new_release():
    # ops #824: the CloudTAK card's Update never builds Print (its compose file is kept out of
    # COMPOSE_FILE), so a CloudTAK flag for it would stay red after Update. Print is also plain HTTP.
    n = _ns(dict(FIXED, **{'cloudtak-print': 'v24.22.2'}), ps=PS_PRINT)
    versions = n['_node_container_versions']()
    assert versions['cloudtak']['cloudtak-print'] == 'v24.22.2'
    assert n['_node_security_gaps'](versions) == {}
    assert n['_node_security_items'](versions) == []


def test_print_plugin_on_an_older_node_24_is_still_flagged_for_the_earlier_release():
    # the exclusion covers the 2026-11-11 release only; the earlier fix (24.22.1) still counts
    n = _ns(dict(FIXED, **{'cloudtak-print': 'v24.22.0'}), ps=PS_PRINT)
    gaps = n['_node_security_gaps'](n['_node_container_versions']())
    assert list(gaps) == ['cloudtak']
    assert [r['id'] for r in gaps['cloudtak']['releases']] == ['CVE-2026-111497']


def test_box_on_fixed_node_gets_no_email():
    r, sent, saved = _sweep(FIXED, {})
    assert r == {'pending': [], 'emailed': False} and sent == [] and saved == []


def test_same_old_node_mails_once_then_again_for_the_next_release():
    old = dict(FIXED, nodered='v22.23.1')
    # ops #935: Node-RED is claimed for both releases now, so its identity names both
    state = {'node:nodered': 'node-CVE-2026-111497+CVE-2026-123864'}
    r, sent, _ = _sweep(old, state)
    assert sent == [] and r['emailed'] is False
    # once the operator updated, the entry is pruned so a later regression mails again
    _, sent, saved = _sweep(FIXED, state)
    assert sent == [] and saved == [{}]


def test_docker_blip_keeps_the_dedup_state():
    state = {'node:nodered': 'node-CVE-2026-111497', 'node:takportal': 'node-CVE-2026-111497'}
    r, sent, saved = _sweep(FIXED, state, ps_rc=1)
    assert sent == [] and saved == []   # state unchanged: nothing pruned, nothing rewritten


def test_unanswering_container_keeps_that_modules_dedup_state():
    state = {'node:nodered': 'node-CVE-2026-111497'}
    _, sent, saved = _sweep(dict(FIXED, nodered=None), state)
    assert sent == [] and saved == []   # state unchanged: nothing pruned, nothing rewritten


def test_update_emails_disabled_and_no_alert_address_still_mean_no_node_email():
    old = dict(FIXED, nodered='v22.23.1')
    for settings in ({'guarddog_update_email_enabled': False}, {'guarddog_alert_email': ''}):
        r, sent, _ = _sweep(old, {}, settings=settings)
        assert sent == [] and r['emailed'] is False


# ── the card flag ─────────────────────────────────────────────────────────────

def test_card_flag_names_the_node_the_cve_and_the_button():
    n = _ns({'nodered': 'v22.23.1'})
    gap = n['_node_security_gaps'](n['_node_container_versions']())['nodered']
    assert n['_node_card_flag'](gap) == (
        'Security update: Node.js on this module is out of date (v22.23.1, CVE-2026-111497, CVE-2026-123864). Press Update.')


def test_card_gaps_come_from_the_same_probe_and_are_cached():
    n = _ns({'nodered': 'v22.23.1'})
    n['_node_card_cache'] = {'at': 0.0, 'gaps': {}, 'busy': False}
    n['_node_card_gaps']()                       # starts the refresh, serves the (empty) cache
    deadline = time.time() + 5
    while n['_node_card_cache']['busy'] and time.time() < deadline:
        time.sleep(0.01)
    assert list(n['_node_card_gaps']()) == ['nodered']
    seen = len(n['_execs'])
    n['_node_card_gaps']()
    assert len(n['_execs']) == seen              # fresh cache: no new docker calls


def test_console_cards_show_the_flag_and_the_api_adds_it_as_a_copy():
    assert "d.node_security" in CONSOLE and 'Node.js out of date' in CONSOLE
    assert "result[key] = {**result[key], 'node_security': _node_card_flag(gap)}" in APP


# ── Update rebuilds on the newest Node ────────────────────────────────────────

def test_cloudtak_deploy_and_update_pull_the_base_image_before_building():
    # the CloudTAK builds use --no-cache, which does not re-fetch the FROM image (ops #135)
    assert len(re.findall(r'_pull_base_images\(cloudtak_dir, wrap=_sudo_wrap, plog=plog\)', APP)) == 2
