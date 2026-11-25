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
"""Guard Dog's update mail covers CloudTAK plugins installed from TAK Portal's Marketplace (ops #1253).

Before: the pending-update sweep listed CloudTAK plugins only from the console's own catalog
(the Simulator). A Marketplace install deletes the plugin's .git folder, so the old git compare
(tak-updates-watch.sh, retired in 10.1.69) never saw them either. A customer on Demo Plugin 2.0.0
heard nothing when a newer release, even a security one, came out. Now the sweep reads TAK Portal's own
update answer (sha-cache.json) and mails each plugin update once; a release in
KNOWN_SECURITY_RELEASES (component plugin:<id>) is mailed as a security update.

The functions are cut out of app.py. The fixtures have the shape of the real files on a fleet
box (read Nov 25, 2026).
"""

import json
import pathlib
import re
import subprocess
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

NOW = 1795600000.0                                    # a fixed "now"
FRESH = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(NOW - 300))
STALE = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(NOW - 25 * 3600))

# what TAK Portal holds on a box where Demo Plugin is one release behind (shape of the real files)
SHA_CACHE = {'updatedAt': FRESH, 'byId': {
    'demo-plugin': {'remoteSha': '0b0b0b0bfadda0f47535e927f347c2f619aeccf3',
                   'installedSha': '0a0a0a0aac613ded6bddaf080676b326d1f2fff2',
                   'updateAvailable': True, 'remoteVersion': '2.0.1', 'installedVersion': '2.0.0'},
    'air-aware': {'remoteSha': '1111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                  'installedSha': '2222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                  'updateAvailable': True, 'remoteVersion': '0.3.0', 'installedVersion': '0.2.4'},
    'print': {'remoteSha': '3333333', 'installedSha': '3333333', 'updateAvailable': False,
              'remoteVersion': '1.0.0', 'installedVersion': '1.0.0'},
}}
CATALOG = {'version': 1, 'plugins': [
    {'id': 'demo-plugin', 'name': 'Demo Plugin', 'repo': 'https://github.com/takwerx/cloudtak-demo-plugin-plugin.git',
     'ref': 'main'},
    {'id': 'air-aware', 'name': 'Air Aware', 'repo': 'https://example.invalid/air-aware.git', 'ref': 'main'},
    {'id': 'print', 'name': 'Print', 'repo': 'https://example.invalid/print.git', 'ref': 'main'},
]}


FIXTURE_RELEASE = {'component': 'plugin:demo-plugin', 'fixed_in': '2.0.1', 'reason': 'a made-up access flaw'}


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _const(name):
    # a multi-line tuple's closing paren sits in column 0: it ends the constant, not the cut
    return re.search(rf'^{name} = .*?(?=^(?!\))\S)', APP, re.S | re.M).group(0)


def _exec(n, *names, consts=()):
    src = '\n'.join([_const(c) for c in consts] + [_cut(x) for x in names])
    exec(compile(src, 'app.py', 'exec'), n)
    return n


class Portal:
    """Fake `docker exec <portal> cat <file>`: answers from `files` (name -> dict | str | None)."""

    def __init__(self, files):
        self.files, self.calls = files, []

    def run(self, cmd, **kw):
        self.calls.append(cmd)
        name = cmd[-1].rsplit('/', 1)[-1]
        body = self.files.get(name)
        if body is None:
            return types.SimpleNamespace(returncode=1, stdout='', stderr=f'cat: {name}: No such file')
        return types.SimpleNamespace(returncode=0, stderr='',
                                     stdout=body if isinstance(body, str) else json.dumps(body))


def _ns(files, portal_installed=True):
    portal = Portal(files)
    n = {
        're': re, 'json': json, 'time': time, 'print': lambda *a, **k: None,
        'subprocess': types.SimpleNamespace(run=portal.run),
        '_sudo_wrap': lambda cmd: cmd,
        '_takportal_ref': lambda: 'abc123',
        'detect_modules': lambda: {'takportal': {'installed': portal_installed}},
    }
    _exec(n, '_semver_tuple', '_apply_security_identity', '_known_security_fixed_by',
          '_takportal_marketplace_read', '_marketplace_plugin_items',
          consts=('KNOWN_SECURITY_RELEASES', '_TAKPORTAL_MARKETPLACE_DATA',
                  '_MARKETPLACE_CACHE_MAX_AGE_S', '_MARKETPLACE_HOW'))
    # a made-up security release for a plugin, the way a real entry is added once it is public
    n['KNOWN_SECURITY_RELEASES'] = n['KNOWN_SECURITY_RELEASES'] + (FIXTURE_RELEASE,)
    n['_portal'] = portal
    return n


def _items(files, now=NOW, **kw):
    n = _ns(files, **kw)
    unknown = set()
    return n['_marketplace_plugin_items'](unknown, now=now), unknown, n['_portal']


FILES = {'sha-cache.json': SHA_CACHE, 'plugins.json': CATALOG}


# ── the customer-facing result ─────────────────────────────────────────────────────────────
def test_demo_plugin_2_0_0_to_2_0_1_is_a_security_item_and_air_aware_a_plain_update():
    items, unknown, portal = _items(FILES)
    assert unknown == set()
    assert [i['key'] for i in items] == ['marketplace:air-aware', 'marketplace:demo-plugin']   # Print is current
    d = items[1]
    assert d['label'] == 'CloudTAK plugin “Demo Plugin”'
    assert (d['installed'], d['target']) == ('v2.0.0', 'v2.0.1')
    assert d['security'] == ['Fixes a made-up access flaw (fixed in v2.0.1)']
    assert d['identity'] == '2.0.1+security'
    assert 'CloudTAK Marketplace' in d['how'] and 'Deploy' in d['how']
    a = items[0]
    assert (a['installed'], a['target'], a['identity']) == ('v0.2.4', 'v0.3.0', '0.3.0') and 'security' not in a
    # it asked the portal container for the two files, nothing else
    assert [c[-1].rsplit('/', 1)[-1] for c in portal.calls] == ['sha-cache.json', 'plugins.json']
    assert all(c[:2] == ['docker', 'exec'] and c[2] == 'abc123' and c[3] == 'cat' for c in portal.calls)


def test_a_box_already_on_1_8_1_or_with_no_update_says_nothing():
    cache = json.loads(json.dumps(SHA_CACHE))
    cache['byId']['demo-plugin'].update(updateAvailable=False, installedVersion='2.0.1')
    cache['byId']['air-aware'].update(updateAvailable=False)
    assert _items({'sha-cache.json': cache, 'plugins.json': CATALOG})[0] == []


def test_installed_version_unknown_claims_no_security_fix():
    cache = json.loads(json.dumps(SHA_CACHE))
    cache['byId']['demo-plugin']['installedVersion'] = ''
    d = [i for i in _items({'sha-cache.json': cache, 'plugins.json': CATALOG})[0]
         if i['key'] == 'marketplace:demo-plugin'][0]
    assert 'security' not in d and d['identity'] == '2.0.1'
    assert d['installed'] == '0a0a0a0'                  # the short commit stands in for the version


def test_a_plugin_with_no_version_is_told_by_its_commit():
    cache = {'updatedAt': FRESH, 'byId': {'x-plugin': {
        'remoteSha': 'abcdef1234567', 'installedSha': '9999999aaaa', 'updateAvailable': True,
        'remoteVersion': '', 'installedVersion': ''}}}
    i = _items({'sha-cache.json': cache, 'plugins.json': CATALOG})[0][0]
    assert (i['label'], i['installed'], i['target'], i['identity']) == (
        'CloudTAK plugin “x-plugin”', '9999999', 'abcdef1', 'abcdef1')


def test_plugin_names_unreadable_shows_the_ids_and_still_reports():
    items, unknown, _ = _items({'sha-cache.json': SHA_CACHE})        # no plugins.json
    assert unknown == set()
    assert items[1]['label'] == 'CloudTAK plugin “demo-plugin”'


def test_names_versions_and_commits_that_are_not_plain_text_never_reach_the_mail():
    cache = {'updatedAt': FRESH, 'byId': {'evil': {
        'remoteSha': 'abcdef1234567', 'installedSha': 'not a sha\nBcc: a@b', 'updateAvailable': True,
        'remoteVersion': '2.0.0\nBcc: a@b', 'installedVersion': '1.0<script>'}}}
    catalog = {'plugins': [{'id': 'evil', 'name': 'Evil\nBcc: attacker@example.com <b>'}]}
    i = _items({'sha-cache.json': cache, 'plugins.json': catalog})[0][0]
    assert '\n' not in i['label'] and '<' not in i['label'] and '@' not in i['label']
    assert (i['installed'], i['target'], i['identity']) == ('(unknown)', 'abcdef1', 'abcdef1')


def test_a_bad_plugin_id_never_reaches_the_mail():
    cache = {'updatedAt': FRESH, 'byId': {'../x\nBcc: a@b': {
        'remoteSha': 'abcdef1', 'updateAvailable': True, 'remoteVersion': '2.0.0'}}}
    assert _items({'sha-cache.json': cache})[0] == []


# ── when TAK Portal cannot be read, nothing is claimed and the dedup state is carried ──────
@pytest.mark.parametrize('files', [
    {},                                                           # no Marketplace data at all
    {'sha-cache.json': 'not json'},
    {'sha-cache.json': {'updatedAt': FRESH}},                     # no byId
    {'sha-cache.json': dict(SHA_CACHE, updatedAt=STALE)},         # the portal stopped checking
    {'sha-cache.json': {k: v for k, v in SHA_CACHE.items() if k != 'updatedAt'}},
])
def test_unreadable_or_stale_answer_is_unknown_not_up_to_date(files):
    items, unknown, _ = _items(files)
    assert items == [] and unknown == {'marketplace'}


def test_no_tak_portal_means_no_items_and_no_calls():
    items, unknown, portal = _items(FILES, portal_installed=False)
    assert items == [] and unknown == set() and portal.calls == []


def test_the_sweep_carries_marketplace_keys_when_unknown():
    carried = _exec({}, '_carried_by_unknown')['_carried_by_unknown']
    assert carried('marketplace:demo-plugin', {'marketplace'}) is True
    assert carried('marketplace:demo-plugin', {'cloudtak'}) is False


# ── the real function, end to end through the sweep and the mail ───────────────────────────
def _collect(files, extra=None):
    n = _ns(files)
    n.update({'os': types.SimpleNamespace(path=types.SimpleNamespace(
        isdir=lambda p: False, expanduser=lambda p: p)),
        '_console_pending_update': lambda s: None, '_module_update_items': lambda u: [],
        '_takserver_tested_items': lambda u: [], '_os_security_items': lambda seen, u: [],
        '_postgres_security_items': lambda u: [], '_java_restart_items': lambda u: [],
        '_java_image_items': lambda u: [], '_tak_db_refresh_items': lambda: [],
        '_postgres_remote_security_items': lambda u: [], '_node_container_versions': lambda: {},
        '_node_security_items': lambda v: [], 'NODE_MODULE_CONTAINERS': {},
        '_detect_cloudtak_plugins': lambda: [],
        '_etlrunner_cfg': lambda s: {}})
    n.update(extra or {})
    _exec(n, '_collect_pending_updates')
    unknown = set()
    pending = n['_collect_pending_updates']({}, unknown=unknown)
    return pending, unknown


def test_collect_pending_updates_includes_marketplace_plugins(monkeypatch):
    # the real function reads the clock itself: freeze the fixture's age against it
    now = time.time()
    fresh = {'sha-cache.json': dict(SHA_CACHE, updatedAt=time.strftime('%Y-%m-%dT%H:%M:%S.000Z',
                                                                       time.gmtime(now - 60))),
             'plugins.json': CATALOG}
    pending, unknown = _collect(fresh)
    assert sorted(p['key'] for p in pending) == ['marketplace:air-aware', 'marketplace:demo-plugin']
    assert unknown == set()


def test_a_marketplace_failure_never_hides_the_other_sources():
    boom = lambda unknown, now=None: (_ for _ in ()).throw(RuntimeError('docker timeout'))
    pending, unknown = _collect(FILES, extra={
        '_marketplace_plugin_items': boom,
        '_console_pending_update': lambda s: {'label': 'infra-TAK', 'installed': 'v1', 'target': 'v2',
                                              'identity': '2'}})
    assert [p['key'] for p in pending] == ['console'] and 'marketplace' in unknown


def _sweep(pending, state):
    sent, saved = [], []
    n = {
        'socket': types.SimpleNamespace(gethostname=lambda: 'box'),
        'load_settings': lambda: {'guarddog_alert_email': 'ops@example.com', 'fqdn': 'tak.example.com',
                                  'console_port': 5001, 'update_channel': 'main'},
        '_safe_alert_email_list': lambda v: v,
        '_gd_quiet_state': lambda: (False, 0, ''),
        '_guarddog_server_identifier': lambda s: 'tak-prod-1',
        '_update_notify_state_load': lambda: json.loads(json.dumps(state)),
        '_update_notify_state_save': lambda s: saved.append(s),
        '_guarddog_send_alert_email_via_relay': lambda to, subj, body: sent.append((subj, body)),
        'print': lambda *a, **k: None, 'time': time, 'PATCH_NOW_REPEAT_S': 24 * 3600,
        '_collect_patch_now_items': lambda feed, unknown, now=None: ([], feed),
        '_collect_pending_updates': lambda settings, seen=None, unknown=None, etl=None: (
            json.loads(json.dumps(pending))),
    }
    _exec(n, '_carried_by_unknown', '_update_notify_check_once')
    return n['_update_notify_check_once'](), sent, saved


def test_the_mail_says_security_update_and_where_to_press_and_is_not_repeated():
    items, _, _ = _items(FILES)
    r, sent, saved = _sweep(items, {})
    assert r['emailed'] is True and len(sent) == 1
    subj, body = sent[0]
    assert subj == '🔒 Security update pending on tak-prod-1 — update this machine'
    assert body.startswith('SECURITY UPDATE: you should update this machine (tak-prod-1).')
    assert 'CloudTAK plugin “Demo Plugin”: v2.0.0 → v2.0.1' in body
    assert 'Fixes a made-up access flaw (fixed in v2.0.1)' in body
    assert 'Fix it from the infra-TAK console: TAK Portal → CloudTAK Marketplace → press Update' in body
    assert 'CloudTAK plugin “Air Aware”: v0.2.4 → v0.3.0' in body       # the plain one rides along, listed after
    assert body.index('Demo Plugin') < body.index('Other pending updates:') < body.index('Air Aware')
    assert saved[-1]['marketplace:demo-plugin'] == '2.0.1+security' and saved[-1]['marketplace:air-aware'] == '0.3.0'
    # the next sweep: same updates, no second mail
    r2, sent2, _ = _sweep(items, saved[-1])
    assert r2['emailed'] is False and sent2 == []


def test_a_later_release_of_a_plugin_mails_again():
    items, _, _ = _items(FILES)
    _, _, saved = _sweep(items, {})
    newer = json.loads(json.dumps(SHA_CACHE))
    newer['byId']['air-aware']['remoteVersion'] = '0.4.0'
    items2, _, _ = _items({'sha-cache.json': newer, 'plugins.json': CATALOG})
    r, sent, _ = _sweep(items2, saved[-1])
    assert r['emailed'] is True and 'Air Aware' in sent[0][1] and 'Demo Plugin' not in sent[0][1]
    assert sent[0][0] == '⬆ Update pending on tak-prod-1'


# ── the table and the reader keep their contract ───────────────────────────────────────────
def test_the_security_table_takes_plugin_components():
    n = _exec({'re': re}, '_semver_tuple', consts=('KNOWN_SECURITY_RELEASES',))
    for x in n['KNOWN_SECURITY_RELEASES']:
        assert set(x) == {'component', 'fixed_in', 'reason'}


def _real_dispatcher_items(installed, remote):
    """The sweep with the REAL table (no fixture entry), a portal that reports Dispatcher."""
    cache = {'updatedAt': FRESH, 'byId': {'dispatcher': {
        'remoteSha': 'bc44445bfadda0f47535e927f347c2f619aeccf3',
        'installedSha': 'b059d26aac613ded6bddaf080676b326d1f2fff2',
        'updateAvailable': True, 'remoteVersion': remote, 'installedVersion': installed}}}
    cat = {'version': 1, 'plugins': [{'id': 'dispatcher', 'name': 'Dispatcher',
           'repo': 'https://github.com/takwerx/cloudtak-dispatcher-plugin.git', 'ref': 'main'}]}
    n = _ns({'sha-cache.json': cache, 'plugins.json': cat})
    n['KNOWN_SECURITY_RELEASES'] = _exec({'re': re}, '_semver_tuple',
                                         consts=('KNOWN_SECURITY_RELEASES',))['KNOWN_SECURITY_RELEASES']
    return n['_marketplace_plugin_items'](set(), now=NOW)


@pytest.mark.parametrize('installed', ['1.8.0', '1.7.0', '1.0.0'])
def test_dispatcher_below_1_8_1_gets_the_security_update_mail(installed):
    """ops #1253 proof: red without the table entry (a plain update item), green with it."""
    (d,) = _real_dispatcher_items(installed, '1.8.1')
    assert d['key'] == 'marketplace:dispatcher' and d['label'] == 'CloudTAK plugin “Dispatcher”'
    assert (d['installed'], d['target']) == (f'v{installed}', 'v1.8.1')
    assert d['security'] == ['Fixes a missing access check on connections in TAK-CAD mode '
                             '(fixed in v1.8.1)']
    assert d['identity'] == '1.8.1+security'


def test_dispatcher_security_mail_reads_plainly_and_names_where_to_press():
    (d,) = _real_dispatcher_items('1.8.0', '1.8.1')
    assert 'Marketplace' in d['how'] and 'Deploy' in d['how']
    assert 'GHSA' not in str(d) and 'CVE' not in str(d)    # nothing beyond what the public notes say


def test_dispatcher_a_later_plain_release_is_not_a_security_item():
    # a box on 1.8.1 that is offered 1.8.2 later: the 1.8.1 fix is already in, so a plain update
    assert _real_dispatcher_items('1.8.1', '1.8.2')[0].get('security') is None
    assert _real_dispatcher_items('1.8.1', '1.8.2')[0]['identity'] == '1.8.2'


def test_the_reader_uses_one_docker_exec_cat_of_the_portal_data_folder():
    n = _ns(FILES)
    assert n['_TAKPORTAL_MARKETPLACE_DATA'] == '/usr/src/app/data/cloudtak-marketplace'
    n['_takportal_marketplace_read']('sha-cache.json')
    assert n['_portal'].calls == [['docker', 'exec', 'abc123', 'cat',
                                   '/usr/src/app/data/cloudtak-marketplace/sha-cache.json']]


def test_the_sweep_calls_the_marketplace_source_inside_a_try():
    body = APP[APP.index('def _collect_pending_updates('):]
    i = body.index('pending.extend(_marketplace_plugin_items(unknown))')
    before = body[:i].rstrip().splitlines()
    assert before[-1].strip().startswith('# ops #1253') and before[-2].strip() == 'try:', \
        '_marketplace_plugin_items must run inside try/except Exception (older tests cut the sweep without it)'
