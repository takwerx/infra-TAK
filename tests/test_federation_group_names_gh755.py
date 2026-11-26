# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Federation works one way: the group search saves cn=tak_<channel> (gh #755, ops #1304).

infra-TAK's CoreConfig makes a TAK group's name the plain channel name ("Fire"), but TAK Server's
Federation Manager group search saves the LDAP name ("cn=tak_Fire"). A federate set up with the
search has inbound and outbound groups no user is in: the link says CONNECTED and data flows one
way. The console now finds those names and swaps them for the plain ones with the Marti calls the
Federation Manager makes. Pins:

  * `cn=tak_X` always maps to X; a bare `tak_X` only when X is a live TAK group and tak_X is not,
    so a channel really called tak_X is left alone;
  * only the LOCAL side is ever changed; the remote group names of a mapping are never touched;
  * the plain name is added BEFORE the prefixed one is removed, then the config is saved;
  * nothing to fix means no write at all (no save to CoreConfig);
  * a failed call is reported, never counted as fixed, and what is left is counted again;
  * the two routes need a login and the Federation card shows the fix.
"""
import ast
import pathlib
import re
import sys
import threading
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
_FNS = {n.name: n for n in TREE.body if isinstance(n, ast.FunctionDef)}
_ASSIGNS = {}
for _n in TREE.body:
    if isinstance(_n, ast.Assign) and len(_n.targets) == 1 and isinstance(_n.targets[0], ast.Name):
        _ASSIGNS[_n.targets[0].id] = _n

_NAMES = ('_fed_q', '_fed_plain_group_name', '_fed_groups_plan', '_fed_marti', '_fed_data',
          '_fed_groups_scan', '_fed_groups_apply', '_fed_groups_unavailable')
_CONSTS = ('_FED_DN_GROUP_RE', '_FED_BARE_PREFIX', '_FED_FIX_LOCK')


class FakeTak:
    """Federates the way TAK Server stores them: one row per (group, direction), a remote->local
    map per federate, and a config file that is only written by POST federategroupconfig."""

    def __init__(self, live=('Fire', 'EMS')):
        self.live = list(live)
        self.feds = {}
        self.calls = []
        self.saved = 0
        self.fail = set()   # (method, path-prefix) pairs that answer http_500

    def add_fed(self, fid, name, groups=(), maps=()):
        m = {}
        for remote, local in maps:
            m.setdefault(remote, []).append(local)
        self.feds[fid] = {'name': name, 'groups': set(groups), 'map': m}

    def req(self, url, timeout=12, method='GET', json_body=None):
        u = urllib.parse.urlsplit(url)
        path = u.path.split('/Marti/api/', 1)[1]
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        self.calls.append((method, path, q, json_body))
        for m, pre in self.fail:
            if m == method and path.startswith(pre):
                return None, 'http_500'
        parts = path.split('/')
        name = parts[0]
        fid = urllib.parse.unquote(parts[1]) if len(parts) > 1 else None
        if name == 'federates' and method == 'GET':
            return {'data': [{'id': k, 'name': v['name']} for k, v in self.feds.items()]}, None
        if name == 'federategroups' and method == 'GET':
            return {'data': [{'group': g, 'direction': d, 'federateId': fid}
                             for g, d in sorted(self.feds[fid]['groups'])]}, None
        if name == 'federategroups' and method == 'POST':
            b = json_body
            dirs = ('INBOUND', 'OUTBOUND') if b['direction'] == 'BOTH' else (b['direction'],)
            for d in dirs:
                self.feds[b['federateId']]['groups'].add((b['group'], d))
            return {'data': 'ok'}, None
        if name == 'federategroups' and method == 'DELETE':
            key = (q['group'], q['direction'])
            if key not in self.feds[fid]['groups']:
                return None, 'http_404'
            self.feds[fid]['groups'].discard(key)
            return True, None
        if name == 'federategroupsmap' and method == 'GET':
            # verified on a real TAK Server (test12, Nov 26 2026): remote -> LIST of locals
            return {'data': {k: list(v) for k, v in self.feds[fid]['map'].items()}}, None
        if name == 'federategroupsmap' and method == 'POST':
            lst = self.feds[fid]['map'].setdefault(q['remoteGroup'], [])
            if q['localGroup'] not in lst:
                lst.append(q['localGroup'])
            return True, None
        if name == 'federategroupsmap' and method == 'DELETE':
            lst = self.feds[fid]['map'].get(q['remoteGroup'], [])
            if q['localGroup'] not in lst:
                return None, 'http_404'
            lst.remove(q['localGroup'])
            if not lst:
                del self.feds[fid]['map'][q['remoteGroup']]
            return True, None
        if name == 'federategroupconfig' and method == 'POST':
            self.saved += 1
            return {'data': 'saved'}, None
        raise AssertionError('unexpected call %s %s' % (method, path))


def _ns(tak, live_known=True):
    ns = {'re': re, 'urllib': urllib, '_threading': threading, 'os': __import__('os')}
    for n in _CONSTS:
        exec(compile(ast.Module([_ASSIGNS[n]], []), 'app.py', 'exec'), ns)
    ns['_tak_admin_marti_req'] = tak.req
    ns['_tak_channel_items'] = (lambda: [{'name': n} for n in tak.live]) if live_known else (lambda: None)
    ns['_tak_core_is_remote'] = lambda: False
    for n in _NAMES:
        exec(compile(ast.get_source_segment(APP, _FNS[n]), 'app.py', 'exec'), ns)
    return ns


# --- the name rule ---------------------------------------------------------------------------

def test_dn_prefix_always_maps_to_plain_name():
    f = _ns(FakeTak())['_fed_plain_group_name']
    assert f('cn=tak_Fire') == 'Fire'
    assert f('cn=tak_Example Co SOG_ESU') == 'Example Co SOG_ESU'
    assert f('cn=tak_Fire,ou=groups,dc=x') == 'Fire'    # the same cut CoreConfig makes
    assert f('cn=tak_Fire', None) == 'Fire'             # no live list needed for the DN form


def test_plain_names_and_other_names_are_left_alone():
    f = _ns(FakeTak())['_fed_plain_group_name']
    for n in ('Fire', 'EMS', 'cn=other', 'cn=tak_', '', None, 'Fire tak_x'):
        assert f(n, {'Fire'}) is None


def test_bare_tak_prefix_needs_a_live_group_and_no_live_group_of_that_name():
    f = _ns(FakeTak())['_fed_plain_group_name']
    assert f('tak_Fire', {'Fire'}) == 'Fire'
    assert f('tak_Fire', {'Fire', 'tak_Fire'}) is None   # a channel really called tak_Fire
    assert f('tak_Gone', {'Fire'}) is None               # stripped name is not a TAK group
    assert f('tak_Fire', None) is None                   # live groups unknown: leave alone


# --- scan + fix against a TAK Server that behaves like the API ------------------------------

def _broken_box():
    t = FakeTak()
    t.add_fed('f1', 'Neighbor County',
              groups=[('cn=tak_Fire', 'INBOUND'), ('cn=tak_Fire', 'OUTBOUND'), ('EMS', 'INBOUND')],
              maps=[('SOG_ESU', 'tak_Fire')])
    t.add_fed('f2', 'Clean', groups=[('Fire', 'INBOUND'), ('Fire', 'OUTBOUND')], maps=[('Fire', 'Fire')])
    return t


def test_scan_lists_only_the_federate_with_prefixed_names():
    t = _broken_box()
    res, err = _ns(t)['_fed_groups_scan']()
    assert err is None
    assert [p['id'] for p in res['federates']] == ['f1']
    p = res['federates'][0]
    assert p['groups'] == [{'group': 'cn=tak_Fire', 'plain': 'Fire', 'directions': ['INBOUND', 'OUTBOUND']}]
    assert p['maps'] == [{'remote': 'SOG_ESU', 'local': 'tak_Fire', 'plain': 'Fire', 'plain_present': False}]
    assert res['count'] == 2
    assert t.saved == 0 and all(c[0] == 'GET' for c in t.calls)   # a check never writes


def test_fix_swaps_names_and_leaves_the_remote_side_alone():
    t = _broken_box()
    ns = _ns(t)
    res, _ = ns['_fed_groups_scan']()
    changed, errors = ns['_fed_groups_apply'](res['federates'])
    assert errors == []
    f1 = t.feds['f1']
    assert f1['groups'] == {('Fire', 'INBOUND'), ('Fire', 'OUTBOUND'), ('EMS', 'INBOUND')}
    assert f1['map'] == {'SOG_ESU': ['Fire']}            # remote name SOG_ESU unchanged
    assert t.feds['f2']['groups'] == {('Fire', 'INBOUND'), ('Fire', 'OUTBOUND')}   # untouched
    assert t.feds['f2']['map'] == {'Fire': ['Fire']}
    assert changed == 3 and t.saved == 1
    again, _ = ns['_fed_groups_scan']()
    assert again['count'] == 0


def test_plain_name_is_added_before_the_prefixed_one_is_removed_then_saved():
    t = _broken_box()
    ns = _ns(t)
    res, _ = ns['_fed_groups_scan']()
    t.calls.clear()
    ns['_fed_groups_apply'](res['federates'])
    writes = [(m, p.split('/')[0]) for m, p, _q, _b in t.calls]
    assert writes[0] == ('POST', 'federategroups')
    assert writes.index(('POST', 'federategroups')) < writes.index(('DELETE', 'federategroups'))
    assert writes.index(('POST', 'federategroupsmap')) < writes.index(('DELETE', 'federategroupsmap'))
    assert writes[-1] == ('POST', 'federategroupconfig')
    add = [b for m, p, _q, b in t.calls if (m, p) == ('POST', 'federategroups')][0]
    assert add == {'federateId': 'f1', 'group': 'Fire', 'direction': 'BOTH'}


def test_group_names_with_spaces_and_equals_are_url_encoded():
    t = FakeTak(live=['Example Co SOG_ESU'])
    t.add_fed('f1', 'N', groups=[('cn=tak_Example Co SOG_ESU', 'INBOUND')])
    ns = _ns(t)
    res, _ = ns['_fed_groups_scan']()
    t.calls.clear()
    changed, errors = ns['_fed_groups_apply'](res['federates'])
    assert errors == [] and t.feds['f1']['groups'] == {('Example Co SOG_ESU', 'INBOUND')}


def test_nothing_to_fix_writes_nothing():
    t = FakeTak()
    t.add_fed('f2', 'Clean', groups=[('Fire', 'INBOUND'), ('Fire', 'OUTBOUND')], maps=[('Fire', 'Fire')])
    ns = _ns(t)
    res, _ = ns['_fed_groups_scan']()
    assert res == {'federates': [], 'count': 0}
    assert ns['_fed_groups_apply'](res['federates']) == (0, [])
    assert t.saved == 0 and all(c[0] == 'GET' for c in t.calls)


def test_plain_name_already_there_is_not_added_twice():
    t = FakeTak()
    t.add_fed('f1', 'N', groups=[('cn=tak_Fire', 'INBOUND'), ('Fire', 'INBOUND')])
    ns = _ns(t)
    res, _ = ns['_fed_groups_scan']()
    t.calls.clear()
    ns['_fed_groups_apply'](res['federates'])
    assert not [c for c in t.calls if c[:2] == ('POST', 'federategroups')]
    assert t.feds['f1']['groups'] == {('Fire', 'INBOUND')}


def test_a_failed_add_keeps_the_old_name_and_is_reported():
    t = _broken_box()
    t.fail.add(('POST', 'federategroups'))
    ns = _ns(t)
    res, _ = ns['_fed_groups_scan']()
    changed, errors = ns['_fed_groups_apply'](res['federates'])
    assert any('could not add group Fire' in e for e in errors)
    assert ('cn=tak_Fire', 'INBOUND') in t.feds['f1']['groups']     # never removed without the add
    after, _ = ns['_fed_groups_scan']()
    assert after['count'] >= 1                                       # still counted as wrong


def test_a_failed_save_is_reported():
    t = _broken_box()
    t.fail.add(('POST', 'federategroupconfig'))
    ns = _ns(t)
    res, _ = ns['_fed_groups_scan']()
    changed, errors = ns['_fed_groups_apply'](res['federates'])
    assert changed == 3 and any('not saved to CoreConfig' in e for e in errors)


def test_unreadable_tak_is_an_error_not_an_empty_answer():
    t = _broken_box()
    t.fail.add(('GET', 'federates'))
    res, err = _ns(t)['_fed_groups_scan']()
    assert res is None and 'could not read federates' in err


def test_bare_tak_prefix_is_fixed_only_when_the_channel_is_live():
    t = FakeTak(live=['Fire'])
    t.add_fed('f1', 'N', maps=[('A', 'tak_Fire'), ('B', 'tak_Unknown')])
    ns = _ns(t)
    res, _ = ns['_fed_groups_scan']()
    assert res['federates'][0]['maps'] == [{'remote': 'A', 'local': 'tak_Fire', 'plain': 'Fire', 'plain_present': False}]
    t2 = FakeTak(live=['Fire'])
    t2.add_fed('f1', 'N', maps=[('A', 'tak_Fire')])
    res2, _ = _ns(t2, live_known=False)['_fed_groups_scan']()
    assert res2['count'] == 0                                        # live list unknown: no guess


def test_map_with_both_names_present_only_removes_the_prefixed_one():
    t = FakeTak(live=['Fire'])
    t.add_fed('f1', 'N', maps=[('A', 'tak_Fire'), ('A', 'Fire'), ('B', 'Other')])
    ns = _ns(t)
    res, _ = ns['_fed_groups_scan']()
    assert res['federates'][0]['maps'] == [{'remote': 'A', 'local': 'tak_Fire', 'plain': 'Fire', 'plain_present': True}]
    t.calls.clear()
    changed, errors = ns['_fed_groups_apply'](res['federates'])
    assert errors == [] and changed == 1
    assert not [c for c in t.calls if c[:2] == ('POST', 'federategroupsmap/f1')]   # no second add
    assert t.feds['f1']['map'] == {'A': ['Fire'], 'B': ['Other']}                   # B is not ours to touch


def test_a_map_value_that_is_a_plain_string_is_read_too():
    ns = _ns(FakeTak())
    plan = ns['_fed_groups_plan']([], {'A': 'cn=tak_Fire'}, set())
    assert plan['maps'] == [{'remote': 'A', 'local': 'cn=tak_Fire', 'plain': 'Fire', 'plain_present': False}]


def test_not_available_when_tak_is_not_here_or_is_remote(tmp_path):
    t = FakeTak()
    ns = _ns(t)
    assert ns['_fed_groups_unavailable']() in (None, 'TAK Server is not on this box')
    ns['os'] = type('O', (), {'path': type('P', (), {'exists': staticmethod(lambda p: True)})})
    ns['_tak_core_is_remote'] = lambda: True
    assert ns['_fed_groups_unavailable']() == 'TAK Server runs on another host'


# --- routes and page -------------------------------------------------------------------------

def _decorators(fn):
    return [ast.unparse(d) for d in _FNS[fn].decorator_list]


def test_routes_need_a_login():
    d = _decorators('takserver_federation_groups_check')
    assert "app.route('/api/takserver/federation-groups-check')" in d and 'login_required' in d
    d = _decorators('takserver_federation_groups_fix')
    assert "app.route('/api/takserver/federation-groups-fix', methods=['POST'])" in d and 'login_required' in d


def test_fix_route_takes_a_lock_and_rechecks_afterwards():
    src = ast.get_source_segment(APP, _FNS['takserver_federation_groups_fix'])
    assert '_FED_FIX_LOCK.acquire(blocking=False)' in src and '_FED_FIX_LOCK.release()' in src
    assert src.count('_fed_groups_scan()') == 2          # before and after


def test_federation_card_shows_the_check_and_the_fix():
    html = (ROOT / 'templates' / 'takserver.html').read_text(encoding='utf-8')
    js = (ROOT / 'static' / 'takserver.js').read_text(encoding='utf-8')
    assert 'id="fed-groups-box"' in html and 'onclick="fixFedGroups()"' in html
    assert 'Do not use the group search' in html
    assert '/api/takserver/federation-groups-check' in js and '/api/takserver/federation-groups-fix' in js
    assert "loadFederationInfo();loadFedGroupsCheck();" in js
    # names reach the page as text, never as HTML
    seg = js[js.index('function loadFedGroupsCheck'):js.index('function fixFedGroups')]
    assert 'innerHTML' not in seg and 'li.textContent' in seg
