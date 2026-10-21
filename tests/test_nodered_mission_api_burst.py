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
"""Node-RED feed engines must not burst TAK's mission API (ops #64).

Field (test12, 2026-10-15): POWER-OUTAGES surged to ~1,800 active outages whose OBJECTIDs
are reassigned every poll, so each 5-min poll sent up to 3,100 single-uid DELETEs, all at
once (the tab predated the v10.1.25 1/s rate limiter, and delay nodes are not
template-synced), plus stacked single-uid PUT chains. TAK Server does an LDAP bind + search
for the cert user on EVERY API call, session cookie or not, so when a burst landed on the
LDAP outpost's hourly bind-cache expiry Authentik ran hundreds of login flows at once and
Guard Dog restarted it three times in 18 hours.

The REAL function bodies from template-functions.json (what deploy.sh syncs into live
tabs) and the REAL deploy.sh merge script run under node with Node-RED stubbed.
"""

import json
import pathlib
import re
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
NR = REPO / 'nodered'
TEMPLATES = json.loads((NR / 'template-functions.json').read_text())

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')

# Runs one function body like Node-RED does: flow/global context, node.send/warn, and a
# manual timer queue so a test can step setTimeout chains.
HARNESS = r'''
const fs = require('fs');
const spec = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const flowCtx = spec.flow || {}, globalCtx = spec.global || {};
const sent = [], warns = [], timers = [];
const ctx = (s) => ({ get: (k) => s[k], set: (k, v) => { s[k] = v; } });
const node = {
  send: (m) => sent.push(Array.isArray(m) ? m : [m]),
  warn: (w) => warns.push(String(w)),
};
const fn = new Function('msg', 'node', 'flow', 'global', 'setTimeout', '_nodeHttps', '_nodeFs',
                        spec.func);
const results = [];
for (const msg of spec.msgs) {
  const before = sent.length;
  const ret = fn(msg, node, ctx(flowCtx), ctx(globalCtx), (f) => timers.push(f), {}, {});
  if (ret) sent.push([ret]);
  results.push(sent.length - before);
  for (let i = 0; i < (spec.tickAfter || 0); i++) { const t = timers.shift(); if (t) t(); }
}
for (let i = 0; i < (spec.drain || 0); i++) { const t = timers.shift(); if (t) t(); }
console.log(JSON.stringify({ sent, warns, flow: flowCtx, global: globalCtx, results }));
'''


def _run(tmp_path, func, msgs, flow=None, glob=None, tick_after=0, drain=0):
    h = tmp_path / 'harness.js'
    h.write_text(HARNESS)
    s = tmp_path / 'spec.json'
    s.write_text(json.dumps({'func': func, 'msgs': msgs, 'flow': flow or {}, 'global': glob or {},
                             'tickAfter': tick_after, 'drain': drain}))
    out = subprocess.run(['node', str(h), str(s)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _reconcile_msg(n_mission, live_uids, poll_min=5, strict=True):
    mission_uids = ['power-outage-areas-%d' % i for i in range(n_mission)]
    feats = [{'uid': u, 'cot': {}, '_hash': 'h'} for u in live_uids]
    return {
        '_features': feats,
        'payload': {'data': [{'uids': mission_uids + list(live_uids)}]},
        '_config': {'configName': 'POWER-OUTAGES', 'missionName': 'POWER-OUTAGES',
                    'uidPrefix': 'power-outage-areas-', 'pollInterval': str(poll_min),
                    'strictMode': strict},
        'takSettings': {'serverUrl': 'host.docker.internal'},
    }


def _deletes(res):
    return [m[1] for m in res['sent'] if len(m) > 1 and m[1] and m[1].get('method') == 'DELETE']


def _aged_misses(n, minutes_ago=60):
    # Streak timestamps already past the 30-min mass-delete bar, oldest = lowest index.
    import time
    now_ms = int(time.time() * 1000)
    return {'power-outage-areas-%d' % i: now_ms - (minutes_ago * 60000) - (n - i) * 1000
            for i in range(n)}


RECONCILE = TEMPLATES['arcgis.reconcile']['func']
BUILD_PUT = TEMPLATES['shared.build_put']['func']


def test_surge_deletes_are_capped_per_poll_and_oldest_go_first(tmp_path):
    live = ['live-%d' % i for i in range(10)]
    res = _run(tmp_path, RECONCILE, [_reconcile_msg(600, live)],
               flow={'_missStreak': _aged_misses(600), '_featureHashes': {u: 'h' for u in live}})
    dels = _deletes(res)
    assert len(dels) == 240                      # 5-min poll at 1/s, 80% of the interval
    sent_uids = [re.search(r'uid=([^&]+)', d['url']).group(1) for d in dels]
    assert sent_uids == ['power-outage-areas-%d' % i for i in range(240)]   # oldest first
    # The 360 deferred keep their streak, so they are due again on the next poll.
    streak = res['flow']['_missStreak']
    assert all(('power-outage-areas-%d' % i) in streak for i in range(240, 600))
    assert not any(('power-outage-areas-%d' % i) in streak for i in range(240))
    assert any('DELETE cap' in w and 'deferred 360' in w for w in res['warns'])
    assert any('360 deferred' in w for w in res['warns'] if 'reconcile:' in w)


def test_deferred_uids_go_out_on_the_next_poll(tmp_path):
    live = ['live-%d' % i for i in range(10)]
    first = _run(tmp_path, RECONCILE, [_reconcile_msg(600, live)],
                 flow={'_missStreak': _aged_misses(600), '_featureHashes': {u: 'h' for u in live}})
    # Next poll: TAK has applied the first 240 DELETEs.
    msg = _reconcile_msg(600, live)
    msg['payload']['data'][0]['uids'] = ['power-outage-areas-%d' % i for i in range(240, 600)] + live
    second = _run(tmp_path, RECONCILE, [msg], flow=first['flow'])
    sent_uids = [re.search(r'uid=([^&]+)', d['url']).group(1) for d in _deletes(second)]
    assert sent_uids == ['power-outage-areas-%d' % i for i in range(240, 480)]


@pytest.mark.parametrize('poll_min,cap', [(1, 48), (5, 240), (30, 250)])
def test_cap_follows_the_poll_interval(tmp_path, poll_min, cap):
    live = ['live-%d' % i for i in range(10)]
    res = _run(tmp_path, RECONCILE, [_reconcile_msg(400, live, poll_min=poll_min)],
               flow={'_missStreak': _aged_misses(400), '_featureHashes': {u: 'h' for u in live}})
    assert len(_deletes(res)) == cap


def test_normal_poll_is_unchanged(tmp_path):
    live = ['live-%d' % i for i in range(100)]
    res = _run(tmp_path, RECONCILE, [_reconcile_msg(5, live)],
               flow={'_missStreak': _aged_misses(5), '_featureHashes': {u: 'h' for u in live}})
    assert len(_deletes(res)) == 5
    assert not any('DELETE cap' in w for w in res['warns'])
    assert not any('deferred' in w for w in res['warns'])


def test_one_shot_purge_stays_armed_until_finished(tmp_path):
    live = ['live-%d' % i for i in range(10)]
    glob = {'_forcePurge': {'POWER-OUTAGES': True}}
    first = _run(tmp_path, RECONCILE, [_reconcile_msg(300, live)], glob=glob,
                 flow={'_featureHashes': {u: 'h' for u in live}})
    assert len(_deletes(first)) == 240
    assert first['global']['_forcePurge'].get('POWER-OUTAGES') is True
    msg = _reconcile_msg(300, live)
    msg['payload']['data'][0]['uids'] = ['power-outage-areas-%d' % i for i in range(240, 300)] + live
    second = _run(tmp_path, RECONCILE, [msg], glob=first['global'], flow=first['flow'])
    assert len(_deletes(second)) == 60
    assert 'POWER-OUTAGES' not in second['global']['_forcePurge']
    assert any('one-shot purge complete' in w for w in second['warns'])


# ── ops #68: a deferred DELETE still gets its offline-device tombstone ───────────────
# The cap defers removals to later polls. When each one's DELETE finally goes out it must
# land in the tombstone map like any other removal, so the ForceDelete sweep (v10.1.5 W4)
# still clears it off EUDs that were offline when the mission dropped it.

def _del_uids(res):
    return [re.search(r'uid=([^&]+)', d['url']).group(1) for d in _deletes(res)]


def _force_deletes(res):
    # The sweep's t-x-d-d + <__forcedelete/> broadcasts, by the UID they remove.
    return [re.search(r'<link uid="([^"]+)"', m[0]['_rawCotXml']).group(1)
            for m in res['sent'] if m and m[0] and m[0].get('_rawCotXml')]


def _drain_backlog(tmp_path, n, poll_min, max_polls=30):
    # Poll until a surge of n stale UIDs has been DELETEd. TAK applies each poll's DELETEs
    # before the next poll, and polls are a full interval apart, so the sweep runs each time.
    live = ['live-%d' % i for i in range(10)]
    remaining = ['power-outage-areas-%d' % i for i in range(n)]
    flow = {'_missStreak': _aged_misses(n), '_featureHashes': {u: 'h' for u in live}}
    polls = []
    while remaining and len(polls) < max_polls:
        msg = _reconcile_msg(n, live, poll_min=poll_min)
        msg['payload']['data'][0]['uids'] = remaining + live
        flow['_tombSweepTs'] = 0
        res = _run(tmp_path, RECONCILE, [msg], flow=flow)
        flow = res['flow']
        polls.append({'deleted': _del_uids(res), 'force': _force_deletes(res),
                      'tombs': dict(flow['_tombstones']), 'warns': res['warns']})
        gone = set(polls[-1]['deleted'])
        remaining = [u for u in remaining if u not in gone]
    assert not remaining, 'backlog did not drain in %d polls' % max_polls
    return polls, flow


DRAIN_CASES = [(5, 240, 600), (1, 48, 200)]   # (poll minutes, DELETE cap, surge size)


@pytest.mark.parametrize('poll_min,cap,n', DRAIN_CASES)
def test_surge_over_the_cap_is_deferred_not_dropped_and_drains_oldest_first(tmp_path, poll_min, cap, n):
    polls, _ = _drain_backlog(tmp_path, n, poll_min)
    assert [len(p['deleted']) for p in polls] == [cap] * (n // cap) + ([n % cap] if n % cap else [])
    # Every removal goes out exactly once, oldest-missing first across the polls.
    assert [u for p in polls for u in p['deleted']] == ['power-outage-areas-%d' % i for i in range(n)]
    for i, p in enumerate(polls[:-1]):
        assert any('DELETE cap' in w and 'deferred %d' % (n - cap * (i + 1)) in w for w in p['warns'])
    assert not any('deferred' in w for w in polls[-1]['warns'])


@pytest.mark.parametrize('poll_min,cap,n', DRAIN_CASES)
def test_deferred_removal_is_tombstoned_when_its_delete_goes_out_not_before(tmp_path, poll_min, cap, n):
    started = _aged_misses(n)
    polls, _ = _drain_backlog(tmp_path, n, poll_min)
    sent = set()
    for p in polls:
        sent |= set(p['deleted'])
        # Tombstoned exactly when DELETEd: nothing still deferred, nothing sent missing.
        assert set(p['tombs']) == sent
        # The sweep only ever ForceDeletes UIDs whose DELETE has gone out.
        assert p['force'] and set(p['force']) <= sent
        assert len(p['force']) == min(250, len(sent))
    # A poll's own removals are broadcast on that poll while the sweep has room.
    assert set(polls[0]['force']) == set(polls[0]['deleted'])
    # The 3-day TTL runs from the DELETE, not from when the UID first went missing.
    for u, ts in polls[-1]['tombs'].items():
        assert ts - started[u] > 59 * 60000
    # Same on a poll where the sweep is skipped (it runs at most every 45s), so its
    # live-shape guard is not what keeps the deferred UIDs out of the map.
    import time
    live = ['live-%d' % i for i in range(10)]
    res = _run(tmp_path, RECONCILE, [_reconcile_msg(n, live, poll_min=poll_min)],
               flow={'_missStreak': _aged_misses(n), '_featureHashes': {u: 'h' for u in live},
                     '_tombSweepTs': int(time.time() * 1000)})
    assert _force_deletes(res) == []
    assert set(res['flow']['_tombstones']) == set(_del_uids(res))
    assert len(res['flow']['_tombstones']) == cap


@pytest.mark.parametrize('poll_min,cap,n', DRAIN_CASES)
def test_every_removal_is_tombstoned_once_the_backlog_clears(tmp_path, poll_min, cap, n):
    polls, flow = _drain_backlog(tmp_path, n, poll_min)
    assert set(flow['_tombstones']) == {'power-outage-areas-%d' % i for i in range(n)}
    assert not any(u.startswith('power-outage-areas-') for u in flow['_missStreak'])
    # A quiet poll after the drain sends no DELETEs and keeps every tombstone for the sweep.
    live = ['live-%d' % i for i in range(10)]
    flow['_tombSweepTs'] = 0
    res = _run(tmp_path, RECONCILE, [_reconcile_msg(0, live, poll_min=poll_min)], flow=flow)
    assert _deletes(res) == []
    assert set(res['flow']['_tombstones']) == set(flow['_tombstones'])
    assert len(_force_deletes(res)) == min(250, n)


def _put_msg(n, key=''):
    m = {'topic': 'POWER-OUTAGES', '_putUrl': 'https://h:8443/Marti/api/missions/P/contents',
         '_putUids': ['u%d' % i for i in range(n)]}
    if key:
        m['_putKey'] = key
    return m


def _puts(res):
    return [m[0] for m in res['sent'] if m and m[0] and m[0].get('method') == 'PUT']


def test_newer_poll_supersedes_a_running_put_chain(tmp_path):
    # Chunk size has shrunk to 1: a 50-uid delta is a 50-PUT chain. A second poll arrives
    # after 5 PUTs; the first chain must stop, the second runs to completion.
    res = _run(tmp_path, BUILD_PUT, [_put_msg(50), _put_msg(50)],
               flow={'_putChunkSize': 1}, tick_after=4, drain=200)
    puts = _puts(res)
    assert len(puts) == 5 + 50
    assert any('superseded' in w for w in res['warns'])


def test_put_chains_for_different_layers_do_not_cancel_each_other(tmp_path):
    res = _run(tmp_path, BUILD_PUT, [_put_msg(20, 'layerA-'), _put_msg(20, 'layerB-')],
               flow={'_putChunkSize': 1}, drain=200)
    assert len(_puts(res)) == 40
    assert not any('superseded' in w for w in res['warns'])


def test_reconcile_tags_the_put_with_its_layer(tmp_path):
    msg = _reconcile_msg(0, ['new-1', 'new-2'])
    msg['_layerPrefix'] = 'layerA-'
    msg['payload']['data'][0]['uids'] = []
    res = _run(tmp_path, RECONCILE, [msg])
    puts = [m[0] for m in res['sent'] if m and m[0] and m[0].get('_putUids')]
    assert puts and puts[0]['_putKey'] == 'layerA-'


# ── deploy.sh: legacy DELETE delay nodes become the 1/s rate limiter ─────────────────

def _merge_script(tmp_path):
    src = (NR / 'deploy.sh').read_text()
    m = re.search(r'docker exec "\$CONTAINER" node -e "\n(.*?)\n"\n', src, re.S)
    assert m, 'merge script not found in deploy.sh'
    js = m.group(1).replace('\\"', '"').replace('/tmp/', str(tmp_path) + '/')
    assert 'Rate limit 1/s' in js
    return js


def _legacy_tab(fid, reconcile_name, key=None):
    rec = {'id': fid + '_rec', 'type': 'function', 'z': fid, 'name': reconcile_name, 'func': 'old',
           'wires': [[fid + '_put'], [fid + '_del']]}
    if key:
        rec['_templateKey'] = key
    return [
        {'id': fid, 'type': 'tab', 'label': fid},
        {'id': fid + '_q', 'type': 'function', 'z': fid,
         'name': 'Build ArcGIS query' if 'TFR' not in reconcile_name else 'Build TFR CoT', 'func': 'x'},
        rec,
        # The pre-v10.1.25 node: fixed 1s delay, unnamed.
        {'id': fid + '_del', 'type': 'delay', 'z': fid, 'name': '', 'pauseType': 'delay',
         'timeout': '1', 'timeoutUnits': 'seconds', 'rate': '1', 'nbRateUnits': '1',
         'rateUnits': 'second', 'drop': False, 'outputs': 1, 'x': 600, 'y': 490,
         'wires': [[fid + '_http']]},
        # The PUT path's 30s delay is on output 1 and must NOT be touched.
        {'id': fid + '_put', 'type': 'delay', 'z': fid, 'name': 'Wait 30s for cache',
         'pauseType': 'delay', 'timeout': '30', 'timeoutUnits': 'seconds', 'wires': [['x']]},
    ]


def test_deploy_converts_legacy_delete_delay_nodes(tmp_path):
    cur = (_legacy_tab('flow_eng_power', 'Reconcile (diff)')
           + _legacy_tab('flow_eng_tfr', 'TFR Reconcile (diff)')
           + _legacy_tab('flow_eng_new', 'Reconcile (diff)', key='arcgis.reconcile'))
    (tmp_path / 'flows_current.json').write_text(json.dumps(cur))
    (tmp_path / 'flows_new.json').write_text(json.dumps([{'id': 'cfg_tab', 'type': 'tab', 'label': 'Configurator'}]))
    shutil.copy(NR / 'template-functions.json', tmp_path / 'template-functions.json')
    js = tmp_path / 'merge.js'
    js.write_text(_merge_script(tmp_path))
    out = subprocess.run(['node', str(js)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert 'Converted 3 engine DELETE delay nodes' in out.stdout
    merged = {n['id']: n for n in json.loads((tmp_path / 'flows_merged.json').read_text())}
    for fid in ('flow_eng_power', 'flow_eng_tfr', 'flow_eng_new'):
        d = merged[fid + '_del']
        assert (d['pauseType'], d['rate'], d['nbRateUnits'], d['rateUnits']) == ('rate', '1', '1', 'second')
        assert d['name'] == 'Rate limit 1/s' and d['drop'] is False
        assert d['wires'] == [[fid + '_http']] and (d['x'], d['y']) == (600, 490)
        assert merged[fid + '_put']['pauseType'] == 'delay'
        assert merged[fid + '_put']['timeout'] == '30'
    # Reconcile bodies got the capped template on the same deploy.
    assert 'DEL_MAX_PER_POLL' in merged['flow_eng_power_rec']['func']
    assert 'DEL_MAX_PER_POLL' in merged['flow_eng_new_rec']['func']


def test_deploy_leaves_current_rate_nodes_alone(tmp_path):
    cur = _legacy_tab('flow_eng_power', 'Reconcile (diff)', key='arcgis.reconcile')
    cur[3].update({'pauseType': 'rate', 'name': 'Rate limit 1/s'})
    (tmp_path / 'flows_current.json').write_text(json.dumps(cur))
    (tmp_path / 'flows_new.json').write_text(json.dumps([]))
    shutil.copy(NR / 'template-functions.json', tmp_path / 'template-functions.json')
    js = tmp_path / 'merge.js'
    js.write_text(_merge_script(tmp_path))
    out = subprocess.run(['node', str(js)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert 'Converted' not in out.stdout


def test_new_tabs_ship_the_rate_limiter():
    html = (NR / 'configurator.html').read_text()
    import base64
    for marker in ('ENGINE_TAB_TEMPLATE', 'TFR_ENGINE_TAB_TEMPLATE', 'KML_ENGINE_TAB_TEMPLATE'):
        b64 = re.search(r'var %s = decodeURIComponent\(escape\(atob\("([^"]+)"\)\)\);' % marker, html).group(1)
        nodes = json.loads(base64.b64decode(b64).decode('utf8'))
        rec = next(n for n in nodes if n.get('_templateKey') in ('arcgis.reconcile', 'tfr.reconcile'))
        dels = [n for n in nodes if n['id'] in rec['wires'][1]]
        assert dels and all(d['type'] == 'delay' and d['pauseType'] == 'rate' for d in dels), marker
