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
"""A Node-RED feed whose TAK mission does not exist must say so (ops #904).

Field (aws-arm, 2026-11-17, found in ops #903): the TFR feed's mission was never created in
TAK Portal. TAK Server answered every mission write with HTTP 404. The feed logged
`uid ... rejected by TAK (500 at chunk=1 - likely no CoT in repository)`, halved the PUT chunk
size down to 1 as if a bad uid was being isolated, and kept sending every chunk. The Subscribe
step called the same 404 `already subscribed or read-only - normal`. An operator lost a day to
a wrong cause. Creating the mission fixed it at once.

The REAL function bodies from template-functions.json (what deploy.sh syncs into live tabs)
run under node with Node-RED stubbed, the same way tests/test_nodered_mission_api_burst.py does.
"""

import json
import pathlib
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
NR = REPO / 'nodered'
TEMPLATES = json.loads((NR / 'template-functions.json').read_text())

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')

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
for (const msg of spec.msgs) {
  const ret = fn(msg, node, ctx(flowCtx), ctx(globalCtx), (f) => timers.push(f), {}, {});
  if (ret) sent.push([ret]);
}
for (let i = 0; i < (spec.drain || 0); i++) { const t = timers.shift(); if (t) t(); }
console.log(JSON.stringify({ sent, warns, flow: flowCtx }));
'''

LOG_ACTION = TEMPLATES['shared.log_action']['func']
BUILD_PUT = TEMPLATES['shared.build_put']['func']

MISSION_URL = 'https://h:8443/Marti/api/missions/TFR/contents'
MISSING_MSG = 'Mission "TFR" does not exist on TAK Server. Create it in TAK Portal (Data Sync feed, Subscriber role).'


def _run(tmp_path, func, msgs, flow=None, drain=0):
    h = tmp_path / 'harness.js'
    h.write_text(HARNESS)
    s = tmp_path / 'spec.json'
    s.write_text(json.dumps({'func': func, 'msgs': msgs, 'flow': flow or {}, 'drain': drain}))
    out = subprocess.run(['node', str(h), str(s)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _resp(code, url=MISSION_URL, method='PUT', batch=True, uids=('tfr-6_7767',)):
    m = {'statusCode': code, 'method': method, 'topic': 'TFR', 'url': url, 'payload': ''}
    if batch:
        m['_isBatchPut'] = True
        m['_sentUids'] = list(uids)
    return m


def _mission_warns(res):
    return [w for w in res['warns'] if 'does not exist on TAK Server' in w]


# ── Log API result ───────────────────────────────────────────────────────────

def test_404_names_the_missing_mission_and_does_not_shrink_the_chunk(tmp_path):
    res = _run(tmp_path, LOG_ACTION, [_resp(404)], flow={'_putChunkSize': 100})
    assert res['flow']['_putChunkSize'] == 100            # a missing mission is not a bad uid
    assert 'TFR: ' + MISSING_MSG in res['warns']
    assert not any('shrinking PUT chunk' in w for w in res['warns'])


def test_404_at_chunk_size_1_does_not_blame_a_500_or_a_missing_cot(tmp_path):
    res = _run(tmp_path, LOG_ACTION, [_resp(404)], flow={'_putChunkSize': 1})
    assert res['flow']['_putChunkSize'] == 1
    joined = '\n'.join(res['warns'])
    assert 'rejected by TAK' not in joined
    assert 'no CoT' not in joined
    assert 'TFR: ' + MISSING_MSG in res['warns']


def test_the_mission_message_is_logged_once_not_once_per_chunk(tmp_path):
    res = _run(tmp_path, LOG_ACTION, [_resp(404), _resp(404), _resp(404)], flow={'_putChunkSize': 100})
    assert len(_mission_warns(res)) == 1


def test_the_mission_message_comes_back_after_an_hour(tmp_path):
    import time
    stale = int(time.time() * 1000) - 2 * 3600 * 1000
    res = _run(tmp_path, LOG_ACTION, [_resp(404)], flow={'_missionMissing': {'TFR': stale}})
    assert len(_mission_warns(res)) == 1


def test_a_successful_write_clears_the_missing_mission_flag(tmp_path):
    res = _run(tmp_path, LOG_ACTION, [_resp(404), _resp(200)], flow={'_putChunkSize': 100})
    assert 'TFR' not in (res['flow'].get('_missionMissing') or {})
    assert any('now exists' in w for w in res['warns'])
    # The next 404 (mission deleted again later) reports again.
    again = _run(tmp_path, LOG_ACTION, [_resp(404)], flow=res['flow'])
    assert len(_mission_warns(again)) == 1


def test_a_404_for_one_mission_does_not_hide_another(tmp_path):
    other = 'https://h:8443/Marti/api/missions/OTHER%20ONE/contents'
    res = _run(tmp_path, LOG_ACTION, [_resp(404), _resp(404, url=other)])
    assert len(_mission_warns(res)) == 2
    assert any('Mission "OTHER ONE" does not exist' in w for w in res['warns'])


def test_a_real_500_still_shrinks_the_chunk(tmp_path):
    # Regression: the adaptive chunking for a uid TAK rejects (500) is untouched.
    res = _run(tmp_path, LOG_ACTION, [_resp(500)], flow={'_putChunkSize': 100})
    assert res['flow']['_putChunkSize'] == 50
    assert any('shrinking PUT chunk 100 -> 50' in w for w in res['warns'])
    assert _mission_warns(res) == []


def test_a_real_500_at_chunk_1_still_names_the_bad_uid(tmp_path):
    res = _run(tmp_path, LOG_ACTION, [_resp(500)], flow={'_putChunkSize': 1})
    assert any('uid tfr-6_7767 rejected by TAK (500 at chunk=1' in w for w in res['warns'])


def test_a_healthy_put_still_restores_the_chunk_size(tmp_path):
    res = _run(tmp_path, LOG_ACTION, [_resp(200)], flow={'_putChunkSize': 4})
    assert res['flow']['_putChunkSize'] == 8


# ── Build PUT UIDs: stop the chain once the mission is known to be missing ──

def _put_msg(n):
    return {'topic': 'TFR', '_putUrl': MISSION_URL, '_putUids': ['u%d' % i for i in range(n)]}


def _puts(res):
    return [m[0] for m in res['sent'] if m and m[0] and m[0].get('method') == 'PUT']


def test_put_chain_stops_after_the_first_chunk_when_the_mission_is_missing(tmp_path):
    # 50 uids at chunk size 1 is a 50-request chain. The poll still sends one request (it is
    # how the feed notices the mission was created), then stops.
    res = _run(tmp_path, BUILD_PUT, [_put_msg(50)],
               flow={'_putChunkSize': 1, '_missionMissing': {'TFR': 1}}, drain=200)
    assert len(_puts(res)) == 1
    assert any('chain stopped' in w and 'TFR' in w for w in res['warns'])


def test_put_chain_runs_in_full_when_the_mission_exists(tmp_path):
    res = _run(tmp_path, BUILD_PUT, [_put_msg(50)], flow={'_putChunkSize': 1}, drain=200)
    assert len(_puts(res)) == 50
    assert not any('chain stopped' in w for w in res['warns'])


def test_put_chain_ignores_a_flag_for_a_different_mission(tmp_path):
    res = _run(tmp_path, BUILD_PUT, [_put_msg(20)],
               flow={'_putChunkSize': 1, '_missionMissing': {'SOMETHING-ELSE': 1}}, drain=200)
    assert len(_puts(res)) == 20


# ── Subscribe step ───────────────────────────────────────────────────────────

def _sub_msg(code):
    return {'statusCode': code, 'topic': 'TFR',
            'takSettings': {'serverUrl': 'host.docker.internal', 'missionApiPort': 8443},
            '_config': {'configName': 'TFR', 'missionName': 'TFR', 'creatorUid': 'nodered'}}


@pytest.mark.parametrize('key', ['arcgis.fn_elevate', 'kml.fn_elevate'])
def test_subscribe_404_says_the_mission_is_missing(tmp_path, key):
    res = _run(tmp_path, TEMPLATES[key]['func'], [_sub_msg(404)])
    joined = '\n'.join(res['warns'])
    assert 'Mission "TFR" does not exist on TAK Server' in joined
    assert 'Create it in TAK Portal' in joined
    assert 'already subscribed' not in joined


@pytest.mark.parametrize('key', ['arcgis.fn_elevate', 'kml.fn_elevate'])
def test_subscribe_500_keeps_the_already_subscribed_text(tmp_path, key):
    res = _run(tmp_path, TEMPLATES[key]['func'], [_sub_msg(500)])
    assert any('HTTP 500 (already subscribed or read-only' in w for w in res['warns'])
    assert _mission_warns(res) == []
