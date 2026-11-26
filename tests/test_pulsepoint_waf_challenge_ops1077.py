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
"""PulsePoint bot challenge must be named, and must make the feed back off (ops #1077).

Field (infra-TAK #642, 2026-11-22): api.pulsepoint.org started answering every incidents
request with `HTTP 202`, an empty body and `x-amzn-waf-action: challenge` (an AWS WAF bot
challenge). The PulsePoint fetch node ran JSON.parse('') on that and logged
`PulsePoint fetch: <agency>:Unexpected end of JSON input`, which pointed operators at their
own server, and it hit the challenge again on every poll.

Now the reply is classified before parsing, the log says what happened, and the feed backs off
(5, 10, 20, 40, then 60 minutes). infra-TAK does not try to solve or evade the challenge.

The REAL function body from template-functions.json (what deploy.sh syncs into live tabs) runs
under node with Node-RED and the HTTPS layer stubbed.
"""

import json
import pathlib
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
NR = REPO / 'nodered'
TEMPLATES = json.loads((NR / 'template-functions.json').read_text())
FETCH = TEMPLATES['pp.fetch.__FEED_ID__']['func']

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')

HARNESS = r'''
const fs = require('fs');
const spec = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const g = spec.global || {};
const sent = [], warns = [], requested = [];
const ctx = { get: (k) => g[k], set: (k, v) => { g[k] = v; } };
const node = { send: (m) => sent.push(m), warn: (w) => warns.push(String(w)) };
// Fake https: spec.replies maps agency id -> { status, headers, body }
const https = {
  request: (opts, cb) => {
    const m = /agencyid=([^&]+)/.exec(opts.path);
    const aid = decodeURIComponent(m[1]);
    requested.push(aid);
    const r = spec.replies[aid];
    const handlers = {};
    const res = {
      statusCode: r.status, headers: r.headers || {},
      setEncoding: () => {},
      on: (ev, f) => { handlers[ev] = f; },
    };
    return {
      on: () => {}, setTimeout: () => {},
      end: () => { cb(res); if (r.body) handlers.data(r.body); handlers.end(); },
      destroy: () => {},
    };
  },
};
const glob = { nodeHttps: https, nodeUrl: require('url'), nodeCrypto: require('crypto'),
               get: (k) => (k === 'nodeHttps' ? https : k === 'nodeUrl' ? require('url')
                            : k === 'nodeCrypto' ? require('crypto') : g[k]),
               set: ctx.set };
const fn = new Function('msg', 'node', 'flow', 'global', spec.func);
const now = Date.now();
fn({ _ppCfg: spec.cfg }, node, ctx, glob);
console.log(JSON.stringify({ sent: sent.map((m) => m._ppIncidents), warns, requested, g, now }));
'''

CHALLENGE = {'status': 202, 'headers': {'x-amzn-waf-action': 'challenge'}, 'body': ''}
GOOD = {'status': 200, 'headers': {},
        'body': json.dumps({'incidents': {'active': [{'ID': '77', 'AgencyID': 'EMS1316'}]}})}


def _run(tmp_path, replies, ids=('05900', 'PID159', 'EMS1316'), state=None):
    h = tmp_path / 'harness.js'
    h.write_text(HARNESS)
    s = tmp_path / 'spec.json'
    func = FETCH.replace('__FEED_ID__', 'f1')
    s.write_text(json.dumps({
        'func': func,
        'cfg': {'activated': True, 'agencyIds': ','.join(ids)},
        'replies': replies,
        'global': {'pp_block_f1': state} if state is not None else {},
    }))
    out = subprocess.run(['node', str(h), str(s)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_challenge_is_named_not_json_error(tmp_path):
    r = _run(tmp_path, {i: CHALLENGE for i in ('05900', 'PID159', 'EMS1316')})
    log = ' '.join(r['warns'])
    assert 'blocked by PulsePoint bot protection' in log
    assert 'WAF challenge' in log
    assert 'Unexpected end of JSON' not in log
    assert r['sent'] == []  # nothing built from an empty reply


def test_challenge_starts_five_minute_backoff(tmp_path):
    r = _run(tmp_path, {i: CHALLENGE for i in ('05900', 'PID159', 'EMS1316')})
    st = r['g']['pp_block_f1']
    assert st['fails'] == 1
    assert 4.9 * 60000 < st['until'] - r['now'] < 5.1 * 60000 + 5000
    assert 'Next try in 5 min' in ' '.join(r['warns'])


def test_no_request_made_while_backed_off(tmp_path):
    state = {'fails': 1, 'until': 9999999999999}
    r = _run(tmp_path, {i: CHALLENGE for i in ('05900', 'PID159')}, ids=('05900', 'PID159'), state=state)
    assert r['requested'] == []
    assert r['warns'] == []


def test_backoff_doubles_and_caps_at_sixty(tmp_path):
    r = _run(tmp_path, {'05900': CHALLENGE}, ids=('05900',), state={'fails': 1, 'until': 1})
    assert r['g']['pp_block_f1']['fails'] == 2
    assert 'Next try in 10 min' in ' '.join(r['warns'])
    r = _run(tmp_path, {'05900': CHALLENGE}, ids=('05900',), state={'fails': 9, 'until': 1})
    assert 'Next try in 60 min' in ' '.join(r['warns'])


def test_recovery_clears_backoff_and_streams(tmp_path):
    r = _run(tmp_path, {'EMS1316': GOOD}, ids=('EMS1316',), state={'fails': 3, 'until': 1})
    assert len(r['sent']) == 1 and len(r['sent'][0]) == 1
    assert r['g']['pp_block_f1'] == {}
    assert 'access restored' in ' '.join(r['warns'])


def test_one_agency_blocked_others_still_stream_no_backoff(tmp_path):
    r = _run(tmp_path, {'05900': CHALLENGE, 'EMS1316': GOOD}, ids=('05900', 'EMS1316'))
    assert len(r['sent']) == 1 and len(r['sent'][0]) == 1
    assert 'pp_block_f1' not in r['g']
    assert '05900:blocked by PulsePoint bot protection' in ' '.join(r['warns'])


def test_non_json_200_is_named_and_does_not_back_off(tmp_path):
    r = _run(tmp_path, {'05900': {'status': 200, 'headers': {}, 'body': '<html>oops</html>'}},
             ids=('05900',))
    log = ' '.join(r['warns'])
    assert 'reply was not JSON (HTTP 200' in log
    assert 'pp_block_f1' not in r['g']


def test_other_http_error_keeps_plain_message(tmp_path):
    r = _run(tmp_path, {'05900': {'status': 500, 'headers': {}, 'body': 'x'}}, ids=('05900',))
    assert '05900:HTTP500' in ' '.join(r['warns'])
    assert 'pp_block_f1' not in r['g']
