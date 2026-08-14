// Harness for v10.1.31 W2/W3/W4 — replays the CORAZ 2026-08-13 CA AIR INTEL flap.
const fs = require('fs');
const tf = JSON.parse(fs.readFileSync('template-functions.json', 'utf8'));
const fn = new Function('msg', 'node', 'flow', 'global', 'context', 'env', 'util',
  tf['arcgis.reconcile'].func);

function mkFeatures(uids) {
  // NOTE: reconcile reads feat.cot (not cotXml) — getting this wrong made every
  // streamed payload undefined and silently zeroed the keepalive assertion.
  return uids.map(u => ({ uid: u, cot: '<event uid="' + u + '"/>', _hash: 'h' }));
}
function mkMission(uids) {
  return { data: { uids: uids.map(u => ({ data: u })) } };
}

// Model real cadence: polls are 5 min apart, so the sweeper's 45s debounce never
// suppresses them in the field. Without this the harness fires polls back-to-back and
// the debounce silently swallows every ForceDelete — which would let a broadcast
// regression pass unnoticed (and did, until Scenario 5b caught it).
const POLL_INTERVAL_MS = 300000;
function tick(state) {
  if (typeof state._tombSweepTs === 'number') state._tombSweepTs -= POLL_INTERVAL_MS;
}

// One poll. Returns {puts, deletes, forceDeletes, warns}
function poll(state, arcgisUids, missionUids, cfgOver) {
  tick(state);
  const cfg = Object.assign({
    configName: 'CA AIR INTEL', missionName: 'AIR-INTEL', uidPrefix: 'firis-',
    strictMode: true, creatorUid: 'admin', cotStreamPort: 8089,
  }, cfgOver || {});
  const out = { puts: [], deletes: [], forceDeletes: [], warns: [], streamed: 0 };
  const flowStore = state;
  const flow = { get: k => flowStore[k], set: (k, v) => { flowStore[k] = v; } };
  const glob = { get: () => ({}), set: () => {} };
  const node = {
    warn: m => out.warns.push(String(m)),
    send: arr => {
      const [a, b] = arr;
      if (b && b.method === 'DELETE') out.deletes.push(decodeURIComponent(b.url.split('uid=')[1].split('&')[0]));
      if (a && a._rawCotXml) out.forceDeletes.push(a._rawCotXml.match(/<link uid="([^"]+)"/)[1]);
      if (a && a._putUids) out.puts.push(...a._putUids);
      if (a && a.payload && !a._rawCotXml) out.streamed++;
    },
  };
  const msg = {
    _features: mkFeatures(arcgisUids),
    payload: mkMission(missionUids),
    _config: cfg,
    takSettings: { serverUrl: 'https://tak.example', missionApiPort: 8443 },
    _arcgisStatus: 200,
    _missionCookie: 'c', _missionBearer: '',
  };
  fn(msg, node, flow, glob, {}, {}, {});
  return out;
}

let pass = 0, fail = 0;
function check(label, cond, detail) {
  if (cond) { pass++; console.log('  PASS  ' + label); }
  else { fail++; console.log('  FAIL  ' + label + (detail ? '  -> ' + detail : '')); }
}

const BASE = Array.from({ length: 30 }, (_, i) => 'firis-base-' + i);
const TALBOT = Array.from({ length: 50 }, (_, i) => 'firis-talbot-r' + i);
const ALL = BASE.concat(TALBOT);

// ── Scenario 1: the actual CORAZ flap ──────────────────────────────────────────
// Alternating 80-feature / 30-feature polls. Nothing may ever be deleted.
console.log('\nScenario 1 — CDN flap (80/30 alternating), mission holds all 80');
{
  const st = {};
  let anyDelete = 0, anyForce = 0;
  for (let i = 0; i < 12; i++) {
    const arcgis = (i % 2 === 0) ? ALL : BASE;          // stale copy every other poll
    const r = poll(st, arcgis, ALL);                     // mission already holds all 80
    anyDelete += r.deletes.length;
    anyForce += r.forceDeletes.length;
  }
  check('zero DELETEs across 12 alternating polls', anyDelete === 0, anyDelete + ' deletes');
  check('zero ForceDelete broadcasts', anyForce === 0, anyForce + ' forcedeletes');
}

// ── Scenario 2: a genuinely retired shape still gets cleaned up ────────────────
console.log('\nScenario 2 — genuine removal (1 UID gone for good)');
{
  const st = {};
  const mission = ALL.slice();
  const gone = TALBOT[0];
  const arcgis = ALL.filter(u => u !== gone);
  let deletedAt = -1;
  for (let i = 0; i < 5; i++) {
    const r = poll(st, arcgis, mission);
    if (r.deletes.includes(gone) && deletedAt < 0) deletedAt = i;
  }
  check('not deleted on poll 1 or 2', deletedAt >= 2, 'deleted at poll index ' + deletedAt);
  check('deleted by poll 3 (MISS_THRESHOLD=3)', deletedAt === 2, 'deleted at poll index ' + deletedAt);
}

// ── Scenario 3: streak resets on a single good poll ────────────────────────────
console.log('\nScenario 3 — miss, miss, then it comes back, then miss again');
{
  const st = {};
  const gone = TALBOT[0];
  const without = ALL.filter(u => u !== gone);
  let deletes = 0;
  poll(st, without, ALL);            // miss 1
  poll(st, without, ALL);            // miss 2
  poll(st, ALL, ALL);                // back -> streak must reset
  deletes += poll(st, without, ALL).deletes.length;  // miss 1 again
  deletes += poll(st, without, ALL).deletes.length;  // miss 2 again
  check('no delete after reset (streak did not carry over)', deletes === 0, deletes + ' deletes');
}

// ── Scenario 4: W4 magnitude guard — the test12 148-wipe shape ─────────────────
console.log('\nScenario 4 — mass delete (148 -> 30, config-change shape)');
{
  const st = {};
  const BIG = Array.from({ length: 148 }, (_, i) => 'firis-big-' + i);
  const KEEP = BIG.slice(0, 30);
  let firstDelete = -1;
  for (let i = 0; i < 8; i++) {
    const r = poll(st, KEEP, BIG);
    if (r.deletes.length && firstDelete < 0) firstDelete = i;
  }
  check('held past MISS_THRESHOLD (not deleted at poll 3)', firstDelete >= 5,
        'first delete at poll index ' + firstDelete);
  check('mass claim eventually converges (by poll 6)', firstDelete === 5,
        'first delete at poll index ' + firstDelete);
  const st2 = {};
  const r1 = poll(st2, KEEP, BIG);
  check('MASS-DELETE GUARD warning emitted', r1.warns.some(w => /MASS-DELETE GUARD/.test(w)),
        JSON.stringify(r1.warns.slice(-1)));
}

// ── Scenario 5: W3 — a tombstoned UID that is live in the mission ──────────────
console.log('\nScenario 5 — W3: never ForceDelete a UID the mission still holds');
{
  const st = { _tombstones: {}, _tombSweepTs: 0 };
  const live = TALBOT[0];
  st._tombstones[live] = Date.now();        // stale tombstone from an earlier flap
  // mission holds it; this poll's ArcGIS result does NOT (stale copy)
  const r = poll(st, BASE, ALL);
  check('no ForceDelete for a UID present in mission contents',
        !r.forceDeletes.includes(live), r.forceDeletes.length + ' broadcast');
  check('stale tombstone was cleared', !st._tombstones[live]);
}

// ── Scenario 5b: a UID deleted THIS pass must still be tombstoned ──────────────
// Field-caught on test12 2026-08-13: W3's live-shape guard read the pre-delete mission
// snapshot, so it cleared the tombstone for UIDs deleted in the same pass — silently
// disabling ghost cleanup for exactly the UIDs that need it.
console.log('\nScenario 5b — deleted-this-pass UID must be tombstoned (regression guard)');
{
  const st = {};
  const gone = TALBOT[0];
  const without = ALL.filter(u => u !== gone);
  let r;
  for (let i = 0; i < 3; i++) r = poll(st, without, ALL);   // 3 misses -> delete on the 3rd
  check('the UID was deleted', r.deletes.includes(gone), JSON.stringify(r.deletes));
  const tombs = st._tombstones || {};
  check('a tombstone was written and SURVIVED the sweep', !!tombs[gone],
        'tombstones: ' + Object.keys(tombs).length);
  // and it must actually broadcast on a later poll (device still offline)
  const r2 = poll(st, without, without);   // mission now reflects the delete
  check('ForceDelete broadcast on the following poll', r2.forceDeletes.includes(gone),
        r2.forceDeletes.length + ' broadcast');
}

// ── Scenario 7: keepalive re-stream (dangling-UID rot) ────────────────────────
// A quiet feed must still re-stream its CoT periodically, or TAK ages the events out
// of its repository while the mission keeps the UIDs — mission points at nothing and
// new subscribers sit on ATAK's yellow pending icon forever.
console.log('\nScenario 7 — quiet feed re-streams so its CoT cannot age out');
{
  const st = {};
  poll(st, ALL, ALL);                       // cold start: seeds, does not stream
  const quiet = poll(st, ALL, ALL);         // nothing changed
  check('steady state does not re-stream every poll', quiet.puts.length === 0);
  // age every keepalive timestamp past the refresh window
  const ls = st._lastStreamed || {};
  const aged = Object.keys(ls).length;
  for (const k of Object.keys(ls)) ls[k] -= (7 * 3600000);
  check('keepalive timestamps are tracked', aged > 0, aged + ' tracked');
  const r = poll(st, ALL, ALL);
  check('due UIDs get re-streamed', r.streamed > 0, r.streamed + ' streamed');
  check('burst is capped per poll', r.streamed <= 25, r.streamed + ' streamed (cap 25)');
}

// ── Scenario 8: tombstone sweep is capped ─────────────────────────────────────
console.log('\nScenario 8 — tombstone sweep burst cap + send-count retirement');
{
  const st = { _tombstones: {}, _tombSweepTs: 0, _tombSends: {} };
  const now = Date.now();
  for (let i = 0; i < 600; i++) st._tombstones['firis-dead-' + i] = now - i * 1000;
  const r = poll(st, BASE, BASE);
  check('sweep burst capped at 250', r.forceDeletes.length === 250,
        r.forceDeletes.length + ' broadcast');
  check('oldest tombstones go first',
        r.forceDeletes.includes('firis-dead-599'), 'oldest present');
  // drive one uid past the send cap
  st._tombSends['firis-dead-599'] = 48;
  const r2 = poll(st, BASE, BASE);
  check('retired uid is no longer broadcast', !r2.forceDeletes.includes('firis-dead-599'));
}

// ── Scenario 6: existing guards still work ─────────────────────────────────────
console.log('\nScenario 6 — 0 features from ArcGIS must still skip deletes');
{
  const st = {};
  let deletes = 0;
  for (let i = 0; i < 5; i++) deletes += poll(st, [], ALL).deletes.length;
  check('zero features never deletes', deletes === 0, deletes + ' deletes');
}

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
