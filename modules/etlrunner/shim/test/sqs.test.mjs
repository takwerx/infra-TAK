// SPDX-License-Identifier: AGPL-3.0-or-later
// W6 follow-on: the outgoing SQS journal. node --test test/sqs.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { sqsReplay, sqsSnapshot, SQS_MAX_DEAD } from '../lib.mjs';

const m = (id, tries = 0) => ({ Id: id, MessageBody: `body-${id}`, queue: 'q', tries, ts: 1 });
const J = (...recs) => recs.map((r) => JSON.stringify(r)).join('\n') + '\n';

test('replay: add, deliver, retry to the end, dead-letter', () => {
    const Q = sqsReplay(J(
        { o: 'a', f: 'L', m: m('1') }, { o: 'a', f: 'L', m: m('2') }, { o: 'a', f: 'L', m: m('3') },
        { o: 'k', f: 'L', id: '1' },              // delivered
        { o: 'r', f: 'L', id: '2', t: 1 },        // failed once: moves behind 3
        { o: 'a', f: 'L', m: m('4') },
        { o: 'x', f: 'L', id: '4' },              // dead
    ));
    assert.deepEqual(Q.L.q.map((x) => [x.Id, x.tries]), [['3', 0], ['2', 1]]);
    assert.deepEqual(Q.L.dead.map((x) => x.Id), ['4']);
});

test('replay: an undelivered message (crash mid-delivery) is still queued', () => {
    const Q = sqsReplay(J({ o: 'a', f: 'L', m: m('1') }));
    assert.equal(Q.L.q[0].Id, '1');
});

test('replay: torn last line and junk are skipped', () => {
    const Q = sqsReplay(J({ o: 'a', f: 'L', m: m('1') }) + '{"o":"a","f":"L","m":{"Id":"2"' + '\nnull\n[1]\n{"o":"a"}\n');
    assert.deepEqual(Q.L.q.map((x) => x.Id), ['1']);
});

test('replay: purge and functions that no longer exist are dropped', () => {
    const t = J({ o: 'a', f: 'L', m: m('1') }, { o: 'a', f: 'gone', m: m('2') }, { o: 'a', f: 'P', m: m('3') }, { o: 'p', f: 'P' });
    const Q = sqsReplay(t, new Set(['L', 'P']));
    assert.deepEqual(Object.keys(Q), ['L']);
});

test('replay: an ack for an unknown id changes nothing', () => {
    const Q = sqsReplay(J({ o: 'a', f: 'L', m: m('1') }, { o: 'k', f: 'L', id: 'nope' }, { o: 'x', f: 'L', id: 'nope' }));
    assert.deepEqual(Q.L.q.map((x) => x.Id), ['1']);
    assert.equal(Q.L.dead.length, 0);
});

test('snapshot round-trips and dead letters stay capped', () => {
    const recs = [];
    for (let i = 0; i < SQS_MAX_DEAD + 5; i++) recs.push({ o: 'a', f: 'L', m: m(`d${i}`) }, { o: 'x', f: 'L', id: `d${i}` });
    recs.push({ o: 'a', f: 'L', m: m('live', 2) });
    const Q = sqsReplay(J(...recs));
    assert.equal(Q.L.dead.length, SQS_MAX_DEAD);
    assert.equal(Q.L.dead[0].Id, 'd5');
    const again = sqsReplay(sqsSnapshot(Q));
    assert.deepEqual(again, Q);
    assert.equal(sqsSnapshot({}), '');
});
