// SPDX-License-Identifier: AGPL-3.0-or-later
// node --test modules/etlrunner/shim/test
// ops #1335: the shim's stacks.json is versioned, backed up, and never loses a layer it cannot read.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseState, serializeState, STATE_FORMAT, STATE_FORMAT_KEY } from '../lib.mjs';

const SHIM = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'shim.mjs');

const fn = (name, over = {}) => ({ FunctionName: name, Image: 'etl-local:etl-geojson-v2.13.0', Env: {}, MemorySize: 512, Timeout: 60, ...over });
const stack = (name, over = {}) => ({ id: `arn:${name}`, status: 'CREATE_COMPLETE', created: '2026-01-01T00:00:00Z', desc: '', fn: fn(name, over) });
// what shims before this change wrote: a flat map, no format key
const legacy = () => ({ 'etl-a-layer-1': stack('etl-a-layer-1'), 'etl-b-layer-2': stack('etl-b-layer-2') });

test('parseState: a file with no format key is format 0 and every runnable layer loads', () => {
    const r = parseState(JSON.stringify(legacy()));
    assert.equal(r.status, 'ok');
    assert.equal(r.format, 0);
    assert.deepEqual(Object.keys(r.stacks).sort(), ['etl-a-layer-1', 'etl-b-layer-2']);
    assert.deepEqual(Object.keys(r.held), []);
});

test('parseState: a layer this shim cannot run is held, never dropped', () => {
    const f = { ...legacy(), 'etl-c-layer-3': stack('etl-c-layer-3', { Image: 'alpine' }), 'etl-d-layer-4': { id: 'x', fn: null } };
    const r = parseState(JSON.stringify(f));
    assert.equal(r.status, 'ok');
    assert.deepEqual(Object.keys(r.stacks).sort(), ['etl-a-layer-1', 'etl-b-layer-2']);
    assert.deepEqual(Object.keys(r.held).sort(), ['etl-c-layer-3', 'etl-d-layer-4']);
    // written back untouched
    const back = JSON.parse(serializeState(r.stacks, r.held));
    assert.deepEqual(back['etl-c-layer-3'], f['etl-c-layer-3']);
    assert.deepEqual(back['etl-d-layer-4'], f['etl-d-layer-4']);
    assert.equal(back[STATE_FORMAT_KEY], STATE_FORMAT);
});

test('serializeState: the format key comes first and round-trips', () => {
    const r = parseState(JSON.stringify(legacy()));
    const text = serializeState(r.stacks, r.held);
    assert.equal(Object.keys(JSON.parse(text))[0], STATE_FORMAT_KEY);
    const again = parseState(text);
    assert.equal(again.status, 'ok');
    assert.equal(again.format, STATE_FORMAT);
    assert.deepEqual(Object.keys(again.stacks).sort(), ['etl-a-layer-1', 'etl-b-layer-2']);
});

test('parseState: a higher or unreadable format number is "newer": leave the file alone', () => {
    for (const bad of [STATE_FORMAT + 1, 99, 0, -1, 1.5, '1', null, 'x']) {
        const r = parseState(JSON.stringify({ [STATE_FORMAT_KEY]: bad, ...legacy() }));
        assert.equal(r.status, 'newer', `format ${JSON.stringify(bad)}`);
    }
});

test('parseState: not JSON, or not an object, is corrupt', () => {
    for (const bad of ['{"etl-a":', 'not json', '[]', '42', 'null']) assert.equal(parseState(bad).status, 'corrupt', bad);
});

test('the format key can never be a StackName (CreateStack names start with a letter)', () => {
    assert.equal(/^[A-Za-z][A-Za-z0-9-]{0,127}$/.test(STATE_FORMAT_KEY), false);
});

// ---- the real shim.mjs, started on a state file. It has no broker here, so it ends at
// "start-up failed"; everything the state load does has happened by then.
function runShim(dir, { waitMs = 1500 } = {}) {
    return new Promise((resolve) => {
        const p = spawn(process.execPath, [SHIM], {
            env: { PATH: process.env.PATH, SHIM_STATE: path.join(dir, 'stacks.json'), SHIM_BROKER_SOCK: path.join(dir, 'none.sock') },
        });
        let out = '';
        p.stdout.on('data', (d) => { out += d; });
        p.stderr.on('data', (d) => { out += d; });
        const timer = setTimeout(() => p.kill('SIGKILL'), waitMs);
        p.on('close', (code) => { clearTimeout(timer); resolve({ code, out }); });
    });
}
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'shim-state-'));
const files = (dir) => fs.readdirSync(dir).sort();

test('shim: a legacy file is copied aside as it was, then gets the format key; no layer is lost', async () => {
    const dir = tmp();
    const original = JSON.stringify(legacy(), null, 1);
    fs.writeFileSync(path.join(dir, 'stacks.json'), original);
    await runShim(dir);
    assert.equal(fs.readFileSync(path.join(dir, 'stacks.json.bak-pre-format'), 'utf8'), original);
    const now = JSON.parse(fs.readFileSync(path.join(dir, 'stacks.json'), 'utf8'));
    assert.equal(now[STATE_FORMAT_KEY], STATE_FORMAT);
    assert.deepEqual(Object.keys(now).filter((k) => k !== STATE_FORMAT_KEY).sort(), ['etl-a-layer-1', 'etl-b-layer-2']);
    assert.equal(fs.statSync(path.join(dir, 'stacks.json')).mode & 0o777, 0o600);   // as save() always wrote it
});

test('shim: a layer it cannot run stays in the file and a time-stamped copy is kept', async () => {
    const dir = tmp();
    const f = { ...legacy(), 'etl-c-layer-3': stack('etl-c-layer-3', { Image: 'alpine' }) };
    const original = JSON.stringify(f, null, 1);
    fs.writeFileSync(path.join(dir, 'stacks.json'), original);
    const { out } = await runShim(dir);
    const now = JSON.parse(fs.readFileSync(path.join(dir, 'stacks.json'), 'utf8'));
    assert.deepEqual(now['etl-c-layer-3'], f['etl-c-layer-3']);
    assert.ok(now['etl-a-layer-1'] && now['etl-b-layer-2']);
    const stamped = files(dir).filter((x) => /^stacks\.json\.bak-2\d{7}T\d{6}Z$/.test(x));
    assert.equal(stamped.length, 1, files(dir).join(','));
    assert.equal(fs.readFileSync(path.join(dir, stamped[0]), 'utf8'), original);
    assert.match(out, /keeping etl-c-layer-3/);
});

test('shim: a file with a newer format is refused and left exactly as it was', async () => {
    const dir = tmp();
    const original = JSON.stringify({ [STATE_FORMAT_KEY]: STATE_FORMAT + 1, ...legacy() }, null, 1);
    fs.writeFileSync(path.join(dir, 'stacks.json'), original);
    const { code, out } = await runShim(dir, { waitMs: 8000 });
    assert.equal(code, 1);
    assert.match(out, /newer than this shim reads/);
    assert.equal(fs.readFileSync(path.join(dir, 'stacks.json'), 'utf8'), original);
    assert.deepEqual(files(dir), ['stacks.json']);
});

test('shim: a corrupt file is kept beside the new one, not silently overwritten', async () => {
    const dir = tmp();
    const original = '{"etl-a-layer-1": {"id": "x", ';
    fs.writeFileSync(path.join(dir, 'stacks.json'), original);
    const { out } = await runShim(dir);
    const kept = files(dir).filter((x) => x.startsWith('stacks.json.corrupt-'));
    assert.equal(kept.length, 1, files(dir).join(','));
    assert.equal(fs.readFileSync(path.join(dir, kept[0]), 'utf8'), original);
    assert.match(out, /not readable/);
});

test('shim: no file is a fresh start with nothing written', async () => {
    const dir = tmp();
    await runShim(dir);
    assert.deepEqual(files(dir), []);
});

test('shim: only five time-stamped copies are kept', async () => {
    const dir = tmp();
    const f = { ...legacy(), 'etl-c-layer-3': stack('etl-c-layer-3', { Image: 'alpine' }) };
    fs.writeFileSync(path.join(dir, 'stacks.json'), JSON.stringify({ [STATE_FORMAT_KEY]: STATE_FORMAT, ...f }, null, 1));
    for (let i = 1; i <= 6; i++) fs.writeFileSync(path.join(dir, `stacks.json.bak-2026010${i}T000000Z`), 'old');
    await runShim(dir);
    const stamped = files(dir).filter((x) => /^stacks\.json\.bak-2/.test(x));
    assert.equal(stamped.length, 5, stamped.join(','));
    assert.ok(!stamped.includes('stacks.json.bak-20260101T000000Z'));
});
