// SPDX-License-Identifier: AGPL-3.0-or-later
// node --test modules/etlrunner/shim/test
import test from 'node:test';
import assert from 'node:assert/strict';
import {
    compile, ValidationError, rateMs, parseCron, cronMatch, field, warmBudgetMb, wantsWarm, planEviction,
    parseLogLines, parseSubnet, inSubnet, clampMem, TASK_RE,
} from '../lib.mjs';

const tmpl = (over = {}) => JSON.stringify({
    Description: 'layer',
    Parameters: { Task: { Default: 'etl-geojson-v2.13.0' }, UniqueID: { Default: 'abc' } },
    Resources: {
        ETLFunction: { Type: 'AWS::Lambda::Function', Properties: {
            FunctionName: { 'Fn::Join': ['-', [{ Ref: 'AWS::StackName' }]] }, MemorySize: 512, Timeout: 120,
            Environment: { Variables: { ETL_API: { 'Fn::ImportValue': 'coe-etl-hosted' }, ETL_LAYER: 7, EMPTY: null } } } },
        ETLRule: { Type: 'AWS::Events::Rule', Properties: { ScheduleExpression: 'rate(1 minute)', State: 'ENABLED' } },
        ...over,
    },
});

test('compile: function, image, env stringified, ETL_API import resolved', () => {
    const fn = compile('test-layer-7', tmpl(), [], 'http://api:5000');
    assert.equal(fn.FunctionName, 'test-layer-7');
    assert.equal(fn.Image, 'etl-local:etl-geojson-v2.13.0');
    assert.deepEqual(fn.Env, { ETL_API: 'http://api:5000', ETL_LAYER: '7', EMPTY: '' });
    assert.equal(fn.MemorySize, 512);
    assert.deepEqual(fn.Schedule, { expr: 'rate(1 minute)', state: 'ENABLED' });
    assert.equal(fn.Outgoing, false);
    assert.equal(fn.Webhook, null);
});

test('compile: parameter override wins over default', () => {
    const fn = compile('test-layer-7', tmpl(), [{ ParameterKey: 'Task', ParameterValue: 'etl-arcgis-v1.2.3' }], 'x');
    assert.equal(fn.Image, 'etl-local:etl-arcgis-v1.2.3');
});

test('compile: Task that is not etl-<name>-v<x.y.z> is a ValidationError (never an arbitrary image)', () => {
    for (const bad of ['alpine', 'etl-geojson', 'etl-x-v1.2.3;rm', '../etl-x-v1.2.3', 'etl-X-v1.2.3', 'etl-x-v1.2.3:latest', 'busybox@sha256:00']) {
        assert.throws(() => compile('s', tmpl(), [{ ParameterKey: 'Task', ParameterValue: bad }], 'x'), ValidationError, bad);
    }
    assert.ok(TASK_RE.test('etl-geojson-v2.13.0'));
});

test('compile: memory clamped to the broker range; bad JSON and missing function rejected', () => {
    assert.equal(clampMem(64), 128);
    assert.equal(clampMem(10240), 3008);
    assert.equal(clampMem('nope'), 128);
    assert.throws(() => compile('s', '{', [], 'x'), ValidationError);
    assert.throws(() => compile('s', JSON.stringify({ Parameters: { Task: { Default: 'etl-a-v1.0.0' } }, Resources: {} }), [], 'x'), ValidationError);
});

test('compile: outgoing queue and webhook detected', () => {
    const fn = compile('test-layer-7', tmpl({ OutgoingQueue: { Type: 'AWS::SQS::Queue' }, WebHookResourceIntegration: { Type: 'AWS::ApiGatewayV2::Integration' } }), [], 'x');
    assert.equal(fn.Outgoing, true);
    assert.equal(fn.Webhook, 'abc');
    assert.deepEqual(fn.Unsupported, []);
});

test('rate()', () => {
    assert.equal(rateMs('rate(1 minute)'), 60000);
    assert.equal(rateMs('rate(5 minutes)'), 300000);
    assert.equal(rateMs('rate(2 hours)'), 7200000);
    assert.equal(rateMs('rate(0 minutes)'), null);
    assert.equal(rateMs('cron(0 * * * ? *)'), null);
});

test('cron(): EventBridge 6 fields, UTC, steps, ranges, lists, names, L', () => {
    const at = (s) => new Date(s);
    const every2 = parseCron('cron(0/2 * * * ? *)');
    assert.ok(cronMatch(every2, at('2026-11-05T10:04:00Z')));
    assert.ok(!cronMatch(every2, at('2026-11-05T10:05:00Z')));
    const wk = parseCron('cron(30 9 ? * MON-FRI *)');
    assert.ok(cronMatch(wk, at('2026-11-05T09:30:00Z')));          // Thursday
    assert.ok(!cronMatch(wk, at('2026-11-08T09:30:00Z')));         // Sunday
    const last = parseCron('cron(0 0 L * ? *)');
    assert.ok(cronMatch(last, at('2026-02-28T00:00:00Z')));
    assert.ok(!cronMatch(last, at('2026-02-27T00:00:00Z')));
    const list = parseCron('cron(0 6,18 * JAN,JUL ? 2026)');
    assert.ok(cronMatch(list, at('2026-07-01T18:00:00Z')));
    assert.ok(!cronMatch(list, at('2027-07-01T18:00:00Z')));
    assert.throws(() => parseCron('cron(* * * *)'));
    assert.throws(() => field('70', 0, 59));
    assert.throws(() => field('*/0', 0, 59));
    assert.equal(parseCron('rate(1 minute)'), null);
});

test('keep-warm: budget = min(10% RAM, 2 GiB); only rate <= 300 s; LRU eviction', () => {
    assert.equal(warmBudgetMb('MemTotal:       16384000 kB\n'), 1600);
    assert.equal(warmBudgetMb('MemTotal:       65536000 kB\n'), 2048);
    assert.equal(warmBudgetMb(''), 0);
    assert.ok(wantsWarm({ Schedule: { expr: 'rate(1 minute)', state: 'ENABLED' } }));
    assert.ok(wantsWarm({ Schedule: { expr: 'rate(5 minutes)', state: 'ENABLED' } }));
    assert.ok(!wantsWarm({ Schedule: { expr: 'rate(6 minutes)', state: 'ENABLED' } }));
    assert.ok(!wantsWarm({ Schedule: { expr: 'rate(1 minute)', state: 'DISABLED' } }));
    assert.ok(!wantsWarm({ Schedule: null }));
    const w = [{ fn: 'a', mb: 512, lastUsed: 3 }, { fn: 'b', mb: 512, lastUsed: 1 }, { fn: 'c', mb: 512, lastUsed: 2 }];
    assert.deepEqual(planEviction(w, 512, 2048), { evict: [], fits: true });
    assert.deepEqual(planEviction(w, 1024, 2048), { evict: ['b'], fits: true });
    assert.deepEqual(planEviction(w, 4096, 2048).fits, false);
    assert.deepEqual(planEviction([], 512, 0), { evict: [], fits: false });
});

test('log lines and the ETL-subnet guard', () => {
    const l = parseLogLines('2026-11-05T10:00:00.123456789Z hello world\n\nnot-a-time line\n');
    assert.equal(l[0].m, 'hello world');
    assert.equal(l[0].t, Date.parse('2026-11-05T10:00:00.123Z'));
    assert.equal(l[1].m, 'not-a-time line');
    const net = parseSubnet('172.30.0.0/16');
    assert.ok(inSubnet('172.30.4.5', net));
    assert.ok(inSubnet('::ffff:172.30.4.5', net));
    assert.ok(!inSubnet('172.31.0.1', net));
    assert.ok(!inSubnet('fe80::1', net));
    assert.throws(() => parseSubnet('nope'));
});
