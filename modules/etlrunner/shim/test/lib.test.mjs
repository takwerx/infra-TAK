// SPDX-License-Identifier: AGPL-3.0-or-later
// node --test modules/etlrunner/shim/test
import test from 'node:test';
import assert from 'node:assert/strict';
import {
    compile, ValidationError, rateMs, parseCron, cronMatch, field, warmBudgetMb, wantsWarm, planEviction,
    parseLogLines, parseSubnet, inSubnet, clampMem, TASK_RE, normalizeFn,
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

test('normalizeFn: state from the spike (numeric env) is fixed; non-ETL images dropped', () => {
    const fn = normalizeFn({ FunctionName: 'test-layer-13', Image: 'etl-local:etl-geojson-v2.13.0', Env: { ETL_LAYER: 13, X: null }, MemorySize: 64, Timeout: 'x' });
    assert.deepEqual(fn.Env, { ETL_LAYER: '13', X: '' });
    assert.equal(fn.MemorySize, 128);
    assert.equal(fn.Timeout, 60);
    assert.equal(normalizeFn({ FunctionName: 'a', Image: 'alpine:latest' }), null);
    assert.equal(normalizeFn({ FunctionName: '../a', Image: 'etl-local:etl-a-v1.0.0' }), null);
    assert.equal(normalizeFn(null), null);
});

// ---- W7 webhooks ----
import { timingSafeEqual } from 'node:crypto';
import { hookRoute, HOOK_PREFIX } from '../lib.mjs';
const SEC = 'A'.repeat(43);
test('hookRoute: right secret routes and strips prefix + secret', () => {
    const r = hookRoute(`${HOOK_PREFIX}/${SEC}/1b2c-3d/a/b`, SEC, timingSafeEqual);
    assert.deepEqual(r, { uid: '1b2c-3d', rest: ['a', 'b'], rawPath: '/1b2c-3d/a/b' });
    assert.equal(hookRoute(`${HOOK_PREFIX}/${SEC}/abc`, SEC, timingSafeEqual).rawPath, '/abc');
});
test('hookRoute: wrong, short, missing secret refused', () => {
    for (const p of [`${HOOK_PREFIX}/${'B'.repeat(43)}/abc`, `${HOOK_PREFIX}/AAA/abc`, `${HOOK_PREFIX}//abc`,
        `${HOOK_PREFIX}/abc`, `/abc`, `/${SEC}/abc`, `/etl-hooksX/${SEC}/abc`]) {
        assert.ok(hookRoute(p, SEC, timingSafeEqual).refuse, p);
    }
});
test('hookRoute: no secret configured refuses everything (fail closed)', () => {
    for (const s of ['', undefined, 'short', 'A'.repeat(44)]) {
        assert.equal(hookRoute(`${HOOK_PREFIX}/${SEC}/abc`, s, timingSafeEqual).refuse, 'no secret configured');
    }
});
test('hookRoute: bad layer id and dot segments refused', () => {
    assert.ok(hookRoute(`${HOOK_PREFIX}/${SEC}/`, SEC, timingSafeEqual).refuse);
    assert.ok(hookRoute(`${HOOK_PREFIX}/${SEC}/a$b`, SEC, timingSafeEqual).refuse);
    assert.ok(hookRoute(`${HOOK_PREFIX}/${SEC}/abc/../x`, SEC, timingSafeEqual).refuse);
});

// ---- security review fixes (2026-11-09) ----
import { hookResponse, hookEventHeaders, rateMs as rate2, compile as compile2, RATE_MIN_MS } from '../lib.mjs';

test('hookResponse: an ETL cannot serve HTML or set cookies on the CloudTAK origin', () => {
    const r = hookResponse({ statusCode: 200, headers: { 'Content-Type': 'text/html', 'Set-Cookie': 'a=b', Location: 'https://evil' }, body: '<script>x</script>' });
    assert.equal(r.status, 200);
    assert.equal(r.headers['Content-Type'], 'text/plain; charset=utf-8');
    assert.equal(r.headers['X-Content-Type-Options'], 'nosniff');
    assert.match(r.headers['Content-Security-Policy'], /^sandbox/);
    assert.ok(!Object.keys(r.headers).some((k) => /set-cookie|location/i.test(k)));
    assert.equal(hookResponse({ statusCode: 200, headers: { 'content-type': 'application/json; charset=utf-8' }, body: '{}' }).headers['Content-Type'], 'application/json; charset=utf-8');
    for (const t of ['image/svg+xml', 'application/xml', 'text/html;x', 'application/json\r\nX: y']) {
        assert.equal(hookResponse({ statusCode: 200, headers: { 'Content-Type': t }, body: '' }).headers['Content-Type'], 'text/plain; charset=utf-8', t);
    }
});

test('hookResponse: bad shapes become 502 instead of crashing the shim', () => {
    for (const r of [{ statusCode: 200, body: {} }, { statusCode: 'x' }, { statusCode: 99 }, { statusCode: 700 }, { statusCode: 200.5 }, { statusCode: 200, body: 5 }]) {
        assert.equal(hookResponse(r).status, 502, JSON.stringify(r));
    }
    assert.equal(hookResponse({ statusCode: 201, body: 'aGk=', isBase64Encoded: true }).body.toString(), 'hi');
    assert.equal(hookResponse('plain').body, 'plain');
    assert.equal(hookResponse({ a: 1 }).body, '{"a":1}');
    assert.equal(hookResponse(null).status, 200);
});

test('hookEventHeaders: the browser cookie never reaches an ETL; Authorization does', () => {
    const h = hookEventHeaders({ cookie: 'session=1', Cookie: 'x', authorization: 'Bearer t', 'x-a': ['1', '2'] });
    assert.deepEqual({ ...h }, { authorization: 'Bearer t', 'x-a': '1,2' });
    assert.equal(Object.getPrototypeOf(h), null);
});

test('rateMs: clamped to one minute, no overflow', () => {
    assert.equal(rate2('rate(1 second)'), RATE_MIN_MS);
    assert.equal(rate2('rate(5 minutes)'), 300000);
    assert.equal(rate2('rate(25 days)'), 25 * 864e5);
    assert.equal(rate2('rate(99999999999999999 days)'), null);
});

test('compile: FunctionName must be the stack name; webhook UniqueID is checked', () => {
    const t = (fnName, extra = {}) => JSON.stringify({
        Parameters: { Task: { Default: 'etl-cot-v1.4.0' }, UniqueID: { Default: extra.uid ?? 'abc-123' } },
        Resources: { F: { Type: 'AWS::Lambda::Function', Properties: { FunctionName: fnName } },
            ...(extra.hook ? { WebHookResourceIntegration: { Type: 'AWS::ApiGatewayV2::Integration' } } : {}) } });
    assert.equal(compile2('test-layer-9', t('test-layer-9'), [], 'http://api:5000').FunctionName, 'test-layer-9');
    assert.throws(() => compile2('test-layer-9', t('test-layer-1'), [], 'http://api:5000'), ValidationError);
    assert.throws(() => compile2('test-layer-9', t('test-layer-9', { hook: true, uid: '../x' }), [], 'http://api:5000'), ValidationError);
    assert.equal(compile2('test-layer-9', t('test-layer-9', { hook: true }), [], 'http://api:5000').Webhook, 'abc-123');
});

import { hookCookie, HOOK_COOKIE, HOOK_MASK } from '../lib.mjs';
test('hookRoute: the secret may come in Caddy\'s cookie when the path is masked', () => {
    const p = `${HOOK_PREFIX}/${HOOK_MASK}/abc-1/x`;
    assert.equal(hookRoute(p, SEC, timingSafeEqual, SEC).uid, 'abc-1');
    assert.equal(hookRoute(p, SEC, timingSafeEqual, SEC).rawPath, '/abc-1/x');
    for (const c of ['', '_', SEC.slice(1), 'x'.repeat(43)]) assert.ok(hookRoute(p, SEC, timingSafeEqual, c).refuse, c);
    // a cookie never stands in for a wrong secret in the path
    assert.ok(hookRoute(`${HOOK_PREFIX}/${'y'.repeat(43)}/abc`, SEC, timingSafeEqual, SEC).refuse);
    assert.equal(hookCookie(`a=1; ${HOOK_COOKIE}=${SEC}; b=2`), SEC);
    assert.equal(hookCookie('a=1'), '');
});
