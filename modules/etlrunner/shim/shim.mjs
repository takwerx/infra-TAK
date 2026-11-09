// SPDX-License-Identifier: AGPL-3.0-or-later
// infra-TAK — TAK Infrastructure Platform
// Copyright (C) 2026 Andreas Johansson (TAKWERX)
//
// etl-shim (ETL Runner, v10.4.0 W1). Answers the subset of AWS APIs CloudTAK uses for ETL
// layers — CloudFormation, Lambda, ECR, CloudWatch Logs, STS, SQS — and runs each ETL
// invocation as a local container of the layer's image (the Lambda base image carries the
// Runtime Interface Emulator on :8080).
//
// It has NO Docker socket. Every container operation is one call to the root broker's `etl`
// verb over /run/etl/broker.sock (broker/takwerx_broker.py, ETL section), which forces the
// image name, network, user, memory and hardened profile itself. See PLAN-v10.4.0 W2.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import fs from 'node:fs';
import { randomUUID, createHash } from 'node:crypto';
import {
    compile, normalizeFn, ValidationError, rateMs, parseCron, cronMatch, wantsWarm, warmBudgetMb, planEviction,
    parseLogLines, parseSubnet, inSubnet, KEEPWARM_MS, MAX_CONCURRENT, REPO,
} from './lib.mjs';

const PORT = 4000;                                            // AWS API — internal only, never published
const HOOK_PORT = 4001;                                       // webhooks — the only port a proxy may expose
const ETL_API = process.env.SHIM_ETL_API || 'http://api:5000';
const BROKER_SOCK = process.env.SHIM_BROKER_SOCK || '/run/etl/broker.sock';
const STATE = process.env.SHIM_STATE || '/data/stacks.json';
const CAP_LABEL = 'com.cloudtak.capabilities';
const NS = 'http://cloudformation.amazonaws.com/doc/2010-05-15/';

const log = (...a) => console.log(new Date().toISOString(), ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- state ----
let stacks = {};            // StackName -> { id, status, created, desc, fn }
try { stacks = JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch { /* fresh */ }
for (const [name, s] of Object.entries(stacks)) {
    const fn = normalizeFn(s?.fn);
    if (fn) s.fn = fn; else { log(`state: dropping stack ${name} (not a runnable ETL function)`); delete stacks[name]; }
}
function save() {
    try {
        const tmp = `${STATE}.tmp`;
        fs.writeFileSync(tmp, JSON.stringify(stacks, null, 1), { mode: 0o600 });
        fs.renameSync(tmp, STATE);
    } catch (e) { log('save fail', e.message); }
}
const runs = {};            // FunctionName -> [{ stream, ts, lines }]
const status = {};          // FunctionName -> { runs, errors, skipped, last: {...} }
const timers = {};
const warm = {};            // FunctionName -> { id, ip, idle, image, mb, lastUsed }
const busy = {};            // FunctionName -> Promise chain (one in-flight invoke per function, like a warm Lambda)
const running = new Set();  // FunctionName of scheduled runs in flight (skip-if-running)
let WARM_BUDGET_MB = 0;
try { WARM_BUDGET_MB = warmBudgetMb(fs.readFileSync('/proc/meminfo', 'utf8')); } catch { /* no warm */ }

// ---- global concurrency gate ----
let active = 0; const waiters = [];
async function gate() { if (active < MAX_CONCURRENT) { active++; return; } await new Promise((r) => waiters.push(r)); active++; }
function ungate() { active--; const w = waiters.shift(); if (w) w(); }

// ---- the broker: one JSON request per connection, half-close, read to EOF ----
function brokerOnce(req, timeoutMs) {
    return new Promise((resolve, reject) => {
        const s = net.createConnection(BROKER_SOCK);
        const chunks = [];
        s.setTimeout(timeoutMs, () => s.destroy(Object.assign(new Error('broker timeout'), { code: 'ETIMEDOUT' })));
        s.on('connect', () => s.end(JSON.stringify(req)));
        s.on('data', (c) => chunks.push(c));
        s.on('error', reject);
        s.on('close', () => {
            if (!chunks.length) return reject(Object.assign(new Error('broker closed without a reply'), { code: 'EMPTY' }));
            try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch (e) { reject(e); }
        });
    });
}
// The broker recycles once a day and re-creates its socket; nothing was sent while the socket
// is missing or refusing, so retrying those cannot run a container twice.
async function broker(action, args = {}, timeoutMs = 60000) {
    const req = { op: 'etl', action, ...args };
    for (let i = 0; ; i++) {
        try {
            const r = await brokerOnce(req, timeoutMs);
            if (!r.ok) throw Object.assign(new Error(`broker ${action}: ${r.code || ''} ${r.error || 'failed'}`), { broker: r });
            return r;
        } catch (e) {
            if (!['ENOENT', 'ECONNREFUSED'].includes(e.code) || i >= 100) throw e;
            await sleep(200);
        }
    }
}

async function localImages() {
    const r = await broker('list-images');
    return r.images.map((im) => ({ imageTag: im.tag, imageDigest: im.digest, labels: im.capabilities ? { [CAP_LABEL]: im.capabilities } : {} }));
}

// ---- schedules ----
const crons = {};           // StackName -> parsed cron
function scheduled(name) {
    const s = stacks[name]; if (!s) return;
    const fn = s.fn.FunctionName;
    if (running.has(fn)) { (status[fn] ||= { runs: 0, errors: 0, skipped: 0 }).skipped++; log(`sched ${name}: previous run still going — skipped`); return; }
    running.add(fn);
    invoke(fn, {}, 'Event').catch((e) => log('sched invoke fail', e.message)).finally(() => running.delete(fn));
}
function disarm(name) { clearTimeout(timers[name]); clearInterval(timers[name]); delete timers[name]; delete crons[name]; }
function arm(name) {
    disarm(name);
    const s = stacks[name]; if (!s || !s.fn.Schedule) return;
    if (s.fn.Schedule.state !== 'ENABLED') { log(`sched ${name}: disabled`); return; }
    const ms = rateMs(s.fn.Schedule.expr);
    if (ms) {
        // stagger the first run so a restart does not fire every layer in the same second
        const jitter = Math.floor(Math.random() * Math.min(ms, 30000));
        timers[name] = setTimeout(() => { scheduled(name); timers[name] = setInterval(() => scheduled(name), ms); }, jitter);
        log(`sched ${name}: every ${ms / 1000}s (first in ${jitter}ms)`); return;
    }
    try { const c = parseCron(s.fn.Schedule.expr); if (c) { crons[name] = c; log(`sched ${name}: ${s.fn.Schedule.expr}`); return; } }
    catch (e) { log(`sched ${name}: ${e.message}`); return; }
    log(`sched ${name}: unsupported expression ${s.fn.Schedule.expr}`);
}
(function cronTick() {
    const now = new Date(); now.setUTCSeconds(0, 0);
    for (const [name, c] of Object.entries(crons)) if (cronMatch(c, now)) scheduled(name);
    setTimeout(cronTick, 60000 - (Date.now() % 60000) + 50);
})();

// ---- containers (all through the broker) ----
async function startContainer(fn) {
    const env = { ...fn.Env, AWS_LAMBDA_FUNCTION_TIMEOUT: String(fn.Timeout), AWS_LAMBDA_FUNCTION_MEMORY_SIZE: String(fn.MemorySize) };
    const r = await broker('run', { fn: fn.FunctionName, image: fn.Image, env, memory_mb: fn.MemorySize });
    if (!r.ip) { await broker('stop', { id: r.id }).catch(() => {}); throw new Error('ETL container has no address on the ETL network'); }
    return { id: r.id, cname: r.name, ip: r.ip, image: fn.Image, mb: fn.MemorySize, since: Date.now() };
}
async function stopContainer(c) { if (c) await broker('stop', { id: c.id }).catch((e) => log('stop fail', e.message)); }
function dropWarm(fnName) {
    const c = warm[fnName]; if (!c) return;
    clearTimeout(c.idle); delete warm[fnName]; stopContainer(c);
}
function post(ip, body, timeoutMs) {
    return new Promise((res, rej) => {
        const r = http.request({ host: ip, port: 8080, method: 'POST', path: '/2015-03-31/functions/function/invocations',
            headers: { 'Content-Length': body.length }, timeout: timeoutMs }, (rr) => {
            const ch = []; rr.on('data', (x) => ch.push(x)); rr.on('end', () => res(Buffer.concat(ch)));
        });
        r.on('error', rej);
        r.on('timeout', () => r.destroy(Object.assign(new Error('invoke timeout'), { code: 'TIMEOUT' })));
        r.write(body); r.end();
    });
}
async function collectLogs(fnName, c, sinceMs, t0) {
    const r = await broker('logs', { id: c.id, since: Math.floor(sinceMs / 1000) });
    (runs[fnName] ||= []).unshift({ stream: `${new Date(t0).toISOString().slice(0, 10)}/[$LATEST]${c.cname}-${t0}`, ts: t0, lines: parseLogLines(r.logs) });
    runs[fnName] = runs[fnName].slice(0, 20);
}
// Keep `c` warm for `fn` if the layer qualifies and the budget allows (LRU eviction).
function keepWarm(fn, c) {
    if (!wantsWarm(fn)) return false;
    const others = Object.entries(warm).filter(([k]) => k !== fn.FunctionName).map(([k, w]) => ({ fn: k, mb: w.mb, lastUsed: w.lastUsed }));
    const plan = planEviction(others, c.mb, WARM_BUDGET_MB);
    if (!plan.fits) return false;
    for (const k of plan.evict) { dropWarm(k); log(`warm ${k}: evicted (budget ${WARM_BUDGET_MB} MiB)`); }
    c.lastUsed = Date.now();
    warm[fn.FunctionName] = c;
    c.idle = setTimeout(() => { if (warm[fn.FunctionName] === c) { delete warm[fn.FunctionName]; stopContainer(c); log(`warm ${fn.FunctionName}: evicted (idle)`); } }, KEEPWARM_MS);
    return true;
}
function invoke(fnName, payload, type) {
    const prev = busy[fnName] || Promise.resolve();
    const p = prev.catch(() => {}).then(() => invokeNow(fnName, payload, type));
    busy[fnName] = p.catch(() => {});
    return p;
}
async function invokeNow(fnName, payload, type) {
    const s = Object.values(stacks).find((x) => x.fn.FunctionName === fnName);
    if (!s) { const e = new Error(`Function not found: ${fnName}`); e.code = 404; throw e; }
    const fn = s.fn, t0 = Date.now(), st = (status[fnName] ||= { runs: 0, errors: 0, skipped: 0, streak: 0 });
    await gate();
    let c = warm[fnName], cold = false, result, err;
    try {
        if (c) { clearTimeout(c.idle); delete warm[fnName]; }
        if (c && c.image !== fn.Image) { await stopContainer(c); c = null; }
        if (!c) { cold = true; c = await startContainer(fn); }
        const body = Buffer.from(JSON.stringify(payload ?? {}));
        for (let i = 0; i < 100; i++) {          // RIE needs a moment to listen after a cold start
            try { result = await post(c.ip, body, fn.Timeout * 1000 + 2000); break; }
            catch (e) { if (e.code !== 'ECONNREFUSED') { err = e; break; } await sleep(50); }
        }
        if (!result && !err) err = new Error('RIE never listened');
    } catch (e) { err = e; }
    if (c) { try { await collectLogs(fnName, c, cold ? 0 : t0 - 1000, t0); } catch { /* container may be gone */ } }
    let fnError = null;
    if (result) { try { const j = JSON.parse(result.toString()); if (j && j.errorType) fnError = `${j.errorType}: ${j.errorMessage}`; } catch { /* non-JSON */ } }
    // a timed-out or failed container is never reused
    if (c && (err || !keepWarm(fn, c))) await stopContainer(c);
    ungate();
    // `streak` = consecutive failed runs; Guard Dog alerts on it (one bad run is weather, five is a broken layer)
    st.runs++;
    if (err || fnError) { st.errors++; st.streak = (st.streak || 0) + 1; st.failing_since ||= new Date(t0).toISOString(); }
    else { st.streak = 0; st.failing_since = null; }
    st.last = { at: new Date(t0).toISOString(), ms: Date.now() - t0, cold, type, ok: !err && !fnError, error: err?.message || fnError || null };
    log(`invoke ${fnName} type=${type} ${cold ? 'cold' : 'warm'} took=${Date.now() - t0}ms${err ? ` ERR ${err.message}` : ''}${fnError ? ` FNERR ${fnError.slice(0, 120)}` : ''}`);
    if (err) throw err;
    return { result, fnError };
}

// ---- SQS outgoing: FIFO per layer, BatchSize 1, 3 tries then dead-letter (as the CloudTAK template asks) ----
const queues = {};          // FunctionName -> { q: [], pumping, dead: [] }
function enqueue(fnName, msg) {
    const Q = (queues[fnName] ||= { q: [], pumping: false, dead: [] });
    Q.q.push(msg); if (!Q.pumping) pump(fnName);
}
async function pump(fnName) {
    const Q = queues[fnName]; Q.pumping = true;
    while (Q.q.length) {
        const m = Q.q.shift();
        const event = { Records: [{ messageId: m.Id, receiptHandle: randomUUID(), body: m.MessageBody,
            attributes: { ApproximateReceiveCount: String(m.tries + 1), SentTimestamp: String(m.ts), MessageGroupId: m.MessageGroupId || '', MessageDeduplicationId: m.MessageDeduplicationId || '' },
            messageAttributes: {}, md5OfBody: createHash('md5').update(m.MessageBody || '').digest('hex'), eventSource: 'aws:sqs',
            eventSourceARN: `arn:aws:sqs:local:000000000000:${m.queue}`, awsRegion: 'local' }] };
        let ok = false;
        try { const r = await invoke(fnName, event, 'SQS'); ok = !r.fnError; } catch { ok = false; }
        if (!ok) { m.tries++; if (m.tries < 3) Q.q.push(m); else { Q.dead.push(m); Q.dead = Q.dead.slice(-1000); log(`sqs ${m.queue}: message ${m.Id} dead-lettered`); } }
    }
    Q.pumping = false;
}
function sqs(op, req, res) {
    const ct = 'application/x-amz-json-1.0';
    if (op !== 'SendMessageBatch' && op !== 'SendMessage') return json(res, 400, { __type: 'com.amazonaws.sqs#UnsupportedOperation', message: `shim: unsupported ${op}` }, ct);
    const queue = String(req.QueueUrl || '').split('/').pop();
    const stack = queue.replace(/-outgoing(-dead)?\.fifo$/, '');
    const s = stacks[stack];
    if (!s || !s.fn.Outgoing) return json(res, 400, { __type: 'com.amazonaws.sqs#QueueDoesNotExist', message: `The specified queue does not exist: ${queue}` }, ct);
    const entries = op === 'SendMessage' ? [{ Id: '0', ...req }] : (req.Entries || []);
    const Successful = [];
    for (const e of entries) {
        const MessageId = randomUUID();
        enqueue(s.fn.FunctionName, { ...e, Id: MessageId, queue, tries: 0, ts: Date.now() });
        Successful.push({ Id: e.Id, MessageId, MD5OfMessageBody: createHash('md5').update(e.MessageBody || '').digest('hex') });
    }
    log(`SQS ${op} ${queue} n=${entries.length}`);
    return json(res, 200, op === 'SendMessage' ? Successful[0] : { Successful, Failed: [] }, ct);
}

// ---- protocol helpers ----
const xmlEsc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
function cfnOk(res, action, inner, ns = NS) {
    res.writeHead(200, { 'Content-Type': 'text/xml' });
    res.end(`<${action}Response xmlns="${ns}"><${action}Result>${inner}</${action}Result><ResponseMetadata><RequestId>${randomUUID()}</RequestId></ResponseMetadata></${action}Response>`);
}
function cfnErr(res, code, msg) {
    res.writeHead(400, { 'Content-Type': 'text/xml' });
    res.end(`<ErrorResponse xmlns="${NS}"><Error><Type>Sender</Type><Code>${code}</Code><Message>${xmlEsc(msg)}</Message></Error><RequestId>${randomUUID()}</RequestId></ErrorResponse>`);
}
function json(res, code, obj, type) {
    const h = { 'Content-Type': type || 'application/json' };
    if (code >= 400 && obj.__type) h['x-amzn-ErrorType'] = obj.__type;
    res.writeHead(code, h); res.end(JSON.stringify(obj));
}
function members(form, prefix) {           // Parameters.member.N.ParameterKey -> [{...}]
    const out = [];
    const re = new RegExp(`^${prefix}\\.member\\.(\\d+)\\.(\\w+)$`);
    for (const [k, v] of form) { const m = re.exec(k); if (m && Number(m[1]) <= 200) (out[m[1] - 1] ||= {})[m[2]] = v; }
    return out.filter(Boolean);
}
function stackXml(name, s) {
    return `<member><StackName>${xmlEsc(name)}</StackName><StackId>${xmlEsc(s.id)}</StackId><StackStatus>${s.status}</StackStatus><CreationTime>${s.created}</CreationTime><Description>${xmlEsc(s.desc || '')}</Description><Parameters/><Outputs/><Tags/></member>`;
}

// ---- handlers ----
async function query(form, res) {          // CloudFormation + STS (both AWS query protocol)
    const action = form.get('Action'), name = form.get('StackName');
    if (action === 'GetCallerIdentity') return cfnOk(res, action, '<Arn>arn:aws:iam::000000000000:user/etl-shim</Arn><UserId>ETLSHIM</UserId><Account>000000000000</Account>', 'https://sts.amazonaws.com/doc/2011-06-15/');
    log(`CFN ${action} ${name || ''}`);
    if (action === 'ListStacks') return cfnOk(res, action, `<StackSummaries>${Object.entries(stacks).map(([n, s]) => `<member><StackName>${xmlEsc(n)}</StackName><StackId>${xmlEsc(s.id)}</StackId><StackStatus>${s.status}</StackStatus><CreationTime>${s.created}</CreationTime></member>`).join('')}</StackSummaries>`);
    if (action === 'DescribeStacks') {
        if (!name) return cfnOk(res, action, `<Stacks>${Object.entries(stacks).map(([n, s]) => stackXml(n, s)).join('')}</Stacks>`);
        // CloudTAK reads its own parent stack only for Tags (CloudFormation.self) — answer with an empty one
        if (!name.includes('-layer-')) return cfnOk(res, action, `<Stacks>${stackXml(name, { id: `arn:aws:cloudformation:local:000000000000:stack/${name}/parent`, status: 'CREATE_COMPLETE', created: new Date(0).toISOString() })}</Stacks>`);
        if (!stacks[name]) return cfnErr(res, 'ValidationError', `Stack with id ${name} does not exist`);
        return cfnOk(res, action, `<Stacks>${stackXml(name, stacks[name])}</Stacks>`);
    }
    if (action === 'CreateStack' || action === 'UpdateStack') {
        if (!name || !/^[A-Za-z][A-Za-z0-9-]{0,127}$/.test(name)) return cfnErr(res, 'ValidationError', `bad StackName ${name}`);
        if (action === 'CreateStack' && stacks[name]) return cfnErr(res, 'AlreadyExistsException', `Stack [${name}] already exists`);
        if (action === 'UpdateStack' && !stacks[name]) return cfnErr(res, 'ValidationError', `Stack with id ${name} does not exist`);
        const body = form.get('TemplateBody');
        let fn;
        try { fn = compile(name, body, members(form, 'Parameters'), ETL_API); }
        catch (e) { if (e instanceof ValidationError) return cfnErr(res, 'ValidationError', e.message); throw e; }
        const prev = stacks[name];
        let desc = ''; try { desc = JSON.parse(body).Description || ''; } catch { /* compile already parsed it */ }
        stacks[name] = { id: prev?.id || `arn:aws:cloudformation:local:000000000000:stack/${name}/${randomUUID()}`,
            status: action === 'CreateStack' ? 'CREATE_COMPLETE' : 'UPDATE_COMPLETE', created: prev?.created || new Date().toISOString(), desc, fn };
        save(); arm(name);
        // a changed image/env must not be served by an old warm container
        dropWarm(fn.FunctionName);
        log(`  -> fn=${fn.FunctionName} image=${fn.Image} schedule=${JSON.stringify(fn.Schedule)} outgoing=${fn.Outgoing} webhook=${fn.Webhook} unsupported=${fn.Unsupported.join(',') || 'none'}`);
        return cfnOk(res, action, `<StackId>${xmlEsc(stacks[name].id)}</StackId>`);
    }
    if (action === 'DeleteStack') {
        disarm(name);
        const fnName = stacks[name]?.fn.FunctionName;
        if (fnName) dropWarm(fnName);
        delete stacks[name]; save(); return cfnOk(res, action, '');
    }
    if (action === 'CancelUpdateStack') return cfnOk(res, action, '');
    return cfnErr(res, 'InvalidAction', `shim: unsupported ${action}`);
}
async function lambda(req, res, body) {
    const m = /^\/2015-03-31\/functions\/([^/]+)(\/invocations)?/.exec(req.url.split('?')[0]);
    if (!m) return json(res, 404, { __type: 'ResourceNotFoundException', Message: 'shim: bad lambda path' });
    const fnName = decodeURIComponent(m[1]);
    const s = Object.values(stacks).find((x) => x.fn.FunctionName === fnName);
    if (!s) return json(res, 404, { __type: 'ResourceNotFoundException', Type: 'User', Message: `Function not found: ${fnName}` });
    if (!m[2]) {
        return json(res, 200, { Configuration: { FunctionName: fnName, PackageType: 'Image', Timeout: s.fn.Timeout, MemorySize: s.fn.MemorySize },
            Code: { RepositoryType: 'ECR', ImageUri: `000000000000.dkr.ecr.local.amazonaws.com/${s.fn.Image}` } });
    }
    const type = req.headers['x-amz-invocation-type'] || 'RequestResponse';
    let payload = {}; try { payload = body.length ? JSON.parse(body.toString()) : {}; } catch { /* raw */ }
    if (type === 'Event') { invoke(fnName, payload, type).catch((e) => log('async invoke fail', e.message)); res.writeHead(202); return res.end(); }
    try {
        const { result, fnError } = await invoke(fnName, payload, type);
        const h = { 'X-Amz-Executed-Version': '$LATEST' }; if (fnError) h['X-Amz-Function-Error'] = 'Unhandled';
        res.writeHead(200, h); res.end(result);
    } catch (e) { json(res, 500, { __type: 'ServiceException', Message: e.message }); }
}
async function jsonTarget(target, body, res) {
    const req = body.length ? JSON.parse(body.toString()) : {};
    const [svc, op] = target.split('.');
    if (svc === 'AmazonSQS') return sqs(op, req, res);
    const ct = 'application/x-amz-json-1.1';
    if (op === 'ListImages') return json(res, 200, { imageIds: (await localImages()).map(({ imageTag, imageDigest }) => ({ imageTag, imageDigest })) }, ct);
    if (op === 'BatchGetImage') {
        const all = await localImages();
        const want = Array.isArray(req.imageIds) ? req.imageIds : [];
        const hit = all.filter((i) => want.some((w) => (w.imageTag && w.imageTag === i.imageTag) || (w.imageDigest && w.imageDigest === i.imageDigest)));
        // static capabilities: an OCI manifest whose annotation carries the label baked in at build time
        return json(res, 200, { images: hit.map((i) => ({ registryId: '000000000000', repositoryName: REPO, imageId: { imageTag: i.imageTag, imageDigest: i.imageDigest },
            imageManifestMediaType: 'application/vnd.oci.image.manifest.v1+json',
            imageManifest: JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', annotations: i.labels[CAP_LABEL] ? { [CAP_LABEL]: i.labels[CAP_LABEL] } : {} }) })), failures: [] }, ct);
    }
    const fnFromGroup = (g) => String(g || '').replace(/^\/aws\/lambda\//, '');
    if (op === 'DescribeLogStreams') {
        const r = runs[fnFromGroup(req.logGroupName)] || [];
        return json(res, 200, { logStreams: r.map((x) => ({ logStreamName: x.stream, creationTime: x.ts, firstEventTimestamp: x.ts, lastEventTimestamp: x.lines.at(-1)?.t || x.ts, lastIngestionTime: x.ts })) }, ct);
    }
    if (op === 'GetLogEvents') {
        const r = (runs[fnFromGroup(req.logGroupName)] || []).find((x) => x.stream === req.logStreamName);
        return json(res, 200, { events: (r?.lines || []).map((l) => ({ timestamp: l.t, message: l.m, ingestionTime: l.t })), nextForwardToken: 'f/end', nextBackwardToken: 'b/end' }, ct);
    }
    if (op === 'DeleteLogGroup') { delete runs[fnFromGroup(req.logGroupName)]; return json(res, 200, {}, ct); }
    log(`JSON unsupported ${String(target).slice(0, 80)}`);
    return json(res, 400, { __type: 'UnknownOperationException', message: 'shim: unsupported operation' }, ct);
}

// ETL containers share a network with the shim (it must reach their emulator) — they must never reach the AWS API.
let etlNets = null;         // [[base, maskBits], ...] of the ETL network
const fromEtlNet = (addr) => etlNets.some((n) => inSubnet(addr, n));

function statusDoc() {
    return { active, queued: waiters.length, max_concurrent: MAX_CONCURRENT, keepwarm_sec: KEEPWARM_MS / 1000, warm_budget_mb: WARM_BUDGET_MB,
        functions: Object.values(stacks).map((s) => ({ name: s.fn.FunctionName, image: s.fn.Image, schedule: s.fn.Schedule, outgoing: s.fn.Outgoing,
            webhook: s.fn.Webhook, warm: Boolean(warm[s.fn.FunctionName]), outgoing_backlog: queues[s.fn.FunctionName]?.q.length || 0,
            dead_letters: queues[s.fn.FunctionName]?.dead.length || 0, ...(status[s.fn.FunctionName] || { runs: 0, errors: 0, skipped: 0 }) })) };
}

const MAX_BODY = 8 * 1024 * 1024;           // CloudFormation's own TemplateBody cap is 51,200 bytes; SQS 256 KiB
function readBody(req, res, cb) {
    const chunks = []; let n = 0;
    req.on('data', (c) => { n += c.length; if (n > MAX_BODY) { res.writeHead(413); res.end(); req.destroy(); return; } chunks.push(c); });
    req.on('end', () => { if (n <= MAX_BODY) cb(Buffer.concat(chunks)); });
}
function apiHandler(req, res) {
    readBody(req, res, async (body) => {
        try {
            if (!etlNets || fromEtlNet(req.socket.remoteAddress)) { res.writeHead(403); return res.end(); }
            if (req.url === '/_status') return json(res, 200, statusDoc());
            const target = req.headers['x-amz-target'];
            if (target) return await jsonTarget(target, body, res);
            if (req.url.startsWith('/2015-03-31/functions')) return await lambda(req, res, body);
            if ((req.headers['content-type'] || '').includes('x-www-form-urlencoded')) return await query(new URLSearchParams(body.toString()), res);
            log(`UNHANDLED ${req.method} ${req.url.slice(0, 120)} ct=${req.headers['content-type']}`);
            json(res, 400, { message: 'shim: unhandled' });
        } catch (e) { log('ERR', e.stack); json(res, 500, { message: e.message }); }
    });
}

function webhookHandler(req, res) {
    readBody(req, res, async (body) => {
        const u = new URL(req.url, 'http://x');
        const [, uid, ...rest] = u.pathname.split('/');
        const s = Object.values(stacks).find((x) => x.fn.Webhook && x.fn.Webhook === uid);
        if (!s) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{"message":"Not Found"}'); }
        const bin = !/^(text\/|application\/(json|xml|x-www-form-urlencoded))/.test(req.headers['content-type'] || 'text/plain');
        const routeKey = rest.length ? `ANY /${uid}/{proxy+}` : `ANY /${uid}`;
        const event = { version: '2.0', routeKey, rawPath: u.pathname, rawQueryString: u.search.slice(1),
            headers: Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, [].concat(v).join(',')])),
            queryStringParameters: u.search ? Object.fromEntries(u.searchParams) : undefined,
            pathParameters: rest.length ? { proxy: rest.join('/') } : undefined,
            requestContext: { accountId: '000000000000', apiId: 'etlshim', domainName: req.headers.host, http: { method: req.method, path: u.pathname,
                protocol: `HTTP/${req.httpVersion}`, sourceIp: req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress, userAgent: req.headers['user-agent'] || '' },
                requestId: randomUUID(), routeKey, stage: '$default', time: new Date().toUTCString(), timeEpoch: Date.now() },
            body: body.length ? (bin ? body.toString('base64') : body.toString()) : undefined, isBase64Encoded: Boolean(body.length && bin) };
        try {
            const { result, fnError } = await invoke(s.fn.FunctionName, event, 'Webhook');
            if (fnError) { res.writeHead(500, { 'Content-Type': 'application/json' }); return res.end('{"message":"Internal Server Error"}'); }
            let r; try { r = JSON.parse(result.toString()); } catch { r = result.toString(); }
            if (r && typeof r === 'object' && 'statusCode' in r) {
                res.writeHead(r.statusCode, r.headers || {});
                return res.end(r.body ? (r.isBase64Encoded ? Buffer.from(r.body, 'base64') : r.body) : '');
            }
            res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(typeof r === 'string' ? r : JSON.stringify(r));
        } catch (e) { log('webhook fail', e.message); res.writeHead(502); res.end(); }
    });
}

// ---- start-up: learn the ETL subnet, reap leftovers, then serve ----
async function main() {
    const n = await broker('net');
    if (!n.subnets?.length) throw new Error(`ETL network ${n.network} has no IPv4 subnet`);
    etlNets = n.subnets.map(parseSubnet);
    log(`api guard: refusing ${n.subnets.join(', ')}`);
    // a restart forgets warm/in-flight containers — reap anything a previous shim started
    const left = (await broker('list')).containers;
    for (const c of left) await broker('stop', { id: c.id }).catch((e) => log('reap fail', e.message));
    if (left.length) log(`reaped ${left.length} leftover ETL container(s)`);

    // The SQS SDK sends to the QueueUrl host (sqs.<region>.amazonaws.com) and ignores AWS_ENDPOINT_URL_SQS, so the
    // shim also answers that name over TLS — a network alias points it here and CloudTAK trusts the shim CA (W6).
    if (process.env.SHIM_TLS_CERT) {
        https.createServer({ cert: fs.readFileSync(process.env.SHIM_TLS_CERT), key: fs.readFileSync(process.env.SHIM_TLS_KEY) }, apiHandler)
            .listen(443, () => log('etl-shim TLS on :443 (SQS QueueUrl host)'));
    }
    http.createServer(apiHandler).listen(PORT, () => {
        log(`etl-shim on :${PORT} api=${ETL_API} max=${MAX_CONCURRENT} keepwarm=${KEEPWARM_MS / 1000}s warm_budget=${WARM_BUDGET_MB}MiB broker=${BROKER_SOCK}`);
        Object.keys(stacks).forEach(arm);
    });
    http.createServer(webhookHandler).listen(HOOK_PORT, () => log(`etl-shim webhooks on :${HOOK_PORT}`));
}
main().catch((e) => { log(`start-up failed: ${e.message} — refusing to serve`); process.exit(1); });
