// SPDX-License-Identifier: AGPL-3.0-or-later
// infra-TAK — TAK Infrastructure Platform
// Copyright (C) 2026 Andreas Johansson (TAKWERX)
//
// etl-shim pure logic: template compile, schedule parsing, keep-warm budget. No I/O here,
// so `node --test` covers it without Docker, a broker or CloudTAK.

// Same shapes the broker enforces (broker/takwerx_broker.py ETL_*_RE). Checked here too so
// CloudTAK gets a CloudFormation ValidationError at deploy time instead of a failed run.
export const TASK_RE = /^etl-[a-z0-9-]{1,64}-v\d{1,4}\.\d{1,4}\.\d{1,4}$/;
export const FN_RE = /^[A-Za-z0-9_-]{1,128}$/;
export const REPO = 'etl-local';
export const MEM_MIN_MB = 128;
export const MEM_MAX_MB = 3008;

export class ValidationError extends Error {}

// ---- CloudFormation template resolution (the subset CloudTAK's ETL template uses) ----
export function resolve(v, params, etlApi) {
    if (v === null || typeof v !== 'object') return v;
    if (Array.isArray(v)) return v.map((x) => resolve(x, params, etlApi));
    if ('Ref' in v) {
        return params[v.Ref] ?? ({ 'AWS::Region': 'local', 'AWS::AccountId': '000000000000',
            'AWS::StackName': params.__stack, 'AWS::Partition': 'aws' })[v.Ref] ?? `ref:${v.Ref}`;
    }
    if ('Fn::ImportValue' in v) {
        const k = resolve(v['Fn::ImportValue'], params, etlApi);
        return /-hosted$/.test(k) ? etlApi : `import:${k}`;
    }
    if ('Fn::Join' in v) { const [sep, parts] = v['Fn::Join']; return resolve(parts, params, etlApi).join(sep); }
    if ('Fn::GetAtt' in v) return `getatt:${[].concat(v['Fn::GetAtt']).join('.')}`;
    const o = {};
    for (const [k, x] of Object.entries(v)) o[k] = resolve(x, params, etlApi);
    return o;
}

export const HANDLED = ['AWS::Lambda::Function', 'AWS::Events::Rule', 'AWS::Lambda::Permission',
    'AWS::Logs::LogGroup', 'AWS::CloudWatch::Alarm', 'AWS::SQS::Queue', 'AWS::Lambda::EventSourceMapping',
    'AWS::ApiGatewayV2::Route', 'AWS::ApiGatewayV2::Integration'];

export function clampMem(mb) {
    const n = Math.round(Number(mb) || MEM_MIN_MB);
    return Math.min(MEM_MAX_MB, Math.max(MEM_MIN_MB, n));
}

// Turn the stack CloudTAK sends (CreateStack/UpdateStack) into the one function we run.
export function compile(name, templateBody, paramList, etlApi) {
    let t;
    try { t = JSON.parse(templateBody); } catch { throw new ValidationError('TemplateBody is not JSON'); }
    const params = { __stack: name };
    for (const [k, p] of Object.entries(t.Parameters || {})) params[k] = p.Default;
    for (const p of paramList || []) if (p.ParameterKey) params[p.ParameterKey] = p.ParameterValue ?? params[p.ParameterKey];
    const R = t.Resources || {};
    const fnRes = Object.values(R).find((r) => r.Type === 'AWS::Lambda::Function');
    if (!fnRes) throw new ValidationError('template has no AWS::Lambda::Function');
    if (!TASK_RE.test(String(params.Task || ''))) {
        throw new ValidationError(`Task ${JSON.stringify(params.Task)} is not an ETL task (expected etl-<name>-v<x.y.z>)`);
    }
    const fp = resolve(fnRes.Properties, params, etlApi);
    if (!FN_RE.test(String(fp.FunctionName || ''))) throw new ValidationError(`bad FunctionName ${JSON.stringify(fp.FunctionName)}`);
    // One function per stack, named after it (CloudTAK's template joins the StackName): a stack
    // can never claim another layer's function, logs or queue.
    if (String(fp.FunctionName) !== String(name)) throw new ValidationError(`FunctionName must equal the StackName ${name}`);
    if (R.WebHookResourceIntegration && !/^[A-Za-z0-9-]{1,64}$/.test(String(params.UniqueID || ''))) {
        throw new ValidationError('bad webhook UniqueID');
    }
    const rule = Object.values(R).find((r) => r.Type === 'AWS::Events::Rule');
    const rp = rule ? resolve(rule.Properties, params, etlApi) : null;
    const env = {};
    for (const [k, v] of Object.entries(fp.Environment?.Variables || {})) env[k] = v === null || v === undefined ? '' : String(v);
    return {
        FunctionName: fp.FunctionName,
        Timeout: Math.min(900, Math.max(1, Number(fp.Timeout) || 60)),
        MemorySize: clampMem(fp.MemorySize),
        Env: env,
        Image: `${REPO}:${params.Task}`,
        Schedule: rp ? { expr: rp.ScheduleExpression, state: rp.State } : null,
        Outgoing: Boolean(R.OutgoingQueue),
        Webhook: R.WebHookResourceIntegration ? String(params.UniqueID) : null,
        Unsupported: Object.entries(R).filter(([, r]) => !HANDLED.includes(r.Type)).map(([k, r]) => `${k}:${r.Type}`),
    };
}

// A function record loaded from /data (written by an older shim, or edited by hand) gets the
// same normalization compile() applies, or is dropped: the broker refuses anything else anyway,
// and a refused run every minute is noise, not safety. Returns the fixed fn, or null.
export function normalizeFn(fn) {
    if (!fn || typeof fn !== 'object') return null;
    const image = String(fn.Image || '');
    if (!image.startsWith(`${REPO}:`) || !TASK_RE.test(image.slice(REPO.length + 1))) return null;
    if (!FN_RE.test(String(fn.FunctionName || ''))) return null;
    const env = {};
    for (const [k, v] of Object.entries(fn.Env || {})) env[k] = v === null || v === undefined ? '' : String(v);
    return { ...fn, Env: env, MemorySize: clampMem(fn.MemorySize), Timeout: Math.min(900, Math.max(1, Number(fn.Timeout) || 60)) };
}

// ---- schedules: EventBridge semantics, UTC ----
// EventBridge's floor is one minute; anything below is clamped up (a 1 ms loop is a DoS).
export const RATE_MIN_MS = 60_000;
export function rateMs(expr) {
    const m = /^rate\((\d+)\s+(second|minute|hour|day)s?\)$/.exec(String(expr).trim());
    if (!m || Number(m[1]) < 1) return null;
    const ms = Number(m[1]) * { second: 1e3, minute: 6e4, hour: 36e5, day: 864e5 }[m[2]];
    return Number.isSafeInteger(ms) ? Math.max(RATE_MIN_MS, ms) : null;
}

const MON = { JAN: 1, FEB: 2, MAR: 3, APR: 4, MAY: 5, JUN: 6, JUL: 7, AUG: 8, SEP: 9, OCT: 10, NOV: 11, DEC: 12 };
const DOW = { SUN: 1, MON: 2, TUE: 3, WED: 4, THU: 5, FRI: 6, SAT: 7 };

// One cron field -> Set of allowed values, or null for '*' / '?'.
export function field(spec, lo, hi, names = {}) {
    if (spec === '*' || spec === '?') return null;
    const set = new Set();
    for (const part of spec.split(',')) {
        const [range, stepS] = part.split('/');
        const step = stepS === undefined ? 1 : Number(stepS);
        if (!Number.isInteger(step) || step < 1) throw new Error(`bad cron step ${spec}`);
        let a, b;
        if (range === '*') { a = lo; b = hi; } else {
            [a, b] = range.split('-').map((x) => names[x.toUpperCase()] ?? Number(x));
            if (b === undefined) b = stepS !== undefined ? hi : a;
        }
        if (!Number.isInteger(a) || !Number.isInteger(b) || a < lo || b > hi || a > b) throw new Error(`bad cron field ${spec}`);
        for (let v = a; v <= b; v += step) set.add(v);
    }
    return set;
}

export function parseCron(expr) {
    const m = /^cron\((.+)\)$/.exec(String(expr).trim());
    if (!m) return null;
    const f = m[1].trim().split(/\s+/);
    if (f.length !== 6) throw new Error(`cron needs 6 fields: ${expr}`);
    const lastDom = f[2] === 'L';
    return {
        min: field(f[0], 0, 59), hour: field(f[1], 0, 23),
        dom: lastDom ? null : field(f[2], 1, 31), lastDom,
        mon: field(f[3], 1, 12, MON), dow: field(f[4].replace(/#\d+$/, ''), 1, 7, DOW),
        year: field(f[5], 1970, 2199),
    };
}

export function cronMatch(c, d) {
    const ok = (s, v) => !s || s.has(v);
    const last = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
    return ok(c.min, d.getUTCMinutes()) && ok(c.hour, d.getUTCHours()) && ok(c.mon, d.getUTCMonth() + 1)
        && ok(c.year, d.getUTCFullYear()) && ok(c.dom, d.getUTCDate())
        && (!c.lastDom || d.getUTCDate() === last) && ok(c.dow, d.getUTCDay() + 1);
}

// ---- keep-warm (PLAN D3): fleet constants + one autotuned budget, no operator knob ----
export const KEEPWARM_MS = 300_000;
export const MAX_CONCURRENT = 4;

// warm_budget = min(10 % of MemTotal, 2 GiB), in MiB. meminfoText is /proc/meminfo.
export function warmBudgetMb(meminfoText) {
    const m = /^MemTotal:\s+(\d+)\s+kB/m.exec(meminfoText || '');
    const totalMb = m ? Number(m[1]) / 1024 : 0;
    return Math.floor(Math.min(totalMb * 0.10, 2048));
}

// A layer stays warm between runs only if it runs at least every KEEPWARM_MS.
export function wantsWarm(fn) {
    if (!fn?.Schedule || fn.Schedule.state !== 'ENABLED') return false;
    const ms = rateMs(fn.Schedule.expr);
    return ms !== null && ms <= KEEPWARM_MS;
}

// Which warm entries to evict so `needMb` more fits in `budgetMb`. warm: [{fn, mb, lastUsed}].
// Least recently used first. Returns { evict: [fn...], fits: bool }.
export function planEviction(warm, needMb, budgetMb) {
    let used = warm.reduce((n, w) => n + w.mb, 0);
    const evict = [];
    for (const w of [...warm].sort((a, b) => a.lastUsed - b.lastUsed)) {
        if (used + needMb <= budgetMb) break;
        evict.push(w.fn); used -= w.mb;
    }
    return { evict, fits: used + needMb <= budgetMb };
}

// ---- docker log lines "2026-10-31T10:00:00.123456789Z message" -> {t, m} ----
export function parseLogLines(text) {
    return String(text || '').split('\n').filter(Boolean).map((l) => {
        const i = l.indexOf(' ');
        const t = Date.parse(l.slice(0, i));
        return Number.isNaN(t) ? { t: Date.now(), m: l } : { t, m: l.slice(i + 1) };
    });
}

// ---- IPv4 subnet guard: the ETL network must never reach the AWS API ----
export const ip4 = (a) => a.replace(/^::ffff:/, '').split('.').reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;

export function parseSubnet(cidr) {
    const [b, m] = String(cidr).split('/');
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(b) || !(Number(m) >= 0 && Number(m) <= 32)) throw new Error(`bad subnet ${cidr}`);
    return [ip4(b), Number(m)];
}

export function inSubnet(addr, net) {
    if (!net || !/^(::ffff:)?\d+\.\d+\.\d+\.\d+$/.test(addr || '')) return false;
    const mask = net[1] ? (~0 << (32 - net[1])) >>> 0 : 0;
    return ((ip4(addr) & mask) >>> 0) === ((net[0] & mask) >>> 0);
}

// ---- W7: webhooks ----------------------------------------------------------------------------
// The public route is https://<CloudTAK map host>/etl-hooks/<box secret>/<layer UniqueID>[/...].
// CloudTAK shows WEBHOOKS_URL + '/' + layer uuid, and infra-TAK sets WEBHOOKS_URL to the part up
// to the secret, so the URL CloudTAK hands out is the working one. Without the secret, nothing
// reaches an ETL: several catalog ETLs accept unauthenticated webhooks (module-scan 2026-11-08).
export const HOOK_PREFIX = '/etl-hooks';
export const HOOK_SECRET_RE = /^[A-Za-z0-9_-]{43}$/;      // secrets.token_urlsafe(32): 256 bits
export const HOOK_MAX_BODY = 1024 * 1024;

// Constant-time string compare (equal length checked first; the length is public: 43).
export function secretEqual(a, b, timingSafeEqual) {
    const x = Buffer.from(String(a)), y = Buffer.from(String(b));
    return x.length === y.length && timingSafeEqual(x, y);
}

// pathname -> { uid, rest, rawPath } or { refuse: reason }. rawPath is the path the ETL sees:
// '/<uid>/...' exactly as API Gateway would have passed it, without our prefix or the secret.
// Caddy moves the secret out of the URI (its error log writes URIs) into this cookie and puts
// HOOK_MASK in the path; Caddy redacts Cookie in logs. A direct call may still carry it in the path.
export const HOOK_COOKIE = 'infratak_hook';
export const HOOK_MASK = '_';
export function hookCookie(cookieHeader) {
    for (const part of String(cookieHeader || '').split(';')) {
        const i = part.indexOf('=');
        if (i > 0 && part.slice(0, i).trim() === HOOK_COOKIE) return part.slice(i + 1).trim();
    }
    return '';
}
export function hookRoute(pathname, secret, timingSafeEqual, cookieSecret = '') {
    if (!HOOK_SECRET_RE.test(String(secret || ''))) return { refuse: 'no secret configured' };
    const parts = String(pathname).split('/');
    // ['', 'etl-hooks', '<secret>' | '_', '<uid>', ...rest]
    if (parts[0] !== '' || `/${parts[1]}` !== HOOK_PREFIX) return { refuse: 'not a hook path' };
    const given = parts[2] === HOOK_MASK ? String(cookieSecret || '') : (parts[2] || '');
    if (!secretEqual(given, secret, timingSafeEqual)) return { refuse: 'bad secret' };
    const uid = parts[3] || '';
    if (!/^[A-Za-z0-9-]{1,64}$/.test(uid)) return { refuse: 'bad layer id' };
    const rest = parts.slice(4);
    if (rest.some((p) => p === '..' || p === '.')) return { refuse: 'bad path' };
    return { uid, rest, rawPath: '/' + [uid, ...rest].join('/') };
}

// ---- W6: the outgoing SQS queue survives a shim restart (append-only journal) ----
// Real SQS keeps a message it acknowledged. The shim answers SendMessage only after the message
// is in the journal (group commit + fsync), and a message leaves the queue only after its
// delivery finished, so a restart redelivers it: at-least-once, as SQS is.
// Records, one JSON object per line: {o:'a', f, m} add to queue; {o:'r', f, id, t} retry (moves
// to the end with t tries); {o:'k', f, id} delivered; {o:'x', f, id} dead-lettered;
// {o:'d', f, m} add straight to dead letters (compaction only); {o:'p', f} purge a function.
export const SQS_MAX_PER_LAYER = 10000;
export const SQS_MAX_DEAD = 1000;
export const SQS_MAX_BYTES = 256 * 1024 * 1024;      // all queued bodies together, on disk and in memory

export function sqsReplay(text, live) {
    const Q = Object.create(null);
    const get = (f) => (Q[f] ||= { q: [], dead: [] });
    for (const line of String(text || '').split('\n')) {
        let r;
        try { r = JSON.parse(line); } catch { continue; }       // a torn last line from a crash
        if (!r || typeof r !== 'object' || typeof r.f !== 'string') continue;
        const at = () => get(r.f).q.findIndex((m) => m.Id === r.id);
        if (r.o === 'a' && r.m && typeof r.m.Id === 'string') get(r.f).q.push(r.m);
        else if (r.o === 'd' && r.m && typeof r.m.Id === 'string') get(r.f).dead.push(r.m);
        else if (r.o === 'p') delete Q[r.f];
        else if (r.o === 'r' || r.o === 'k' || r.o === 'x') {
            const i = at();
            if (i < 0) continue;
            const [m] = get(r.f).q.splice(i, 1);
            if (r.o === 'r') get(r.f).q.push({ ...m, tries: Number(r.t) || 0 });
            if (r.o === 'x') get(r.f).dead.push(m);
        }
    }
    for (const f of Object.keys(Q)) {
        if (live && !live.has(f)) { delete Q[f]; continue; }
        Q[f].dead = Q[f].dead.slice(-SQS_MAX_DEAD);
        if (!Q[f].q.length && !Q[f].dead.length) delete Q[f];
    }
    return Q;
}

export function sqsSnapshot(queues) {
    const out = [];
    for (const [f, Q] of Object.entries(queues)) {
        for (const m of Q.dead || []) out.push(JSON.stringify({ o: 'd', f, m }));
        for (const m of Q.q || []) out.push(JSON.stringify({ o: 'a', f, m }));
    }
    return out.length ? out.join('\n') + '\n' : '';
}

export const sqsBytes = (m) => Buffer.byteLength(m?.MessageBody || '') + 512;


// ---- webhook responses are served on the CloudTAK map origin: never let an ETL decide that ----
// A browser that opens a webhook URL must not run ETL-chosen script or take ETL-chosen cookies
// on the CloudTAK origin. Status must be an integer 200-599; only JSON or plain text; nothing
// else from the ETL's headers survives.
export const HOOK_SAFE_TYPE = /^(application\/json|text\/plain)(\s*;[\w=\-\s."]*)?$/i;
export const HOOK_FIXED_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "sandbox; default-src 'none'",
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
};
export function hookResponse(r) {
    const fail = { status: 502, headers: { ...HOOK_FIXED_HEADERS, 'Content-Type': 'application/json' }, body: '{"message":"Bad Gateway"}' };
    if (r === null || r === undefined) return { status: 200, headers: { ...HOOK_FIXED_HEADERS, 'Content-Type': 'application/json' }, body: 'null' };
    if (typeof r !== 'object' || !('statusCode' in r)) {
        const body = typeof r === 'string' ? r : JSON.stringify(r);
        return { status: 200, headers: { ...HOOK_FIXED_HEADERS, 'Content-Type': 'application/json' }, body };
    }
    const status = Number(r.statusCode);
    if (!Number.isInteger(status) || status < 200 || status > 599) return fail;
    let body = r.body ?? '';
    if (typeof body !== 'string') return fail;
    if (r.isBase64Encoded) body = Buffer.from(body, 'base64');
    let ct = '';
    const h = r.headers && typeof r.headers === 'object' ? r.headers : {};
    for (const [k, v] of Object.entries(h)) if (k.toLowerCase() === 'content-type' && typeof v === 'string') ct = v.trim();
    if (!HOOK_SAFE_TYPE.test(ct)) ct = 'text/plain; charset=utf-8';
    return { status, headers: { ...HOOK_FIXED_HEADERS, 'Content-Type': ct }, body };
}

// Request headers an ETL sees: never the browser's cookies (a visit from a signed-in CloudTAK user
// would hand them over). Authorization stays: webhook ETLs authenticate callers with it.
export function hookEventHeaders(headers) {
    const out = Object.create(null);
    for (const [k, v] of Object.entries(headers || {})) {
        if (k.toLowerCase() === 'cookie') continue;
        out[k] = [].concat(v).join(',');
    }
    return out;
}

// ---- the shim's AWS API authenticates its callers (SigV4, as AWS does) ----
// CloudTAK's api/events sign every AWS SDK call with the per-box secret infra-TAK puts in their
// env; the shim recomputes the signature exactly as @smithy/signature-v4 builds it. Without
// this, any container on CloudTAK's default network could create, invoke or delete ETL stacks.
import { createHash as _hash, createHmac as _hmac } from 'node:crypto';
export const SIGV4_SKEW_MS = 15 * 60 * 1000;
const _sha = (b) => _hash('sha256').update(b).digest('hex');
export const escapeUri = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

export function sigv4CanonicalPath(path) {
    const segs = [];
    for (const p of path.split('/')) {
        if (!p || p === '.') continue;
        if (p === '..') segs.pop(); else segs.push(p);
    }
    const norm = `${path.startsWith('/') ? '/' : ''}${segs.join('/')}${segs.length && path.endsWith('/') ? '/' : ''}`;
    return escapeUri(norm).replace(/%2F/g, '/');
}

export function sigv4CanonicalQuery(search) {
    const q = new Map();
    for (const part of String(search || '').replace(/^\?/, '').split('&')) {
        if (!part) continue;
        const i = part.indexOf('=');
        const dec = (x) => decodeURIComponent(x.replace(/\+/g, '%20'));
        const k = dec(i < 0 ? part : part.slice(0, i)), v = i < 0 ? '' : dec(part.slice(i + 1));
        if (k.toLowerCase() === 'x-amz-signature') continue;
        (q.get(k) || q.set(k, []).get(k)).push(v);
    }
    return [...q.keys()].sort().flatMap((k) => q.get(k).sort().map((v) => `${escapeUri(k)}=${escapeUri(v)}`)).join('&');
}

// Returns null when the request is signed with `secret`, else the reason.
export function sigv4Verify({ method, url, headers, body, secret, now = Date.now(), timingSafeEqual }) {
    if (!secret) return 'no secret configured';
    const auth = String(headers.authorization || '');
    const m = /^AWS4-HMAC-SHA256 Credential=([^/,\s]+)\/(\d{8})\/([a-z0-9-]{1,32})\/([a-z0-9-]{1,32})\/aws4_request, ?SignedHeaders=([a-z0-9;.-]+), ?Signature=([0-9a-f]{64})$/.exec(auth);
    if (!m) return 'not signed';
    const [, , date, region, service, signedHeaders, sig] = m;
    const amzDate = String(headers['x-amz-date'] || '');
    const dm = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(amzDate);
    if (!dm || amzDate.slice(0, 8) !== date) return 'bad x-amz-date';
    const t = Date.UTC(+dm[1], +dm[2] - 1, +dm[3], +dm[4], +dm[5], +dm[6]);
    if (Math.abs(now - t) > SIGV4_SKEW_MS) return 'request time too skewed';
    const names = signedHeaders.split(';');
    if (!names.includes('host') || !names.includes('x-amz-date')) return 'host and x-amz-date must be signed';
    const bodyHash = _sha(body || Buffer.alloc(0));
    const claimed = headers['x-amz-content-sha256'];
    if (claimed !== undefined && claimed !== bodyHash) return 'body hash mismatch';
    const hdrs = names.map((n) => {
        const v = headers[n];
        if (v === undefined) return null;
        return `${n}:${[].concat(v).join(',').trim().replace(/\s+/g, ' ')}\n`;
    });
    if (hdrs.includes(null)) return 'a signed header is missing';
    const qi = String(url).indexOf('?');
    const path = qi < 0 ? String(url) : String(url).slice(0, qi);
    const canonical = [method, sigv4CanonicalPath(path), sigv4CanonicalQuery(qi < 0 ? '' : String(url).slice(qi + 1)),
        hdrs.join(''), signedHeaders, bodyHash].join('\n');
    const scope = `${date}/${region}/${service}/aws4_request`;
    const sts = ['AWS4-HMAC-SHA256', amzDate, scope, _sha(canonical)].join('\n');
    let k = _hmac('sha256', `AWS4${secret}`).update(date).digest();
    for (const p of [region, service, 'aws4_request']) k = _hmac('sha256', k).update(p).digest();
    const want = _hmac('sha256', k).update(sts).digest();
    const got = Buffer.from(sig, 'hex');
    return got.length === want.length && timingSafeEqual(got, want) ? null : 'bad signature';
}
