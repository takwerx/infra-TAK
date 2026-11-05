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
export function rateMs(expr) {
    const m = /^rate\((\d+)\s+(second|minute|hour|day)s?\)$/.exec(String(expr).trim());
    if (!m || Number(m[1]) < 1) return null;
    return Number(m[1]) * { second: 1e3, minute: 6e4, hour: 36e5, day: 864e5 }[m[2]];
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
