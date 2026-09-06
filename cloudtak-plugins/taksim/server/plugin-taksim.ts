// CloudTAK lints copied plugin routes with its OWN house-style rules, which differ across
// versions (@stylistic/brace-style flips between releases and isn't defined on older
// ones). A plugin can't satisfy every CloudTAK version, so this route file opts out of
// CloudTAK's lint — infra-TAK owns its correctness (vue-tsc/eslint before any box pull).
/* eslint-disable */
import { Type } from '@sinclair/typebox';
import Schema from '@openaddresses/batch-schema';
import Err from '@openaddresses/batch-error';
// CloudTAK 13.45+ (hub/api split): api/stateless/routes/ placement, libs from api/common/,
// ConfigStateless signature — same contract as the Dispatcher plugin's server routes.
import Auth from '../../common/auth.js';
import type ConfigStateless from '../config.js';

// SPDX-License-Identifier: AGPL-3.0-or-later
// infra-TAK — TAK Simulator server route (PLAN v10.1.61 companion, W11)
// Copyright (C) 2026 Andreas Johansson (TAKWERX)
//
// The browser plugin (api/web/plugins/taksim) can only reach CloudTAK's own /api routes.
// This file forwards its calls to the TAK Simulator engine on the box, which the CloudTAK
// api container reaches over the private `infratak` Docker network (W10):
//
//   TAKSIM_ENGINE_URL    http://tak-simulator:5090   (set by infra-TAK when the simulator
//   TAKSIM_ENGINE_TOKEN  <bearer token>               is deployed; absent otherwise -> 503)
//
// Every route requires an authenticated CloudTAK user (Auth.is_auth). v1 deliberately
// does not require admin for the director actions — an exercise director is not
// necessarily a CloudTAK admin (PLAN v10.1.61 companion §2, operator decision). The
// engine itself still pins every lane to the channel the console enrolled it on and
// demands the typed confirmation for a real channel, so a non-admin director can only
// send EXERCISE-marked traffic where the console operator already allowed it.
// Admin-only for the write routes is the one-line flip below (CloudTAK system admin).
//
// Installed into api/stateless/routes/ by the infra-TAK plugin installer (server_path);
// auto-loaded by CloudTAK's schema.load('./routes/').

const DIRECTOR_ADMIN_ONLY = false;   // true -> live/run/cmd/save/pause/resume/stop need a CloudTAK admin
const MAX_BODY_BYTES = 256 * 1024;
const ENGINE_TIMEOUT_MS = 95_000;    // /live and /run wait for lanes to connect (<= ~45 s)

type EngineReply = { status: number; body: Record<string, unknown> };

function engineConfig(): { url: string; token: string } | null {
    const url = (process.env.TAKSIM_ENGINE_URL || '').trim();
    const token = (process.env.TAKSIM_ENGINE_TOKEN || '').trim();
    if (!url || !token) return null;
    return { url, token };
}

async function engine(method: 'GET' | 'POST', path: string, body?: unknown): Promise<EngineReply> {
    const cfg = engineConfig();
    if (!cfg) {
        return { status: 503, body: { status: 503, message: 'TAK Simulator is not installed on this box', error: 'TAK Simulator is not installed on this box' } };
    }
    let r: Response;
    try {
        r = await fetch(new URL(path, cfg.url.endsWith('/') ? cfg.url : cfg.url + '/'), {
            method,
            headers: {
                Authorization: `Bearer ${cfg.token}`,
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
            body: body === undefined ? undefined : JSON.stringify(body),
            signal: AbortSignal.timeout(ENGINE_TIMEOUT_MS),
        });
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { status: 502, body: { status: 502, message: `TAK Simulator engine unreachable: ${msg}`, error: msg } };
    }
    const text = await r.text();
    let json: Record<string, unknown>;
    try {
        json = JSON.parse(text) as Record<string, unknown>;
    } catch {
        json = { error: text.slice(0, 300) };
    }
    if (r.ok) return { status: 200, body: json };
    // Never relay the engine's 401 as a 401: CloudTAK's std() treats a 401 as the USER's
    // token being revoked and logs them out. A token mismatch here is a box-side problem.
    const status = r.status === 401 ? 502 : r.status;
    const errors = Array.isArray(json.errors) ? (json.errors as unknown[]).map(String) : [];
    const message = r.status === 401
        ? 'TAK Simulator engine rejected the token — redeploy the simulator in the console'
        : String(json.error || `engine HTTP ${r.status}`) + (errors.length ? `: ${errors[0]}` : '');
    return { status, body: { status, message, error: json.error, errors, details: errors.join('; ') } };
}

function tooLarge(body: unknown): boolean {
    try {
        return JSON.stringify(body ?? {}).length > MAX_BODY_BYTES;
    } catch {
        return true;
    }
}

export default async function router(schema: Schema, config: ConfigStateless) {
    const bodySchema = Type.Record(Type.String(), Type.Any());

    // ── reads ────────────────────────────────────────────────────────────────
    await schema.get('/plugins/taksim/status', {
        name: 'TAK Simulator Status',
        group: 'TAKSim',
        description: 'Engine status: installed?, run state, lanes, default channel',
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);
            if (!engineConfig()) {
                res.json({ installed: false, state: 'idle', run: null, lanes_enrolled: [], default_channel: 'tak_simulation' });
                return;
            }
            const r = await engine('GET', 'status');
            res.status(r.status).json(r.status === 200 ? { installed: true, ...r.body } : r.body);
        } catch (err) {
            Err.respond(err, res);
        }
    });

    await schema.get('/plugins/taksim/state', {
        name: 'TAK Simulator State',
        group: 'TAKSim',
        description: 'Live entities and persistent objects of the current run (poll every 2 s)',
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);
            const r = await engine('GET', 'state');
            res.status(r.status).json(r.body);
        } catch (err) {
            Err.respond(err, res);
        }
    });

    await schema.get('/plugins/taksim/scenarios', {
        name: 'TAK Simulator Scenarios',
        group: 'TAKSim',
        description: 'Preset and uploaded scenarios on the box',
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);
            const r = await engine('GET', 'scenarios');
            res.status(r.status).json(r.body);
        } catch (err) {
            Err.respond(err, res);
        }
    });

    // ── writes ───────────────────────────────────────────────────────────────
    const posts: { path: string; name: string; description: string }[] = [
        { path: 'live', name: 'TAK Simulator Start Live Session', description: 'Start an empty director session at a map center' },
        { path: 'run', name: 'TAK Simulator Run Scenario', description: 'Run a preset or uploaded scenario at a map center' },
        { path: 'cmd', name: 'TAK Simulator Command', description: 'Director command: spawn, goto, orbit, heading, hold, alt, lostlink, rename, team, remove, event, tempo' },
        { path: 'save', name: 'TAK Simulator Save Layout', description: 'Save the live layout as an uploaded scenario' },
        { path: 'pause', name: 'TAK Simulator Pause', description: 'Freeze the simulated clock' },
        { path: 'resume', name: 'TAK Simulator Resume', description: 'Resume the simulated clock' },
        { path: 'stop', name: 'TAK Simulator Stop', description: 'Stop and clear everything (delete events for every emitted UID)' },
    ];
    for (const p of posts) {
        await schema.post(`/plugins/taksim/${p.path}`, {
            name: p.name,
            group: 'TAKSim',
            description: p.description,
            body: bodySchema,
            res: Type.Any(),
        }, async (req, res) => {
            try {
                if (DIRECTOR_ADMIN_ONLY) {
                    await Auth.as_user(config, req, { admin: true });
                } else {
                    await Auth.is_auth(config, req);
                }
                if (tooLarge(req.body)) {
                    res.status(413).json({ status: 413, message: 'request body too large (256 kB max)' });
                    return;
                }
                const r = await engine('POST', p.path, req.body ?? {});
                res.status(r.status).json(r.body);
            } catch (err) {
                Err.respond(err, res);
            }
        });
    }
}
