// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * TAK Simulator client — the one place this plugin talks to the engine.
 *
 * Every call goes through CloudTAK's std() helper (so it carries the user's Bearer token —
 * raw fetch() has none and gets "No Auth Present") to the server route
 * server/plugin-taksim.ts, which forwards to the engine over the private infratak network
 * with the engine token the browser never sees:
 *
 *   /api/plugins/taksim/<status|state|scenarios>            GET
 *   /api/plugins/taksim/<live|run|cmd|save|pause|resume|stop>  POST
 *
 * This file is the merge point with other simulator front ends (Matt H's "CloudTAK
 * Simulate" panel maps its Orbit Here / Hold / Lost Link / Set Course one to one onto the
 * `cmd` ops below).
 */
import { std } from '../../../src/std.ts';

const BASE = '/api/plugins/taksim';

export interface LatLon {
    lat: number;
    lon: number;
}

export interface SensorSpec {
    fov: number;
    range_m: number;
    vfov?: number;
    elevation?: number;
    sweep_deg_s?: number;
}

export interface LaneStats {
    id: string;
    channel: string;
    exercise: boolean;
    connected: boolean;
    sent: number;
    dropped: number;
    msgs_per_s: number;
    last_error: string | null;
}

export interface RunStats {
    scenario: string;
    title: string;
    state: string;
    live: boolean;
    sim_t: number;
    duration_s: number;
    tempo: number;
    loop: boolean;
    entities_alive: number;
    entities_total: number;
    events_fired: number;
    events_total: number;
    persistent_objects: number;
    uids_emitted: number;
    lanes: LaneStats[];
}

export interface EngineStatus {
    installed: boolean;
    version?: string;
    state: string;                 // idle | running | paused | stopping | stopped
    run: RunStats | null;
    lanes_enrolled: string[];
    default_channel: string;       // tak_simulation
    tak_host?: string;
    dry_run?: boolean;
}

export interface SimEntity {
    id: string;
    uid: string;
    callsign: string;
    type: string;
    team: string;
    role: string;
    lane: string;
    lat: number;
    lon: number;
    hae_m: number;
    heading: number;
    speed_mps: number;
    alive: boolean;
    lostlink: boolean;
    emitted: boolean;
    path_kind: string;
    sensor: SensorSpec | null;
    video: boolean;
}

export interface SimObject {
    uid: string;
    id: string | null;
    kind: string | null;
    callsign: string | null;
    type: string;
    lane: string;
}

export interface SimState {
    state: string;
    run: RunStats | null;
    entities: SimEntity[];
    objects: SimObject[];
}

export interface ScenarioSummary {
    name: string;
    file?: string;
    title?: string;
    story?: string;
    duration_s?: number;
    loop?: boolean;
    warn?: string | null;
    default_tempo?: number;
    entities?: number;
    events?: number;
    lanes?: string[];
    valid: boolean;
    errors?: string[];
}

export type Tempo = 1 | 2 | 4 | 10;

export interface SpawnPath {
    kind: 'static' | 'orbit' | 'heading' | 'waypoints' | 'random_walk';
    points?: LatLon[];
    center?: LatLon;
    radius_m?: number;
    speed_mps?: number;
    loop?: boolean;
    clockwise?: boolean;
    heading_deg?: number;
    turn_deg_s?: number;
}

export interface SpawnCmd {
    op: 'spawn';
    id?: string;
    callsign: string;
    type: string;
    at: LatLon;
    hae_m?: number;
    team?: string;
    role?: string;
    lane?: string;
    interval_s?: number;
    stale_s?: number;
    sensor?: SensorSpec;
    video?: { stream: string };
    remarks?: string;
    path?: SpawnPath;
}

export type EventCmd =
    | { op: 'event'; kind: 'chat'; from: string; text: string; room?: string }
    | { op: 'event'; kind: 'casevac'; id: string; at: LatLon; title?: string; urgent?: number; priority?: number; routine?: number; litter?: number; ambulatory?: number; remarks?: string; stale_s?: number }
    | { op: 'event'; kind: 'emergency' | 'emergency_cancel'; from: string; alert?: string }
    | { op: 'event'; kind: 'marker'; id: string; callsign: string; type?: string; at: LatLon; remarks?: string; stale_s?: number }
    | { op: 'event'; kind: 'route'; id: string; callsign?: string; points: LatLon[]; color?: string; stale_s?: number }
    | { op: 'event'; kind: 'polygon'; id: string; callsign?: string; points: LatLon[]; stroke?: string; fill?: string; fill_alpha?: number; remarks?: string; stale_s?: number }
    | { op: 'event'; kind: 'circle'; id: string; callsign?: string; at: LatLon; radius_m: number; stroke?: string; fill?: string; fill_alpha?: number; remarks?: string; stale_s?: number }
    | { op: 'event'; kind: 'remove'; id: string };

export type Cmd =
    | SpawnCmd
    | { op: 'goto'; id: string; to: LatLon; speed_mps: number }
    | { op: 'route'; id: string; points: LatLon[]; speed_mps: number; loop?: boolean }
    | { op: 'orbit'; id: string; center?: LatLon; radius_m: number; speed_mps: number; clockwise?: boolean }
    | { op: 'heading'; id: string; heading_deg: number; speed_mps: number; hae_m?: number }
    | { op: 'hold'; id: string }
    | { op: 'alt'; id: string; hae_m: number }
    | { op: 'lostlink'; id: string; on: boolean }
    | { op: 'rename'; id: string; callsign: string }
    | { op: 'team'; id: string; team: string; role?: string }
    | { op: 'remove'; id: string }
    | { op: 'tempo'; tempo: Tempo }
    | EventCmd;

export interface LiveParams {
    center: LatLon;
    tempo?: Tempo;
    lanes?: Record<string, { channel: string; exercise?: boolean }>;
    exercise?: boolean;
    confirm_exercise?: string;
}

export interface RunParams {
    scenario: string;
    center: LatLon;
    tempo?: Tempo;
    loop?: boolean;
    lanes?: Record<string, { channel: string; exercise?: boolean }>;
    exercise?: boolean;
    confirm_exercise?: string;
    params?: { count?: number; interval_s?: number; max_msgs_per_sec?: number };
}

export interface StartResult {
    started: boolean;
    live: boolean;
    scenario: string;
    entities: number;
    events: number;
    lanes: Record<string, string>;
    exercise: Record<string, boolean>;
}

export interface SaveResult {
    saved: string;
    file: string;
    summary: ScenarioSummary;
}

export class TakSimError extends Error {
    errors: string[];
    status: number;

    constructor(message: string, errors: string[] = [], status = 0) {
        super(message);
        this.name = 'TakSimError';
        this.errors = errors;
        this.status = status;
    }

    // The engine's isolation gate: a real channel needs its name typed back.
    get needsConfirmation(): boolean {
        return this.errors.some(e => e.includes('confirm_exercise'));
    }
}

async function call<T>(method: 'GET' | 'POST', path: string, body?: unknown, timeout = 20000): Promise<T> {
    try {
        return await std(`${BASE}${path}`, { method, body, timeout }) as T;
    } catch (err) {
        const e = err as Error & { body?: { errors?: string[]; status?: number; message?: string } };
        const errors = Array.isArray(e.body?.errors) ? e.body.errors.map(String) : [];
        throw new TakSimError(e.message || 'TAK Simulator request failed', errors, Number(e.body?.status) || 0);
    }
}

export const getStatus = (): Promise<EngineStatus> => call<EngineStatus>('GET', '/status');
export const getState = (): Promise<SimState> => call<SimState>('GET', '/state');
export async function getScenarios(): Promise<ScenarioSummary[]> {
    const r = await call<{ scenarios?: ScenarioSummary[] }>('GET', '/scenarios');
    return r.scenarios ?? [];
}

// Lane connect + channel activation can take up to ~20 s: give these a longer timeout.
export const startLive = (p: LiveParams): Promise<StartResult> => call<StartResult>('POST', '/live', p, 60000);
export const startRun = (p: RunParams): Promise<StartResult> => call<StartResult>('POST', '/run', p, 60000);
export const sendCmd = <T = unknown>(c: Cmd): Promise<T> => call<T>('POST', '/cmd', c, 15000);
export const saveLayout = (title: string, name?: string): Promise<SaveResult> =>
    call<SaveResult>('POST', '/save', name ? { title, name } : { title });
export const pause = (): Promise<{ ok: boolean; state: string }> => call('POST', '/pause', {});
export const resume = (): Promise<{ ok: boolean; state: string }> => call('POST', '/resume', {});
// Stop = clear everything: the engine sends a t-x-d-d for every UID it ever emitted.
export const stop = (): Promise<{ ok: boolean; state: string }> => call('POST', '/stop', {}, 60000);

// Channels the logged-in CloudTAK user is a member of, with their active flag (TAK
// returns IN/OUT rows per channel — deduped). Used for the "you are not in the
// simulation channel" warning.
export async function getUserChannels(): Promise<{ name: string; active: boolean }[]> {
    const resp = await std('/api/marti/group?useCache=true', { method: 'GET' }) as { data?: { name: string; active?: boolean }[] } | null;
    const seen = new Map<string, boolean>();
    for (const g of resp?.data ?? []) {
        seen.set(g.name, (seen.get(g.name) ?? false) || g.active !== false);
    }
    return [...seen.entries()].map(([name, active]) => ({ name, active })).sort((a, b) => a.name.localeCompare(b.name));
}
