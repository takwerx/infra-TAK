// SPDX-License-Identifier: AGPL-3.0-or-later
// The unit type picker (W11): category -> CoT type + defaults the director can override.
// Speeds and altitudes are entered the way an operator thinks (knots, feet) and converted
// to what the engine speaks (m/s, meters HAE).

import type { DetectKind } from './taksim-client.ts';

export type UnitGroup = 'Ground' | 'Air' | 'Sea' | 'Sensors' | 'Hidden targets';

export interface SensorDefaults {
    fov: number;
    range_m: number;
    sweep_deg_s: number;
}

// Detection defaults for a sensor kind (v10.1.62): what it sees and how well.
export interface DetectDefaults {
    kinds: DetectKind[];
    error_m: number;
}

export const DETECT_KINDS: DetectKind[] = ['air', 'sea', 'ground'];

export interface UnitKind {
    key: string;
    label: string;
    group: UnitGroup;
    type: string;           // CoT type on the wire
    callsign: string;       // default callsign
    altFt: number;
    speedKt: number;
    interval_s: number;
    stale_s: number;
    team?: string;
    sensor?: SensorDefaults;
    detect?: DetectDefaults;   // sensors: detection defaults (off unless the director switches it on)
    video?: boolean;
    silent?: boolean;          // hidden target: never reports itself
    detected_type?: string;    // what a sensor reports a hidden target as
    eud?: boolean;             // team marker (a person with a TAK device); default by type in the engine
}

export const UNIT_KINDS: UnitKind[] = [
    { key: 'ground', label: 'Ground unit', group: 'Ground', type: 'a-f-G-U-C', callsign: 'ALPHA 1', altFt: 0, speedKt: 3, interval_s: 5, stale_s: 60 },
    { key: 'vehicle', label: 'Vehicle', group: 'Ground', type: 'a-f-G-E-V-C', callsign: 'VEHICLE 1', altFt: 0, speedKt: 25, interval_s: 3, stale_s: 60 },
    { key: 'hostile', label: 'Hostile ground', group: 'Ground', type: 'a-h-G', callsign: 'HOSTILE 1', altFt: 0, speedKt: 3, interval_s: 5, stale_s: 60, team: 'Red' },
    { key: 'neutral', label: 'Neutral ground', group: 'Ground', type: 'a-n-G', callsign: 'NEUTRAL 1', altFt: 0, speedKt: 3, interval_s: 5, stale_s: 60, team: 'White' },
    { key: 'helo', label: 'Helicopter', group: 'Air', type: 'a-f-A-M-H', callsign: 'HELO 1', altFt: 1500, speedKt: 110, interval_s: 2, stale_s: 60 },
    { key: 'fixed', label: 'Fixed wing', group: 'Air', type: 'a-f-A-M-F', callsign: 'JET 1', altFt: 8000, speedKt: 250, interval_s: 2, stale_s: 60 },
    { key: 'uas', label: 'UAS', group: 'Air', type: 'a-f-A-M-H-Q', callsign: 'UAS 1', altFt: 400, speedKt: 30, interval_s: 2, stale_s: 60, sensor: { fov: 45, range_m: 1500, sweep_deg_s: 0 }, detect: { kinds: ['ground', 'sea'], error_m: 10 }, video: true },
    { key: 'adsb', label: 'ADS-B aircraft', group: 'Air', type: 'a-n-A-C-F', callsign: 'N123AB', altFt: 5000, speedKt: 180, interval_s: 2, stale_s: 60, team: 'White' },
    { key: 'vessel', label: 'Vessel', group: 'Sea', type: 'a-f-S-X-M', callsign: 'BOAT 1', altFt: 0, speedKt: 12, interval_s: 5, stale_s: 90 },
    { key: 'ais', label: 'AIS vessel', group: 'Sea', type: 'a-n-S-X-M', callsign: 'MV NORTHERN STAR', altFt: 0, speedKt: 10, interval_s: 10, stale_s: 120, team: 'White' },
    { key: 'radar', label: 'Radar site', group: 'Sensors', type: 'a-f-G-E-S', callsign: 'RADAR 1', altFt: 0, speedKt: 0, interval_s: 2, stale_s: 60, sensor: { fov: 30, range_m: 15000, sweep_deg_s: 30 }, detect: { kinds: ['sea', 'air'], error_m: 50 } },
    { key: 'camera', label: 'Fixed camera', group: 'Sensors', type: 'a-f-G-E-S', callsign: 'CAM 1', altFt: 0, speedKt: 0, interval_s: 5, stale_s: 60, sensor: { fov: 60, range_m: 800, sweep_deg_s: 0 }, detect: { kinds: ['ground'], error_m: 5 }, video: true },
    // Hidden targets (v10.1.62): never on the wire themselves; a sensor that sees one reports
    // it as the *unknown* symbol of its domain — the "not on AIS" contact of the drill.
    { key: 'dark-vessel', label: 'Hidden vessel', group: 'Hidden targets', type: 'a-h-S-X-M', callsign: 'DARK VESSEL 1', altFt: 0, speedKt: 12, interval_s: 5, stale_s: 90, silent: true, detected_type: 'a-u-S' },
    { key: 'dark-air', label: 'Hidden aircraft', group: 'Hidden targets', type: 'a-h-A-M-F', callsign: 'BOGEY 1', altFt: 3000, speedKt: 250, interval_s: 2, stale_s: 60, silent: true, detected_type: 'a-u-A' },
    { key: 'dark-ground', label: 'Hidden ground', group: 'Hidden targets', type: 'a-h-G-U-C', callsign: 'INTRUDER 1', altFt: 0, speedKt: 3, interval_s: 5, stale_s: 60, silent: true, detected_type: 'a-u-G' },
];

export const UNIT_GROUPS: UnitGroup[] = ['Ground', 'Air', 'Sea', 'Sensors', 'Hidden targets'];

// The engine's own default (scenario.default_eud): only friendly ground personnel are EUDs.
export const defaultEud = (type: string): boolean => type.startsWith('a-f-G-U');

export function unitKind(key: string): UnitKind {
    return UNIT_KINDS.find(k => k.key === key) ?? UNIT_KINDS[0];
}

// Same lists the engine validates against (simulator/engine/scenario.py TEAMS / ROLES).
export const TEAMS = ['White', 'Yellow', 'Orange', 'Magenta', 'Red', 'Maroon', 'Purple', 'Dark Blue',
    'Blue', 'Cyan', 'Teal', 'Green', 'Dark Green', 'Brown'];
export const ROLES = ['Team Member', 'Team Lead', 'HQ', 'Sniper', 'Medic', 'Forward Observer', 'RTO', 'K9'];
export const EMERGENCIES = ['911 Alert', 'Ring The Bell', 'In Contact', 'Geo-fence Breached'];
export const TEMPOS = [1, 2, 4, 10] as const;

const KT_TO_MPS = 0.514444;
const FT_TO_M = 0.3048;

export const ktToMps = (kt: number): number => Math.round(kt * KT_TO_MPS * 100) / 100;
export const mpsToKt = (mps: number): number => Math.round(mps / KT_TO_MPS);
export const ftToM = (ft: number): number => Math.round(ft * FT_TO_M * 10) / 10;
export const mToFt = (m: number): number => Math.round(m / FT_TO_M);

// A short human label for a CoT type in the unit list.
export function typeLabel(type: string): string {
    const k = UNIT_KINDS.find(u => u.type === type);
    if (k) return k.label;
    if (type.startsWith('a-') && type.includes('-A')) return 'Air';
    if (type.startsWith('a-') && type.includes('-S')) return 'Sea';
    return type;
}
