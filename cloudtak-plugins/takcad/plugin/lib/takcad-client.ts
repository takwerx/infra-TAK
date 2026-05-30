/**
 * TAK-CAD REST client.
 *
 * All endpoints are routed through CloudTAK's Marti proxy:
 *   /api/marti/<path>  →  https://tak-server:8443/Marti/api/<path>
 *
 * GET  /api/marti/plugins/takcad/submit?fn=<method>[&uid=<uid>]
 * PUT  /api/marti/plugins/takcad/submit/result?fn=<method>   (JSON body)
 * DEL  /api/marti/plugins/takcad/submit?fn=<method>&uid=<uid>
 */

import type {
    IncidentRef, IncidentMetadata, IncidentTypeRef,
    VehicleRef, VehicleType,
    PersonRef, Role,
    ResponseMessage,
} from './takcad-types.ts';

const BASE     = '/api/marti/plugins/takcad/submit';
const BASE_PUT = '/api/marti/plugins/takcad/submit/result';

export class TakCadError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'TakCadError';
    }
}

async function cadGet<T>(fn: string, params: Record<string, string> = {}): Promise<T> {
    const qs = new URLSearchParams({ fn, ...params });
    const resp = await fetch(`${BASE}?${qs}`);
    if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new TakCadError(`${fn} failed (${resp.status}): ${text}`);
    }
    return resp.json() as Promise<T>;
}

async function cadPut<T>(fn: string, body: unknown): Promise<T> {
    const resp = await fetch(`${BASE_PUT}?fn=${encodeURIComponent(fn)}`, {
        method:  'PUT',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
    });
    if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new TakCadError(`${fn} failed (${resp.status}): ${text}`);
    }
    return resp.json() as Promise<T>;
}

async function cadDelete(fn: string, uid: string): Promise<void> {
    const qs = new URLSearchParams({ fn, uid });
    const resp = await fetch(`${BASE}?${qs}`, { method: 'DELETE' });
    if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new TakCadError(`${fn} failed (${resp.status}): ${text}`);
    }
}

// ── Incidents ────────────────────────────────────────────────────────────────
export const getIncidents        = ()                      => cadGet<IncidentRef[]>('getIncidents');
export const getIncidentMetadata = ()                      => cadGet<IncidentMetadata[]>('getIncidentMetadata');
export const getIncident         = (uid: string)           => cadGet<IncidentRef>('getIncident', { uid });
export const insertIncident      = (i: IncidentRef)        => cadPut<ResponseMessage>('insertIncident', i);
export const updateIncident      = (i: IncidentRef)        => cadPut<ResponseMessage>('updateIncident', i);
export const deleteIncident      = (uid: string)           => cadDelete('deleteIncident', uid);
export const getIncidentTypes    = ()                      => cadGet<IncidentTypeRef[]>('getIncidentTypes');

// ── Vehicles ─────────────────────────────────────────────────────────────────
export const getVehicles      = ()                 => cadGet<VehicleRef[]>('getVehicles');
export const getVehicle       = (uid: string)      => cadGet<VehicleRef>('getVehicle', { uid });
export const insertVehicle    = (v: VehicleRef)    => cadPut<ResponseMessage>('insertVehicle', v);
export const updateVehicle    = (v: VehicleRef)    => cadPut<ResponseMessage>('updateVehicle', v);
export const deleteVehicle    = (uid: string)      => cadDelete('deleteVehicle', uid);
export const getVehicleTypes  = ()                 => cadGet<VehicleType[]>('getVehicleTypes');

// ── Personnel ────────────────────────────────────────────────────────────────
export const getPersonnel   = ()                => cadGet<PersonRef[]>('getPersonnel');
export const getPerson      = (uid: string)     => cadGet<PersonRef>('getPerson', { uid });
export const insertPerson   = (p: PersonRef)    => cadPut<ResponseMessage>('insertPerson', p);
export const updatePerson   = (p: PersonRef)    => cadPut<ResponseMessage>('updatePerson', p);
export const deletePerson   = (uid: string)     => cadDelete('deletePerson', uid);
export const getRoles       = ()                => cadGet<Role[]>('getRoles');

// ── Geocoding (OpenRouteService) ─────────────────────────────────────────────
// Key configured in the TAK-CAD alpha release docs.  Safe to call from browser.
const ORS_KEY  = '5b3ce3597851110001cf62488c4f8dccd2cc447aa974115095a2e6e4';
const ORS_BASE = 'https://api.openrouteservice.org/geocode';

export interface GeocodeSuggestion {
    label:   string;
    lat:     number;
    lon:     number;
}

export async function geocodeAddress(query: string): Promise<GeocodeSuggestion[]> {
    const qs = new URLSearchParams({ api_key: ORS_KEY, text: query, size: '5' });
    const resp = await fetch(`${ORS_BASE}/search?${qs}`);
    if (!resp.ok) return [];
    const json = await resp.json() as { features?: { geometry: { coordinates: number[] }; properties: { label: string } }[] };
    return (json.features ?? []).map(f => ({
        label: f.properties.label,
        lon:   f.geometry.coordinates[0],
        lat:   f.geometry.coordinates[1],
    }));
}
