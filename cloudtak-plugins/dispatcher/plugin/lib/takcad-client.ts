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

import { std } from '../../../src/std.ts';
import type {
    IncidentRef, IncidentMetadata, IncidentTypeRef,
    VehicleRef, VehicleType,
    PersonRef, Role,
    ResponseMessage,
} from './takcad-types.ts';

// Routed through CloudTAK's std() helper so requests carry the user's Bearer
// token (from Capacitor Preferences). Raw fetch() has no auth → "No Auth Present".
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
    return await std(`${BASE}?${qs.toString()}`, { method: 'GET' }) as T;
}

// Inserts → PUT /submit/result (onSubmitDataWithResult), returns a ResponseMessage.
async function cadPut<T>(fn: string, body: unknown): Promise<T> {
    return await std(`${BASE_PUT}?fn=${encodeURIComponent(fn)}`, { method: 'PUT', body }) as T;
}

// Updates → POST /submit?fn=&uid= (updateInPlugin → onUpdateData). NOTE: the server
// routes update via a DIFFERENT endpoint than insert (PUT /submit/result gives
// "method not implemented"), AND requires the uid as a query param ("missing uid"
// otherwise). onUpdateData is fire-and-forget (void) → TAK Server returns a generic
// 200 ack, not a ResponseMessage, so we synthesize success on a clean call.
async function cadUpdate(fn: string, uid: string, body: unknown): Promise<ResponseMessage> {
    const qs = new URLSearchParams({ fn, uid });
    await std(`${BASE}?${qs.toString()}`, { method: 'POST', body });
    return { success: true, result: null, warnings: [], errors: [] };
}

async function cadDelete(fn: string, uid: string): Promise<void> {
    const qs = new URLSearchParams({ fn, uid });
    await std(`${BASE}?${qs.toString()}`, { method: 'DELETE' });
}

// ── Incidents ────────────────────────────────────────────────────────────────
export const getIncidents        = ()                      => cadGet<IncidentRef[]>('getIncidents');
export const getIncidentMetadata = ()                      => cadGet<IncidentMetadata[]>('getIncidentMetadata');
export const getIncident         = (uid: string)           => cadGet<IncidentRef>('getIncident', { uid });
export const insertIncident      = (i: IncidentRef)        => cadPut<ResponseMessage>('insertIncident', i);
export const updateIncident      = (i: IncidentRef)        => cadUpdate('updateIncident', i.uid, i);
export const deleteIncident      = (uid: string)           => cadDelete('deleteIncident', uid);
export const getIncidentTypes    = ()                      => cadGet<IncidentTypeRef[]>('getIncidentTypes');

// ── Vehicles ─────────────────────────────────────────────────────────────────
export const getVehicles      = ()                 => cadGet<VehicleRef[]>('getVehicles');
export const getVehicle       = (uid: string)      => cadGet<VehicleRef>('getVehicle', { uid });
export const insertVehicle    = (v: VehicleRef)    => cadPut<ResponseMessage>('insertVehicle', v);
export const updateVehicle    = (v: VehicleRef)    => cadUpdate('updateVehicle', v.uid, v);
export const deleteVehicle    = (uid: string)      => cadDelete('deleteVehicle', uid);
export const getVehicleTypes  = ()                 => cadGet<VehicleType[]>('getVehicleTypes');

// Vehicle-to-incident assignment uses a separate VehicleResponseMetadata DTO —
// NOT updateIncident.vehicleUidsRequested (the server ignores that field on update).
// insertVehicleResponse → PUT /submit/result (onSubmitDataWithResult).
// deleteVehicleResponse → POST /submit?uid= (onUpdateData — DELETE bridge is broken).
export interface VehicleResponseMetadata {
    uid:            string;
    callsign:       string;
    vehicleUid:     string;
    incidentUid:    string;
    responseStatus: string | null;
    eta:            number | null;
    arrivalTime:    string | null;
}
export const insertVehicleResponse = (r: VehicleResponseMetadata) => cadPut<ResponseMessage>('insertVehicleResponse', r);
export const deleteVehicleResponse = (uid: string)                => cadUpdate('deleteVehicleResponse', uid, {});

// ── Personnel ────────────────────────────────────────────────────────────────
export const getPersonnel   = ()                => cadGet<PersonRef[]>('getPersonnel');
export const getPerson      = (uid: string)     => cadGet<PersonRef>('getPerson', { uid });
export const insertPerson   = (p: PersonRef)    => cadPut<ResponseMessage>('insertPerson', p);
export const updatePerson   = (p: PersonRef)    => cadUpdate('updatePerson', p.uid, p);
export const deletePerson   = (uid: string)     => cadDelete('deletePerson', uid);
export const getRoles       = ()                => cadGet<Role[]>('getRoles');

// ── Missions ─────────────────────────────────────────────────────────────────
export interface MissionRef {
    guid:        string;
    name:        string;
    description?: string;
}

export async function getMissions(): Promise<MissionRef[]> {
    const resp = await std('/api/marti/mission', { method: 'GET' }) as { items?: MissionRef[] } | null;
    return resp?.items ?? [];
}

// ── Geocoding ────────────────────────────────────────────────────────────────
// Proxied through CloudTAK (server route plugin-takcad.ts → OpenRouteService).
// A direct browser call to openrouteservice.org is blocked by CloudTAK's CSP
// (connect-src is 'self' only), so it must go server-side. Auth via std().
export interface GeocodeSuggestion {
    label:      string;
    lat:        number;
    lon:        number;
    streetName: string;
    city:       string;
    state:      string;
    zipCode:    string;
    country:    string;
}

export async function geocodeAddress(query: string): Promise<GeocodeSuggestion[]> {
    const qs = new URLSearchParams({ q: query });
    const resp = await std(`/api/takcad/geocode?${qs.toString()}`, { method: 'GET' }) as { suggestions?: GeocodeSuggestion[] };
    return resp.suggestions ?? [];
}

// Reverse geocode a map-clicked point into an address (for "pick on map").
export async function reverseGeocode(lat: number, lon: number): Promise<GeocodeSuggestion | null> {
    const qs = new URLSearchParams({ lat: String(lat), lon: String(lon) });
    const resp = await std(`/api/takcad/geocode/reverse?${qs.toString()}`, { method: 'GET' }) as { suggestion?: GeocodeSuggestion | null };
    return resp.suggestion ?? null;
}
