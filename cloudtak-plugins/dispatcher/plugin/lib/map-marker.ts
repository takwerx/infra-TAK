import { std } from '../../../src/std.ts';

export interface MarkerIncident {
    uid:         string;
    number:      string;
    name:        string;
    type:        string;
    address:     string;
    lat:         number;
    lon:         number;
    time:        string;
    dispatcher:  string;
    details:     string;
    missionName?: string;
}

// Build the remarks string for a CoT incident marker.
function buildRemarks(incident: MarkerIncident): string {
    const t = new Date(incident.time);
    const hhmm = `${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}`;
    const parts = [
        incident.type,
        `Start: ${hhmm}`,
        incident.dispatcher ? `Dispatcher: ${incident.dispatcher}` : '',
        incident.details    ? incident.details                       : '',
    ].filter(Boolean);
    return parts.join(' | ');
}

// Drop or update a CoT a-u-G marker. Same UID = update on all subscribed clients.
// callsign (map label) = "{number} {name}". missionName routes it into a DataSync feed.
export async function dropIncidentMarker(incident: MarkerIncident): Promise<void> {
    await std('/api/takcad/cot', {
        method: 'POST',
        body: {
            uid:         incident.uid,
            name:        `${incident.number} ${incident.name}`,
            type:        incident.type,
            address:     incident.address,
            lat:         incident.lat,
            lon:         incident.lon,
            remarks:     buildRemarks(incident),
            missionName: incident.missionName,
        },
    });
}

// Resend same UID with updated remarks (e.g. after adding a note).
export async function updateIncidentMarker(incident: MarkerIncident): Promise<void> {
    await dropIncidentMarker(incident);
}

// Remove the marker by sending a CoT with stale time in the past.
export async function removeIncidentMarker(incident: MarkerIncident): Promise<void> {
    await std('/api/takcad/cot', {
        method: 'POST',
        body: {
            uid:          incident.uid,
            name:         `${incident.number} ${incident.name}`,
            type:         incident.type,
            address:      incident.address,
            lat:          incident.lat,
            lon:          incident.lon,
            remarks:      buildRemarks(incident),
            missionName:  incident.missionName,
            deleteMarker: true,
        },
    });
}

// Post a plain-text message to the DataSync mission log.
export async function postMissionCallLog(
    missionGuid: string,
    incident: { number: string; name: string; type: string; address: string; time: string }
): Promise<void> {
    const t = new Date(incident.time);
    const hhmm = `${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}`;
    const msg = `CALL FOR SERVICE: ${incident.number} | ${incident.name} | ${incident.type}${incident.address ? ' | ' + incident.address : ''} | ${hhmm}`;
    await std(`/api/marti/missions/${encodeURIComponent(missionGuid)}/log`, {
        method: 'POST',
        body:   { message: msg },
    });
}
