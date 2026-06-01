import { std } from '../../../src/std.ts';

// Drop a CoT a-u-G (unknown ground — yellow diamond/clover) at the incident location.
// Routed through the /takcad/cot server proxy (same auth pattern as geocode proxy).
export async function dropIncidentMarker(incident: {
    uid:     string;
    name:    string;
    type:    string;
    address: string;
    lat:     number;
    lon:     number;
}): Promise<void> {
    await std('/api/takcad/cot', {
        method: 'POST',
        body: {
            uid:     incident.uid,
            name:    incident.name,
            type:    incident.type,
            address: incident.address,
            lat:     incident.lat,
            lon:     incident.lon,
        },
    });
}

// Post a plain-text message to the active mission's thread (DataSync log entry).
export async function postMissionCallLog(
    missionGuid: string,
    incident: { name: string; type: string; address: string }
): Promise<void> {
    const msg = `CALL FOR SERVICE: ${incident.name} | ${incident.type}${incident.address ? ' | ' + incident.address : ''} | ${new Date().toLocaleTimeString()}`;
    await std(`/api/marti/missions/${encodeURIComponent(missionGuid)}/log`, {
        method: 'POST',
        body:   { message: msg },
    });
}
