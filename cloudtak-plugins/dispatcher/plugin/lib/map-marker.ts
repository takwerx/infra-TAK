import { std } from '../../../src/std.ts';
import { normalize_geojson } from '@tak-ps/node-cot/normalize_geojson';
import type { useMapStore } from '../../../src/stores/map.ts';

type MapStore = ReturnType<typeof useMapStore>;

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
    feedGuid?:   string;  // DataSync mission GUID to route the marker into
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

// Drop or update an incident marker via CloudTAK's worker DB — the same supported,
// fork-free mechanism the ping plugin and CloudTAK's own draw tools use.
//
// Setting feat.origin = { mode: 'Mission', mode_id: feedGuid } routes the CoT into
// THAT specific DataSync feed (independent of the user's active mission). The worker
// broadcasts it to TAK Server over the user's existing connection and links it to the
// feed for all subscribers. Requires the feed to be SUBSCRIBED in CloudTAK first.
export async function dropIncidentMarker(mapStore: MapStore, incident: MarkerIncident): Promise<void> {
    const feat = {
        id:   incident.uid,
        type: 'Feature',
        properties: {
            callsign: `${incident.number} ${incident.name}`,
            type:     'a-u-G',
            how:      'h-g-i-g-o',
            remarks:  buildRemarks(incident),
        },
        geometry: {
            type:        'Point',
            coordinates: [incident.lon, incident.lat],
        },
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const norm = await normalize_geojson(feat as any);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const withOrigin: any = incident.feedGuid
        ? { ...norm, origin: { mode: 'Mission', mode_id: incident.feedGuid } }
        : norm;
    await mapStore.worker.db.add(JSON.parse(JSON.stringify(withOrigin)), { authored: true });
}

// Resend (same UID) with updated remarks — db.add detects the existing CoT and updates it.
export async function updateIncidentMarker(mapStore: MapStore, incident: MarkerIncident): Promise<void> {
    await dropIncidentMarker(mapStore, incident);
}

// Remove the marker from the map and its DataSync feed.
export async function removeIncidentMarker(mapStore: MapStore, incident: MarkerIncident): Promise<void> {
    await mapStore.worker.db.remove(incident.uid, { mission: true });
}

// Post a plain-text entry to the DataSync mission log.
// CloudTAK's log route keys by mission NAME (not guid) and the body field is `content`.
// entryUid links the log entry to the incident's CoT marker.
export async function postMissionCallLog(
    missionName: string,
    incident: { uid: string; number: string; name: string; type: string; address: string; time: string }
): Promise<void> {
    const t = new Date(incident.time);
    const hhmm = `${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}`;
    const content = `CALL FOR SERVICE: ${incident.number} | ${incident.name} | ${incident.type}${incident.address ? ' | ' + incident.address : ''} | ${hhmm}`;
    await std(`/api/marti/missions/${encodeURIComponent(missionName)}/log`, {
        method: 'POST',
        body:   { content, entryUid: incident.uid },
    });
}
