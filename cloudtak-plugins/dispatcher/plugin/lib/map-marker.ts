import { std } from '../../../src/std.ts';
import { normalize_geojson } from '@tak-ps/node-cot/normalize_geojson';
import type { useMapStore } from '../../../src/stores/map.ts';
import SubscriptionChat from '../../../src/base/subscription-chat.ts';
import ProfileConfig from '../../../src/base/profile.ts';

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

// Iconset path for the incident marker, in CloudTAK's colon web-render form
// "<iconset-uuid>:<group>/<file>" (no extension). node-cot's from_geojson rewrites it
// for the wire as <usericon iconsetpath="<uuid>/<group>/<file>.png"> — the exact path
// an ATAK CoT inspector showed for this iconset's incident icon. The iconset UUID is
// baked into the iconset zip, so it is stable on every box (ATAK, TAK Aware, CloudTAK)
// that has the iconset loaded.
const INCIDENT_ICON = 'db450cbe-2fec-47fb-bd2b-ba2db89b035e:Incident Management/incident';

// Drop or update an incident marker via CloudTAK's worker DB — the same supported,
// fork-free mechanism the ping plugin and CloudTAK's own draw tools use.
//
// IMPORTANT: normalize_geojson is a generic drawn-SHAPE normalizer. For a Point it
// HARDCODES properties.type='u-d-p' and rebuilds properties from a whitelist
// (callsign / remarks / colors only) — it silently drops any custom type, how, or
// icon. So we let it compute the base fields (center/time/stale/archived) and then
// restore the atom type + how + usericon afterward. db.add passes feat.properties
// straight through to the broadcast CoT (it does NOT re-normalize), so the usericon
// reaches ATAK/iTAK. Without this restore the CoT goes out as a bare u-d-p point with
// no <usericon> (renders as a white/green dot).
//
// Setting feat.origin = { mode: 'Mission', mode_id: feedGuid } routes the CoT into
// THAT specific DataSync feed (independent of the user's active mission). Requires the
// feed to be SUBSCRIBED in CloudTAK first.
export async function dropIncidentMarker(mapStore: MapStore, incident: MarkerIncident): Promise<void> {
    const feat = {
        id:   incident.uid,
        type: 'Feature',
        properties: {
            callsign: `${incident.number} ${incident.name}`,
            remarks:  buildRemarks(incident),
        },
        geometry: {
            type:        'Point',
            coordinates: [incident.lon, incident.lat],
        },
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const norm: any = await normalize_geojson(feat as any);
    norm.properties.type = 'a-n-G';
    norm.properties.how  = 'h-g-i-g-o';
    norm.properties.icon = INCIDENT_ICON;
    const withOrigin = incident.feedGuid
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

// Post an announcement into the DataSync feed's mission-chat thread — the same chat
// MissionChats.vue drives. Reuses CloudTAK's SubscriptionChat so the message both
// writes to the local chat DB (keyed by feed.guid) and broadcasts to every feed
// subscriber over the user's connection (chatroom/dest = feed.name).
export async function postFeedChat(
    mapStore: MapStore,
    feed: { guid: string; name: string },
    message: string
): Promise<void> {
    const username = (await ProfileConfig.get('username'))?.value;
    const callsign = (await ProfileConfig.get('tak_callsign'))?.value;
    const sender = {
        uid:      username ? `ANDROID-CloudTAK-${username}` : 'ANDROID-CloudTAK-dispatcher',
        callsign: String(callsign || 'Dispatcher'),
    };
    const chat = new SubscriptionChat(feed.guid, feed.name);
    await chat.send(message, sender, mapStore.worker);
}
