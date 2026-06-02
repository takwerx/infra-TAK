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

// Drop or update an incident marker via CloudTAK's worker DB — the same supported,
// fork-free mechanism the ping plugin and CloudTAK's own draw tools use.
//
// We use a GENERIC atom marker (a-u-G — unknown ground, the universal yellow
// diamond/clover) with NO custom usericon and NO <color>: iTAK and TAK Aware choke on a
// colored custom-iconset marker, whereas a plain atom type renders identically on every
// client (ATAK, WinTAK, iTAK, TAK Aware, CloudTAK). normalize_geojson rebuilds properties
// from a whitelist and forces type='u-d-p', dropping how — so we restore type + how after
// it. db.add passes feat.properties straight through to the broadcast CoT.
//
// Setting feat.origin = { mode: 'Mission', mode_id: feedGuid } routes the CoT into THAT
// specific DataSync feed (independent of the user's active mission). Requires the feed to
// be SUBSCRIBED in CloudTAK first.
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
    norm.properties.type = 'a-u-G';
    norm.properties.how  = 'h-g-i-g-o';
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
