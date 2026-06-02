import { std } from '../../../src/std.ts';
import Chatroom from '../../../src/base/chatroom.ts';
import ProfileConfig from '../../../src/base/profile.ts';
import type { useMapStore } from '../../../src/stores/map.ts';

type MapStore = ReturnType<typeof useMapStore>;

export interface TakContact {
    uid:      string;
    callsign: string;
    lastSeen?: string;
}

// CloudTAK proxies TAK Server's /Marti/api/contacts/all at /api/marti/api/contacts/all
// (route is /marti/api/contacts/all, mounted under /api). Returns a bare JSON array.
// TAK Server interleaves an empty placeholder entry (callsign:"", uid:"", notes:" admin")
// between every real contact, so filter to entries that actually have a uid + callsign.
export async function getContacts(): Promise<TakContact[]> {
    const resp = await std('/api/marti/api/contacts/all', { method: 'GET' }) as TakContact[] | null;
    return Array.isArray(resp) ? resp.filter(c => c && c.uid && c.callsign) : [];
}

// Build the dispatcher's GeoChat sender identity from the CloudTAK profile.
async function dispatcherSender(): Promise<{ uid: string; callsign: string }> {
    const username = (await ProfileConfig.get('username'))?.value;
    const myCallsign = (await ProfileConfig.get('tak_callsign'))?.value;
    return {
        uid:      username ? `ANDROID-CloudTAK-${username}` : 'ANDROID-CloudTAK-dispatcher',
        callsign: String(myCallsign || 'Dispatcher'),
    };
}

// Send a direct GeoChat to a contact via CloudTAK's Chatroom — the same path
// MenuChat.vue uses (worker.conn.sendCOT under the hood). The old POST /api/marti/chats
// had no backing route and silently failed.
async function sendDirectChat(
    mapStore: MapStore,
    contact: { uid: string; callsign: string },
    message: string
): Promise<void> {
    const sender = await dispatcherSender();
    const room = new Chatroom(contact.callsign);
    await room.chats.send(message, sender, mapStore.worker, { uid: contact.uid, callsign: contact.callsign });
}

// Assignment notification sent to a contact when they're added to an incident.
export async function sendAssignmentMessage(
    mapStore: MapStore,
    contact: { uid: string; callsign: string },
    incident: { name: string; address: string }
): Promise<void> {
    const msg = `You have been assigned to: ${incident.name}${incident.address ? ' at ' + incident.address : ''}. Incident on your map.`;
    await sendDirectChat(mapStore, contact, msg);
}

// Update notification sent to an assigned responder when the dispatcher adds an incident note.
export async function sendUpdateMessage(
    mapStore: MapStore,
    contact: { uid: string; callsign: string },
    incident: { name: string },
    note: string
): Promise<void> {
    await sendDirectChat(mapStore, contact, `UPDATE — ${incident.name}: ${note}`);
}
