import { std } from '../../../src/std.ts';

export interface TakContact {
    uid:      string;
    callsign: string;
    lastSeen?: string;
}

export async function getContacts(): Promise<TakContact[]> {
    const resp = await std('/api/marti/contacts/all', { method: 'GET' }) as TakContact[] | null;
    return Array.isArray(resp) ? resp : [];
}

// Send a direct GeoChat assignment message to a contact.
export async function sendAssignmentMessage(
    contactUid: string,
    incident: { name: string; address: string }
): Promise<void> {
    const msg = `You have been assigned to: ${incident.name}${incident.address ? ' at ' + incident.address : ''}. Incident on your map.`;
    await std('/api/marti/chats', {
        method: 'POST',
        body: {
            chatroom: contactUid,
            message:  msg,
        },
    });
}
