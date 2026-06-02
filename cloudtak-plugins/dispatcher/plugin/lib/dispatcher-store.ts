import { reactive } from 'vue';
import { Preferences } from '@capacitor/preferences';
import type { DispatcherEvent, DispatcherIncident } from './events-client.ts';

export type ServerMode = 'detecting' | 'takcad' | 'standalone';

interface DispatcherState {
    serverMode:     ServerMode;
    forcedMode:     'standalone' | null;
    dispatcherName: string;
    // Standalone Event→Incident model (server-backed; shared across dispatchers on this CloudTAK).
    events:         DispatcherEvent[];
    activeEvent:    DispatcherEvent | null;
    incidents:      DispatcherIncident[];
}

export const dispatcherStore = reactive<DispatcherState>({
    serverMode:     'detecting',
    forcedMode:     null,
    dispatcherName: '',
    events:         [],
    activeEvent:    null,
    incidents:      [],
});

// The board itself is now server-backed (CloudTAK Postgres via the dispatcher route), so it
// no longer persists in the browser. We keep ONE tiny Preferences key — the last opened
// Event id — purely as a convenience so a reload reselects it. Everything else (the event
// list and incidents) is re-fetched from the server on mount. Uses Capacitor Preferences
// (the same API CloudTAK uses for the dispatcher name) because plain localStorage is
// unreliable in CloudTAK's PWA context.
const LAST_EVENT_KEY = 'tak-dispatcher-last-event-v1';

export async function loadLastEventId(): Promise<string | null> {
    try {
        const { value } = await Preferences.get({ key: LAST_EVENT_KEY });
        return value || null;
    } catch {
        return null;
    }
}

export function saveLastEventId(id: string | null): void {
    if (id) Preferences.set({ key: LAST_EVENT_KEY, value: id }).catch(() => {});
    else Preferences.remove({ key: LAST_EVENT_KEY }).catch(() => {});
}
