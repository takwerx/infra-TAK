import { reactive } from 'vue';
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
// no longer persists in the browser. We keep ONE tiny key — the last opened Event id —
// purely as a convenience so a reload reselects it. Everything else (the event list and
// incidents) is re-fetched from the server on mount. Stored in localStorage, the same store
// CloudTAK uses for its own auth token; CloudTAK's web build has no Capacitor runtime, so
// the Capacitor Preferences API is unavailable here.
const LAST_EVENT_KEY = 'tak-dispatcher-last-event-v1';

export async function loadLastEventId(): Promise<string | null> {
    try {
        return localStorage.getItem(LAST_EVENT_KEY) || null;
    } catch {
        return null;
    }
}

export function saveLastEventId(id: string | null): void {
    try {
        if (id) localStorage.setItem(LAST_EVENT_KEY, id);
        else localStorage.removeItem(LAST_EVENT_KEY);
    } catch {
        // ignore storage failures (private mode / quota)
    }
}
