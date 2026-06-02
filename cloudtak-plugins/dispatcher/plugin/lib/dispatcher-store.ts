import { reactive, watch } from 'vue';
import { Preferences } from '@capacitor/preferences';
import type { MissionRef } from './takcad-client.ts';

export type ServerMode = 'detecting' | 'takcad' | 'standalone';

export interface IncidentNote {
    text: string;
    time: string;
}

export interface LocalIncident {
    uid:                 string;
    number:              string;
    name:                string;
    type:                string;
    address:             string;
    lat:                 number;
    lon:                 number;
    time:                string;
    dispatcher:          string;
    details:             string;
    status:              'ACTIVE' | 'CANCELLED';
    assignedContacts: { uid: string; callsign: string }[];
    notes:               IncidentNote[];
}

interface DispatcherState {
    serverMode:     ServerMode;
    forcedMode:     'standalone' | null;
    dispatcherName: string;
    activeFeed:     MissionRef | null;
    localIncidents: LocalIncident[];
}

export const dispatcherStore = reactive<DispatcherState>({
    serverMode:     'detecting',
    forcedMode:     null,
    dispatcherName: '',
    activeFeed:     null,
    localIncidents: [],
});

// Standalone incidents (+ chosen feed and forced mode) live only in the browser tab, so
// a reload / CloudTAK rebuild would otherwise wipe the board. Persist the durable slice
// via Capacitor Preferences — the SAME API CloudTAK uses for the dispatcher name, which
// works in both web and native (plain localStorage is unreliable in CloudTAK's PWA
// context, which is why nothing persisted before). dispatcherName keeps its own existing
// 'dispatcher-name' key; serverMode is never persisted (re-detected each mount). Markers
// themselves return via feed sync — this restores the structured board (status,
// assignments, notes). Per-browser only; cross-machine sharing is the larger
// persist-to-mission item.
const STORAGE_KEY = 'tak-dispatcher-board-v1';

interface PersistedBoard {
    forcedMode:     'standalone' | null;
    activeFeed:     MissionRef | null;
    localIncidents: LocalIncident[];
}

let hydrated = false;

// Load the persisted board into the store. Call once on plugin mount, BEFORE the
// forcedMode check, so a restored standalone session comes back intact.
export async function hydrateDispatcherStore(): Promise<void> {
    if (hydrated) return;
    try {
        const { value } = await Preferences.get({ key: STORAGE_KEY });
        if (value) {
            const data = JSON.parse(value);
            if (data.forcedMode === 'standalone') dispatcherStore.forcedMode = 'standalone';
            if (data.activeFeed) dispatcherStore.activeFeed = data.activeFeed;
            if (Array.isArray(data.localIncidents)) dispatcherStore.localIncidents = data.localIncidents;
        }
    } catch {
        /* best-effort */
    }
    hydrated = true;
}

// Auto-save the durable slice on any change (deep — fires on note/assignment edits too).
// Guarded by `hydrated` so the empty initial state never clobbers a saved board before
// hydrateDispatcherStore() has run.
watch(
    () => [
        dispatcherStore.forcedMode,
        dispatcherStore.activeFeed,
        dispatcherStore.localIncidents,
    ],
    () => {
        if (!hydrated) return;
        const snapshot: PersistedBoard = {
            forcedMode:     dispatcherStore.forcedMode,
            activeFeed:     dispatcherStore.activeFeed,
            localIncidents: dispatcherStore.localIncidents,
        };
        Preferences.set({ key: STORAGE_KEY, value: JSON.stringify(snapshot) }).catch(() => {});
    },
    { deep: true },
);
