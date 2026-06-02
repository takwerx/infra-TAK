import { reactive, watch } from 'vue';
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

// Standalone incidents (and the chosen feed + dispatcher name) live only in the browser
// tab. Persist the durable slice to localStorage so an open board survives a reload /
// CloudTAK rebuild — markers themselves come back via feed sync; this restores the
// dispatcher's structured list (status, assignments, notes). serverMode is intentionally
// NOT persisted — it is re-detected on every mount. Per-browser only (not shared between
// dispatcher machines — that is the larger "persist to the mission" item).
const STORAGE_KEY = 'tak-dispatcher-state-v1';

interface PersistedState {
    forcedMode:     'standalone' | null;
    dispatcherName: string;
    activeFeed:     MissionRef | null;
    localIncidents: LocalIncident[];
}

function loadPersisted(): PersistedState {
    const empty: PersistedState = { forcedMode: null, dispatcherName: '', activeFeed: null, localIncidents: [] };
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return empty;
        const data = JSON.parse(raw);
        return {
            forcedMode:     data.forcedMode === 'standalone' ? 'standalone' : null,
            dispatcherName: typeof data.dispatcherName === 'string' ? data.dispatcherName : '',
            activeFeed:     data.activeFeed ?? null,
            localIncidents: Array.isArray(data.localIncidents) ? data.localIncidents : [],
        };
    } catch {
        return empty;
    }
}

const persisted = loadPersisted();

export const dispatcherStore = reactive<DispatcherState>({
    serverMode:     'detecting',
    forcedMode:     persisted.forcedMode,
    dispatcherName: persisted.dispatcherName,
    activeFeed:     persisted.activeFeed,
    localIncidents: persisted.localIncidents,
});

// Auto-save the durable slice on any change (deep — fires on note/assignment edits too).
watch(
    () => [
        dispatcherStore.forcedMode,
        dispatcherStore.dispatcherName,
        dispatcherStore.activeFeed,
        dispatcherStore.localIncidents,
    ],
    () => {
        try {
            const snapshot: PersistedState = {
                forcedMode:     dispatcherStore.forcedMode,
                dispatcherName: dispatcherStore.dispatcherName,
                activeFeed:     dispatcherStore.activeFeed,
                localIncidents: dispatcherStore.localIncidents,
            };
            localStorage.setItem(STORAGE_KEY, JSON.stringify(snapshot));
        } catch {
            /* storage unavailable / full — best-effort */
        }
    },
    { deep: true },
);
