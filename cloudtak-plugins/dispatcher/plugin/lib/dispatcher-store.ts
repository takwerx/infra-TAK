import { reactive } from 'vue';
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
