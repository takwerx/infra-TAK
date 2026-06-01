import { reactive } from 'vue';

export type ServerMode = 'detecting' | 'takcad' | 'standalone';

export interface LocalIncident {
    uid:                string;
    name:               string;
    type:               string;
    address:            string;
    lat:                number;
    lon:                number;
    time:               string;
    status:             'ACTIVE' | 'CANCELLED';
    assignedContactUids: string[];
}

interface DispatcherState {
    serverMode:     ServerMode;
    forcedMode:     'standalone' | null;
    localIncidents: LocalIncident[];
}

export const dispatcherStore = reactive<DispatcherState>({
    serverMode:     'detecting',
    forcedMode:     null,
    localIncidents: [],
});
