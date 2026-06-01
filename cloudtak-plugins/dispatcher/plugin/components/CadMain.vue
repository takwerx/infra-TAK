<template>
    <div class='d-flex flex-column h-100 overflow-hidden'>
        <!-- Header -->
        <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0'>
            <IconBuildingEstate
                :size='18'
                class='me-2 text-warning'
            />
            <span class='fw-semibold'>Dispatcher</span>
            <span
                v-if='activeCount > 0'
                class='ms-2 badge bg-danger'
            >{{ activeCount }}</span>
            <!-- Server-mode pill -->
            <span
                v-if='store.serverMode === "takcad"'
                class='ms-2 badge bg-success text-white small'
            >TAK-CAD Connected</span>
            <span
                v-else-if='store.serverMode === "standalone"'
                class='ms-2 badge bg-secondary text-white small'
            >Standalone</span>
            <span
                v-else
                class='ms-2 badge bg-secondary text-white small opacity-50'
            >Detecting…</span>
        </div>

        <!-- Tab nav -->
        <div class='d-flex border-bottom flex-shrink-0'>
            <button
                v-for='tab in TABS'
                :key='tab.key'
                class='flex-fill btn btn-sm rounded-0 py-2 border-0'
                :class='activeTab === tab.key ? "bg-warning text-dark fw-semibold" : "text-muted"'
                @click='activeTab = tab.key'
            >
                {{ tab.label }}
            </button>
        </div>

        <!-- Views -->
        <div class='flex-grow-1 overflow-hidden'>
            <IncidentListView
                v-if='activeTab === "incidents"'
                :server-mode='store.serverMode'
                :incident-types='incidentTypes'
                :vehicles='vehicles'
                :personnel='personnel'
                @active-count='activeCount = $event'
                @status='connectionStatus = $event'
            />
            <VehicleListView
                v-else-if='activeTab === "vehicles"'
                :server-mode='store.serverMode'
                :vehicle-types='vehicleTypes'
            />
            <PersonnelListView
                v-else-if='activeTab === "personnel"'
                :roles='roles'
            />
        </div>
    </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { IconBuildingEstate } from '@tabler/icons-vue';
import IncidentListView from './IncidentListView.vue';
import VehicleListView  from './VehicleListView.vue';
import PersonnelListView from './PersonnelListView.vue';
import { getIncidentTypes, getVehicleTypes, getVehicles, getPersonnel, getRoles, getIncidentMetadata } from '../lib/takcad-client.ts';
import type { IncidentTypeRef, VehicleType, VehicleRef, PersonRef, Role } from '../lib/takcad-types.ts';
import { dispatcherStore as store } from '../lib/dispatcher-store.ts';

const TABS = [
    { key: 'incidents',  label: 'Incidents'  },
    { key: 'vehicles',   label: 'Vehicles'   },
    { key: 'personnel',  label: 'Personnel'  },
] as const;

type TabKey = typeof TABS[number]['key'];

const activeTab        = ref<TabKey>('incidents');
const activeCount      = ref(0);
const connectionStatus = ref('');
const incidentTypes    = ref<IncidentTypeRef[]>([]);
const vehicleTypes     = ref<VehicleType[]>([]);
const vehicles         = ref<VehicleRef[]>([]);
const personnel        = ref<PersonRef[]>([]);
const roles            = ref<Role[]>([]);

onMounted(async () => {
    // Mode detection: attempt getIncidentMetadata — success = takcad, error = standalone
    store.serverMode = 'detecting';
    try {
        await getIncidentMetadata();
        store.serverMode = 'takcad';
        // Load TAK-CAD metadata in parallel (takcad mode only)
        try {
            [incidentTypes.value, vehicleTypes.value, vehicles.value, personnel.value, roles.value] =
                await Promise.all([getIncidentTypes(), getVehicleTypes(), getVehicles(), getPersonnel(), getRoles()]);
        } catch (e) {
            console.warn('[dispatcher] takcad metadata load failed', e);
        }
    } catch {
        store.serverMode = 'standalone';
    }
});
</script>
