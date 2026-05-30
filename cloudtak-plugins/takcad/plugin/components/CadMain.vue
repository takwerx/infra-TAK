<template>
    <div class='d-flex flex-column h-100 overflow-hidden'>
        <!-- Header -->
        <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0'>
            <IconBuildingEstate
                :size='18'
                class='me-2 text-warning'
            />
            <span class='fw-semibold'>TAK CAD</span>
            <span
                v-if='activeCount > 0'
                class='ms-2 badge bg-danger'
            >{{ activeCount }}</span>
            <span class='ms-auto text-white-50 small'>{{ connectionStatus }}</span>
        </div>

        <!-- Tab nav -->
        <div class='d-flex border-bottom flex-shrink-0'>
            <button
                v-for='tab in TABS'
                :key='tab.key'
                class='flex-fill btn btn-sm rounded-0 py-2 border-0'
                :class='activeTab === tab.key ? "bg-warning text-dark fw-semibold" : "text-white-50"'
                @click='activeTab = tab.key'
            >
                {{ tab.label }}
            </button>
        </div>

        <!-- Views -->
        <div class='flex-grow-1 overflow-hidden'>
            <IncidentListView
                v-if='activeTab === "incidents"'
                :incident-types='incidentTypes'
                :vehicles='vehicles'
                :personnel='personnel'
                @active-count='activeCount = $event'
                @status='connectionStatus = $event'
            />
            <VehicleListView
                v-else-if='activeTab === "vehicles"'
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
import { getIncidentTypes, getVehicleTypes, getVehicles, getPersonnel, getRoles } from '../lib/takcad-client.ts';
import type { IncidentTypeRef, VehicleType, VehicleRef, PersonRef, Role } from '../lib/takcad-types.ts';

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
    try {
        [incidentTypes.value, vehicleTypes.value, vehicles.value, personnel.value, roles.value] =
            await Promise.all([getIncidentTypes(), getVehicleTypes(), getVehicles(), getPersonnel(), getRoles()]);
    } catch (e) {
        console.warn('[takcad] bootstrap load failed', e);
    }
});
</script>
