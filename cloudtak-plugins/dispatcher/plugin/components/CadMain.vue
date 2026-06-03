<template>
    <div class='d-flex flex-column h-100 overflow-hidden'>

        <div
            v-if='setupError'
            class='alert alert-danger m-2 small'
            style='white-space:pre-wrap;font-family:monospace;font-size:10px;overflow:auto'
        >
            <div class='fw-bold mb-1'>Dispatcher error:</div>{{ setupError }}
        </div>
        <template v-else>
            <!-- Header -->
            <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                <IconHeadset :size='18' class='text-warning' />
                <span class='fw-semibold'>Dispatcher</span>
                <span
                    v-if='activeCount > 0'
                    class='badge bg-danger'
                >{{ activeCount }}</span>
                <span
                    class='text-muted ms-auto small'
                    :title='`Dispatcher: ${store.dispatcherName}`'
                >{{ store.dispatcherName }}</span>
                <!-- TAK-CAD connection toggle -->
                <button
                    v-if='store.serverMode === "takcad"'
                    class='badge bg-success text-white small border-0'
                    style='cursor:pointer'
                    title='TAK-CAD connected — click to disconnect'
                    @click='forceStandalone'
                >TAK-CAD ●</button>
                <button
                    v-else-if='store.serverMode === "standalone"'
                    class='badge bg-secondary text-white small border-0'
                    style='cursor:pointer'
                    title='Connect to TAK-CAD'
                    @click='retryDetection'
                >TAK-CAD</button>
                <span
                    v-else
                    class='badge bg-secondary text-white small opacity-50'
                >TAK-CAD…</span>
            </div>

            <!-- ── TAK-CAD mode: DataSync feed picker (markers/log routing) ─────── -->
            <div
                v-if='store.serverMode === "takcad"'
                class='px-3 py-2 border-bottom flex-shrink-0'
            >
                <div v-if='!takcadFeed'>
                    <button
                        class='btn btn-sm btn-outline-secondary w-100'
                        :disabled='loadingFeeds'
                        @click='fetchFeeds'
                    >
                        <span v-if='loadingFeeds' class='spinner-border spinner-border-sm me-1' />
                        {{ loadingFeeds ? 'Loading…' : '+ Select DataSync Feed' }}
                    </button>
                    <div
                        v-if='feeds.length'
                        class='border rounded mt-1'
                        style='max-height:160px;overflow-y:auto;background:var(--bs-body-bg,#1e2228)'
                    >
                        <button
                            v-for='f in feeds'
                            :key='f.guid'
                            class='btn btn-sm w-100 text-start px-3 py-2 border-0 border-bottom rounded-0'
                            style='font-size:12px'
                            @click='selectFeed(f)'
                        >
                            {{ f.name }}
                        </button>
                    </div>
                    <div
                        v-else-if='feedsFetched && !loadingFeeds'
                        class='text-muted small text-center py-1'
                    >
                        No DataSync feeds found
                    </div>
                </div>
                <div
                    v-else
                    class='d-flex align-items-center gap-2 small'
                >
                    <span class='badge bg-primary text-white'>DataSync</span>
                    <span class='text-truncate flex-grow-1'>{{ takcadFeed.name }}</span>
                    <button
                        class='btn btn-link btn-sm p-0 text-muted text-decoration-none'
                        @click='takcadFeed = null; feeds = []; feedsFetched = false'
                    >
                        ✕
                    </button>
                </div>
            </div>

            <!-- ── Standalone mode: Event bar (when an Event is open) ───────────── -->
            <div
                v-else-if='store.serverMode === "standalone" && store.activeEvent'
                class='px-3 py-2 border-bottom flex-shrink-0 d-flex align-items-center gap-2 small'
            >
                <span class='badge bg-primary text-white'>Event</span>
                <div class='flex-grow-1 text-truncate'>
                    <span class='fw-semibold'>{{ store.activeEvent.name }}</span>
                    <span class='ms-2'>
                        <span class='badge bg-primary text-white'>DataSync</span>
                        <span class='fw-semibold'>{{ store.activeEvent.feed_name }}</span>
                    </span>
                </div>
                <span
                    v-if='store.activeEvent.status === "archived"'
                    class='badge bg-secondary'
                >Archived</span>
                <button
                    class='btn btn-link btn-sm p-0 text-muted text-decoration-none'
                    title='Back to events'
                    @click='closeEvent'
                >
                    ✕
                </button>
            </div>

            <!-- ── Standalone mode: Events screen (no Event open) ──────────────── -->
            <div
                v-if='store.serverMode === "standalone" && !store.activeEvent'
                class='flex-grow-1 overflow-hidden'
            >
                <EventsView @opened='onEventOpened' />
            </div>

            <!-- ── Otherwise: tabs + incident/vehicle/personnel views ──────────── -->
            <template v-else>
                <!-- Tab nav — Vehicles/Personnel only in TAK-CAD mode -->
                <div class='d-flex border-bottom flex-shrink-0'>
                    <button
                        v-for='tab in visibleTabs'
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
                        :takcad-feed='takcadFeed'
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
            </template>
        </template>
    </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onErrorCaptured, watch } from 'vue';
import ProfileConfig from '../../../src/base/profile.ts';
import { IconHeadset } from '@tabler/icons-vue';
import IncidentListView from './IncidentListView.vue';
import VehicleListView  from './VehicleListView.vue';
import PersonnelListView from './PersonnelListView.vue';
import EventsView from './EventsView.vue';
import { getIncidentTypes, getVehicleTypes, getVehicles, getPersonnel, getRoles, getIncidentMetadata, getMissions } from '../lib/takcad-client.ts';
import type { MissionRef } from '../lib/takcad-client.ts';
import type { IncidentTypeRef, VehicleType, VehicleRef, PersonRef, Role } from '../lib/takcad-types.ts';
import { listIncidents } from '../lib/events-client.ts';
import type { DispatcherEvent } from '../lib/events-client.ts';
import { dispatcherStore as store, saveLastEventId } from '../lib/dispatcher-store.ts';

const TABS = [
    { key: 'incidents',  label: 'Incidents',  takCadOnly: false },
    { key: 'vehicles',   label: 'Vehicles',   takCadOnly: true  },
    { key: 'personnel',  label: 'Personnel',  takCadOnly: true  },
] as const;

type TabKey = typeof TABS[number]['key'];

const visibleTabs = computed(() =>
    TABS.filter(t => !t.takCadOnly || store.serverMode === 'takcad')
);

// Diagnostic: surface any child setup/render throw as text instead of a blank panel.
const setupError = ref('');
onErrorCaptured((err) => {
    setupError.value = err instanceof Error ? (err.stack || err.message) : String(err);
    // eslint-disable-next-line no-console
    console.error('[dispatcher] captured render error', err);
    return false;
});

const activeTab        = ref<TabKey>('incidents');
const activeCount      = ref(0);
const connectionStatus = ref('');
const incidentTypes    = ref<IncidentTypeRef[]>([]);
const vehicleTypes     = ref<VehicleType[]>([]);
const vehicles         = ref<VehicleRef[]>([]);
const personnel        = ref<PersonRef[]>([]);
const roles            = ref<Role[]>([]);
const feeds            = ref<MissionRef[]>([]);
const loadingFeeds     = ref(false);
const feedsFetched     = ref(false);

// TAK-CAD mode keeps its own local DataSync feed for marker/log routing (the standalone
// path now routes via the open Event's feed_guid instead).
const takcadFeed = ref<MissionRef | null>(null);

async function fetchFeeds() {
    loadingFeeds.value = true;
    feedsFetched.value = false;
    try { feeds.value = await getMissions(); }
    catch { feeds.value = []; }
    finally { loadingFeeds.value = false; feedsFetched.value = true; }
}

function selectFeed(f: MissionRef) {
    takcadFeed.value = f;
    feeds.value = [];
    feedsFetched.value = false;
}

// An Event was opened from the Events screen → load its incidents and remember it.
async function onEventOpened(event: DispatcherEvent) {
    saveLastEventId(event.id);
    activeTab.value = 'incidents';
    try { store.incidents = await listIncidents(event.id); }
    catch { store.incidents = []; }
}

function closeEvent() {
    store.activeEvent = null;
    store.incidents = [];
    saveLastEventId(null);
    activeCount.value = 0;
}

async function detect() {
    store.serverMode = 'detecting';
    try {
        await getIncidentMetadata();
        store.serverMode = 'takcad';
        try {
            [incidentTypes.value, vehicleTypes.value, vehicles.value, personnel.value, roles.value] =
                await Promise.all([getIncidentTypes(), getVehicleTypes(), getVehicles(), getPersonnel(), getRoles()]);
        } catch (e) {
            console.warn('[dispatcher] takcad metadata load failed', e);
        }
    } catch {
        store.serverMode = 'standalone';
    }
}

// Reset badge and tab when disconnecting from TAK-CAD
watch(() => store.serverMode, (mode) => {
    if (mode === 'standalone') {
        activeCount.value = 0;
        if (activeTab.value !== 'incidents') activeTab.value = 'incidents';
    }
});

function forceStandalone() {
    store.forcedMode = 'standalone';
    store.serverMode = 'standalone';
}

async function retryDetection() {
    store.forcedMode = null;
    await detect();
}

onMounted(async () => {
    // Dispatcher identity = the user's CloudTAK callsign (no separate prompt). Same callsign
    // GeoChat messages are sent from; it also lands in incident-marker remarks.
    const callsign = (await ProfileConfig.get('tak_callsign'))?.value;
    const username = (await ProfileConfig.get('username'))?.value;
    store.dispatcherName = String(callsign || username || 'Dispatcher');

    if (store.forcedMode === 'standalone') {
        store.serverMode = 'standalone';
        return;
    }
    await detect();
});
</script>
