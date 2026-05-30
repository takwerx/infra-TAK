<template>
    <div class="d-flex flex-column h-100 overflow-hidden">

        <!-- ── Incident List ──────────────────────────────────── -->
        <template v-if="view === 'list'">
            <div class="d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2">
                <div class="d-flex rounded overflow-hidden border border-secondary flex-grow-1">
                    <button
                        v-for="t in LIST_TABS" :key="t.key"
                        class="flex-fill btn btn-sm py-1 rounded-0 border-0 small"
                        :class="listTab === t.key ? 'bg-secondary text-white' : 'text-white-50'"
                        @click="listTab = t.key"
                    >{{ t.label }} <span class="badge" :class="listTab === t.key ? 'bg-warning text-dark' : 'bg-dark text-white-50'">{{ t.key === 'active' ? activeIncidents.length : cancelledIncidents.length }}</span></button>
                </div>
                <button class="btn btn-sm btn-warning" @click="openCreate">+ New</button>
            </div>

            <!-- Sort bar -->
            <div class="d-flex px-3 py-1 border-bottom text-white-50 small flex-shrink-0">
                <button v-for="col in SORT_COLS" :key="col.key"
                    class="btn btn-sm btn-link p-0 text-white-50 small me-3 text-decoration-none"
                    @click="toggleSort(col.key)"
                >
                    {{ col.label }}
                    <span v-if="sortCol === col.key">{{ sortAsc ? '↑' : '↓' }}</span>
                </button>
                <span class="ms-auto text-white-25 font-monospace" style="font-size:10px">{{ lastRefreshed }}</span>
            </div>

            <!-- List -->
            <div class="flex-grow-1 overflow-auto">
                <div v-if="loading && !displayedIncidents.length" class="text-center text-white-50 py-4 small">
                    <span class="spinner-border spinner-border-sm me-2" />Loading…
                </div>
                <div v-else-if="loadError" class="alert alert-danger m-3 py-2 small">{{ loadError }}</div>
                <div v-else-if="!displayedIncidents.length" class="text-center text-white-50 py-4 small">No incidents</div>
                <div
                    v-for="inc in displayedIncidents" :key="inc.uid"
                    class="d-flex align-items-start px-3 py-2 border-bottom incident-row"
                    role="button"
                    @click="openDetail(inc.uid)"
                >
                    <div class="flex-grow-1 overflow-hidden">
                        <div class="d-flex align-items-center gap-2">
                            <span class="fw-semibold small text-white text-truncate">{{ inc.incidentName }}</span>
                            <span class="badge small" :class="statusBadge(inc.status)">{{ inc.status }}</span>
                        </div>
                        <div class="small text-white-50 text-truncate">{{ formatAddress(inc.location) }}</div>
                        <div class="d-flex gap-3 small text-white-50 mt-1">
                            <span>{{ inc.incidentType?.name ?? '—' }}</span>
                            <span v-if="inc.dispatcher">{{ inc.dispatcher }}</span>
                        </div>
                    </div>
                    <div class="text-end ms-2 flex-shrink-0">
                        <div class="small text-white-50">{{ shortTime(inc.incidentTime) }}</div>
                        <div class="small text-warning">{{ inc.vehiclesResponding?.length ?? 0 }}🚗 {{ inc.personnelResponding?.length ?? 0 }}👤</div>
                    </div>
                </div>
            </div>
        </template>

        <!-- ── Incident Detail ────────────────────────────────── -->
        <template v-else-if="view === 'detail' && detailIncident">
            <div class="d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2">
                <button class="btn btn-sm btn-outline-secondary" @click="view = 'list'">← Back</button>
                <span class="fw-semibold text-truncate flex-grow-1">{{ detailIncident.incidentName }}</span>
                <span class="badge" :class="statusBadge(detailIncident.status)">{{ detailIncident.status }}</span>
            </div>

            <div class="flex-grow-1 overflow-auto p-3 d-flex flex-column gap-3">

                <!-- Core info -->
                <div class="card bg-dark border-secondary">
                    <div class="card-body py-2 px-3 d-flex flex-column gap-1 small">
                        <div class="row g-1">
                            <div class="col-4 text-white-50">Type</div>
                            <div class="col-8 text-white">{{ detailIncident.incidentType?.name }}</div>
                            <div class="col-4 text-white-50">Time</div>
                            <div class="col-8 text-white">{{ formatTime(detailIncident.incidentTime) }}</div>
                            <div class="col-4 text-white-50">Location</div>
                            <div class="col-8 text-white">{{ formatAddress(detailIncident.location) }}</div>
                            <template v-if="detailIncident.location?.coords">
                                <div class="col-4 text-white-50">Coords</div>
                                <div class="col-8 font-monospace text-white-50" style="font-size:11px">
                                    {{ detailIncident.location.coords.latitudeDeg.toFixed(6) }},
                                    {{ detailIncident.location.coords.longitudeDeg.toFixed(6) }}
                                </div>
                            </template>
                            <div class="col-4 text-white-50">Dispatcher</div>
                            <div class="col-8 text-white">{{ detailIncident.dispatcher || '—' }}</div>
                            <template v-if="detailIncident.details">
                                <div class="col-4 text-white-50">Details</div>
                                <div class="col-8 text-white" style="white-space:pre-wrap">{{ detailIncident.details }}</div>
                            </template>
                            <template v-if="detailIncident.firstResponderArrivalTime">
                                <div class="col-4 text-white-50">Arrival</div>
                                <div class="col-8 text-white">{{ formatTime(detailIncident.firstResponderArrivalTime) }}</div>
                            </template>
                        </div>
                    </div>
                </div>

                <!-- Caller info -->
                <template v-if="detailIncident.callerInfo">
                    <div class="small text-white-50 fw-semibold text-uppercase">Caller</div>
                    <div class="card bg-dark border-secondary">
                        <div class="card-body py-2 px-3 d-flex flex-column gap-1 small">
                            <div class="row g-1">
                                <div class="col-4 text-white-50">Name</div>
                                <div class="col-8 text-white">{{ detailIncident.callerInfo.name || '—' }}</div>
                                <div class="col-4 text-white-50">Phone</div>
                                <div class="col-8 text-white">{{ detailIncident.callerInfo.phoneNumber || '—' }}</div>
                                <div class="col-4 text-white-50">Type</div>
                                <div class="col-8 text-white">{{ detailIncident.callerInfo.callerInfoType || '—' }}</div>
                            </div>
                        </div>
                    </div>
                </template>

                <!-- Responding vehicles -->
                <div class="small text-white-50 fw-semibold text-uppercase d-flex align-items-center">
                    <span class="me-auto">Responding Vehicles ({{ detailIncident.vehiclesResponding?.length ?? 0 }})</span>
                    <button class="btn btn-sm btn-outline-warning py-0 px-2" @click="view = 'responders'">Manage</button>
                </div>
                <div v-if="detailIncident.vehiclesResponding?.length" class="card bg-dark border-secondary">
                    <div class="card-body py-1 px-3">
                        <div v-for="vr in detailIncident.vehiclesResponding" :key="vr.vehicle.vehicleUid"
                            class="d-flex align-items-center py-1 border-bottom border-secondary small gap-2">
                            <span class="text-white">{{ vr.vehicle.vehicleUid }}</span>
                            <span v-if="vr.responseStatus" class="badge bg-secondary">{{ vr.responseStatus }}</span>
                            <span v-if="vr.eta" class="text-white-50 ms-auto">ETA {{ vr.eta }}</span>
                        </div>
                    </div>
                </div>
                <div v-else class="text-white-50 small">No vehicles assigned</div>

                <!-- Responding personnel -->
                <div class="small text-white-50 fw-semibold text-uppercase">Personnel ({{ detailIncident.personnelResponding?.length ?? 0 }})</div>
                <div v-if="detailIncident.personnelResponding?.length" class="card bg-dark border-secondary">
                    <div class="card-body py-1 px-3">
                        <div v-for="pr in detailIncident.personnelResponding" :key="pr.personUid"
                            class="d-flex align-items-center py-1 border-bottom border-secondary small gap-2">
                            <span class="text-white">{{ pr.callsign }}</span>
                        </div>
                    </div>
                </div>
                <div v-else class="text-white-50 small">No personnel assigned</div>

                <!-- Notes -->
                <div class="small text-white-50 fw-semibold text-uppercase">Notes</div>
                <div v-if="detailIncident.notes?.length" class="d-flex flex-column gap-1">
                    <div v-for="note in detailIncident.notes" :key="note.uid"
                        class="card bg-dark border-secondary">
                        <div class="card-body py-1 px-3 small">
                            <div class="d-flex align-items-center gap-2 text-white-50 mb-1">
                                <span class="fw-semibold text-white">{{ note.creator }}</span>
                                <span>{{ formatTime(note.timestamp) }}</span>
                                <button class="btn btn-sm btn-link text-danger py-0 px-1 ms-auto text-decoration-none"
                                    @click="deleteNote(note.uid)">✕</button>
                            </div>
                            <div class="text-white" style="white-space:pre-wrap">{{ note.info }}</div>
                        </div>
                    </div>
                </div>
                <div class="input-group">
                    <input v-model="newNote" type="text" class="form-control form-control-sm bg-dark text-white border-secondary"
                        placeholder="Add a note…" @keyup.enter="addNote" />
                    <button class="btn btn-sm btn-secondary" :disabled="!newNote.trim()" @click="addNote">Add</button>
                </div>

                <!-- Actions -->
                <div v-if="detailError" class="alert alert-danger py-2 small">{{ detailError }}</div>
                <div class="d-flex gap-2 flex-wrap">
                    <button class="btn btn-sm btn-outline-warning" @click="openEdit">Edit</button>
                    <button v-if="isActive(detailIncident.status)"
                        class="btn btn-sm btn-outline-secondary" :disabled="saving" @click="closeIncident">
                        <span v-if="saving" class="spinner-border spinner-border-sm me-1" />Close Incident
                    </button>
                    <button class="btn btn-sm btn-outline-danger ms-auto" :disabled="saving" @click="confirmDelete">Delete</button>
                </div>

            </div>
        </template>

        <!-- ── Responder Manager ───────────────────────────────── -->
        <template v-else-if="view === 'responders' && detailIncident">
            <div class="d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2">
                <button class="btn btn-sm btn-outline-secondary" @click="view = 'detail'">← Back</button>
                <span class="fw-semibold">Assign Responders</span>
            </div>
            <div class="flex-grow-1 overflow-auto p-3 d-flex flex-column gap-3">

                <!-- Vehicles -->
                <div class="small text-white-50 fw-semibold text-uppercase">Vehicles</div>
                <div v-for="veh in vehicles" :key="veh.uid" class="d-flex align-items-center gap-2 py-1 border-bottom border-secondary small">
                    <input type="checkbox"
                        :checked="isVehicleAssigned(veh.uid)"
                        @change="toggleVehicle(veh.uid)"
                        class="form-check-input mt-0" />
                    <span class="text-white">{{ veh.callsign }}</span>
                    <span v-if="veh.vehicleType" class="text-white-50">{{ veh.vehicleType.name }}</span>
                    <span v-if="veh.incidentsRequestingThisVehicle?.length" class="ms-auto badge bg-warning text-dark small">{{ veh.incidentsRequestingThisVehicle.length }} inc</span>
                </div>
                <div v-if="!vehicles.length" class="text-white-50 small">No vehicles registered</div>

                <!-- Personnel -->
                <div class="small text-white-50 fw-semibold text-uppercase">Personnel</div>
                <div v-for="person in personnel" :key="person.uid" class="d-flex align-items-center gap-2 py-1 border-bottom border-secondary small">
                    <input type="checkbox"
                        :checked="isPersonnelAssigned(person.uid)"
                        @change="togglePersonnel(person.uid, person.callsign)"
                        class="form-check-input mt-0" />
                    <span class="text-white">{{ person.callsign }}</span>
                    <span v-if="person.roles?.length" class="text-white-50">{{ person.roles.map(r => r.name).join(', ') }}</span>
                </div>
                <div v-if="!personnel.length" class="text-white-50 small">No personnel registered</div>

                <div v-if="detailError" class="alert alert-danger py-2 small">{{ detailError }}</div>
                <button class="btn btn-sm btn-warning" :disabled="saving" @click="saveResponders">
                    <span v-if="saving" class="spinner-border spinner-border-sm me-1" />Save Assignments
                </button>
            </div>
        </template>

        <!-- ── Incident Form ──────────────────────────────────── -->
        <template v-else-if="view === 'form'">
            <div class="d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2">
                <button class="btn btn-sm btn-outline-secondary" @click="cancelForm">← Back</button>
                <span class="fw-semibold">{{ editUid ? 'Edit Incident' : 'New Incident' }}</span>
            </div>
            <div class="flex-grow-1 overflow-auto p-3">
                <IncidentForm
                    :uid="editUid"
                    :incident-types="incidentTypes"
                    @saved="onFormSaved"
                    @cancel="cancelForm"
                />
            </div>
        </template>

    </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue';
import IncidentForm from './IncidentForm.vue';
import {
    getIncidentMetadata, getIncident,
    updateIncident, deleteIncident,
} from '../lib/takcad-client.ts';
import type { IncidentMetadata, IncidentRef, VehicleRef, PersonRef, IncidentTypeRef, PersonCallsign, VehicleResponseStatus } from '../lib/takcad-types.ts';
import { isActive, formatAddress, formatTime, STATUS_CANCELLED } from '../lib/takcad-types.ts';

const props = defineProps<{
    incidentTypes: IncidentTypeRef[];
    vehicles:      VehicleRef[];
    personnel:     PersonRef[];
}>();

const emit = defineEmits<{
    (e: 'active-count', n: number): void;
    (e: 'status',       s: string): void;
}>();

type ViewName = 'list' | 'detail' | 'form' | 'responders';
type ListTab  = 'active' | 'cancelled';

const SORT_COLS = [
    { key: 'time',       label: 'Time'       },
    { key: 'address',    label: 'Address'    },
    { key: 'type',       label: 'Type'       },
    { key: 'dispatcher', label: 'Dispatcher' },
] as const;
type SortCol = typeof SORT_COLS[number]['key'];

const LIST_TABS = [
    { key: 'active',    label: 'Active'    },
    { key: 'cancelled', label: 'Cancelled' },
] as const;

const view           = ref<ViewName>('list');
const listTab        = ref<ListTab>('active');
const incidents      = ref<IncidentMetadata[]>([]);
const detailIncident = ref<IncidentRef | null>(null);
const loading        = ref(false);
const loadError      = ref('');
const detailError    = ref('');
const saving         = ref(false);
const editUid        = ref<string | undefined>(undefined);
const newNote        = ref('');
const lastRefreshed  = ref('');
const sortCol        = ref<SortCol>('time');
const sortAsc        = ref(false);

// responders working copy (modified while in responders view, saved on Save)
const pendingVehicleUids    = ref<string[]>([]);
const pendingPersonnelItems = ref<PersonCallsign[]>([]);

const activeIncidents    = computed(() => incidents.value.filter(i => isActive(i.status)));
const cancelledIncidents = computed(() => incidents.value.filter(i => !isActive(i.status)));

const displayedIncidents = computed(() => {
    const src = listTab.value === 'active' ? activeIncidents.value : cancelledIncidents.value;
    return [...src].sort((a, b) => {
        let av = '', bv = '';
        if (sortCol.value === 'time')       { av = a.incidentTime; bv = b.incidentTime; }
        if (sortCol.value === 'address')    { av = formatAddress(a.location); bv = formatAddress(b.location); }
        if (sortCol.value === 'type')       { av = a.incidentType?.name ?? ''; bv = b.incidentType?.name ?? ''; }
        if (sortCol.value === 'dispatcher') { av = a.dispatcher ?? ''; bv = b.dispatcher ?? ''; }
        return sortAsc.value ? av.localeCompare(bv) : bv.localeCompare(av);
    });
});

watch(activeIncidents, n => emit('active-count', n.length), { immediate: true });

function toggleSort(col: SortCol) {
    if (sortCol.value === col) sortAsc.value = !sortAsc.value;
    else { sortCol.value = col; sortAsc.value = col !== 'time'; }
}

function statusBadge(status: string) {
    if (status === 'ACTIVE')     return 'bg-success';
    if (status === 'CANCELLED')  return 'bg-secondary';
    return 'bg-warning text-dark';
}

function shortTime(iso: string): string {
    try { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
    catch { return iso; }
}

async function loadList() {
    loading.value = true;
    loadError.value = '';
    try {
        incidents.value = await getIncidentMetadata();
        lastRefreshed.value = new Date().toLocaleTimeString();
        emit('status', '');
    } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        loadError.value = msg;
        emit('status', 'Error');
    } finally {
        loading.value = false;
    }
}

async function openDetail(uid: string) {
    detailError.value = '';
    view.value = 'detail';
    try {
        detailIncident.value = await getIncident(uid);
    } catch (e) {
        detailError.value = e instanceof Error ? e.message : String(e);
    }
}

function openCreate() {
    editUid.value = undefined;
    view.value = 'form';
}

function openEdit() {
    if (!detailIncident.value) return;
    editUid.value = detailIncident.value.uid;
    view.value = 'form';
}

function cancelForm() {
    view.value = detailIncident.value ? 'detail' : 'list';
}

async function onFormSaved(uid: string) {
    await openDetail(uid);
    await loadList();
}

async function closeIncident() {
    if (!detailIncident.value) return;
    saving.value = true; detailError.value = '';
    try {
        const updated = { ...detailIncident.value, status: STATUS_CANCELLED };
        await updateIncident(updated);
        detailIncident.value = updated;
        await loadList();
    } catch (e) {
        detailError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

async function confirmDelete() {
    if (!detailIncident.value) return;
    if (!confirm(`Delete incident "${detailIncident.value.incidentName}"?`)) return;
    saving.value = true; detailError.value = '';
    try {
        await deleteIncident(detailIncident.value.uid);
        view.value = 'list';
        detailIncident.value = null;
        await loadList();
    } catch (e) {
        detailError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

async function addNote() {
    if (!detailIncident.value || !newNote.value.trim()) return;
    const note = {
        uid:         crypto.randomUUID(),
        info:        newNote.value.trim(),
        creator:     'Dispatcher',
        incidentUid: detailIncident.value.uid,
        timestamp:   new Date().toISOString(),
    };
    const updated = { ...detailIncident.value, notes: [...(detailIncident.value.notes ?? []), note] };
    saving.value = true; detailError.value = '';
    try {
        await updateIncident(updated);
        detailIncident.value = updated;
        newNote.value = '';
    } catch (e) {
        detailError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

async function deleteNote(noteUid: string) {
    if (!detailIncident.value) return;
    const updated = { ...detailIncident.value, notes: detailIncident.value.notes.filter(n => n.uid !== noteUid) };
    saving.value = true; detailError.value = '';
    try {
        await updateIncident(updated);
        detailIncident.value = updated;
    } catch (e) {
        detailError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

// Responder management
watch(view, (v) => {
    if (v === 'responders' && detailIncident.value) {
        pendingVehicleUids.value    = [...(detailIncident.value.vehicleUidsRequested ?? [])];
        pendingPersonnelItems.value = [...(detailIncident.value.personnelResponding  ?? [])];
    }
});

function isVehicleAssigned(uid: string)    { return pendingVehicleUids.value.includes(uid); }
function isPersonnelAssigned(uid: string)  { return pendingPersonnelItems.value.some(p => p.personUid === uid); }

function toggleVehicle(uid: string) {
    if (isVehicleAssigned(uid)) pendingVehicleUids.value = pendingVehicleUids.value.filter(u => u !== uid);
    else pendingVehicleUids.value = [...pendingVehicleUids.value, uid];
}

function togglePersonnel(uid: string, callsign: string) {
    if (isPersonnelAssigned(uid)) pendingPersonnelItems.value = pendingPersonnelItems.value.filter(p => p.personUid !== uid);
    else pendingPersonnelItems.value = [...pendingPersonnelItems.value, { personUid: uid, callsign }];
}

async function saveResponders() {
    if (!detailIncident.value) return;
    saving.value = true; detailError.value = '';

    // Build vehiclesResponding from the checked vehicle UIDs, preserving existing status/eta
    const existingByUid = new Map<string, VehicleResponseStatus>(
        (detailIncident.value.vehiclesResponding ?? []).map(vr => [vr.vehicle.vehicleUid, vr])
    );
    const vehiclesResponding: VehicleResponseStatus[] = pendingVehicleUids.value.map(uid => (
        existingByUid.get(uid) ?? { vehicle: { vehicleUid: uid, assigned: true }, eta: null, responseStatus: null }
    ));

    const updated: IncidentRef = {
        ...detailIncident.value,
        vehicleUidsRequested: pendingVehicleUids.value,
        vehiclesResponding,
        personnelResponding: pendingPersonnelItems.value,
    };

    try {
        await updateIncident(updated);
        detailIncident.value = updated;
        view.value = 'detail';
    } catch (e) {
        detailError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

let pollTimer: ReturnType<typeof setInterval>;

onMounted(() => {
    loadList();
    pollTimer = setInterval(loadList, 30_000);
});

onUnmounted(() => clearInterval(pollTimer));
</script>

<style scoped>
.incident-row:hover { background: rgba(255,255,255,.05); cursor: pointer; }
</style>
