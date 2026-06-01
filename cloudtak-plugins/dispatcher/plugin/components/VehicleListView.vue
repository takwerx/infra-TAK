<template>
    <div class='d-flex flex-column h-100 overflow-hidden'>
        <!-- ── Standalone mode: connected contacts ─────────────────────────── -->
        <template v-if='serverMode === "standalone"'>
            <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0'>
                <span class='text-muted small me-auto'>{{ contacts.length }} connected units</span>
                <button
                    class='btn btn-sm btn-outline-secondary'
                    :disabled='contactsLoading'
                    @click='loadContacts'
                >
                    <span
                        v-if='contactsLoading'
                        class='spinner-border spinner-border-sm'
                    />
                    <span v-else>↻</span>
                </button>
            </div>
            <div class='flex-grow-1 overflow-auto'>
                <div
                    v-if='contactsError'
                    class='alert alert-danger m-3 py-2 small'
                >
                    {{ contactsError }}
                </div>
                <div
                    v-else-if='!contacts.length && !contactsLoading'
                    class='text-center text-muted py-4 small'
                >
                    No connected TAK users
                </div>
                <div
                    v-for='c in contacts'
                    :key='c.uid'
                    class='d-flex align-items-center px-3 py-2 border-bottom small gap-2'
                >
                    <div class='flex-grow-1'>
                        <div class='fw-semibold'>
                            {{ c.callsign }}
                        </div>
                        <div
                            v-if='c.lastSeen'
                            class='text-muted'
                            style='font-size:11px'
                        >
                            Last seen {{ c.lastSeen }}
                        </div>
                    </div>
                    <span
                        v-if='sendStatus[c.uid]'
                        class='badge'
                        :class='sendStatus[c.uid] === "Sent" ? "bg-success text-white" : "bg-danger text-white"'
                    >{{ sendStatus[c.uid] }}</span>
                    <button
                        class='btn btn-sm btn-outline-warning py-0 px-2'
                        :disabled='sendingTo === c.uid'
                        @click='assignContact(c)'
                    >
                        <span
                            v-if='sendingTo === c.uid'
                            class='spinner-border spinner-border-sm'
                        />
                        <span v-else>Assign</span>
                    </button>
                </div>
            </div>
        </template>

        <!-- ── TAK-CAD mode: vehicle registry ─────────────────────────────── -->
        <!-- ── Vehicle List ──────────────────────────────────── -->
        <template v-else-if='serverMode === "takcad" && view === "list"'>
            <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0'>
                <span class='text-muted small me-auto'>{{ vehicles.length }} vehicles</span>
                <button
                    class='btn btn-sm btn-warning'
                    @click='openCreate'
                >
                    + Add Vehicle
                </button>
            </div>
            <div class='flex-grow-1 overflow-auto'>
                <div
                    v-if='loading'
                    class='text-center text-muted py-4 small'
                >
                    <span class='spinner-border spinner-border-sm me-2' />Loading…
                </div>
                <div
                    v-else-if='loadError'
                    class='alert alert-danger m-3 py-2 small'
                >
                    {{ loadError }}
                </div>
                <div
                    v-else-if='!vehicles.length'
                    class='text-center text-muted py-4 small'
                >
                    No vehicles registered
                </div>
                <div
                    v-for='veh in vehicles'
                    :key='veh.uid'
                    class='d-flex align-items-center px-3 py-2 border-bottom vehicle-row'
                    role='button'
                    @click='openDetail(veh)'
                >
                    <div class='flex-grow-1'>
                        <div class='d-flex align-items-center gap-2'>
                            <span class='fw-semibold small'>{{ veh.callsign }}</span>
                            <span
                                v-if='veh.status'
                                class='badge small'
                                :class='statusBadge(veh.status)'
                            >{{ statusLabel(veh.status) }}</span>
                        </div>
                        <div class='small text-muted'>
                            {{ veh.vehicleType?.name ?? 'Untyped' }}
                            <span
                                v-if='veh.vehiclePersonnel?.length'
                                class='ms-2'
                            >· {{ veh.vehiclePersonnel.map(p => p.callsign).join(', ') }}</span>
                        </div>
                    </div>
                    <div
                        v-if='veh.incidentsRequestingThisVehicle?.length'
                        class='badge bg-warning text-dark ms-2'
                    >
                        {{ veh.incidentsRequestingThisVehicle.length }} inc
                    </div>
                </div>
            </div>
        </template>

        <!-- ── Vehicle Detail / Edit ─────────────────────────── -->
        <template v-else-if='view === "detail" && selected'>
            <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                <button
                    class='btn btn-sm btn-outline-secondary'
                    @click='view = "list"'
                >
                    ← Back
                </button>
                <span class='fw-semibold flex-grow-1'>{{ selected.callsign }}</span>
                <span
                    v-if='selected.status && !editing'
                    class='badge'
                    :class='statusBadge(selected.status)'
                >{{ statusLabel(selected.status) }}</span>
            </div>
            <div class='flex-grow-1 overflow-auto p-3 d-flex flex-column gap-3'>
                <div v-if='!editing'>
                    <div class='card border'>
                        <div class='card-body py-2 px-3 small d-flex flex-column gap-1'>
                            <div class='row g-1'>
                                <div class='col-4 text-muted'>
                                    Callsign
                                </div>
                                <div class='col-8'>
                                    {{ selected.callsign || '—' }}
                                </div>
                                <div class='col-4 text-muted'>
                                    Type
                                </div>
                                <div class='col-8'>
                                    {{ selected.vehicleType?.name ?? '—' }}
                                </div>
                                <div class='col-4 text-muted'>
                                    Status
                                </div>
                                <div class='col-8'>
                                    {{ statusLabel(selected.status ?? '') }}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div
                        v-if='selected.vehiclePersonnel?.length'
                        class='mt-3'
                    >
                        <div class='small text-muted fw-semibold text-uppercase mb-1'>
                            Personnel
                        </div>
                        <div class='card border'>
                            <div class='card-body py-1 px-3'>
                                <div
                                    v-for='p in selected.vehiclePersonnel'
                                    :key='p.personUid'
                                    class='py-1 border-bottom border small'
                                >
                                    {{ p.callsign }}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div
                        v-if='detailError'
                        class='alert alert-danger py-2 small mt-3'
                    >
                        {{ detailError }}
                    </div>
                    <div class='d-flex gap-2 mt-3'>
                        <button
                            class='btn btn-sm btn-outline-warning'
                            @click='editing = true'
                        >
                            Edit
                        </button>
                        <button
                            class='btn btn-sm btn-outline-danger ms-auto'
                            :disabled='saving'
                            @click='confirmDelete'
                        >
                            Delete
                        </button>
                    </div>
                </div>

                <!-- Inline edit form -->
                <form
                    v-else
                    class='d-flex flex-column gap-2'
                    @submit.prevent='saveEdit'
                >
                    <div>
                        <label class='form-label small text-muted mb-1'>Callsign <span class='text-danger'>*</span></label>
                        <input
                            v-model='editForm.callsign'
                            required
                            type='text'
                            class='form-control form-control-sm border'
                        >
                    </div>
                    <div>
                        <label class='form-label small text-muted mb-1'>Vehicle Type</label>
                        <select
                            v-model='editForm.vehicleTypeUid'
                            class='form-select form-select-sm border'
                        >
                            <option value=''>
                                — None —
                            </option>
                            <option
                                v-for='t in vehicleTypes'
                                :key='t.uid'
                                :value='t.uid'
                            >
                                {{ t.name }}
                            </option>
                        </select>
                    </div>
                    <div>
                        <label class='form-label small text-muted mb-1'>Status</label>
                        <select
                            v-model='editForm.status'
                            class='form-select form-select-sm border'
                        >
                            <option
                                v-for='s in VEHICLE_STATUSES'
                                :key='s.value'
                                :value='s.value'
                            >
                                {{ s.label }}
                            </option>
                        </select>
                    </div>
                    <div
                        v-if='detailError'
                        class='alert alert-danger py-2 small'
                    >
                        {{ detailError }}
                    </div>
                    <div class='d-flex gap-2'>
                        <button
                            type='submit'
                            class='btn btn-sm btn-warning'
                            :disabled='saving'
                        >
                            <span
                                v-if='saving'
                                class='spinner-border spinner-border-sm me-1'
                            />Save
                        </button>
                        <button
                            type='button'
                            class='btn btn-sm btn-outline-secondary'
                            @click='editing = false'
                        >
                            Cancel
                        </button>
                    </div>
                </form>
            </div>
        </template>

        <!-- ── Add Vehicle ────────────────────────────────────── -->
        <template v-else-if='view === "create"'>
            <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                <button
                    class='btn btn-sm btn-outline-secondary'
                    @click='view = "list"'
                >
                    ← Back
                </button>
                <span class='fw-semibold'>Add Vehicle</span>
            </div>
            <div class='p-3'>
                <form
                    class='d-flex flex-column gap-3'
                    @submit.prevent='saveCreate'
                >
                    <div>
                        <label class='form-label small text-muted mb-1'>Callsign <span class='text-danger'>*</span></label>
                        <input
                            v-model='createForm.callsign'
                            required
                            type='text'
                            class='form-control form-control-sm border'
                            placeholder='e.g. ENG-1'
                        >
                    </div>
                    <div>
                        <label class='form-label small text-muted mb-1'>Vehicle Type</label>
                        <select
                            v-model='createForm.vehicleTypeUid'
                            class='form-select form-select-sm border'
                        >
                            <option value=''>
                                — None —
                            </option>
                            <option
                                v-for='t in vehicleTypes'
                                :key='t.uid'
                                :value='t.uid'
                            >
                                {{ t.name }}
                            </option>
                        </select>
                    </div>
                    <div>
                        <label class='form-label small text-muted mb-1'>Status</label>
                        <select
                            v-model='createForm.status'
                            class='form-select form-select-sm border'
                        >
                            <option
                                v-for='s in VEHICLE_STATUSES'
                                :key='s.value'
                                :value='s.value'
                            >
                                {{ s.label }}
                            </option>
                        </select>
                    </div>
                    <div
                        v-if='createError'
                        class='alert alert-danger py-2 small'
                    >
                        {{ createError }}
                    </div>
                    <div class='d-flex gap-2'>
                        <button
                            type='submit'
                            class='btn btn-sm btn-warning flex-grow-1'
                            :disabled='saving'
                        >
                            <span
                                v-if='saving'
                                class='spinner-border spinner-border-sm me-1'
                            />Add Vehicle
                        </button>
                        <button
                            type='button'
                            class='btn btn-sm btn-outline-secondary'
                            @click='view = "list"'
                        >
                            Cancel
                        </button>
                    </div>
                </form>
            </div>
        </template>
    </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted, watch } from 'vue';
import { getVehicles, insertVehicle, updateVehicle, deleteVehicle } from '../lib/takcad-client.ts';
import type { VehicleRef, VehicleType } from '../lib/takcad-types.ts';
import { getContacts, sendAssignmentMessage } from '../lib/contacts-client.ts';
import type { TakContact } from '../lib/contacts-client.ts';

const props = defineProps<{
    serverMode:   'detecting' | 'takcad' | 'standalone';
    vehicleTypes: VehicleType[];
}>();

// Wire values from Vehicle$StatusEnum; labels match what ATAK responders see.
const VEHICLE_STATUSES = [
    { value: 'AVAILABLE',       label: 'Available'   },
    { value: 'AT_STATION',      label: 'At Station'  },
    { value: 'IN_ROUTE',        label: 'Responding'  },
    { value: 'ON_SCENE',        label: 'Arrived'     },
    { value: 'OUT_OF_SERVICE',  label: 'Unavailable' },
    { value: 'UNKNOWN',         label: 'Unknown'     },
] as const;

type VehicleStatus = typeof VEHICLE_STATUSES[number]['value'];

function statusLabel(val: string): string {
    return VEHICLE_STATUSES.find(s => s.value === val)?.label ?? val;
}

function statusBadge(val: string): string {
    if (val === 'AVAILABLE')      return 'bg-success text-white';
    if (val === 'AT_STATION')     return 'bg-secondary text-white';
    if (val === 'IN_ROUTE')       return 'bg-primary text-white';
    if (val === 'ON_SCENE')       return 'bg-warning text-dark';
    if (val === 'OUT_OF_SERVICE') return 'bg-danger text-white';
    return 'bg-secondary text-white';
}

type ViewName = 'list' | 'detail' | 'create';

const view        = ref<ViewName>('list');
const vehicles    = ref<VehicleRef[]>([]);
const selected    = ref<VehicleRef | null>(null);
const loading     = ref(false);
const loadError   = ref('');
const detailError = ref('');
const createError = ref('');
const saving      = ref(false);
const editing     = ref(false);

const editForm   = reactive({ callsign: '', vehicleTypeUid: '', status: 'AVAILABLE' as VehicleStatus });
const createForm = reactive({ callsign: '', vehicleTypeUid: '', status: 'AVAILABLE' as VehicleStatus });

async function loadList() {
    loading.value = true; loadError.value = '';
    try { vehicles.value = await getVehicles(); }
    catch (e) { loadError.value = e instanceof Error ? e.message : String(e); }
    finally { loading.value = false; }
}

function openDetail(veh: VehicleRef) {
    selected.value    = veh;
    editing.value     = false;
    detailError.value = '';
    editForm.callsign      = veh.callsign;
    editForm.vehicleTypeUid = veh.vehicleType?.uid ?? '';
    editForm.status        = (veh.status as VehicleStatus) ?? 'AVAILABLE';
    view.value = 'detail';
}

function openCreate() {
    createForm.callsign      = '';
    createForm.vehicleTypeUid = props.vehicleTypes[0]?.uid ?? '';
    createForm.status        = 'AVAILABLE';
    createError.value        = '';
    view.value = 'create';
}

async function saveEdit() {
    if (!selected.value) return;
    saving.value = true; detailError.value = '';
    const vt = props.vehicleTypes.find(t => t.uid === editForm.vehicleTypeUid) ?? null;
    const updated: VehicleRef = {
        ...selected.value,
        callsign:    editForm.callsign,
        name:        editForm.callsign,
        vehicleType: vt,
        status:      editForm.status,
    };
    try {
        const r = await updateVehicle(updated);
        if (!r.success) throw new Error(r.errors?.join(', ') || 'Update failed');
        selected.value = updated;
        vehicles.value = vehicles.value.map(v => v.uid === updated.uid ? updated : v);
        editing.value  = false;
    } catch (e) {
        detailError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

async function saveCreate() {
    saving.value = true; createError.value = '';
    const vt = props.vehicleTypes.find(t => t.uid === createForm.vehicleTypeUid) ?? null;
    // Location starts empty — ATAK GPS populates it when the responder assigns themselves.
    const payload: VehicleRef = {
        uid:                            crypto.randomUUID(),
        callsign:                       createForm.callsign,
        name:                           createForm.callsign,
        status:                         createForm.status,
        location:                       { address: { streetName: '', city: '', state: '', zipCode: '', country: '' }, coords: null },
        vehicleType:                    vt,
        vehiclePersonnel:               [],
        incidentsRequestingThisVehicle: [],
    };
    try {
        const r = await insertVehicle(payload);
        if (!r.success) throw new Error(r.errors?.join(', ') || 'Insert failed');
        vehicles.value = [...vehicles.value, payload];
        view.value = 'list';
    } catch (e) {
        createError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

async function confirmDelete() {
    if (!selected.value) return;
    if (!confirm(`Delete vehicle "${selected.value.callsign}"?`)) return;
    saving.value = true; detailError.value = '';
    try {
        await deleteVehicle(selected.value.uid);
        vehicles.value = vehicles.value.filter(v => v.uid !== selected.value!.uid);
        view.value     = 'list';
        selected.value = null;
    } catch (e) {
        detailError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

// ── Standalone mode: contacts list ───────────────────────────────────────────
const contacts        = ref<TakContact[]>([]);
const contactsLoading = ref(false);
const contactsError   = ref('');
const sendingTo       = ref<string | null>(null);
const sendStatus      = ref<Record<string, string>>({});

async function loadContacts() {
    contactsLoading.value = true; contactsError.value = '';
    try { contacts.value = await getContacts(); }
    catch (e) { contactsError.value = e instanceof Error ? e.message : String(e); }
    finally { contactsLoading.value = false; }
}

async function assignContact(contact: TakContact) {
    sendingTo.value = contact.uid;
    try {
        await sendAssignmentMessage(contact.uid, { name: 'Active Incident', address: '' });
        sendStatus.value = { ...sendStatus.value, [contact.uid]: 'Sent' };
    } catch (e) {
        sendStatus.value = { ...sendStatus.value, [contact.uid]: 'Failed' };
        console.warn('[dispatcher] assignment msg failed', e);
    } finally {
        sendingTo.value = null;
    }
}

let pollTimer: ReturnType<typeof setInterval>;

onMounted(() => {
    if (props.serverMode === 'takcad') {
        loadList();
        pollTimer = setInterval(loadList, 15_000);
    } else if (props.serverMode === 'standalone') {
        loadContacts();
        pollTimer = setInterval(loadContacts, 15_000);
    }
});

watch(() => props.serverMode, (mode) => {
    clearInterval(pollTimer);
    if (mode === 'takcad') {
        loadList();
        pollTimer = setInterval(loadList, 15_000);
    } else if (mode === 'standalone') {
        loadContacts();
        pollTimer = setInterval(loadContacts, 15_000);
    }
});

onUnmounted(() => clearInterval(pollTimer));
</script>

<style scoped>
.vehicle-row:hover { background: rgba(255,255,255,.05); cursor: pointer; }
</style>
