<template>
    <div class='d-flex flex-column h-100 overflow-hidden'>

        <!-- ── Vehicle List ──────────────────────────────────── -->
        <template v-if='view === "list"'>
            <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0'>
                <span class='text-white-50 small me-auto'>{{ vehicles.length }} vehicles</span>
                <button class='btn btn-sm btn-warning' @click='openCreate'>+ Add Vehicle</button>
            </div>
            <div class='flex-grow-1 overflow-auto'>
                <div v-if='loading' class='text-center text-white-50 py-4 small'>
                    <span class='spinner-border spinner-border-sm me-2' />Loading…
                </div>
                <div v-else-if='loadError' class='alert alert-danger m-3 py-2 small'>{{ loadError }}</div>
                <div v-else-if='!vehicles.length' class='text-center text-white-50 py-4 small'>No vehicles registered</div>
                <div v-for='veh in vehicles' :key='veh.uid'
                    class='d-flex align-items-center px-3 py-2 border-bottom vehicle-row'
                    role='button'
                    @click='openDetail(veh)'>
                    <div class='flex-grow-1'>
                        <div class='fw-semibold small text-white'>{{ veh.callsign }}</div>
                        <div class='small text-white-50'>{{ veh.vehicleType?.name ?? 'Untyped' }}</div>
                    </div>
                    <div class='text-end small'>
                        <div v-if='veh.vehiclePersonnel?.length' class='text-white-50'>
                            {{ veh.vehiclePersonnel.map(p => p.callsign).join(', ') }}
                        </div>
                        <div v-if='veh.incidentsRequestingThisVehicle?.length' class='badge bg-warning text-dark'>
                            {{ veh.incidentsRequestingThisVehicle.length }} incident(s)
                        </div>
                    </div>
                </div>
            </div>
        </template>

        <!-- ── Vehicle Detail / Edit ─────────────────────────── -->
        <template v-else-if="view === 'detail' && selected">
            <div class="d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2">
                <button class="btn btn-sm btn-outline-secondary" @click="view = 'list'">← Back</button>
                <span class="fw-semibold flex-grow-1">{{ selected.callsign }}</span>
            </div>
            <div class="flex-grow-1 overflow-auto p-3 d-flex flex-column gap-3">

                <div v-if="!editing">
                    <div class="card bg-dark border-secondary">
                        <div class="card-body py-2 px-3 small d-flex flex-column gap-1">
                            <div class="row g-1">
                                <div class="col-4 text-white-50">Callsign</div>
                                <div class="col-8 text-white">{{ selected.callsign }}</div>
                                <div class="col-4 text-white-50">Type</div>
                                <div class="col-8 text-white">{{ selected.vehicleType?.name ?? '—' }}</div>
                            </div>
                        </div>
                    </div>

                    <div v-if="selected.vehiclePersonnel?.length" class="mt-3">
                        <div class="small text-white-50 fw-semibold text-uppercase mb-1">Personnel</div>
                        <div class="card bg-dark border-secondary">
                            <div class="card-body py-1 px-3">
                                <div v-for="p in selected.vehiclePersonnel" :key="p.personUid"
                                    class="py-1 border-bottom border-secondary small text-white">
                                    {{ p.callsign }}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div v-if="detailError" class="alert alert-danger py-2 small mt-3">{{ detailError }}</div>
                    <div class="d-flex gap-2 mt-3">
                        <button class="btn btn-sm btn-outline-warning" @click="editing = true">Edit</button>
                        <button class="btn btn-sm btn-outline-danger ms-auto" :disabled="saving" @click="confirmDelete">Delete</button>
                    </div>
                </div>

                <!-- Inline edit form -->
                <form v-else @submit.prevent="saveEdit" class="d-flex flex-column gap-2">
                    <div>
                        <label class="form-label small text-white-50 mb-1">Callsign <span class="text-danger">*</span></label>
                        <input v-model="editForm.callsign" required type="text"
                            class="form-control form-control-sm bg-dark text-white border-secondary" />
                    </div>
                    <div>
                        <label class="form-label small text-white-50 mb-1">Vehicle Type</label>
                        <select v-model="editForm.vehicleTypeUid"
                            class="form-select form-select-sm bg-dark text-white border-secondary">
                            <option value="">— None —</option>
                            <option v-for="t in vehicleTypes" :key="t.uid" :value="t.uid">{{ t.name }}</option>
                        </select>
                    </div>
                    <div v-if="detailError" class="alert alert-danger py-2 small">{{ detailError }}</div>
                    <div class="d-flex gap-2">
                        <button type="submit" class="btn btn-sm btn-warning" :disabled="saving">
                            <span v-if="saving" class="spinner-border spinner-border-sm me-1" />Save
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-secondary" @click="editing = false">Cancel</button>
                    </div>
                </form>

            </div>
        </template>

        <!-- ── Add Vehicle ────────────────────────────────────── -->
        <template v-else-if="view === 'create'">
            <div class="d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2">
                <button class="btn btn-sm btn-outline-secondary" @click="view = 'list'">← Back</button>
                <span class="fw-semibold">Add Vehicle</span>
            </div>
            <div class="p-3">
                <form @submit.prevent="saveCreate" class="d-flex flex-column gap-3">
                    <div>
                        <label class="form-label small text-white-50 mb-1">Callsign <span class="text-danger">*</span></label>
                        <input v-model="createForm.callsign" required type="text"
                            class="form-control form-control-sm bg-dark text-white border-secondary"
                            placeholder="e.g. ENG-1" />
                    </div>
                    <div>
                        <label class="form-label small text-white-50 mb-1">Vehicle Type</label>
                        <select v-model="createForm.vehicleTypeUid"
                            class="form-select form-select-sm bg-dark text-white border-secondary">
                            <option value="">— None —</option>
                            <option v-for="t in vehicleTypes" :key="t.uid" :value="t.uid">{{ t.name }}</option>
                        </select>
                    </div>
                    <div v-if="createError" class="alert alert-danger py-2 small">{{ createError }}</div>
                    <div class="d-flex gap-2">
                        <button type="submit" class="btn btn-sm btn-warning flex-grow-1" :disabled="saving">
                            <span v-if="saving" class="spinner-border spinner-border-sm me-1" />Add Vehicle
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-secondary" @click="view = 'list'">Cancel</button>
                    </div>
                </form>
            </div>
        </template>

    </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { getVehicles, insertVehicle, updateVehicle, deleteVehicle } from '../lib/takcad-client.ts';
import type { VehicleRef, VehicleType } from '../lib/takcad-types.ts';

const props = defineProps<{ vehicleTypes: VehicleType[] }>();

type ViewName = 'list' | 'detail' | 'create';

const view       = ref<ViewName>('list');
const vehicles   = ref<VehicleRef[]>([]);
const selected   = ref<VehicleRef | null>(null);
const loading    = ref(false);
const loadError  = ref('');
const detailError = ref('');
const createError = ref('');
const saving     = ref(false);
const editing    = ref(false);

const editForm   = reactive({ callsign: '', vehicleTypeUid: '' });
const createForm = reactive({ callsign: '', vehicleTypeUid: '' });

async function loadList() {
    loading.value = true; loadError.value = '';
    try { vehicles.value = await getVehicles(); }
    catch (e) { loadError.value = e instanceof Error ? e.message : String(e); }
    finally { loading.value = false; }
}

function openDetail(veh: VehicleRef) {
    selected.value = veh;
    editing.value  = false;
    detailError.value = '';
    editForm.callsign      = veh.callsign;
    editForm.vehicleTypeUid = veh.vehicleType?.uid ?? '';
    view.value = 'detail';
}

function openCreate() {
    createForm.callsign      = '';
    createForm.vehicleTypeUid = props.vehicleTypes[0]?.uid ?? '';
    createError.value = '';
    view.value = 'create';
}

async function saveEdit() {
    if (!selected.value) return;
    saving.value = true; detailError.value = '';
    const vt = props.vehicleTypes.find(t => t.uid === editForm.vehicleTypeUid) ?? null;
    const updated: VehicleRef = { ...selected.value, callsign: editForm.callsign, vehicleType: vt };
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
    const payload: VehicleRef = {
        uid:                            crypto.randomUUID(),
        callsign:                       createForm.callsign,
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
        view.value = 'list';
        selected.value = null;
    } catch (e) {
        detailError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

let pollTimer: ReturnType<typeof setInterval>;
onMounted(() => { loadList(); pollTimer = setInterval(loadList, 60_000); });
onUnmounted(() => clearInterval(pollTimer));
</script>

<style scoped>
.vehicle-row:hover { background: rgba(255,255,255,.05); cursor: pointer; }
</style>
