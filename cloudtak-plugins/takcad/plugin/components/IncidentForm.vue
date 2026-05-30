<template>
    <form
        class='d-flex flex-column gap-3'
        @submit.prevent='submit'
    >
        <!-- Name -->
        <div>
            <label class='form-label small text-white-50 mb-1'>Incident Name <span class='text-danger'>*</span></label>
            <input
                v-model='form.incidentName'
                type='text'
                required
                class='form-control form-control-sm bg-dark text-white border-secondary'
                placeholder='e.g. Structure Fire - 123 Main St'
            >
        </div>

        <!-- Type -->
        <div>
            <label class='form-label small text-white-50 mb-1'>Incident Type <span class='text-danger'>*</span></label>
            <select
                v-model='form.incidentTypeUid'
                required
                class='form-select form-select-sm bg-dark text-white border-secondary'
            >
                <option value=''>
                    — Select type —
                </option>
                <option
                    v-for='t in incidentTypes'
                    :key='t.uid'
                    :value='t.uid'
                >
                    {{ t.name }}
                </option>
            </select>
        </div>

        <!-- Date/Time -->
        <div>
            <label class='form-label small text-white-50 mb-1'>Incident Time <span class='text-danger'>*</span></label>
            <input
                v-model='form.incidentTimeLocal'
                type='datetime-local'
                required
                class='form-control form-control-sm bg-dark text-white border-secondary'
            >
        </div>

        <!-- Location -->
        <div>
            <label class='form-label small text-white-50 mb-1'>Location <span class='text-danger'>*</span></label>
            <div class='input-group mb-1'>
                <input
                    v-model='geoQuery'
                    type='text'
                    class='form-control form-control-sm bg-dark text-white border-secondary'
                    placeholder='Search address…'
                    @input='onGeoInput'
                >
                <button
                    type='button'
                    class='btn btn-sm btn-secondary'
                    :disabled='geocoding'
                    @click='doGeocode'
                >
                    <span
                        v-if='geocoding'
                        class='spinner-border spinner-border-sm'
                    />
                    <span v-else>Search</span>
                </button>
            </div>
            <div
                v-if='geoSuggestions.length'
                class='list-group mb-1'
            >
                <button
                    v-for='s in geoSuggestions'
                    :key='s.label'
                    type='button'
                    class='list-group-item list-group-item-action list-group-item-dark py-1 small'
                    @click='applySuggestion(s)'
                >
                    {{ s.label }}
                </button>
            </div>
            <div class='row g-1'>
                <div class='col-8'>
                    <input
                        v-model='form.streetName'
                        type='text'
                        class='form-control form-control-sm bg-dark text-white border-secondary'
                        placeholder='Street address'
                    >
                </div>
                <div class='col-4'>
                    <input
                        v-model='form.city'
                        type='text'
                        class='form-control form-control-sm bg-dark text-white border-secondary'
                        placeholder='City'
                    >
                </div>
                <div class='col-4'>
                    <input
                        v-model='form.state'
                        type='text'
                        class='form-control form-control-sm bg-dark text-white border-secondary'
                        placeholder='State'
                    >
                </div>
                <div class='col-4'>
                    <input
                        v-model='form.zipCode'
                        type='text'
                        class='form-control form-control-sm bg-dark text-white border-secondary'
                        placeholder='ZIP'
                    >
                </div>
                <div class='col-4'>
                    <input
                        v-model='form.country'
                        type='text'
                        class='form-control form-control-sm bg-dark text-white border-secondary'
                        placeholder='Country'
                    >
                </div>
            </div>
            <div class='row g-1 mt-1'>
                <div class='col-6'>
                    <input
                        v-model.number='form.lat'
                        type='number'
                        step='any'
                        class='form-control form-control-sm bg-dark text-white border-secondary'
                        placeholder='Latitude'
                    >
                </div>
                <div class='col-6'>
                    <input
                        v-model.number='form.lon'
                        type='number'
                        step='any'
                        class='form-control form-control-sm bg-dark text-white border-secondary'
                        placeholder='Longitude'
                    >
                </div>
            </div>
        </div>

        <!-- Dispatcher -->
        <div>
            <label class='form-label small text-white-50 mb-1'>Dispatcher</label>
            <input
                v-model='form.dispatcher'
                type='text'
                class='form-control form-control-sm bg-dark text-white border-secondary'
                placeholder='Callsign or name'
            >
        </div>

        <!-- Details -->
        <div>
            <label class='form-label small text-white-50 mb-1'>Details</label>
            <textarea
                v-model='form.details'
                rows='3'
                class='form-control form-control-sm bg-dark text-white border-secondary'
                placeholder='Incident notes…'
            />
        </div>

        <!-- Caller Info (collapsible) -->
        <div>
            <button
                type='button'
                class='btn btn-sm btn-link text-white-50 p-0 text-decoration-none'
                @click='showCaller = !showCaller'
            >
                {{ showCaller ? '▾' : '▸' }} Caller Info
            </button>
            <div
                v-if='showCaller'
                class='mt-2 d-flex flex-column gap-2'
            >
                <input
                    v-model='form.callerName'
                    type='text'
                    class='form-control form-control-sm bg-dark text-white border-secondary'
                    placeholder='Caller name'
                >
                <input
                    v-model='form.callerPhone'
                    type='tel'
                    class='form-control form-control-sm bg-dark text-white border-secondary'
                    placeholder='Phone number'
                >
                <select
                    v-model='form.callerType'
                    class='form-select form-select-sm bg-dark text-white border-secondary'
                >
                    <option value=''>
                        — Caller type —
                    </option>
                    <option value='PHONE'>
                        Phone
                    </option>
                    <option value='RADIO'>
                        Radio
                    </option>
                    <option value='OTHER'>
                        Other
                    </option>
                </select>
            </div>
        </div>

        <!-- Error -->
        <div
            v-if='saveError'
            class='alert alert-danger py-2 small'
        >
            {{ saveError }}
        </div>

        <!-- Submit -->
        <div class='d-flex gap-2'>
            <button
                type='submit'
                class='btn btn-sm btn-warning flex-grow-1'
                :disabled='saving'
            >
                <span
                    v-if='saving'
                    class='spinner-border spinner-border-sm me-1'
                />
                {{ uid ? 'Save Changes' : 'Create Incident' }}
            </button>
            <button
                type='button'
                class='btn btn-sm btn-outline-secondary'
                @click='emit("cancel")'
            >
                Cancel
            </button>
        </div>
    </form>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { getIncident, insertIncident, updateIncident, geocodeAddress } from '../lib/takcad-client.ts';
import type { GeocodeSuggestion } from '../lib/takcad-client.ts';
import type { IncidentRef, IncidentTypeRef } from '../lib/takcad-types.ts';
import { STATUS_ACTIVE } from '../lib/takcad-types.ts';

const props = defineProps<{
    uid?:          string;
    incidentTypes: IncidentTypeRef[];
}>();

const emit = defineEmits<{
    (e: 'saved',  uid: string): void;
    (e: 'cancel'            ): void;
}>();

const saving       = ref(false);
const saveError    = ref('');
const showCaller   = ref(false);
const geocoding    = ref(false);
const geoQuery     = ref('');
const geoSuggestions = ref<GeocodeSuggestion[]>([]);
let geoDebounce: ReturnType<typeof setTimeout>;

const form = reactive({
    incidentName:    '',
    incidentTypeUid: '',
    incidentTimeLocal: toLocalInput(new Date().toISOString()),
    streetName: '', city: '', state: '', zipCode: '', country: '',
    lat: null as number | null,
    lon: null as number | null,
    dispatcher: '',
    details:    '',
    callerName:  '',
    callerPhone: '',
    callerType:  '',
});

function toLocalInput(iso: string): string {
    try {
        const d = new Date(iso);
        const pad = (n: number) => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    } catch { return ''; }
}

function onGeoInput() {
    clearTimeout(geoDebounce);
    if (geoQuery.value.length < 4) { geoSuggestions.value = []; return; }
    geoDebounce = setTimeout(doGeocode, 500);
}

async function doGeocode() {
    if (!geoQuery.value.trim()) return;
    geocoding.value = true;
    try {
        geoSuggestions.value = await geocodeAddress(geoQuery.value);
    } finally {
        geocoding.value = false;
    }
}

function applySuggestion(s: GeocodeSuggestion) {
    form.lat = s.lat;
    form.lon = s.lon;
    // parse label: "123 Main St, City, State, Country"
    const parts = s.label.split(', ');
    if (parts.length >= 1) form.streetName = parts[0];
    if (parts.length >= 2) form.city       = parts[1];
    if (parts.length >= 3) form.state      = parts[2];
    geoSuggestions.value = [];
    geoQuery.value = s.label;
}

onMounted(async () => {
    if (props.uid) {
        try {
            const inc = await getIncident(props.uid);
            form.incidentName    = inc.incidentName;
            form.incidentTypeUid = inc.incidentType?.uid ?? '';
            form.incidentTimeLocal = toLocalInput(inc.incidentTime);
            form.streetName = inc.location?.address?.streetName ?? '';
            form.city       = inc.location?.address?.city       ?? '';
            form.state      = inc.location?.address?.state      ?? '';
            form.zipCode    = inc.location?.address?.zipCode    ?? '';
            form.country    = inc.location?.address?.country    ?? '';
            form.lat        = inc.location?.coords?.latitudeDeg  ?? null;
            form.lon        = inc.location?.coords?.longitudeDeg ?? null;
            form.dispatcher = inc.dispatcher ?? '';
            form.details    = inc.details    ?? '';
            if (inc.callerInfo) {
                showCaller.value  = true;
                form.callerName   = inc.callerInfo.name        ?? '';
                form.callerPhone  = inc.callerInfo.phoneNumber ?? '';
                form.callerType   = inc.callerInfo.callerInfoType ?? '';
            }
        } catch (e) {
            saveError.value = e instanceof Error ? e.message : String(e);
        }
    } else if (props.incidentTypes.length) {
        form.incidentTypeUid = props.incidentTypes[0].uid;
    }
});

async function submit() {
    saveError.value = '';
    const incidentType = props.incidentTypes.find(t => t.uid === form.incidentTypeUid);
    if (!incidentType) { saveError.value = 'Select an incident type'; return; }

    const hasAddress = form.streetName || form.city;
    const hasCoords  = form.lat != null && form.lon != null;
    if (!hasAddress && !hasCoords) { saveError.value = 'Enter an address or coordinates'; return; }

    let existing: IncidentRef | null = null;
    if (props.uid) {
        try { existing = await getIncident(props.uid); }
        catch { /* create fresh */ }
    }

    const payload: IncidentRef = {
        ...(existing ?? {}),
        uid:          props.uid ?? crypto.randomUUID(),
        incidentName: form.incidentName,
        incidentType,
        incidentTime: new Date(form.incidentTimeLocal).toISOString(),
        status:       existing?.status ?? STATUS_ACTIVE,
        dispatcher:   form.dispatcher || null,
        details:      form.details    || null,
        location: {
            address: hasAddress ? {
                streetName: form.streetName,
                city:       form.city,
                state:      form.state,
                zipCode:    form.zipCode,
                country:    form.country,
            } : null,
            coords: hasCoords ? { latitudeDeg: form.lat!, longitudeDeg: form.lon! } : null,
        },
        callerInfo: form.callerName || form.callerPhone ? {
            uid:              crypto.randomUUID(),
            name:             form.callerName  || null,
            phoneNumber:      form.callerPhone || null,
            callerInfoType:   form.callerType  || null,
            timestamp:        new Date().toISOString(),
            phoneContactMethod:  null,
            radioContactDetails: null,
            otherContactDetails: null,
        } : null,
        notes:                existing?.notes                ?? [],
        requestedCallsigns:   existing?.requestedCallsigns   ?? [],
        vehicleUidsRequested: existing?.vehicleUidsRequested ?? [],
        personnelResponding:  existing?.personnelResponding   ?? [],
        vehiclesResponding:   existing?.vehiclesResponding    ?? [],
        firstResponderArrivalTime: existing?.firstResponderArrivalTime ?? null,
        incidentCompletionTime:    existing?.incidentCompletionTime    ?? null,
        sourceSystem:              existing?.sourceSystem ?? { uid: crypto.randomUUID(), name: 'CloudTAK', platform: 'CLOUDTAK' },
    };

    saving.value = true;
    try {
        const resp = props.uid ? await updateIncident(payload) : await insertIncident(payload);
        if (!resp.success) throw new Error(resp.errors?.join(', ') || 'Server returned failure');
        emit('saved', payload.uid);
    } catch (e) {
        saveError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}
</script>
