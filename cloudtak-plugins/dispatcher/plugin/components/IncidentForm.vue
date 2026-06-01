<template>
    <form
        class='d-flex flex-column gap-3'
        @submit.prevent='submit'
    >
        <!-- Name -->
        <div>
            <label class='form-label small text-muted mb-1'>Incident Name <span class='text-danger'>*</span></label>
            <input
                v-model='form.incidentName'
                type='text'
                required
                class='form-control form-control-sm border'
                placeholder='e.g. Structure Fire - 123 Main St'
            >
        </div>

        <!-- Type -->
        <div>
            <label class='form-label small text-muted mb-1'>Incident Type <span class='text-danger'>*</span></label>
            <template v-if='serverMode === "takcad"'>
                <select
                    v-model='form.incidentTypeUid'
                    required
                    class='form-select form-select-sm border'
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
            </template>
            <template v-else>
                <input
                    v-model='form.incidentTypeFree'
                    type='text'
                    required
                    class='form-control form-control-sm border'
                    placeholder='e.g. Fire, Medical, Rescue'
                >
            </template>
        </div>

        <!-- Date/Time -->
        <div>
            <label class='form-label small text-muted mb-1'>Incident Time <span class='text-danger'>*</span></label>
            <input
                v-model='form.incidentTimeLocal'
                type='datetime-local'
                required
                class='form-control form-control-sm border'
            >
        </div>

        <!-- Location -->
        <div>
            <label class='form-label small text-muted mb-1'>Location <span class='text-danger'>*</span></label>
            <div class='input-group mb-1'>
                <input
                    v-model='geoQuery'
                    type='text'
                    class='form-control form-control-sm border'
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
                <button
                    type='button'
                    class='btn btn-sm'
                    :class='picking ? "btn-warning" : "btn-outline-secondary"'
                    title='Click a point on the map to set the location'
                    @click='pickOnMap'
                >
                    📍
                </button>
            </div>
            <div
                v-if='picking'
                class='small text-warning mb-1'
            >
                Click a point on the map to set the incident location…
            </div>
            <div
                v-if='geoSuggestions.length'
                class='list-group mb-1'
            >
                <button
                    v-for='s in geoSuggestions'
                    :key='s.label'
                    type='button'
                    class='list-group-item list-group-item-action py-1 small'
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
                        class='form-control form-control-sm border'
                        placeholder='Street address'
                    >
                </div>
                <div class='col-4'>
                    <input
                        v-model='form.city'
                        type='text'
                        class='form-control form-control-sm border'
                        placeholder='City'
                    >
                </div>
                <div class='col-4'>
                    <input
                        v-model='form.state'
                        type='text'
                        class='form-control form-control-sm border'
                        placeholder='State'
                    >
                </div>
                <div class='col-4'>
                    <input
                        v-model='form.zipCode'
                        type='text'
                        class='form-control form-control-sm border'
                        placeholder='ZIP'
                    >
                </div>
                <div class='col-4'>
                    <input
                        v-model='form.country'
                        type='text'
                        class='form-control form-control-sm border'
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
                        class='form-control form-control-sm border'
                        placeholder='Latitude'
                    >
                </div>
                <div class='col-6'>
                    <input
                        v-model.number='form.lon'
                        type='number'
                        step='any'
                        class='form-control form-control-sm border'
                        placeholder='Longitude'
                    >
                </div>
            </div>
        </div>

        <!-- Dispatcher (takcad only) -->
        <div v-if='serverMode === "takcad"'>
            <label class='form-label small text-muted mb-1'>Dispatcher</label>
            <input
                v-model='form.dispatcher'
                type='text'
                class='form-control form-control-sm border'
                placeholder='Callsign or name'
            >
        </div>

        <!-- Details -->
        <div>
            <label class='form-label small text-muted mb-1'>Details</label>
            <textarea
                v-model='form.details'
                rows='3'
                class='form-control form-control-sm border'
                placeholder='Incident notes…'
            />
        </div>

        <!-- Caller Info (takcad only, collapsible) -->
        <div v-if='serverMode === "takcad"'>
            <button
                type='button'
                class='btn btn-sm btn-link text-muted p-0 text-decoration-none'
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
                    class='form-control form-control-sm border'
                    placeholder='Caller name'
                >
                <input
                    v-model='form.callerPhone'
                    type='tel'
                    class='form-control form-control-sm border'
                    placeholder='Phone number'
                >
                <select
                    v-model='form.callerType'
                    class='form-select form-select-sm border'
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
import { useMapStore } from '../../../src/stores/map.ts';
import { getIncident, insertIncident, updateIncident, geocodeAddress, reverseGeocode } from '../lib/takcad-client.ts';
import type { GeocodeSuggestion } from '../lib/takcad-client.ts';
import type { IncidentRef, IncidentTypeRef } from '../lib/takcad-types.ts';
import { STATUS_ACTIVE } from '../lib/takcad-types.ts';
import { dropIncidentMarker, postMissionCallLog } from '../lib/map-marker.ts';
import type { LocalIncident } from '../lib/dispatcher-store.ts';

const props = defineProps<{
    serverMode:        'detecting' | 'takcad' | 'standalone';
    uid?:              string;
    incidentTypes:     IncidentTypeRef[];
    activeMissionGuid?: string;
}>();

const emit = defineEmits<{
    (e: 'saved',           uid: string):      void;
    (e: 'saved-standalone', inc: LocalIncident): void;
    (e: 'cancel'                          ):   void;
}>();

const saving       = ref(false);
const saveError    = ref('');
const showCaller   = ref(false);
const geocoding    = ref(false);
const mapStore     = useMapStore();
const picking      = ref(false);
const geoQuery     = ref('');
const geoSuggestions = ref<GeocodeSuggestion[]>([]);
let geoDebounce: ReturnType<typeof setTimeout>;

const form = reactive({
    incidentName:      '',
    incidentTypeUid:   '',
    incidentTypeFree:  '',
    incidentTimeLocal: toLocalInput(new Date().toISOString()),
    streetName: '', city: '', state: '', zipCode: '', country: '',
    lat:        null as number | null,
    lon:        null as number | null,
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
    try { geoSuggestions.value = await geocodeAddress(geoQuery.value); }
    finally { geocoding.value = false; }
}

function applySuggestion(s: GeocodeSuggestion) {
    form.lat        = s.lat;
    form.lon        = s.lon;
    form.streetName = s.streetName;
    form.city       = s.city;
    form.state      = s.state;
    form.zipCode    = s.zipCode;
    form.country    = s.country;
    geoSuggestions.value = [];
    geoQuery.value = s.label;
}

function pickOnMap() {
    const map = mapStore.map;
    if (!map) return;
    picking.value = true;
    map.getCanvas().style.cursor = 'crosshair';
    map.once('click', async (e: { lngLat: { lat: number; lng: number } }) => {
        map.getCanvas().style.cursor = '';
        picking.value = false;
        form.lat = Number(e.lngLat.lat.toFixed(6));
        form.lon = Number(e.lngLat.lng.toFixed(6));
        try {
            const s = await reverseGeocode(form.lat, form.lon);
            if (s) {
                form.streetName = s.streetName;
                form.city       = s.city;
                form.state      = s.state;
                form.zipCode    = s.zipCode;
                form.country    = s.country;
                geoQuery.value  = s.label;
            }
        } catch { /* coords set regardless */ }
    });
}

onMounted(async () => {
    if (props.uid && props.serverMode === 'takcad') {
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
            form.dispatcher = inc.dispatcher?.name ?? '';
            form.details    = inc.details    ?? '';
            const caller = inc.callerInfo?.[0];
            if (caller) {
                showCaller.value = true;
                form.callerName  = caller.name        ?? '';
                form.callerPhone = caller.phoneNumber ?? '';
                form.callerType  = caller.callerInfoType ?? '';
            }
        } catch (e) {
            saveError.value = e instanceof Error ? e.message : String(e);
        }
    } else if (props.serverMode === 'takcad' && props.incidentTypes.length) {
        form.incidentTypeUid = props.incidentTypes[0].uid;
    }
});

async function submit() {
    saveError.value = '';

    const hasCoords = form.lat != null && form.lon != null;
    if (!hasCoords) {
        saveError.value = 'Coordinates are required — use the address search or enter latitude/longitude.';
        return;
    }

    const address = [form.streetName, form.city, form.state].filter(Boolean).join(', ');

    if (props.serverMode === 'standalone') {
        await submitStandalone(address, hasCoords);
    } else {
        await submitTakCad(address, hasCoords);
    }
}

async function submitStandalone(address: string, hasCoords: boolean) {
    void hasCoords;
    const incidentType = form.incidentTypeFree.trim();
    if (!incidentType) { saveError.value = 'Enter an incident type'; return; }

    const uid = crypto.randomUUID();
    saving.value = true;
    try {
        await dropIncidentMarker({
            uid,
            name:    form.incidentName,
            type:    incidentType,
            address,
            lat:     form.lat!,
            lon:     form.lon!,
        });

        if (props.activeMissionGuid) {
            try {
                await postMissionCallLog(props.activeMissionGuid, {
                    name:    form.incidentName,
                    type:    incidentType,
                    address,
                });
            } catch { /* mission log is best-effort */ }
        }

        const local: LocalIncident = {
            uid,
            name:                form.incidentName,
            type:                incidentType,
            address,
            lat:                 form.lat!,
            lon:                 form.lon!,
            time:                new Date().toISOString(),
            status:              'ACTIVE',
            assignedContactUids: [],
        };
        emit('saved-standalone', local);
    } catch (e) {
        saveError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

async function submitTakCad(address: string, hasCoords: boolean) {
    void address;
    const incidentType = props.incidentTypes.find(t => t.uid === form.incidentTypeUid);
    if (!incidentType) { saveError.value = 'Select an incident type'; return; }

    const hasAddress = !!(form.streetName || form.city);

    let existing: IncidentRef | null = null;
    if (props.uid) {
        try { existing = await getIncident(props.uid); }
        catch { /* create fresh */ }
    }

    const uid = props.uid ?? crypto.randomUUID();
    const payload: IncidentRef = {
        ...(existing ?? {}),
        uid,
        incidentName: form.incidentName,
        incidentType,
        incidentTime: new Date(form.incidentTimeLocal).toISOString(),
        status:       existing?.status ?? STATUS_ACTIVE,
        dispatcher:   form.dispatcher ? { name: form.dispatcher } : null,
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
        callerInfo: (form.callerName || form.callerPhone) ? [{
            uid:                 crypto.randomUUID(),
            name:                form.callerName  || null,
            phoneNumber:         form.callerPhone || null,
            callerInfoType:      form.callerType  || null,
            timestamp:           new Date().toISOString(),
            phoneContactMethod:  null,
            radioContactDetails: null,
            otherContactDetails: null,
        }] : [],
        notes:                existing?.notes                ?? [],
        requestedCallsigns:   existing?.requestedCallsigns   ?? [],
        vehicleUidsRequested: existing?.vehicleUidsRequested ?? [],
        personnelResponding:  existing?.personnelResponding   ?? [],
        vehiclesResponding:   existing?.vehiclesResponding    ?? [],
        firstResponderArrivalTime: existing?.firstResponderArrivalTime ?? null,
        incidentCompletionTime:    existing?.incidentCompletionTime    ?? null,
        sourceSystem: existing?.sourceSystem ?? { uid: crypto.randomUUID(), name: 'CloudTAK', platform: 'OTHER' },
    };

    saving.value = true;
    try {
        const resp = props.uid ? await updateIncident(payload) : await insertIncident(payload);
        if (!resp.success) throw new Error(resp.errors?.join(', ') || 'Server returned failure');

        // Also drop a map marker so iTAK subscribers see the incident pin
        try {
            await dropIncidentMarker({
                uid,
                name:    form.incidentName,
                type:    incidentType.name,
                address: [form.streetName, form.city].filter(Boolean).join(', '),
                lat:     form.lat!,
                lon:     form.lon!,
            });
        } catch { /* marker is best-effort */ }

        emit('saved', uid);
    } catch (e) {
        saveError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}
</script>
