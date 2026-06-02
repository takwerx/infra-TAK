<template>
    <div class='d-flex flex-column h-100 overflow-hidden'>
        <!-- ── Create Event form ─────────────────────────────────────────────── -->
        <template v-if='view === "create"'>
            <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                <button
                    class='btn btn-sm btn-outline-secondary'
                    @click='view = "list"'
                >
                    ← Back
                </button>
                <span class='fw-semibold'>New Event</span>
            </div>
            <div class='flex-grow-1 overflow-auto p-3 d-flex flex-column gap-3'>
                <div>
                    <label class='form-label small text-muted mb-1'>Event Name <span class='text-danger'>*</span></label>
                    <input
                        v-model='form.name'
                        type='text'
                        class='form-control form-control-sm border'
                        placeholder='e.g. 2025-FESTIVAL'
                        @input='onNameInput'
                    >
                </div>
                <div>
                    <label class='form-label small text-muted mb-1'>Incident Prefix</label>
                    <input
                        v-model='form.prefix'
                        type='text'
                        class='form-control form-control-sm border text-warning fw-semibold'
                        placeholder='FESTIVAL'
                        maxlength='12'
                    >
                    <div class='form-text small'>
                        Incidents are numbered {{ (form.prefix || 'INC').toUpperCase() }}-001, -002, …
                    </div>
                </div>
                <div>
                    <label class='form-label small text-muted mb-1'>DataSync Feed <span class='text-danger'>*</span></label>
                    <button
                        v-if='!selectedFeed'
                        class='btn btn-sm btn-outline-secondary w-100'
                        :disabled='loadingFeeds'
                        @click='fetchFeeds'
                    >
                        <span v-if='loadingFeeds' class='spinner-border spinner-border-sm me-1' />
                        {{ loadingFeeds ? 'Loading…' : '+ Select DataSync Feed' }}
                    </button>
                    <div
                        v-if='!selectedFeed && feeds.length'
                        class='border rounded mt-1'
                        style='max-height:160px;overflow-y:auto;background:var(--bs-body-bg,#1e2228)'
                    >
                        <button
                            v-for='f in feeds'
                            :key='f.guid'
                            class='btn btn-sm w-100 text-start px-3 py-2 border-0 border-bottom rounded-0'
                            style='font-size:12px'
                            @click='selectedFeed = f'
                        >
                            {{ f.name }}
                        </button>
                    </div>
                    <div
                        v-else-if='!selectedFeed && feedsFetched && !loadingFeeds'
                        class='text-muted small text-center py-1'
                    >
                        No DataSync feeds found
                    </div>
                    <div
                        v-if='selectedFeed'
                        class='d-flex align-items-center gap-2 small mt-1'
                    >
                        <span class='badge bg-primary'>DataSync</span>
                        <span class='text-truncate flex-grow-1'>{{ selectedFeed.name }}</span>
                        <button
                            class='btn btn-link btn-sm p-0 text-muted text-decoration-none'
                            @click='selectedFeed = null; feeds = []; feedsFetched = false'
                        >
                            ✕
                        </button>
                    </div>
                </div>

                <div
                    v-if='createError'
                    class='alert alert-danger py-2 small'
                >
                    {{ createError }}
                </div>
                <button
                    class='btn btn-sm btn-warning'
                    :disabled='saving || !form.name.trim() || !selectedFeed'
                    @click='submitCreate'
                >
                    <span v-if='saving' class='spinner-border spinner-border-sm me-1' />
                    Create Event
                </button>
            </div>
        </template>

        <!-- ── Events list ───────────────────────────────────────────────────── -->
        <template v-else>
            <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                <span class='text-muted small me-auto'>Events</span>
                <button
                    class='btn btn-sm btn-warning'
                    @click='openCreate'
                >
                    + New Event
                </button>
            </div>
            <div class='flex-grow-1 overflow-auto'>
                <div
                    v-if='loading && !store.events.length'
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
                    v-else-if='!store.events.length'
                    class='text-center text-muted py-4 small'
                >
                    No events yet
                </div>
                <div
                    v-for='ev in store.events'
                    :key='ev.id'
                    class='d-flex align-items-start px-3 py-2 border-bottom event-row'
                >
                    <div
                        class='flex-grow-1 overflow-hidden'
                        role='button'
                        @click='open(ev)'
                    >
                        <div class='d-flex align-items-center gap-2'>
                            <span class='fw-semibold small text-truncate'>{{ ev.name }}</span>
                            <span
                                v-if='ev.status === "archived"'
                                class='badge bg-secondary small'
                            >Archived</span>
                        </div>
                        <div class='small text-muted text-truncate'>
                            {{ ev.feed_name }} · {{ ev.prefix }}-NNN
                        </div>
                    </div>
                    <div class='text-end ms-2 flex-shrink-0 d-flex gap-1'>
                        <button
                            v-if='ev.status === "active"'
                            class='btn btn-sm btn-link text-muted py-0 px-1 text-decoration-none'
                            title='Archive event (removes markers, keeps records)'
                            :disabled='busyId === ev.id'
                            @click.stop='archive(ev)'
                        >
                            Archive
                        </button>
                        <button
                            class='btn btn-sm btn-link text-danger py-0 px-1 text-decoration-none'
                            title='Nuke event (permanent delete)'
                            :disabled='busyId === ev.id'
                            @click.stop='nuke(ev)'
                        >
                            Nuke
                        </button>
                    </div>
                </div>
            </div>
        </template>
    </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { useMapStore } from '../../../src/stores/map.ts';
import { getMissions } from '../lib/takcad-client.ts';
import type { MissionRef } from '../lib/takcad-client.ts';
import {
    listEvents, createEvent, setEventStatus, deleteEvent, listIncidents,
} from '../lib/events-client.ts';
import type { DispatcherEvent } from '../lib/events-client.ts';
import { removeIncidentMarker } from '../lib/map-marker.ts';
import { dispatcherStore as store, loadLastEventId } from '../lib/dispatcher-store.ts';

const emit = defineEmits<{
    (e: 'opened', ev: DispatcherEvent): void;
}>();

const mapStore = useMapStore();

const view         = ref<'list' | 'create'>('list');
const loading      = ref(false);
const loadError    = ref('');
const saving       = ref(false);
const createError  = ref('');
const busyId       = ref('');

const feeds        = ref<MissionRef[]>([]);
const loadingFeeds = ref(false);
const feedsFetched = ref(false);
const selectedFeed = ref<MissionRef | null>(null);

const form = reactive({
    name:   '',
    prefix: '',
});

// User hasn't touched the prefix field yet → keep deriving it from the name.
let prefixDirty = false;

// Derive a prefix from the event name: strip a leading 4-digit year token, uppercase,
// keep [A-Z0-9-], collapse separators, ≤12 chars. e.g. "2025-FESTIVAL" → "FESTIVAL".
function derivePrefix(name: string): string {
    return name
        .replace(/^\s*\d{4}[\s_-]*/, '')
        .replace(/[^A-Z0-9]+/gi, '-')
        .replace(/-+/g, '-')
        .replace(/^-|-$/g, '')
        .toUpperCase()
        .slice(0, 12);
}

function onNameInput() {
    if (!prefixDirty) form.prefix = derivePrefix(form.name);
}

async function loadList() {
    loading.value = true; loadError.value = '';
    try {
        store.events = await listEvents();
        // Optional convenience: reselect the last-opened Event on first load.
        const lastId = await loadLastEventId();
        if (lastId) {
            const ev = store.events.find(e => e.id === lastId);
            if (ev) await open(ev);
        }
    } catch (e) {
        loadError.value = e instanceof Error ? e.message : String(e);
    } finally {
        loading.value = false;
    }
}

async function fetchFeeds() {
    loadingFeeds.value = true;
    feedsFetched.value = false;
    try { feeds.value = await getMissions(); }
    catch { feeds.value = []; }
    finally { loadingFeeds.value = false; feedsFetched.value = true; }
}

function openCreate() {
    form.name = '';
    form.prefix = '';
    prefixDirty = false;
    selectedFeed.value = null;
    feeds.value = [];
    feedsFetched.value = false;
    createError.value = '';
    view.value = 'create';
}

async function submitCreate() {
    if (!form.name.trim() || !selectedFeed.value) return;
    saving.value = true; createError.value = '';
    try {
        const ev = await createEvent({
            name:      form.name.trim(),
            prefix:    (form.prefix || derivePrefix(form.name) || 'INC').toUpperCase(),
            feed_guid: selectedFeed.value.guid,
            feed_name: selectedFeed.value.name,
        });
        store.events = [ev, ...store.events];
        view.value = 'list';
        await open(ev);
    } catch (e) {
        createError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

async function open(ev: DispatcherEvent) {
    store.activeEvent = ev;
    emit('opened', ev);
}

// Remove every marker this Event dropped into its feed (records stay server-side).
async function clearEventMarkers(ev: DispatcherEvent) {
    let incidents;
    try { incidents = await listIncidents(ev.id); }
    catch { return; }
    for (const inc of incidents) {
        try {
            await removeIncidentMarker(mapStore, {
                uid:        inc.id,
                number:     inc.number,
                name:       inc.type ?? '',
                type:       inc.type ?? '',
                address:    inc.address ?? '',
                lat:        inc.lat ?? 0,
                lon:        inc.lon ?? 0,
                time:       inc.created_at,
                dispatcher: inc.dispatcher ?? '',
                details:    inc.details ?? '',
                feedGuid:   ev.feed_guid,
            });
        } catch { /* best-effort */ }
    }
}

async function archive(ev: DispatcherEvent) {
    busyId.value = ev.id;
    try {
        await clearEventMarkers(ev);
        const updated = await setEventStatus(ev.id, 'archived');
        store.events = store.events.map(e => e.id === ev.id ? updated : e);
    } catch (e) {
        loadError.value = e instanceof Error ? e.message : String(e);
    } finally {
        busyId.value = '';
    }
}

async function nuke(ev: DispatcherEvent) {
    if (!confirm(`Nuke event "${ev.name}"? This permanently deletes the event and ALL its incident records.`)) return;
    busyId.value = ev.id;
    try {
        await clearEventMarkers(ev);
        await deleteEvent(ev.id);
        store.events = store.events.filter(e => e.id !== ev.id);
        if (store.activeEvent?.id === ev.id) store.activeEvent = null;
    } catch (e) {
        loadError.value = e instanceof Error ? e.message : String(e);
    } finally {
        busyId.value = '';
    }
}

onMounted(loadList);
</script>

<style scoped>
.event-row:hover { background: rgba(255,255,255,.05); }
</style>
