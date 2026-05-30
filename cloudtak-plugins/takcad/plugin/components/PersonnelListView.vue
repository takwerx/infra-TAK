<template>
    <div class='d-flex flex-column h-100 overflow-hidden'>
        <!-- ── Personnel List ────────────────────────────────── -->
        <template v-if='view === "list"'>
            <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0'>
                <span class='text-white-50 small me-auto'>{{ personnel.length }} personnel</span>
                <button
                    class='btn btn-sm btn-warning'
                    @click='openCreate'
                >
                    + Add Person
                </button>
            </div>
            <div class='flex-grow-1 overflow-auto'>
                <div
                    v-if='loading'
                    class='text-center text-white-50 py-4 small'
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
                    v-else-if='!personnel.length'
                    class='text-center text-white-50 py-4 small'
                >
                    No personnel registered
                </div>
                <div
                    v-for='person in personnel'
                    :key='person.uid'
                    class='d-flex align-items-center px-3 py-2 border-bottom person-row'
                    role='button'
                    @click='openDetail(person)'
                >
                    <div class='flex-grow-1'>
                        <div class='fw-semibold small text-white'>
                            {{ person.callsign }}
                        </div>
                        <div class='small text-white-50'>
                            {{ person.roles?.map(r => r.name).join(', ') || 'No roles' }}
                        </div>
                    </div>
                    <div
                        v-if='person.takCadGroup'
                        class='small text-white-50'
                    >
                        {{ person.takCadGroup }}
                    </div>
                </div>
            </div>
        </template>

        <!-- ── Person Detail / Edit ──────────────────────────── -->
        <template v-else-if='view === "detail" && selected'>
            <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                <button
                    class='btn btn-sm btn-outline-secondary'
                    @click='view = "list"'
                >
                    ← Back
                </button>
                <span class='fw-semibold flex-grow-1'>{{ selected.callsign }}</span>
            </div>
            <div class='flex-grow-1 overflow-auto p-3 d-flex flex-column gap-3'>
                <div v-if='!editing'>
                    <div class='card bg-dark border-secondary'>
                        <div class='card-body py-2 px-3 small d-flex flex-column gap-1'>
                            <div class='row g-1'>
                                <div class='col-4 text-white-50'>
                                    Callsign
                                </div>
                                <div class='col-8 text-white'>
                                    {{ selected.callsign }}
                                </div>
                                <div class='col-4 text-white-50'>
                                    Group
                                </div>
                                <div class='col-8 text-white'>
                                    {{ selected.takCadGroup || '—' }}
                                </div>
                                <div class='col-4 text-white-50'>
                                    Roles
                                </div>
                                <div class='col-8 text-white'>
                                    {{ selected.roles?.map(r => r.name).join(', ') || '—' }}
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
                            @click='startEdit'
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
                        <label class='form-label small text-white-50 mb-1'>Callsign <span class='text-danger'>*</span></label>
                        <input
                            v-model='editForm.callsign'
                            required
                            type='text'
                            class='form-control form-control-sm bg-dark text-white border-secondary'
                        >
                    </div>
                    <div>
                        <label class='form-label small text-white-50 mb-1'>TAK CAD Group</label>
                        <input
                            v-model='editForm.takCadGroup'
                            type='text'
                            class='form-control form-control-sm bg-dark text-white border-secondary'
                            placeholder='e.g. ALPHA'
                        >
                    </div>
                    <div>
                        <label class='form-label small text-white-50 mb-1'>Roles</label>
                        <div
                            v-for='role in roles'
                            :key='role.uid'
                            class='form-check'
                        >
                            <input
                                :id='`edit-role-${role.uid}`'
                                type='checkbox'
                                class='form-check-input'
                                :checked='editForm.roleUids.includes(role.uid)'
                                @change='toggleRole(role.uid, editForm.roleUids)'
                            >
                            <label
                                class='form-check-label text-white-50 small'
                                :for='`edit-role-${role.uid}`'
                            >{{ role.name }}</label>
                        </div>
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

        <!-- ── Add Person ─────────────────────────────────────── -->
        <template v-else-if='view === "create"'>
            <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                <button
                    class='btn btn-sm btn-outline-secondary'
                    @click='view = "list"'
                >
                    ← Back
                </button>
                <span class='fw-semibold'>Add Person</span>
            </div>
            <div class='p-3'>
                <form
                    class='d-flex flex-column gap-3'
                    @submit.prevent='saveCreate'
                >
                    <div>
                        <label class='form-label small text-white-50 mb-1'>Callsign <span class='text-danger'>*</span></label>
                        <input
                            v-model='createForm.callsign'
                            required
                            type='text'
                            class='form-control form-control-sm bg-dark text-white border-secondary'
                            placeholder='e.g. DISPATCH-1'
                        >
                    </div>
                    <div>
                        <label class='form-label small text-white-50 mb-1'>TAK CAD Group</label>
                        <input
                            v-model='createForm.takCadGroup'
                            type='text'
                            class='form-control form-control-sm bg-dark text-white border-secondary'
                            placeholder='e.g. ALPHA'
                        >
                    </div>
                    <div>
                        <label class='form-label small text-white-50 mb-1'>Roles</label>
                        <div
                            v-for='role in roles'
                            :key='role.uid'
                            class='form-check'
                        >
                            <input
                                :id='`create-role-${role.uid}`'
                                type='checkbox'
                                class='form-check-input'
                                :checked='createForm.roleUids.includes(role.uid)'
                                @change='toggleRole(role.uid, createForm.roleUids)'
                            >
                            <label
                                class='form-check-label text-white-50 small'
                                :for='`create-role-${role.uid}`'
                            >{{ role.name }}</label>
                        </div>
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
                            />Add Person
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
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { getPersonnel, insertPerson, updatePerson, deletePerson } from '../lib/takcad-client.ts';
import type { PersonRef, Role } from '../lib/takcad-types.ts';

const props = defineProps<{ roles: Role[] }>();

type ViewName = 'list' | 'detail' | 'create';

const view        = ref<ViewName>('list');
const personnel   = ref<PersonRef[]>([]);
const selected    = ref<PersonRef | null>(null);
const loading     = ref(false);
const loadError   = ref('');
const detailError = ref('');
const createError = ref('');
const saving      = ref(false);
const editing     = ref(false);

const editForm   = reactive({ callsign: '', takCadGroup: '', roleUids: [] as string[] });
const createForm = reactive({ callsign: '', takCadGroup: '', roleUids: [] as string[] });

function toggleRole(uid: string, arr: string[]) {
    const idx = arr.indexOf(uid);
    if (idx >= 0) arr.splice(idx, 1);
    else arr.push(uid);
}

async function loadList() {
    loading.value = true; loadError.value = '';
    try { personnel.value = await getPersonnel(); }
    catch (e) { loadError.value = e instanceof Error ? e.message : String(e); }
    finally { loading.value = false; }
}

function openDetail(person: PersonRef) {
    selected.value    = person;
    editing.value     = false;
    detailError.value = '';
    view.value = 'detail';
}

function startEdit() {
    if (!selected.value) return;
    editForm.callsign    = selected.value.callsign;
    editForm.takCadGroup = selected.value.takCadGroup ?? '';
    editForm.roleUids    = selected.value.roles?.map(r => r.uid) ?? [];
    editing.value = true;
}

function openCreate() {
    createForm.callsign    = '';
    createForm.takCadGroup = '';
    createForm.roleUids    = [];
    createError.value      = '';
    view.value = 'create';
}

async function saveEdit() {
    if (!selected.value) return;
    saving.value = true; detailError.value = '';
    const assignedRoles = props.roles.filter(r => editForm.roleUids.includes(r.uid));
    const updated: PersonRef = {
        ...selected.value,
        callsign:    editForm.callsign,
        takCadGroup: editForm.takCadGroup || null,
        roles:       assignedRoles,
    };
    try {
        const r = await updatePerson(updated);
        if (!r.success) throw new Error(r.errors?.join(', ') || 'Update failed');
        selected.value  = updated;
        personnel.value = personnel.value.map(p => p.uid === updated.uid ? updated : p);
        editing.value   = false;
    } catch (e) {
        detailError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

async function saveCreate() {
    saving.value = true; createError.value = '';
    const assignedRoles = props.roles.filter(r => createForm.roleUids.includes(r.uid));
    const payload: PersonRef = {
        uid:         crypto.randomUUID(),
        callsign:    createForm.callsign,
        takCadGroup: createForm.takCadGroup || null,
        roles:       assignedRoles,
    };
    try {
        const r = await insertPerson(payload);
        if (!r.success) throw new Error(r.errors?.join(', ') || 'Insert failed');
        personnel.value = [...personnel.value, payload];
        view.value = 'list';
    } catch (e) {
        createError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

async function confirmDelete() {
    if (!selected.value) return;
    if (!confirm(`Delete "${selected.value.callsign}"?`)) return;
    saving.value = true; detailError.value = '';
    try {
        await deletePerson(selected.value.uid);
        personnel.value = personnel.value.filter(p => p.uid !== selected.value!.uid);
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
.person-row:hover { background: rgba(255,255,255,.05); cursor: pointer; }
</style>
