<template>
    <div class='d-flex flex-column h-100 overflow-hidden'>
        <!-- ── TAK-CAD mode: full server-backed UI ──────────────────────────── -->
        <template v-if='serverMode === "takcad"'>
            <!-- ── Incident List ──────────────────────────────────── -->
            <template v-if='view === "list"'>
                <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                    <div class='d-flex rounded overflow-hidden border flex-grow-1'>
                        <button
                            v-for='t in LIST_TABS'
                            :key='t.key'
                            class='flex-fill btn btn-sm py-1 rounded-0 border-0 small'
                            :class='listTab === t.key ? "bg-primary text-white" : "text-muted"'
                            @click='listTab = t.key'
                        >
                            {{ t.label }} <span
                                class='badge'
                                :class='listTab === t.key ? "bg-warning text-dark" : "text-muted"'
                            >{{ t.key === 'active' ? activeIncidents.length : cancelledIncidents.length }}</span>
                        </button>
                    </div>
                    <button
                        class='btn btn-sm btn-warning'
                        @click='openCreate'
                    >
                        + New
                    </button>
                </div>

                <!-- Sort bar -->
                <div class='d-flex px-3 py-1 border-bottom text-muted small flex-shrink-0'>
                    <button
                        v-for='col in SORT_COLS'
                        :key='col.key'
                        class='btn btn-sm btn-link p-0 text-muted small me-3 text-decoration-none'
                        @click='toggleSort(col.key)'
                    >
                        {{ col.label }}
                        <span v-if='sortCol === col.key'>{{ sortAsc ? '↑' : '↓' }}</span>
                    </button>
                    <span
                        class='ms-auto text-muted font-monospace'
                        style='font-size:10px'
                    >{{ lastRefreshed }}</span>
                </div>

                <!-- List -->
                <div class='flex-grow-1 overflow-auto'>
                    <div
                        v-if='loading && !displayedIncidents.length'
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
                        v-else-if='!displayedIncidents.length'
                        class='text-center text-muted py-4 small'
                    >
                        No incidents
                    </div>
                    <div
                        v-for='inc in displayedIncidents'
                        :key='inc.uid'
                        class='d-flex align-items-start px-3 py-2 border-bottom incident-row'
                        role='button'
                        @click='openDetail(inc.uid)'
                    >
                        <div class='flex-grow-1 overflow-hidden'>
                            <div class='d-flex align-items-center gap-2'>
                                <span class='fw-semibold small text-truncate'>{{ inc.incidentName }}</span>
                                <span
                                    class='badge small'
                                    :class='statusBadge(inc.status)'
                                >{{ inc.status }}</span>
                            </div>
                            <div class='small text-muted text-truncate'>
                                {{ formatAddress(inc.location) }}
                            </div>
                            <div class='d-flex gap-3 small text-muted mt-1'>
                                <span>{{ inc.incidentType ?? '—' }}</span>
                            </div>
                        </div>
                        <div class='text-end ms-2 flex-shrink-0'>
                            <div class='small text-muted'>
                                {{ shortTime(inc.incidentTime) }}
                            </div>
                        </div>
                    </div>
                </div>
            </template>

            <!-- ── Incident Detail ────────────────────────────────── -->
            <template v-else-if='view === "detail" && detailIncident'>
                <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                    <button
                        class='btn btn-sm btn-outline-secondary'
                        @click='view = "list"'
                    >
                        ← Back
                    </button>
                    <span class='fw-semibold text-truncate flex-grow-1'>{{ detailIncident.incidentName }}</span>
                    <span
                        class='badge'
                        :class='statusBadge(detailIncident.status)'
                    >{{ detailIncident.status }}</span>
                </div>

                <div class='flex-grow-1 overflow-auto p-3 d-flex flex-column gap-3'>
                    <!-- Core info -->
                    <div class='card border'>
                        <div class='card-body py-2 px-3 d-flex flex-column gap-1 small'>
                            <div class='row g-1'>
                                <div class='col-4 text-muted'>
                                    Type
                                </div>
                                <div class='col-8'>
                                    {{ detailIncident.incidentType?.name }}
                                </div>
                                <div class='col-4 text-muted'>
                                    Time
                                </div>
                                <div class='col-8'>
                                    {{ formatTime(detailIncident.incidentTime) }}
                                </div>
                                <div class='col-4 text-muted'>
                                    Location
                                </div>
                                <div class='col-8'>
                                    {{ formatAddress(detailIncident.location) }}
                                </div>
                                <template v-if='detailIncident.location?.coords'>
                                    <div class='col-4 text-muted'>
                                        Coords
                                    </div>
                                    <div
                                        class='col-8 font-monospace text-muted'
                                        style='font-size:11px'
                                    >
                                        {{ detailIncident.location.coords.latitudeDeg.toFixed(6) }},
                                        {{ detailIncident.location.coords.longitudeDeg.toFixed(6) }}
                                    </div>
                                </template>
                                <div class='col-4 text-muted'>
                                    Dispatcher
                                </div>
                                <div class='col-8'>
                                    {{ detailIncident.dispatcher?.name || '—' }}
                                </div>
                                <template v-if='detailIncident.details'>
                                    <div class='col-4 text-muted'>
                                        Details
                                    </div>
                                    <div
                                        class='col-8'
                                        style='white-space:pre-wrap'
                                    >
                                        {{ detailIncident.details }}
                                    </div>
                                </template>
                                <template v-if='detailIncident.firstResponderArrivalTime'>
                                    <div class='col-4 text-muted'>
                                        Arrival
                                    </div>
                                    <div class='col-8'>
                                        {{ formatTime(detailIncident.firstResponderArrivalTime) }}
                                    </div>
                                </template>
                            </div>
                        </div>
                    </div>

                    <!-- Caller info -->
                    <template v-if='detailIncident.callerInfo?.length'>
                        <div class='small text-muted fw-semibold text-uppercase'>
                            Caller
                        </div>
                        <div class='card border'>
                            <div class='card-body py-2 px-3 d-flex flex-column gap-1 small'>
                                <div class='row g-1'>
                                    <div class='col-4 text-muted'>
                                        Name
                                    </div>
                                    <div class='col-8'>
                                        {{ detailIncident.callerInfo[0].name || '—' }}
                                    </div>
                                    <div class='col-4 text-muted'>
                                        Phone
                                    </div>
                                    <div class='col-8'>
                                        {{ detailIncident.callerInfo[0].phoneNumber || '—' }}
                                    </div>
                                    <div class='col-4 text-muted'>
                                        Type
                                    </div>
                                    <div class='col-8'>
                                        {{ detailIncident.callerInfo[0].callerInfoType || '—' }}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </template>

                    <!-- Responding vehicles -->
                    <div class='small text-muted fw-semibold text-uppercase d-flex align-items-center'>
                        <span class='me-auto'>Responding Vehicles ({{ detailIncident.vehiclesResponding?.length ?? 0 }})</span>
                        <button
                            class='btn btn-sm btn-outline-warning py-0 px-2'
                            @click='view = "responders"'
                        >
                            Manage
                        </button>
                    </div>
                    <div
                        v-if='detailIncident.vehiclesResponding?.length'
                        class='card border'
                    >
                        <div class='card-body py-1 px-3'>
                            <div
                                v-for='vr in detailIncident.vehiclesResponding'
                                :key='vr.vehicle.vehicleUid'
                                class='d-flex align-items-center py-1 border-bottom border small gap-2'
                            >
                                <span class=''>{{ vr.vehicle.vehicleUid }}</span>
                                <span
                                    v-if='vr.responseStatus'
                                    class='badge bg-secondary'
                                >{{ vr.responseStatus }}</span>
                                <span
                                    v-if='vr.eta'
                                    class='text-muted ms-auto'
                                >ETA {{ vr.eta }}</span>
                            </div>
                        </div>
                    </div>
                    <div
                        v-else
                        class='text-muted small'
                    >
                        No vehicles assigned
                    </div>

                    <!-- Responding personnel -->
                    <div class='small text-muted fw-semibold text-uppercase'>
                        Personnel ({{ detailIncident.personnelResponding?.length ?? 0 }})
                    </div>
                    <div
                        v-if='detailIncident.personnelResponding?.length'
                        class='card border'
                    >
                        <div class='card-body py-1 px-3'>
                            <div
                                v-for='pr in detailIncident.personnelResponding'
                                :key='pr.personUid'
                                class='d-flex align-items-center py-1 border-bottom border small gap-2'
                            >
                                <span class=''>{{ pr.callsign }}</span>
                            </div>
                        </div>
                    </div>
                    <div
                        v-else
                        class='text-muted small'
                    >
                        No personnel assigned
                    </div>

                    <!-- Notes -->
                    <div class='small text-muted fw-semibold text-uppercase'>
                        Notes
                    </div>
                    <div
                        v-if='detailIncident.notes?.length'
                        class='d-flex flex-column gap-1'
                    >
                        <div
                            v-for='note in detailIncident.notes'
                            :key='note.uid'
                            class='card border'
                        >
                            <div class='card-body py-1 px-3 small'>
                                <div class='d-flex align-items-center gap-2 text-muted mb-1'>
                                    <span class='fw-semibold'>{{ note.creator }}</span>
                                    <span>{{ formatTime(note.timestamp) }}</span>
                                    <button
                                        class='btn btn-sm btn-link text-danger py-0 px-1 ms-auto text-decoration-none'
                                        @click='deleteNote(note.uid)'
                                    >
                                        ✕
                                    </button>
                                </div>
                                <div style='white-space:pre-wrap'>
                                    {{ note.info }}
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class='input-group'>
                        <input
                            v-model='newNote'
                            type='text'
                            class='form-control form-control-sm border'
                            placeholder='Add a note…'
                            @keyup.enter='addNote'
                        >
                        <button
                            class='btn btn-sm btn-secondary'
                            :disabled='!newNote.trim()'
                            @click='addNote'
                        >
                            Add
                        </button>
                    </div>

                    <!-- Actions -->
                    <div
                        v-if='detailError'
                        class='alert alert-danger py-2 small'
                    >
                        {{ detailError }}
                    </div>
                    <div class='d-flex gap-2 flex-wrap'>
                        <button
                            class='btn btn-sm btn-outline-warning'
                            @click='openEdit'
                        >
                            Edit
                        </button>
                        <button
                            v-if='isActive(detailIncident.status)'
                            class='btn btn-sm btn-outline-secondary'
                            :disabled='saving'
                            @click='closeIncident'
                        >
                            <span
                                v-if='saving'
                                class='spinner-border spinner-border-sm me-1'
                            />Close Incident
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
            </template>

            <!-- ── Responder Manager ───────────────────────────────── -->
            <template v-else-if='view === "responders" && detailIncident'>
                <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                    <button
                        class='btn btn-sm btn-outline-secondary'
                        @click='view = "detail"'
                    >
                        ← Back
                    </button>
                    <span class='fw-semibold'>Assign Responders</span>
                </div>
                <div class='flex-grow-1 overflow-auto p-3 d-flex flex-column gap-3'>
                    <!-- Vehicles -->
                    <div class='small text-muted fw-semibold text-uppercase'>
                        Vehicles
                    </div>
                    <div
                        v-for='veh in vehicles'
                        :key='veh.uid'
                        class='d-flex align-items-center gap-2 py-1 border-bottom border small'
                    >
                        <input
                            type='checkbox'
                            :checked='isVehicleAssigned(veh.uid)'
                            class='form-check-input mt-0'
                            @change='toggleVehicle(veh.uid)'
                        >
                        <span class=''>{{ veh.callsign }}</span>
                        <span
                            v-if='veh.vehicleType'
                            class='text-muted'
                        >{{ veh.vehicleType.name }}</span>
                        <span
                            v-if='veh.incidentsRequestingThisVehicle?.length'
                            class='ms-auto badge bg-warning text-dark small'
                        >{{ veh.incidentsRequestingThisVehicle.length }} inc</span>
                    </div>
                    <div
                        v-if='!vehicles.length'
                        class='text-muted small'
                    >
                        No vehicles registered
                    </div>

                    <!-- Personnel -->
                    <div class='small text-muted fw-semibold text-uppercase'>
                        Personnel
                    </div>
                    <div
                        v-for='person in personnel'
                        :key='person.uid'
                        class='d-flex align-items-center gap-2 py-1 border-bottom border small'
                    >
                        <input
                            type='checkbox'
                            :checked='isPersonnelAssigned(person.uid)'
                            class='form-check-input mt-0'
                            @change='togglePersonnel(person.uid, person.callsign)'
                        >
                        <span class=''>{{ person.callsign }}</span>
                        <span
                            v-if='person.roles?.length'
                            class='text-muted'
                        >{{ person.roles.map(r => r.name).join(', ') }}</span>
                    </div>
                    <div
                        v-if='!personnel.length'
                        class='text-muted small'
                    >
                        No personnel registered
                    </div>

                    <div
                        v-if='detailError'
                        class='alert alert-danger py-2 small'
                    >
                        {{ detailError }}
                    </div>
                    <button
                        class='btn btn-sm btn-warning'
                        :disabled='saving'
                        @click='saveResponders'
                    >
                        <span
                            v-if='saving'
                            class='spinner-border spinner-border-sm me-1'
                        />Save Assignments
                    </button>
                </div>
            </template>

            <!-- ── Incident Form (takcad) ─────────────────────────── -->
            <template v-else-if='view === "form"'>
                <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                    <button
                        class='btn btn-sm btn-outline-secondary'
                        @click='cancelForm'
                    >
                        ← Back
                    </button>
                    <span class='fw-semibold'>{{ editUid ? 'Edit Incident' : 'New Incident' }}</span>
                </div>
                <div class='flex-grow-1 overflow-auto p-3'>
                    <IncidentForm
                        :uid='editUid'
                        :server-mode='serverMode'
                        :incident-types='incidentTypes'
                        :active-feed='dispatcherStore.activeFeed'
                        @saved='onFormSaved'
                        @cancel='cancelForm'
                    />
                </div>
            </template>
        </template>

        <!-- ── Standalone mode: CloudTAK-native UI ─────────────────────────── -->
        <template v-else-if='serverMode === "standalone"'>
            <!-- Feed gate: require DataSync feed before dispatching -->
            <div
                v-if='!dispatcherStore.activeFeed'
                class='text-center text-muted py-4 small px-3'
            >
                Select a DataSync Feed above to begin dispatching.
            </div>

            <!-- Standalone incident list / form (only when feed is selected) -->
            <template v-else-if='slView === "list"'>
                <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0'>
                    <span class='text-muted small me-auto'>{{ slActiveIncidents.length }} active</span>
                    <button
                        class='btn btn-sm btn-warning'
                        @click='slView = "form"'
                    >
                        + New
                    </button>
                </div>
                <div class='flex-grow-1 overflow-auto'>
                    <div
                        v-if='!slActiveIncidents.length'
                        class='text-center text-muted py-4 small'
                    >
                        No incidents this session
                    </div>
                    <div
                        v-for='inc in slActiveIncidents'
                        :key='inc.uid'
                        class='d-flex align-items-start px-3 py-2 border-bottom incident-row'
                        role='button'
                        @click='slOpenDetail(inc.uid)'
                    >
                        <div class='flex-grow-1 overflow-hidden'>
                            <div class='d-flex align-items-center gap-2'>
                                <span class='fw-semibold small text-truncate'>{{ inc.name }}</span>
                                <span class='badge bg-success text-white small'>{{ inc.status }}</span>
                            </div>
                            <div class='small text-muted text-truncate'>
                                {{ inc.address || `${inc.lat.toFixed(5)}, ${inc.lon.toFixed(5)}` }}
                            </div>
                            <div class='small text-muted'>
                                {{ inc.type }} · {{ shortTime(inc.time) }}
                            </div>
                        </div>
                    </div>
                </div>
            </template>

            <!-- Standalone incident detail -->
            <template v-else-if='slView === "detail" && slDetail'>
                <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                    <button
                        class='btn btn-sm btn-outline-secondary'
                        @click='slView = "list"'
                    >
                        ← Back
                    </button>
                    <span class='fw-semibold text-truncate flex-grow-1'>{{ slDetail.name }}</span>
                    <span class='badge bg-success text-white'>{{ slDetail.status }}</span>
                </div>
                <div class='flex-grow-1 overflow-auto p-3 d-flex flex-column gap-3'>
                    <div class='card border'>
                        <div class='card-body py-2 px-3 small d-flex flex-column gap-1'>
                            <div class='row g-1'>
                                <div class='col-4 text-muted'>
                                    Type
                                </div>
                                <div class='col-8'>
                                    {{ slDetail.type }}
                                </div>
                                <div class='col-4 text-muted'>
                                    Time
                                </div>
                                <div class='col-8'>
                                    {{ formatTime(slDetail.time) }}
                                </div>
                                <div class='col-4 text-muted'>
                                    Address
                                </div>
                                <div class='col-8'>
                                    {{ slDetail.address || '—' }}
                                </div>
                                <div class='col-4 text-muted'>
                                    Coords
                                </div>
                                <div
                                    class='col-8 font-monospace text-muted'
                                    style='font-size:11px'
                                >
                                    {{ slDetail.lat.toFixed(6) }}, {{ slDetail.lon.toFixed(6) }}
                                </div>
                            </div>
                        </div>
                    </div>
                    <!-- Notes log -->
                    <div
                        v-if='slDetail.notes.length'
                        class='border-top pt-2 mt-2'
                    >
                        <div class='small text-muted mb-1'>Notes</div>
                        <div
                            v-for='(n, i) in slDetail.notes'
                            :key='i'
                            class='small mb-1'
                        >
                            <span class='text-muted'>{{ shortTime(n.time) }}</span>
                            {{ n.text }}
                        </div>
                    </div>

                    <!-- Add note -->
                    <div class='d-flex gap-1 mt-2'>
                        <input
                            v-model='slNoteInput'
                            type='text'
                            class='form-control form-control-sm border flex-grow-1'
                            placeholder='Add note…'
                            @keydown.enter='slAddNote(slDetail)'
                        >
                        <button
                            class='btn btn-sm btn-outline-secondary'
                            :disabled='!slNoteInput.trim()'
                            @click='slAddNote(slDetail)'
                        >
                            Add
                        </button>
                    </div>

                    <!-- Assigned Units -->
                    <div class='border-top pt-2 mt-3'>
                        <div class='small text-muted mb-1 fw-semibold'>
                            Assigned Units
                        </div>
                        <div
                            v-for='c in slDetail.assignedContacts'
                            :key='c.uid'
                            class='d-flex align-items-center gap-2 small py-1 border-bottom'
                        >
                            <span class='flex-grow-1'>{{ c.callsign }}</span>
                            <button
                                class='btn btn-link btn-sm p-0 text-danger text-decoration-none'
                                @click='slUnassignContact(slDetail, c.uid)'
                            >
                                ✕
                            </button>
                        </div>
                        <div
                            v-if='!slDetail.assignedContacts.length'
                            class='text-muted small py-1'
                        >
                            No units assigned
                        </div>

                        <!-- Assign: free-text search + contacts picker button -->
                        <div class='d-flex gap-1 mt-2'>
                            <input
                                v-model='slContactSearch'
                                type='text'
                                class='form-control form-control-sm border'
                                :placeholder='loadingContacts ? "Loading contacts…" : "Search contacts to assign…"'
                                :disabled='loadingContacts'
                            >
                            <button
                                class='btn btn-sm btn-outline-secondary d-flex align-items-center'
                                :class='{ active: showContactPicker }'
                                :disabled='loadingContacts'
                                title='Pick from contacts'
                                @click='toggleContactPicker'
                            >
                                <IconUsers :size='16' />
                            </button>
                        </div>
                        <div
                            v-if='filteredContacts.length && slContactSearch'
                            class='border rounded mt-1'
                            style='max-height:120px;overflow-y:auto'
                        >
                            <button
                                v-for='c in filteredContacts'
                                :key='c.uid'
                                class='btn btn-sm w-100 text-start px-2 py-1 border-0 border-bottom rounded-0'
                                style='font-size:12px'
                                @click='slAssignContact(slDetail, c)'
                            >
                                + {{ c.callsign }}
                            </button>
                        </div>

                        <!-- Multi-select contacts picker (mirrors CloudTAK's contacts tool) -->
                        <div
                            v-if='showContactPicker'
                            class='border rounded mt-1'
                        >
                            <div class='small text-muted px-2 py-1 border-bottom d-flex align-items-center'>
                                <span class='flex-grow-1'>Select units to assign</span>
                                <span>{{ pickerSelected.length }} selected</span>
                            </div>
                            <div style='max-height:160px;overflow-y:auto'>
                                <label
                                    v-for='c in assignablePickerContacts'
                                    :key='c.uid'
                                    class='d-flex align-items-center gap-2 px-2 py-1 border-bottom small mb-0'
                                    style='cursor:pointer'
                                >
                                    <input
                                        type='checkbox'
                                        class='form-check-input mt-0'
                                        :checked='pickerSelected.includes(c.uid)'
                                        @change='togglePickerContact(c.uid)'
                                    >
                                    <span class='flex-grow-1'>{{ c.callsign }}</span>
                                </label>
                                <div
                                    v-if='!assignablePickerContacts.length'
                                    class='text-muted small px-2 py-2'
                                >
                                    {{ loadingContacts ? 'Loading contacts…' : 'No contacts available' }}
                                </div>
                            </div>
                            <div class='d-flex align-items-center gap-2 p-2 border-top'>
                                <button
                                    class='btn btn-sm btn-link text-muted p-0 text-decoration-none'
                                    @click='showContactPicker = false'
                                >
                                    Cancel
                                </button>
                                <button
                                    class='btn btn-sm btn-primary ms-auto'
                                    :disabled='!pickerSelected.length'
                                    @click='slAssignSelected(slDetail)'
                                >
                                    Assign {{ pickerSelected.length || '' }} selected
                                </button>
                            </div>
                        </div>
                    </div>

                    <div class='d-flex gap-2 mt-2'>
                        <button
                            class='btn btn-sm btn-outline-secondary'
                            @click='flyToIncident(slDetail)'
                        >
                            Show on Map
                        </button>
                        <button
                            class='btn btn-sm btn-warning ms-auto'
                            @click='slCloseIncident(slDetail)'
                        >
                            Close Incident
                        </button>
                    </div>
                </div>
            </template>

            <!-- Standalone incident form -->
            <template v-else-if='slView === "form"'>
                <div class='d-flex align-items-center px-3 py-2 border-bottom flex-shrink-0 gap-2'>
                    <button
                        class='btn btn-sm btn-outline-secondary'
                        @click='slView = "list"'
                    >
                        ← Back
                    </button>
                    <span class='fw-semibold'>New Incident</span>
                </div>
                <div class='flex-grow-1 overflow-auto p-3'>
                    <IncidentForm
                        :server-mode='serverMode'
                        :incident-types='incidentTypes'
                        :active-feed='dispatcherStore.activeFeed'
                        @saved-standalone='onStandaloneSaved'
                        @cancel='slView = "list"'
                    />
                </div>
            </template>
        </template>

        <!-- ── Detecting state ─────────────────────────────────────────────── -->
        <template v-else>
            <div class='text-center text-muted py-4 small'>
                <span class='spinner-border spinner-border-sm me-2' />Connecting…
            </div>
        </template>
    </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue';
import { IconUsers } from '@tabler/icons-vue';
import { useMapStore } from '../../../src/stores/map.ts';
import IncidentForm from './IncidentForm.vue';
import {
    getIncidentMetadata, getIncident,
    updateIncident, deleteIncident,
    insertVehicleResponse, deleteVehicleResponse,
    postMissionLog,
} from '../lib/takcad-client.ts';
import type { VehicleResponseMetadata } from '../lib/takcad-client.ts';
import { removeIncidentMarker, updateIncidentMarker } from '../lib/map-marker.ts';
import { getContacts, sendAssignmentMessage } from '../lib/contacts-client.ts';
import type { TakContact } from '../lib/contacts-client.ts';
import type { IncidentMetadata, IncidentRef, VehicleRef, PersonRef, IncidentTypeRef, PersonCallsign } from '../lib/takcad-types.ts';
import { isActive, formatAddress, formatTime, STATUS_CANCELLED } from '../lib/takcad-types.ts';
import { dispatcherStore } from '../lib/dispatcher-store.ts';
import type { LocalIncident } from '../lib/dispatcher-store.ts';

const props = defineProps<{
    serverMode:    'detecting' | 'takcad' | 'standalone';
    incidentTypes: IncidentTypeRef[];
    vehicles:      VehicleRef[];
    personnel:     PersonRef[];
}>();

const emit = defineEmits<{
    (e: 'active-count', n: number): void;
    (e: 'status',       s: string): void;
}>();

const mapStore = useMapStore();

// ── TAK-CAD mode state ────────────────────────────────────────────────────────
type ViewName = 'list' | 'detail' | 'form' | 'responders';
type ListTab  = 'active' | 'cancelled';

const SORT_COLS = [
    { key: 'time',    label: 'Time'    },
    { key: 'address', label: 'Address' },
    { key: 'type',    label: 'Type'    },
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

const pendingVehicleUids    = ref<string[]>([]);
const vehicleResponseUids   = ref<Map<string, string>>(new Map());
const pendingPersonnelItems = ref<PersonCallsign[]>([]);

const activeIncidents    = computed(() => incidents.value.filter(i => isActive(i.status)));
const cancelledIncidents = computed(() => incidents.value.filter(i => !isActive(i.status)));

const displayedIncidents = computed(() => {
    const src = listTab.value === 'active' ? activeIncidents.value : cancelledIncidents.value;
    return [...src].sort((a, b) => {
        let av = '', bv = '';
        if (sortCol.value === 'time')    { av = a.incidentTime; bv = b.incidentTime; }
        if (sortCol.value === 'address') { av = formatAddress(a.location); bv = formatAddress(b.location); }
        if (sortCol.value === 'type')    { av = a.incidentType ?? ''; bv = b.incidentType ?? ''; }
        return sortAsc.value ? av.localeCompare(bv) : bv.localeCompare(av);
    });
});

watch(activeIncidents, n => {
    if (props.serverMode === 'takcad') emit('active-count', n.length);
}, { immediate: true });

function toggleSort(col: SortCol) {
    if (sortCol.value === col) sortAsc.value = !sortAsc.value;
    else { sortCol.value = col; sortAsc.value = col !== 'time'; }
}

function statusBadge(status: string) {
    if (status === 'ACTIVE')    return 'bg-success text-white';
    if (status === 'CANCELLED') return 'bg-secondary text-white';
    return 'bg-warning text-dark';
}

function shortTime(iso: string): string {
    try { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
    catch { return iso; }
}

async function loadList() {
    loading.value = true; loadError.value = '';
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
    try { detailIncident.value = await getIncident(uid); }
    catch (e) { detailError.value = e instanceof Error ? e.message : String(e); }
}

function openCreate() { editUid.value = undefined; view.value = 'form'; }
function openEdit()   { if (!detailIncident.value) return; editUid.value = detailIncident.value.uid; view.value = 'form'; }
function cancelForm() { view.value = detailIncident.value ? 'detail' : 'list'; }

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
        const check = await getIncident(detailIncident.value.uid);
        if (isActive(check.status)) {
            detailError.value = 'The TAK-CAD server accepted the update but didn\'t change the status — cancelling incidents isn\'t supported by this server build.';
        } else {
            detailIncident.value = check;
            await loadList();
        }
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
        const msg = e instanceof Error ? e.message : String(e);
        detailError.value = msg.includes('PluginManager process')
            ? 'Delete isn\'t supported by the TAK Server plugin on this build. Use "Close Incident" to cancel it instead.'
            : msg;
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

watch(view, (v) => {
    if (v === 'responders' && detailIncident.value) {
        const resMap = new Map<string, string>();
        (detailIncident.value.vehiclesResponding ?? []).forEach(vr => {
            resMap.set(vr.vehicle.vehicleUid, vr.uid);
        });
        vehicleResponseUids.value   = resMap;
        pendingVehicleUids.value    = [...resMap.keys()];
        pendingPersonnelItems.value = [...(detailIncident.value.personnelResponding ?? [])];
    }
});

function isVehicleAssigned(uid: string)   { return pendingVehicleUids.value.includes(uid); }
function isPersonnelAssigned(uid: string) { return pendingPersonnelItems.value.some(p => p.personUid === uid); }

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
    const incidentUid = detailIncident.value.uid;
    const prevUids    = [...vehicleResponseUids.value.keys()];
    const toAdd       = pendingVehicleUids.value.filter(uid => !prevUids.includes(uid));
    const toRemove    = prevUids.filter(uid => !pendingVehicleUids.value.includes(uid));
    try {
        for (const vehUid of toRemove) {
            const respUid = vehicleResponseUids.value.get(vehUid);
            if (respUid) await deleteVehicleResponse(respUid);
        }
        for (const vehUid of toAdd) {
            const veh = props.vehicles.find(v => v.uid === vehUid);
            const meta: VehicleResponseMetadata = {
                uid:            crypto.randomUUID(),
                callsign:       veh?.callsign ?? '',
                vehicleUid:     vehUid,
                incidentUid,
                responseStatus: 'IN_ROUTE',
                eta:            null,
                arrivalTime:    null,
            };
            await insertVehicleResponse(meta);
        }
        detailIncident.value = await getIncident(incidentUid);
        view.value = 'detail';
    } catch (e) {
        detailError.value = e instanceof Error ? e.message : String(e);
    } finally {
        saving.value = false;
    }
}

async function refreshDetail() {
    if (detailIncident.value && view.value === 'detail') {
        try { detailIncident.value = await getIncident(detailIncident.value.uid); }
        catch { /* stale display ok */ }
    }
}

// ── Standalone mode state ─────────────────────────────────────────────────────
type SlViewName = 'list' | 'detail' | 'form';

const slView           = ref<SlViewName>('list');
const slDetail         = ref<LocalIncident | null>(null);
const slNoteInput      = ref('');
const slContactSearch  = ref('');
const allContacts      = ref<TakContact[]>([]);
const loadingContacts  = ref(false);
const showContactPicker = ref(false);
const pickerSelected    = ref<string[]>([]);

const filteredContacts = computed(() => {
    const q = slContactSearch.value.toLowerCase();
    const assigned = new Set((slDetail.value?.assignedContacts ?? []).map(c => c.uid));
    return allContacts.value.filter(c =>
        !assigned.has(c.uid) &&
        (!q || c.callsign.toLowerCase().includes(q))
    );
});

// Contacts not yet assigned — the multi-select picker's candidate list.
const assignablePickerContacts = computed(() => {
    const assigned = new Set((slDetail.value?.assignedContacts ?? []).map(c => c.uid));
    return allContacts.value.filter(c => !assigned.has(c.uid));
});

function toggleContactPicker() {
    showContactPicker.value = !showContactPicker.value;
    pickerSelected.value = [];
}

function togglePickerContact(uid: string) {
    const i = pickerSelected.value.indexOf(uid);
    if (i === -1) pickerSelected.value.push(uid);
    else pickerSelected.value.splice(i, 1);
}

async function slAssignSelected(inc: LocalIncident) {
    const chosen = allContacts.value.filter(c => pickerSelected.value.includes(c.uid));
    for (const c of chosen) {
        await slAssignContact(inc, c);
    }
    pickerSelected.value = [];
    showContactPicker.value = false;
}

const slActiveIncidents = computed(() =>
    dispatcherStore.localIncidents.filter(i => i.status === 'ACTIVE')
);

watch(slActiveIncidents, n => {
    if (props.serverMode === 'standalone') emit('active-count', n.length);
}, { immediate: true });


async function slOpenDetail(uid: string) {
    slDetail.value = dispatcherStore.localIncidents.find(i => i.uid === uid) ?? null;
    slView.value = 'detail';
    slContactSearch.value = '';
    showContactPicker.value = false;
    pickerSelected.value = [];
    if (!allContacts.value.length) {
        loadingContacts.value = true;
        try { allContacts.value = await getContacts(); }
        catch { allContacts.value = []; }
        finally { loadingContacts.value = false; }
    }
}

async function slAssignContact(inc: LocalIncident, contact: TakContact) {
    if (inc.assignedContacts.some(c => c.uid === contact.uid)) return;
    inc.assignedContacts.push({ uid: contact.uid, callsign: contact.callsign });
    inc.notes.push({ text: `${contact.callsign} was assigned`, time: new Date().toISOString() });
    slContactSearch.value = '';

    // GeoChat assignment message
    try {
        await sendAssignmentMessage(mapStore, contact, { name: `${inc.number} ${inc.type}`, address: inc.address });
    } catch (e) { console.warn('[dispatcher] assignment message failed', e); }

    // Update CoT marker remarks with responders
    const responders = inc.assignedContacts.map(c => c.callsign).join(', ');
    const updatedDetails = [inc.details, `Responding: ${responders}`].filter(Boolean).join('\n');
    try { await updateIncidentMarker(mapStore, { ...inc, details: updatedDetails, feedGuid: dispatcherStore.activeFeed?.guid }); }
    catch { /* best-effort */ }

    // DataSync log
    const feed = dispatcherStore.activeFeed;
    if (feed) {
        try { await postMissionLog(feed.name, `ASSIGNED: ${inc.number} → ${contact.callsign}`); }
        catch { /* best-effort */ }
    }
}

async function slUnassignContact(inc: LocalIncident, uid: string) {
    const contact = inc.assignedContacts.find(c => c.uid === uid);
    inc.assignedContacts = inc.assignedContacts.filter(c => c.uid !== uid);

    const feed = dispatcherStore.activeFeed;
    if (feed && contact) {
        try { await postMissionLog(feed.name, `UNASSIGNED: ${inc.number} → ${contact.callsign}`); }
        catch { /* best-effort */ }
    }

    // Update marker remarks
    const responders = inc.assignedContacts.map(c => c.callsign).join(', ');
    const updatedDetails = [inc.details, responders ? `Responding: ${responders}` : ''].filter(Boolean).join('\n');
    try { await updateIncidentMarker(mapStore, { ...inc, details: updatedDetails, feedGuid: dispatcherStore.activeFeed?.guid }); }
    catch { /* best-effort */ }
}

async function slAddNote(inc: LocalIncident) {
    const text = slNoteInput.value.trim();
    if (!text) return;
    const time = new Date().toISOString();
    inc.notes.push({ text, time });
    slNoteInput.value = '';

    // Update CoT marker with latest notes appended to details
    const updatedDetails = [inc.details, ...inc.notes.map(n => n.text)].filter(Boolean).join('\n');
    try {
        await updateIncidentMarker(mapStore, { ...inc, details: updatedDetails, feedGuid: dispatcherStore.activeFeed?.guid });
    } catch { /* best-effort */ }

    // DataSync log entry
    const feed = dispatcherStore.activeFeed;
    if (feed) {
        try { await postMissionLog(feed.name, `UPDATE ${inc.number}: ${text}`); }
        catch { /* best-effort */ }
    }
}

async function slCloseIncident(inc: LocalIncident) {
    const idx = dispatcherStore.localIncidents.findIndex(i => i.uid === inc.uid);
    if (idx !== -1) dispatcherStore.localIncidents[idx].status = 'CANCELLED';

    // Remove CoT marker
    try { await removeIncidentMarker(mapStore, { ...inc, feedGuid: dispatcherStore.activeFeed?.guid }); } catch { /* best-effort */ }

    // DataSync log entry
    const feed = dispatcherStore.activeFeed;
    if (feed) {
        try {
            const closedAt = new Date();
            const startMs = new Date(inc.time).getTime();
            const durMin = Math.round((closedAt.getTime() - startMs) / 60000);
            const hhmm = `${String(closedAt.getHours()).padStart(2, '0')}:${String(closedAt.getMinutes()).padStart(2, '0')}`;
            await postMissionLog(feed.name, `INCIDENT CLOSED: ${inc.number} | ${inc.name} | Closed ${hhmm} | ${durMin} min`);
        } catch { /* best-effort */ }
    }

    slView.value = 'list';
}

function flyToIncident(inc: LocalIncident) {
    mapStore.map?.flyTo({ center: [inc.lon, inc.lat], zoom: 15 });
}

function onStandaloneSaved(inc: LocalIncident) {
    dispatcherStore.localIncidents.push(inc);
    slView.value = 'list';
}

// ── Polling ───────────────────────────────────────────────────────────────────
let pollTimer: ReturnType<typeof setInterval>;

onMounted(() => {
    if (props.serverMode === 'takcad') {
        loadList();
        pollTimer = setInterval(() => { loadList(); refreshDetail(); }, 15_000);
    }
});

onUnmounted(() => clearInterval(pollTimer));

// Start polling when mode resolves to takcad
watch(() => props.serverMode, (mode) => {
    if (mode === 'takcad' && !pollTimer) {
        loadList();
        pollTimer = setInterval(() => { loadList(); refreshDetail(); }, 15_000);
    }
});
</script>

<style scoped>
.incident-row:hover { background: rgba(255,255,255,.05); cursor: pointer; }
</style>
