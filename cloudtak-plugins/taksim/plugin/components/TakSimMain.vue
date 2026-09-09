<template>
    <component
        :is='floating ? "div" : MenuTemplate'
        v-bind='floating ? {} : { name: "TAK Simulator" }'
        :class='floating ? "overflow-auto h-100" : ""'
    >
        <div class='px-2 pb-3'>
            <!-- ── errors / notices ─────────────────────────────────────────── -->
            <div
                v-if='error'
                class='alert alert-danger py-2 px-2 small mb-2'
                style='white-space:pre-wrap'
            >
                <div class='d-flex align-items-start gap-2'>
                    <div class='flex-grow-1'>
                        {{ error }}
                    </div>
                    <button
                        class='btn btn-sm btn-link p-0 text-danger'
                        @click='error = ""'
                    >
                        ✕
                    </button>
                </div>
            </div>
            <div
                v-if='notice'
                class='alert alert-success py-2 px-2 small mb-2'
            >
                {{ notice }}
            </div>

            <!-- ── map-click banner ─────────────────────────────────────────── -->
            <div
                v-if='picking'
                class='alert alert-warning py-2 px-2 small mb-2 d-flex align-items-center gap-2'
            >
                <IconCrosshair :size='16' />
                <div class='flex-grow-1'>
                    <span v-if='!picking.multi'>Click the map to place <strong>{{ picking.label }}</strong>.</span>
                    <span v-else>Click the map to add points for <strong>{{ picking.label }}</strong> ({{ picking.count }} so far, {{ picking.min }} needed) — Enter or Esc finishes.</span>
                </div>
                <button
                    class='btn btn-sm btn-outline-secondary'
                    @click='cancelPick'
                >
                    Cancel
                </button>
            </div>

            <!-- ── floating elsewhere: this anchored view collapses so the panel is not driven twice ── -->
            <div
                v-if='floatedElsewhere'
                class='p-3 text-center text-muted small d-flex flex-column align-items-center gap-2'
            >
                <span>The simulator panel is floating over the map.</span>
                <button
                    class='btn btn-sm btn-outline-primary'
                    @click='dockSim()'
                >
                    Dock back to panel
                </button>
            </div>

            <!-- ── not installed ────────────────────────────────────────────── -->
            <div
                v-else-if='status && !status.installed'
                class='alert alert-secondary small'
            >
                TAK Simulator is not deployed on this box. Deploy it from the infra-TAK console
                (<a
                    :href='consoleUrl'
                    target='_blank'
                    rel='noopener'
                >Simulator page</a>), then reload CloudTAK.
            </div>

            <template v-else>
                <!-- ── 1. Session ───────────────────────────────────────────── -->
                <div class='card mb-2'>
                    <div class='card-header py-2 px-2 d-flex align-items-center gap-2'>
                        <IconRadar
                            :size='16'
                            class='text-primary'
                        />
                        <span class='fw-semibold'>Session</span>
                        <span
                            class='badge ms-auto'
                            :class='stateBadgeClass'
                        >{{ stateLabel }}</span>
                        <button
                            v-if='!floating'
                            class='btn btn-sm btn-link p-0 text-muted'
                            title='Pop the panel out as a floating window over the map'
                            @click='popOutSim()'
                        >
                            <IconExternalLink :size='16' />
                        </button>
                    </div>
                    <div class='card-body py-2 px-2 small'>
                        <div
                            v-if='status && status.run'
                            class='mb-2'
                        >
                            <div>
                                <strong>{{ status.run.title }}</strong>
                                <span class='text-muted'> · t+{{ Math.round(status.run.sim_t) }}s · {{ status.run.tempo }}× · {{ status.run.entities_alive }} unit(s), {{ status.run.persistent_objects }} object(s)</span>
                            </div>
                            <div class='text-muted'>
                                <span
                                    v-for='ln in status.run.lanes'
                                    :key='ln.id'
                                    class='me-2'
                                >
                                    lane {{ ln.id }} → <code>{{ channelName(ln.channel) }}</code>
                                    <span
                                        v-if='ln.exercise'
                                        class='badge bg-warning text-dark ms-1'
                                    >EXERCISE</span>
                                    <span
                                        :class='ln.connected ? "text-success" : "text-danger"'
                                    > ●</span>
                                </span>
                            </div>
                        </div>
                        <div
                            v-else
                            class='text-muted mb-2'
                        >
                            No session. Lanes enrolled: {{ (status && status.lanes_enrolled.length) ? status.lanes_enrolled.join(', ') : 'none' }} · default channel <code>{{ simChannel }}</code>
                        </div>

                        <div
                            v-if='channelWarning'
                            class='alert alert-warning py-1 px-2 small mb-2'
                        >
                            {{ channelWarning }}
                        </div>

                        <div
                            v-if='confirmNeeded'
                            class='alert alert-warning py-2 px-2 small mb-2'
                        >
                            <div class='mb-1'>
                                A lane targets a real channel. Type <code>{{ confirmNeeded }}</code> to confirm sending EXERCISE-marked traffic there:
                            </div>
                            <input
                                v-model='confirmText'
                                class='form-control form-control-sm'
                                :placeholder='confirmNeeded'
                            >
                        </div>

                        <div class='d-flex flex-wrap gap-1 align-items-center mb-2'>
                            <button
                                class='btn btn-sm btn-primary'
                                :disabled='busy || running'
                                @click='doStartLive'
                            >
                                Start live session
                            </button>
                            <select
                                v-model='tempo'
                                class='form-select form-select-sm w-auto'
                                :disabled='busy'
                                @change='onTempoChange'
                            >
                                <option
                                    v-for='t in TEMPOS'
                                    :key='t'
                                    :value='t'
                                >
                                    {{ t }}×
                                </option>
                            </select>
                            <button
                                v-if='status && status.state === "running"'
                                class='btn btn-sm btn-outline-secondary'
                                :disabled='busy'
                                @click='doPause'
                            >
                                Pause
                            </button>
                            <button
                                v-if='status && status.state === "paused"'
                                class='btn btn-sm btn-outline-secondary'
                                :disabled='busy'
                                @click='doResume'
                            >
                                Resume
                            </button>
                            <button
                                class='btn btn-sm btn-danger ms-auto'
                                :disabled='busy || !running'
                                title='Stop and clear everything — a delete goes out for every unit and object'
                                @click='doStop'
                            >
                                Stop (clears everything)
                            </button>
                        </div>

                        <div class='d-flex gap-1 align-items-center'>
                            <select
                                v-model='presetName'
                                class='form-select form-select-sm'
                                :disabled='busy || running'
                            >
                                <option value=''>
                                    Load preset…
                                </option>
                                <option
                                    v-for='sc in scenarios'
                                    :key='sc.name'
                                    :value='sc.name'
                                    :disabled='!sc.valid'
                                >
                                    {{ sc.title || sc.name }} ({{ sc.entities }} units{{ sc.sensors_detecting ? `, ${sc.sensors_detecting} detecting` : '' }}{{ sc.silent ? `, ${sc.silent} silent` : '' }}, {{ Math.round((sc.duration_s || 0) / 60) }} min{{ sc.valid ? '' : ' — invalid' }})
                                </option>
                            </select>
                            <button
                                class='btn btn-sm btn-outline-primary text-nowrap'
                                :disabled='busy || running || !presetName'
                                @click='doRunPreset'
                            >
                                Run at map center
                            </button>
                            <button
                                class='btn btn-sm btn-outline-secondary text-nowrap'
                                :disabled='busy || running || !presetName'
                                title='Start a live session with this scenario already placed at the map center — move units, add or remove them, then save it as a new layout'
                                @click='doOpenForEditing'
                            >
                                Open for editing
                            </button>
                        </div>
                    </div>
                </div>

                <!-- ── 2. Add unit ──────────────────────────────────────────── -->
                <div class='card mb-2'>
                    <div
                        class='card-header py-2 px-2 d-flex align-items-center gap-2 cursor-pointer'
                        @click='showAdd = !showAdd'
                    >
                        <IconPlus :size='16' />
                        <span class='fw-semibold'>Add unit</span>
                        <span class='ms-auto text-muted small'>{{ showAdd ? '▾' : '▸' }}</span>
                    </div>
                    <div
                        v-if='showAdd'
                        class='card-body py-2 px-2 small'
                    >
                        <div class='row g-1 mb-1'>
                            <div class='col-6'>
                                <label class='form-label mb-0'>Type</label>
                                <select
                                    v-model='form.kind'
                                    class='form-select form-select-sm'
                                >
                                    <optgroup
                                        v-for='g in UNIT_GROUPS'
                                        :key='g'
                                        :label='g'
                                    >
                                        <option
                                            v-for='k in UNIT_KINDS.filter(u => u.group === g)'
                                            :key='k.key'
                                            :value='k.key'
                                        >
                                            {{ k.label }}
                                        </option>
                                    </optgroup>
                                </select>
                            </div>
                            <div class='col-6'>
                                <label class='form-label mb-0'>Callsign</label>
                                <input
                                    v-model='form.callsign'
                                    class='form-control form-control-sm'
                                    maxlength='32'
                                >
                            </div>
                            <div class='col-4'>
                                <label class='form-label mb-0'>Team</label>
                                <select
                                    v-model='form.team'
                                    class='form-select form-select-sm'
                                >
                                    <option
                                        v-for='t in TEAMS'
                                        :key='t'
                                        :value='t'
                                    >
                                        {{ t }}
                                    </option>
                                </select>
                            </div>
                            <div class='col-4'>
                                <label class='form-label mb-0'>Altitude (ft)</label>
                                <input
                                    v-model.number='form.altFt'
                                    type='number'
                                    class='form-control form-control-sm'
                                >
                            </div>
                            <div class='col-4'>
                                <label class='form-label mb-0'>Speed (kt)</label>
                                <input
                                    v-model.number='form.speedKt'
                                    type='number'
                                    class='form-control form-control-sm'
                                >
                            </div>
                        </div>
                        <div class='d-flex flex-wrap gap-2 align-items-center mb-1'>
                            <label
                                class='form-check form-check-inline mb-0'
                                title='A hidden target never reports itself — it is on the map only as the track of a sensor that sees it'
                            >
                                <input
                                    v-model='form.silent'
                                    type='checkbox'
                                    class='form-check-input'
                                >
                                <span class='form-check-label'>Hidden target</span>
                            </label>
                            <template v-if='form.silent'>
                                <span>seen as</span>
                                <select
                                    v-model='form.detectedType'
                                    class='form-select form-select-sm w-auto'
                                >
                                    <option value=''>
                                        unknown (by domain)
                                    </option>
                                    <option value='a-u-S'>
                                        unknown surface
                                    </option>
                                    <option value='a-u-A'>
                                        unknown air
                                    </option>
                                    <option value='a-u-G'>
                                        unknown ground
                                    </option>
                                </select>
                            </template>
                            <label
                                v-else
                                class='form-check form-check-inline mb-0'
                                title='A person with a TAK device reports team and role and draws as the team marker; a ship, aircraft, vehicle or sensor draws as its 2525 symbol'
                            >
                                <input
                                    v-model='form.eud'
                                    type='checkbox'
                                    class='form-check-input'
                                >
                                <span class='form-check-label'>Team marker (TAK user)</span>
                            </label>
                        </div>
                        <div class='d-flex flex-wrap gap-2 align-items-center mb-1'>
                            <label class='form-check form-check-inline mb-0'>
                                <input
                                    v-model='form.sensorOn'
                                    type='checkbox'
                                    class='form-check-input'
                                >
                                <span class='form-check-label'>Sensor cone</span>
                            </label>
                            <template v-if='form.sensorOn'>
                                <span>FOV°</span>
                                <input
                                    v-model.number='form.fov'
                                    type='number'
                                    class='form-control form-control-sm w-auto'
                                    style='width:70px!important'
                                >
                                <span>range m</span>
                                <input
                                    v-model.number='form.rangeM'
                                    type='number'
                                    class='form-control form-control-sm'
                                    style='width:90px'
                                >
                                <span>sweep °/s</span>
                                <input
                                    v-model.number='form.sweep'
                                    type='number'
                                    class='form-control form-control-sm'
                                    style='width:70px'
                                >
                            </template>
                        </div>
                        <div
                            v-if='form.sensorOn'
                            class='d-flex flex-wrap gap-2 align-items-center mb-1'
                        >
                            <label
                                class='form-check form-check-inline mb-0'
                                title='Hidden targets inside the cone become tracks named by this sensor (one track per sensor that sees them)'
                            >
                                <input
                                    v-model='form.detectOn'
                                    type='checkbox'
                                    class='form-check-input'
                                >
                                <span class='form-check-label'>Detects</span>
                            </label>
                            <template v-if='form.detectOn'>
                                <label
                                    v-for='k in DETECT_KINDS'
                                    :key='k'
                                    class='form-check form-check-inline mb-0'
                                >
                                    <input
                                        v-model='form.detKinds'
                                        type='checkbox'
                                        class='form-check-input'
                                        :value='k'
                                    >
                                    <span class='form-check-label'>{{ k }}</span>
                                </label>
                                <span title='position error the track is reported with (1 sigma)'>± m</span>
                                <input
                                    v-model.number='form.detErr'
                                    type='number'
                                    min='0'
                                    max='5000'
                                    class='form-control form-control-sm'
                                    style='width:70px'
                                >
                                <span title='chance a look inside the cone acquires the target'>hit %</span>
                                <input
                                    v-model.number='form.detPct'
                                    type='number'
                                    min='0'
                                    max='100'
                                    class='form-control form-control-sm'
                                    style='width:70px'
                                >
                                <span title='altitude band it sees, feet'>alt ft</span>
                                <input
                                    v-model.number='form.detAltMinFt'
                                    type='number'
                                    class='form-control form-control-sm'
                                    style='width:80px'
                                >
                                <span>–</span>
                                <input
                                    v-model.number='form.detAltMaxFt'
                                    type='number'
                                    class='form-control form-control-sm'
                                    style='width:80px'
                                >
                                <label
                                    class='form-check form-check-inline mb-0'
                                    title='Also report real AIS vessels the channel carries (the lane must be in that channel)'
                                >
                                    <input
                                        v-model='form.detAis'
                                        type='checkbox'
                                        class='form-check-input'
                                    >
                                    <span class='form-check-label'>real AIS too</span>
                                </label>
                            </template>
                        </div>
                        <div class='d-flex gap-2 align-items-center mb-2'>
                            <label class='form-check form-check-inline mb-0'>
                                <input
                                    v-model='form.videoOn'
                                    type='checkbox'
                                    class='form-check-input'
                                >
                                <span class='form-check-label'>Video</span>
                            </label>
                            <input
                                v-if='form.videoOn'
                                v-model='form.stream'
                                class='form-control form-control-sm'
                                placeholder='MediaMTX stream name (e.g. uas1)'
                                maxlength='64'
                            >
                        </div>
                        <div class='d-flex gap-1 align-items-center'>
                            <button
                                class='btn btn-sm btn-primary'
                                :disabled='busy || !running || !!picking'
                                @click='addUnitOnMap'
                            >
                                Place on map
                            </button>
                            <span class='text-muted'>or</span>
                            <input
                                v-model='form.lat'
                                class='form-control form-control-sm'
                                placeholder='lat'
                                style='width:90px'
                            >
                            <input
                                v-model='form.lon'
                                class='form-control form-control-sm'
                                placeholder='lon'
                                style='width:90px'
                            >
                            <button
                                class='btn btn-sm btn-outline-primary'
                                :disabled='busy || !running || !form.lat || !form.lon'
                                @click='addUnitAt'
                            >
                                Add
                            </button>
                        </div>
                        <div
                            v-if='!running'
                            class='text-muted mt-1'
                        >
                            Start a live session (or a preset) first.
                        </div>
                    </div>
                </div>

                <!-- ── 3. Units ─────────────────────────────────────────────── -->
                <div class='card mb-2'>
                    <div class='card-header py-2 px-2 d-flex align-items-center gap-2'>
                        <IconUsers :size='16' />
                        <span class='fw-semibold'>Units</span>
                        <span class='badge bg-secondary ms-auto'>{{ entities.length }}</span>
                    </div>
                    <div class='card-body p-0 small'>
                        <div
                            v-if='!entities.length'
                            class='text-muted p-2'
                        >
                            No units yet.
                        </div>
                        <div
                            v-for='u in entities'
                            :key='u.id'
                            class='border-bottom'
                        >
                            <div
                                class='d-flex align-items-center gap-2 px-2 py-1 cursor-pointer'
                                :class='selected === u.id ? "bg-primary-lt" : ""'
                                @click='selectUnit(u)'
                            >
                                <span
                                    :class='u.lostlink ? "text-danger" : (u.silent ? "text-secondary" : (u.emitted ? "text-success" : "text-muted"))'
                                    :title='u.lostlink ? "lost link" : (u.silent ? "hidden — never reports itself" : (u.emitted ? "reporting" : "not yet reported"))'
                                >●</span>
                                <span class='fw-semibold text-truncate'>{{ u.callsign }}</span>
                                <span class='text-muted text-truncate'>{{ typeLabel(u.type) }}</span>
                                <span
                                    v-if='u.silent'
                                    class='badge'
                                    :class='u.seen_by.length ? "bg-warning text-dark" : "bg-dark"'
                                    :title='u.seen_by.length ? "seen by " + seenByNames(u).join(", ") : "hidden — no sensor sees it"'
                                >{{ u.seen_by.length ? 'seen by ' + u.seen_by.length : 'hidden' }}</span>
                                <span
                                    v-else-if='u.sensor && u.sensor.detect'
                                    class='badge bg-info text-dark'
                                    title='detection on'
                                >detecting</span>
                                <span class='ms-auto text-muted text-nowrap'>{{ mToFt(u.hae_m) }} ft · {{ Math.round(u.heading) }}° · {{ mpsToKt(u.speed_mps) }} kt</span>
                            </div>
                            <div
                                v-if='selected === u.id'
                                class='px-2 pb-2 pt-1'
                                style='background:rgba(128,128,128,.08)'
                            >
                                <div class='d-flex flex-wrap gap-1 mb-1'>
                                    <button
                                        class='btn btn-sm btn-outline-primary'
                                        :disabled='busy || !!picking'
                                        @click='unitGoto(u)'
                                    >
                                        Go To (map)
                                    </button>
                                    <button
                                        class='btn btn-sm btn-outline-primary'
                                        :disabled='busy || !!picking'
                                        @click='unitRoute(u)'
                                    >
                                        Route (map)
                                    </button>
                                    <button
                                        class='btn btn-sm btn-outline-primary'
                                        :disabled='busy'
                                        @click='unitOrbit(u)'
                                    >
                                        Orbit here
                                    </button>
                                    <button
                                        class='btn btn-sm btn-outline-secondary'
                                        :disabled='busy'
                                        @click='cmd({ op: "hold", id: u.id })'
                                    >
                                        Hold
                                    </button>
                                    <button
                                        class='btn btn-sm'
                                        :class='u.lostlink ? "btn-danger" : "btn-outline-danger"'
                                        :disabled='busy'
                                        @click='cmd({ op: "lostlink", id: u.id, on: !u.lostlink })'
                                    >
                                        {{ u.lostlink ? 'Link restored' : 'Lost link' }}
                                    </button>
                                    <button
                                        v-if='u.sensor'
                                        class='btn btn-sm'
                                        :class='u.sensor.detect ? "btn-info" : "btn-outline-info"'
                                        :disabled='busy'
                                        :title='u.sensor.detect ? "Detection is on — click to switch it off (its tracks are deleted)" : "Switch detection on: hidden targets inside the cone become tracks"'
                                        @click='toggleDetect(u)'
                                    >
                                        {{ u.sensor.detect ? 'Detecting' : 'Detect' }}
                                    </button>
                                    <button
                                        class='btn btn-sm btn-outline-danger ms-auto'
                                        :disabled='busy'
                                        @click='cmd({ op: "remove", id: u.id })'
                                    >
                                        Remove
                                    </button>
                                </div>
                                <div class='d-flex flex-wrap gap-1 align-items-center mb-1'>
                                    <span>Course°</span>
                                    <input
                                        v-model.number='act.headingDeg'
                                        type='number'
                                        min='0'
                                        max='360'
                                        class='form-control form-control-sm'
                                        style='width:70px'
                                    >
                                    <span>kt</span>
                                    <input
                                        v-model.number='act.speedKt'
                                        type='number'
                                        min='0'
                                        class='form-control form-control-sm'
                                        style='width:70px'
                                    >
                                    <span>ft</span>
                                    <input
                                        v-model.number='act.altFt'
                                        type='number'
                                        class='form-control form-control-sm'
                                        style='width:80px'
                                    >
                                    <button
                                        class='btn btn-sm btn-outline-primary'
                                        :disabled='busy'
                                        @click='unitSetCourse(u)'
                                    >
                                        Set course
                                    </button>
                                    <button
                                        class='btn btn-sm btn-outline-secondary'
                                        :disabled='busy'
                                        @click='cmd({ op: "alt", id: u.id, hae_m: ftToM(act.altFt) })'
                                    >
                                        Set alt
                                    </button>
                                    <span>orbit r m</span>
                                    <input
                                        v-model.number='act.radiusM'
                                        type='number'
                                        min='1'
                                        class='form-control form-control-sm'
                                        style='width:80px'
                                    >
                                </div>
                                <div class='d-flex flex-wrap gap-1 align-items-center'>
                                    <input
                                        v-model='act.chat'
                                        class='form-control form-control-sm'
                                        placeholder='chat text'
                                        maxlength='500'
                                        style='min-width:120px;flex:1'
                                        @keyup.enter='unitChat(u)'
                                    >
                                    <button
                                        class='btn btn-sm btn-outline-primary'
                                        :disabled='busy || !act.chat'
                                        @click='unitChat(u)'
                                    >
                                        Chat
                                    </button>
                                    <select
                                        v-model='act.alert'
                                        class='form-select form-select-sm w-auto'
                                    >
                                        <option
                                            v-for='a in EMERGENCIES'
                                            :key='a'
                                            :value='a'
                                        >
                                            {{ a }}
                                        </option>
                                    </select>
                                    <button
                                        class='btn btn-sm btn-outline-danger'
                                        :disabled='busy'
                                        @click='cmd({ op: "event", kind: "emergency", from: u.id, alert: act.alert })'
                                    >
                                        911
                                    </button>
                                    <button
                                        class='btn btn-sm btn-outline-secondary'
                                        :disabled='busy'
                                        @click='cmd({ op: "event", kind: "emergency_cancel", from: u.id, alert: act.alert })'
                                    >
                                        Cancel 911
                                    </button>
                                    <button
                                        class='btn btn-sm btn-outline-warning'
                                        :disabled='busy'
                                        @click='unitCasevac(u)'
                                    >
                                        CASEVAC here
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ── 3b. Detections (v10.1.62) ───────────────────────────── -->
                <div
                    v-if='detections.length'
                    class='card mb-2'
                >
                    <div class='card-header py-2 px-2 d-flex align-items-center gap-2'>
                        <IconRadar :size='16' />
                        <span class='fw-semibold'>Detections</span>
                        <span class='badge bg-secondary ms-auto'>{{ detections.length }}</span>
                    </div>
                    <div class='card-body p-0 small'>
                        <div
                            v-for='d in detections'
                            :key='d.uid'
                            class='d-flex align-items-center gap-2 px-2 py-1 border-bottom'
                        >
                            <span class='text-truncate'>{{ entityName(d.sensor) }}</span>
                            <span class='text-muted'>→</span>
                            <span class='fw-semibold text-truncate'>{{ d.callsign }}</span>
                            <span class='text-muted text-truncate'>{{ d.type }}</span>
                            <span
                                v-if='d.real'
                                class='badge bg-warning text-dark'
                                title='a real track observed in the channel'
                            >real</span>
                            <span class='ms-auto text-muted text-nowrap'>{{ Math.round(d.since_s) }}s</span>
                        </div>
                    </div>
                </div>

                <!-- ── 4. Shapes ────────────────────────────────────────────── -->
                <div class='card mb-2'>
                    <div class='card-header py-2 px-2 d-flex align-items-center gap-2'>
                        <IconPolygon :size='16' />
                        <span class='fw-semibold'>Shapes &amp; markers</span>
                        <span class='badge bg-secondary ms-auto'>{{ objects.length }}</span>
                    </div>
                    <div class='card-body py-2 px-2 small'>
                        <div class='d-flex flex-wrap gap-1 align-items-center mb-2'>
                            <input
                                v-model='shapeName'
                                class='form-control form-control-sm'
                                placeholder='name'
                                maxlength='32'
                                style='width:110px'
                            >
                            <button
                                class='btn btn-sm btn-outline-primary'
                                :disabled='busy || !running || !!picking'
                                @click='addMarker'
                            >
                                Marker
                            </button>
                            <button
                                class='btn btn-sm btn-outline-warning'
                                :disabled='busy || !running || !!picking'
                                @click='addCasevac'
                            >
                                CASEVAC
                            </button>
                            <button
                                class='btn btn-sm btn-outline-primary'
                                :disabled='busy || !running || !!picking'
                                @click='addCircle'
                            >
                                Circle
                            </button>
                            <input
                                v-model.number='circleRadius'
                                type='number'
                                min='1'
                                class='form-control form-control-sm'
                                title='circle radius (m)'
                                style='width:80px'
                            >
                            <button
                                class='btn btn-sm btn-outline-primary'
                                :disabled='busy || !running || !!picking'
                                @click='addPolygon'
                            >
                                Polygon
                            </button>
                            <button
                                class='btn btn-sm btn-outline-primary'
                                :disabled='busy || !running || !!picking'
                                @click='addRoute'
                            >
                                Route
                            </button>
                        </div>
                        <div
                            v-if='!objects.length'
                            class='text-muted'
                        >
                            No shapes yet. Polygon and route take several clicks — Enter or Esc finishes.
                        </div>
                        <div
                            v-for='o in objects'
                            :key='o.uid'
                            class='d-flex align-items-center gap-2 py-1 border-top'
                        >
                            <span class='badge bg-secondary'>{{ o.kind }}</span>
                            <span class='text-truncate'>{{ o.callsign || o.id }}</span>
                            <button
                                v-if='o.id'
                                class='btn btn-sm btn-link text-danger p-0 ms-auto text-decoration-none'
                                :disabled='busy'
                                @click='cmd({ op: "remove", id: o.id })'
                            >
                                ✕
                            </button>
                        </div>
                    </div>
                </div>

                <!-- ── 5. Save layout ───────────────────────────────────────── -->
                <div class='card mb-2'>
                    <div class='card-header py-2 px-2 d-flex align-items-center gap-2'>
                        <IconDeviceFloppy :size='16' />
                        <span class='fw-semibold'>Save layout</span>
                    </div>
                    <div class='card-body py-2 px-2 small'>
                        <div
                            v-if='openedFrom && running'
                            class='text-muted mb-1'
                        >
                            Opened from <strong>{{ openedFrom.title }}</strong> (<code>{{ openedFrom.name }}</code>). Saving writes a new layout; the original is kept — delete it on the console page if you no longer want it.
                        </div>
                        <div class='d-flex gap-1 align-items-center'>
                            <input
                                v-model='saveTitle'
                                class='form-control form-control-sm'
                                placeholder='Scenario title'
                                maxlength='80'
                            >
                            <button
                                class='btn btn-sm btn-primary text-nowrap'
                                :disabled='busy || !running || !saveTitle'
                                @click='doSave'
                            >
                                Save
                            </button>
                        </div>
                        <div
                            v-if='saved'
                            class='text-muted mt-1'
                        >
                            Saved as <code>{{ saved.saved }}</code> — {{ saved.summary.entities }} unit(s), {{ saved.summary.events }} object(s). It is now in the preset list here and on the console page.
                        </div>
                        <div class='mt-1'>
                            <a
                                :href='consoleUrl'
                                target='_blank'
                                rel='noopener'
                            >Open in console</a>
                        </div>
                    </div>
                </div>
            </template>
        </div>
    </component>
</template>

<script setup lang='ts'>
import { ref, reactive, computed, watch, onMounted, onUnmounted } from 'vue';
import type { Map as MapLibreMap, MapMouseEvent } from 'maplibre-gl';
import MenuTemplate from '../../../src/components/CloudTAK/util/MenuTemplate.vue';
import { IconRadar, IconPlus, IconUsers, IconPolygon, IconDeviceFloppy, IconCrosshair, IconExternalLink } from '@tabler/icons-vue';
import { getMap, taksimState } from '../lib/taksim-store.ts';
import { popOutSim, dockSim } from '../lib/float-pane.ts';
import {
    getStatus, getState, getScenarios, getUserChannels, startLive, startRun, sendCmd, saveLayout,
    pause, resume, stop, TakSimError,
} from '../lib/taksim-client.ts';
import type { EngineStatus, SimState, SimEntity, SimObject, SimDetection, ScenarioSummary, LatLon, Cmd, Tempo, SaveResult, DetectSpec, DetectKind } from '../lib/taksim-client.ts';
import { UNIT_KINDS, UNIT_GROUPS, TEAMS, EMERGENCIES, TEMPOS, DETECT_KINDS, unitKind, ktToMps, mpsToKt, ftToM, mToFt, typeLabel, defaultEud } from '../lib/units.ts';

// floating: this instance lives inside the floating pane (TakSimFloat) rather than the
// side menu; the anchored instance collapses while the pane is up (v10.1.62).
const props = defineProps<{ floating?: boolean }>();
const floatedElsewhere = computed(() => taksimState.floating && !props.floating);

// ── state ─────────────────────────────────────────────────────────────────────
const status = ref<EngineStatus | null>(null);
const state = ref<SimState | null>(null);
const scenarios = ref<ScenarioSummary[]>([]);
const userChannels = ref<{ name: string; active: boolean }[] | null>(null);
const error = ref('');
const notice = ref('');
const busy = ref(false);
const tempo = ref<Tempo>(1);
const presetName = ref('');
const confirmNeeded = ref('');
const confirmText = ref('');
const showAdd = ref(true);
const selected = ref<string | null>(null);
const shapeName = ref('');
const circleRadius = ref(500);
const saveTitle = ref('');
const saved = ref<SaveResult | null>(null);
const openedFrom = ref<{ name: string; title: string } | null>(null);   // the scenario this live session was opened on (W3)

const running = computed(() => !!status.value && (status.value.state === 'running' || status.value.state === 'paused'));
watch(running, (v) => { if (!v) openedFrom.value = null; });   // a stopped session was opened from nothing
const entities = computed<SimEntity[]>(() => state.value?.entities ?? []);
const objects = computed<SimObject[]>(() => state.value?.objects ?? []);
const detections = computed<SimDetection[]>(() => state.value?.detections ?? []);

function entityName(id: string): string {
    return entities.value.find(e => e.id === id)?.callsign ?? id;
}

function seenByNames(u: SimEntity): string[] {
    return u.seen_by.map(entityName);
}
const simChannel = computed(() => channelName(status.value?.default_channel || 'tak_simulation'));
const stateLabel = computed(() => status.value ? status.value.state : 'connecting…');
const stateBadgeClass = computed(() => {
    const s = status.value?.state;
    if (s === 'running') return 'bg-success';
    if (s === 'paused') return 'bg-warning text-dark';
    if (s === 'stopping') return 'bg-danger';
    return 'bg-secondary';
});
// The console lives beside CloudTAK: map.<fqdn> → https://<fqdn>:5001/simulator.
const consoleUrl = computed(() => `https://${window.location.hostname.replace(/^map\./, '')}:5001/simulator`);

function channelName(group: string): string {
    return group.startsWith('tak_') ? group.slice(4) : group;
}

// Channels the traffic goes to (a running session's lanes, else the default one) that the
// logged-in user is NOT in or has switched off — they would see nothing.
const channelWarning = computed(() => {
    if (!userChannels.value || !status.value) return '';
    const targets = status.value.run
        ? status.value.run.lanes.map(l => channelName(l.channel))
        : [simChannel.value];
    const missing = targets.filter(t => !userChannels.value!.some(c => c.name === t && c.active));
    if (!missing.length) return '';
    return `You are not in the ${missing.map(m => `"${m}"`).join(', ')} channel (or it is switched off), so you will not see the simulation on this map. Join it in TAK Portal / toggle it under Channels.`;
});

// ── add-unit form ─────────────────────────────────────────────────────────────
const form = reactive({
    kind: 'ground', callsign: 'ALPHA 1', team: 'Cyan', altFt: 0, speedKt: 3,
    sensorOn: false, fov: 60, rangeM: 1000, sweep: 0, videoOn: false, stream: '', lat: '', lon: '',
    // v10.1.62: hidden targets, team-marker choice, detection
    silent: false, detectedType: '', eud: true,
    detectOn: false, detKinds: ['air', 'sea', 'ground'] as DetectKind[], detErr: 50, detPct: 100,
    detAltMinFt: -1600, detAltMaxFt: 98000, detAis: false,
});
watch(() => form.kind, (key) => {
    const k = unitKind(key);
    form.callsign = nextCallsign(k.callsign);
    form.team = k.team ?? 'Cyan';
    form.altFt = k.altFt;
    form.speedKt = k.speedKt;
    form.sensorOn = !!k.sensor;
    if (k.sensor) {
        form.fov = k.sensor.fov;
        form.rangeM = k.sensor.range_m;
        form.sweep = k.sensor.sweep_deg_s;
    }
    form.videoOn = !!k.video;
    form.silent = !!k.silent;
    form.detectedType = k.detected_type ?? '';
    form.eud = k.eud ?? defaultEud(k.type);
    form.detectOn = false;                       // a sensor starts as a cone; Detects is a choice
    if (k.detect) {
        form.detKinds = [...k.detect.kinds];
        form.detErr = k.detect.error_m;
    } else {
        form.detKinds = ['air', 'sea', 'ground'];
        form.detErr = 50;
    }
    form.detPct = 100;
    form.detAltMinFt = -1600;
    form.detAltMaxFt = 98000;
    form.detAis = false;
});

// The detect block the Add-unit form describes (a sensor with Detects on), or null.
function detectFromForm(): DetectSpec | null {
    if (!form.sensorOn || !form.detectOn || !form.detKinds.length) return null;
    const d: DetectSpec = { kinds: [...form.detKinds], error_m: Math.max(0, form.detErr || 0) };
    const p = Math.min(100, Math.max(0, form.detPct));
    if (p < 100) d.p_detect = p / 100;
    if (Number.isFinite(form.detAltMinFt) && form.detAltMinFt > -1600) d.alt_min_m = ftToM(form.detAltMinFt);
    if (Number.isFinite(form.detAltMaxFt) && form.detAltMaxFt < 98000) d.alt_max_m = ftToM(form.detAltMaxFt);
    if (form.detAis) d.observe = ['a-n-S'];
    return d;
}

// Detect on/off on a live sensor: on = the kind's defaults (or everything), off = null,
// which also deletes the tracks it holds.
async function toggleDetect(u: SimEntity) {
    if (!u.sensor) return;
    if (u.sensor.detect) {
        await cmd({ op: 'detect', id: u.id, detect: null });
        return;
    }
    const k = UNIT_KINDS.find(x => x.type === u.type && x.detect);
    await cmd({ op: 'detect', id: u.id, detect: k?.detect ? { kinds: [...k.detect.kinds], error_m: k.detect.error_m } : { kinds: ['air', 'sea', 'ground'], error_m: 50 } });
}

function nextCallsign(base: string): string {
    // "ALPHA 1" → "ALPHA 2" when a unit with that callsign already exists.
    const m = base.match(/^(.*?)(\d+)$/);
    if (!m) return base;
    let n = parseInt(m[2], 10);
    let cs = base;
    while (entities.value.some(e => e.callsign === cs)) {
        n += 1;
        cs = `${m[1]}${n}`;
    }
    return cs;
}

// per-selected-unit action fields
const act = reactive({ headingDeg: 0, speedKt: 0, altFt: 0, radiusM: 1000, chat: '', alert: '911 Alert' });

function selectUnit(u: SimEntity) {
    if (selected.value === u.id) {
        selected.value = null;
        return;
    }
    selected.value = u.id;
    act.headingDeg = Math.round(u.heading);
    act.speedKt = mpsToKt(u.speed_mps) || unitKindForType(u.type).speedKt;
    act.altFt = mToFt(u.hae_m);
    act.radiusM = u.type.includes('-A') ? 3000 : 500;
}

function unitKindForType(type: string) {
    return UNIT_KINDS.find(k => k.type === type) ?? UNIT_KINDS[0];
}

// ── map click capture ─────────────────────────────────────────────────────────
const picking = ref<{ label: string; multi: boolean; min: number; count: number } | null>(null);
let pickCleanup: (() => void) | null = null;

function beginPick(label: string, multi = false, min = 1): Promise<LatLon[] | null> {
    cancelPick();
    return new Promise((resolve) => {
        let map: MapLibreMap;
        try {
            map = getMap();
        } catch (e) {
            error.value = e instanceof Error ? e.message : String(e);
            resolve(null);
            return;
        }
        const pts: LatLon[] = [];
        picking.value = { label, multi, min, count: 0 };
        const finish = (ok: boolean) => {
            if (pickCleanup) pickCleanup();
            resolve(ok ? pts : null);
        };
        const onClick = (e: MapMouseEvent) => {
            pts.push({ lat: e.lngLat.lat, lon: e.lngLat.lng });
            if (picking.value) picking.value.count = pts.length;
            if (!multi) finish(true);
        };
        const onKey = (ev: KeyboardEvent) => {
            if (ev.key === 'Escape' || (multi && ev.key === 'Enter')) {
                ev.preventDefault();
                finish(multi && pts.length >= min);
            }
        };
        pickCleanup = () => {
            map.off('click', onClick);
            window.removeEventListener('keydown', onKey);
            map.getCanvas().style.cursor = '';
            picking.value = null;
            pickCleanup = null;
        };
        map.on('click', onClick);
        window.addEventListener('keydown', onKey);
        map.getCanvas().style.cursor = 'crosshair';
    });
}

function cancelPick() {
    if (pickCleanup) pickCleanup();
}

// ── engine calls ──────────────────────────────────────────────────────────────
async function guarded<T>(fn: () => Promise<T>, okNotice?: string): Promise<T | null> {
    busy.value = true;
    error.value = '';
    try {
        const r = await fn();
        if (okNotice) flash(okNotice);
        return r;
    } catch (err) {
        if (err instanceof TakSimError && err.needsConfirmation) {
            const m = err.errors.find(e => e.includes('confirm_exercise')) || '';
            const q = m.match(/'([^']+)'/);
            confirmNeeded.value = q ? q[1] : m;
            error.value = 'This session would send on a real channel — type the channel name(s) above to confirm.';
        } else if (err instanceof TakSimError) {
            error.value = err.errors.length ? `${err.message}\n${err.errors.slice(0, 5).join('\n')}` : err.message;
        } else {
            error.value = err instanceof Error ? err.message : String(err);
        }
        return null;
    } finally {
        busy.value = false;
    }
}

let noticeTimer: ReturnType<typeof setTimeout> | null = null;
function flash(msg: string) {
    notice.value = msg;
    if (noticeTimer) clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => { notice.value = ''; }, 4000);
}

async function refresh() {
    try {
        status.value = await getStatus();
        state.value = (status.value.installed && running.value) ? await getState() : null;
        error.value = error.value.startsWith('TAK Simulator engine') ? '' : error.value;
    } catch (err) {
        if (err instanceof TakSimError && err.status === 503) {
            status.value = { installed: false, state: 'idle', run: null, lanes_enrolled: [], default_channel: 'tak_simulation' };
        } else if (!error.value) {
            error.value = err instanceof Error ? err.message : String(err);
        }
    }
    if (status.value?.run && Number.isFinite(status.value.run.tempo)) tempo.value = status.value.run.tempo as Tempo;
}

async function loadScenarios() {
    try {
        scenarios.value = await getScenarios();
    } catch {
        scenarios.value = [];
    }
}

async function loadChannels() {
    try {
        userChannels.value = await getUserChannels();
    } catch {
        userChannels.value = null;
    }
}

function mapCenter(): LatLon {
    const c = getMap().getCenter();
    return { lat: c.lat, lon: c.lng };
}

async function doStartLive() {
    const r = await guarded(() => startLive({
        center: mapCenter(), tempo: tempo.value,
        confirm_exercise: confirmNeeded.value ? confirmText.value.trim() : undefined,
    }));
    if (r) {
        confirmNeeded.value = '';
        confirmText.value = '';
        openedFrom.value = null;
        flash(`Live session started on ${Object.entries(r.lanes).map(([k, v]) => `lane ${k} → ${channelName(v)}`).join(', ')}`);
        await refresh();
        await loadChannels();
    }
}

async function doOpenForEditing() {
    const src = scenarios.value.find(s => s.name === presetName.value);
    if (!src) return;
    const r = await guarded(() => startLive({
        center: mapCenter(), tempo: tempo.value, from: src.name, recenter: true,
        confirm_exercise: confirmNeeded.value ? confirmText.value.trim() : undefined,
    }));
    if (r) {
        confirmNeeded.value = '';
        confirmText.value = '';
        openedFrom.value = { name: src.name, title: src.title || src.name };
        if (!saveTitle.value) saveTitle.value = `${src.title || src.name} (edited)`;
        flash(`Opened ${src.title || src.name} for editing: ${r.entities} unit(s), ${r.events} object(s) placed`
            + (r.dropped_events ? `; ${r.dropped_events} timeline event(s) left out` : ''));
        await refresh();
        await loadChannels();
    }
}

async function doRunPreset() {
    const r = await guarded(() => startRun({
        scenario: presetName.value, center: mapCenter(), tempo: tempo.value,
        confirm_exercise: confirmNeeded.value ? confirmText.value.trim() : undefined,
    }));
    if (r) {
        confirmNeeded.value = '';
        confirmText.value = '';
        openedFrom.value = null;
        flash(`Running ${r.scenario}: ${r.entities} units, ${r.events} events`);
        await refresh();
        await loadChannels();
    }
}

async function doPause() {
    await guarded(() => pause());
    await refresh();
}

async function doResume() {
    await guarded(() => resume());
    await refresh();
}

async function doStop() {
    cancelPick();
    await guarded(() => stop(), 'Stopped — delete events sent for every unit and object');
    selected.value = null;
    await refresh();
}

async function onTempoChange() {
    if (running.value) await cmd({ op: 'tempo', tempo: tempo.value });
}

async function cmd(c: Cmd): Promise<unknown> {
    const r = await guarded(() => sendCmd(c));
    if (r !== null) await refresh();
    return r;
}

// ── add unit ──────────────────────────────────────────────────────────────────
function spawnCmd(at: LatLon): Cmd {
    const k = unitKind(form.kind);
    const c: Cmd = {
        op: 'spawn', callsign: form.callsign.trim() || k.callsign, type: k.type, at,
        hae_m: ftToM(form.altFt || 0), team: form.team, interval_s: k.interval_s, stale_s: k.stale_s,
    };
    if (form.sensorOn) {
        c.sensor = { fov: form.fov, range_m: form.rangeM, sweep_deg_s: form.sweep };
        const d = detectFromForm();
        if (d) c.sensor.detect = d;
    }
    if (form.videoOn && form.stream.trim()) c.video = { stream: form.stream.trim() };
    if (form.silent) {
        c.silent = true;
        if (form.detectedType) c.detected_type = form.detectedType;
    } else if (form.eud !== defaultEud(k.type)) {
        c.eud = form.eud;
    }
    return c;
}

async function addUnitOnMap() {
    const pts = await beginPick(form.callsign || unitKind(form.kind).label);
    if (!pts) return;
    const r = await cmd(spawnCmd(pts[0]));
    if (r) afterSpawn();
}

async function addUnitAt() {
    const lat = parseFloat(form.lat);
    const lon = parseFloat(form.lon);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
        error.value = 'lat / lon must be numbers';
        return;
    }
    const r = await cmd(spawnCmd({ lat, lon }));
    if (r) afterSpawn();
}

function afterSpawn() {
    form.callsign = nextCallsign(form.callsign);
    flash('Unit placed');
}

// ── per-unit actions ──────────────────────────────────────────────────────────
function actSpeedMps(u: SimEntity): number {
    const kt = act.speedKt > 0 ? act.speedKt : (mpsToKt(u.speed_mps) || unitKindForType(u.type).speedKt || 3);
    return ktToMps(kt);
}

async function unitGoto(u: SimEntity) {
    const pts = await beginPick(`${u.callsign} destination`);
    if (!pts) return;
    await cmd({ op: 'goto', id: u.id, to: pts[0], speed_mps: actSpeedMps(u) });
}

async function unitRoute(u: SimEntity) {
    const pts = await beginPick(`${u.callsign} route`, true, 1);
    if (!pts) return;
    await cmd({ op: 'route', id: u.id, points: pts, speed_mps: actSpeedMps(u), loop: false });
}

async function unitOrbit(u: SimEntity) {
    await cmd({ op: 'orbit', id: u.id, radius_m: act.radiusM > 0 ? act.radiusM : 1000, speed_mps: actSpeedMps(u) });
}

async function unitSetCourse(u: SimEntity) {
    await cmd({ op: 'heading', id: u.id, heading_deg: ((act.headingDeg % 360) + 360) % 360, speed_mps: actSpeedMps(u), hae_m: ftToM(act.altFt) });
}

async function unitChat(u: SimEntity) {
    const text = act.chat.trim();
    if (!text) return;
    const r = await cmd({ op: 'event', kind: 'chat', from: u.id, text });
    if (r) act.chat = '';
}

async function unitCasevac(u: SimEntity) {
    await cmd({ op: 'event', kind: 'casevac', id: newId('cv'), title: `CASEVAC ${u.callsign}`, at: { lat: u.lat, lon: u.lon } });
}

// ── shapes ────────────────────────────────────────────────────────────────────
function newId(prefix: string): string {
    return `${prefix}${Date.now().toString(36)}`;
}

function shapeLabel(fallback: string): string {
    return shapeName.value.trim() || fallback;
}

async function addMarker() {
    const pts = await beginPick(shapeLabel('marker'));
    if (!pts) return;
    await cmd({ op: 'event', kind: 'marker', id: newId('m'), callsign: shapeLabel('Marker'), type: 'a-h-G', at: pts[0] });
}

async function addCasevac() {
    const pts = await beginPick(shapeLabel('CASEVAC'));
    if (!pts) return;
    await cmd({ op: 'event', kind: 'casevac', id: newId('cv'), title: shapeLabel('CASEVAC'), at: pts[0] });
}

async function addCircle() {
    const pts = await beginPick(`${shapeLabel('circle')} center`);
    if (!pts) return;
    await cmd({ op: 'event', kind: 'circle', id: newId('c'), callsign: shapeLabel('Circle'), at: pts[0], radius_m: circleRadius.value > 0 ? circleRadius.value : 500 });
}

async function addPolygon() {
    const pts = await beginPick(shapeLabel('polygon'), true, 3);
    if (!pts) return;
    await cmd({ op: 'event', kind: 'polygon', id: newId('p'), callsign: shapeLabel('Area'), points: pts });
}

async function addRoute() {
    const pts = await beginPick(shapeLabel('route'), true, 2);
    if (!pts) return;
    await cmd({ op: 'event', kind: 'route', id: newId('r'), callsign: shapeLabel('Route'), points: pts });
}

// ── save ──────────────────────────────────────────────────────────────────────
async function doSave() {
    const r = await guarded(() => saveLayout(saveTitle.value.trim()));
    if (r) {
        saved.value = r;
        flash(`Layout saved as ${r.saved}`);
        await loadScenarios();
    }
}

// ── lifecycle ─────────────────────────────────────────────────────────────────
let timer: ReturnType<typeof setInterval> | null = null;
onMounted(async () => {
    await refresh();
    await Promise.all([loadScenarios(), loadChannels()]);
    timer = setInterval(refresh, 2000);
});
onUnmounted(() => {
    if (timer) clearInterval(timer);
    cancelPick();
});
</script>
