// SPDX-License-Identifier: AGPL-3.0-or-later
// Pop the simulator panel out as a draggable, resizable pane over the map and dock it back
// (v10.1.62) — the same CloudTAK FloatStore the Dispatcher plugin uses (generic add() since
// CloudTAK 13.45). The pane is a singleton keyed by this uid.
import { defineAsyncComponent } from 'vue';
import { useFloatStore } from '../../../src/stores/float.ts';
import { taksimState } from './taksim-store.ts';

const PANE_UID = 'plugin-taksim-float';

// Async import so TakSimMain (which triggers pop-out) and TakSimFloat (which hosts
// TakSimMain) do not form a static import cycle.
const TakSimFloat = defineAsyncComponent(() => import('../components/TakSimFloat.vue'));

export function popOutSim(): void {
    useFloatStore().add({
        uid:       PANE_UID,
        name:      'TAK Simulator',
        component: TakSimFloat,
        width:     460,
        height:    700,
    });
    taksimState.floating = true;
}

export function dockSim(): void {
    useFloatStore().delete(PANE_UID);
    taksimState.floating = false;
}
