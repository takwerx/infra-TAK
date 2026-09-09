<template>
    <FloatingPane
        :uid='uid'
        @close='dock'
    >
        <template #header>
            <div class='d-flex align-items-center gap-2 mx-2'>
                <IconRadar
                    :size='18'
                    class='text-primary'
                />
                <span class='fw-semibold'>TAK Simulator</span>
            </div>
        </template>
        <TakSimMain floating />
    </FloatingPane>
</template>

<script setup lang="ts">
// The floating host for the simulator panel (v10.1.62): CloudTAK's FloatingPane chrome
// (drag, resize, close) around the same TakSimMain the menu shows.
import { onUnmounted } from 'vue';
import { IconRadar } from '@tabler/icons-vue';
import FloatingPane from '../../../src/components/CloudTAK/util/FloatingPane.vue';
import TakSimMain from './TakSimMain.vue';
import { taksimState } from '../lib/taksim-store.ts';

defineProps<{ uid: string }>();
const emit = defineEmits<{ (e: 'close'): void }>();

function dock() {
    taksimState.floating = false;
    emit('close');
}

// Pane torn down by any other path (plugin disable, map teardown) → let the anchored
// menu view resume instead of showing the dock-back placeholder forever.
onUnmounted(() => {
    taksimState.floating = false;
});
</script>
