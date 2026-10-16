<script setup lang="ts">
/** A number that gets a 1 s background highlight when it changes (theme.css; off with reduced motion). */
import { ref, watch, onBeforeUnmount } from 'vue';
import { compact } from '../format.ts';

const props = defineProps<{ value: number | null | undefined; suffix?: string }>();
const changed = ref(false);
let timer: ReturnType<typeof setTimeout> | null = null;

watch(
  () => props.value,
  (next, prev) => {
    if (prev === undefined || next === prev) return;
    changed.value = true;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => (changed.value = false), 1000);
  }
);
onBeforeUnmount(() => {
  if (timer) clearTimeout(timer);
});
</script>

<template>
  <span class="bd-num" :class="{ 'bd-changed': changed }">{{ compact(value) }}{{ suffix ?? '' }}</span>
</template>
