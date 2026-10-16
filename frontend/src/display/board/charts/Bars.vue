<script setup lang="ts">
/**
 * Hourly or per-minute bars in plain SVG: no chart library on the TV. One
 * neutral colour; `ticks` marks bars (hours with a critical alert) with a
 * small red tick under them, so colour is never the only thing that changed.
 */
import { computed } from 'vue';

const props = defineProps<{ values: readonly number[]; ticks?: readonly boolean[]; label: string }>();

const GAP = 0.2;
const max = computed(() => Math.max(1, ...props.values));
const bars = computed(() =>
  props.values.map((v, i) => {
    const h = v > 0 ? Math.max(2, (v / max.value) * 88) : 0;
    return { x: i + GAP / 2, w: 1 - GAP, y: 90 - h, h, tick: props.ticks?.[i] === true };
  })
);
</script>

<template>
  <svg
    class="bd-bars"
    :viewBox="`0 0 ${Math.max(1, values.length)} 100`"
    preserveAspectRatio="none"
    role="img"
    :aria-label="label"
  >
    <line x1="0" :x2="values.length" y1="90" y2="90" class="bd-bars-axis" vector-effect="non-scaling-stroke" />
    <template v-for="(b, i) in bars" :key="i">
      <rect :x="b.x" :y="b.y" :width="b.w" :height="b.h" class="bd-bars-bar" />
      <rect v-if="b.tick" :x="b.x" y="93" :width="b.w" height="7" class="bd-bars-tick" />
    </template>
  </svg>
</template>

<style scoped>
.bd-bars {
  display: block;
  width: 100%;
  flex: 1 1 0;
  min-height: 3vh;
}
.bd-bars-bar {
  fill: var(--bd-bar);
}
.bd-bars-tick {
  fill: var(--bd-critical);
}
.bd-bars-axis {
  stroke: var(--bd-border);
  stroke-width: 1;
}
</style>
