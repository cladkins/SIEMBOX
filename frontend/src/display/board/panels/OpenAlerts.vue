<script setup lang="ts">
import { computed } from 'vue';
import type { OpenAlerts, Sev } from '../../types.ts';
import { SEV_ORDER } from '../severity.ts';
import { ageOf, compact } from '../../format.ts';
import SevRows from './SevRows.vue';

const props = defineProps<{ data: OpenAlerts; now: number }>();
const counts = computed(
  () => Object.fromEntries(SEV_ORDER.map((s) => [s, props.data.by_severity[s]?.open ?? 0])) as Record<Sev, number>
);
const untouched = computed(() => SEV_ORDER.reduce((sum, s) => sum + (props.data.by_severity[s]?.untouched ?? 0), 0));
const oldestCritical = computed(() => props.data.by_severity.critical?.oldest_at ?? null);
</script>

<template>
  <p v-if="data.total === 0" class="bd-number bd-all-clear">0 open — all clear</p>
  <template v-else>
    <SevRows :counts="counts" />
    <p class="bd-label bd-muted bd-foot">
      {{ compact(untouched) }} untouched<template v-if="oldestCritical">
        · Oldest critical waiting {{ ageOf(oldestCritical, now) }}</template
      >
    </p>
  </template>
</template>

<style scoped>
.bd-all-clear {
  margin: auto 0;
  color: var(--bd-text-2);
}
.bd-foot {
  margin: auto 0 0;
}
</style>
