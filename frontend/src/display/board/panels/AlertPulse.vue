<script setup lang="ts">
import { computed } from 'vue';
import type { AlertPulse } from '../../types.ts';
import { changeText, compact } from '../../format.ts';
import { SEV_COLOR, SEV_SHAPE } from '../severity.ts';
import Num from '../Num.vue';
import Bars from '../charts/Bars.vue';

const props = defineProps<{ data: AlertPulse }>();
const change = computed(() => changeText(props.data.total_24h, props.data.prev_24h));
</script>

<template>
  <p v-if="data.total_24h === 0 && data.prev_24h === 0" class="bd-label bd-muted bd-empty">No alerts in 24 h</p>
  <template v-else>
    <div class="bd-pulse-head">
      <span class="bd-hero"><Num :value="data.total_24h" /></span>
      <span class="bd-label bd-muted">{{ change.text }} vs prev 24 h</span>
    </div>
    <Bars
      :values="data.hourly.map((h) => h.total)"
      :ticks="data.hourly.map((h) => h.critical > 0)"
      label="Alerts per hour, last 24 hours"
    />
    <p class="bd-label bd-pulse-foot">
      <span :style="data.by_severity_24h.critical > 0 ? { color: SEV_COLOR.critical } : undefined"
        >{{ SEV_SHAPE.critical }} {{ compact(data.by_severity_24h.critical) }} critical</span
      >
      <span :style="data.by_severity_24h.high > 0 ? { color: SEV_COLOR.high } : undefined"
        >{{ SEV_SHAPE.high }} {{ compact(data.by_severity_24h.high) }} high</span
      >
      <span class="bd-muted">last hour {{ compact(data.last_hour) }}</span>
    </p>
  </template>
</template>

<style scoped>
.bd-empty {
  margin: auto 0;
}
.bd-pulse-head {
  display: flex;
  align-items: baseline;
  gap: 2vh;
  flex-wrap: wrap;
}
.bd-pulse-foot {
  display: flex;
  gap: 2.5vh;
  margin: 0;
  white-space: nowrap;
  flex-wrap: wrap;
}
</style>
