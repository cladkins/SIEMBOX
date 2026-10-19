<script setup lang="ts">
import { computed } from 'vue';
import type { Ingest } from '../../types.ts';
import { compact } from '../../format.ts';
import Num from '../Num.vue';
import Bars from '../charts/Bars.vue';
import HealthTag from './HealthTag.vue';

const props = defineProps<{ data: Ingest }>();

const rate = computed(() => props.data.logs_last_minute ?? props.data.rate_15m_per_minute);
const bars = computed(() => props.data.per_minute ?? props.data.hourly.map((h) => h.total));
const health = computed(() => {
  switch (props.data.state) {
    case 'stalled':
      return { level: 'down' as const, text: `Stalled · no logs for ${compact(props.data.stall_minutes)} min` };
    case 'slow':
      return { level: 'warning' as const, text: 'Slow' };
    case 'idle':
      return { level: 'ok' as const, text: 'Idle' };
    default:
      return { level: 'ok' as const, text: 'Flowing' };
  }
});
</script>

<template>
  <p v-if="data.state === 'idle' && !data.last_log_at" class="bd-label bd-muted bd-empty">
    No logs received in the last 24 h — connect a source
  </p>
  <template v-else>
    <div class="bd-ingest-head">
      <span class="bd-hero"><Num :value="rate" /></span>
      <span class="bd-label bd-muted">/min</span>
    </div>
    <Bars :values="bars" :label="data.per_minute ? 'Logs per minute, last hour' : 'Logs per hour, last 24 hours'" />
    <p class="bd-ingest-foot">
      <HealthTag :level="health.level" :text="health.text" />
      <span v-if="data.parsed_pct_24h !== null" class="bd-label bd-muted">{{ Math.round(data.parsed_pct_24h) }}% parsed</span>
      <HealthTag v-if="(data.udp_dropped_15m ?? 0) > 0" level="warning" :text="`${compact(data.udp_dropped_15m)} UDP drops`" />
    </p>
  </template>
</template>

<style scoped>
.bd-empty {
  margin: auto 0;
}
.bd-ingest-head {
  display: flex;
  align-items: baseline;
  gap: 1vh;
}
.bd-ingest-foot {
  display: flex;
  align-items: baseline;
  gap: 2vh;
  margin: 0;
  flex-wrap: wrap;
}
</style>
