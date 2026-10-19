<script setup lang="ts">
import type { TopSources } from '../../types.ts';
import { ageOf } from '../../format.ts';
import { SEV_COLOR, SEV_LABEL, SEV_SHAPE } from '../severity.ts';
import Num from '../Num.vue';

defineProps<{ data: TopSources; now: number }>();
</script>

<template>
  <p v-if="data.items.length === 0" class="bd-label bd-muted bd-empty">No alerts with a source address in 24 h</p>
  <ul v-else class="bd-list">
    <li v-for="(item, i) in data.items.slice(0, 6)" :key="i" class="bd-row">
      <span :style="{ color: SEV_COLOR[item.worst_severity] }" :aria-label="SEV_LABEL[item.worst_severity]">{{
        SEV_SHAPE[item.worst_severity]
      }}</span>
      <span class="bd-row-label">{{ item.ip }}<span v-if="item.country_code" class="bd-muted"> · {{ item.country_code }}</span></span>
      <span class="bd-row-value"><Num :value="item.alerts" /></span>
      <span class="bd-row-value bd-muted bd-age">· {{ ageOf(item.last_at, now) }}</span>
    </li>
  </ul>
</template>

<style scoped>
.bd-age {
  font-weight: 400;
}
.bd-empty {
  margin: auto 0;
}
</style>
