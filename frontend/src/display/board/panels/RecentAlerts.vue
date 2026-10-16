<script setup lang="ts">
import type { RecentAlerts } from '../../types.ts';
import { ageOf } from '../../format.ts';
import { CATEGORY_LABEL, SEV_COLOR, SEV_LABEL, SEV_SHAPE } from '../severity.ts';

defineProps<{ data: RecentAlerts; now: number }>();
const floorWords: Record<string, string> = { critical: 'critical', high: 'high or critical', medium: 'medium or higher' };
</script>

<template>
  <p v-if="data.items.length === 0" class="bd-label bd-muted bd-empty">
    No open {{ floorWords[data.min_severity] ?? data.min_severity }} alerts in the last 24 h
  </p>
  <ul v-else class="bd-list">
    <li v-for="(item, i) in data.items.slice(0, 6)" :key="i" class="bd-row">
      <span :style="{ color: SEV_COLOR[item.severity] }" :aria-label="SEV_LABEL[item.severity]">{{
        SEV_SHAPE[item.severity]
      }}</span>
      <span class="bd-row-label">{{ item.label || CATEGORY_LABEL[item.category] }}</span>
      <span class="bd-row-value bd-muted">{{ ageOf(item.at, now) }}</span>
    </li>
    <li v-if="data.more" class="bd-row bd-muted">+ more</li>
  </ul>
</template>

<style scoped>
.bd-empty {
  margin: auto 0;
}
</style>
