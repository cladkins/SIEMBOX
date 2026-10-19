<script setup lang="ts">
import type { Endpoints } from '../../types.ts';
import { ageOf, compact } from '../../format.ts';
import Num from '../Num.vue';

defineProps<{ data: Endpoints; now: number }>();
</script>

<template>
  <ul class="bd-list">
    <li class="bd-row">
      <span class="bd-row-label bd-muted">✓ Online</span><span class="bd-row-value"><Num :value="data.online" /></span>
    </li>
    <li class="bd-row">
      <span class="bd-row-label">
        <span v-if="data.offline > 0" class="bd-tag bd-fill-warning">▲ Offline</span>
        <span v-else class="bd-muted">Offline</span>
      </span>
      <span class="bd-row-value"><Num :value="data.offline" /></span>
    </li>
    <li v-for="(e, i) in data.offline_list.slice(0, 3)" :key="i" class="bd-row">
      <span class="bd-row-label">▲ {{ e.hostname ?? 'unnamed host' }}</span>
      <span class="bd-row-value bd-muted">{{ e.last_seen_at ? ageOf(e.last_seen_at, now) : 'never' }}</span>
    </li>
    <li class="bd-row bd-muted">
      <span class="bd-row-label">EDR detections, 24 h</span><span class="bd-row-value">{{ compact(data.detections_24h) }}</span>
    </li>
  </ul>
</template>
