<script setup lang="ts">
import type { Shippers } from '../../types.ts';
import { ageOf } from '../../format.ts';
import Num from '../Num.vue';

defineProps<{ data: Shippers; now: number }>();
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
    <li v-if="data.error > 0" class="bd-row">
      <span class="bd-row-label"><span class="bd-tag bd-fill-critical">✕ Error</span></span>
      <span class="bd-row-value"><Num :value="data.error" /></span>
    </li>
    <li v-if="data.pending > 0" class="bd-row bd-muted">
      <span class="bd-row-label">Pending</span><span class="bd-row-value"><Num :value="data.pending" /></span>
    </li>
    <li v-for="(s, i) in data.offline_list.slice(0, Math.max(0, 6 - 2 - (data.error > 0 ? 1 : 0) - (data.pending > 0 ? 1 : 0)))" :key="i" class="bd-row">
      <span class="bd-row-label">▲ {{ s.name }}</span>
      <span class="bd-row-value bd-muted">{{ s.last_seen_at ? ageOf(s.last_seen_at, now) : 'never' }}</span>
    </li>
  </ul>
</template>
