<script setup lang="ts">
import { computed } from 'vue';
import type { Sources } from '../../types.ts';
import { clockText, compact, duration, plural } from '../../format.ts';
import Num from '../Num.vue';

const props = defineProps<{ data: Sources; timezone: string | null }>();
const KIND: Record<string, string> = { shipper: 'Shipper', poller: 'Poller', direct: 'Direct source' };
const empty = computed(() => props.data.active + props.data.silent + props.data.quiet + (props.data.unknown ?? 0) === 0);
const rows = computed(() => props.data.rows.slice(0, 6));
const more = computed(() => props.data.more_active + Math.max(0, props.data.rows.length - 6));
const since = computed(() => {
  if (!props.data.since) return null;
  const t = Date.parse(props.data.since);
  return Number.isNaN(t) ? null : clockText(t, props.timezone);
});
</script>

<template>
  <p v-if="empty && !since" class="bd-label bd-muted bd-empty">No sources seen in 24 h</p>
  <template v-else>
    <ul v-if="rows.length > 0" class="bd-list">
      <li v-for="(row, i) in rows" :key="i" class="bd-row">
        <template v-if="row.state === 'silent'">
          <span class="bd-tag bd-fill-warning">▲ SILENT</span>
          <span class="bd-row-label">{{ row.label ?? KIND[row.kind] }}</span>
          <span class="bd-row-value">{{ duration((row.silent_minutes ?? 0) * 60_000) }}</span>
        </template>
        <template v-else>
          <span class="bd-muted">{{ row.state === 'active' ? '✓' : row.state === 'quiet' ? '·' : '?' }}</span>
          <span class="bd-row-label">{{ row.label ?? KIND[row.kind] }}</span>
          <span class="bd-row-value bd-muted">{{
            row.state === 'active' ? `${compact(row.logs_per_minute)}/min` : row.state === 'quiet' ? 'quiet' : 'unknown'
          }}</span>
        </template>
      </li>
      <li v-if="more > 0" class="bd-row bd-muted">… +{{ compact(more) }} more active</li>
    </ul>
    <ul v-else class="bd-list">
      <li class="bd-row">
        <span class="bd-row-label">✓ Active</span><span class="bd-row-value"><Num :value="data.active" /></span>
      </li>
      <li class="bd-row">
        <span class="bd-row-label">▲ Silent</span><span class="bd-row-value"><Num :value="data.silent" /></span>
      </li>
      <li class="bd-row">
        <span class="bd-row-label bd-muted">· Quiet</span><span class="bd-row-value"><Num :value="data.quiet" /></span>
      </li>
    </ul>
    <p class="bd-small bd-foot">
      <template v-if="since">Collecting since {{ since }}</template>
      <template v-if="since && data.unknown_shippers > 0"> · </template>
      <template v-if="data.unknown_shippers > 0">{{ plural(data.unknown_shippers, 'unknown shipper') }} seen</template>
    </p>
  </template>
</template>

<style scoped>
.bd-empty {
  margin: auto 0;
}
.bd-foot {
  margin: auto 0 0;
}
</style>
