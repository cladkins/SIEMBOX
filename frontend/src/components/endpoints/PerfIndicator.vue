<template>
  <el-tooltip :content="tooltip" placement="top" :show-after="300">
    <div v-if="row.perf_at" class="perf-ind" :class="{ stale: !fresh }" data-testid="perf-indicator">
      <div v-for="m in meters" :key="m.label" class="meter" :class="m.level">
        <span class="meter-label">{{ m.label }}</span>
        <span class="meter-bar"><span class="meter-fill" :style="{ width: `${Math.min(100, Math.max(0, m.value ?? 0))}%` }" /></span>
        <span class="meter-val">{{ m.value === null ? '—' : `${Math.round(m.value)}%` }}</span>
      </div>
      <el-tag v-if="Number(row.perf_alerts_open) > 0" type="danger" size="small" effect="plain" class="perf-alerts">
        {{ row.perf_alerts_open }} perf alert{{ Number(row.perf_alerts_open) === 1 ? '' : 's' }}
      </el-tag>
    </div>
    <span v-else class="muted">{{ supported ? 'no data yet' : '—' }}</span>
  </el-tooltip>
</template>

<script setup lang="ts">
/** The Endpoints list's small current CPU / memory / fullest-disk indicator. */
import { computed } from 'vue';
import { isFresh, levelOf, supportsPerfMetrics, type Level } from '@/utils/endpointPerformance';

const props = defineProps<{
  row: {
    perf_at?: string | null;
    perf_cpu_pct?: number | string | null;
    perf_mem_pct?: number | string | null;
    perf_disk_max_pct?: number | string | null;
    perf_disk_max_mount?: string | null;
    perf_alerts_open?: number | null;
    capabilities?: string[] | null;
    agent_version?: string | null;
  };
}>();

const num = (v: unknown) => (v === null || v === undefined || v === '' ? null : Number(v));
const fresh = computed(() => isFresh(props.row.perf_at));
const supported = computed(() => supportsPerfMetrics(props.row));
const meters = computed<Array<{ label: string; value: number | null; level: Level }>>(() => {
  const cpu = num(props.row.perf_cpu_pct);
  const mem = num(props.row.perf_mem_pct);
  const disk = num(props.row.perf_disk_max_pct);
  return [
    { label: 'CPU', value: cpu, level: levelOf(cpu, 95) },
    { label: 'MEM', value: mem, level: levelOf(mem, 95) },
    { label: 'DSK', value: disk, level: levelOf(disk, 90) },
  ];
});
const tooltip = computed(() => {
  if (!props.row.perf_at) {
    return supported.value
      ? 'The agent reports performance; its first sample arrives within a minute or two.'
      : 'This agent does not report performance (needs v0.0.23 or later).';
  }
  const when = new Date(props.row.perf_at).toLocaleString();
  const disk = props.row.perf_disk_max_mount ? `Fullest disk: ${props.row.perf_disk_max_mount}. ` : '';
  return `${disk}${fresh.value ? 'Sampled' : 'Last sample (stale)'} ${when}.`;
});
</script>

<style scoped>
.perf-ind {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 120px;
}
.perf-ind.stale {
  opacity: 0.5;
}
.meter {
  display: grid;
  grid-template-columns: 28px 1fr 34px;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  line-height: 14px;
}
.meter-label {
  color: var(--el-text-color-secondary);
}
.meter-bar {
  height: 6px;
  border-radius: 3px;
  background: var(--el-fill-color-dark);
  overflow: hidden;
}
.meter-fill {
  display: block;
  height: 100%;
  background: var(--el-color-success);
}
.meter.warn .meter-fill {
  background: var(--el-color-warning);
}
.meter.crit .meter-fill {
  background: var(--el-color-danger);
}
.meter-val {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
.perf-alerts {
  margin-top: 2px;
  align-self: flex-start;
}
.muted {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
</style>
