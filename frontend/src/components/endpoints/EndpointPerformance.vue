<template>
  <div class="endpoint-perf" data-testid="endpoint-performance">
    <div class="perf-toolbar">
      <el-radio-group v-model="range" size="small" data-testid="perf-range" @change="reload">
        <el-radio-button v-for="r in PERF_RANGES" :key="r.value" :value="r.value">{{ r.label }}</el-radio-button>
      </el-radio-group>
      <span class="muted">
        <template v-if="data?.latest">Last sample {{ formatTime(data.latest.ts) }}</template>
        <template v-if="data">
          · {{ data.source === 'raw' ? 'per-minute samples' : 'hourly averages' }}<template v-if="data.bucket_seconds > 60">,
            {{ bucketLabel(data.bucket_seconds) }} buckets</template>
        </template>
      </span>
      <el-button size="small" :loading="loading" @click="reload"><el-icon><Refresh /></el-icon></el-button>
    </div>

    <el-alert
      v-if="data && !data.supported && !data.latest"
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 10px"
      :title="`Agent ${data.agent_version ? 'v' + data.agent_version : '(unknown version)'} does not report performance — update it to v${data.min_agent_version} or later (or it is turned off in the agent's agent.json: performance_metrics).`"
    />
    <el-alert
      v-else-if="data && !data.performance.metrics"
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 10px"
      :title="`Performance metrics are turned off in this endpoint's scan policy (${data.policy}).`"
    />

    <el-alert
      v-for="a in data?.open_alerts || []"
      :key="`${a.metric}:${a.target}`"
      type="warning"
      :closable="false"
      show-icon
      style="margin-bottom: 8px"
      data-testid="perf-open-alert"
    >
      <template #title>
        {{ a.title || `${a.metric} ${a.target}` }}
        <span class="muted"> — open since {{ formatTime(a.opened_at) }}, now {{ formatPct(a.last_value, 1) }}</span>
        <router-link v-if="a.alert_id" :to="{ path: '/alerts', query: { alert: String(a.alert_id) } }" style="margin-left: 6px">alert</router-link>
      </template>
    </el-alert>

    <div v-if="data?.latest" class="perf-tiles">
      <div class="tile" :class="levelOf(data.latest.cpu_pct, cpuThreshold ?? undefined)">
        <div class="tile-label">CPU</div>
        <div class="tile-value">{{ formatPct(data.latest.cpu_pct, 1) }}</div>
        <div class="tile-sub">{{ data.latest.cpu_count ? `${data.latest.cpu_count} cores` : '' }}</div>
      </div>
      <div class="tile" :class="levelOf(memPct, memThreshold ?? undefined)">
        <div class="tile-label">Memory</div>
        <div class="tile-value">{{ formatPct(memPct, 1) }}</div>
        <div class="tile-sub">{{ formatBytes(data.latest.mem_used) }} of {{ formatBytes(data.latest.mem_total) }}</div>
      </div>
      <div class="tile">
        <div class="tile-label">Swap</div>
        <div class="tile-value">{{ data.latest.swap_total ? formatBytes(data.latest.swap_used) : 'none' }}</div>
        <div class="tile-sub">{{ data.latest.swap_total ? `of ${formatBytes(data.latest.swap_total)}` : '' }}</div>
      </div>
      <div class="tile">
        <div class="tile-label">Load</div>
        <div class="tile-value">{{ data.latest.load1 ?? '—' }}</div>
        <div class="tile-sub">{{ data.latest.load1 !== null ? `${data.latest.load5} · ${data.latest.load15}` : 'not on Windows' }}</div>
      </div>
      <div class="tile">
        <div class="tile-label">Uptime</div>
        <div class="tile-value">{{ formatUptime(data.latest.uptime_s) }}</div>
        <div class="tile-sub">&nbsp;</div>
      </div>
      <div v-for="d in latestDisks" :key="d.mount" class="tile" :class="levelOf(d.pct, diskThreshold ?? undefined)">
        <div class="tile-label" :title="d.mount">Disk {{ d.mount }}</div>
        <div class="tile-value">{{ formatPct(d.pct, 0) }}</div>
        <div class="tile-sub">{{ formatBytes(d.used) }} of {{ formatBytes(d.used + d.free) }}</div>
      </div>
    </div>

    <div v-loading="loading" class="perf-grid">
      <PerfChart
        title="CPU"
        subtitle="% of all cores"
        :datasets="cpuSets"
        :from="from"
        :to="to"
        :y-max="100"
        :threshold="cpuThreshold"
        :format="pctFmt"
      />
      <PerfChart
        title="Memory"
        subtitle="% in use"
        :datasets="memSets"
        :from="from"
        :to="to"
        :y-max="100"
        :threshold="memThreshold"
        :format="pctFmt"
      />
      <PerfChart v-if="showLoad" title="Load average" :datasets="loadSets" :from="from" :to="to" />
      <PerfChart
        title="Disk"
        subtitle="% used per mount"
        :datasets="diskSets"
        :from="from"
        :to="to"
        :y-max="100"
        :threshold="diskThreshold"
        :format="pctFmt"
      />
      <PerfChart
        title="Network"
        subtitle="per interface; solid in, dashed out"
        :datasets="netSets"
        :from="from"
        :to="to"
        :format="formatRate"
      />
    </div>

    <div class="perf-procs">
      <div class="perf-procs-head">
        <strong>Top processes</strong>
        <el-radio-group v-model="procSort" size="small">
          <el-radio-button value="cpu">By CPU</el-radio-button>
          <el-radio-button value="mem">By memory</el-radio-button>
        </el-radio-group>
        <el-select
          v-if="procs.times.length"
          v-model="procAt"
          size="small"
          style="width: 210px"
          data-testid="perf-proc-time"
          @change="loadProcesses"
        >
          <el-option v-for="t in procs.times" :key="t" :value="t" :label="formatTime(t)" />
        </el-select>
        <span class="muted">CPU % is of one core (as top shows it); sampled every 5 minutes. Names only, never command lines.</span>
      </div>
      <el-table :data="procRows" size="small" stripe max-height="340" v-loading="procs.loading">
        <el-table-column prop="pid" label="PID" width="80" />
        <el-table-column prop="name" label="Process" min-width="180" show-overflow-tooltip />
        <el-table-column label="User" width="120" show-overflow-tooltip>
          <template #default="{ row }">{{ row.user || '—' }}</template>
        </el-table-column>
        <el-table-column label="CPU" width="90" align="right">
          <template #default="{ row }">{{ formatPct(row.cpu_pct, 1) }}</template>
        </el-table-column>
        <el-table-column label="Memory" width="110" align="right">
          <template #default="{ row }">{{ formatBytes(row.mem_rss) }}</template>
        </el-table-column>
        <el-table-column label="Mem %" width="80" align="right">
          <template #default="{ row }">{{ formatPct(row.mem_pct, 1) }}</template>
        </el-table-column>
        <template #empty>No process snapshots{{ data && !data.performance.processes ? ' (process sampling is off in the scan policy)' : '' }}.</template>
      </el-table>
    </div>
    <p class="muted" style="margin-top: 8px">
      Per-minute samples are kept {{ data?.retention.raw_days ?? 7 }} days (1h–24h charts), hourly averages
      {{ data?.retention.hourly_days ?? 90 }} days (7d–90d). Alert thresholds come from the endpoint's scan policy
      ({{ data?.policy || 'Default' }}).
    </p>
  </div>
</template>

<script setup lang="ts">
/**
 * The Endpoints details pane's Performance tab: current numbers, open
 * performance alerts, CPU / memory / load / disk / network charts over a
 * chosen range (refreshed every minute for the short ranges), and the top
 * processes snapshot.
 */
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue';
import { ElMessage } from 'element-plus';
import { Refresh } from '@element-plus/icons-vue';
import PerfChart, { type PerfDataset } from './PerfChart.vue';
import { api } from '@/services/api';
import {
  PERF_RANGES,
  RANGE_MS,
  formatBytes,
  formatPct,
  formatRate,
  formatUptime,
  hasLoad,
  levelOf,
  seriesColor,
  swapPct,
  toXY,
  type DiskSeries,
  type NetSeries,
  type PerfPoint,
  type PerfRange,
  type PolicyPerformance,
} from '@/utils/endpointPerformance';

const props = defineProps<{ agentId: string }>();

interface LatestDisk {
  mount: string;
  used: number;
  free: number;
  total: number;
  pct: number;
}
interface PerfResponse {
  range: PerfRange;
  from: string;
  to: string;
  bucket_seconds: number;
  source: 'raw' | 'hourly';
  supported: boolean;
  min_agent_version: string;
  agent_version: string | null;
  policy: string;
  performance: PolicyPerformance;
  retention: { raw_days: number; hourly_days: number };
  points: PerfPoint[];
  disks: DiskSeries[];
  net: NetSeries[];
  latest: {
    ts: string;
    cpu_pct: number | null;
    cpu_count: number | null;
    mem_total: number;
    mem_used: number;
    swap_total: number;
    swap_used: number;
    load1: number | null;
    load5: number | null;
    load15: number | null;
    uptime_s: number | null;
    disks: LatestDisk[];
  } | null;
  open_alerts: Array<{
    metric: string;
    target: string;
    opened_at: string;
    last_value: number | null;
    alert_id: number | null;
    title: string | null;
  }>;
}
interface ProcRow {
  pid: number;
  name: string;
  user: string | null;
  cpu_pct: number;
  mem_rss: number;
  mem_pct: number;
}

const range = ref<PerfRange>('24h');
const loading = ref(false);
const data = ref<PerfResponse | null>(null);
const procSort = ref<'cpu' | 'mem'>('cpu');
const procAt = ref<string>('');
const procs = reactive<{ times: string[]; snapshot: { ts: string; by_cpu: ProcRow[]; by_mem: ProcRow[] } | null; loading: boolean }>({
  times: [],
  snapshot: null,
  loading: false,
});
let timer: ReturnType<typeof setInterval> | undefined;

const from = computed(() => (data.value ? Date.parse(data.value.from) : Date.now() - RANGE_MS[range.value]));
const to = computed(() => (data.value ? Date.parse(data.value.to) : Date.now()));
const bucket = computed(() => data.value?.bucket_seconds ?? 60);
const points = computed(() => data.value?.points ?? []);
const thresholdOf = (m: 'cpu' | 'memory' | 'disk') => {
  const p = data.value?.performance;
  return p && p.metrics && p.thresholds[m].enabled ? p.thresholds[m].percent : null;
};
const cpuThreshold = computed(() => thresholdOf('cpu'));
const memThreshold = computed(() => thresholdOf('memory'));
const diskThreshold = computed(() => thresholdOf('disk'));
const memPct = computed(() => {
  const l = data.value?.latest;
  return l && l.mem_total ? (l.mem_used / l.mem_total) * 100 : null;
});
const latestDisks = computed(() => (data.value?.latest?.disks ?? []).slice(0, 6));
const showLoad = computed(() => points.value.length === 0 || hasLoad(points.value));
const pctFmt = (v: number) => `${Math.round(v * 10) / 10}%`;

const cpuSets = computed<PerfDataset[]>(() => [
  { label: 'Average', data: toXY(points.value, (p) => p.cpu, bucket.value), color: '#409eff', fill: true },
  ...(bucket.value > 60
    ? [{ label: 'Peak', data: toXY(points.value, (p) => p.cpu_max, bucket.value), color: '#409eff', faint: true }]
    : []),
]);
const memSets = computed<PerfDataset[]>(() => {
  const sets: PerfDataset[] = [{ label: 'Memory', data: toXY(points.value, (p) => p.mem_pct, bucket.value), color: '#67c23a', fill: true }];
  if (points.value.some((p) => (p.swap_total ?? 0) > 0)) {
    sets.push({ label: 'Swap', data: toXY(points.value, (p) => swapPct(p), bucket.value), color: '#e6a23c', dashed: true });
  }
  return sets;
});
const loadSets = computed<PerfDataset[]>(() => [
  { label: '1 min', data: toXY(points.value, (p) => p.load1, bucket.value), color: '#9b59b6' },
  { label: '5 min', data: toXY(points.value, (p) => p.load5, bucket.value), color: '#16a085' },
  { label: '15 min', data: toXY(points.value, (p) => p.load15, bucket.value), color: '#909399' },
]);
const diskSets = computed<PerfDataset[]>(() =>
  (data.value?.disks ?? []).slice(0, 8).map((d, i) => ({
    label: d.mount,
    data: toXY(d.points, (p) => p.pct, bucket.value),
    color: seriesColor(i),
  }))
);
const netSets = computed<PerfDataset[]>(() =>
  (data.value?.net ?? []).slice(0, 4).flatMap((n, i) => [
    { label: `${n.iface} in`, data: toXY(n.points, (p) => p.rx, bucket.value), color: seriesColor(i) },
    { label: `${n.iface} out`, data: toXY(n.points, (p) => p.tx, bucket.value), color: seriesColor(i), dashed: true },
  ])
);
const procRows = computed<ProcRow[]>(() => (procSort.value === 'cpu' ? procs.snapshot?.by_cpu : procs.snapshot?.by_mem) ?? []);

function bucketLabel(sec: number): string {
  if (sec % 86_400 === 0) return `${sec / 86_400}-day`;
  if (sec % 3600 === 0) return `${sec / 3600}-hour`;
  return `${sec / 60}-minute`;
}
function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

async function loadPerformance() {
  const agentId = props.agentId;
  const r = range.value;
  loading.value = !data.value || data.value.range !== r;
  try {
    const res = await api.getEndpointPerformance(agentId, r);
    if (agentId !== props.agentId || r !== range.value) return;
    data.value = res.data;
  } catch {
    ElMessage.error('Failed to load performance data');
  } finally {
    loading.value = false;
  }
}

async function loadProcesses() {
  const agentId = props.agentId;
  procs.loading = !procs.snapshot;
  try {
    const res = await api.getEndpointProcesses(agentId, { range: range.value, at: procAt.value || undefined });
    if (agentId !== props.agentId) return;
    procs.times = res.data.times || [];
    procs.snapshot = res.data.snapshot;
    if (!procAt.value && procs.snapshot) procAt.value = procs.snapshot.ts;
  } catch {
    ElMessage.error('Failed to load top processes');
  } finally {
    procs.loading = false;
  }
}

function reload() {
  procAt.value = '';
  void loadPerformance();
  void loadProcesses();
}

function schedule() {
  clearInterval(timer);
  // Short ranges follow the live per-minute samples.
  timer = setInterval(() => {
    if (['1h', '6h', '24h'].includes(range.value)) {
      void loadPerformance();
      if (procAt.value === procs.times[0]) {
        procAt.value = '';
        void loadProcesses();
      }
    }
  }, 60_000);
}

watch(
  () => props.agentId,
  () => {
    data.value = null;
    procs.snapshot = null;
    procs.times = [];
    reload();
  }
);
onMounted(() => {
  reload();
  schedule();
});
onBeforeUnmount(() => clearInterval(timer));
</script>

<style scoped>
.perf-toolbar {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}
.perf-tiles {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  gap: 8px;
  margin-bottom: 12px;
}
.tile {
  border: 1px solid var(--el-border-color-lighter);
  border-left: 3px solid var(--el-color-success);
  border-radius: 6px;
  padding: 6px 8px;
  min-width: 0;
}
.tile.warn {
  border-left-color: var(--el-color-warning);
}
.tile.crit {
  border-left-color: var(--el-color-danger);
}
.tile-label {
  font-size: 11px;
  color: var(--el-text-color-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.tile-value {
  font-size: 18px;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}
.tile-sub {
  font-size: 11px;
  color: var(--el-text-color-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.perf-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 10px;
}
.perf-procs {
  margin-top: 14px;
}
.perf-procs-head {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 6px;
}
.muted {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
</style>
