<template>
  <div class="perf-settings" data-testid="perf-settings">
    <el-form-item label="Performance metrics">
      <el-switch v-model="model.metrics" data-testid="perf-metrics-switch" />
      <span class="muted hint">CPU, memory, disks, load, uptime and network, once a minute.</span>
    </el-form-item>
    <el-form-item label="Top processes">
      <el-switch v-model="model.processes" :disabled="!model.metrics" data-testid="perf-processes-switch" />
      <span class="muted hint">The 10 busiest processes by CPU and by memory, every 5 minutes (names only).</span>
    </el-form-item>
    <p class="muted" style="margin: 4px 0 8px">
      Alerts: one per endpoint and metric (per mount point for disks) while the value stays high; it is marked recovered
      once the value is {{ RECOVERY_MARGIN }} points below the threshold for a few minutes, and a new alert can only open after that.
    </p>
    <el-table :data="rows" size="small" :class="{ disabled: !model.metrics }">
      <el-table-column label="Alert" width="150">
        <template #default="{ row }">
          <el-checkbox v-model="model.thresholds[row.value as PerfMetric].enabled" :disabled="!model.metrics" :data-testid="`perf-th-${row.value}-enabled`">
            {{ row.label }}
          </el-checkbox>
        </template>
      </el-table-column>
      <el-table-column label="Above" width="150">
        <template #default="{ row }">
          <el-input-number
            v-model="model.thresholds[row.value as PerfMetric].percent"
            :min="1"
            :max="99.9"
            :step="1"
            :precision="1"
            size="small"
            controls-position="right"
            style="width: 110px"
            :disabled="!model.metrics || !model.thresholds[row.value as PerfMetric].enabled"
            :data-testid="`perf-th-${row.value}-percent`"
          />
          %
        </template>
      </el-table-column>
      <el-table-column label="For (minutes)" width="150">
        <template #default="{ row }">
          <el-input-number
            v-model="model.thresholds[row.value as PerfMetric].minutes"
            :min="0"
            :max="MAX_THRESHOLD_MINUTES"
            :step="1"
            :precision="0"
            size="small"
            controls-position="right"
            style="width: 110px"
            :disabled="!model.metrics || !model.thresholds[row.value as PerfMetric].enabled"
          />
        </template>
      </el-table-column>
      <el-table-column label="Severity" width="130">
        <template #default="{ row }">
          <el-select
            v-model="model.thresholds[row.value as PerfMetric].severity"
            size="small"
            :disabled="!model.metrics || !model.thresholds[row.value as PerfMetric].enabled"
          >
            <el-option v-for="s in PERF_SEVERITIES" :key="s" :value="s" :label="s" />
          </el-select>
        </template>
      </el-table-column>
      <el-table-column label="" min-width="160">
        <template #default="{ row }"><span class="muted">{{ row.help }}</span></template>
      </el-table-column>
    </el-table>
    <p class="muted" style="margin-top: 6px">
      0 minutes: the newest sample alone (disks). Agents before v{{ MIN_PERF_AGENT_VERSION }} report no performance;
      an agent's own <code>performance_metrics: false</code> in agent.json turns it off whatever the policy says.
    </p>
  </div>
</template>

<script setup lang="ts">
/** The scan policy editor's Performance tab: metrics and process sampling on/off, and the alert thresholds. */
import {
  MAX_THRESHOLD_MINUTES,
  MIN_PERF_AGENT_VERSION,
  PERF_METRICS,
  PERF_SEVERITIES,
  RECOVERY_MARGIN,
  type PerfMetric,
  type PolicyPerformance,
} from '@/utils/endpointPerformance';

const model = defineModel<PolicyPerformance>({ required: true });
const rows = PERF_METRICS;
</script>

<style scoped>
.muted {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.hint {
  margin-left: 10px;
}
.disabled {
  opacity: 0.6;
}
</style>
