<template>
  <el-card>
    <template #header>
      <div class="card-header">
        <span>System Information <HelpTip text="Version and runtime details for this SIEMBox instance. Raw/Parsed row totals are live-row estimates (marked ~) — exact counts would scan millions of rows; Alerts is exact. Sizes are actual disk usage, which stays at its high-water mark after deletions: Postgres reuses freed space for new logs but only returns it to the OS on VACUUM FULL, so a table can show large after a purge (flagged as % reclaimable)." /></span>
        <el-button size="small" @click="fetchStatistics" :icon="Refresh" circle />
      </div>
    </template>

    <div v-loading="statsLoading">
      <el-descriptions :column="1" border v-if="statistics || syslogStatus">
        <!-- Syslog Status Section -->
        <template v-if="syslogStatus">
          <el-descriptions-item label="Syslog Receiver">
            <el-tag
              :type="syslogStatus.status === 'healthy' ? 'success' : syslogStatus.status === 'warning' ? 'warning' : 'danger'"
              size="small"
            >
              {{ syslogStatus.status }}
            </el-tag>
            <br />
            <el-text size="small" type="info">{{ syslogStatus.status_message }}</el-text>
            <br />
            <el-text size="small" type="info">Port {{ syslogStatus.actual_listening_port }}</el-text>
          </el-descriptions-item>

          <el-descriptions-item label="Last Log Received">
            <strong>{{ syslogStatus.last_log_received ? formatDate(syslogStatus.last_log_received) : 'Never' }}</strong>
            <br />
            <el-text size="small" type="info">
              {{ formatNumber(syslogStatus.logs_received_last_5min) }} logs in last 5 min
            </el-text>
          </el-descriptions-item>
        </template>

        <!-- Port Mismatch Warning -->
        <el-descriptions-item v-if="syslogStatus && !syslogStatus.ports_match">
          <el-alert type="warning" :closable="false" show-icon>
            <template #title>
              <el-text size="small">
                Configuration port ({{ syslogStatus.configured_port }}) doesn't match listening port ({{ syslogStatus.actual_listening_port }})
              </el-text>
            </template>
          </el-alert>
        </el-descriptions-item>

        <!-- Database Statistics Section -->
        <template v-if="statistics">
          <el-descriptions-item label="Raw Logs">
            <strong>{{ statistics.counts_are_estimated ? '~' : '' }}{{ formatNumber(statistics.total_raw_logs) }}</strong>
            <br />
            <el-text size="small" type="info">{{ statistics.raw_logs_size }}</el-text>
            <el-tooltip
              v-if="statistics.raw_logs_bloat_pct >= 20"
              content="Most of this table's disk space is deleted rows not yet compacted. Postgres reuses it for new logs but won't shrink the file without VACUUM FULL."
              placement="top"
            >
              <el-tag type="info" size="small" style="margin-left: 6px">~{{ statistics.raw_logs_bloat_pct }}% reclaimable</el-tag>
            </el-tooltip>
          </el-descriptions-item>

          <el-descriptions-item label="Parsed Logs">
            <strong>{{ statistics.counts_are_estimated ? '~' : '' }}{{ formatNumber(statistics.total_parsed_logs) }}</strong>
            <br />
            <el-text size="small" type="info">{{ statistics.parsed_logs_size }}</el-text>
            <el-tooltip
              v-if="statistics.parsed_logs_bloat_pct >= 20"
              content="Most of this table's disk space is deleted rows not yet compacted. Postgres reuses it for new logs but won't shrink the file without VACUUM FULL."
              placement="top"
            >
              <el-tag type="info" size="small" style="margin-left: 6px">~{{ statistics.parsed_logs_bloat_pct }}% reclaimable</el-tag>
            </el-tooltip>
          </el-descriptions-item>

          <el-descriptions-item label="Alerts">
            <strong>{{ formatNumber(statistics.total_alerts) }}</strong>
            <br />
            <el-text size="small" type="info">{{ statistics.alerts_size }}</el-text>
          </el-descriptions-item>

          <el-descriptions-item label="Oldest Raw Log">
            <el-text size="small">
              {{ statistics.oldest_raw_log ? formatDate(statistics.oldest_raw_log) : 'N/A' }}
            </el-text>
          </el-descriptions-item>

          <el-descriptions-item label="Oldest Parsed Log">
            <el-text size="small">
              {{ statistics.oldest_parsed_log ? formatDate(statistics.oldest_parsed_log) : 'N/A' }}
            </el-text>
          </el-descriptions-item>

          <el-descriptions-item label="Oldest Alert">
            <el-text size="small">
              {{ statistics.oldest_alert ? formatDate(statistics.oldest_alert) : 'N/A' }}
            </el-text>
          </el-descriptions-item>
        </template>
      </el-descriptions>

      <el-empty v-else description="No statistics available" />
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { api } from '@/services/api';
import { ElMessage } from 'element-plus';
import { Refresh } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import { formatDate, formatNumber } from './format';

const props = defineProps<{
  /**
   * Show only the retention stats (row totals, table sizes, oldest records).
   * Skips fetching the syslog receiver status, so its rows never render. The
   * Retention page uses this; the System page shows the whole card.
   */
  statsOnly?: boolean;
}>();

const statsLoading = ref(false);
const statistics = ref<any>(null);
const syslogStatus = ref<any>(null);

onMounted(() => {
  fetchStatistics();
});

async function fetchSyslogStatus() {
  try {
    const response = await api.getSyslogStatus();
    syslogStatus.value = response.data;
  } catch (error) {
    console.error('Failed to fetch syslog status', error);
  }
}

async function fetchStatistics() {
  statsLoading.value = true;
  try {
    const response = await api.getRetentionStatistics();
    statistics.value = response.data;
    // Also refresh syslog status when refreshing statistics (skipped when
    // the card shows only the retention stats)
    if (!props.statsOnly) await fetchSyslogStatus();
  } catch (error) {
    ElMessage.error('Failed to fetch statistics');
  } finally {
    statsLoading.value = false;
  }
}

defineExpose({ fetchStatistics });
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
