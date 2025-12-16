<template>
  <div class="settings">
    <el-row :gutter="20">
      <el-col :span="16">
        <el-card>
          <template #header>
            <span>Log Retention Settings</span>
          </template>

          <el-form :model="retentionForm" label-width="200px" v-loading="loading">
            <el-form-item label="Auto Cleanup">
              <el-switch v-model="retentionForm.auto_cleanup_enabled" />
              <el-text size="small" type="info" style="margin-left: 10px">
                Automatically clean up old logs based on retention periods
              </el-text>
            </el-form-item>

            <el-divider />

            <el-form-item label="Raw Logs Retention">
              <el-input-number
                v-model="retentionForm.raw_logs_days"
                :min="1"
                :max="365"
                style="width: 150px"
              />
              <el-text size="small" type="info" style="margin-left: 10px">days</el-text>
              <br />
              <el-text size="small" type="info">
                Delete raw syslog messages older than this many days
              </el-text>
            </el-form-item>

            <el-form-item label="Parsed Logs Retention">
              <el-input-number
                v-model="retentionForm.parsed_logs_days"
                :min="1"
                :max="730"
                style="width: 150px"
              />
              <el-text size="small" type="info" style="margin-left: 10px">days</el-text>
              <br />
              <el-text size="small" type="info">
                Delete parsed logs older than this many days
              </el-text>
            </el-form-item>

            <el-form-item label="Alerts Retention">
              <el-input-number
                v-model="retentionForm.alerts_days"
                :min="1"
                :max="3650"
                style="width: 150px"
              />
              <el-text size="small" type="info" style="margin-left: 10px">days</el-text>
              <br />
              <el-text size="small" type="info">
                Delete closed alerts older than this many days
              </el-text>
            </el-form-item>

            <el-form-item>
              <el-button type="primary" @click="saveRetentionSettings" :loading="saving">
                <el-icon><Check /></el-icon> Save Settings
              </el-button>
              <el-button @click="fetchRetentionSettings">Reset</el-button>
            </el-form-item>
          </el-form>
        </el-card>

        <el-card style="margin-top: 20px">
          <template #header>
            <span>Syslog Server Configuration</span>
          </template>

          <el-alert type="info" :closable="false" style="margin-bottom: 20px">
            These settings tell log shippers where to send logs. The syslog receiver must be restarted to listen on a different port.
          </el-alert>

          <el-form :model="syslogForm" label-width="200px" v-loading="syslogLoading">
            <el-form-item label="Syslog Host">
              <el-input
                v-model="syslogForm.syslog_host"
                placeholder="localhost or 0.0.0.0"
                style="width: 300px"
              />
              <br />
              <el-text size="small" type="info">
                IP address or hostname where syslog server listens
              </el-text>
            </el-form-item>

            <el-form-item label="Syslog Port">
              <el-input-number
                v-model="syslogForm.syslog_port"
                :min="1"
                :max="65535"
                style="width: 150px"
              />
              <br />
              <el-text size="small" type="info">
                Port number for syslog receiver (default: 514)
              </el-text>
            </el-form-item>

            <el-form-item>
              <el-button type="primary" @click="saveSyslogSettings" :loading="syslogSaving">
                <el-icon><Check /></el-icon> Save Settings
              </el-button>
              <el-button @click="fetchSyslogSettings">Reset</el-button>
            </el-form-item>
          </el-form>
        </el-card>

        <el-card style="margin-top: 20px">
          <template #header>
            <span>Manual Cleanup</span>
          </template>

          <el-alert type="warning" :closable="false" style="margin-bottom: 20px">
            <strong>Warning:</strong> Manual cleanup will immediately delete old logs based on the retention periods above.
            This action cannot be undone.
          </el-alert>

          <el-button type="danger" @click="runManualCleanup" :loading="cleaning">
            <el-icon><Delete /></el-icon> Run Cleanup Now
          </el-button>
        </el-card>
      </el-col>

      <el-col :span="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>System Information</span>
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

              <!-- Divider between Syslog and Database Stats -->
              <el-descriptions-item v-if="syslogStatus && statistics">
                <el-divider />
              </el-descriptions-item>

              <!-- Database Statistics Section -->
              <template v-if="statistics">
                <el-descriptions-item label="Raw Logs">
                  <strong>{{ formatNumber(statistics.total_raw_logs) }}</strong>
                  <br />
                  <el-text size="small" type="info">{{ statistics.raw_logs_size }}</el-text>
                </el-descriptions-item>

                <el-descriptions-item label="Parsed Logs">
                  <strong>{{ formatNumber(statistics.total_parsed_logs) }}</strong>
                  <br />
                  <el-text size="small" type="info">{{ statistics.parsed_logs_size }}</el-text>
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
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { api } from '@/services/api';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Check, Delete, Refresh } from '@element-plus/icons-vue';
import { format } from 'date-fns';

const loading = ref(false);
const saving = ref(false);
const cleaning = ref(false);
const statsLoading = ref(false);
const syslogLoading = ref(false);
const syslogSaving = ref(false);

const retentionForm = reactive({
  raw_logs_days: 30,
  parsed_logs_days: 90,
  alerts_days: 365,
  auto_cleanup_enabled: true,
});

const syslogForm = reactive({
  syslog_host: '',
  syslog_port: 514,
});

const statistics = ref<any>(null);
const syslogStatus = ref<any>(null);

onMounted(() => {
  fetchRetentionSettings();
  fetchSyslogSettings();
  fetchStatistics();
});

async function fetchRetentionSettings() {
  loading.value = true;
  try {
    const response = await api.getRetentionSettings();
    Object.assign(retentionForm, response.data);
  } catch (error) {
    ElMessage.error('Failed to fetch retention settings');
  } finally {
    loading.value = false;
  }
}

async function saveRetentionSettings() {
  saving.value = true;
  try {
    await api.updateRetentionSettings(retentionForm);
    ElMessage.success('Retention settings saved successfully');
  } catch (error) {
    ElMessage.error('Failed to save retention settings');
  } finally {
    saving.value = false;
  }
}

async function runManualCleanup() {
  try {
    await ElMessageBox.confirm(
      'This will permanently delete old logs based on your retention settings. Are you sure?',
      'Confirm Manual Cleanup',
      {
        confirmButtonText: 'Run Cleanup',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    );

    cleaning.value = true;
    const response = await api.runManualCleanup(retentionForm);
    const results = response.data.results;

    ElMessage.success({
      message: `Cleanup completed: ${results.raw_logs_deleted} raw logs, ${results.parsed_logs_deleted} parsed logs, ${results.alerts_deleted} alerts deleted`,
      duration: 5000,
    });

    // Refresh statistics after cleanup
    fetchStatistics();
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to run cleanup');
    }
  } finally {
    cleaning.value = false;
  }
}

async function fetchSyslogSettings() {
  syslogLoading.value = true;
  try {
    const response = await api.getSyslogSettings();
    Object.assign(syslogForm, response.data);
  } catch (error) {
    ElMessage.error('Failed to fetch syslog settings');
  } finally {
    syslogLoading.value = false;
  }
}

async function saveSyslogSettings() {
  syslogSaving.value = true;
  try {
    await api.updateSyslogSettings(syslogForm);
    ElMessage.success('Syslog settings saved successfully');
    // Refresh status after saving
    await fetchSyslogStatus();
  } catch (error) {
    ElMessage.error('Failed to save syslog settings');
  } finally {
    syslogSaving.value = false;
  }
}

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
    // Also refresh syslog status when refreshing statistics
    await fetchSyslogStatus();
  } catch (error) {
    ElMessage.error('Failed to fetch statistics');
  } finally {
    statsLoading.value = false;
  }
}

const formatNumber = (num: number): string => {
  return new Intl.NumberFormat().format(num);
};

const formatDate = (date: string): string => {
  return format(new Date(date), 'MMM dd, yyyy HH:mm');
};
</script>

<style scoped>
.settings {
  padding: 0;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
