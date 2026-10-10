<template>
  <div class="retention-settings">
    <el-card>
      <template #header>
        <span>Log Retention Settings <HelpTip text="How long SIEMBox keeps data before the daily background cleanup removes it. Larger windows mean more searchable history but a bigger database — the totals below show current table sizes." /></span>
      </template>

      <el-form :model="retentionForm" label-width="200px" v-loading="loading">
        <el-form-item>
          <template #label>Auto Cleanup <HelpTip text="Runs the retention purge automatically once a day in the background. For alerts it only removes CLOSED ones — open alerts are kept regardless of age." /></template>
          <el-switch v-model="retentionForm.auto_cleanup_enabled" />
          <el-text size="small" type="info" style="margin-left: 10px">
            Automatically clean up old logs based on retention periods
          </el-text>
        </el-form-item>

        <el-divider />

        <el-form-item>
          <template #label>Raw Logs Retention <HelpTip text="Original syslog message bodies. Deleting a raw log also deletes its parsed record (they are linked), so your effective searchable history is the SMALLER of this and the parsed-logs setting." /></template>
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

        <el-form-item>
          <template #label>Parsed Logs Retention <HelpTip text="The structured, normalized copy that detection rules evaluate and the log views search. Keeping these longer than raw logs preserves searchable fields after the raw text is gone." /></template>
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

        <el-form-item>
          <template #label>Alerts Retention <HelpTip text="Auto cleanup deletes only CLOSED alerts older than this. The Manual Cleanup below deletes any alert older than this, open or closed." /></template>
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
        <span>Manual Cleanup <HelpTip text="Starts a background purge using the retention values above. Runs in safe 10k-row batches so ingestion keeps flowing; progress appears next to the button and you can leave this page while it runs. Unlike auto cleanup, this also deletes alerts that are still open." /></span>
      </template>

      <el-alert type="warning" :closable="false" style="margin-bottom: 20px">
        <strong>Warning:</strong> Manual cleanup will immediately delete old logs based on the retention periods above.
        This action cannot be undone.
      </el-alert>

      <el-button type="danger" @click="runManualCleanup" :loading="cleaning">
        <el-icon><Delete /></el-icon> Run Cleanup Now
      </el-button>
      <el-text v-if="cleanupProgress" size="small" type="info" style="margin-left: 12px">
        {{ cleanupProgress }}
      </el-text>
    </el-card>

    <!-- Retention stats: row totals, table sizes and oldest records (the System
         Information card without its syslog receiver rows). -->
    <SystemInformationCard ref="statsCard" stats-only style="margin-top: 20px" />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { api } from '@/services/api';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Check, Delete } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import SystemInformationCard from './SystemInformationCard.vue';

const loading = ref(false);
const saving = ref(false);
const cleaning = ref(false);
const cleanupProgress = ref('');

// Refreshed when a cleanup finishes, so the totals reflect what was purged.
const statsCard = ref<InstanceType<typeof SystemInformationCard> | null>(null);

const retentionForm = reactive({
  raw_logs_days: 30,
  parsed_logs_days: 90,
  alerts_days: 365,
  auto_cleanup_enabled: true,
});

onMounted(async () => {
  // Re-attach to a cleanup job still running from an earlier visit/click.
  try {
    const { data } = await api.getCleanupStatus();
    if (data.job?.status === 'running') pollCleanupJob();
  } catch {
    /* status is best-effort */
  }
  fetchRetentionSettings();
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
    // The purge runs as a background job on the server (it can take minutes to
    // hours on large tables) — start it, then poll for live progress.
    await api.runManualCleanup(retentionForm);
    await pollCleanupJob();
  } catch (error: any) {
    if (error?.response?.status === 409 && error.response.data?.job) {
      // A purge is already running (an earlier click, or the automated sweep
      // that fires on backend startup) — attach and show its progress.
      ElMessage.info(
        error.response.data.job.trigger === 'automatic'
          ? 'The automated retention sweep is running — showing its progress.'
          : 'A cleanup is already running — showing its progress.'
      );
      await pollCleanupJob();
    } else if (error !== 'cancel') {
      ElMessage.error('Failed to start cleanup');
      cleaning.value = false;
    } else {
      cleaning.value = false;
    }
  }
}

async function pollCleanupJob() {
  cleaning.value = true;
  let sawJob = false;
  try {
    for (;;) {
      const { data } = await api.getCleanupStatus();
      const job = data.job;
      if (!job) {
        // Job state is in backend memory; it disappearing mid-poll means the
        // backend restarted — which also stops the purge itself. Batches
        // already deleted stay deleted; re-running continues where it left off.
        if (sawJob) {
          ElMessage.warning(
            'The cleanup job is gone — the backend likely restarted, which stops the purge. ' +
            'Already-deleted batches are kept; run cleanup again to continue.'
          );
        }
        break;
      }
      sawJob = true;
      const r = job.results;
      const label = job.trigger === 'automatic' ? 'Automated sweep — deleted so far' : 'Deleted so far';
      cleanupProgress.value =
        `${label} — raw logs: ${r.raw_logs_deleted.toLocaleString()}, ` +
        `parsed logs: ${r.parsed_logs_deleted.toLocaleString()}, ` +
        `alerts: ${r.alerts_deleted.toLocaleString()}`;
      if (job.status === 'completed') {
        const what = job.trigger === 'automatic' ? 'Automated cleanup' : 'Cleanup';
        ElMessage.success({
          message: `${what} completed: ${r.raw_logs_deleted.toLocaleString()} raw logs, ${r.parsed_logs_deleted.toLocaleString()} parsed logs, ${r.alerts_deleted.toLocaleString()} alerts deleted`,
          duration: 8000,
        });
        break;
      }
      if (job.status === 'failed') {
        ElMessage.error(`Cleanup failed: ${job.error || 'unknown error'}`);
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
    statsCard.value?.fetchStatistics();
  } catch {
    ElMessage.warning('Lost track of the cleanup job — it continues on the server. Reload to re-check.');
  } finally {
    cleaning.value = false;
    cleanupProgress.value = '';
  }
}
</script>
