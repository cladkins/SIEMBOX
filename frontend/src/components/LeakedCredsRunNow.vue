<template>
  <!-- Run the leaked-credential check now (admin only: the API refuses everyone else).
       Shown under Settings → Digital Risk → Notifications and checks, and on the Digital Risk page. -->
  <div class="leaked-creds-run-now">
    <div class="run-now">
      <el-button :icon="VideoPlay" :loading="running" @click="runNow">Run check now</el-button>
      <el-checkbox v-model="force" :disabled="running">Re-check every enabled identity, not just the due ones</el-checkbox>
    </div>
    <el-text size="small" type="info">
      Runs the leaked-credential check now instead of waiting for the next 15-minute tick. It stops
      starting new checks after about 90 seconds (HIBP calls are paced to your plan); anything left stays
      due for the scheduled job.
    </el-text>

    <el-alert
      v-if="runResult"
      :type="runResult.type"
      :title="runResult.title"
      :description="runResult.description"
      show-icon
      :closable="false"
      class="run-result"
    />
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { ElMessage } from 'element-plus';
import { VideoPlay } from '@element-plus/icons-vue';
import exposureService from '@/services/exposureService';
import { apiErrorMessage, apiErrorStatus, pluralize, runSummaryMessage } from '@/utils/exposure';

const emit = defineEmits<{
  /** A manual run finished, or one was already running (identities and findings may have changed). */
  (e: 'ran'): void;
}>();

const force = ref(false);
const running = ref(false);
const runResult = ref<{ type: 'success' | 'info' | 'warning' | 'error'; title: string; description: string } | null>(null);

async function runNow() {
  running.value = true;
  runResult.value = null;
  try {
    const summary = await exposureService.runNow(force.value);
    runResult.value = runSummaryMessage(summary);
    if (summary.skipped) ElMessage.info('Nothing was checked');
    else ElMessage.success(`Checked ${pluralize(summary.checked, 'identity', 'identities')}`);
    emit('ran');
  } catch (error) {
    const message = apiErrorMessage(error, 'The check could not be started');
    if (apiErrorStatus(error) === 409) {
      // Someone (or the scheduled job) is already running a check.
      runResult.value = { type: 'info', title: 'A check is already running', description: message };
      ElMessage.warning(message);
      emit('ran');
    } else {
      runResult.value = { type: 'error', title: 'The check failed', description: message };
      ElMessage.error(message);
    }
  } finally {
    running.value = false;
  }
}
</script>

<style scoped>
.run-now {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}

/* el-checkbox never wraps its label: on a phone this one would run off the card. */
.run-now :deep(.el-checkbox) {
  height: auto;
  margin-right: 0;
  white-space: normal;
}

.run-now :deep(.el-checkbox__label) {
  line-height: 1.4;
}

.run-result {
  margin-top: 12px;
}
</style>
