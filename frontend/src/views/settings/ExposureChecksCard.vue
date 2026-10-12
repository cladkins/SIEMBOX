<template>
  <el-card>
    <template #header>
      <span>
        Notifications and checks
        <HelpTip text="Exposure alerts always land in the alert queue. Notifications are opt-in: when on, new findings at or above the minimum severity go to the channels set up in Settings → Notifications, grouped into one message per identity per check." />
      </span>
    </template>

    <el-form :model="form" label-width="220px" v-loading="loading">
      <el-form-item label="Leaked-credential checks">
        <el-switch v-model="form.exposure_leaked_creds_enabled" :disabled="saving" aria-label="Leaked-credential checks" />
        <el-text size="small" type="info" class="inline-hint">
          Check monitored identities against Have I Been Pwned in the background
        </el-text>
      </el-form-item>

      <el-form-item label="Exposure notifications">
        <el-switch v-model="form.notify_exposure_enabled" :disabled="saving" aria-label="Exposure notifications" />
        <el-text size="small" type="info" class="inline-hint">
          Send new findings to your
          <router-link to="/settings/notifications">notification channels</router-link>
        </el-text>
      </el-form-item>

      <el-form-item label="Minimum severity">
        <el-select
          v-model="form.notify_exposure_min_severity"
          :disabled="saving || !form.notify_exposure_enabled"
          aria-label="Minimum severity for exposure notifications"
          style="width: 200px"
        >
          <el-option v-for="s in EXPOSURE_SEVERITIES" :key="s" :label="capitalize(s)" :value="s" />
        </el-select>
      </el-form-item>

      <el-form-item>
        <el-button type="primary" :loading="saving" :disabled="loading || loadFailed" @click="save">
          <el-icon><Check /></el-icon> Save
        </el-button>
        <el-button :disabled="saving" @click="load(true)">Reset</el-button>
      </el-form-item>
    </el-form>

    <el-divider />

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
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { ElMessage } from 'element-plus';
import { Check, VideoPlay } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import exposureService, {
  EXPOSURE_SEVERITIES,
  type ExposureSettings,
  type LeakedCredentialRunSummary,
} from '@/services/exposureService';
import { apiErrorMessage, apiErrorStatus, formatWhen, pluralize } from '@/utils/exposure';

const emit = defineEmits<{
  /** Settings were saved. */
  (e: 'changed'): void;
  /** A manual run finished (identities and findings may have changed). */
  (e: 'ran'): void;
}>();

const form = reactive<ExposureSettings>({
  notify_exposure_enabled: false,
  notify_exposure_min_severity: 'medium',
  exposure_leaked_creds_enabled: true,
});
const loading = ref(false);
const loadFailed = ref(false);
const saving = ref(false);

const force = ref(false);
const running = ref(false);
const runResult = ref<{ type: 'success' | 'info' | 'warning' | 'error'; title: string; description: string } | null>(null);

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

function applySettings(settings: ExposureSettings) {
  form.notify_exposure_enabled = settings.notify_exposure_enabled;
  form.notify_exposure_min_severity = settings.notify_exposure_min_severity;
  form.exposure_leaked_creds_enabled = settings.exposure_leaked_creds_enabled;
}

async function load(showLoading = false) {
  if (showLoading) loading.value = true;
  try {
    applySettings(await exposureService.getSettings());
    loadFailed.value = false;
  } catch (error) {
    // Don't let Save write the placeholder defaults over settings we never read.
    loadFailed.value = true;
    ElMessage.error(apiErrorMessage(error, 'Failed to load the exposure settings'));
  } finally {
    loading.value = false;
  }
}

async function save() {
  saving.value = true;
  try {
    applySettings(
      await exposureService.updateSettings({
        exposure_leaked_creds_enabled: form.exposure_leaked_creds_enabled,
        notify_exposure_enabled: form.notify_exposure_enabled,
        notify_exposure_min_severity: form.notify_exposure_min_severity,
      })
    );
    ElMessage.success('Digital Risk settings saved');
    emit('changed');
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, 'Failed to save the settings'));
  } finally {
    saving.value = false;
  }
}

function describeRun(s: LeakedCredentialRunSummary) {
  if (s.skipped) {
    return { type: 'info' as const, title: 'Nothing was checked', description: s.reason ? `Reason: ${s.reason}.` : '' };
  }
  const parts = [
    `Checked ${pluralize(s.checked, 'identity', 'identities')}`,
    pluralize(s.newFindings, 'new finding'),
  ];
  if (s.failed) parts.push(`${s.failed} failed (see their status above)`);
  if (s.remaining) parts.push(`${s.remaining} still due`);
  let description = parts.join(' · ');
  if (s.error) {
    description += `. Stopped early: ${s.error}`;
    if (s.rateLimitedUntil) description += `. Checks resume after ${formatWhen(s.rateLimitedUntil, s.rateLimitedUntil)}`;
    return { type: 'warning' as const, title: 'Check stopped early', description };
  }
  return { type: s.failed ? ('warning' as const) : ('success' as const), title: 'Check complete', description };
}

async function runNow() {
  running.value = true;
  runResult.value = null;
  try {
    const summary = await exposureService.runNow(force.value);
    runResult.value = describeRun(summary);
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

onMounted(() => load(true));
</script>

<style scoped>
.inline-hint {
  margin-left: 10px;
}

.inline-hint a {
  color: var(--el-color-primary);
}

.run-now {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}

.run-result {
  margin-top: 12px;
}
</style>
