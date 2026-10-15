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

    <LeakedCredsRunNow @ran="emit('ran')" />
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { ElMessage } from 'element-plus';
import { Check } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import LeakedCredsRunNow from '@/components/LeakedCredsRunNow.vue';
import exposureService, { EXPOSURE_SEVERITIES, type ExposureSettings } from '@/services/exposureService';
import { apiErrorMessage } from '@/utils/exposure';

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

onMounted(() => load(true));
</script>

<style scoped>
.inline-hint {
  margin-left: 10px;
}

.inline-hint a {
  color: var(--el-color-primary);
}
</style>
