<template>
  <div class="asset-discovery-settings">
    <el-card>
      <template #header>
        <span>Auto-Discovery Settings</span>
      </template>

      <el-alert type="info" :closable="false" style="margin-bottom: 20px">
        Automatically discover assets from incoming logs. The system scans the raw_logs table periodically.
      </el-alert>

      <el-form :model="autoDiscoveryForm" label-width="250px" v-loading="autoDiscoveryLoading">
        <el-form-item>
          <template #label>Enable Auto-Discovery <HelpTip text="Periodically scans incoming logs and creates or updates Assets from the source IPs and hostnames it sees — so your inventory builds itself from real traffic." /></template>
          <el-switch
            v-model="autoDiscoveryForm.auto_discovery_enabled"
            :disabled="authStore.user?.role !== 'admin' || autoDiscoverySaving"
            @change="saveAutoDiscoverySetting('auto_discovery_enabled', autoDiscoveryForm.auto_discovery_enabled ? 'true' : 'false')"
          />
        </el-form-item>

        <el-form-item label="Discovery Interval (minutes)">
          <el-input-number
            v-model="autoDiscoveryForm.auto_discovery_interval_minutes"
            :min="5"
            :max="1440"
            :step="5"
            :disabled="authStore.user?.role !== 'admin' || autoDiscoverySaving"
            style="width: 200px"
          />
          <el-button
            type="primary"
            :loading="autoDiscoverySaving"
            :disabled="authStore.user?.role !== 'admin'"
            @click="saveAutoDiscoverySetting('auto_discovery_interval_minutes', autoDiscoveryForm.auto_discovery_interval_minutes.toString())"
            style="margin-left: 10px"
          >
            Save
          </el-button>
          <br />
          <el-text size="small" type="info">
            How often to scan logs for new assets (5-1440 minutes). Default: 360 (6 hours)
          </el-text>
        </el-form-item>

        <el-form-item label="Stale Asset Threshold (days)">
          <el-input-number
            v-model="autoDiscoveryForm.stale_asset_threshold_days"
            :min="1"
            :max="365"
            :disabled="authStore.user?.role !== 'admin' || autoDiscoverySaving"
            style="width: 200px"
          />
          <el-button
            type="primary"
            :loading="autoDiscoverySaving"
            :disabled="authStore.user?.role !== 'admin'"
            @click="saveAutoDiscoverySetting('stale_asset_threshold_days', autoDiscoveryForm.stale_asset_threshold_days.toString())"
            style="margin-left: 10px"
          >
            Save
          </el-button>
          <br />
          <el-text size="small" type="info">
            Days before marking an asset as offline if not seen in logs
          </el-text>
        </el-form-item>
      </el-form>

      <el-alert v-if="authStore.user?.role !== 'admin'" type="warning" :closable="false" style="margin-top: 20px">
        You do not have permission to modify settings. Contact an administrator.
      </el-alert>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { api } from '@/services/api';
import { ElMessage } from 'element-plus';
import HelpTip from '@/components/HelpTip.vue';
import { useAuthStore } from '@/stores/auth';
const authStore = useAuthStore();

const autoDiscoveryLoading = ref(false);
const autoDiscoverySaving = ref(false);

const autoDiscoveryForm = reactive({
  auto_discovery_enabled: true,
  auto_discovery_interval_minutes: 360,
  stale_asset_threshold_days: 30
});

onMounted(() => {
  fetchAutoDiscoverySettings();
});

async function fetchAutoDiscoverySettings() {
  autoDiscoveryLoading.value = true;
  try {
    // GET /settings/auto-discovery returns the parsed shape
    // { enabled, interval_minutes, stale_threshold_days }. Note the backend's
    // stale_threshold_days maps to this form's stale_asset_threshold_days.
    const { data } = await api.getAutoDiscoverySettings();
    autoDiscoveryForm.auto_discovery_enabled = !!data.enabled;
    if (Number.isFinite(data.interval_minutes)) {
      autoDiscoveryForm.auto_discovery_interval_minutes = data.interval_minutes;
    }
    if (Number.isFinite(data.stale_threshold_days)) {
      autoDiscoveryForm.stale_asset_threshold_days = data.stale_threshold_days;
    }
  } catch (error) {
    console.error('Failed to fetch auto-discovery settings', error);
  } finally {
    autoDiscoveryLoading.value = false;
  }
}

async function saveAutoDiscoverySetting(key: string, value: string) {
  if (authStore.user?.role !== 'admin') {
    ElMessage.warning('Only administrators can modify settings');
    return;
  }

  // The backend exposes a single PUT /settings/auto-discovery that takes a JSON
  // body ({ enabled?, interval_minutes?, stale_threshold_days? }) — there is no
  // per-key settings route. Map the one field being saved onto that contract.
  // The form's stale_asset_threshold_days maps to the backend's
  // stale_threshold_days.
  const payload: Record<string, boolean | number> = {};
  if (key === 'auto_discovery_enabled') {
    payload.enabled = value === 'true';
  } else if (key === 'auto_discovery_interval_minutes') {
    payload.interval_minutes = parseInt(value, 10);
  } else if (key === 'stale_asset_threshold_days') {
    payload.stale_threshold_days = parseInt(value, 10);
  } else {
    return;
  }

  autoDiscoverySaving.value = true;
  try {
    await api.updateAutoDiscoverySettings(payload);
    ElMessage.success('Setting updated successfully');

    if (key === 'auto_discovery_interval_minutes') {
      ElMessage.info('Auto-discovery will use the new interval on the next run');
    }
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to update setting');
    console.error(error);
  } finally {
    autoDiscoverySaving.value = false;
  }
}
</script>
