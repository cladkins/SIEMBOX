<template>
  <div class="application-settings">
    <el-card v-loading="loading">
      <template #header>
        <span>Software inventory</span>
      </template>

      <el-alert v-if="loadError" type="error" :closable="false" :title="loadError" show-icon style="margin-bottom: 16px" />

      <p class="intro">
        Application Monitoring lists the software SIEMBox sees: a background job matches log program names, parsers, nmap
        services, shipper-reported containers, endpoint-agent findings, user agents and DNS queries against the catalog's
        application signatures every two minutes, a few minutes behind ingestion. Ingestion itself is unchanged.
      </p>

      <el-descriptions v-if="status" :column="1" size="small" border class="status">
        <el-descriptions-item label="Status">
          <el-tag size="small" :type="!status.enabled ? 'info' : status.caught_up ? 'success' : 'warning'">
            {{ !status.enabled ? 'Switched off' : status.caught_up ? 'Up to date' : 'Building (processing existing logs)' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="Signatures">{{ signatureSourceText(status.signatures.source, status.signatures.count) }}</el-descriptions-item>
        <el-descriptions-item v-if="status.last_summary" label="Last run">{{ status.last_summary }}</el-descriptions-item>
        <el-descriptions-item label="Stored">{{ status.rows.toLocaleString('en-US') }} inventory rows, {{ size(status.bytes) }}</el-descriptions-item>
      </el-descriptions>

      <el-form :model="form" label-width="220px" class="form">
        <el-form-item label="Build the inventory">
          <el-switch v-model="form.enabled" />
          <el-text size="small" type="info" class="hint">Off: the job stops at its next run and the page says so.</el-text>
        </el-form-item>
        <el-form-item label="Keep listed for (days)">
          <el-input-number v-model="form.retention_days" :min="1" :max="3650" />
          <el-text size="small" type="info" class="hint">
            An application, version or location not seen for this long drops out. Scan, container and endpoint evidence follows
            its source at once (an upgraded image replaces the old version).
          </el-text>
        </el-form-item>
        <el-form-item label="Backfill on upgrade (days)">
          <el-input-number v-model="form.backfill_days" :min="0" :max="90" />
          <el-text size="small" type="info" class="hint">Existing logs processed the first time the job runs. Has no effect afterwards.</el-text>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="saving" @click="save">Save</el-button>
          <el-button @click="load">Reset</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { ElMessage } from 'element-plus';
import { api } from '@/services/api';
import { signatureSourceText } from '@/utils/applications';

interface Status {
  enabled: boolean;
  caught_up: boolean;
  last_summary: string | null;
  signatures: { source: string | null; count: number };
  rows: number;
  bytes: number;
}

const loading = ref(false);
const saving = ref(false);
const loadError = ref('');
const status = ref<Status | null>(null);
const form = reactive({ enabled: true, retention_days: 30, backfill_days: 7 });

const size = (bytes: number) =>
  bytes >= 1 << 30 ? `${(bytes / (1 << 30)).toFixed(1)} GB` : bytes >= 1 << 20 ? `${(bytes / (1 << 20)).toFixed(1)} MB` : `${Math.round(bytes / 1024)} kB`;

function apply(data: { inventory: typeof form; status: Status }) {
  Object.assign(form, data.inventory);
  status.value = data.status;
}

function message(err: unknown, fallback: string): string {
  return (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? fallback;
}

async function load() {
  loading.value = true;
  loadError.value = '';
  try {
    apply((await api.getApplicationSettings()).data);
  } catch (err) {
    loadError.value = message(err, 'Could not load the Application Monitoring settings.');
  } finally {
    loading.value = false;
  }
}

async function save() {
  saving.value = true;
  try {
    apply((await api.updateApplicationSettings({ ...form })).data);
    ElMessage.success('Application Monitoring settings saved');
  } catch (err) {
    ElMessage.error(message(err, 'Could not save the Application Monitoring settings.'));
  } finally {
    saving.value = false;
  }
}

onMounted(load);
</script>

<style scoped>
.intro {
  margin: 0 0 16px;
  color: var(--siembox-text-secondary);
  font-size: 13px;
}
.status {
  margin-bottom: 20px;
}
.hint {
  display: block;
  width: 100%;
  line-height: 1.4;
  margin-top: 4px;
}
@media (max-width: 768px) {
  .form :deep(.el-form-item) {
    flex-direction: column;
    align-items: flex-start;
  }
  .form :deep(.el-form-item__label) {
    justify-content: flex-start;
    width: auto !important;
  }
}
</style>
