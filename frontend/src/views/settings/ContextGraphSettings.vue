<template>
  <div class="context-graph-settings">
    <el-card v-loading="loading">
      <template #header>
        <span>Relationships seen in logs</span>
      </template>

      <el-alert v-if="loadError" type="error" :closable="false" :title="loadError" show-icon style="margin-bottom: 16px" />

      <p class="intro">
        The Context Graph's dashed links (which IP signed in as which user, which device logged it, which domains an IP queried)
        come from a background job that rolls up parsed logs every minute, a few minutes behind ingestion. Ingestion itself is unchanged.
      </p>

      <el-descriptions v-if="status" :column="1" size="small" border class="status">
        <el-descriptions-item label="Status">
          <el-tag size="small" :type="STATUS_TAG[status.status] ?? 'info'">{{ STATUS_TEXT[status.status] ?? status.status }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item v-if="status.covered_from" label="Covers logs from">{{ status.covered_from }}</el-descriptions-item>
        <el-descriptions-item v-if="status.covered_until" label="Up to">{{ when(status.covered_until) }}</el-descriptions-item>
        <el-descriptions-item v-if="status.incomplete_days?.length" label="Incomplete days">
          {{ status.incomplete_days.join(', ') }} (the daily cap was reached: too many distinct values)
        </el-descriptions-item>
        <el-descriptions-item label="Stored">
          about {{ status.rows.toLocaleString('en-US') }} relationships, {{ size(status.bytes) }}
        </el-descriptions-item>
      </el-descriptions>

      <el-form :model="form" label-width="220px" class="form">
        <el-form-item label="Build relationships">
          <el-switch v-model="form.enabled" />
          <el-text size="small" type="info" class="hint">Off: the job stops within a minute and the graph says so.</el-text>
        </el-form-item>
        <el-form-item label="Keep for (days)">
          <el-input-number v-model="form.retention_days" :min="0" :max="3650" />
          <el-text size="small" type="info" class="hint">
            0 = as long as raw logs ({{ status ? `${status.raw_logs_retention_days} days` : 'Data Retention' }}). Longer keeps
            user, IP and host links after the logs that showed them are deleted.
          </el-text>
        </el-form-item>
        <el-form-item label="Backfill on upgrade (days)">
          <el-input-number v-model="form.backfill_days" :min="0" :max="90" />
          <el-text size="small" type="info" class="hint">Existing logs processed the first time the job runs. Has no effect afterwards.</el-text>
        </el-form-item>
        <el-form-item label="Daily new-relationship cap">
          <el-input-number v-model="form.daily_new_cap" :min="10000" :max="10000000" :step="50000" />
          <el-text size="small" type="info" class="hint">
            Past this many new relationships in a day (a spraying attacker can make one per log), that day only updates the
            ones it has and is marked incomplete. About 300 bytes each.
          </el-text>
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
import { format } from 'date-fns';
import { api } from '@/services/api';

interface Status {
  status: 'ok' | 'building' | 'behind' | 'disabled' | 'partial' | 'timeout';
  covered_from?: string;
  covered_until?: string;
  incomplete_days?: string[];
  effective_retention_days: number;
  raw_logs_retention_days: number;
  rows: number;
  bytes: number;
}

const STATUS_TEXT: Record<string, string> = {
  ok: 'Up to date',
  building: 'Building (processing existing logs)',
  behind: 'Behind: the job has not caught up in the last 5 minutes',
  disabled: 'Switched off',
};
const STATUS_TAG: Record<string, 'success' | 'warning' | 'info' | 'danger'> = {
  ok: 'success',
  building: 'warning',
  behind: 'warning',
  disabled: 'info',
};

const loading = ref(false);
const saving = ref(false);
const loadError = ref('');
const status = ref<Status | null>(null);
const form = reactive({ enabled: true, retention_days: 0, backfill_days: 7, daily_new_cap: 500000 });

const when = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : format(d, 'yyyy-MM-dd HH:mm');
};
const size = (bytes: number) =>
  bytes >= 1 << 30 ? `${(bytes / (1 << 30)).toFixed(1)} GB` : bytes >= 1 << 20 ? `${(bytes / (1 << 20)).toFixed(1)} MB` : `${Math.round(bytes / 1024)} kB`;

function apply(data: { log_edges: typeof form; status: Status }) {
  Object.assign(form, data.log_edges);
  status.value = data.status;
}

function message(err: unknown, fallback: string): string {
  const data = (err as { response?: { data?: { message?: string } } })?.response?.data;
  return data?.message ?? fallback;
}

async function load() {
  loading.value = true;
  loadError.value = '';
  try {
    apply((await api.getContextGraphSettings()).data);
  } catch (err) {
    loadError.value = message(err, 'Could not load the Context Graph settings.');
  } finally {
    loading.value = false;
  }
}

async function save() {
  saving.value = true;
  try {
    apply((await api.updateContextGraphSettings({ ...form })).data);
    ElMessage.success('Context Graph settings saved');
  } catch (err) {
    ElMessage.error(message(err, 'Could not save the Context Graph settings.'));
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
