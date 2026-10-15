<template>
  <el-dialog
    :model-value="modelValue"
    @update:model-value="(v: boolean) => emit('update:modelValue', v)"
    title="Alert Details"
    width="900px"
    @closed="tab = initialTab"
  >
    <div v-if="alert" class="alert-detail">
      <el-tabs v-model="tab">
        <el-tab-pane label="Details" name="details">
          <el-descriptions :column="2" border>
            <el-descriptions-item label="Severity">
              <el-tag :type="getSeverityType(alert.severity)">
                {{ alert.severity.toUpperCase() }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="Status">
              <el-tag :type="getStatusType(alert.status)">
                {{ formatStatus(alert.status) }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="Title" :span="2">
              {{ alert.title }}
            </el-descriptions-item>
            <el-descriptions-item label="Description" :span="2">
              {{ alert.description || 'N/A' }}
            </el-descriptions-item>
            <el-descriptions-item label="Created">
              {{ formatDate(alert.created_at) }}
            </el-descriptions-item>
            <el-descriptions-item label="Updated">
              {{ formatDate(alert.updated_at) }}
            </el-descriptions-item>
          </el-descriptions>

          <div class="matched-data">
            <h4>Matched Data</h4>
            <pre>{{ JSON.stringify(alert.matched_data, null, 2) }}</pre>
            <!-- A leaked-credential alert carries HIBP breach data (CC BY 4.0): credit it here. -->
            <HibpAttribution v-if="isHibpAlert(alert)" />
            <!-- Raised by a Digital Risk finding: open that finding (every role can). -->
            <p v-if="isExposureAlert(alert)" class="finding-link">
              <router-link
                :to="{ path: '/digital-risk', query: { alert_id: String(alert.id) } }"
                @click="emit('update:modelValue', false)"
              >View finding on the Digital Risk page →</router-link>
            </p>
          </div>

          <div class="alert-explain">
            <ExplainWithAI kind="alert" :data="explainPayload(alert)" label="Explain this alert" />
          </div>
        </el-tab-pane>

        <el-tab-pane label="AI Triage" name="triage">
          <AlertTriagePanel
            :key="alert.id"
            :alert-id="alert.id"
            :severity="alert.severity"
            @use-status="(status: string) => emit('edit-status', alert!, status)"
          />
        </el-tab-pane>
      </el-tabs>
    </div>

    <template #footer>
      <el-button v-if="authStore.canAnalyst" type="success" @click="alert && emit('edit-status', alert)">Update Status</el-button>
      <el-button @click="emit('update:modelValue', false)">Close</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { format } from 'date-fns';
import type { Alert } from '@/stores/alerts';
import ExplainWithAI from '@/components/ExplainWithAI.vue';
import AlertTriagePanel from '@/components/AlertTriagePanel.vue';
import HibpAttribution from '@/components/HibpAttribution.vue';
import { isHibpAlert } from '@/utils/exposure';
import { useAuthStore } from '@/stores/auth';

const props = withDefaults(
  defineProps<{
    modelValue: boolean;
    alert: Alert | null;
    initialTab?: 'details' | 'triage';
  }>(),
  { initialTab: 'details' }
);

const emit = defineEmits<{
  'update:modelValue': [value: boolean];
  'edit-status': [alert: Alert, proposedStatus?: string];
}>();

// Changing an alert's status is analyst and up; viewers only read it.
const authStore = useAuthStore();

const tab = ref(props.initialTab);
watch(
  () => props.modelValue,
  (open) => {
    if (open) tab.value = props.initialTab;
  }
);

// Alerts the exposure jobs raise for their findings (findingWriter.ts sets the source).
const isExposureAlert = (alert: Alert) => alert.source === 'leaked-creds' || alert.source === 'domain-monitor';

const explainPayload = (alert: Alert) => ({
  severity: alert.severity,
  status: alert.status,
  title: alert.title,
  description: alert.description,
  created_at: alert.created_at,
  matched_data: alert.matched_data,
});

const getSeverityType = (severity: string) => {
  const types: Record<string, any> = { critical: 'danger', high: 'warning', medium: 'primary', low: 'success' };
  return types[severity] || 'info';
};
const getStatusType = (status: string) => {
  const types: Record<string, any> = { new: 'primary', investigating: 'warning', closed: 'success', false_positive: 'info' };
  return types[status] || 'info';
};
const formatStatus = (status: string) => status.replace('_', ' ').replace(/\b\w/g, (l) => l.toUpperCase());
const formatDate = (date: string) => format(new Date(date), 'MMM dd, yyyy HH:mm:ss');
</script>

<style scoped>
.alert-detail {
  padding: 10px 0;
}
.matched-data {
  margin-top: 20px;
}
.matched-data h4 {
  margin-bottom: 10px;
  color: var(--siembox-text-color);
}
.matched-data pre {
  background: var(--siembox-bg-color);
  padding: 15px;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 12px;
}
.alert-explain {
  margin-top: 16px;
}
.finding-link {
  margin: 10px 0 0;
  font-size: 13px;
}
.finding-link a {
  color: var(--el-color-primary);
  text-decoration: none;
}
.finding-link a:hover {
  text-decoration: underline;
}
</style>
