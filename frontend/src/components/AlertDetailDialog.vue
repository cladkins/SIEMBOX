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
      <el-button type="success" @click="alert && emit('edit-status', alert)">Update Status</el-button>
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

const tab = ref(props.initialTab);
watch(
  () => props.modelValue,
  (open) => {
    if (open) tab.value = props.initialTab;
  }
);

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
</style>
