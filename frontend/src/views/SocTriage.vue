<template>
  <div class="soc-triage">
    <el-alert
      v-if="!triageStore.enabled || triageStore.notConfigured"
      class="cfg-alert"
      type="warning"
      :closable="false"
      show-icon
      title="AI Triage is not configured"
    >
      An admin can enable automatic alert analysis in
      <router-link to="/settings">Settings → AI Triage</router-link>. Once enabled, new
      {{ triageStore.minSeverity }}+ severity alerts are analyzed automatically and appear here.
    </el-alert>

    <el-card class="filter-card">
      <el-form :inline="true" :model="filters" class="filter-form">
        <el-form-item label="Verdict">
          <el-select v-model="filters.triageVerdict" clearable placeholder="All" style="width: 170px" @change="applyFilters">
            <el-option label="True Positive" value="true_positive" />
            <el-option label="Suspicious" value="suspicious" />
            <el-option label="False Positive" value="false_positive" />
            <el-option label="Inconclusive" value="inconclusive" />
          </el-select>
        </el-form-item>
        <el-form-item label="Triage status">
          <el-select v-model="filters.triageStatus" clearable placeholder="All" style="width: 160px" @change="applyFilters">
            <el-option label="Pending" value="pending" />
            <el-option label="Analyzing" value="analyzing" />
            <el-option label="Complete" value="complete" />
            <el-option label="Failed" value="failed" />
            <el-option label="Skipped" value="skipped" />
          </el-select>
        </el-form-item>
        <el-form-item label="Severity">
          <el-select v-model="filters.severity" clearable placeholder="All" style="width: 140px" @change="applyFilters">
            <el-option label="Critical" value="critical" />
            <el-option label="High" value="high" />
            <el-option label="Medium" value="medium" />
            <el-option label="Low" value="low" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button @click="resetFilters">Reset</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="table-card">
      <el-table :data="rows" v-loading="loading" stripe @row-click="openRow">
        <el-table-column label="Risk" width="90">
          <template #default="{ row }">
            <span v-if="row.triage_status === 'complete'" class="risk-score">{{ row.triage_risk_score ?? '—' }}</span>
            <span v-else class="triage-dash">—</span>
          </template>
        </el-table-column>
        <el-table-column label="Verdict" width="150">
          <template #default="{ row }">
            <el-tag
              v-if="row.triage_status === 'pending' || row.triage_status === 'analyzing'"
              type="warning"
              size="small"
            >
              <el-icon class="spin"><Loading /></el-icon> analyzing
            </el-tag>
            <el-tag v-else-if="row.triage_status === 'complete'" :type="verdictType(row.triage_verdict)" size="small">
              {{ verdictLabel(row.triage_verdict) }}
            </el-tag>
            <el-tag v-else-if="row.triage_status === 'failed'" type="danger" size="small">failed</el-tag>
            <el-tag v-else-if="row.triage_status === 'skipped'" type="info" size="small">skipped</el-tag>
            <span v-else class="triage-dash">—</span>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="Severity" width="110">
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)">{{ row.severity.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="title" label="Title" min-width="280" show-overflow-tooltip />
        <el-table-column prop="status" label="Status" width="140">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)">{{ formatStatus(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="Created" width="180">
          <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="Actions" width="90" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click.stop="openRow(row)">View</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-empty v-if="!loading && rows.length === 0" description="No alerts match these filters" />

      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="[20, 50, 100]"
        :total="total"
        layout="total, sizes, prev, pager, next"
        @size-change="fetchRows"
        @current-change="fetchRows"
        class="pagination"
      />
    </el-card>

    <AlertDetailDialog v-model="detailVisible" :alert="selectedAlert" initial-tab="triage" @edit-status="onEditStatus" />

    <el-dialog v-model="statusDialogVisible" title="Update Alert Status" width="500px">
      <el-form v-if="selectedAlert" :model="statusForm" label-width="100px">
        <el-form-item label="Status">
          <el-select v-model="statusForm.status">
            <el-option label="New" value="new" />
            <el-option label="Investigating" value="investigating" />
            <el-option label="Closed" value="closed" />
            <el-option label="False Positive" value="false_positive" />
          </el-select>
        </el-form-item>
        <el-form-item label="Notes">
          <el-input v-model="statusForm.description" type="textarea" :rows="4" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="statusDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="submitStatusUpdate" :loading="updatingStatus">Update</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue';
import { format } from 'date-fns';
import { ElMessage } from 'element-plus';
import { Loading } from '@element-plus/icons-vue';
import { api } from '@/services/api';
import { useAlertsStore, type Alert } from '@/stores/alerts';
import { useTriageStore } from '@/stores/triage';
import AlertDetailDialog from '@/components/AlertDetailDialog.vue';

const alertsStore = useAlertsStore();
const triageStore = useTriageStore();

const rows = ref<Alert[]>([]);
const total = ref(0);
const loading = ref(false);
const currentPage = ref(1);
const pageSize = ref(20);

const filters = ref({
  triageVerdict: '',
  triageStatus: '',
  severity: '',
});

const detailVisible = ref(false);
const selectedAlert = ref<Alert | null>(null);
const statusDialogVisible = ref(false);
const statusForm = ref({ status: '', description: '' });
const updatingStatus = ref(false);

let pollTimer: number | null = null;

async function fetchRows() {
  loading.value = true;
  try {
    const params: any = {
      limit: pageSize.value,
      offset: (currentPage.value - 1) * pageSize.value,
      sortBy: 'risk_score',
    };
    if (filters.value.triageVerdict) params.triageVerdict = filters.value.triageVerdict;
    if (filters.value.triageStatus) params.triageStatus = filters.value.triageStatus;
    if (filters.value.severity) params.severity = filters.value.severity;
    const res = await api.getAlerts(params);
    rows.value = res.data.alerts;
    total.value = res.data.total;
  } catch {
    ElMessage.error('Failed to fetch triage queue');
  } finally {
    loading.value = false;
  }
}

function applyFilters() {
  currentPage.value = 1;
  fetchRows();
}
function resetFilters() {
  filters.value = { triageVerdict: '', triageStatus: '', severity: '' };
  applyFilters();
}

function openRow(row: Alert) {
  selectedAlert.value = row;
  detailVisible.value = true;
}

function onEditStatus(alert: Alert, proposedStatus?: string) {
  selectedAlert.value = alert;
  statusForm.value = { status: proposedStatus || alert.status, description: alert.description || '' };
  statusDialogVisible.value = true;
}

async function submitStatusUpdate() {
  if (!selectedAlert.value) return;
  updatingStatus.value = true;
  try {
    await alertsStore.updateAlert(selectedAlert.value.id, statusForm.value);
    ElMessage.success('Alert updated successfully');
    statusDialogVisible.value = false;
    fetchRows();
  } catch {
    ElMessage.error('Failed to update alert');
  } finally {
    updatingStatus.value = false;
  }
}

function verdictType(v?: string | null): string {
  return (
    ({ true_positive: 'danger', suspicious: 'warning', false_positive: 'success', inconclusive: 'info' } as Record<
      string,
      string
    >)[v || 'inconclusive'] || 'info'
  );
}
function verdictLabel(v?: string | null): string {
  return (v || 'inconclusive').replace('_', ' ');
}
function getSeverityType(severity: string) {
  return ({ critical: 'danger', high: 'warning', medium: 'primary', low: 'success' } as Record<string, string>)[
    severity
  ] || 'info';
}
function getStatusType(status: string) {
  return ({ new: 'primary', investigating: 'warning', closed: 'success', false_positive: 'info' } as Record<
    string,
    string
  >)[status] || 'info';
}
function formatStatus(status: string) {
  return status.replace('_', ' ').replace(/\b\w/g, (l) => l.toUpperCase());
}
function formatDate(date: string) {
  return format(new Date(date), 'MMM dd, yyyy HH:mm:ss');
}

onMounted(() => {
  triageStore.checkHealth();
  fetchRows();
  // Self-terminating poll, same pattern as Alerts.vue — only refetches while
  // something on the current page is still being analyzed.
  pollTimer = window.setInterval(() => {
    const hasPending = rows.value.some((r) => r.triage_status === 'pending' || r.triage_status === 'analyzing');
    if (hasPending) fetchRows();
  }, 8000);
});

onUnmounted(() => {
  if (pollTimer) window.clearInterval(pollTimer);
});
</script>

<style scoped>
.soc-triage {
  padding: 0;
}
.cfg-alert {
  margin-bottom: 20px;
}
.filter-card {
  margin-bottom: 20px;
}
.filter-form {
  margin: 0;
}
.table-card {
  margin-bottom: 20px;
}
.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}
.risk-score {
  font-weight: 600;
}
.triage-dash {
  color: var(--siembox-text-secondary);
}
.spin {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
:deep(.el-table__row) {
  cursor: pointer;
}
</style>
