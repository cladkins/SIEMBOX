<template>
  <div class="alerts">
    <el-card class="filter-card">
      <el-form :inline="true" :model="filters" class="filter-form">
        <el-form-item label="Search">
          <el-input
            v-model="filters.search"
            clearable
            placeholder="Keyword or IP…"
            style="width: 240px"
            @keyup.enter="applySearch"
            @clear="applySearch"
          >
            <template #prefix><el-icon><Search /></el-icon></template>
          </el-input>
        </el-form-item>

        <el-form-item label="Severity">
          <el-select v-model="filters.severity" clearable placeholder="All" style="width: 150px" @change="applySearch">
            <el-option label="Critical" value="critical" />
            <el-option label="High" value="high" />
            <el-option label="Medium" value="medium" />
            <el-option label="Low" value="low" />
          </el-select>
        </el-form-item>

        <el-form-item label="Status">
          <el-select v-model="filters.status" clearable placeholder="All" style="width: 160px" @change="applySearch">
            <el-option label="New" value="new" />
            <el-option label="Investigating" value="investigating" />
            <el-option label="Closed" value="closed" />
            <el-option label="False Positive" value="false_positive" />
          </el-select>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="applySearch">
            <el-icon><Search /></el-icon> Search
          </el-button>
          <el-button @click="resetFilters">Reset</el-button>
          <el-dropdown trigger="click" @command="exportAlerts" style="margin-left: 12px">
            <el-button :loading="exporting">
              <el-icon><Download /></el-icon> Export<el-icon class="el-icon--right"><ArrowDown /></el-icon>
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="csv">Export CSV</el-dropdown-item>
                <el-dropdown-item command="json">Export JSON</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="table-card">
      <el-table :data="alertsStore.alerts" v-loading="alertsStore.loading" stripe>
        <el-table-column prop="severity" label="Severity" width="120" sortable>
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)">
              {{ row.severity.toUpperCase() }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column prop="title" label="Title" min-width="300" show-overflow-tooltip />

        <el-table-column prop="status" label="Status" width="150">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)">
              {{ formatStatus(row.status) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column v-if="triageStore.enabled" label="Triage" width="150">
          <template #default="{ row }">
            <span v-if="!row.triage_status" class="triage-dash">—</span>
            <el-tag v-else-if="row.triage_status === 'pending' || row.triage_status === 'analyzing'" type="warning" size="small">
              <el-icon class="spin"><Loading /></el-icon> analyzing
            </el-tag>
            <el-tag v-else-if="row.triage_status === 'complete'" :type="triageVerdictType(row.triage_verdict)" size="small">
              {{ triageVerdictLabel(row.triage_verdict) }} · {{ row.triage_risk_score ?? '—' }}
            </el-tag>
            <el-tag v-else-if="row.triage_status === 'failed'" type="danger" size="small">failed</el-tag>
            <el-tag v-else type="info" size="small">skipped</el-tag>
          </template>
        </el-table-column>

        <el-table-column prop="created_at" label="Created" width="180" sortable>
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>

        <el-table-column label="Actions" width="200" fixed="right">
          <template #default="{ row }">
            <el-button type="primary" size="small" @click="viewAlert(row)">View</el-button>
            <el-button type="success" size="small" @click="updateStatus(row)">Update</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50, 100]"
        :total="alertsStore.total"
        layout="total, sizes, prev, pager, next"
        @size-change="fetchAlerts"
        @current-change="fetchAlerts"
        class="pagination"
      />
    </el-card>

    <!-- Alert Detail Dialog -->
    <AlertDetailDialog
      v-model="detailDialogVisible"
      :alert="selectedAlert"
      :initial-tab="detailInitialTab"
      @edit-status="onEditStatus"
    />

    <!-- Update Status Dialog -->
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
        <el-button type="primary" @click="submitStatusUpdate" :loading="updating">
          Update
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { useAlertsStore, type Alert } from '@/stores/alerts';
import { useTriageStore } from '@/stores/triage';
import { ElMessage } from 'element-plus';
import { format } from 'date-fns';
import { Search, Download, ArrowDown, Loading } from '@element-plus/icons-vue';
import { api } from '@/services/api';
import AlertDetailDialog from '@/components/AlertDetailDialog.vue';

const alertsStore = useAlertsStore();
const triageStore = useTriageStore();

const filters = ref({
  severity: '',
  status: '',
  search: '',
});

const currentPage = ref(1);
const pageSize = ref(20);

const detailDialogVisible = ref(false);
const detailInitialTab = ref<'details' | 'triage'>('details');
const statusDialogVisible = ref(false);
const selectedAlert = ref<Alert | null>(null);
const statusForm = ref({
  status: '',
  description: '',
});
const updating = ref(false);

let triagePollTimer: number | null = null;

onMounted(() => {
  fetchAlerts();
  triageStore.checkHealth();
  // Only refetch the list while some visible row is still being analyzed —
  // mirrors ContainerScanning.vue's self-terminating poll (no websockets in
  // this app).
  triagePollTimer = window.setInterval(() => {
    const hasPending = alertsStore.alerts.some(
      (a) => a.triage_status === 'pending' || a.triage_status === 'analyzing'
    );
    if (hasPending) fetchAlerts();
  }, 8000);
});

onUnmounted(() => {
  if (triagePollTimer) window.clearInterval(triagePollTimer);
});

const fetchAlerts = async () => {
  const params: any = {
    limit: pageSize.value,
    offset: (currentPage.value - 1) * pageSize.value,
  };

  if (filters.value.severity) {
    params.severity = filters.value.severity;
  }
  if (filters.value.status) {
    params.status = filters.value.status;
  }
  if (filters.value.search && filters.value.search.trim()) {
    params.search = filters.value.search.trim();
  }

  try {
    await alertsStore.fetchAlerts(params);
  } catch (error) {
    ElMessage.error('Failed to fetch alerts');
  }
};

const applySearch = () => {
  currentPage.value = 1;
  fetchAlerts();
};

const resetFilters = () => {
  filters.value = { severity: '', status: '', search: '' };
  currentPage.value = 1;
  fetchAlerts();
};

const exporting = ref(false);
const exportAlerts = async (fmt: 'csv' | 'json') => {
  exporting.value = true;
  try {
    // Export the current filtered view (server caps the row count).
    const params: any = {};
    if (filters.value.severity) params.severity = filters.value.severity;
    if (filters.value.status) params.status = filters.value.status;
    if (filters.value.search && filters.value.search.trim()) params.search = filters.value.search.trim();

    const res = await api.exportAlerts(params, fmt);
    const blob = new Blob([res.data], { type: fmt === 'json' ? 'application/json' : 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `siembox-alerts-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.${fmt}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    ElMessage.success(`Exported alerts as ${fmt.toUpperCase()}`);
  } catch (error) {
    ElMessage.error('Export failed');
  } finally {
    exporting.value = false;
  }
};

const viewAlert = (alert: Alert) => {
  selectedAlert.value = alert;
  detailInitialTab.value = 'details';
  detailDialogVisible.value = true;
};

const updateStatus = (alert: Alert) => {
  onEditStatus(alert);
};

// Triggered either by the row's "Update" button or the detail dialog's
// footer/"Use suggested status" action (the latter passes the AI's proposed
// status as a pre-fill — the actual change still requires this explicit form submit).
const onEditStatus = (alert: Alert, proposedStatus?: string) => {
  selectedAlert.value = alert;
  statusForm.value = {
    status: proposedStatus || alert.status,
    description: alert.description || '',
  };
  statusDialogVisible.value = true;
};

const triageVerdictType = (v?: string | null) =>
  ({ true_positive: 'danger', suspicious: 'warning', false_positive: 'success', inconclusive: 'info' } as Record<
    string,
    string
  >)[v || 'inconclusive'] || 'info';
const triageVerdictLabel = (v?: string | null) => (v || 'inconclusive').replace('_', ' ');

const submitStatusUpdate = async () => {
  if (!selectedAlert.value) return;

  updating.value = true;
  try {
    await alertsStore.updateAlert(selectedAlert.value.id, statusForm.value);
    ElMessage.success('Alert updated successfully');
    statusDialogVisible.value = false;
    fetchAlerts();
  } catch (error) {
    ElMessage.error('Failed to update alert');
  } finally {
    updating.value = false;
  }
};

const getSeverityType = (severity: string) => {
  const types: Record<string, any> = {
    critical: 'danger',
    high: 'warning',
    medium: 'primary',
    low: 'success',
  };
  return types[severity] || 'info';
};

const getStatusType = (status: string) => {
  const types: Record<string, any> = {
    new: 'primary',
    investigating: 'warning',
    closed: 'success',
    false_positive: 'info',
  };
  return types[status] || 'info';
};

const formatStatus = (status: string) => {
  return status.replace('_', ' ').replace(/\b\w/g, (l) => l.toUpperCase());
};

const formatDate = (date: string) => {
  return format(new Date(date), 'MMM dd, yyyy HH:mm:ss');
};
</script>

<style scoped>
.alerts {
  padding: 0;
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
</style>
