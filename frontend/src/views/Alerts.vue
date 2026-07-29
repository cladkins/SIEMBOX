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
          <el-tooltip
            content="One log can satisfy several detection rules, so a single event otherwise appears as several rows. Grouped shows one row per event, titled by its most severe detection."
            placement="top"
          >
            <el-switch
              v-model="groupByEvent"
              active-text="Group by event"
              @change="toggleGrouping"
            />
          </el-tooltip>
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
      <el-table
        :data="alertsStore.alerts"
        v-loading="alertsStore.loading"
        stripe
        :row-class-name="rowClassName"
      >
        <el-table-column v-if="groupByEvent" type="expand">
          <template #default="{ row }">
            <div v-if="groupSize(row) > 1" class="correlated">
              <div class="correlated-head">
                {{ groupSize(row) }} rules matched this event — one piece of evidence, {{ groupSize(row) }} independent detections.
              </div>
              <el-table :data="row.correlated" size="small" stripe>
                <el-table-column label="Severity" width="110">
                  <template #default="{ row: c }">
                    <el-tag :type="getSeverityType(c.severity)" size="small">
                      {{ c.severity.toUpperCase() }}
                    </el-tag>
                  </template>
                </el-table-column>
                <el-table-column prop="title" label="Detection" min-width="320" show-overflow-tooltip />
                <el-table-column label="Status" width="140">
                  <template #default="{ row: c }">
                    <el-tag :type="getStatusType(c.status)" size="small">{{ formatStatus(c.status) }}</el-tag>
                  </template>
                </el-table-column>
                <el-table-column label="Created" width="180">
                  <template #default="{ row: c }">{{ formatDate(c.created_at) }}</template>
                </el-table-column>
                <el-table-column label="Actions" width="200">
                  <template #default="{ row: c }">
                    <el-button
                      type="primary"
                      size="small"
                      :loading="loadingCorrelated === c.id"
                      @click="openCorrelated(c, 'view')"
                    >View</el-button>
                    <el-button
                      type="success"
                      size="small"
                      :loading="loadingCorrelated === c.id"
                      @click="openCorrelated(c, 'update')"
                    >Update</el-button>
                  </template>
                </el-table-column>
              </el-table>
            </div>
          </template>
        </el-table-column>

        <el-table-column prop="severity" label="Severity" width="120" sortable>
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)">
              {{ row.severity.toUpperCase() }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="Title" min-width="300" show-overflow-tooltip>
          <template #default="{ row }">
            <span>{{ row.title }}</span>
            <el-tooltip
              v-if="groupSize(row) > 1"
              :content="`${groupSize(row)} detection rules matched this single event. The most severe one titles the row; expand to see the rest.`"
              placement="top"
            >
              <el-tag size="small" type="info" class="group-badge">+{{ groupSize(row) - 1 }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>

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
import { useRoute } from 'vue-router';
import { useAlertsStore, type Alert } from '@/stores/alerts';
import { useTriageStore } from '@/stores/triage';
import { ElMessage } from 'element-plus';
import { format } from 'date-fns';
import { Search, Download, ArrowDown, Loading } from '@element-plus/icons-vue';
import { api } from '@/services/api';
import AlertDetailDialog from '@/components/AlertDetailDialog.vue';

const route = useRoute();
const alertsStore = useAlertsStore();
const triageStore = useTriageStore();

const filters = ref({
  severity: '',
  status: '',
  search: '',
});

// Deep-link support: the dashboard's severity charts click through here as
// e.g. /alerts?severity=critical.
const initialSeverity = route.query.severity;
if (typeof initialSeverity === 'string') {
  filters.value.severity = initialSeverity;
}

// One log can satisfy several rules — the engine evaluates all of them with no
// early exit — so the flat list shows one event as N rows. Grouped is the
// default because that fan-out reads as N separate problems otherwise; the
// toggle restores the flat, one-row-per-alert view.
const groupByEvent = ref(true);

const currentPage = ref(1);
const pageSize = ref(20);

/** Number of alerts in this row's event group (1 when ungrouped). */
function groupSize(row: any): number {
  return row?.correlated_count ?? 1;
}

/** Element Plus always draws the expand arrow; hide it where there is nothing to open. */
function rowClassName({ row }: { row: any }): string {
  return groupSize(row) > 1 ? '' : 'no-expand';
}

function toggleGrouping() {
  currentPage.value = 1; // page N of the grouped list is not page N of the flat one
  fetchAlerts();
}

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
  if (groupByEvent.value) {
    params.group = 'event';
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

/** Which correlated alert is being fetched, so only its buttons show a spinner. */
const loadingCorrelated = ref<number | null>(null);

/**
 * Open a correlated (non-representative) alert in the normal detail or status
 * dialog.
 *
 * The `correlated` entries carried by a grouped row are summaries — id,
 * severity, title, status, created_at — deliberately without `description` or
 * `matched_data`. Those are the large fields, and repeating them for every
 * member of every group would balloon the list response for data most rows
 * never open. So fetch the full alert on demand; the detail endpoint already
 * exists and the dialogs are unchanged.
 */
async function openCorrelated(summary: { id: number }, mode: 'view' | 'update') {
  loadingCorrelated.value = summary.id;
  try {
    const { data } = await api.getAlert(summary.id);
    if (mode === 'view') viewAlert(data);
    else updateStatus(data);
  } catch (error) {
    ElMessage.error('Failed to load alert');
  } finally {
    loadingCorrelated.value = null;
  }
}

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

/* Event grouping: correlated detections shown inside an expanded row. */
.group-badge {
  margin-left: 8px;
  vertical-align: middle;
}

.correlated {
  padding: 8px 16px 12px 48px;
}

.correlated-head {
  margin-bottom: 8px;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}

/* Element Plus renders the expand arrow on every row; a group of one has
   nothing to open, so hide the control rather than offer an empty drawer. */
.el-table :deep(.no-expand) .el-table__expand-icon {
  visibility: hidden;
  cursor: default;
}
</style>
