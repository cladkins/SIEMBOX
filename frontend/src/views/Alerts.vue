<template>
  <div class="alerts">
    <el-card class="filter-card">
      <el-form :inline="true" :model="filters" class="filter-form">
        <el-form-item label="Severity">
          <el-select v-model="filters.severity" clearable placeholder="All" @change="fetchAlerts">
            <el-option label="Critical" value="critical" />
            <el-option label="High" value="high" />
            <el-option label="Medium" value="medium" />
            <el-option label="Low" value="low" />
          </el-select>
        </el-form-item>

        <el-form-item label="Status">
          <el-select v-model="filters.status" clearable placeholder="All" @change="fetchAlerts">
            <el-option label="New" value="new" />
            <el-option label="Investigating" value="investigating" />
            <el-option label="Closed" value="closed" />
            <el-option label="False Positive" value="false_positive" />
          </el-select>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="fetchAlerts">
            <el-icon><Search /></el-icon> Search
          </el-button>
          <el-button @click="resetFilters">Reset</el-button>
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
    <el-dialog v-model="detailDialogVisible" title="Alert Details" width="800px">
      <div v-if="selectedAlert" class="alert-detail">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="Severity">
            <el-tag :type="getSeverityType(selectedAlert.severity)">
              {{ selectedAlert.severity.toUpperCase() }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Status">
            <el-tag :type="getStatusType(selectedAlert.status)">
              {{ formatStatus(selectedAlert.status) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Title" :span="2">
            {{ selectedAlert.title }}
          </el-descriptions-item>
          <el-descriptions-item label="Description" :span="2">
            {{ selectedAlert.description || 'N/A' }}
          </el-descriptions-item>
          <el-descriptions-item label="Created">
            {{ formatDate(selectedAlert.created_at) }}
          </el-descriptions-item>
          <el-descriptions-item label="Updated">
            {{ formatDate(selectedAlert.updated_at) }}
          </el-descriptions-item>
        </el-descriptions>

        <div class="matched-data">
          <h4>Matched Data</h4>
          <pre>{{ JSON.stringify(selectedAlert.matched_data, null, 2) }}</pre>
        </div>
      </div>
    </el-dialog>

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
import { ref, onMounted } from 'vue';
import { useAlertsStore, type Alert } from '@/stores/alerts';
import { ElMessage } from 'element-plus';
import { format } from 'date-fns';
import { Search } from '@element-plus/icons-vue';

const alertsStore = useAlertsStore();

const filters = ref({
  severity: '',
  status: '',
});

const currentPage = ref(1);
const pageSize = ref(20);

const detailDialogVisible = ref(false);
const statusDialogVisible = ref(false);
const selectedAlert = ref<Alert | null>(null);
const statusForm = ref({
  status: '',
  description: '',
});
const updating = ref(false);

onMounted(() => {
  fetchAlerts();
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

  try {
    await alertsStore.fetchAlerts(params);
  } catch (error) {
    ElMessage.error('Failed to fetch alerts');
  }
};

const resetFilters = () => {
  filters.value = { severity: '', status: '' };
  currentPage.value = 1;
  fetchAlerts();
};

const viewAlert = (alert: Alert) => {
  selectedAlert.value = alert;
  detailDialogVisible.value = true;
};

const updateStatus = (alert: Alert) => {
  selectedAlert.value = alert;
  statusForm.value = {
    status: alert.status,
    description: alert.description || '',
  };
  statusDialogVisible.value = true;
};

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
</style>
