<template>
  <div class="dashboard">
    <!-- Section: Alerts -->
    <div class="section-header">
      <h3>Security Alerts</h3>
    </div>
    <el-row :gutter="20" class="stats-row">
      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card total">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="40"><Bell /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ alertStats?.total || 0 }}</div>
              <div class="stat-label">Total Alerts (24h)</div>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card critical">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="40"><WarningFilled /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ alertStats?.critical_count || 0 }}</div>
              <div class="stat-label">Critical Alerts</div>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card high">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="40"><Warning /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ alertStats?.high_count || 0 }}</div>
              <div class="stat-label">High Severity</div>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card new">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="40"><Document /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ alertStats?.new_count || 0 }}</div>
              <div class="stat-label">New Alerts</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- Section: Assets & Vulnerabilities -->
    <div class="section-header">
      <h3>Assets & Vulnerabilities</h3>
    </div>
    <el-row :gutter="20" class="stats-row">
      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card assets">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="40"><Monitor /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ Number(assetStats?.active_assets || 0) + Number(assetStats?.offline_assets || 0) }}</div>
              <div class="stat-label">Total Assets</div>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card assets-online">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="40"><CircleCheck /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ Number(assetStats?.active_assets || 0) }}</div>
              <div class="stat-label">Online Assets</div>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card vulns-critical">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="40"><WarnTriangleFilled /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ vulnStats?.critical_count || 0 }}</div>
              <div class="stat-label">Critical Vulns</div>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card vulns-total">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="40"><DataBoard /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ vulnStats?.total_vulnerabilities || 0 }}</div>
              <div class="stat-label">Total Vulnerabilities</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- Charts Row -->
    <el-row :gutter="20" class="charts-row">
      <el-col :xs="24" :md="12">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>Alerts by Severity</span>
            </div>
          </template>
          <div class="chart-container">
            <canvas ref="severityChart"></canvas>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :md="12">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>Alerts by Status</span>
            </div>
          </template>
          <div class="chart-container">
            <canvas ref="statusChart"></canvas>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- Recent Alerts Table -->
    <el-card class="recent-alerts">
      <template #header>
        <div class="card-header">
          <span>Recent Alerts</span>
          <el-button type="primary" size="small" @click="goToAlerts">View All</el-button>
        </div>
      </template>

      <el-table :data="recentAlerts" v-loading="loading" stripe>
        <el-table-column prop="severity" label="Severity" width="120">
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)">
              {{ row.severity.toUpperCase() }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column prop="title" label="Title" min-width="300" />

        <el-table-column prop="status" label="Status" width="150">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)">
              {{ formatStatus(row.status) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column prop="created_at" label="Time" width="180">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>

        <el-table-column label="Actions" width="100">
          <template #default="{ row }">
            <el-button type="primary" size="small" @click="viewAlert(row)">View</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue';
import { useRouter } from 'vue-router';
import { useAlertsStore } from '@/stores/alerts';
import { api } from '@/services/api';
import { Chart, registerables } from 'chart.js';
import { format } from 'date-fns';
import { Bell, WarningFilled, Warning, Document, Monitor, CircleCheck, WarnTriangleFilled, DataBoard } from '@element-plus/icons-vue';

Chart.register(...registerables);

const router = useRouter();
const alertsStore = useAlertsStore();

const alertStats = computed(() => alertsStore.statistics);
const recentAlerts = computed(() => alertsStore.alerts.slice(0, 10));
const loading = ref(false);

const assetStats = ref<any>(null);
const vulnStats = ref<any>(null);

const severityChart = ref<HTMLCanvasElement>();
const statusChart = ref<HTMLCanvasElement>();
let severityChartInstance: Chart | null = null;
let statusChartInstance: Chart | null = null;

onMounted(async () => {
  await loadData();
  createCharts();
});

// alertStats arrives asynchronously (and can refresh). The original code built
// the charts once in onMounted and bailed out (early return) whenever the stats
// weren't loaded yet, leaving the canvases permanently blank. Rebuild whenever
// the stats change; createCharts() destroys the prior instances first.
watch(alertStats, () => {
  createCharts();
});

const loadData = async () => {
  loading.value = true;
  try {
    await Promise.all([
      alertsStore.fetchStatistics(),
      alertsStore.fetchAlerts({ limit: 10 }),
      loadAssetStats(),
      loadVulnStats(),
    ]);
  } catch (error) {
    console.error('Failed to load dashboard data:', error);
  } finally {
    loading.value = false;
  }
};

const loadAssetStats = async () => {
  try {
    const response = await api.getAssetStatistics();
    assetStats.value = response.data;
  } catch (error) {
    console.error('Failed to load asset statistics:', error);
    assetStats.value = { active_assets: 0, offline_assets: 0 };
  }
};

const loadVulnStats = async () => {
  try {
    const response = await api.getVulnerabilitySummary();
    vulnStats.value = response.data;
  } catch (error) {
    console.error('Failed to load vulnerability statistics:', error);
    vulnStats.value = { total_vulnerabilities: 0, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0 };
  }
};

const createCharts = () => {
  if (!alertStats.value) return;

  // Destroy any prior instances before recreating — Chart.js throws "Canvas is
  // already in use" if a new chart is attached to a canvas that still owns one,
  // and leaving them around leaks on every refresh.
  severityChartInstance?.destroy();
  severityChartInstance = null;
  statusChartInstance?.destroy();
  statusChartInstance = null;

  // Severity Chart
  if (severityChart.value) {
    severityChartInstance = new Chart(severityChart.value, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [
          {
            data: [
              alertStats.value.critical_count,
              alertStats.value.high_count,
              alertStats.value.medium_count,
              alertStats.value.low_count,
            ],
            backgroundColor: ['#f56c6c', '#e6a23c', '#409eff', '#67c23a'],
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: {
            position: 'bottom',
          },
        },
      },
    });
  }

  // Status Chart
  if (statusChart.value) {
    statusChartInstance = new Chart(statusChart.value, {
      type: 'pie',
      data: {
        labels: ['New', 'Investigating', 'Closed'],
        datasets: [
          {
            data: [
              alertStats.value.new_count,
              alertStats.value.investigating_count,
              alertStats.value.closed_count,
            ],
            backgroundColor: ['#409eff', '#e6a23c', '#67c23a'],
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: {
            position: 'bottom',
          },
        },
      },
    });
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

const goToAlerts = () => {
  router.push('/alerts');
};

const viewAlert = (alert: any) => {
  router.push(`/alerts?id=${alert.id}`);
};
</script>

<style scoped>
.dashboard {
  padding: 0;
}

.section-header {
  margin-bottom: 15px;
  margin-top: 10px;
}

.section-header h3 {
  font-size: 16px;
  font-weight: 600;
  color: var(--siembox-text-color);
  margin: 0;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--siembox-border-color, #dcdfe6);
}

.stats-row {
  margin-bottom: 20px;
}

.stat-card {
  margin-bottom: 20px;
  background-color: var(--siembox-card-bg, #fff);
  transition: background-color 0.3s;
}

.stat-content {
  display: flex;
  align-items: center;
  gap: 20px;
}

.stat-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 70px;
  height: 70px;
  border-radius: 50%;
  background: rgba(64, 158, 255, 0.1);
  color: #409eff;
}

.stat-card.critical .stat-icon,
.stat-card.vulns-critical .stat-icon {
  background: rgba(245, 108, 108, 0.1);
  color: #f56c6c;
}

.stat-card.high .stat-icon {
  background: rgba(230, 162, 60, 0.1);
  color: #e6a23c;
}

.stat-card.new .stat-icon {
  background: rgba(103, 194, 58, 0.1);
  color: #67c23a;
}

.stat-card.assets .stat-icon {
  background: rgba(64, 158, 255, 0.1);
  color: #409eff;
}

.stat-card.assets-online .stat-icon {
  background: rgba(103, 194, 58, 0.1);
  color: #67c23a;
}

.stat-card.vulns-total .stat-icon {
  background: rgba(144, 147, 153, 0.1);
  color: var(--siembox-text-tertiary);
}

.stat-info {
  flex: 1;
}

.stat-value {
  font-size: 32px;
  font-weight: bold;
  color: var(--siembox-text-color);
}

.stat-label {
  font-size: 14px;
  color: var(--siembox-text-secondary, #909399);
  margin-top: 5px;
}

.charts-row {
  margin-bottom: 20px;
}

.chart-container {
  height: 300px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.recent-alerts {
  margin-bottom: 20px;
}
</style>
