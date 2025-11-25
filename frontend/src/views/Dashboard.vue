<template>
  <div class="dashboard">
    <!-- Statistics Cards -->
    <el-row :gutter="20" class="stats-row">
      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card total">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="40"><Bell /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ statistics?.total || 0 }}</div>
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
              <div class="stat-value">{{ statistics?.critical_count || 0 }}</div>
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
              <div class="stat-value">{{ statistics?.high_count || 0 }}</div>
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
              <div class="stat-value">{{ statistics?.new_count || 0 }}</div>
              <div class="stat-label">New Alerts</div>
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
import { ref, onMounted, computed } from 'vue';
import { useRouter } from 'vue-router';
import { useAlertsStore } from '@/stores/alerts';
import { Chart, registerables } from 'chart.js';
import { format } from 'date-fns';
import { Bell, WarningFilled, Warning, Document } from '@element-plus/icons-vue';

Chart.register(...registerables);

const router = useRouter();
const alertsStore = useAlertsStore();

const statistics = computed(() => alertsStore.statistics);
const recentAlerts = computed(() => alertsStore.alerts.slice(0, 10));
const loading = ref(false);

const severityChart = ref<HTMLCanvasElement>();
const statusChart = ref<HTMLCanvasElement>();
let severityChartInstance: Chart | null = null;
let statusChartInstance: Chart | null = null;

onMounted(async () => {
  await loadData();
  createCharts();
});

const loadData = async () => {
  loading.value = true;
  try {
    await Promise.all([
      alertsStore.fetchStatistics(),
      alertsStore.fetchAlerts({ limit: 10 }),
    ]);
  } catch (error) {
    console.error('Failed to load dashboard data:', error);
  } finally {
    loading.value = false;
  }
};

const createCharts = () => {
  if (!statistics.value) return;

  // Severity Chart
  if (severityChart.value) {
    severityChartInstance = new Chart(severityChart.value, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [
          {
            data: [
              statistics.value.critical_count,
              statistics.value.high_count,
              statistics.value.medium_count,
              statistics.value.low_count,
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
              statistics.value.new_count,
              statistics.value.investigating_count,
              statistics.value.closed_count,
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

.stats-row {
  margin-bottom: 20px;
}

.stat-card {
  margin-bottom: 20px;
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

.stat-card.critical .stat-icon {
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

.stat-info {
  flex: 1;
}

.stat-value {
  font-size: 32px;
  font-weight: bold;
  color: #303133;
}

.stat-label {
  font-size: 14px;
  color: #909399;
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
