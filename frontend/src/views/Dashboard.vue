<template>
  <div class="dashboard">
    <el-alert
      v-if="showGettingStarted"
      type="info"
      :closable="true"
      show-icon
      style="margin-bottom: 16px"
      @close="dismissGettingStarted"
    >
      <template #title>
        New here? <el-link type="primary" :underline="false" @click="$router.push('/getting-started')">Open the Getting Started checklist</el-link>
        to secure your account, ingest logs, and install detections.
      </template>
    </el-alert>

    <!-- Detection blind-spot warning: rules only run on parser-matched logs, so
         a mostly-unparsed stream means detections are silently starved. -->
    <el-alert
      v-if="parseCoverage && parseCoverage.total > 0 && (parseCoverage.parsed_pct ?? 100) < 50"
      type="warning"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
    >
      <template #title>
        {{ (100 - (parseCoverage.parsed_pct ?? 0)).toFixed(1) }}% of your logs are invisible to detection —
        parsers matched only {{ parseCoverage.parsed.toLocaleString() }} of
        {{ parseCoverage.total.toLocaleString() }} logs in the last 24h. Detection rules are not evaluated on
        unparsed logs.
        <el-link type="primary" :underline="false" @click="$router.push('/parsers')">Review parsers</el-link>
      </template>
    </el-alert>

    <!-- Section: Alerts -->
    <div class="section-header">
      <h3>Alerts</h3>
    </div>
    <el-row :gutter="20" class="charts-row">
      <el-col :xs="24" :sm="12" :md="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>Alerts by Severity</span>
              <el-text size="small" type="info">Click a slice to investigate</el-text>
            </div>
          </template>
          <div class="chart-container">
            <canvas ref="severityChart"></canvas>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>SOC Triage Risk Rating</span>
              <el-text size="small" type="info">Click a bar to open SOC Triage</el-text>
            </div>
          </template>
          <div class="chart-container">
            <canvas ref="riskChart"></canvas>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="8">
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

    <!-- Geo Row: alerts by country (world map) -->
    <el-row :gutter="20" class="charts-row">
      <el-col :xs="24">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>Alerts by Country (last 30 days)</span>
              <el-text size="small" type="info">Click a country to investigate it</el-text>
            </div>
          </template>
          <AlertsCountryMap :data="alertsByCountry" @country-click="goToCountry" />
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

      <el-col :xs="24" :md="12">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>Vulnerability Criticality</span>
              <el-text size="small" type="info">Click a slice to investigate</el-text>
            </div>
          </template>
          <div class="chart-container">
            <canvas ref="vulnChart"></canvas>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- Section: Detection pipeline health -->
    <el-row :gutter="20" class="stats-row">
      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card coverage">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="40"><View /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">
                {{ parseCoverage?.parsed_pct != null ? parseCoverage.parsed_pct + '%' : '—' }}
              </div>
              <div class="stat-label">Detection Coverage (24h)</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card coverage-unparsed">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="40"><Hide /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ (parseCoverage?.unparsed ?? 0).toLocaleString() }}</div>
              <div class="stat-label">Unparsed Logs (24h)</div>
            </div>
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
import { Monitor, CircleCheck, View, Hide } from '@element-plus/icons-vue';
import AlertsCountryMap from '@/components/AlertsCountryMap.vue';

Chart.register(...registerables);

// Shared 4-tier criticality vocabulary (severity, vuln criticality, and risk
// rating all use it) so color coding stays consistent across every chart.
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;
const SEVERITY_LABELS = ['Critical', 'High', 'Medium', 'Low'];
const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f56c6c',
  high: '#e6a23c',
  medium: '#409eff',
  low: '#67c23a',
};

const router = useRouter();
const alertsStore = useAlertsStore();

const alertStats = computed(() => alertsStore.statistics);
const recentAlerts = computed(() => alertsStore.alerts.slice(0, 10));
const loading = ref(false);

// Getting Started banner — dismissible, remembered per browser.
const showGettingStarted = ref(localStorage.getItem('onboarding_dismissed') !== '1');
function dismissGettingStarted() {
  localStorage.setItem('onboarding_dismissed', '1');
  showGettingStarted.value = false;
}

const assetStats = ref<any>(null);
const vulnStats = ref<any>(null);
const parseCoverage = ref<any>(null);
const riskSummary = ref<any>(null);

const severityChart = ref<HTMLCanvasElement>();
const statusChart = ref<HTMLCanvasElement>();
const riskChart = ref<HTMLCanvasElement>();
const vulnChart = ref<HTMLCanvasElement>();
let severityChartInstance: Chart | null = null;
let statusChartInstance: Chart | null = null;
let riskChartInstance: Chart | null = null;
let vulnChartInstance: Chart | null = null;

const alertsByCountry = ref<Array<{ country_code: string; country_name: string; count: number; foreign_count: number }>>([]);

onMounted(async () => {
  await loadData();
  createCharts();
});

// Click a country on the map -> investigate it on the Threat Intel tab.
function goToCountry(code: string) {
  router.push({ path: '/threat-intel', query: { country: code } });
}

// Click a severity slice -> that severity's alerts / vulnerabilities.
function goToAlertsBySeverity(severity: string) {
  router.push({ path: '/alerts', query: { severity } });
}
function goToVulnsBySeverity(severity: string) {
  router.push({ path: '/vulnerability-management', query: { severity } });
}
function goToSocTriage() {
  router.push('/soc-triage');
}

// alertStats/vulnStats/riskSummary each arrive asynchronously (and can
// refresh independently). The original code built the charts once in
// onMounted and bailed out (early return) whenever the stats weren't loaded
// yet, leaving the canvases permanently blank. Rebuild whenever any of them
// change; createCharts() destroys the prior instances first.
watch(alertStats, () => createCharts());
watch(vulnStats, () => createCharts());
watch(riskSummary, () => createCharts());

const loadData = async () => {
  loading.value = true;
  try {
    await Promise.all([
      alertsStore.fetchStatistics(),
      alertsStore.fetchAlerts({ limit: 10 }),
      loadAssetStats(),
      loadVulnStats(),
      loadAlertsByCountry(),
      loadParseCoverage(),
      loadRiskSummary(),
    ]);
  } catch (error) {
    console.error('Failed to load dashboard data:', error);
  } finally {
    loading.value = false;
  }
};

const loadAlertsByCountry = async () => {
  try {
    const response = await api.getAlertsByCountry({ days: 30, limit: 12 });
    alertsByCountry.value = Array.isArray(response.data) ? response.data : [];
  } catch (error) {
    console.error('Failed to load alerts by country:', error);
    alertsByCountry.value = [];
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

const loadParseCoverage = async () => {
  try {
    const response = await api.getParseCoverage();
    parseCoverage.value = response.data;
  } catch (error) {
    console.error('Failed to load parse coverage:', error);
    parseCoverage.value = null;
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

const loadRiskSummary = async () => {
  try {
    const response = await api.getTriageRiskSummary();
    riskSummary.value = response.data;
  } catch (error) {
    console.error('Failed to load SOC triage risk summary:', error);
    riskSummary.value = null;
  }
};

// Chart.js only shows a pointer cursor for elements it knows are interactive;
// wire that up generically for every clickable chart's onHover.
function pointerOnHover(evt: any, elements: any[]) {
  const target = evt?.native?.target as HTMLElement | undefined;
  if (target) target.style.cursor = elements.length ? 'pointer' : 'default';
}

const createCharts = () => {
  // Destroy any prior instances before recreating — Chart.js throws "Canvas is
  // already in use" if a new chart is attached to a canvas that still owns one,
  // and leaving them around leaks on every refresh.
  severityChartInstance?.destroy();
  severityChartInstance = null;
  statusChartInstance?.destroy();
  statusChartInstance = null;
  riskChartInstance?.destroy();
  riskChartInstance = null;
  vulnChartInstance?.destroy();
  vulnChartInstance = null;

  // Severity Chart — pie, click a slice to see those alerts
  if (alertStats.value && severityChart.value) {
    const stats = alertStats.value;
    severityChartInstance = new Chart(severityChart.value, {
      type: 'pie',
      data: {
        labels: SEVERITY_LABELS,
        datasets: [
          {
            data: SEVERITY_ORDER.map((s) => stats[`${s}_count`] ?? 0),
            backgroundColor: SEVERITY_ORDER.map((s) => SEVERITY_COLORS[s]),
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
        onHover: pointerOnHover,
        onClick: (_evt, elements) => {
          if (!elements.length) return;
          goToAlertsBySeverity(SEVERITY_ORDER[elements[0].index]);
        },
      },
    });
  }

  // Status Chart — unchanged, not clickable
  if (alertStats.value && statusChart.value) {
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

  // SOC Triage Risk Rating — horizontal bar, click a band to open SOC Triage
  if (riskSummary.value && riskChart.value) {
    const risk = riskSummary.value;
    riskChartInstance = new Chart(riskChart.value, {
      type: 'bar',
      data: {
        labels: SEVERITY_LABELS,
        datasets: [
          {
            data: SEVERITY_ORDER.map((s) => risk[s] ?? 0),
            backgroundColor: SEVERITY_ORDER.map((s) => SEVERITY_COLORS[s]),
          },
        ],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: true,
        scales: {
          x: { beginAtZero: true, ticks: { precision: 0 } },
        },
        plugins: {
          legend: { display: false },
        },
        onHover: pointerOnHover,
        onClick: (_evt, elements) => {
          if (!elements.length) return;
          goToSocTriage();
        },
      },
    });
  }

  // Vulnerability Criticality — pie, click a slice to see those vulnerabilities
  if (vulnStats.value && vulnChart.value) {
    const vulns = vulnStats.value;
    vulnChartInstance = new Chart(vulnChart.value, {
      type: 'pie',
      data: {
        labels: SEVERITY_LABELS,
        datasets: [
          {
            data: SEVERITY_ORDER.map((s) => vulns[`${s}_count`] ?? 0),
            backgroundColor: SEVERITY_ORDER.map((s) => SEVERITY_COLORS[s]),
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
        onHover: pointerOnHover,
        onClick: (_evt, elements) => {
          if (!elements.length) return;
          goToVulnsBySeverity(SEVERITY_ORDER[elements[0].index]);
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

.stat-card.assets .stat-icon {
  background: rgba(64, 158, 255, 0.1);
  color: #409eff;
}

.stat-card.assets-online .stat-icon {
  background: rgba(103, 194, 58, 0.1);
  color: #67c23a;
}

.stat-card.coverage .stat-icon {
  background: rgba(103, 194, 58, 0.1);
  color: #67c23a;
}

.stat-card.coverage-unparsed .stat-icon {
  background: rgba(230, 162, 60, 0.1);
  color: #e6a23c;
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

/* The country bar chart grows with the number of countries; give it room and
   let it fill the width (maintainAspectRatio is off for the horizontal bar). */
.chart-container--wide {
  height: 360px;
  width: 100%;
}

.empty-geo {
  padding: 32px 16px;
  text-align: center;
  color: var(--siembox-text-secondary, #909399);
  font-size: 14px;
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
