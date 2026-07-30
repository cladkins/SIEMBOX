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
    <el-row :gutter="16" class="charts-row">
      <el-col :xs="24" :sm="12" :md="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>Alerts by Severity</span>
              <el-text size="small" type="info">Click a row to investigate</el-text>
            </div>
          </template>
          <RankedBarList :items="severityItems" @item-click="goToAlertsBySeverity" />
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
          <RankedBarList :items="riskItems" @item-click="goToSocTriage" />
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>Alerts by Status</span>
              <el-text size="small" type="info">Click a row to investigate</el-text>
            </div>
          </template>
          <RankedBarList :items="statusItems" @item-click="goToAlertsByStatus" />
        </el-card>
      </el-col>
    </el-row>

    <!-- Geo Row: alerts by country (world map) -->
    <el-row :gutter="16" class="charts-row">
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
    <el-row :gutter="16" class="stats-row">
      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card assets">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="28"><Monitor /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ Number(assetStats?.active_assets || 0) + Number(assetStats?.offline_assets || 0) }}</div>
              <div class="stat-label">Total Assets</div>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card assets-online" :class="{ 'is-warning': !assetsHealthy }">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="28"><CircleCheck v-if="assetsHealthy" /><WarningFilled v-else /></el-icon>
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
              <el-text size="small" type="info">Click a row to investigate</el-text>
            </div>
          </template>
          <RankedBarList :items="vulnItems" @item-click="goToVulnsBySeverity" />
        </el-card>
      </el-col>
    </el-row>

    <!-- Section: Detection pipeline health -->
    <el-row :gutter="16" class="stats-row">
      <el-col :xs="24" :sm="12" :md="6">
        <el-card class="stat-card coverage" :class="{ 'is-warning': !coverageHealthy }">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="28"><CircleCheck v-if="coverageHealthy" /><WarningFilled v-else /></el-icon>
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
        <el-card class="stat-card coverage-unparsed" :class="{ 'is-warning': !coverageHealthy }">
          <div class="stat-content">
            <div class="stat-icon">
              <el-icon :size="28"><Hide /></el-icon>
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

      <el-table :data="recentAlerts" v-loading="loading" stripe size="small">
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
import { api } from '@/services/api';
import { format } from 'date-fns';
import { Monitor, CircleCheck, WarningFilled, Hide } from '@element-plus/icons-vue';
import AlertsCountryMap from '@/components/AlertsCountryMap.vue';
import RankedBarList from '@/components/RankedBarList.vue';

// Shared 4-tier criticality vocabulary (severity, vuln criticality, and risk
// rating all use it) so color coding stays consistent across every panel.
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;
const SEVERITY_LABELS = ['Critical', 'High', 'Medium', 'Low'];
const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f56c6c',
  high: '#e6a23c',
  medium: '#409eff',
  low: '#67c23a',
};
const STATUS_COLORS: Record<string, string> = {
  new: '#409eff',
  investigating: '#e6a23c',
  closed: '#67c23a',
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

const alertsByCountry = ref<Array<{ country_code: string; country_name: string; count: number; foreign_count: number }>>([]);

// Detection coverage and asset health drive the stat tiles' color/icon state
// (green + check vs. orange + warning) — the 50% threshold matches the
// blind-spot warning banner above, so the two stay consistent about what
// counts as "healthy".
const coverageHealthy = computed(() => {
  if (!parseCoverage.value || parseCoverage.value.total <= 0) return true;
  return (parseCoverage.value.parsed_pct ?? 100) >= 50;
});
const assetsHealthy = computed(() => Number(assetStats.value?.offline_assets || 0) === 0);

const severityItems = computed(() =>
  SEVERITY_ORDER.map((s, i) => ({
    key: s,
    label: SEVERITY_LABELS[i],
    value: alertStats.value ? Number(alertStats.value[`${s}_count`] ?? 0) : 0,
    color: SEVERITY_COLORS[s],
  }))
);

const riskItems = computed(() =>
  SEVERITY_ORDER.map((s, i) => ({
    key: s,
    label: SEVERITY_LABELS[i],
    value: riskSummary.value ? Number(riskSummary.value[s] ?? 0) : 0,
    color: SEVERITY_COLORS[s],
  }))
);

const vulnItems = computed(() =>
  SEVERITY_ORDER.map((s, i) => ({
    key: s,
    label: SEVERITY_LABELS[i],
    value: vulnStats.value ? Number(vulnStats.value[`${s}_count`] ?? 0) : 0,
    color: SEVERITY_COLORS[s],
  }))
);

const statusItems = computed(() => [
  { key: 'new', label: 'New', value: alertStats.value ? Number(alertStats.value.new_count ?? 0) : 0, color: STATUS_COLORS.new },
  {
    key: 'investigating',
    label: 'Investigating',
    value: alertStats.value ? Number(alertStats.value.investigating_count ?? 0) : 0,
    color: STATUS_COLORS.investigating,
  },
  { key: 'closed', label: 'Closed', value: alertStats.value ? Number(alertStats.value.closed_count ?? 0) : 0, color: STATUS_COLORS.closed },
]);

onMounted(async () => {
  await loadData();
});

// Click a country on the map -> investigate it on the Threat Intel tab.
function goToCountry(code: string) {
  router.push({ path: '/threat-intel', query: { country: code } });
}

// Click a row -> that severity's/status's alerts, or that severity's vulns.
function goToAlertsBySeverity(severity: string) {
  router.push({ path: '/alerts', query: { severity } });
}
function goToAlertsByStatus(status: string) {
  router.push({ path: '/alerts', query: { status } });
}
function goToVulnsBySeverity(severity: string) {
  router.push({ path: '/vulnerability-management', query: { severity } });
}
function goToSocTriage() {
  router.push('/soc-triage');
}

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
  margin-bottom: 12px;
  margin-top: 8px;
}

.section-header h3 {
  font-size: 15px;
  font-weight: 600;
  color: var(--siembox-text-color);
  margin: 0;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--siembox-border-color, #dcdfe6);
}

.stats-row,
.charts-row {
  margin-bottom: 16px;
}

:deep(.el-card__body) {
  padding: 14px 18px;
}

.stat-card {
  margin-bottom: 0;
  background-color: var(--siembox-card-bg, #fff);
  border-left: 3px solid transparent;
  transition: background-color 0.3s, border-color 0.3s;
}

.stat-content {
  display: flex;
  align-items: center;
  gap: 14px;
}

.stat-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 52px;
  height: 52px;
  border-radius: 50%;
  background: rgba(64, 158, 255, 0.1);
  color: #409eff;
  flex-shrink: 0;
}

.stat-card.assets {
  border-left-color: #409eff;
}
.stat-card.assets .stat-icon {
  background: rgba(64, 158, 255, 0.1);
  color: #409eff;
}

.stat-card.assets-online {
  border-left-color: #67c23a;
}
.stat-card.assets-online .stat-icon {
  background: rgba(103, 194, 58, 0.1);
  color: #67c23a;
}

.stat-card.coverage {
  border-left-color: #67c23a;
}
.stat-card.coverage .stat-icon {
  background: rgba(103, 194, 58, 0.1);
  color: #67c23a;
}

.stat-card.coverage-unparsed {
  border-left-color: #67c23a;
}
.stat-card.coverage-unparsed .stat-icon {
  background: rgba(103, 194, 58, 0.1);
  color: #67c23a;
}

/* Shared "unhealthy" override for any stat tile, regardless of its base color. */
.stat-card.is-warning {
  border-left-color: #e6a23c;
}
.stat-card.is-warning .stat-icon {
  background: rgba(230, 162, 60, 0.1);
  color: #e6a23c;
}

.stat-info {
  flex: 1;
  min-width: 0;
}

.stat-value {
  font-size: 26px;
  font-weight: bold;
  line-height: 1.2;
  color: var(--siembox-text-color);
}

.stat-label {
  font-size: 13px;
  color: var(--siembox-text-secondary, #909399);
  margin-top: 3px;
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
