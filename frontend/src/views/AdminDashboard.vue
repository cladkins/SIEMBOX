<template>
  <div class="admin-dashboard">
    <el-row :gutter="20" align="top">
      <!-- Left Column: Overview, User Lookup, Jobs -->
      <el-col :span="16">
        <!-- System Overview -->
        <el-card class="section-card">
          <template #header>
            <div class="card-header">
              <span>System Overview</span>
              <el-button size="small" @click="fetchOverview" :icon="Refresh" circle :loading="overviewLoading" />
            </div>
          </template>

          <div v-loading="overviewLoading">
            <el-row :gutter="20" v-if="overview">
              <!-- Health Status -->
              <el-col :span="8">
                <div class="stat-box">
                  <div class="stat-title">System Health</div>
                  <div class="health-indicators">
                    <div class="health-item">
                      <el-tag :type="overview.health.database === 'healthy' ? 'success' : 'danger'" size="small">
                        Database
                      </el-tag>
                    </div>
                    <div class="health-item">
                      <el-tag :type="overview.health.syslog === 'healthy' ? 'success' : overview.health.syslog === 'warning' ? 'warning' : 'danger'" size="small">
                        Syslog
                      </el-tag>
                    </div>
                    <div class="health-item">
                      <el-tag :type="overview.health.shippers.online > 0 ? 'success' : 'warning'" size="small">
                        {{ overview.health.shippers.online }} Shipper{{ overview.health.shippers.online !== 1 ? 's' : '' }}
                      </el-tag>
                    </div>
                  </div>
                </div>
              </el-col>

              <!-- Key Metrics -->
              <el-col :span="8">
                <div class="stat-box">
                  <div class="stat-title">Activity</div>
                  <div class="metric-grid">
                    <div class="metric">
                      <span class="metric-value">{{ overview.metrics.activeUsers24h }}</span>
                      <span class="metric-label">Active Users</span>
                    </div>
                    <div class="metric">
                      <span class="metric-value" :class="{ 'text-danger': overview.metrics.criticalAlerts > 0 }">
                        {{ overview.metrics.alertsToday }}
                      </span>
                      <span class="metric-label">Alerts Today</span>
                    </div>
                    <div class="metric">
                      <span class="metric-value">{{ overview.metrics.activeScans }}</span>
                      <span class="metric-label">Active Scans</span>
                    </div>
                    <div class="metric">
                      <span class="metric-value" :class="{ 'text-warning': overview.metrics.recentErrors > 0 }">
                        {{ overview.metrics.recentErrors }}
                      </span>
                      <span class="metric-label">Errors (1h)</span>
                    </div>
                  </div>
                </div>
              </el-col>

              <!-- System Info -->
              <el-col :span="8">
                <div class="stat-box">
                  <div class="stat-title">System Info</div>
                  <div class="info-list">
                    <div class="info-item">
                      <span class="info-label">Version</span>
                      <span class="info-value">{{ overview.system.version }}</span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">Uptime</span>
                      <span class="info-value">{{ formatUptime(overview.system.uptime) }}</span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">DB Size</span>
                      <span class="info-value">{{ overview.metrics.dbSizeMB }} MB</span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">Assets</span>
                      <span class="info-value">{{ overview.metrics.totalAssets }}</span>
                    </div>
                  </div>
                </div>
              </el-col>
            </el-row>

            <el-alert v-else-if="overviewError" type="error" :closable="false" show-icon>
              {{ overviewError }}
            </el-alert>

            <el-empty v-else-if="!overviewLoading" description="No data available" />
          </div>
        </el-card>

        <!-- User Lookup -->
        <el-card class="section-card" style="margin-top: 20px">
          <template #header>
            <div class="card-header">
              <span>User Lookup</span>
            </div>
          </template>

          <el-form :inline="true" @submit.prevent="searchUsers">
            <el-form-item>
              <el-input
                v-model="userSearch"
                placeholder="Search by username or email"
                style="width: 300px"
                clearable
                @clear="searchUsers"
              >
                <template #prefix>
                  <el-icon><Search /></el-icon>
                </template>
              </el-input>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="searchUsers" :loading="usersLoading">Search</el-button>
            </el-form-item>
          </el-form>

          <el-table :data="users" v-loading="usersLoading" stripe style="margin-top: 15px">
            <el-table-column prop="username" label="Username" width="150" />
            <el-table-column prop="email" label="Email" min-width="200" />
            <el-table-column prop="role" label="Role" width="100">
              <template #default="{ row }">
                <el-tag :type="getRoleType(row.role)" size="small">{{ row.role }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Status" width="100">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'danger'" size="small">
                  {{ row.enabled ? 'Active' : 'Disabled' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Last Login" width="160">
              <template #default="{ row }">
                <span v-if="row.last_login">{{ formatDate(row.last_login) }}</span>
                <el-text type="info" v-else>Never</el-text>
              </template>
            </el-table-column>
            <el-table-column label="Activity" width="100" align="center">
              <template #default="{ row }">
                <el-tooltip :content="`${row.actions_24h} actions in 24h`">
                  <span>{{ row.actions_24h }}</span>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column label="Actions" width="120" align="center">
              <template #default="{ row }">
                <el-button size="small" @click="viewUserActivity(row)">Activity</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <!-- Background Jobs -->
        <el-card class="section-card" style="margin-top: 20px">
          <template #header>
            <div class="card-header">
              <span>Background Jobs</span>
              <div>
                <el-radio-group v-model="jobsFilter" size="small" @change="fetchJobs">
                  <el-radio-button value="">All</el-radio-button>
                  <el-radio-button value="running">Running</el-radio-button>
                  <el-radio-button value="queued">Queued</el-radio-button>
                  <el-radio-button value="completed">Completed</el-radio-button>
                  <el-radio-button value="failed">Failed</el-radio-button>
                </el-radio-group>
                <el-button size="small" @click="fetchJobs" :icon="Refresh" circle style="margin-left: 10px" :loading="jobsLoading" />
              </div>
            </div>
          </template>

          <!-- Active Jobs Progress -->
          <div v-if="activeJobs.length > 0" class="active-jobs">
            <div class="active-jobs-title">Active Scans</div>
            <div v-for="job in activeJobs" :key="job.id" class="active-job">
              <div class="job-info">
                <el-tag :type="job.status === 'running' ? 'primary' : 'warning'" size="small">{{ job.type }}</el-tag>
                <span class="job-target">{{ job.target }}</span>
              </div>
              <el-progress
                :percentage="getJobProgress(job)"
                :status="job.status === 'running' ? undefined : 'warning'"
                :stroke-width="10"
              />
            </div>
          </div>

          <el-table :data="jobs" v-loading="jobsLoading" stripe style="margin-top: 15px">
            <el-table-column prop="type" label="Type" width="120">
              <template #default="{ row }">
                <el-tag size="small">{{ row.type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="target" label="Target" min-width="200" show-overflow-tooltip />
            <el-table-column prop="status" label="Status" width="100">
              <template #default="{ row }">
                <el-tag :type="getStatusType(row.status)" size="small">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Started" width="160">
              <template #default="{ row }">
                <span v-if="row.started_at">{{ formatDate(row.started_at) }}</span>
                <el-text type="info" v-else>Pending</el-text>
              </template>
            </el-table-column>
            <el-table-column label="Duration" width="100">
              <template #default="{ row }">
                <span v-if="row.duration_seconds">{{ formatDuration(row.duration_seconds) }}</span>
                <span v-else-if="row.status === 'running'">Running...</span>
                <span v-else>-</span>
              </template>
            </el-table-column>
            <el-table-column label="Results" width="120">
              <template #default="{ row }">
                <span v-if="row.type === 'vulnerability'">{{ row.vulnerabilities_found || 0 }} vulns</span>
                <span v-else>{{ row.assets_discovered || 0 }} assets</span>
              </template>
            </el-table-column>
            <el-table-column prop="initiated_by_username" label="User" width="100" />
          </el-table>

          <div class="job-counts" v-if="jobCounts">
            <el-tag v-for="(count, status) in jobCounts" :key="status" :type="getStatusType(status)" size="small" style="margin-right: 10px">
              {{ status }}: {{ count }}
            </el-tag>
          </div>
        </el-card>
      </el-col>

      <!-- Right Column: Recent Errors -->
      <el-col :span="8">
        <el-card class="section-card errors-card">
          <template #header>
            <div class="card-header">
              <span>Recent Errors</span>
              <div>
                <el-select v-model="errorsHours" size="small" style="width: 100px" @change="fetchErrors">
                  <el-option :value="1" label="1 hour" />
                  <el-option :value="6" label="6 hours" />
                  <el-option :value="24" label="24 hours" />
                  <el-option :value="72" label="3 days" />
                </el-select>
                <el-button size="small" @click="fetchErrors" :icon="Refresh" circle style="margin-left: 5px" :loading="errorsLoading" />
              </div>
            </div>
          </template>

          <div v-loading="errorsLoading">
            <!-- Error Summary -->
            <div v-if="errorSummary && errorSummary.total > 0" class="error-summary">
              <el-tag
                v-for="(count, category) in errorSummary.byCategory"
                :key="category"
                :type="getCategoryType(category)"
                size="small"
                style="margin-right: 5px; margin-bottom: 5px"
              >
                {{ category }}: {{ count }}
              </el-tag>
            </div>

            <el-alert v-if="errorSummary && errorSummary.total === 0" type="success" :closable="false">
              No errors in the last {{ errorsHours }} hour{{ errorsHours !== 1 ? 's' : '' }}
            </el-alert>

            <!-- Error Timeline -->
            <el-timeline v-if="errors.length > 0" class="error-timeline">
              <el-timeline-item
                v-for="error in errors"
                :key="error.id"
                :timestamp="formatDate(error.timestamp)"
                :type="getSeverityType(error.severity)"
                placement="top"
              >
                <div class="error-item">
                  <div class="error-header">
                    <el-tag :type="getCategoryType(error.category)" size="small">{{ error.category }}</el-tag>
                    <el-tag v-if="error.endpoint" type="info" size="small">{{ error.endpoint }}</el-tag>
                  </div>
                  <div class="error-message">{{ error.human_message }}</div>
                  <div class="error-resolution" v-if="error.resolution">
                    <el-icon><InfoFilled /></el-icon>
                    {{ error.resolution }}
                  </div>
                  <el-collapse v-if="error.message !== error.human_message">
                    <el-collapse-item title="Technical Details">
                      <code class="error-code">{{ error.message }}</code>
                    </el-collapse-item>
                  </el-collapse>
                </div>
              </el-timeline-item>
            </el-timeline>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- User Activity Dialog -->
    <el-dialog v-model="activityDialogVisible" :title="`Activity: ${selectedUser?.username || ''}`" width="800px">
      <div v-loading="activityLoading">
        <div v-if="userActivity" class="activity-summary">
          <el-tag type="info">{{ userActivity.summary.totalActions }} total actions</el-tag>
          <el-tag type="primary">{{ userActivity.summary.actions24h }} in 24h</el-tag>
          <el-tag type="warning">{{ userActivity.summary.actions7d }} in 7d</el-tag>
          <el-tag v-if="userActivity.summary.errors > 0" type="danger">{{ userActivity.summary.errors }} errors</el-tag>
        </div>

        <el-table :data="userActivity?.activity || []" stripe style="margin-top: 15px" max-height="400">
          <el-table-column label="Time" width="160">
            <template #default="{ row }">{{ formatDate(row.timestamp) }}</template>
          </el-table-column>
          <el-table-column prop="action" label="Action" width="150" />
          <el-table-column prop="resource_type" label="Resource" width="120" />
          <el-table-column label="Status" width="80">
            <template #default="{ row }">
              <el-tag :type="row.response_status < 400 ? 'success' : 'danger'" size="small">
                {{ row.response_status }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="ip_address" label="IP" width="130" />
        </el-table>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { api } from '@/services/api';
import { ElMessage } from 'element-plus';
import { Refresh, Search, InfoFilled } from '@element-plus/icons-vue';
import { format } from 'date-fns';

// Data
const overview = ref<any>(null);
const users = ref<any[]>([]);
const jobs = ref<any[]>([]);
const jobCounts = ref<Record<string, number>>({});
const errors = ref<any[]>([]);
const errorSummary = ref<any>(null);
const userActivity = ref<any>(null);
const selectedUser = ref<any>(null);

// Loading states
const overviewLoading = ref(false);
const usersLoading = ref(false);
const jobsLoading = ref(false);
const errorsLoading = ref(false);
const activityLoading = ref(false);

// Error states
const overviewError = ref('');

// Filters
const userSearch = ref('');
const jobsFilter = ref('');
const errorsHours = ref(24);

// Dialog
const activityDialogVisible = ref(false);

// Auto-refresh interval
let refreshInterval: ReturnType<typeof setInterval> | null = null;

// Computed
const activeJobs = computed(() => {
  return jobs.value.filter(j => j.status === 'running' || j.status === 'queued');
});

// Methods
async function fetchOverview() {
  overviewLoading.value = true;
  overviewError.value = '';
  try {
    const response = await api.getAdminOverview();
    overview.value = response.data;
  } catch (error: any) {
    console.error('Failed to fetch overview:', error);
    overviewError.value = error.response?.data?.message || error.message || 'Failed to load system overview';
  } finally {
    overviewLoading.value = false;
  }
}

async function searchUsers() {
  usersLoading.value = true;
  try {
    const response = await api.searchAdminUsers(userSearch.value);
    users.value = response.data.users;
  } catch (error) {
    console.error('Failed to search users:', error);
  } finally {
    usersLoading.value = false;
  }
}

async function fetchJobs() {
  jobsLoading.value = true;
  try {
    const response = await api.getAdminJobs(jobsFilter.value);
    jobs.value = response.data.jobs;
    jobCounts.value = response.data.counts;
  } catch (error) {
    console.error('Failed to fetch jobs:', error);
  } finally {
    jobsLoading.value = false;
  }
}

async function fetchErrors() {
  errorsLoading.value = true;
  try {
    const response = await api.getAdminErrors(errorsHours.value);
    errors.value = response.data.errors;
    errorSummary.value = response.data.summary;
  } catch (error) {
    console.error('Failed to fetch errors:', error);
  } finally {
    errorsLoading.value = false;
  }
}

async function viewUserActivity(user: any) {
  selectedUser.value = user;
  activityDialogVisible.value = true;
  activityLoading.value = true;

  try {
    const response = await api.getUserActivity(user.id);
    userActivity.value = response.data;
  } catch (error) {
    ElMessage.error('Failed to fetch user activity');
    console.error('Failed to fetch user activity:', error);
  } finally {
    activityLoading.value = false;
  }
}

function getJobProgress(job: any): number {
  if (job.status === 'completed') return 100;
  if (job.status === 'queued') return 0;

  // Try to get progress from results_summary
  const progress = job.results_summary?.progress;
  if (progress?.percentComplete) return progress.percentComplete;

  // Estimate based on duration
  if (job.started_at) {
    const elapsed = (Date.now() - new Date(job.started_at).getTime()) / 1000;
    // Assume average scan takes 5 minutes
    return Math.min(95, Math.round((elapsed / 300) * 100));
  }

  return 10;
}

// Formatting helpers
function formatDate(date: string): string {
  return format(new Date(date), 'MMM dd, HH:mm');
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}m ${secs}s`;
}

// Tag type helpers
function getRoleType(role: string): string {
  const types: Record<string, string> = {
    admin: 'danger',
    analyst: 'warning',
    operator: 'primary',
    viewer: 'info',
  };
  return types[role] || 'info';
}

function getStatusType(status: string): string {
  const types: Record<string, string> = {
    running: 'primary',
    queued: 'warning',
    completed: 'success',
    failed: 'danger',
    cancelled: 'info',
  };
  return types[status] || 'info';
}

function getSeverityType(severity: string): string {
  const types: Record<string, string> = {
    critical: 'danger',
    error: 'danger',
    warning: 'warning',
    info: 'info',
  };
  return types[severity] || 'info';
}

function getCategoryType(category: string): string {
  const types: Record<string, string> = {
    database: 'danger',
    auth: 'warning',
    network: 'primary',
    scanner: 'info',
    parser: 'success',
    application: 'info',
  };
  return types[category] || 'info';
}

// Lifecycle
onMounted(() => {
  fetchOverview();
  searchUsers();
  fetchJobs();
  fetchErrors();

  // Auto-refresh every 30 seconds
  refreshInterval = setInterval(() => {
    fetchOverview();
    fetchJobs();
    fetchErrors();
  }, 30000);
});

onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval);
  }
});
</script>

<style scoped>
.admin-dashboard {
  padding: 0;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.stat-box {
  padding: 10px;
  background: var(--siembox-bg-color);
  border-radius: 4px;
  height: 100%;
}

.stat-title {
  font-weight: 600;
  margin-bottom: 10px;
  color: var(--siembox-text-color);
}

.health-indicators {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.health-item {
  display: flex;
  align-items: center;
}

.metric-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}

.metric {
  text-align: center;
}

.metric-value {
  font-size: 24px;
  font-weight: 600;
  display: block;
}

.metric-label {
  font-size: 12px;
  color: var(--siembox-text-tertiary);
}

.text-danger {
  color: #f56c6c;
}

.text-warning {
  color: #e6a23c;
}

.info-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.info-item {
  display: flex;
  justify-content: space-between;
}

.info-label {
  color: var(--siembox-text-tertiary);
  font-size: 13px;
}

.info-value {
  font-weight: 500;
}

.active-jobs {
  background: var(--siembox-success-bg);
  padding: 15px;
  border-radius: 4px;
  margin-bottom: 15px;
}

.active-jobs-title {
  font-weight: 600;
  margin-bottom: 10px;
}

.active-job {
  margin-bottom: 10px;
}

.active-job:last-child {
  margin-bottom: 0;
}

.job-info {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 5px;
}

.job-target {
  font-size: 13px;
  color: var(--siembox-text-secondary);
}

.job-counts {
  margin-top: 15px;
  padding-top: 15px;
  border-top: 1px solid #ebeef5;
}

.errors-card {
  max-height: calc(100vh - 100px);
  overflow-y: auto;
}

.error-summary {
  margin-bottom: 15px;
  padding-bottom: 15px;
  border-bottom: 1px solid #ebeef5;
}

.error-timeline {
  padding-left: 0;
}

.error-item {
  padding: 10px;
  background: var(--siembox-bg-color);
  border-radius: 4px;
}

.error-header {
  display: flex;
  gap: 5px;
  margin-bottom: 8px;
}

.error-message {
  font-weight: 500;
  margin-bottom: 8px;
}

.error-resolution {
  font-size: 12px;
  color: #67c23a;
  display: flex;
  align-items: center;
  gap: 5px;
}

.error-code {
  display: block;
  font-size: 11px;
  background: var(--siembox-bg-color);
  padding: 8px;
  border-radius: 4px;
  white-space: pre-wrap;
  word-break: break-all;
}

.activity-summary {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}
</style>
