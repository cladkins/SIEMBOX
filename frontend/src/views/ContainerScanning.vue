<template>
  <div class="container-scanning">
    <div class="page-header">
      <h2>Container Scanning</h2>
      <p class="subtitle">
        Scan a container image for known OS &amp; library vulnerabilities with Trivy.
        Trivy pulls the image itself — no Docker daemon required.
      </p>
    </div>

    <el-card class="scan-card">
      <el-form :inline="true" @submit.prevent="startScan">
        <el-form-item label="Image reference">
          <el-input
            v-model="imageRef"
            placeholder="e.g. nginx:latest, ghcr.io/cladkins/siembox-backend:latest"
            style="width: 480px"
            clearable
            @keyup.enter="startScan"
          />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="starting" :disabled="!imageRef.trim()" @click="startScan">
            <el-icon><Search /></el-icon> Scan
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="scans-card">
      <template #header>
        <div class="card-header">
          <span>Recent Scans</span>
          <el-button size="small" :loading="loading" @click="loadScans">
            <el-icon><Refresh /></el-icon> Refresh
          </el-button>
        </div>
      </template>

      <el-table :data="scans" v-loading="loading" stripe>
        <el-table-column prop="image_ref" label="Image" min-width="240" show-overflow-tooltip />
        <el-table-column prop="status" label="Status" width="120">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Vulnerabilities" width="120">
          <template #default="{ row }">
            <el-tag v-if="row.status === 'completed'" :type="row.vulnerabilities_found > 0 ? 'danger' : 'success'">
              {{ row.vulnerabilities_found }}
            </el-tag>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column label="Severity" min-width="200">
          <template #default="{ row }">
            <span v-if="row.severity_counts">
              <el-tag
                v-for="sev in severityOrder"
                v-show="(row.severity_counts[sev] || 0) > 0"
                :key="sev"
                :type="severityType(sev)"
                size="small"
                class="sev-tag"
              >
                {{ sev[0].toUpperCase() }} {{ row.severity_counts[sev] }}
              </el-tag>
            </span>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="Started" width="180">
          <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="Actions" width="100">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="viewScan(row)">View</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="detailVisible" title="Scan Details" width="900px">
      <div v-if="selectedScan" v-loading="loadingDetail">
        <el-descriptions :column="2" border class="detail-desc">
          <el-descriptions-item label="Image">{{ selectedScan.image_ref }}</el-descriptions-item>
          <el-descriptions-item label="Status">
            <el-tag :type="statusType(selectedScan.status)">{{ selectedScan.status }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Vulnerabilities">{{ selectedScan.vulnerabilities_found }}</el-descriptions-item>
          <el-descriptions-item label="Duration">
            {{ selectedScan.duration_seconds != null ? selectedScan.duration_seconds + 's' : '—' }}
          </el-descriptions-item>
        </el-descriptions>

        <el-alert
          v-if="selectedScan.error_message"
          type="error"
          :closable="false"
          :title="selectedScan.error_message"
          style="margin: 12px 0"
        />

        <el-table
          v-if="selectedScan.vulnerabilities?.length"
          :data="selectedScan.vulnerabilities"
          stripe
          max-height="460"
          style="margin-top: 12px"
        >
          <el-table-column prop="severity" label="Severity" width="110">
            <template #default="{ row }">
              <el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="vuln_id" label="ID" width="180">
            <template #default="{ row }">
              <el-link v-if="row.primary_url" :href="row.primary_url" target="_blank" rel="noopener noreferrer" type="primary">
                {{ row.vuln_id }}
              </el-link>
              <span v-else>{{ row.vuln_id }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="pkg_name" label="Package" min-width="140" show-overflow-tooltip />
          <el-table-column label="Installed → Fixed" min-width="200">
            <template #default="{ row }">
              <span>{{ row.installed_version || '?' }}</span>
              <span v-if="row.fixed_version"> → <strong>{{ row.fixed_version }}</strong></span>
              <el-tag v-else size="small" type="info">no fix</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="title" label="Title" min-width="240" show-overflow-tooltip />
        </el-table>

        <el-empty
          v-else-if="selectedScan.status === 'completed'"
          description="No vulnerabilities found"
        />
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { ElMessage } from 'element-plus';
import { Search, Refresh } from '@element-plus/icons-vue';
import { format } from 'date-fns';
import { api } from '@/services/api';

const imageRef = ref('');
const starting = ref(false);
const loading = ref(false);
const scans = ref<any[]>([]);

const detailVisible = ref(false);
const loadingDetail = ref(false);
const selectedScan = ref<any>(null);

const severityOrder = ['critical', 'high', 'medium', 'low', 'unknown'];
let pollTimer: number | null = null;

function statusType(status: string) {
  return { completed: 'success', running: 'warning', queued: 'info', failed: 'danger', cancelled: 'info' }[status] || 'info';
}
function severityType(sev: string) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', unknown: 'info' }[sev] || 'info';
}
function formatDate(d: string) {
  return d ? format(new Date(d), 'MMM dd, yyyy HH:mm') : '—';
}

async function startScan() {
  const ref = imageRef.value.trim();
  if (!ref) return;
  starting.value = true;
  try {
    await api.scanContainer(ref);
    ElMessage.success('Scan started');
    imageRef.value = '';
    await loadScans();
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.response?.data?.message || 'Failed to start scan');
  } finally {
    starting.value = false;
  }
}

async function loadScans() {
  loading.value = true;
  try {
    const { data } = await api.getContainerScans(20);
    scans.value = Array.isArray(data) ? data : [];
  } catch (error) {
    console.error('Failed to load container scans:', error);
  } finally {
    loading.value = false;
  }
}

async function viewScan(row: any) {
  detailVisible.value = true;
  loadingDetail.value = true;
  selectedScan.value = null;
  try {
    const { data } = await api.getContainerScan(row.id);
    selectedScan.value = data;
  } catch (error) {
    ElMessage.error('Failed to load scan details');
  } finally {
    loadingDetail.value = false;
  }
}

// Poll while any scan is still queued/running so the table reflects progress.
function startPolling() {
  pollTimer = window.setInterval(() => {
    if (scans.value.some((s) => s.status === 'queued' || s.status === 'running')) {
      loadScans();
    }
  }, 5000);
}

onMounted(() => {
  loadScans();
  startPolling();
});
onUnmounted(() => {
  if (pollTimer) window.clearInterval(pollTimer);
});
</script>

<style scoped>
.container-scanning {
  padding: 0;
}
.page-header {
  margin-bottom: 16px;
}
.page-header h2 {
  margin: 0 0 4px;
}
.subtitle {
  margin: 0;
  color: var(--siembox-text-secondary, #909399);
  font-size: 14px;
}
.scan-card {
  margin-bottom: 16px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.sev-tag {
  margin-right: 4px;
}
.detail-desc {
  margin-bottom: 8px;
}
</style>
