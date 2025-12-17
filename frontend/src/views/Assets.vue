<template>
  <div class="assets-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <span class="title">Asset Inventory</span>
          <div class="header-actions">
            <el-button type="primary" @click="showScanDialog = true" v-if="canTriggerScans">
              <el-icon><Search /></el-icon>
              Trigger Scan
            </el-button>
            <el-button @click="loadAssets">
              <el-icon><Refresh /></el-icon>
              Refresh
            </el-button>
          </div>
        </div>
      </template>

      <!-- Filters -->
      <div class="filters">
        <el-input
          v-model="filters.search"
          placeholder="Search IP or hostname..."
          clearable
          @change="loadAssets"
          style="width: 300px"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>

        <el-select v-model="filters.status" placeholder="Status" clearable @change="loadAssets" style="width: 150px">
          <el-option label="Active" value="active" />
          <el-option label="Inactive" value="inactive" />
          <el-option label="Offline" value="offline" />
        </el-select>

        <el-select v-model="filters.criticality" placeholder="Criticality" clearable @change="loadAssets" style="width: 150px">
          <el-option label="Critical" value="critical" />
          <el-option label="High" value="high" />
          <el-option label="Medium" value="medium" />
          <el-option label="Low" value="low" />
        </el-select>
      </div>

      <!-- Assets Table -->
      <el-table
        :data="assets"
        v-loading="loading"
        @row-click="showAssetDetails"
        style="width: 100%; margin-top: 20px"
        :default-sort="{ prop: 'last_seen', order: 'descending' }"
      >
        <el-table-column prop="ip_address" label="IP Address" width="150" sortable />
        <el-table-column prop="hostname" label="Hostname" width="200" sortable />
        <el-table-column prop="os_type" label="OS" width="120" />
        <el-table-column prop="asset_type" label="Type" width="120">
          <template #default="{ row }">
            <el-tag :type="getAssetTypeColor(row.asset_type)">{{ row.asset_type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="criticality" label="Criticality" width="120">
          <template #default="{ row }">
            <el-tag :type="getCriticalityColor(row.criticality)">{{ row.criticality }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="Status" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusColor(row.status)">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_seen" label="Last Seen" width="180" sortable>
          <template #default="{ row }">
            {{ formatDate(row.last_seen) }}
          </template>
        </el-table-column>
        <el-table-column label="Actions" width="150" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click.stop="showAssetDetails(row)">Details</el-button>
            <el-button link type="danger" size="small" @click.stop="confirmDelete(row)">Delete</el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- Pagination -->
      <div class="pagination">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[25, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @current-change="loadAssets"
          @size-change="loadAssets"
        />
      </div>
    </el-card>

    <!-- Asset Details Dialog -->
    <el-dialog v-model="showDetailsDialog" title="Asset Details" width="800px">
      <div v-if="selectedAsset" v-loading="loadingDetails">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="IP Address">{{ selectedAsset.ip_address }}</el-descriptions-item>
          <el-descriptions-item label="Hostname">{{ selectedAsset.hostname || 'N/A' }}</el-descriptions-item>
          <el-descriptions-item label="MAC Address">{{ selectedAsset.mac_address || 'N/A' }}</el-descriptions-item>
          <el-descriptions-item label="OS">{{ selectedAsset.os_type }} {{ selectedAsset.os_version }}</el-descriptions-item>
          <el-descriptions-item label="Type">
            <el-tag :type="getAssetTypeColor(selectedAsset.asset_type)">{{ selectedAsset.asset_type }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Criticality">
            <el-tag :type="getCriticalityColor(selectedAsset.criticality)">{{ selectedAsset.criticality }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Status">
            <el-tag :type="getStatusColor(selectedAsset.status)">{{ selectedAsset.status }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Discovery Method">{{ selectedAsset.discovery_method }}</el-descriptions-item>
          <el-descriptions-item label="First Seen">{{ formatDate(selectedAsset.first_seen) }}</el-descriptions-item>
          <el-descriptions-item label="Last Seen">{{ formatDate(selectedAsset.last_seen) }}</el-descriptions-item>
        </el-descriptions>

        <!-- Services Tab -->
        <el-tabs v-model="activeTab" style="margin-top: 20px">
          <el-tab-pane label="Services" name="services">
            <el-table :data="selectedAsset.services" style="width: 100%">
              <el-table-column prop="port" label="Port" width="80" />
              <el-table-column prop="protocol" label="Protocol" width="100" />
              <el-table-column prop="service_name" label="Service" width="150" />
              <el-table-column prop="service_version" label="Version" width="200" />
              <el-table-column prop="state" label="State" width="100">
                <template #default="{ row }">
                  <el-tag :type="row.state === 'open' ? 'success' : 'info'">{{ row.state }}</el-tag>
                </template>
              </el-table-column>
            </el-table>
          </el-tab-pane>
          <el-tab-pane label="Metadata" name="metadata">
            <pre>{{ JSON.stringify(selectedAsset.metadata, null, 2) }}</pre>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-dialog>

    <!-- Trigger Scan Dialog -->
    <el-dialog v-model="showScanDialog" title="Trigger Asset Scan" width="600px">
      <el-form :model="scanForm" label-width="120px">
        <el-form-item label="Scan Type">
          <el-select v-model="scanForm.scanType" placeholder="Select scan type">
            <el-option label="Ping Scan (Fast)" value="ping" />
            <el-option label="Port Scan" value="port" />
            <el-option label="Service Detection" value="service" />
            <el-option label="OS Detection" value="os" />
          </el-select>
        </el-form-item>
        <el-form-item label="Targets">
          <el-input
            v-model="scanForm.targets"
            type="textarea"
            :rows="4"
            placeholder="Enter IP addresses or CIDR ranges (one per line)&#10;Example:&#10;192.168.1.1&#10;192.168.1.0/24"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showScanDialog = false">Cancel</el-button>
        <el-button type="primary" @click="triggerScan" :loading="scanLoading">Trigger Scan</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Search, Refresh } from '@element-plus/icons-vue';
import assetService, { type Asset, type AssetWithServices } from '@/services/assetService';
import { useAuthStore } from '@/stores/auth';

const authStore = useAuthStore();
const canTriggerScans = computed(() => ['admin', 'analyst', 'operator'].includes(authStore.user?.role || ''));

const assets = ref<Asset[]>([]);
const loading = ref(false);
const total = ref(0);
const currentPage = ref(1);
const pageSize = ref(50);

const filters = ref({
  search: '',
  status: '',
  criticality: ''
});

const showDetailsDialog = ref(false);
const loadingDetails = ref(false);
const selectedAsset = ref<AssetWithServices | null>(null);
const activeTab = ref('services');

const showScanDialog = ref(false);
const scanLoading = ref(false);
const scanForm = ref({
  scanType: 'ping',
  targets: ''
});

async function loadAssets() {
  loading.value = true;
  try {
    const response = await assetService.getAssets({
      ...filters.value,
      limit: pageSize.value,
      offset: (currentPage.value - 1) * pageSize.value
    });
    assets.value = response.assets;
    total.value = response.total;
  } catch (error) {
    ElMessage.error('Failed to load assets');
    console.error(error);
  } finally {
    loading.value = false;
  }
}

async function showAssetDetails(asset: Asset) {
  showDetailsDialog.value = true;
  loadingDetails.value = true;
  try {
    selectedAsset.value = await assetService.getAsset(asset.id);
  } catch (error) {
    ElMessage.error('Failed to load asset details');
    console.error(error);
  } finally {
    loadingDetails.value = false;
  }
}

async function confirmDelete(asset: Asset) {
  try {
    await ElMessageBox.confirm(
      `Are you sure you want to delete asset ${asset.ip_address}?`,
      'Confirm Delete',
      { type: 'warning' }
    );
    await assetService.deleteAsset(asset.id);
    ElMessage.success('Asset deleted successfully');
    await loadAssets();
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete asset');
      console.error(error);
    }
  }
}

async function triggerScan() {
  if (!scanForm.value.targets.trim()) {
    ElMessage.warning('Please enter at least one target');
    return;
  }

  scanLoading.value = true;
  try {
    const targets = scanForm.value.targets.split('\n').map(t => t.trim()).filter(t => t);
    const result = await assetService.triggerScan(targets, scanForm.value.scanType);
    ElMessage.success(`Scan initiated (ID: ${result.scanId})`);
    showScanDialog.value = false;
    scanForm.value.targets = '';
  } catch (error: any) {
    ElMessage.error(error.response?.data?.error || 'Failed to trigger scan');
    console.error(error);
  } finally {
    scanLoading.value = false;
  }
}

function getAssetTypeColor(type: string) {
  const colors: Record<string, string> = {
    server: '',
    workstation: 'success',
    network: 'warning',
    iot: 'info'
  };
  return colors[type] || '';
}

function getCriticalityColor(criticality: string) {
  const colors: Record<string, string> = {
    critical: 'danger',
    high: 'warning',
    medium: '',
    low: 'info'
  };
  return colors[criticality] || '';
}

function getStatusColor(status: string) {
  const colors: Record<string, string> = {
    active: 'success',
    inactive: 'warning',
    offline: 'danger'
  };
  return colors[status] || '';
}

function formatDate(date: string) {
  return new Date(date).toLocaleString();
}

onMounted(() => {
  loadAssets();
});
</script>

<style scoped>
.assets-container {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.title {
  font-size: 18px;
  font-weight: bold;
}

.header-actions {
  display: flex;
  gap: 10px;
}

.filters {
  display: flex;
  gap: 15px;
  flex-wrap: wrap;
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 20px;
}
</style>
