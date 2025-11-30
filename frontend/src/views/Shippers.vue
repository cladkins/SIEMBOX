<template>
  <div class="shippers">
    <el-row :gutter="20">
      <el-col :span="24">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>Log Shippers</span>
              <div>
                <el-button type="primary" @click="showCreateShipper" :icon="Plus">
                  Add Shipper
                </el-button>
                <el-button @click="fetchShippers" :icon="Refresh" circle />
              </div>
            </div>
          </template>

          <el-table :data="shippers" v-loading="loading" stripe>
            <el-table-column prop="name" label="Name" min-width="150" />
            <el-table-column prop="description" label="Description" min-width="200" />
            <el-table-column label="Status" width="120">
              <template #default="{ row }">
                <el-tag :type="getStatusType(row.status)">
                  {{ row.status }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Last Seen" width="180">
              <template #default="{ row }">
                <span v-if="row.last_seen">{{ formatDate(row.last_seen) }}</span>
                <el-text v-else type="info">Never</el-text>
              </template>
            </el-table-column>
            <el-table-column prop="version" label="Version" width="100" />
            <el-table-column prop="hostname" label="Hostname" width="150" />
            <el-table-column label="Sources" width="100" align="center">
              <template #default="{ row }">
                <el-tag size="small">{{ row.sources?.length || 0 }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Actions" width="200" align="center">
              <template #default="{ row }">
                <el-button size="small" @click="viewShipper(row)" :icon="View">
                  View
                </el-button>
                <el-button size="small" type="danger" @click="deleteShipperConfirm(row)" :icon="Delete">
                  Delete
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <!-- Create/Edit Shipper Dialog -->
    <el-dialog
      v-model="shipperDialogVisible"
      :title="editingShipper ? 'Edit Shipper' : 'Add New Shipper'"
      width="600px"
    >
      <el-form :model="shipperForm" label-width="120px">
        <el-form-item label="Name" required>
          <el-input v-model="shipperForm.name" placeholder="e.g., NPM Server" />
        </el-form-item>
        <el-form-item label="Description">
          <el-input
            v-model="shipperForm.description"
            type="textarea"
            :rows="2"
            placeholder="Description of what this shipper monitors"
          />
        </el-form-item>
        <el-form-item v-if="!editingShipper">
          <el-alert type="info" :closable="false">
            An API key will be automatically generated when you create the shipper.
          </el-alert>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="shipperDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="saveShipper" :loading="saving">
          {{ editingShipper ? 'Update' : 'Create' }}
        </el-button>
      </template>
    </el-dialog>

    <!-- View Shipper Dialog -->
    <el-dialog
      v-model="viewDialogVisible"
      :title="currentShipper?.name || 'Shipper Details'"
      width="900px"
    >
      <div v-if="currentShipper">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="Name">{{ currentShipper.name }}</el-descriptions-item>
          <el-descriptions-item label="Status">
            <el-tag :type="getStatusType(currentShipper.status)">
              {{ currentShipper.status }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Description" :span="2">
            {{ currentShipper.description || 'N/A' }}
          </el-descriptions-item>
          <el-descriptions-item label="API Key" :span="2">
            <el-input v-model="currentShipper.api_key" readonly>
              <template #append>
                <el-button :icon="CopyDocument" @click="copyApiKey(currentShipper.api_key)">
                  Copy
                </el-button>
              </template>
            </el-input>
          </el-descriptions-item>
          <el-descriptions-item label="Hostname">
            {{ currentShipper.hostname || 'N/A' }}
          </el-descriptions-item>
          <el-descriptions-item label="Version">
            {{ currentShipper.version || 'N/A' }}
          </el-descriptions-item>
          <el-descriptions-item label="Last Seen">
            {{ currentShipper.last_seen ? formatDate(currentShipper.last_seen) : 'Never' }}
          </el-descriptions-item>
          <el-descriptions-item label="IP Address">
            {{ currentShipper.ip_address || 'N/A' }}
          </el-descriptions-item>
        </el-descriptions>

        <el-divider />

        <!-- Log Sources Section -->
        <div class="section-header">
          <h3>Log Sources</h3>
          <el-button size="small" type="primary" @click="showAddSource" :icon="Plus">
            Add Source
          </el-button>
        </div>

        <el-table :data="currentShipper.sources" stripe style="margin-bottom: 20px">
          <el-table-column prop="source_type" label="Type" width="100">
            <template #default="{ row }">
              <el-tag>{{ row.source_type }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="Path/Container" min-width="200">
            <template #default="{ row }">
              <span v-if="row.source_type === 'file'">{{ row.file_path }}</span>
              <span v-else-if="row.source_type === 'docker'">{{ row.container_name }}</span>
              <span v-else-if="row.source_type === 'journal'">{{ row.journal_unit }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="tag" label="Tag" width="150" />
          <el-table-column prop="facility" label="Facility" width="100" />
          <el-table-column label="Enabled" width="80" align="center">
            <template #default="{ row }">
              <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
                {{ row.enabled ? 'Yes' : 'No' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="Actions" width="100" align="center">
            <template #default="{ row }">
              <el-button
                size="small"
                type="danger"
                @click="deleteSource(row)"
                :icon="Delete"
              >
                Delete
              </el-button>
            </template>
          </el-table-column>
        </el-table>

        <!-- Volume Mounts Section -->
        <div class="section-header">
          <h3>Volume Mounts</h3>
          <el-button size="small" type="primary" @click="showAddVolume" :icon="Plus">
            Add Volume
          </el-button>
        </div>

        <el-table :data="currentShipper.volumes" stripe>
          <el-table-column prop="host_path" label="Host Path" min-width="200" />
          <el-table-column prop="container_path" label="Container Path" min-width="200" />
          <el-table-column label="Read Only" width="100" align="center">
            <template #default="{ row }">
              <el-tag :type="row.read_only ? 'info' : 'warning'" size="small">
                {{ row.read_only ? 'Yes' : 'No' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="Actions" width="100" align="center">
            <template #default="{ row }">
              <el-button
                size="small"
                type="danger"
                @click="deleteVolume(row)"
                :icon="Delete"
              >
                Delete
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-dialog>

    <!-- Add Source Dialog -->
    <el-dialog v-model="sourceDialogVisible" title="Add Log Source" width="600px">
      <el-form :model="sourceForm" label-width="130px">
        <el-form-item label="Source Type" required>
          <el-select v-model="sourceForm.source_type" placeholder="Select source type">
            <el-option label="File" value="file" />
            <el-option label="Docker Container" value="docker" />
            <el-option label="Systemd Journal" value="journal" />
          </el-select>
        </el-form-item>

        <el-form-item
          v-if="sourceForm.source_type === 'file'"
          label="File Path"
          required
        >
          <el-input
            v-model="sourceForm.file_path"
            placeholder="/var/log/nginx/access.log"
          />
        </el-form-item>

        <el-form-item
          v-if="sourceForm.source_type === 'docker'"
          label="Container Name"
          required
        >
          <el-input v-model="sourceForm.container_name" placeholder="nginx" />
        </el-form-item>

        <el-form-item
          v-if="sourceForm.source_type === 'journal'"
          label="Journal Unit"
          required
        >
          <el-input v-model="sourceForm.journal_unit" placeholder="nginx.service" />
        </el-form-item>

        <el-form-item label="Tag" required>
          <el-input v-model="sourceForm.tag" placeholder="nginx-access" />
        </el-form-item>

        <el-form-item label="Facility">
          <el-select v-model="sourceForm.facility">
            <el-option label="local0" value="local0" />
            <el-option label="local1" value="local1" />
            <el-option label="local2" value="local2" />
            <el-option label="local3" value="local3" />
            <el-option label="local4" value="local4" />
            <el-option label="local5" value="local5" />
            <el-option label="local6" value="local6" />
            <el-option label="local7" value="local7" />
          </el-select>
        </el-form-item>

        <el-form-item label="Enabled">
          <el-switch v-model="sourceForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="sourceDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="saveSource" :loading="saving">Add</el-button>
      </template>
    </el-dialog>

    <!-- Add Volume Dialog -->
    <el-dialog v-model="volumeDialogVisible" title="Add Volume Mount" width="600px">
      <el-form :model="volumeForm" label-width="130px">
        <el-form-item label="Host Path" required>
          <el-input
            v-model="volumeForm.host_path"
            placeholder="/var/log/nginx"
          />
          <el-text size="small" type="info">
            Path on the host machine where logs are stored
          </el-text>
        </el-form-item>

        <el-form-item label="Container Path" required>
          <el-input v-model="volumeForm.container_path" placeholder="/logs/nginx" />
          <el-text size="small" type="info">
            Path inside the shipper container where logs will be accessible
          </el-text>
        </el-form-item>

        <el-form-item label="Read Only">
          <el-switch v-model="volumeForm.read_only" />
          <el-text size="small" type="info" style="margin-left: 10px">
            Recommended: Keep enabled for security
          </el-text>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="volumeDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="saveVolume" :loading="saving">Add</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { api } from '@/services/api';
import { ElMessage, ElMessageBox } from 'element-plus';
import {
  Plus,
  Refresh,
  View,
  Delete,
  CopyDocument,
} from '@element-plus/icons-vue';
import { format } from 'date-fns';

const loading = ref(false);
const saving = ref(false);
const shippers = ref<any[]>([]);
const currentShipper = ref<any>(null);

const shipperDialogVisible = ref(false);
const viewDialogVisible = ref(false);
const sourceDialogVisible = ref(false);
const volumeDialogVisible = ref(false);
const editingShipper = ref(false);

const shipperForm = reactive({
  name: '',
  description: '',
});

const sourceForm = reactive({
  source_type: 'file',
  file_path: '',
  container_name: '',
  journal_unit: '',
  tag: '',
  facility: 'local0',
  enabled: true,
});

const volumeForm = reactive({
  host_path: '',
  container_path: '',
  read_only: true,
});

onMounted(() => {
  fetchShippers();
});

async function fetchShippers() {
  loading.value = true;
  try {
    const response = await api.getShippers();
    shippers.value = response.data;
  } catch (error) {
    ElMessage.error('Failed to fetch shippers');
  } finally {
    loading.value = false;
  }
}

function showCreateShipper() {
  editingShipper.value = false;
  shipperForm.name = '';
  shipperForm.description = '';
  shipperDialogVisible.value = true;
}

async function saveShipper() {
  if (!shipperForm.name) {
    ElMessage.warning('Please enter a shipper name');
    return;
  }

  saving.value = true;
  try {
    if (editingShipper.value) {
      await api.updateShipper(currentShipper.value.id, shipperForm);
      ElMessage.success('Shipper updated successfully');
    } else {
      await api.createShipper(shipperForm);
      ElMessage.success('Shipper created successfully');
    }
    shipperDialogVisible.value = false;
    fetchShippers();
  } catch (error) {
    ElMessage.error('Failed to save shipper');
  } finally {
    saving.value = false;
  }
}

async function viewShipper(shipper: any) {
  loading.value = true;
  try {
    const response = await api.getShipper(shipper.id);
    currentShipper.value = response.data;
    viewDialogVisible.value = true;
  } catch (error) {
    ElMessage.error('Failed to load shipper details');
  } finally {
    loading.value = false;
  }
}

async function deleteShipperConfirm(shipper: any) {
  try {
    await ElMessageBox.confirm(
      `Are you sure you want to delete "${shipper.name}"? This will remove all sources and volumes associated with this shipper.`,
      'Confirm Delete',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    );

    await api.deleteShipper(shipper.id);
    ElMessage.success('Shipper deleted successfully');
    fetchShippers();
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete shipper');
    }
  }
}

function showAddSource() {
  sourceForm.source_type = 'file';
  sourceForm.file_path = '';
  sourceForm.container_name = '';
  sourceForm.journal_unit = '';
  sourceForm.tag = '';
  sourceForm.facility = 'local0';
  sourceForm.enabled = true;
  sourceDialogVisible.value = true;
}

async function saveSource() {
  if (!sourceForm.tag) {
    ElMessage.warning('Please enter a tag');
    return;
  }

  if (sourceForm.source_type === 'file' && !sourceForm.file_path) {
    ElMessage.warning('Please enter a file path');
    return;
  }

  if (sourceForm.source_type === 'docker' && !sourceForm.container_name) {
    ElMessage.warning('Please enter a container name');
    return;
  }

  if (sourceForm.source_type === 'journal' && !sourceForm.journal_unit) {
    ElMessage.warning('Please enter a journal unit');
    return;
  }

  saving.value = true;
  try {
    await api.createShipperSource(currentShipper.value.id, sourceForm);
    ElMessage.success('Source added successfully');
    sourceDialogVisible.value = false;

    // Refresh shipper details
    const response = await api.getShipper(currentShipper.value.id);
    currentShipper.value = response.data;
  } catch (error) {
    ElMessage.error('Failed to add source');
  } finally {
    saving.value = false;
  }
}

async function deleteSource(source: any) {
  try {
    await ElMessageBox.confirm(
      'Are you sure you want to delete this source?',
      'Confirm Delete',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    );

    await api.deleteShipperSource(currentShipper.value.id, source.id);
    ElMessage.success('Source deleted successfully');

    // Refresh shipper details
    const response = await api.getShipper(currentShipper.value.id);
    currentShipper.value = response.data;
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete source');
    }
  }
}

function showAddVolume() {
  volumeForm.host_path = '';
  volumeForm.container_path = '';
  volumeForm.read_only = true;
  volumeDialogVisible.value = true;
}

async function saveVolume() {
  if (!volumeForm.host_path || !volumeForm.container_path) {
    ElMessage.warning('Please enter both host path and container path');
    return;
  }

  saving.value = true;
  try {
    await api.createShipperVolume(currentShipper.value.id, volumeForm);
    ElMessage.success('Volume added successfully');
    volumeDialogVisible.value = false;

    // Refresh shipper details
    const response = await api.getShipper(currentShipper.value.id);
    currentShipper.value = response.data;
  } catch (error) {
    ElMessage.error('Failed to add volume');
  } finally {
    saving.value = false;
  }
}

async function deleteVolume(volume: any) {
  try {
    await ElMessageBox.confirm(
      'Are you sure you want to delete this volume mount?',
      'Confirm Delete',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    );

    await api.deleteShipperVolume(currentShipper.value.id, volume.id);
    ElMessage.success('Volume deleted successfully');

    // Refresh shipper details
    const response = await api.getShipper(currentShipper.value.id);
    currentShipper.value = response.data;
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete volume');
    }
  }
}

function copyApiKey(apiKey: string) {
  navigator.clipboard.writeText(apiKey);
  ElMessage.success('API key copied to clipboard');
}

function getStatusType(status: string) {
  const types: Record<string, any> = {
    online: 'success',
    offline: 'danger',
    pending: 'warning',
  };
  return types[status] || 'info';
}

const formatDate = (date: string): string => {
  return format(new Date(date), 'MMM dd, yyyy HH:mm');
};
</script>

<style scoped>
.shippers {
  padding: 0;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
  margin-top: 20px;
}

.section-header h3 {
  margin: 0;
  font-size: 16px;
}
</style>
