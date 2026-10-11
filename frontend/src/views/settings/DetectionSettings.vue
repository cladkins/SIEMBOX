<template>
  <div class="detection-settings">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>IP Whitelist Management <HelpTip text="Whitelisted IPs and CIDR ranges never generate alerts — the rules engine suppresses every alert whose source IP matches, so add your own trusted hosts here instead of editing individual rules. Rules can also target non-whitelisted traffic via the not_in_whitelist condition." /></span>
          <el-button type="primary" size="small" @click="showAddIpDialog" :icon="Plus">
            Add IP
          </el-button>
        </div>
      </template>

      <el-alert type="info" :closable="false" style="margin-bottom: 15px">
        Trusted IPs that are excluded from detection alerts (e.g. your internal LAN). Supports CIDR
        notation (e.g., 192.168.1.0/24) and single IPs (10.0.0.5). Leave empty to alert on all sources.
      </el-alert>

      <el-table :data="ipWhitelist" v-loading="ipLoading" stripe>
        <el-table-column prop="ip_address" label="IP Address / CIDR" min-width="180">
          <template #default="{ row }">
            <el-tag>{{ row.ip_address }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column prop="description" label="Description" min-width="250" />

        <el-table-column label="Added" width="180">
          <template #default="{ row }">
            <el-text size="small">{{ formatDate(row.created_at) }}</el-text>
          </template>
        </el-table-column>

        <el-table-column label="Actions" width="180" align="center">
          <template #default="{ row }">
            <el-button
              size="small"
              @click="editIpWhitelist(row)"
              :icon="Edit"
            >
              Edit
            </el-button>
            <el-button
              size="small"
              type="danger"
              @click="deleteIpWhitelistConfirm(row)"
              :icon="Delete"
            >
              Delete
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- IP Whitelist Dialog -->
    <el-dialog
      v-model="ipWhitelistDialogVisible"
      :title="ipWhitelistForm.id ? 'Edit IP Whitelist Entry' : 'Add IP to Whitelist'"
      width="600px"
    >
      <el-form :model="ipWhitelistForm" label-width="130px">
        <el-form-item label="IP Address / CIDR" required>
          <el-input
            v-model="ipWhitelistForm.ip_address"
            placeholder="192.168.1.0/24 or 10.0.0.5"
            :disabled="!!ipWhitelistForm.id"
          />
          <el-text size="small" type="info">
            Use CIDR notation for ranges (e.g., 192.168.1.0/24) or single IPs (10.0.0.5)
          </el-text>
        </el-form-item>

        <el-form-item label="Description">
          <el-input
            v-model="ipWhitelistForm.description"
            type="textarea"
            :rows="2"
            placeholder="e.g., Production servers in data center A"
          />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="ipWhitelistDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="saveIpWhitelist" :loading="saving">
          {{ ipWhitelistForm.id ? 'Update' : 'Add' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { api } from '@/services/api';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Delete, Plus, Edit } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import { formatDate } from './format';

const saving = ref(false);
const ipLoading = ref(false);
const ipWhitelistDialogVisible = ref(false);

const ipWhitelistForm = reactive({
  id: null as number | null,
  ip_address: '',
  description: '',
});

const ipWhitelist = ref<any[]>([]);

onMounted(() => {
  fetchIpWhitelist();
});

// IP Whitelist Management Functions
async function fetchIpWhitelist() {
  ipLoading.value = true;
  try {
    const response = await api.getIpWhitelist();
    ipWhitelist.value = response.data;
  } catch (error) {
    ElMessage.error('Failed to fetch IP whitelist');
  } finally {
    ipLoading.value = false;
  }
}

function showAddIpDialog() {
  ipWhitelistForm.id = null;
  ipWhitelistForm.ip_address = '';
  ipWhitelistForm.description = '';
  ipWhitelistDialogVisible.value = true;
}

function editIpWhitelist(entry: any) {
  ipWhitelistForm.id = entry.id;
  ipWhitelistForm.ip_address = entry.ip_address;
  ipWhitelistForm.description = entry.description || '';
  ipWhitelistDialogVisible.value = true;
}

async function saveIpWhitelist() {
  if (!ipWhitelistForm.ip_address) {
    ElMessage.warning('Please enter an IP address or CIDR');
    return;
  }

  saving.value = true;
  try {
    if (ipWhitelistForm.id) {
      // Update existing entry (description only)
      await api.updateIpWhitelist(ipWhitelistForm.id, {
        description: ipWhitelistForm.description,
      });
      ElMessage.success('IP whitelist entry updated');
    } else {
      // Add new entry
      await api.addIpWhitelist(ipWhitelistForm);
      ElMessage.success('IP address added to whitelist');
    }
    ipWhitelistDialogVisible.value = false;
    fetchIpWhitelist();
  } catch (error: any) {
    if (error.response?.status === 409) {
      ElMessage.error('This IP address already exists in the whitelist');
    } else if (error.response?.status === 400) {
      ElMessage.error('Invalid IP address or CIDR format');
    } else {
      ElMessage.error('Failed to save IP whitelist entry');
    }
  } finally {
    saving.value = false;
  }
}

async function deleteIpWhitelistConfirm(entry: any) {
  try {
    await ElMessageBox.confirm(
      `Are you sure you want to remove "${entry.ip_address}" from the whitelist?`,
      'Confirm Delete',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    );

    await api.deleteIpWhitelist(entry.id);
    ElMessage.success('IP address removed from whitelist');
    fetchIpWhitelist();
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete IP whitelist entry');
    }
  }
}
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
