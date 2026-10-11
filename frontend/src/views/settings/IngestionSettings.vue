<template>
  <div class="ingestion-settings">
    <el-card>
      <template #header>
        <span>Syslog Server Configuration</span>
      </template>

      <el-alert type="info" :closable="false" style="margin-bottom: 20px">
        These settings tell log shippers where to send logs. The syslog receiver must be restarted to listen on a different port.
      </el-alert>

      <el-form :model="syslogForm" label-width="200px" v-loading="syslogLoading">
        <el-form-item label="Syslog Host">
          <el-input
            v-model="syslogForm.syslog_host"
            placeholder="localhost or 0.0.0.0"
            style="width: 300px"
          />
          <br />
          <el-text size="small" type="info">
            IP address or hostname where syslog server listens
          </el-text>
        </el-form-item>

        <el-form-item label="Syslog Port">
          <el-input-number
            v-model="syslogForm.syslog_port"
            :min="1"
            :max="65535"
            style="width: 150px"
          />
          <br />
          <el-text size="small" type="info">
            Port number for syslog receiver (default: 514)
          </el-text>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="saveSyslogSettings" :loading="syslogSaving">
            <el-icon><Check /></el-icon> Save Settings
          </el-button>
          <el-button @click="fetchSyslogSettings">Reset</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { api } from '@/services/api';
import { ElMessage } from 'element-plus';
import { Check } from '@element-plus/icons-vue';

const syslogLoading = ref(false);
const syslogSaving = ref(false);

const syslogForm = reactive({
  syslog_host: '',
  syslog_port: 514,
});

onMounted(() => {
  fetchSyslogSettings();
});

async function fetchSyslogSettings() {
  syslogLoading.value = true;
  try {
    const response = await api.getSyslogSettings();
    Object.assign(syslogForm, response.data);
  } catch (error) {
    ElMessage.error('Failed to fetch syslog settings');
  } finally {
    syslogLoading.value = false;
  }
}

async function saveSyslogSettings() {
  syslogSaving.value = true;
  try {
    await api.updateSyslogSettings(syslogForm);
    ElMessage.success('Syslog settings saved successfully');
  } catch (error) {
    ElMessage.error('Failed to save syslog settings');
  } finally {
    syslogSaving.value = false;
  }
}
</script>
