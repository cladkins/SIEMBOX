<template>
  <div class="notification-settings">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>Notifications <HelpTip text="Where and when SIEMBox pushes events out: channels define destinations (Slack, Email, NTFY), preferences below choose which events fire and at what minimum severity." /></span>
          <div>
            <el-button size="small" @click="sendTestAlert" :loading="testAlertSending">
              Send test alert
            </el-button>
            <el-button type="primary" size="small" @click="showCreateChannel" :icon="Plus">
              New Channel
            </el-button>
          </div>
        </div>
      </template>

      <el-alert type="info" :closable="false" style="margin-bottom: 15px">
        Configure notification channels (Slack, Email, NTFY) and choose which events trigger them.
        "Test" sends a generic message to one channel; <strong>Send test alert</strong> previews the
        real new-alert email across all enabled channels (it ignores the enabled / severity preferences below).
      </el-alert>

      <el-table :data="notificationChannels" v-loading="notificationChannelsLoading" stripe>
        <el-table-column prop="name" label="Name" min-width="150" />

        <el-table-column label="Type" width="120">
          <template #default="{ row }">
            <el-tag :type="channelTagType(row.channel_type)" size="small">
              {{ row.channel_type }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="Enabled" width="90" align="center">
          <template #default="{ row }">
            <el-switch
              v-model="row.enabled"
              :loading="notificationChannelsSaving"
              @change="toggleChannelEnabled(row)"
            />
          </template>
        </el-table-column>

        <el-table-column label="Actions" width="280" align="center" fixed="right">
          <template #default="{ row }">
            <el-button
              size="small"
              type="success"
              @click="testChannel(row)"
              :icon="VideoPlay"
            >
              Test
            </el-button>
            <el-button
              size="small"
              @click="editChannel(row)"
              :icon="Edit"
            >
              Edit
            </el-button>
            <el-button
              size="small"
              type="danger"
              @click="deleteChannelConfirm(row)"
              :icon="Delete"
            >
              Delete
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-divider />

      <h4 style="margin: 0 0 15px 0">Notification Preferences</h4>

      <el-form :model="notificationSettingsForm" label-width="200px" v-loading="notificationSettingsLoading">
        <el-form-item label="Alerts">
          <el-switch v-model="notificationSettingsForm.alertsEnabled" />
          <el-text size="small" type="info" style="margin-left: 10px">
            Notify on new detection alerts
          </el-text>
        </el-form-item>

        <el-form-item>
          <template #label>Alerts Min Severity <HelpTip text="Only alerts at or above this severity are pushed to your channels. Lower-severity alerts still appear in the Alerts view — this filters notifications, not detection." /></template>
          <el-select
            v-model="notificationSettingsForm.alertsMinSeverity"
            :disabled="!notificationSettingsForm.alertsEnabled"
            style="width: 200px"
          >
            <el-option label="Low" value="low" />
            <el-option label="Medium" value="medium" />
            <el-option label="High" value="high" />
            <el-option label="Critical" value="critical" />
          </el-select>
        </el-form-item>

        <el-divider />

        <el-form-item label="Vulnerabilities">
          <el-switch v-model="notificationSettingsForm.vulnEnabled" />
          <el-text size="small" type="info" style="margin-left: 10px">
            Notify on newly discovered vulnerabilities
          </el-text>
        </el-form-item>

        <el-form-item>
          <template #label>Vulnerabilities Min Severity <HelpTip text="Only newly found vulnerabilities at or above this severity trigger a notification. Everything found still lands in the Vulnerabilities view." /></template>
          <el-select
            v-model="notificationSettingsForm.vulnMinSeverity"
            :disabled="!notificationSettingsForm.vulnEnabled"
            style="width: 200px"
          >
            <el-option label="Low" value="low" />
            <el-option label="Medium" value="medium" />
            <el-option label="High" value="high" />
            <el-option label="Critical" value="critical" />
          </el-select>
        </el-form-item>

        <el-divider />

        <el-form-item>
          <template #label>Ingestion Health <HelpTip text="A watchdog for the pipeline itself: notifies when NO logs have arrived for the stall threshold below — usually a dead shipper, a network problem, or a device that stopped forwarding." /></template>
          <el-switch v-model="notificationSettingsForm.ingestionEnabled" />
          <el-text size="small" type="info" style="margin-left: 10px">
            Notify when log ingestion stalls
          </el-text>
        </el-form-item>

        <el-form-item label="Stall Threshold (minutes)">
          <el-input-number
            v-model="notificationSettingsForm.ingestionStallMinutes"
            :min="1"
            :max="1440"
            :disabled="!notificationSettingsForm.ingestionEnabled"
            style="width: 200px"
          />
          <br />
          <el-text size="small" type="info">
            Alert if no logs have been ingested for this many minutes
          </el-text>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="saveNotificationSettings" :loading="notificationSettingsSaving">
            <el-icon><Check /></el-icon> Save Preferences
          </el-button>
          <el-button @click="fetchNotificationSettings">Reset</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- Notification Channel Dialog -->
    <el-dialog
      v-model="notificationChannelDialogVisible"
      :title="notificationChannelForm.id ? 'Edit Channel' : 'New Channel'"
      width="640px"
    >
      <el-form :model="notificationChannelForm" label-width="150px">
        <el-form-item label="Name" required>
          <el-input v-model="notificationChannelForm.name" placeholder="e.g., Security Slack" />
        </el-form-item>

        <el-form-item label="Type" required>
          <el-select
            v-model="notificationChannelForm.channel_type"
            :disabled="!!notificationChannelForm.id"
            style="width: 100%"
          >
            <el-option label="Slack" value="slack" />
            <el-option label="Email" value="email" />
            <el-option label="NTFY" value="ntfy" />
          </el-select>
        </el-form-item>

        <el-form-item label="Enabled">
          <el-switch v-model="notificationChannelForm.enabled" />
        </el-form-item>

        <!-- Slack config -->
        <template v-if="notificationChannelForm.channel_type === 'slack'">
          <el-form-item label="Webhook URL" required>
            <el-input
              v-model="notificationChannelForm.slackWebhookUrl"
              placeholder="https://hooks.slack.com/services/..."
            />
          </el-form-item>
        </template>

        <!-- NTFY config -->
        <template v-else-if="notificationChannelForm.channel_type === 'ntfy'">
          <el-form-item label="Server URL" required>
            <el-input
              v-model="notificationChannelForm.ntfyServerUrl"
              placeholder="https://ntfy.sh"
            />
          </el-form-item>

          <el-form-item label="Topic" required>
            <el-input
              v-model="notificationChannelForm.ntfyTopic"
              placeholder="e.g., siembox-alerts"
            />
          </el-form-item>

          <el-form-item label="Token">
            <el-input
              v-model="notificationChannelForm.ntfyToken"
              placeholder="Optional access token"
            />
          </el-form-item>
        </template>

        <!-- Email config -->
        <template v-else-if="notificationChannelForm.channel_type === 'email'">
          <el-form-item label="SMTP Host" required>
            <el-input v-model="notificationChannelForm.emailHost" placeholder="smtp.example.com" />
          </el-form-item>

          <el-form-item label="SMTP Port" required>
            <el-input-number
              v-model="notificationChannelForm.emailPort"
              :min="1"
              :max="65535"
              style="width: 150px"
            />
          </el-form-item>

          <el-form-item label="Use TLS/SSL">
            <el-switch v-model="notificationChannelForm.emailSecure" />
          </el-form-item>

          <el-form-item label="Username">
            <el-input v-model="notificationChannelForm.emailUser" placeholder="SMTP username" />
          </el-form-item>

          <el-form-item label="Password">
            <el-input
              v-model="notificationChannelForm.emailPassword"
              type="password"
              show-password
              placeholder="SMTP password"
            />
          </el-form-item>

          <el-form-item label="From" required>
            <el-input v-model="notificationChannelForm.emailFrom" placeholder="siembox@example.com" />
          </el-form-item>

          <el-form-item label="To" required>
            <el-input v-model="notificationChannelForm.emailTo" placeholder="security@example.com" />
          </el-form-item>
        </template>
      </el-form>

      <template #footer>
        <el-button @click="notificationChannelDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="saveChannel" :loading="notificationChannelsSaving">
          {{ notificationChannelForm.id ? 'Update' : 'Create' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { api } from '@/services/api';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Check, Delete, Plus, Edit, VideoPlay } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';

// Notifications state
const notificationChannelsLoading = ref(false);
const notificationChannelsSaving = ref(false);
const notificationChannelDialogVisible = ref(false);
const notificationChannels = ref<any[]>([]);

const notificationChannelForm = reactive({
  id: null as number | null,
  name: '',
  channel_type: 'slack' as 'slack' | 'email' | 'ntfy',
  enabled: true,
  // slack
  slackWebhookUrl: '',
  // ntfy
  ntfyServerUrl: 'https://ntfy.sh',
  ntfyTopic: '',
  ntfyToken: '',
  // email
  emailHost: '',
  emailPort: 587,
  emailSecure: false,
  emailUser: '',
  emailPassword: '',
  emailFrom: '',
  emailTo: '',
});

const notificationSettingsLoading = ref(false);
const notificationSettingsSaving = ref(false);

const notificationSettingsForm = reactive({
  alertsEnabled: false,
  alertsMinSeverity: 'medium' as 'low' | 'medium' | 'high' | 'critical',
  vulnEnabled: false,
  vulnMinSeverity: 'high' as 'low' | 'medium' | 'high' | 'critical',
  ingestionEnabled: false,
  ingestionStallMinutes: 15,
});

onMounted(() => {
  fetchNotificationChannels();
  fetchNotificationSettings();
});

// Notification Channels Management Functions
async function fetchNotificationChannels() {
  notificationChannelsLoading.value = true;
  try {
    const response = await api.getNotificationChannels();
    notificationChannels.value = response.data;
  } catch (error) {
    ElMessage.error('Failed to fetch notification channels');
  } finally {
    notificationChannelsLoading.value = false;
  }
}

function channelTagType(type: string): string {
  const types: Record<string, string> = {
    slack: 'primary',
    email: 'success',
    ntfy: 'warning',
  };
  return types[type] || 'info';
}

function resetNotificationChannelForm() {
  notificationChannelForm.id = null;
  notificationChannelForm.name = '';
  notificationChannelForm.channel_type = 'slack';
  notificationChannelForm.enabled = true;
  notificationChannelForm.slackWebhookUrl = '';
  notificationChannelForm.ntfyServerUrl = 'https://ntfy.sh';
  notificationChannelForm.ntfyTopic = '';
  notificationChannelForm.ntfyToken = '';
  notificationChannelForm.emailHost = '';
  notificationChannelForm.emailPort = 587;
  notificationChannelForm.emailSecure = false;
  notificationChannelForm.emailUser = '';
  notificationChannelForm.emailPassword = '';
  notificationChannelForm.emailFrom = '';
  notificationChannelForm.emailTo = '';
}

function showCreateChannel() {
  resetNotificationChannelForm();
  notificationChannelDialogVisible.value = true;
}

function editChannel(channel: any) {
  resetNotificationChannelForm();
  notificationChannelForm.id = channel.id;
  notificationChannelForm.name = channel.name;
  notificationChannelForm.channel_type = channel.channel_type;
  notificationChannelForm.enabled = channel.enabled;

  const config = channel.config || {};
  if (channel.channel_type === 'slack') {
    notificationChannelForm.slackWebhookUrl = config.webhook_url || '';
  } else if (channel.channel_type === 'ntfy') {
    notificationChannelForm.ntfyServerUrl = config.server_url || 'https://ntfy.sh';
    notificationChannelForm.ntfyTopic = config.topic || '';
    notificationChannelForm.ntfyToken = config.token || '';
  } else if (channel.channel_type === 'email') {
    notificationChannelForm.emailHost = config.host || '';
    notificationChannelForm.emailPort = config.port ?? 587;
    notificationChannelForm.emailSecure = !!config.secure;
    notificationChannelForm.emailUser = config.user || '';
    notificationChannelForm.emailPassword = config.password || '';
    notificationChannelForm.emailFrom = config.from || '';
    notificationChannelForm.emailTo = config.to || '';
  }

  notificationChannelDialogVisible.value = true;
}

function buildChannelConfig(): any {
  if (notificationChannelForm.channel_type === 'slack') {
    return { webhook_url: notificationChannelForm.slackWebhookUrl.trim() };
  }
  if (notificationChannelForm.channel_type === 'ntfy') {
    const config: any = {
      server_url: notificationChannelForm.ntfyServerUrl.trim() || 'https://ntfy.sh',
      topic: notificationChannelForm.ntfyTopic.trim(),
    };
    if (notificationChannelForm.ntfyToken.trim()) {
      config.token = notificationChannelForm.ntfyToken.trim();
    }
    return config;
  }
  // email
  return {
    host: notificationChannelForm.emailHost.trim(),
    port: notificationChannelForm.emailPort,
    secure: notificationChannelForm.emailSecure,
    user: notificationChannelForm.emailUser.trim(),
    password: notificationChannelForm.emailPassword,
    from: notificationChannelForm.emailFrom.trim(),
    to: notificationChannelForm.emailTo.trim(),
  };
}

async function saveChannel() {
  if (!notificationChannelForm.name.trim()) {
    ElMessage.warning('Please enter a name');
    return;
  }

  const type = notificationChannelForm.channel_type;
  if (type === 'slack' && !notificationChannelForm.slackWebhookUrl.trim()) {
    ElMessage.warning('Please enter a webhook URL');
    return;
  }
  if (type === 'ntfy' && !notificationChannelForm.ntfyTopic.trim()) {
    ElMessage.warning('Please enter a topic');
    return;
  }
  if (type === 'email') {
    if (!notificationChannelForm.emailHost.trim()) {
      ElMessage.warning('Please enter an SMTP host');
      return;
    }
    if (!notificationChannelForm.emailFrom.trim() || !notificationChannelForm.emailTo.trim()) {
      ElMessage.warning('Please enter From and To addresses');
      return;
    }
  }

  const payload = {
    name: notificationChannelForm.name.trim(),
    channel_type: notificationChannelForm.channel_type,
    enabled: notificationChannelForm.enabled,
    config: buildChannelConfig(),
  };

  notificationChannelsSaving.value = true;
  try {
    if (notificationChannelForm.id) {
      await api.updateNotificationChannel(notificationChannelForm.id, payload);
      ElMessage.success('Channel updated successfully');
    } else {
      await api.createNotificationChannel(payload);
      ElMessage.success('Channel created successfully');
    }
    notificationChannelDialogVisible.value = false;
    fetchNotificationChannels();
  } catch (error: any) {
    ElMessage.error(error.response?.data?.error || 'Failed to save channel');
  } finally {
    notificationChannelsSaving.value = false;
  }
}

async function toggleChannelEnabled(channel: any) {
  notificationChannelsSaving.value = true;
  try {
    await api.updateNotificationChannel(channel.id, { enabled: channel.enabled });
    ElMessage.success(`Channel ${channel.enabled ? 'enabled' : 'disabled'}`);
    fetchNotificationChannels();
  } catch (error: any) {
    // Revert the optimistic switch toggle on failure
    channel.enabled = !channel.enabled;
    ElMessage.error(error.response?.data?.error || 'Failed to update channel');
  } finally {
    notificationChannelsSaving.value = false;
  }
}

async function testChannel(channel: any) {
  try {
    const response = await api.testNotificationChannel(channel.id);
    ElMessage.success(response.data?.message || 'Test message sent successfully');
  } catch (error: any) {
    ElMessage.error(error.response?.data?.error || 'Failed to send test message');
  }
}

const testAlertSending = ref(false);
async function sendTestAlert() {
  testAlertSending.value = true;
  try {
    const response = await api.sendTestAlert();
    const results = response.data?.results || [];
    const msg = response.data?.message || 'Test alert sent.';
    if (results.length === 0) {
      ElMessage.warning(msg);
    } else if (results.every((r: any) => r.ok)) {
      ElMessage.success(msg);
    } else {
      ElMessage.warning(msg);
    }
  } catch (error: any) {
    ElMessage.error(error.response?.data?.error || 'Failed to send test alert');
  } finally {
    testAlertSending.value = false;
  }
}

async function deleteChannelConfirm(channel: any) {
  try {
    await ElMessageBox.confirm(
      `Are you sure you want to delete the channel "${channel.name}"?`,
      'Confirm Delete',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    );

    await api.deleteNotificationChannel(channel.id);
    ElMessage.success('Channel deleted successfully');
    fetchNotificationChannels();
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete channel');
    }
  }
}

// Notification Preferences Management Functions
async function fetchNotificationSettings() {
  notificationSettingsLoading.value = true;
  try {
    const response = await api.getNotificationSettings();
    const data = response.data || {};
    notificationSettingsForm.alertsEnabled = data.notify_alerts_enabled === 'true';
    notificationSettingsForm.alertsMinSeverity = data.notify_alerts_min_severity || 'medium';
    notificationSettingsForm.vulnEnabled = data.notify_vuln_enabled === 'true';
    notificationSettingsForm.vulnMinSeverity = data.notify_vuln_min_severity || 'high';
    notificationSettingsForm.ingestionEnabled = data.notify_ingestion_enabled === 'true';
    notificationSettingsForm.ingestionStallMinutes = parseInt(data.notify_ingestion_stall_minutes) || 15;
  } catch (error) {
    ElMessage.error('Failed to fetch notification preferences');
  } finally {
    notificationSettingsLoading.value = false;
  }
}

async function saveNotificationSettings() {
  notificationSettingsSaving.value = true;
  try {
    await api.updateNotificationSettings({
      notify_alerts_enabled: notificationSettingsForm.alertsEnabled ? 'true' : 'false',
      notify_alerts_min_severity: notificationSettingsForm.alertsMinSeverity,
      notify_vuln_enabled: notificationSettingsForm.vulnEnabled ? 'true' : 'false',
      notify_vuln_min_severity: notificationSettingsForm.vulnMinSeverity,
      notify_ingestion_enabled: notificationSettingsForm.ingestionEnabled ? 'true' : 'false',
      notify_ingestion_stall_minutes: notificationSettingsForm.ingestionStallMinutes.toString(),
    });
    ElMessage.success('Notification preferences saved successfully');
  } catch (error: any) {
    ElMessage.error(error.response?.data?.error || 'Failed to save notification preferences');
  } finally {
    notificationSettingsSaving.value = false;
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
