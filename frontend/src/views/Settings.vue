<template>
  <div class="settings">
    <el-row :gutter="20">
      <el-col :span="16">
        <el-card>
          <template #header>
            <span>Log Retention Settings</span>
          </template>

          <el-form :model="retentionForm" label-width="200px" v-loading="loading">
            <el-form-item label="Auto Cleanup">
              <el-switch v-model="retentionForm.auto_cleanup_enabled" />
              <el-text size="small" type="info" style="margin-left: 10px">
                Automatically clean up old logs based on retention periods
              </el-text>
            </el-form-item>

            <el-divider />

            <el-form-item label="Raw Logs Retention">
              <el-input-number
                v-model="retentionForm.raw_logs_days"
                :min="1"
                :max="365"
                style="width: 150px"
              />
              <el-text size="small" type="info" style="margin-left: 10px">days</el-text>
              <br />
              <el-text size="small" type="info">
                Delete raw syslog messages older than this many days
              </el-text>
            </el-form-item>

            <el-form-item label="Parsed Logs Retention">
              <el-input-number
                v-model="retentionForm.parsed_logs_days"
                :min="1"
                :max="730"
                style="width: 150px"
              />
              <el-text size="small" type="info" style="margin-left: 10px">days</el-text>
              <br />
              <el-text size="small" type="info">
                Delete parsed logs older than this many days
              </el-text>
            </el-form-item>

            <el-form-item label="Alerts Retention">
              <el-input-number
                v-model="retentionForm.alerts_days"
                :min="1"
                :max="3650"
                style="width: 150px"
              />
              <el-text size="small" type="info" style="margin-left: 10px">days</el-text>
              <br />
              <el-text size="small" type="info">
                Delete closed alerts older than this many days
              </el-text>
            </el-form-item>

            <el-form-item>
              <el-button type="primary" @click="saveRetentionSettings" :loading="saving">
                <el-icon><Check /></el-icon> Save Settings
              </el-button>
              <el-button @click="fetchRetentionSettings">Reset</el-button>
            </el-form-item>
          </el-form>
        </el-card>

        <el-card style="margin-top: 20px">
          <template #header>
            <span>Security — Two-Factor Authentication (MFA)</span>
          </template>

          <div v-loading="mfaLoading">
            <template v-if="mfaEnabled">
              <el-alert
                type="success"
                :closable="false"
                show-icon
                title="MFA is enabled on your account"
                style="margin-bottom: 12px"
              />
              <p class="mfa-note">
                You'll be asked for a 6-digit code from your authenticator app (or a recovery code) at login.
              </p>
              <el-button type="danger" plain @click="openMfaDisable">Disable MFA</el-button>
            </template>

            <template v-else>
              <p class="mfa-note">
                Protect your account with a time-based one-time code (TOTP) from an app like Google
                Authenticator, Authy, or 1Password. Optional, per-account, and recommended for admins.
              </p>
              <el-button type="primary" @click="startMfaSetup" :loading="mfaSetupLoading">
                <el-icon><Key /></el-icon> Enable MFA
              </el-button>
            </template>
          </div>
        </el-card>

        <!-- MFA enrollment dialog -->
        <el-dialog v-model="mfaSetupVisible" title="Enable two-factor authentication" width="520px">
          <ol class="mfa-steps">
            <li>
              Scan this in your authenticator app, or enter the key manually:
              <div class="mfa-qr">
                <qrcode-vue v-if="mfaOtpauthUrl" :value="mfaOtpauthUrl" :size="180" level="M" render-as="svg" />
              </div>
              <div class="mfa-secret-box">
                <div class="mfa-secret">{{ mfaSecret }}</div>
                <el-button size="small" @click="copySecret">Copy key</el-button>
              </div>
              <div class="mfa-uri">{{ mfaOtpauthUrl }}</div>
            </li>
            <li>
              Enter the 6-digit code it shows:
              <el-input
                v-model="mfaCode"
                placeholder="123456"
                style="max-width: 200px; margin-top: 6px"
                @keyup.enter="confirmMfaEnable"
              />
            </li>
          </ol>
          <template #footer>
            <el-button @click="mfaSetupVisible = false">Cancel</el-button>
            <el-button type="primary" :loading="mfaEnabling" :disabled="!mfaCode.trim()" @click="confirmMfaEnable">
              Verify &amp; enable
            </el-button>
          </template>
        </el-dialog>

        <!-- Recovery codes (shown once) -->
        <el-dialog v-model="mfaRecoveryVisible" title="Save your recovery codes" width="520px" :close-on-click-modal="false">
          <el-alert
            type="warning"
            :closable="false"
            show-icon
            title="These are shown only once"
            description="Store them somewhere safe. Each code works once if you lose your authenticator."
            style="margin-bottom: 12px"
          />
          <div class="recovery-grid">
            <code v-for="(c, i) in mfaRecoveryCodes" :key="i">{{ c }}</code>
          </div>
          <template #footer>
            <el-button @click="copyRecovery">Copy all</el-button>
            <el-button type="primary" @click="mfaRecoveryVisible = false">I've saved them</el-button>
          </template>
        </el-dialog>

        <!-- Disable MFA dialog -->
        <el-dialog v-model="mfaDisableVisible" title="Disable MFA" width="460px">
          <p class="mfa-note">Enter a current code (or a recovery code) to turn MFA off.</p>
          <el-input v-model="mfaDisableCode" placeholder="6-digit or recovery code" @keyup.enter="confirmMfaDisable" />
          <template #footer>
            <el-button @click="mfaDisableVisible = false">Cancel</el-button>
            <el-button type="danger" :loading="mfaDisabling" :disabled="!mfaDisableCode.trim()" @click="confirmMfaDisable">
              Disable
            </el-button>
          </template>
        </el-dialog>

        <el-card style="margin-top: 20px">
          <template #header>
            <span>AI Builder</span>
          </template>

          <el-form :model="aiForm" label-width="200px" v-loading="aiLoading">
            <el-form-item label="Provider">
              <el-select v-model="aiForm.provider" style="width: 220px">
                <el-option label="Anthropic (Claude)" value="anthropic" />
                <el-option label="OpenAI" value="openai" />
                <el-option label="Ollama (local)" value="ollama" />
              </el-select>
            </el-form-item>

            <el-form-item label="Model">
              <el-input v-model="aiForm.model" style="width: 320px" :placeholder="aiModelPlaceholder" />
            </el-form-item>

            <el-form-item v-if="aiForm.provider !== 'anthropic'" label="Base URL">
              <el-input
                v-model="aiForm.baseUrl"
                style="width: 320px"
                :placeholder="aiForm.provider === 'ollama' ? 'http://localhost:11434' : 'https://api.openai.com/v1'"
              />
            </el-form-item>

            <el-form-item v-if="aiForm.provider !== 'ollama'" label="API Key">
              <el-input
                v-model="aiForm.apiKey"
                type="password"
                show-password
                style="width: 320px"
                :placeholder="aiKeyPlaceholder"
              />
              <el-text size="small" :type="aiConfigured ? 'success' : 'warning'" style="margin-left: 10px">
                {{ aiKeyStatus }}
              </el-text>
            </el-form-item>

            <el-form-item>
              <el-button type="primary" @click="saveAiSettings" :loading="aiSaving">
                <el-icon><Check /></el-icon> Save AI Settings
              </el-button>
            </el-form-item>
            <el-text size="small" type="info">
              Powers "Generate with AI" on the Parsers and Detection Rules pages. The API key is stored
              encrypted at rest; you can instead set ANTHROPIC_API_KEY / OPENAI_API_KEY as environment variables.
              Leave the key blank to keep the existing one.
            </el-text>
          </el-form>
        </el-card>

        <el-card style="margin-top: 20px">
          <template #header>
            <span>AI Analyst (chat)</span>
          </template>

          <el-form :model="chatForm" label-width="200px" v-loading="chatLoading">
            <el-form-item label="Provider">
              <el-select v-model="chatForm.provider" style="width: 260px">
                <el-option label="Inherit main AI config" value="" />
                <el-option label="Anthropic (Claude)" value="anthropic" />
                <el-option label="OpenAI" value="openai" />
                <el-option label="Ollama (local)" value="ollama" />
              </el-select>
            </el-form-item>

            <template v-if="chatForm.provider">
              <el-form-item label="Model">
                <el-input v-model="chatForm.model" style="width: 320px" :placeholder="chatModelPlaceholder" />
              </el-form-item>

              <el-form-item v-if="chatForm.provider !== 'anthropic'" label="Base URL">
                <el-input
                  v-model="chatForm.baseUrl"
                  style="width: 320px"
                  :placeholder="chatForm.provider === 'ollama' ? 'http://localhost:11434' : 'https://api.openai.com/v1'"
                />
              </el-form-item>

              <el-form-item v-if="chatForm.provider !== 'ollama'" label="API Key">
                <el-input
                  v-model="chatForm.apiKey"
                  type="password"
                  show-password
                  style="width: 320px"
                  :placeholder="chatKeyPlaceholder"
                />
                <el-text size="small" :type="chatConfigured ? 'success' : 'warning'" style="margin-left: 10px">
                  {{ chatKeyStatus }}
                </el-text>
              </el-form-item>
            </template>

            <el-form-item>
              <el-button type="primary" @click="saveChatSettings" :loading="chatSaving">
                <el-icon><Check /></el-icon> Save Analyst Settings
              </el-button>
            </el-form-item>
            <el-text size="small" type="info">
              Powers the conversational AI Analyst. Leave the provider on "Inherit main AI config" to reuse the
              AI Builder model above, or choose a separate model (e.g. a larger one, or a local Ollama instruct
              model like Qwen2.5 / Llama 3.1) just for the analyst — the tool loop works best with a strong
              instruction-following model. Key stored encrypted at rest; leave blank to keep the existing one.
              <span v-if="chatInheritsFrom === 'main'"> Currently inheriting the main AI config.</span>
            </el-text>
          </el-form>
        </el-card>

        <el-card style="margin-top: 20px">
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

        <el-card style="margin-top: 20px">
          <template #header>
            <span>Auto-Discovery Settings</span>
          </template>

          <el-alert type="info" :closable="false" style="margin-bottom: 20px">
            Automatically discover assets from incoming logs. The system scans the raw_logs table periodically.
          </el-alert>

          <el-form :model="autoDiscoveryForm" label-width="250px" v-loading="autoDiscoveryLoading">
            <el-form-item label="Enable Auto-Discovery">
              <el-switch
                v-model="autoDiscoveryForm.auto_discovery_enabled"
                :disabled="authStore.user?.role !== 'admin' || autoDiscoverySaving"
                @change="saveAutoDiscoverySetting('auto_discovery_enabled', autoDiscoveryForm.auto_discovery_enabled ? 'true' : 'false')"
              />
            </el-form-item>

            <el-form-item label="Discovery Interval (minutes)">
              <el-input-number
                v-model="autoDiscoveryForm.auto_discovery_interval_minutes"
                :min="5"
                :max="1440"
                :step="5"
                :disabled="authStore.user?.role !== 'admin' || autoDiscoverySaving"
                style="width: 200px"
              />
              <el-button
                type="primary"
                :loading="autoDiscoverySaving"
                :disabled="authStore.user?.role !== 'admin'"
                @click="saveAutoDiscoverySetting('auto_discovery_interval_minutes', autoDiscoveryForm.auto_discovery_interval_minutes.toString())"
                style="margin-left: 10px"
              >
                Save
              </el-button>
              <br />
              <el-text size="small" type="info">
                How often to scan logs for new assets (5-1440 minutes). Default: 360 (6 hours)
              </el-text>
            </el-form-item>

            <el-form-item label="Stale Asset Threshold (days)">
              <el-input-number
                v-model="autoDiscoveryForm.stale_asset_threshold_days"
                :min="1"
                :max="365"
                :disabled="authStore.user?.role !== 'admin' || autoDiscoverySaving"
                style="width: 200px"
              />
              <el-button
                type="primary"
                :loading="autoDiscoverySaving"
                :disabled="authStore.user?.role !== 'admin'"
                @click="saveAutoDiscoverySetting('stale_asset_threshold_days', autoDiscoveryForm.stale_asset_threshold_days.toString())"
                style="margin-left: 10px"
              >
                Save
              </el-button>
              <br />
              <el-text size="small" type="info">
                Days before marking an asset as offline if not seen in logs
              </el-text>
            </el-form-item>
          </el-form>

          <el-alert v-if="authStore.user?.role !== 'admin'" type="warning" :closable="false" style="margin-top: 20px">
            You do not have permission to modify settings. Contact an administrator.
          </el-alert>
        </el-card>

        <el-card style="margin-top: 20px">
          <template #header>
            <span>Manual Cleanup</span>
          </template>

          <el-alert type="warning" :closable="false" style="margin-bottom: 20px">
            <strong>Warning:</strong> Manual cleanup will immediately delete old logs based on the retention periods above.
            This action cannot be undone.
          </el-alert>

          <el-button type="danger" @click="runManualCleanup" :loading="cleaning">
            <el-icon><Delete /></el-icon> Run Cleanup Now
          </el-button>
        </el-card>

        <el-card style="margin-top: 20px">
          <template #header>
            <div class="card-header">
              <span>IP Whitelist Management</span>
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

        <el-card style="margin-top: 20px">
          <template #header>
            <div class="card-header">
              <span>Notifications</span>
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

            <el-form-item label="Alerts Min Severity">
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

            <el-form-item label="Vulnerabilities Min Severity">
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

            <el-form-item label="Ingestion Health">
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
      </el-col>

      <el-col :span="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>System Information</span>
              <el-button size="small" @click="fetchStatistics" :icon="Refresh" circle />
            </div>
          </template>

          <div v-loading="statsLoading">
            <el-descriptions :column="1" border v-if="statistics || syslogStatus">
              <!-- Syslog Status Section -->
              <template v-if="syslogStatus">
                <el-descriptions-item label="Syslog Receiver">
                  <el-tag
                    :type="syslogStatus.status === 'healthy' ? 'success' : syslogStatus.status === 'warning' ? 'warning' : 'danger'"
                    size="small"
                  >
                    {{ syslogStatus.status }}
                  </el-tag>
                  <br />
                  <el-text size="small" type="info">{{ syslogStatus.status_message }}</el-text>
                  <br />
                  <el-text size="small" type="info">Port {{ syslogStatus.actual_listening_port }}</el-text>
                </el-descriptions-item>

                <el-descriptions-item label="Last Log Received">
                  <strong>{{ syslogStatus.last_log_received ? formatDate(syslogStatus.last_log_received) : 'Never' }}</strong>
                  <br />
                  <el-text size="small" type="info">
                    {{ formatNumber(syslogStatus.logs_received_last_5min) }} logs in last 5 min
                  </el-text>
                </el-descriptions-item>
              </template>

              <!-- Port Mismatch Warning -->
              <el-descriptions-item v-if="syslogStatus && !syslogStatus.ports_match">
                <el-alert type="warning" :closable="false" show-icon>
                  <template #title>
                    <el-text size="small">
                      Configuration port ({{ syslogStatus.configured_port }}) doesn't match listening port ({{ syslogStatus.actual_listening_port }})
                    </el-text>
                  </template>
                </el-alert>
              </el-descriptions-item>

              <!-- Database Statistics Section -->
              <template v-if="statistics">
                <el-descriptions-item label="Raw Logs">
                  <strong>{{ formatNumber(statistics.total_raw_logs) }}</strong>
                  <br />
                  <el-text size="small" type="info">{{ statistics.raw_logs_size }}</el-text>
                </el-descriptions-item>

                <el-descriptions-item label="Parsed Logs">
                  <strong>{{ formatNumber(statistics.total_parsed_logs) }}</strong>
                  <br />
                  <el-text size="small" type="info">{{ statistics.parsed_logs_size }}</el-text>
                </el-descriptions-item>

                <el-descriptions-item label="Alerts">
                  <strong>{{ formatNumber(statistics.total_alerts) }}</strong>
                  <br />
                  <el-text size="small" type="info">{{ statistics.alerts_size }}</el-text>
                </el-descriptions-item>

                <el-descriptions-item label="Oldest Raw Log">
                  <el-text size="small">
                    {{ statistics.oldest_raw_log ? formatDate(statistics.oldest_raw_log) : 'N/A' }}
                  </el-text>
                </el-descriptions-item>

                <el-descriptions-item label="Oldest Parsed Log">
                  <el-text size="small">
                    {{ statistics.oldest_parsed_log ? formatDate(statistics.oldest_parsed_log) : 'N/A' }}
                  </el-text>
                </el-descriptions-item>

                <el-descriptions-item label="Oldest Alert">
                  <el-text size="small">
                    {{ statistics.oldest_alert ? formatDate(statistics.oldest_alert) : 'N/A' }}
                  </el-text>
                </el-descriptions-item>
              </template>
            </el-descriptions>

            <el-empty v-else description="No statistics available" />
          </div>
        </el-card>
      </el-col>
    </el-row>

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
import { ref, onMounted, reactive, computed } from 'vue';
import { api } from '@/services/api';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Check, Delete, Refresh, Plus, Edit, VideoPlay, Key } from '@element-plus/icons-vue';
import { format } from 'date-fns';
import QrcodeVue from 'qrcode.vue';
import { useAuthStore } from '@/stores/auth';
const authStore = useAuthStore();

// --- MFA (two-factor) ------------------------------------------------------
const mfaLoading = ref(false);
const mfaEnabled = ref(false);
const mfaSetupLoading = ref(false);
const mfaSetupVisible = ref(false);
const mfaSecret = ref('');
const mfaOtpauthUrl = ref('');
const mfaCode = ref('');
const mfaEnabling = ref(false);
const mfaRecoveryVisible = ref(false);
const mfaRecoveryCodes = ref<string[]>([]);
const mfaDisableVisible = ref(false);
const mfaDisableCode = ref('');
const mfaDisabling = ref(false);

async function loadMfaStatus() {
  mfaLoading.value = true;
  try {
    const { data } = await api.getProfile();
    mfaEnabled.value = !!data.mfa_enabled;
  } catch {
    /* non-fatal */
  } finally {
    mfaLoading.value = false;
  }
}

async function startMfaSetup() {
  mfaSetupLoading.value = true;
  try {
    const { data } = await api.mfaSetup();
    mfaSecret.value = data.secret;
    mfaOtpauthUrl.value = data.otpauthUrl;
    mfaCode.value = '';
    mfaSetupVisible.value = true;
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Could not start MFA setup');
  } finally {
    mfaSetupLoading.value = false;
  }
}

async function confirmMfaEnable() {
  if (!mfaCode.value.trim()) return;
  mfaEnabling.value = true;
  try {
    const { data } = await api.mfaEnable(mfaCode.value.trim());
    mfaRecoveryCodes.value = data.recoveryCodes || [];
    mfaSetupVisible.value = false;
    mfaRecoveryVisible.value = true;
    mfaEnabled.value = true;
    ElMessage.success('MFA enabled');
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Invalid code');
  } finally {
    mfaEnabling.value = false;
  }
}

function openMfaDisable() {
  mfaDisableCode.value = '';
  mfaDisableVisible.value = true;
}

async function confirmMfaDisable() {
  if (!mfaDisableCode.value.trim()) return;
  mfaDisabling.value = true;
  try {
    await api.mfaDisable(mfaDisableCode.value.trim());
    mfaEnabled.value = false;
    mfaDisableVisible.value = false;
    ElMessage.success('MFA disabled');
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Invalid code');
  } finally {
    mfaDisabling.value = false;
  }
}

async function copySecret() {
  try {
    await navigator.clipboard.writeText(mfaSecret.value);
    ElMessage.success('Key copied');
  } catch {
    ElMessage.warning('Copy failed');
  }
}

async function copyRecovery() {
  try {
    await navigator.clipboard.writeText(mfaRecoveryCodes.value.join('\n'));
    ElMessage.success('Recovery codes copied');
  } catch {
    ElMessage.warning('Copy failed');
  }
}

const loading = ref(false);
const saving = ref(false);
const cleaning = ref(false);
const statsLoading = ref(false);
const syslogLoading = ref(false);
const syslogSaving = ref(false);
const ipLoading = ref(false);
const ipWhitelistDialogVisible = ref(false);
const autoDiscoveryLoading = ref(false);
const autoDiscoverySaving = ref(false);

const retentionForm = reactive({
  raw_logs_days: 30,
  parsed_logs_days: 90,
  alerts_days: 365,
  auto_cleanup_enabled: true,
});

// AI builder settings
const aiLoading = ref(false);
const aiSaving = ref(false);
const aiConfigured = ref(false);
const aiKeySource = ref<'stored' | 'env' | 'none'>('none');
const aiForm = reactive({ provider: 'anthropic', model: '', baseUrl: '', apiKey: '' });

const aiModelPlaceholder = computed(() =>
  ({ anthropic: 'claude-sonnet-4-6', openai: 'gpt-4o', ollama: 'llama3.1' } as Record<string, string>)[aiForm.provider] || ''
);
const aiKeyPlaceholder = computed(() =>
  aiKeySource.value === 'stored' ? '•••••••• (saved — leave blank to keep)'
  : aiKeySource.value === 'env' ? 'set via environment variable'
  : 'paste your API key'
);
const aiKeyStatus = computed(() =>
  aiConfigured.value
    ? aiKeySource.value === 'env' ? 'Configured via environment variable' : 'Key configured'
    : 'No API key configured'
);

async function fetchAiSettings() {
  aiLoading.value = true;
  try {
    const { data } = await api.getAiSettings();
    aiForm.provider = data.provider || 'anthropic';
    aiForm.model = data.model || '';
    aiForm.baseUrl = data.baseUrl || '';
    aiForm.apiKey = '';
    aiConfigured.value = !!data.configured;
    aiKeySource.value = data.keySource || 'none';
  } catch (error) {
    // non-admins / not configured — leave defaults
  } finally {
    aiLoading.value = false;
  }
}

async function saveAiSettings() {
  aiSaving.value = true;
  try {
    const payload: any = { provider: aiForm.provider, model: aiForm.model, baseUrl: aiForm.baseUrl };
    if (aiForm.apiKey) payload.apiKey = aiForm.apiKey; // only send when changing
    await api.updateAiSettings(payload);
    ElMessage.success('AI settings saved');
    await fetchAiSettings();
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to save AI settings');
  } finally {
    aiSaving.value = false;
  }
}

// AI Analyst (chat) settings — a separate model config that may inherit the main one.
const chatLoading = ref(false);
const chatSaving = ref(false);
const chatConfigured = ref(false);
const chatKeySource = ref<'stored' | 'env' | 'none'>('none');
const chatInheritsFrom = ref<'chat' | 'main'>('main');
const chatForm = reactive({ provider: '', model: '', baseUrl: '', apiKey: '' });

const chatModelPlaceholder = computed(() =>
  ({ anthropic: 'claude-sonnet-4-6', openai: 'gpt-4o', ollama: 'llama3.1' } as Record<string, string>)[
    chatForm.provider
  ] || 'inherits main config'
);
const chatKeyPlaceholder = computed(() =>
  chatKeySource.value === 'stored'
    ? '•••••••• (saved — leave blank to keep)'
    : chatKeySource.value === 'env'
    ? 'set via environment variable'
    : 'paste your API key'
);
const chatKeyStatus = computed(() =>
  chatConfigured.value
    ? chatKeySource.value === 'env'
      ? 'Configured via environment variable'
      : 'Key configured'
    : 'No API key configured'
);

async function fetchChatSettings() {
  chatLoading.value = true;
  try {
    const { data } = await api.getChatAiSettings();
    chatInheritsFrom.value = data.inheritsFrom || 'main';
    const own = data.inheritsFrom === 'chat';
    chatForm.provider = own ? data.provider || '' : '';
    chatForm.model = own ? data.model || '' : '';
    chatForm.baseUrl = own ? data.baseUrl || '' : '';
    chatForm.apiKey = '';
    chatConfigured.value = !!data.configured;
    chatKeySource.value = data.keySource || 'none';
  } catch (error) {
    // non-admins / not configured — leave defaults
  } finally {
    chatLoading.value = false;
  }
}

async function saveChatSettings() {
  chatSaving.value = true;
  try {
    const payload: any = { provider: chatForm.provider };
    if (chatForm.provider) {
      payload.model = chatForm.model;
      payload.baseUrl = chatForm.baseUrl;
      if (chatForm.apiKey) payload.apiKey = chatForm.apiKey; // only send when changing
    }
    await api.updateChatAiSettings(payload);
    ElMessage.success('AI Analyst settings saved');
    await fetchChatSettings();
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to save analyst settings');
  } finally {
    chatSaving.value = false;
  }
}

const syslogForm = reactive({
  syslog_host: '',
  syslog_port: 514,
});

const autoDiscoveryForm = reactive({
  auto_discovery_enabled: true,
  auto_discovery_interval_minutes: 360,
  stale_asset_threshold_days: 30
});

const ipWhitelistForm = reactive({
  id: null as number | null,
  ip_address: '',
  description: '',
});

const statistics = ref<any>(null);
const syslogStatus = ref<any>(null);
const ipWhitelist = ref<any[]>([]);

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
  fetchRetentionSettings();
  fetchAiSettings();
  fetchChatSettings();
  fetchSyslogSettings();
  fetchAutoDiscoverySettings();
  fetchStatistics();
  fetchIpWhitelist();
  fetchNotificationChannels();
  fetchNotificationSettings();
  loadMfaStatus();
});

async function fetchRetentionSettings() {
  loading.value = true;
  try {
    const response = await api.getRetentionSettings();
    Object.assign(retentionForm, response.data);
  } catch (error) {
    ElMessage.error('Failed to fetch retention settings');
  } finally {
    loading.value = false;
  }
}

async function saveRetentionSettings() {
  saving.value = true;
  try {
    await api.updateRetentionSettings(retentionForm);
    ElMessage.success('Retention settings saved successfully');
  } catch (error) {
    ElMessage.error('Failed to save retention settings');
  } finally {
    saving.value = false;
  }
}

async function runManualCleanup() {
  try {
    await ElMessageBox.confirm(
      'This will permanently delete old logs based on your retention settings. Are you sure?',
      'Confirm Manual Cleanup',
      {
        confirmButtonText: 'Run Cleanup',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    );

    cleaning.value = true;
    const response = await api.runManualCleanup(retentionForm);
    const results = response.data.results;

    ElMessage.success({
      message: `Cleanup completed: ${results.raw_logs_deleted} raw logs, ${results.parsed_logs_deleted} parsed logs, ${results.alerts_deleted} alerts deleted`,
      duration: 5000,
    });

    // Refresh statistics after cleanup
    fetchStatistics();
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to run cleanup');
    }
  } finally {
    cleaning.value = false;
  }
}

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
    // Refresh status after saving
    await fetchSyslogStatus();
  } catch (error) {
    ElMessage.error('Failed to save syslog settings');
  } finally {
    syslogSaving.value = false;
  }
}

async function fetchSyslogStatus() {
  try {
    const response = await api.getSyslogStatus();
    syslogStatus.value = response.data;
  } catch (error) {
    console.error('Failed to fetch syslog status', error);
  }
}

async function fetchAutoDiscoverySettings() {
  autoDiscoveryLoading.value = true;
  try {
    const response = await api.get('/settings');
    const settings = response.data;

    settings.forEach((setting: any) => {
      if (setting.setting_key === 'auto_discovery_enabled') {
        autoDiscoveryForm.auto_discovery_enabled = setting.setting_value === 'true';
      } else if (setting.setting_key === 'auto_discovery_interval_minutes') {
        autoDiscoveryForm.auto_discovery_interval_minutes = parseInt(setting.setting_value);
      } else if (setting.setting_key === 'stale_asset_threshold_days') {
        autoDiscoveryForm.stale_asset_threshold_days = parseInt(setting.setting_value);
      }
    });
  } catch (error) {
    console.error('Failed to fetch auto-discovery settings', error);
  } finally {
    autoDiscoveryLoading.value = false;
  }
}

async function saveAutoDiscoverySetting(key: string, value: string) {
  if (authStore.user?.role !== 'admin') {
    ElMessage.warning('Only administrators can modify settings');
    return;
  }

  autoDiscoverySaving.value = true;
  try {
    await api.put(`/settings/${key}`, { setting_value: value });
    ElMessage.success('Setting updated successfully');

    if (key === 'auto_discovery_interval_minutes') {
      ElMessage.info('Auto-discovery will use the new interval on the next run');
    }
  } catch (error: any) {
    ElMessage.error(error.response?.data?.error || 'Failed to update setting');
    console.error(error);
  } finally {
    autoDiscoverySaving.value = false;
  }
}

async function fetchStatistics() {
  statsLoading.value = true;
  try {
    const response = await api.getRetentionStatistics();
    statistics.value = response.data;
    // Also refresh syslog status when refreshing statistics
    await fetchSyslogStatus();
  } catch (error) {
    ElMessage.error('Failed to fetch statistics');
  } finally {
    statsLoading.value = false;
  }
}

const formatNumber = (num: number): string => {
  return new Intl.NumberFormat().format(num);
};

const formatDate = (date: string): string => {
  return format(new Date(date), 'MMM dd, yyyy HH:mm');
};

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
.settings {
  padding: 0;
}

.mfa-note {
  font-size: 13px;
  color: var(--el-text-color-secondary);
  margin: 0 0 12px;
}
.mfa-steps {
  margin: 0;
  padding-left: 18px;
}
.mfa-steps li {
  margin-bottom: 14px;
}
.mfa-qr {
  display: flex;
  justify-content: center;
  margin: 12px 0;
}
/* White quiet-zone so the code scans even in dark mode. */
.mfa-qr :deep(svg) {
  background: #fff;
  padding: 10px;
  border-radius: 6px;
}
.mfa-secret-box {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 6px 0;
}
.mfa-secret {
  font-family: var(--el-font-family-mono, monospace);
  font-size: 16px;
  letter-spacing: 2px;
  background: var(--el-fill-color-light);
  padding: 6px 10px;
  border-radius: 4px;
  word-break: break-all;
}
.mfa-uri {
  font-size: 11px;
  color: var(--el-text-color-secondary);
  word-break: break-all;
}
.recovery-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
}
.recovery-grid code {
  font-family: var(--el-font-family-mono, monospace);
  font-size: 14px;
  background: var(--el-fill-color-light);
  padding: 6px 10px;
  border-radius: 4px;
  text-align: center;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
