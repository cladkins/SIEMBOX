<template>
  <div class="onboarding">
    <el-card>
      <template #header>
        <div class="card-header">
          <div>
            <span>Getting Started</span>
            <div class="subtitle">
              A quick guided setup. Each step shows live status and links to the right page — do them in any
              order. SIEMBox ships empty and unopinionated, so this is the fastest path to a working SIEM.
            </div>
          </div>
          <el-button size="small" :loading="loading" @click="refresh">
            <el-icon><Refresh /></el-icon> Refresh
          </el-button>
        </div>
      </template>

      <el-progress
        :percentage="percent"
        :status="percent === 100 ? 'success' : undefined"
        :stroke-width="14"
        style="margin-bottom: 20px"
      />

      <el-steps direction="vertical" :space="140" v-loading="loading">
        <!-- 1. Secure account -->
        <el-step :status="steps.account ? 'success' : 'process'">
          <template #title>
            Secure your account
            <el-tag v-if="mfaEnabled" type="success" size="small" effect="light">MFA on</el-tag>
          </template>
          <template #description>
            <div class="step-body">
              <p>Change the default <code>admin</code> password and turn on two-factor authentication.</p>
              <el-form :model="pw" inline @submit.prevent>
                <el-form-item>
                  <el-input v-model="pw.current" type="password" placeholder="Current password" show-password style="width: 180px" />
                </el-form-item>
                <el-form-item>
                  <el-input v-model="pw.next" type="password" placeholder="New password (8+)" show-password style="width: 180px" />
                </el-form-item>
                <el-form-item>
                  <el-button :loading="pwSaving" :disabled="!pw.current || pw.next.length < 8" @click="changePassword">
                    Update password
                  </el-button>
                </el-form-item>
              </el-form>
              <el-button size="small" @click="go('/settings/account')">
                {{ mfaEnabled ? 'MFA enabled — manage in Settings' : 'Enable MFA in Settings → Account' }} →
              </el-button>
            </div>
          </template>
        </el-step>

        <!-- 2. Log ingestion -->
        <el-step :status="steps.ingestion ? 'success' : 'process'">
          <template #title>
            Set up log ingestion
            <el-tag v-if="steps.ingestion" type="success" size="small" effect="light">{{ shipperCount }} shipper(s)</el-tag>
          </template>
          <template #description>
            <div class="step-body">
              <p>
                Point devices at the syslog listener (UDP/TCP <code>514</code>), or install the universal
                <strong>log shipper</strong> for files, Docker logs, and journald (it registers with a key).
              </p>
              <el-button size="small" @click="go('/shippers')">Log Shippers →</el-button>
            </div>
          </template>
        </el-step>

        <!-- 3. Content packs -->
        <el-step :status="steps.content ? 'success' : 'process'">
          <template #title>
            Install parsers &amp; detections
            <el-tag v-if="steps.content" type="success" size="small" effect="light">{{ parserCount }} parsers · {{ ruleCount }} rules</el-tag>
          </template>
          <template #description>
            <div class="step-body">
              <p>Install a one-click <strong>Content Pack</strong> for your stack, or browse the full catalog.</p>
              <el-button size="small" @click="go('/content-packs')">Content Packs →</el-button>
              <el-button size="small" @click="go('/rules')">Detection Rules →</el-button>
            </div>
          </template>
        </el-step>

        <!-- 4. API keys -->
        <el-step :status="steps.ai ? 'success' : 'wait'">
          <template #title>
            Add API keys (optional)
            <el-tag v-if="steps.ai" type="success" size="small" effect="light">AI configured</el-tag>
          </template>
          <template #description>
            <div class="step-body">
              <p>Add an AI provider key to unlock <em>Generate with AI</em> and the AI Security Analyst. Optional.</p>
              <el-button v-if="authStore.isAdmin" size="small" @click="go('/settings/ai')">Settings → AI Builder →</el-button>
              <el-text v-else size="small" type="info">An administrator can add a key in Settings → AI Builder.</el-text>
            </div>
          </template>
        </el-step>

        <!-- 5. Notifications -->
        <el-step :status="steps.notifications ? 'success' : 'process'">
          <template #title>
            Notifications &amp; test alert
            <el-tag v-if="steps.notifications" type="success" size="small" effect="light">{{ channelCount }} channel(s)</el-tag>
          </template>
          <template #description>
            <div class="step-body">
              <p>Add an Email / Slack / ntfy channel so alerts reach you, then send a test alert to confirm.</p>
              <el-button v-if="authStore.isAdmin" size="small" @click="go('/settings/notifications')">Settings → Notifications →</el-button>
              <el-text v-else size="small" type="info">An administrator can set up channels in Settings → Notifications.</el-text>
            </div>
          </template>
        </el-step>

        <!-- 6. Digital Risk (optional) -->
        <el-step :status="steps.digitalRisk ? 'success' : 'wait'">
          <template #title>
            Digital Risk monitoring (optional)
            <el-tag v-if="digitalRiskTag" :type="steps.digitalRisk ? 'success' : 'info'" size="small" effect="light">
              {{ digitalRiskTag }}
            </el-tag>
          </template>
          <template #description>
            <div class="step-body">
              <p>
                Get alerted when your organization's email accounts turn up in a data breach (via Have I Been
                Pwned), and list the domains and brand names to watch. Optional.
              </p>
              <!-- The settings page's banner, when breach checks can't run for what is watched. -->
              <p v-if="digitalRiskProblem">
                <el-text size="small" :type="authStore.isAdmin ? (digitalRiskProblem.type === 'error' ? 'danger' : 'warning') : 'info'">
                  {{ digitalRiskProblem.title }}
                </el-text>
              </p>
              <DigitalRiskQuickSetup v-if="authStore.isAdmin" :status="exposureStatus" @changed="refreshDigitalRisk" />
              <el-text v-else size="small" type="info">
                An administrator can set up Digital Risk monitoring in Settings → Digital Risk.
              </el-text>
            </div>
          </template>
        </el-step>
      </el-steps>

      <div class="finish-row">
        <el-button type="primary" @click="finish">
          {{ percent === 100 ? 'All set — finish' : 'Dismiss for now' }}
        </el-button>
        <span class="finish-hint">You can reopen this any time from the sidebar.</span>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { api } from '@/services/api';
import exposureService, { type ExposureStatus, type MonitoredIdentity } from '@/services/exposureService';
import { breachChecksReady, describeExposureStatus, domainMonitorState, pluralize } from '@/utils/exposure';
import { ElMessage } from 'element-plus';
import { Refresh } from '@element-plus/icons-vue';
import { useAuthStore } from '@/stores/auth';
import DigitalRiskQuickSetup from '@/components/DigitalRiskQuickSetup.vue';

const router = useRouter();
const authStore = useAuthStore();
const loading = ref(false);

const mfaEnabled = ref(false);
const shipperCount = ref(0);
const parserCount = ref(0);
const ruleCount = ref(0);
const channelCount = ref(0);
const aiConfigured = ref(false);
// GET /exposure/status and GET /exposure/identities, both readable by every role.
const exposureStatus = ref<ExposureStatus | null>(null);
const identityRows = ref<MonitoredIdentity[] | null>(null);

const pw = reactive({ current: '', next: '' });
const pwSaving = ref(false);
const passwordChanged = ref(false);

// What Digital Risk actually watches: enabled identities while breach checks
// can run, and enabled domains while domain monitoring is on. Anything else is
// only saved.
const digitalRiskCounts = computed(() => {
  const s = exposureStatus.value;
  const identities = s?.counts.identities_enabled ?? 0;
  const domains = s?.counts.domains_enabled ?? 0;
  return {
    identities,
    identitiesWatched: s && breachChecksReady(s) ? identities : 0,
    domains,
    domainsWatched: s && domainMonitorState(s) === 'on' ? domains : 0,
  };
});

const steps = computed(() => ({
  // "account" is satisfied by enabling MFA or changing the password this session.
  account: mfaEnabled.value || passwordChanged.value,
  ingestion: shipperCount.value > 0,
  content: parserCount.value > 0 || ruleCount.value > 0,
  ai: aiConfigured.value,
  notifications: channelCount.value > 0,
  // Done once something is being watched.
  digitalRisk: digitalRiskCounts.value.identitiesWatched + digitalRiskCounts.value.domainsWatched > 0,
}));

const digitalRiskTag = computed(() => {
  const { identities, identitiesWatched, domains, domainsWatched } = digitalRiskCounts.value;
  const parts: string[] = [];
  if (domains > 0) parts.push(`${pluralize(domains, 'domain')}${domainsWatched > 0 ? '' : ' saved'}`);
  if (identities > 0) parts.push(`${pluralize(identities, 'identity', 'identities')}${identitiesWatched > 0 ? '' : ' saved'}`);
  return parts.join(' · ');
});

// Identities are monitored, but the settings banner reports a problem: breach
// checks can't run (no key, provider disabled, checks off, ...) or an identity's
// last check failed (counted from the list, which outlives the last run).
const digitalRiskProblem = computed(() => {
  if (!exposureStatus.value || digitalRiskCounts.value.identities === 0) return null;
  const banner = describeExposureStatus(exposureStatus.value, {
    failingIdentities: identityRows.value?.filter((i) => i.enabled && i.last_status === 'error').length,
  });
  return banner.type === 'success' ? null : banner;
});

// AI and Digital Risk are optional, so they don't count against the required percentage.
const percent = computed(() => {
  const required = ['account', 'ingestion', 'content', 'notifications'] as const;
  const done = required.filter((k) => steps.value[k]).length;
  return Math.round((done / required.length) * 100);
});

function go(path: string) {
  router.push(path);
}

async function refresh() {
  loading.value = true;
  try {
    // Admin-only endpoints are only requested for admins: anyone else gets a
    // 403, which the API client turns into a "no permission" popup.
    const [profile, shippers, parsers, rules, channels, ai, exposure, identities] = await Promise.allSettled([
      api.getProfile(),
      api.getShippers(),
      api.getParsers(),
      api.getRules(),
      api.getNotificationChannels(),
      authStore.isAdmin ? api.getAiSettings() : Promise.resolve(null),
      exposureService.getStatus(),
      exposureService.listIdentities(),
    ]);
    if (profile.status === 'fulfilled') mfaEnabled.value = !!profile.value.data.mfa_enabled;
    if (shippers.status === 'fulfilled') shipperCount.value = (shippers.value.data || []).length;
    if (parsers.status === 'fulfilled') parserCount.value = (parsers.value.data || []).length;
    if (rules.status === 'fulfilled') ruleCount.value = (rules.value.data || []).length;
    if (channels.status === 'fulfilled') channelCount.value = (channels.value.data || []).length;
    if (ai.status === 'fulfilled' && ai.value) {
      const d = ai.value.data || {};
      aiConfigured.value = !!(d.configured || d.api_key_set || d.apiKeySet || d.has_key);
    }
    if (exposure.status === 'fulfilled') exposureStatus.value = exposure.value;
    if (identities.status === 'fulfilled') identityRows.value = identities.value;
  } finally {
    loading.value = false;
  }
}

// After the inline Digital Risk setup adds something: re-read just its state.
async function refreshDigitalRisk() {
  // On failure the API client has shown the error and the step keeps its last state.
  const [status, identities] = await Promise.allSettled([
    exposureService.getStatus(),
    exposureService.listIdentities(),
  ]);
  if (status.status === 'fulfilled') exposureStatus.value = status.value;
  if (identities.status === 'fulfilled') identityRows.value = identities.value;
}

async function changePassword() {
  if (!pw.current || pw.next.length < 8) return;
  pwSaving.value = true;
  try {
    await api.changeOwnPassword(pw.current, pw.next);
    passwordChanged.value = true;
    pw.current = '';
    pw.next = '';
    ElMessage.success('Password updated. Use it next time you log in.');
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Could not change password');
  } finally {
    pwSaving.value = false;
  }
}

function finish() {
  localStorage.setItem('onboarding_dismissed', '1');
  ElMessage.success('Setup checklist dismissed');
  router.push('/');
}

onMounted(refresh);
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}
.subtitle {
  font-size: 13px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
  max-width: 760px;
}
.step-body {
  padding: 4px 0 8px;
}
.step-body p {
  margin: 0 0 8px;
  color: var(--el-text-color-regular);
  font-size: 13px;
}
.finish-row {
  margin-top: 16px;
  display: flex;
  align-items: center;
  gap: 12px;
}
.finish-hint {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
</style>
