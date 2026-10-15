<template>
  <!-- Is monitoring working? A quiet page must mean "nothing found", not "nothing checked". -->
  <el-card class="dr-monitoring">
    <template #header>
      <span>
        Monitoring
        <HelpTip text="Whether the breach checks and the domain checks can run, and what they last did. Run state resets when the backend restarts; each identity's and domain's last check is kept." />
      </span>
    </template>

    <el-row :gutter="24">
      <!-- Breach checks -->
      <el-col :xs="24" :md="12" class="monitor-col">
        <h4 class="col-title">Breach checks (Have I Been Pwned)</h4>
        <el-alert
          v-if="identitiesError"
          type="error"
          show-icon
          :closable="false"
          title="Couldn't load identities"
          class="col-alert"
        >
          <p class="alert-line">{{ identitiesError }}</p>
          <el-button link type="primary" size="small" @click="emit('retry', 'identities')">Try again</el-button>
        </el-alert>
        <el-alert :type="breach.type" show-icon :closable="false" :title="breach.title" class="col-alert">
          <p class="alert-line">{{ breach.detail }}</p>
        </el-alert>

        <p class="facts">
          <span>{{ status.counts.identities_enabled.toLocaleString() }} of {{ pluralize(status.counts.identities, 'identity', 'identities') }} enabled</span>
          <span v-if="lastOk">last successful check {{ formatRelative(lastOk) }}</span>
          <span v-if="checksReady">next check {{ nextBreachCheck }}</span>
        </p>

        <div v-if="breachIssues.length" class="attention">
          <div class="attention-title">Needs attention</div>
          <ul class="attention-list">
            <li v-for="item in breachIssues.slice(0, MAX_LISTED)" :key="item.id">
              <span class="attention-name">{{ item.value }}</span>
              <el-tag size="small" :type="item.tag.type" effect="light">{{ item.tag.label }}</el-tag>
              <span v-if="item.note" class="attention-note">{{ item.note }}</span>
            </li>
          </ul>
          <p v-if="breachIssues.length > MAX_LISTED" class="attention-more">
            and {{ breachIssues.length - MAX_LISTED }} more in
            <router-link v-if="isAdmin" to="/settings/digital-risk">Settings → Digital Risk</router-link>
            <template v-else>Settings → Digital Risk</template>
          </p>
        </div>

        <template v-if="isAdmin">
          <LeakedCredsRunNow class="run-now" @ran="emit('ran')" />
          <p v-if="breachNeedsFix" class="fix-line">
            <router-link to="/settings/digital-risk">Fix in Settings → Digital Risk →</router-link>
          </p>
        </template>
        <p v-else-if="breachNeedsFix" class="fix-line muted">Only an administrator can change this.</p>
      </el-col>

      <!-- Domain monitoring -->
      <el-col :xs="24" :md="12" class="monitor-col">
        <h4 class="col-title">Domain monitoring</h4>
        <el-alert
          v-if="domainsError"
          type="error"
          show-icon
          :closable="false"
          title="Couldn't load domains"
          class="col-alert"
        >
          <p class="alert-line">{{ domainsError }}</p>
          <el-button link type="primary" size="small" @click="emit('retry', 'domains')">Try again</el-button>
        </el-alert>
        <template v-else-if="domainHealth">
          <el-alert :type="domainHealth.type" show-icon :closable="false" :title="domainHealth.title" class="col-alert">
            <p class="alert-line">{{ domainHealth.detail }}</p>
          </el-alert>

          <p class="facts">
            <span>{{ status.counts.domains_enabled.toLocaleString() }} of {{ pluralize(status.counts.domains, 'domain') }} enabled</span>
            <span v-if="lastDomainCheck">last check {{ formatRelative(lastDomainCheck) }}</span>
          </p>

          <div v-if="domainHealth.attention.length" class="attention">
            <div class="attention-title">Needs attention</div>
            <ul class="attention-list">
              <li v-for="item in domainHealth.attention.slice(0, MAX_LISTED)" :key="item.id">
                <span class="attention-name">{{ item.domain }}</span>
                <el-tag size="small" :type="item.tag.type" effect="light">{{ item.tag.label }}</el-tag>
                <span v-if="item.note" class="attention-note">{{ item.note }}</span>
              </li>
            </ul>
            <p v-if="domainHealth.attention.length > MAX_LISTED" class="attention-more">
              and {{ domainHealth.attention.length - MAX_LISTED }} more
            </p>
          </div>

          <p v-if="domainFix" class="fix-line" :class="{ muted: !isAdmin }">
            <router-link v-if="isAdmin" to="/settings/digital-risk">{{ domainFix }}</router-link>
            <template v-else>Only an administrator can change this.</template>
          </p>
        </template>
      </el-col>
    </el-row>

    <p class="notify-line">
      <el-icon class="notify-icon" aria-hidden="true"><Bell /></el-icon>
      <span v-if="status.notifications.enabled">
        New findings at {{ capitalize(status.notifications.min_severity) }} or above go to your notification channels.
      </span>
      <span v-else>Exposure notifications are off: new findings only reach the alert queue.</span>
      <router-link v-if="isAdmin" to="/settings/digital-risk" class="notify-link">Change in Settings →</router-link>
    </p>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { Bell } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import LeakedCredsRunNow from '@/components/LeakedCredsRunNow.vue';
import type { ExposureStatus, MonitoredIdentity, WatchedDomain } from '@/services/exposureService';
import {
  breachChecksReady,
  describeDomainMonitoring,
  describeExposureStatus,
  formatRelative,
  pluralize,
  statusContextFromIdentities,
} from '@/utils/exposure';
import { breachAttention, lastSuccessfulCheck } from './dashboard';

const props = defineProps<{
  status: ExposureStatus;
  /** null until loaded (or when the load failed). */
  identities: MonitoredIdentity[] | null;
  domains: WatchedDomain[] | null;
  identitiesError: string | null;
  domainsError: string | null;
  isAdmin: boolean;
}>();
const emit = defineEmits<{
  /** A manual breach check finished. */
  (e: 'ran'): void;
  (e: 'retry', what: 'identities' | 'domains'): void;
}>();

const MAX_LISTED = 5;
const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

// The Settings banner's wording, pointing at Settings instead of "below". Without
// the identities list it falls back to the last run's counts, as Settings does.
const breach = computed(() =>
  describeExposureStatus(props.status, {
    ...statusContextFromIdentities(props.identities),
    place: 'dashboard',
  })
);
const breachNeedsFix = computed(() => breach.value.type === 'warning' || breach.value.type === 'error');
const checksReady = computed(() => breachChecksReady(props.status));
const lastOk = computed(() => (props.identities ? lastSuccessfulCheck(props.identities) : null));
// The job's next tick is in memory: right after a restart it isn't known yet.
const nextBreachCheck = computed(() => {
  const next = props.status.leaked_creds.job?.next_run_at;
  return next ? formatRelative(next) : 'within 15 minutes';
});
const breachIssues = computed(() => (props.identities ? breachAttention(props.identities) : []));

const domainHealth = computed(() => (props.domains ? describeDomainMonitoring(props.status, props.domains) : null));
const lastDomainCheck = computed(() => {
  let best: string | null = null;
  for (const d of props.domains ?? []) {
    if (d.enabled && d.last_checked_at && (!best || Date.parse(d.last_checked_at) > Date.parse(best))) best = d.last_checked_at;
  }
  return best;
});
// What an administrator can do about the domain headline in Settings.
const domainFix = computed(() => {
  const health = domainHealth.value;
  if (!health || !props.domains || !props.status.features.domain_monitor_available) return '';
  if (props.status.features.domain_monitor_enabled === false) return 'Switch it on in Settings → Digital Risk →';
  if (props.domains.length === 0) return 'Add one in Settings →';
  if (!props.domains.some((d) => d.enabled)) return 'Enable one in Settings →';
  return health.type === 'warning' || health.type === 'error' ? 'Fix in Settings → Digital Risk →' : '';
});
</script>

<style scoped>
.col-title {
  margin: 0 0 10px;
  font-size: 14px;
  font-weight: 600;
  color: var(--siembox-text-color);
}

.monitor-col {
  margin-bottom: 8px;
}

.col-alert {
  margin-bottom: 10px;
}

.alert-line {
  margin: 2px 0 0;
  line-height: 1.5;
}

.facts {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 0;
  margin: 0 0 10px;
  font-size: 12px;
  color: var(--siembox-text-secondary);
}

.facts span:not(:last-child)::after {
  content: '·';
  margin: 0 8px;
}

.attention {
  margin-bottom: 10px;
}

.attention-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--siembox-text-secondary);
  margin-bottom: 4px;
}

.attention-list {
  margin: 0;
  padding: 0;
  list-style: none;
}

.attention-list li {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  padding: 3px 0;
  font-size: 13px;
  border-bottom: 1px solid var(--siembox-border-color);
}

.attention-list li:last-child {
  border-bottom: none;
}

.attention-name {
  font-weight: 500;
  color: var(--siembox-text-color);
  overflow-wrap: anywhere;
}

.attention-note {
  flex-basis: 100%;
  font-size: 12px;
  color: var(--siembox-text-secondary);
  overflow-wrap: anywhere;
}

.attention-more {
  margin: 4px 0 0;
  font-size: 12px;
  color: var(--siembox-text-secondary);
}

.run-now {
  margin-top: 6px;
}

.fix-line {
  margin: 8px 0 0;
  font-size: 13px;
}

.fix-line a,
.attention-more a,
.notify-link {
  color: var(--el-color-primary);
  text-decoration: none;
}

.fix-line a:hover,
.attention-more a:hover,
.notify-link:hover {
  text-decoration: underline;
}

.muted {
  color: var(--siembox-text-secondary);
}

.notify-line {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  margin: 8px 0 0;
  padding-top: 10px;
  border-top: 1px solid var(--siembox-border-color);
  font-size: 13px;
  color: var(--siembox-text-secondary);
}

.notify-icon {
  flex-shrink: 0;
}
</style>
