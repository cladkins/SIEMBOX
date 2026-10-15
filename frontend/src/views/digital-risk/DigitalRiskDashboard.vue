<template>
  <div class="digital-risk">
    <div class="page-header">
      <p class="subtitle">{{ subtitle }}</p>
      <div class="header-controls">
        <el-radio-group v-model="days" size="small" aria-label="Time window" @change="loadSummary">
          <el-radio-button v-for="w in WINDOWS" :key="w.days" :value="w.days">{{ w.label }}</el-radio-button>
        </el-radio-group>
        <el-button size="small" :icon="Refresh" :loading="anyLoading" @click="reloadAll">Refresh</el-button>
        <el-button v-if="isAdmin" size="small" :icon="Setting" @click="router.push('/settings/digital-risk')">Configure</el-button>
      </div>
    </div>

    <!-- Never flash the setup card before the status says nothing is set up. -->
    <el-card v-if="!status && !statusError" class="section">
      <el-skeleton :rows="5" animated />
    </el-card>

    <el-alert
      v-else-if="!status && statusError"
      type="error"
      show-icon
      :closable="false"
      title="Couldn't load the Digital Risk status"
      class="section"
    >
      <p class="alert-line">{{ statusError }}</p>
      <el-button link type="primary" size="small" @click="reloadAll">Try again</el-button>
    </el-alert>

    <!-- Nothing watched yet. -->
    <el-card v-else-if="status && notSetUp" class="section setup-card">
      <template #header><span>Set up Digital Risk monitoring</span></template>
      <p class="setup-intro">Digital Risk watches, outside your network:</p>
      <ul class="setup-list">
        <li><strong>Leaked credentials</strong>: your email addresses and email domains in data breaches, from Have I Been Pwned.</li>
        <li><strong>Lookalike domains</strong>: newly registered names that imitate your domains or brand, and the TLS certificates issued for them.</li>
        <li><strong>Changes to your domains</strong>: DNS, registration and certificate changes, and registrations about to expire.</li>
      </ul>
      <!-- The quick setup ends with its own "Settings → Digital Risk" button for the other options. -->
      <DigitalRiskQuickSetup v-if="isAdmin" :status="status" @changed="reloadAll" />
      <el-text v-else type="info">An administrator hasn't set up Digital Risk monitoring yet.</el-text>
    </el-card>

    <template v-else-if="status">
      <!-- 1. Is monitoring working? -->
      <DrMonitoringCard
        class="section"
        :status="status"
        :identities="identities"
        :domains="domains"
        :identities-error="identitiesError"
        :domains-error="domainsError"
        :is-admin="isAdmin"
        @ran="onRan"
        @retry="(what) => (what === 'identities' ? loadIdentities() : loadDomains())"
      />

      <el-alert
        v-if="summaryError"
        type="error"
        show-icon
        :closable="false"
        title="Couldn't load the Digital Risk summary"
        class="section"
      >
        <p class="alert-line">{{ summaryError }}</p>
        <el-button link type="primary" size="small" @click="loadSummary">Try again</el-button>
      </el-alert>

      <template v-else>
        <!-- 2. What is open, how severe, and what is new? -->
        <el-row :gutter="16" class="section tiles">
          <el-col :xs="24" :sm="12" :md="6">
            <el-card class="stat-card" :style="{ '--tile-color': openColor }">
              <div class="stat-content">
                <div class="stat-icon">
                  <el-icon :size="26"><WarningFilled v-if="summary && summary.open.total > 0" /><CircleCheck v-else /></el-icon>
                </div>
                <div class="stat-info">
                  <button type="button" class="stat-button" :disabled="!summary" @click="filterOpen()">
                    <span class="stat-value">{{ summary ? summary.open.total.toLocaleString() : '—' }}</span>
                    <span class="stat-label">Open findings</span>
                  </button>
                </div>
              </div>
              <el-skeleton v-if="!summary" :rows="0" animated class="stat-skeleton" />
              <template v-else>
                <div v-if="openChips.length" class="sev-chips">
                  <button
                    v-for="chip in openChips"
                    :key="chip.severity"
                    type="button"
                    class="sev-chip"
                    :aria-label="`${chip.count} open ${chip.severity} findings`"
                    :title="`Show the open ${chip.severity} findings`"
                    @click="filterOpen(chip.severity)"
                  >
                    <span class="sev-dot" :style="{ backgroundColor: SEVERITY_COLORS[chip.severity] }" aria-hidden="true" />
                    {{ chip.count.toLocaleString() }}
                    <span class="sev-name">{{ SEVERITY_LABELS[chip.severity] }}</span>
                  </button>
                </div>
                <div v-if="oldestDays !== null" class="stat-sub">Oldest open critical/high: {{ pluralize(oldestDays, 'day') }}</div>
              </template>
            </el-card>
          </el-col>

          <el-col :xs="24" :sm="12" :md="6">
            <el-card class="stat-card" :style="{ '--tile-color': NEUTRAL_BLUE }">
              <div class="stat-content">
                <div class="stat-icon"><el-icon :size="26"><TrendCharts /></el-icon></div>
                <div class="stat-info">
                  <button type="button" class="stat-button" :disabled="!summary" @click="filterNew">
                    <span class="stat-value">{{ summary ? summary.in_window.new.toLocaleString() : '—' }}</span>
                    <span class="stat-label">New in the last {{ windowLabel }}</span>
                  </button>
                </div>
              </div>
              <el-skeleton v-if="!summary" :rows="0" animated class="stat-skeleton" />
              <div v-else class="stat-sub">
                <span aria-hidden="true">{{ trendMark }}</span>
                {{ summary.in_window.prev_new.toLocaleString() }} in the {{ windowLabel }} before
              </div>
            </el-card>
          </el-col>

          <el-col :xs="24" :sm="12" :md="6">
            <el-card class="stat-card" :style="{ '--tile-color': accountsColor }">
              <div class="stat-content">
                <div class="stat-icon"><el-icon :size="26"><Key /></el-icon></div>
                <div class="stat-info">
                  <button type="button" class="stat-button" :disabled="!summary" @click="accountsCard?.scrollIntoView()">
                    <span class="stat-value">{{ accountsTile.value }}</span>
                    <span class="stat-label">Accounts to reset</span>
                  </button>
                </div>
              </div>
              <el-skeleton v-if="!summary || accountsTile.loading" :rows="0" animated class="stat-skeleton" />
              <template v-else>
                <div v-if="accountsTile.sub" class="stat-sub">{{ accountsTile.sub }}</div>
                <div v-if="accountsTile.note" class="stat-sub stat-note">{{ accountsTile.note }}</div>
              </template>
            </el-card>
          </el-col>

          <el-col :xs="24" :sm="12" :md="6">
            <el-card class="stat-card" :style="{ '--tile-color': lookalikesColor }">
              <div class="stat-content">
                <div class="stat-icon"><el-icon :size="26"><Message /></el-icon></div>
                <div class="stat-info">
                  <button type="button" class="stat-button" :disabled="!summary" @click="lookalikesCard?.scrollIntoView()">
                    <span class="stat-value">{{ lookalikesValue }}</span>
                    <span class="stat-label">Lookalikes with mail (MX)</span>
                  </button>
                </div>
              </div>
              <el-skeleton v-if="!summary" :rows="0" animated class="stat-skeleton" />
              <div v-else class="stat-sub">{{ lookalikesSub }}</div>
            </el-card>
          </el-col>
        </el-row>

        <!-- 3. What is trending? Stacked below 1200px: beside the chart, the type
             list's labels, bars and counts need more than a third of a laptop window. -->
        <el-row :gutter="16" class="section">
          <el-col :xs="24" :lg="14" :xl="16" class="row-col">
            <el-card class="fill-card">
              <template #header>
                <span>Findings detected per {{ summary?.window.bucket ?? 'week' }}</span>
              </template>
              <el-skeleton v-if="!summary" :rows="6" animated />
              <DrTrendChart v-else :trend="summary.trend" :window="summary.window" />
            </el-card>
          </el-col>
          <el-col :xs="24" :lg="10" :xl="8" class="row-col">
            <el-card class="fill-card">
              <template #header>
                <div class="card-header">
                  <span>Open findings by type</span>
                  <el-text v-if="typeBars.length" size="small" type="info">Click a row to see them</el-text>
                </div>
              </template>
              <el-skeleton v-if="!summary" :rows="5" animated />
              <p v-else-if="!typeBars.length" class="card-empty">No open findings</p>
              <RankedBarList v-else :items="typeBars" label-width="200px" @item-click="filterType" />
            </el-card>
          </el-col>
        </el-row>

        <!-- 4. Which account or domain, and what to do about it. Full width each: the
             tables have too many columns to share a row without scrolling sideways. -->
        <template v-if="summary">
          <DrAccountsCard
            ref="accountsCard"
            class="section"
            :accounts="summary.accounts"
            :checks-ready="checksReady"
            :breach-title="breachTitle"
            :identities="status.counts.identities"
            :identities-enabled="status.counts.identities_enabled"
            :identities-loaded="!!identities"
            :identities-error="!!identitiesError"
            :failing-identities="failingIdentities"
            :last-checked="lastBreachCheck"
            @filter="applyQueueFilters"
          />
          <DrLookalikesCard
            ref="lookalikesCard"
            class="section"
            :lookalikes="summary.lookalikes"
            :domain-monitor="domainMonitor"
            :is-admin="isAdmin"
            @filter="applyQueueFilters"
          />
        </template>
      </template>

      <!-- 5. The triage queue. -->
      <ExposureFindingsCard
        ref="findingsCard"
        class="section"
        :domain-monitor="domainMonitor"
        :can-resolve="isAdmin"
        default-open-only
        default-sort="severity"
        :initial-filters="deepLink.filters"
        :assets="{ domains: domains ?? [], identities: identities ?? [] }"
        @changed="onResolved"
      />
    </template>

    <!-- 6. Needs no setup, so it is always here. -->
    <PasswordCheckCard class="section" />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { CircleCheck, Key, Message, Refresh, Setting, TrendCharts, WarningFilled } from '@element-plus/icons-vue';
import DigitalRiskQuickSetup from '@/components/DigitalRiskQuickSetup.vue';
import RankedBarList from '@/components/RankedBarList.vue';
import { useExposureStatus } from '@/composables/useExposureStatus';
import exposureService, {
  type ExposureSeverity,
  type ExposureSummary,
  type MonitoredIdentity,
  type SummaryDays,
  type WatchedDomain,
} from '@/services/exposureService';
import { useAuthStore } from '@/stores/auth';
import { useThemeStore } from '@/stores/theme';
import {
  apiErrorMessage,
  breachChecksReady,
  describeExposureStatus,
  formatWhen,
  pluralize,
  statusContextFromIdentities,
} from '@/utils/exposure';
import { SEVERITY_COLORS, SEVERITY_LABELS, SEVERITY_ORDER } from '@/utils/severity';
import DrAccountsCard from './DrAccountsCard.vue';
import DrLookalikesCard from './DrLookalikesCard.vue';
import DrMonitoringCard from './DrMonitoringCard.vue';
import DrTrendChart from './DrTrendChart.vue';
import ExposureFindingsCard from './ExposureFindingsCard.vue';
import PasswordCheckCard from './PasswordCheckCard.vue';
import {
  isNotSetUp,
  parseDeepLink,
  parseTypeKey,
  typeItems,
  type FindingsFilters,
} from './dashboard';

// Every signed-in role opens this page (every GET it makes is open to them).
// The admin-only controls (Configure, Run check now, Resolve, the links into
// Settings, the inline setup) are decided here, once, and handed down: the
// cards never read the auth store.
const authStore = useAuthStore();
const isAdmin = computed(() => authStore.isAdmin);
const themeStore = useThemeStore();
const route = useRoute();
const router = useRouter();

const WINDOWS: ReadonlyArray<{ days: SummaryDays; label: string }> = [
  { days: 30, label: '30 days' },
  { days: 90, label: '90 days' },
  { days: 180, label: '180 days' },
  { days: 365, label: '1 year' },
];
const NEUTRAL = 'var(--siembox-text-tertiary)';
const NEUTRAL_BLUE = '#409eff';

// The deep link is read once; the URL isn't written back.
const deepLink = parseDeepLink(route.query as Record<string, unknown>);
const days = ref<SummaryDays>(deepLink.days ?? 90);

const { status, loading: statusLoading, error: statusError, refresh: refreshStatus, domainMonitor } = useExposureStatus();

const identities = ref<MonitoredIdentity[] | null>(null);
const identitiesError = ref<string | null>(null);
const identitiesLoading = ref(false);
const domains = ref<WatchedDomain[] | null>(null);
const domainsError = ref<string | null>(null);
const domainsLoading = ref(false);
const summary = ref<ExposureSummary | null>(null);
const summaryError = ref<string | null>(null);
const summaryLoading = ref(false);

const findingsCard = ref<InstanceType<typeof ExposureFindingsCard> | null>(null);
const accountsCard = ref<InstanceType<typeof DrAccountsCard> | null>(null);
const lookalikesCard = ref<InstanceType<typeof DrLookalikesCard> | null>(null);

const anyLoading = computed(
  () => statusLoading.value || identitiesLoading.value || domainsLoading.value || summaryLoading.value
);
const notSetUp = computed(() => !!status.value && isNotSetUp(status.value));

const subtitle = computed(() => {
  const c = status.value?.counts;
  if (!c) return 'Leaked credentials and domain threats';
  return `Leaked credentials and domain threats for ${pluralize(c.domains_enabled, 'domain')} and ${pluralize(
    c.identities_enabled,
    'identity',
    'identities'
  )} you monitor`;
});

// ---- Loading (each part on its own, newest answer wins) ----------------------------------

let latestIdentitiesLoad = 0;
async function loadIdentities(): Promise<void> {
  const thisLoad = ++latestIdentitiesLoad;
  identitiesLoading.value = true;
  try {
    const rows = await exposureService.listIdentities();
    if (thisLoad !== latestIdentitiesLoad) return;
    identities.value = rows;
    identitiesError.value = null;
  } catch (error) {
    if (thisLoad === latestIdentitiesLoad) identitiesError.value = apiErrorMessage(error, 'The identities request failed.');
  } finally {
    if (thisLoad === latestIdentitiesLoad) identitiesLoading.value = false;
  }
}

let latestDomainsLoad = 0;
async function loadDomains(): Promise<void> {
  const thisLoad = ++latestDomainsLoad;
  domainsLoading.value = true;
  try {
    const rows = await exposureService.listDomains();
    if (thisLoad !== latestDomainsLoad) return;
    domains.value = rows;
    domainsError.value = null;
  } catch (error) {
    if (thisLoad === latestDomainsLoad) domainsError.value = apiErrorMessage(error, 'The domains request failed.');
  } finally {
    if (thisLoad === latestDomainsLoad) domainsLoading.value = false;
  }
}

// A new window choice supersedes a summary request still in flight.
let latestSummaryLoad = 0;
async function loadSummary(): Promise<void> {
  const thisLoad = ++latestSummaryLoad;
  summaryLoading.value = true;
  try {
    const next = await exposureService.getSummary(days.value);
    if (thisLoad !== latestSummaryLoad) return;
    summary.value = next;
    summaryError.value = null;
  } catch (error) {
    if (thisLoad === latestSummaryLoad) summaryError.value = apiErrorMessage(error, 'The summary request failed.');
  } finally {
    if (thisLoad === latestSummaryLoad) summaryLoading.value = false;
  }
}

async function reloadAll(): Promise<void> {
  await Promise.allSettled([refreshStatus(), loadIdentities(), loadDomains(), loadSummary(), findingsCard.value?.reload()]);
}

// A finding was resolved: the tiles, the chart's backlog and the counts follow.
function onResolved() {
  void loadSummary();
  void refreshStatus();
}

// A manual breach check ran: identities' last checks and maybe new findings.
function onRan() {
  void refreshStatus();
  void loadIdentities();
  void loadSummary();
  void findingsCard.value?.reload();
}

onMounted(() => {
  void Promise.allSettled([refreshStatus(), loadIdentities(), loadDomains(), loadSummary()]);
});

// ---- Tiles ---------------------------------------------------------------------------------

const checksReady = computed(() => !!status.value && breachChecksReady(status.value));
// Empty until GET /identities has answered.
const identityContext = computed(() => statusContextFromIdentities(identities.value));
const breachTitle = computed(() =>
  status.value ? describeExposureStatus(status.value, { ...identityContext.value, place: 'dashboard' }).title : ''
);
const lastBreachCheck = computed(() => identityContext.value.lastSuccessfulCheck ?? null);
// Enabled identities whose latest check failed. A failure doesn't record when the
// identity last succeeded (it may keep that time, stamp its own, or have none), so
// with no successful check in view the page says the last check failed, not that
// none was ever checked.
const failingIdentities = computed(() => identityContext.value.failingIdentities ?? 0);

const openChips = computed(() =>
  summary.value
    ? SEVERITY_ORDER.map((severity) => ({ severity, count: summary.value!.open.by_severity[severity] ?? 0 })).filter(
        (c) => c.count > 0
      )
    : []
);
// The tile takes the colour of the most severe open finding.
const openColor = computed(() => {
  const worst = openChips.value[0]?.severity;
  return worst ? SEVERITY_COLORS[worst] : NEUTRAL;
});
const oldestDays = computed(() => {
  const at = summary.value?.open.oldest_critical_high_first_seen;
  if (!at || !summary.value) return null;
  const ms = Date.parse(summary.value.generated_at) - Date.parse(at);
  return Number.isFinite(ms) ? Math.max(0, Math.floor(ms / 86_400_000)) : null;
});

const windowLabel = computed(() => (summary.value?.window.days === 365 ? 'year' : `${summary.value?.window.days ?? days.value} days`));
const trendMark = computed(() => {
  const s = summary.value?.in_window;
  if (!s) return '';
  return s.new > s.prev_new ? '▲' : s.new < s.prev_new ? '▼' : '=';
});

// A zero only reads as good when a check ran: the checks can run, and some
// enabled identity has been checked successfully (an email domain HIBP skips
// as not verified never is). Until the identities have loaded that isn't known,
// so the tile keeps its skeleton.
const accountsTile = computed((): { value: string; sub: string; note: string; loading?: boolean } => {
  const a = summary.value?.accounts;
  const s = status.value;
  if (!a || !s) return { value: '—', sub: '', note: '' };
  const pausedUntil = checksReady.value ? s.leaked_creds.paused_until : null;
  const pausedNote = pausedUntil ? `Breach checks are paused until ${formatWhen(pausedUntil, 'later')}` : '';
  if (a.total === 0) {
    if (!checksReady.value) return { value: '—', sub: "Breach checks aren't running", note: '' };
    if (s.counts.identities === 0) return { value: '—', sub: 'No identities are monitored', note: '' };
    if (s.counts.identities_enabled === 0) return { value: '—', sub: 'Every monitored identity is disabled', note: '' };
    if (!identities.value) {
      return identitiesError.value
        ? { value: '—', sub: "Couldn't load the identities", note: '' }
        : { value: '—', sub: '', note: '', loading: true };
    }
    if (!lastBreachCheck.value) {
      return { value: '—', sub: failingIdentities.value > 0 ? 'Last check failed' : 'Not checked yet', note: pausedNote };
    }
  }
  return {
    value: a.to_reset.toLocaleString(),
    sub: `of ${pluralize(a.total, 'breached account')}`,
    note: checksReady.value ? pausedNote : "Breach checks aren't running now",
  };
});
const accountsColor = computed(() => ((summary.value?.accounts.to_reset ?? 0) > 0 ? SEVERITY_COLORS.high : NEUTRAL));

const lookalikesUnknown = computed(() => {
  const l = summary.value?.lookalikes;
  if (!l) return '';
  if (domainMonitor.value === 'unavailable') return "Domain monitoring isn't available";
  if (domainMonitor.value === 'off') return 'Domain monitoring is switched off';
  if (l.state === 'not_watched') return 'No domains are watched';
  if (l.state === 'not_checked') return 'Not checked yet';
  return '';
});
const lookalikesValue = computed(() => {
  const l = summary.value?.lookalikes;
  if (!l || lookalikesUnknown.value) return '—';
  return l.with_mx.toLocaleString();
});
const lookalikesSub = computed(() => {
  const l = summary.value?.lookalikes;
  if (!l) return '';
  if (lookalikesUnknown.value) return lookalikesUnknown.value;
  return `of ${l.registered.toLocaleString()} registered · ${l.with_current_cert.toLocaleString()} with a current TLS certificate`;
});
const lookalikesColor = computed(() =>
  !lookalikesUnknown.value && (summary.value?.lookalikes.with_mx ?? 0) > 0 ? SEVERITY_COLORS.high : NEUTRAL
);

const typeBars = computed(() => (summary.value ? typeItems(summary.value.by_type, themeStore.isDark) : []));

// ---- Click-throughs into the queue ------------------------------------------------------------

function applyQueueFilters(filters: FindingsFilters) {
  void findingsCard.value?.applyFilters(filters);
}

function filterOpen(severity?: ExposureSeverity) {
  applyQueueFilters({ severity, open_only: true, sort: 'severity' });
}

// The tile counts from the window's start (a bucket boundary), so the queue does too.
function filterNew() {
  if (!summary.value) return;
  applyQueueFilters({ since: summary.value.window.since, open_only: false, sort: 'newest' });
}

function filterType(key: string) {
  applyQueueFilters({ ...parseTypeKey(key), open_only: true, sort: 'severity' });
}
</script>

<style scoped>
.digital-risk {
  padding: 0;
}

.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.subtitle {
  margin: 0;
  font-size: 14px;
  color: var(--siembox-text-secondary);
}

.header-controls {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.header-controls .el-button + .el-button {
  margin-left: 0;
}

.section {
  margin-top: 16px;
}

.alert-line {
  margin: 2px 0 0;
  line-height: 1.5;
}

.setup-intro {
  margin: 0 0 6px;
  font-size: 14px;
}

.setup-list {
  margin: 0 0 16px;
  padding-left: 20px;
  font-size: 13px;
  line-height: 1.7;
  color: var(--siembox-text-color);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.card-empty {
  margin: 0;
  padding: 24px 0;
  text-align: center;
  font-size: 13px;
  color: var(--siembox-text-secondary);
}

/* Columns stack below md/lg; the gutter then needs a gap between the stacked cards. */
.row-col {
  margin-bottom: 16px;
}

.section.el-row {
  margin-bottom: -16px;
}

.fill-card {
  height: 100%;
}

/* ---- Tiles (the stat-card look of Dashboard.vue) ---- */

.tiles .el-col {
  margin-bottom: 16px;
}

.stat-card {
  --tile-color: var(--siembox-text-tertiary);
  height: 100%;
  background-color: var(--siembox-card-bg, #fff);
  border-left: 3px solid var(--tile-color);
  transition: background-color 0.3s, border-color 0.3s;
}

.stat-card :deep(.el-card__body) {
  padding: 14px 18px;
}

.stat-content {
  display: flex;
  align-items: center;
  gap: 14px;
}

.stat-icon {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 48px;
  height: 48px;
  border-radius: 50%;
  color: var(--tile-color);
  flex-shrink: 0;
  overflow: hidden;
}

/* A soft disc in the tile's colour behind the icon. */
.stat-icon::before {
  content: '';
  position: absolute;
  inset: 0;
  background: var(--tile-color);
  opacity: 0.12;
}

.stat-info {
  flex: 1;
  min-width: 0;
}

.stat-button {
  display: block;
  width: 100%;
  padding: 0;
  border: none;
  background: none;
  text-align: left;
  font: inherit;
  color: inherit;
  cursor: pointer;
  border-radius: 4px;
}

.stat-button:disabled {
  cursor: default;
}

.stat-button:focus-visible,
.sev-chip:focus-visible {
  outline: 2px solid var(--el-color-primary);
  outline-offset: 2px;
}

.stat-value {
  display: block;
  font-size: 26px;
  font-weight: bold;
  line-height: 1.2;
  color: var(--siembox-text-color);
}

.stat-label {
  display: block;
  font-size: 13px;
  color: var(--siembox-text-secondary, #909399);
  margin-top: 3px;
}

.stat-button:not(:disabled):hover .stat-label {
  color: var(--el-color-primary);
}

.stat-sub {
  margin-top: 8px;
  font-size: 12px;
  line-height: 1.5;
  color: var(--siembox-text-secondary);
}

.stat-note {
  margin-top: 2px;
  color: var(--el-color-warning);
}

.stat-skeleton {
  margin-top: 8px;
}

.sev-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 10px;
}

.sev-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 1px 6px;
  border: 1px solid var(--siembox-border-color);
  border-radius: 10px;
  background: none;
  font: inherit;
  font-size: 12px;
  font-weight: 600;
  color: var(--siembox-text-color);
  cursor: pointer;
}

.sev-chip:hover {
  border-color: var(--el-color-primary);
}

.sev-name {
  font-weight: 400;
  color: var(--siembox-text-secondary);
}

.sev-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
</style>
