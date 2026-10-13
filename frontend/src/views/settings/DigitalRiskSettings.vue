<template>
  <div class="digital-risk-settings">
    <!-- Which state the feature is in, most urgent first (see describeExposureStatus). -->
    <div v-loading="statusLoading && !status" class="status-banner">
      <el-alert
        v-if="statusError"
        type="error"
        show-icon
        :closable="false"
        title="Couldn't load the Digital Risk status"
      >
        <p class="banner-line">{{ statusError }}</p>
        <el-button link type="primary" size="small" @click="refreshBanner">Try again</el-button>
      </el-alert>
      <el-alert v-else-if="banner" :type="banner.type" show-icon :closable="false" :title="banner.title">
        <p class="banner-line">{{ banner.detail }}</p>
        <p v-if="countsLine" class="banner-line banner-counts">
          {{ countsLine }}
          <el-button link type="primary" size="small" :loading="statusLoading" @click="refreshBanner">Refresh</el-button>
        </p>
      </el-alert>
    </div>

    <ExposureDomainsCard
      ref="ownDomainsCard"
      scope="own"
      :domain-monitor="domainMonitor"
      @changed="refreshStatus"
      @deleted="reloadFindings"
    />
    <ExposureIdentitiesCard
      ref="identitiesCard"
      class="section"
      :status="status"
      @changed="onIdentitiesCardChanged"
      @deleted="reloadFindings"
      @loaded="identityRows = $event"
      @domains-refreshed="onDomainsRefreshed('identities')"
    />
    <ExposureDomainsCard
      ref="brandDomainsCard"
      scope="brand"
      class="section"
      :domain-monitor="domainMonitor"
      @changed="refreshStatus"
      @deleted="reloadFindings"
    />
    <ExposureProviderCard
      ref="providerCard"
      class="section"
      :encryption-error="encryptionError"
      @changed="refreshStatus"
      @encryption-error="encryptionError = $event"
      @domains-refreshed="onDomainsRefreshed('provider')"
      @identities-changed="onIdentitiesChanged"
    />
    <ExposureChecksCard class="section" @changed="refreshStatus" @ran="onCheckRan" />
    <ExposureFindingsCard ref="findingsCard" class="section" :domain-monitor="domainMonitor" @changed="refreshStatus" />
    <PasswordCheckCard class="section" />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import exposureService, {
  EXPOSURE_SEVERITIES,
  type ExposureStatus,
  type MonitoredIdentity,
} from '@/services/exposureService';
import {
  apiErrorMessage,
  describeExposureStatus,
  domainMonitorState,
  domainVerificationCounts,
  pluralize,
} from '@/utils/exposure';
import ExposureChecksCard from './ExposureChecksCard.vue';
import ExposureDomainsCard from './ExposureDomainsCard.vue';
import ExposureFindingsCard from './ExposureFindingsCard.vue';
import ExposureIdentitiesCard from './ExposureIdentitiesCard.vue';
import ExposureProviderCard from './ExposureProviderCard.vue';
import PasswordCheckCard from './PasswordCheckCard.vue';

// Each card loads and writes its own slice of /api/exposure (through the same
// client the onboarding checklist uses) and emits `changed` after a write. The
// page owns the status banner, and reloads the findings when a domain or an
// identity is deleted (its findings go with it).
const status = ref<ExposureStatus | null>(null);
const statusLoading = ref(false);
const statusError = ref<string | null>(null);
// The API can't report a missing CREDENTIAL_ENCRYPTION_KEY up front; the
// provider card hands over the 400 message when a key save runs into it.
const encryptionError = ref<string | null>(null);

const identitiesCard = ref<InstanceType<typeof ExposureIdentitiesCard> | null>(null);
const ownDomainsCard = ref<InstanceType<typeof ExposureDomainsCard> | null>(null);
const brandDomainsCard = ref<InstanceType<typeof ExposureDomainsCard> | null>(null);
const providerCard = ref<InstanceType<typeof ExposureProviderCard> | null>(null);
const findingsCard = ref<InstanceType<typeof ExposureFindingsCard> | null>(null);
// The identities card's list as last loaded. A failed check is recorded on the
// identity (last_status), which outlives the latest run's summary in /status
// (kept in memory, so it resets when the backend restarts).
const identityRows = ref<MonitoredIdentity[] | null>(null);

const banner = computed(() =>
  status.value
    ? describeExposureStatus(status.value, {
        encryptionKeyError: encryptionError.value,
        failingIdentities: identityRows.value?.filter((i) => i.enabled && i.last_status === 'error').length,
        // Email domains HIBP skips (not verified, no domain search) or may only partly search.
        ...(identityRows.value ? domainVerificationCounts(identityRows.value) : {}),
      })
    : null
);
// While the status loads (or if it fails) this is 'on', so no "not checked" note flashes up.
const domainMonitor = computed(() => domainMonitorState(status.value));

const countsLine = computed(() => {
  const c = status.value?.counts;
  if (!c) return '';
  const bySeverity = [...EXPOSURE_SEVERITIES]
    .reverse()
    .filter((s) => (c.findings_open_by_severity[s] ?? 0) > 0)
    .map((s) => `${c.findings_open_by_severity[s]} ${s}`);
  return [
    pluralize(c.domains, 'watched domain'),
    pluralize(c.identities, 'monitored identity', 'monitored identities'),
    `${pluralize(c.findings_open, 'open finding')}${bySeverity.length ? ` (${bySeverity.join(', ')})` : ''}`,
  ].join(' · ');
});

let latestStatusLoad = 0;

async function refreshStatus() {
  const thisLoad = ++latestStatusLoad;
  statusLoading.value = true;
  try {
    const next = await exposureService.getStatus();
    if (thisLoad !== latestStatusLoad) return;
    status.value = next;
    statusError.value = null;
  } catch (error) {
    if (thisLoad === latestStatusLoad) statusError.value = apiErrorMessage(error, 'The status request failed.');
  } finally {
    if (thisLoad === latestStatusLoad) statusLoading.value = false;
  }
}

// Refresh re-reads what can change without an edit on this page: the status,
// the identities' and domains' last checks (the background jobs), whether the
// saved key is usable (CREDENTIAL_ENCRYPTION_KEY fixed or broken), and the
// findings. The settings form is left alone, so unsaved edits survive.
async function refreshBanner() {
  await Promise.all([
    refreshStatus(),
    identitiesCard.value?.reload(),
    ownDomainsCard.value?.reload(),
    brandDomainsCard.value?.reload(),
    providerCard.value?.reload(),
    reloadFindings(),
  ]);
}

// A manual run changes identities' last-check state and may add findings.
function onCheckRan() {
  void refreshStatus();
  void identitiesCard.value?.reload();
  void reloadFindings();
}

// HIBP was asked which domains are verified (from either card): the identities'
// verification lines, the other card's view and the banner change with it.
function onDomainsRefreshed(from: 'identities' | 'provider') {
  void refreshStatus();
  void identitiesCard.value?.reload();
  if (from === 'identities') void providerCard.value?.reloadDomains();
}

// An identity was added, changed or deleted: the HIBP card's "In SIEMBox" column follows.
function onIdentitiesCardChanged() {
  void refreshStatus();
  void providerCard.value?.reloadDomains();
}

// The HIBP card added a verified domain as a monitored identity.
function onIdentitiesChanged() {
  void refreshStatus();
  void identitiesCard.value?.reload();
}

// Deleting an identity or a domain also deletes its findings (ON DELETE CASCADE).
function reloadFindings() {
  return findingsCard.value?.reload();
}

onMounted(refreshStatus);
</script>

<style scoped>
.status-banner {
  min-height: 48px;
  margin-bottom: 20px;
}

.banner-line {
  margin: 2px 0 0;
  line-height: 1.5;
}

.banner-counts {
  color: var(--el-text-color-secondary);
}

.section {
  margin-top: 20px;
}
</style>
