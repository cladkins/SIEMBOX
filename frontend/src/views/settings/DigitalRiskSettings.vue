<template>
  <div class="digital-risk-settings">
    <p class="page-link">
      Monitoring status, findings, trends and the password check are on the
      <router-link to="/digital-risk">Digital Risk page →</router-link>
    </p>

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
        <p v-if="counts" class="banner-line banner-counts">
          {{ counts.watched }} ·
          <router-link to="/digital-risk" class="counts-link">{{ counts.findings }}</router-link>
          <el-button link type="primary" size="small" :loading="statusLoading" @click="refreshBanner">Refresh</el-button>
        </p>
      </el-alert>
    </div>

    <ExposureDomainsCard
      ref="ownDomainsCard"
      scope="own"
      :domain-monitor="domainMonitor"
      @changed="refreshStatus"
      @deleted="refreshStatus"
    />
    <ExposureIdentitiesCard
      ref="identitiesCard"
      class="section"
      :status="status"
      @changed="onIdentitiesCardChanged"
      @deleted="refreshStatus"
      @loaded="identityRows = $event"
      @domains-refreshed="onDomainsRefreshed('identities')"
    />
    <ExposureDomainsCard
      ref="brandDomainsCard"
      scope="brand"
      class="section"
      :domain-monitor="domainMonitor"
      @changed="refreshStatus"
      @deleted="refreshStatus"
    />
    <!-- Next to the watched domains: the certificate checks' fallback source and its optional key. -->
    <CertSpotterCard ref="certSpotterCard" class="section" />
    <ExposureProviderCard
      ref="providerCard"
      class="section"
      :encryption-error="encryptionError"
      @changed="onProviderChanged"
      @encryption-error="encryptionError = $event"
      @domains-refreshed="onDomainsRefreshed('provider')"
      @identities-changed="onIdentitiesChanged"
    />
    <ExposureChecksCard class="section" @changed="refreshStatus" @ran="onCheckRan" />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useExposureStatus } from '@/composables/useExposureStatus';
import { EXPOSURE_SEVERITIES, type MonitoredIdentity } from '@/services/exposureService';
import { describeExposureStatus, pluralize, statusContextFromIdentities } from '@/utils/exposure';
import CertSpotterCard from './CertSpotterCard.vue';
import ExposureChecksCard from './ExposureChecksCard.vue';
import ExposureDomainsCard from './ExposureDomainsCard.vue';
import ExposureIdentitiesCard from './ExposureIdentitiesCard.vue';
import ExposureProviderCard from './ExposureProviderCard.vue';

// Configuration only: each card loads and writes its own slice of
// /api/exposure (through the same client the onboarding checklist and the
// Digital Risk page use) and emits `changed` after a write. The page owns the
// status banner. Findings, trends and the password check are on /digital-risk.
const { status, loading: statusLoading, error: statusError, refresh: refreshStatus, domainMonitor } = useExposureStatus();
// The API can't report a missing CREDENTIAL_ENCRYPTION_KEY up front; the
// provider card hands over the 400 message when a key save runs into it.
const encryptionError = ref<string | null>(null);

const identitiesCard = ref<InstanceType<typeof ExposureIdentitiesCard> | null>(null);
const ownDomainsCard = ref<InstanceType<typeof ExposureDomainsCard> | null>(null);
const brandDomainsCard = ref<InstanceType<typeof ExposureDomainsCard> | null>(null);
const providerCard = ref<InstanceType<typeof ExposureProviderCard> | null>(null);
const certSpotterCard = ref<InstanceType<typeof CertSpotterCard> | null>(null);
// The identities card's list as last loaded. A failed check is recorded on the
// identity (last_status), which outlives the latest run's summary in /status
// (kept in memory, so it resets when the backend restarts).
const identityRows = ref<MonitoredIdentity[] | null>(null);

const banner = computed(() =>
  status.value ? describeExposureStatus(status.value, statusContextFromIdentities(identityRows.value, encryptionError.value)) : null
);

// "2 watched domains · 3 monitored identities · 5 open findings (1 critical, 4 high)"; the
// findings part links to the Digital Risk page, where they are listed.
const counts = computed(() => {
  const c = status.value?.counts;
  if (!c) return null;
  const bySeverity = [...EXPOSURE_SEVERITIES]
    .reverse()
    .filter((s) => (c.findings_open_by_severity[s] ?? 0) > 0)
    .map((s) => `${c.findings_open_by_severity[s]} ${s}`);
  return {
    watched: [
      pluralize(c.domains, 'watched domain'),
      pluralize(c.identities, 'monitored identity', 'monitored identities'),
    ].join(' · '),
    findings: `${pluralize(c.findings_open, 'open finding')}${bySeverity.length ? ` (${bySeverity.join(', ')})` : ''}`,
  };
});

// Refresh re-reads what can change without an edit on this page: the status,
// the identities' and domains' last checks (the background jobs), and whether
// the saved key is usable (CREDENTIAL_ENCRYPTION_KEY fixed or broken). The
// settings form is left alone, so unsaved edits survive.
async function refreshBanner() {
  await Promise.all([
    refreshStatus(),
    identitiesCard.value?.reload(),
    ownDomainsCard.value?.reload(),
    brandDomainsCard.value?.reload(),
    providerCard.value?.reload(),
    certSpotterCard.value?.reload(),
  ]);
}

// A manual run changes identities' last-check state; a run with a due email
// domain may also have re-listed the verified domains.
function onCheckRan() {
  void refreshStatus();
  void identitiesCard.value?.reload();
  void providerCard.value?.reloadDomains();
}

// The HIBP key was saved, replaced or removed (or the provider toggled): each
// email domain's verification line belongs to the key, so it is re-read too.
function onProviderChanged() {
  void refreshStatus();
  void identitiesCard.value?.reload();
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

onMounted(refreshStatus);
</script>

<style scoped>
.page-link {
  margin: 0 0 12px;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}

.page-link a,
.counts-link {
  color: var(--el-color-primary);
  text-decoration: none;
}

.page-link a:hover,
.counts-link:hover {
  text-decoration: underline;
}

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
