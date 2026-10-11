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
        <el-button link type="primary" size="small" @click="refreshStatus">Try again</el-button>
      </el-alert>
      <el-alert v-else-if="banner" :type="banner.type" show-icon :closable="false" :title="banner.title">
        <p class="banner-line">{{ banner.detail }}</p>
        <p v-if="countsLine" class="banner-line banner-counts">
          {{ countsLine }}
          <el-button link type="primary" size="small" :loading="statusLoading" @click="refreshStatus">Refresh</el-button>
        </p>
      </el-alert>
    </div>

    <ExposureDomainsCard scope="own" :domain-monitor-available="domainMonitorAvailable" @changed="refreshStatus" />
    <ExposureIdentitiesCard ref="identitiesCard" class="section" @changed="refreshStatus" />
    <ExposureDomainsCard
      scope="brand"
      class="section"
      :domain-monitor-available="domainMonitorAvailable"
      @changed="refreshStatus"
    />
    <ExposureProviderCard
      class="section"
      :encryption-error="encryptionError"
      @changed="refreshStatus"
      @encryption-error="encryptionError = $event"
    />
    <ExposureChecksCard class="section" @changed="refreshStatus" @ran="onCheckRan" />
    <ExposureFindingsCard ref="findingsCard" class="section" @changed="refreshStatus" />
    <PasswordCheckCard class="section" />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import exposureService, { EXPOSURE_SEVERITIES, type ExposureStatus } from '@/services/exposureService';
import { apiErrorMessage, describeExposureStatus, pluralize } from '@/utils/exposure';
import ExposureChecksCard from './ExposureChecksCard.vue';
import ExposureDomainsCard from './ExposureDomainsCard.vue';
import ExposureFindingsCard from './ExposureFindingsCard.vue';
import ExposureIdentitiesCard from './ExposureIdentitiesCard.vue';
import ExposureProviderCard from './ExposureProviderCard.vue';
import PasswordCheckCard from './PasswordCheckCard.vue';

// Each card loads and writes its own slice of /api/exposure (through the same
// client the onboarding checklist uses) and emits `changed` after a write, so
// the page only owns the status banner.
const status = ref<ExposureStatus | null>(null);
const statusLoading = ref(false);
const statusError = ref<string | null>(null);
// The API can't report a missing CREDENTIAL_ENCRYPTION_KEY up front; the
// provider card hands over the 400 message when a key save runs into it.
const encryptionError = ref<string | null>(null);

const identitiesCard = ref<InstanceType<typeof ExposureIdentitiesCard> | null>(null);
const findingsCard = ref<InstanceType<typeof ExposureFindingsCard> | null>(null);

const banner = computed(() => (status.value ? describeExposureStatus(status.value, encryptionError.value) : null));
const domainMonitorAvailable = computed(() => status.value?.features.domain_monitor_available ?? false);

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

// A manual run changes identities' last-check state and may add findings.
function onCheckRan() {
  void refreshStatus();
  void identitiesCard.value?.reload();
  void findingsCard.value?.reload();
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
