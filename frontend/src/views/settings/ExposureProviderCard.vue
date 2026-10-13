<template>
  <el-card>
    <template #header>
      <div class="card-header">
        <span>
          Have I Been Pwned
          <HelpTip text="Breach searches use your own HIBP API key (an HIBP subscription). The key is stored encrypted with CREDENTIAL_ENCRYPTION_KEY and is write-only: no screen or API ever shows it again, so this field always starts empty." />
        </span>
        <div class="header-tags" v-if="provider">
          <el-tag v-if="provider.configured && provider.usable === false" size="small" type="danger">
            Saved key can’t be decrypted
          </el-tag>
          <el-tag v-else size="small" :type="provider.configured ? 'success' : 'warning'">
            {{ provider.configured ? 'Key configured' : 'No key saved' }}
          </el-tag>
          <el-tag size="small" :type="provider.enabled ? 'success' : 'info'" effect="plain">
            {{ provider.enabled ? 'Enabled' : 'Disabled' }}
          </el-tag>
        </div>
      </div>
    </template>

    <p class="card-intro">
      Checks for the identities above need an HIBP API key.
      <a :href="HIBP_API_KEY_URL" target="_blank" rel="noopener noreferrer">Get an HIBP API key</a>
      — then paste it here. The password check below works without one.
    </p>

    <el-alert
      v-if="encryptionError"
      type="error"
      show-icon
      :closable="false"
      class="card-alert"
      title="The server can't store API keys: CREDENTIAL_ENCRYPTION_KEY is missing or invalid"
      :description="encryptionError"
    />

    <el-form label-width="150px" v-loading="loading" @submit.prevent="saveKey">
      <el-form-item label="Enabled">
        <el-switch
          :model-value="provider?.enabled ?? false"
          :loading="toggling"
          :disabled="!provider || (busy && !toggling)"
          aria-label="Enable Have I Been Pwned"
          @change="(value: string | number | boolean) => setEnabled(value === true)"
        />
        <el-text size="small" type="info" class="inline-hint">
          Breach checks run only while the provider is enabled and a key is saved.
        </el-text>
      </el-form-item>

      <el-form-item :label="provider?.configured ? 'Replace key' : 'API key'" :error="keyError">
        <el-input
          v-model="apiKey"
          type="password"
          show-password
          autocomplete="new-password"
          :placeholder="provider?.configured ? 'Key configured — paste a new key to replace it' : '32-character hex API key'"
          :disabled="busy"
          aria-label="HIBP API key"
          style="width: 360px"
          @input="onKeyInput"
        />
      </el-form-item>

      <el-form-item>
        <el-button type="primary" native-type="submit" :loading="saving" :disabled="!apiKey.trim() || (busy && !saving)">
          Save key
        </el-button>
        <el-button
          :loading="testing"
          :disabled="(busy && !testing) || (!apiKey.trim() && !provider?.configured)"
          @click="testKey"
        >
          Test key
        </el-button>
        <el-button
          v-if="provider?.configured"
          type="danger"
          plain
          :loading="removing"
          :disabled="busy && !removing"
          @click="removeKey"
        >
          Remove key
        </el-button>
      </el-form-item>
    </el-form>

    <el-alert
      v-if="testResult"
      :type="testResult.ok ? 'success' : 'error'"
      show-icon
      :closable="false"
      class="card-alert"
      :title="testResult.ok ? 'HIBP accepted the key' : 'Key test failed'"
    >
      <template v-if="testResult.ok">
        <div v-for="line in testResult.lines" :key="line">{{ line }}</div>
      </template>
      <template v-else>{{ testResult.message }}</template>
    </el-alert>

    <el-text size="small" type="info">
      <strong>Test key</strong> checks the key typed above, or the saved key when the field is empty, with
      HIBP's subscription-status call; nothing is saved. HIBP's public test key (32 zeros) always fails
      this check by design, even though breach searches accept it for HIBP's test accounts.
    </el-text>

    <!-- Which email domains HIBP will search for this key (its verified domains). Read from what the
         backend last stored: opening this page never calls HIBP; Re-check does. -->
    <el-divider content-position="left">Domain search</el-divider>
    <div v-loading="domainsLoading && !domainsView" class="domain-search">
      <el-alert
        v-if="domainsLoadError"
        type="error"
        show-icon
        :closable="false"
        :title="`Couldn't load the verified-domain status: ${domainsLoadError}`"
      >
        <el-button link type="primary" size="small" @click="loadDomains()">Try again</el-button>
      </el-alert>
      <template v-else-if="domainsView">
        <el-alert v-if="domainsAlert" :type="domainsAlert.type" show-icon :closable="false" class="card-alert">
          <p class="alert-text">{{ domainsAlert.text }}</p>
          <div v-if="domainsAlert.actions.length" class="alert-actions">
            <a
              v-if="domainsAlert.actions.includes('dashboard')"
              :href="HIBP_DOMAINS_DASHBOARD_URL"
              target="_blank"
              rel="noopener noreferrer"
            >Open HIBP dashboard ↗</a>
            <a
              v-if="domainsAlert.actions.includes('plans')"
              :href="HIBP_PRICING_URL"
              target="_blank"
              rel="noopener noreferrer"
            >HIBP plans ↗</a>
            <el-button
              v-if="domainsAlert.actions.includes('test_key')"
              size="small"
              :loading="testing"
              :disabled="busy && !testing"
              @click="testKey"
            >
              Test key
            </el-button>
            <!-- With a table below, its own Re-check button is the one to use. -->
            <el-tooltip
              v-if="domainsAlert.actions.includes('recheck') && !hasDomainRows"
              :disabled="!recheckWaitLabel"
              :content="recheckWaitLabel"
              placement="top"
            >
              <span>
                <el-button size="small" type="primary" :loading="rechecking" :disabled="!!recheckWaitLabel" @click="recheck()">
                  Re-check with HIBP
                </el-button>
              </span>
            </el-tooltip>
          </div>
        </el-alert>

        <template v-if="domainsView.domains && hasDomainRows">
          <el-table :data="domainsView.domains" size="small" stripe class="domains-table">
            <el-table-column label="Domain" min-width="200" prop="domain" />
            <el-table-column label="Breached addresses (HIBP)" min-width="170">
              <template #default="{ row }">{{ countLabel(row.pwn_count) }}</template>
            </el-table-column>
            <el-table-column label="Plan coverage" min-width="140">
              <template #default="{ row }">
                <el-tag v-if="row.within_plan === true" type="success" size="small" effect="plain">Covered</el-tag>
                <el-tooltip
                  v-else-if="row.within_plan === false"
                  :content="planLimitTooltip(row, domainsView.plan)"
                  placement="top"
                >
                  <el-tag type="warning" size="small">May be limited</el-tag>
                </el-tooltip>
                <span v-else class="muted">—</span>
              </template>
            </el-table-column>
            <el-table-column label="In SIEMBox" min-width="130">
              <template #default="{ row }">
                <el-tag v-if="row.identity_id !== null" type="info" size="small" effect="plain">Monitored</el-tag>
                <el-button
                  v-else
                  size="small"
                  :loading="monitoring === row.domain"
                  :disabled="monitoring !== null && monitoring !== row.domain"
                  @click="monitor(row.domain)"
                >
                  Monitor
                </el-button>
              </template>
            </el-table-column>
          </el-table>
          <p class="domains-meta">{{ domainsMeta }}</p>
          <p v-if="domainsIncomplete" class="domains-meta">
            HIBP lists more domains than SIEMBox shows (2,000), or some entries were unreadable; domains not shown
            are searched directly.
          </p>
          <div class="alert-actions">
            <el-tooltip :disabled="!recheckWaitLabel" :content="recheckWaitLabel" placement="top">
              <span>
                <el-button size="small" :loading="rechecking" :disabled="!!recheckWaitLabel" @click="recheck()">
                  Re-check
                </el-button>
              </span>
            </el-tooltip>
            <a :href="HIBP_DOMAINS_DASHBOARD_URL" target="_blank" rel="noopener noreferrer">Verify another domain ↗</a>
          </div>
          <!-- The breached-address counts are HIBP data. -->
          <HibpAttribution />
        </template>
      </template>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import HelpTip from '@/components/HelpTip.vue';
import HibpAttribution from '@/components/HibpAttribution.vue';
import exposureService, {
  type ExposureProvider,
  type HibpVerifiedDomainsView,
} from '@/services/exposureService';
import {
  HIBP_API_KEY_URL,
  HIBP_DOMAINS_DASHBOARD_URL,
  HIBP_PRICING_URL,
  apiErrorMessage,
  formatRelative,
  formatWhen,
  identityAddedMessage,
  isEncryptionKeyError,
  normalizeHibpKey,
  planLimitTooltip,
  refreshFailureMessage,
  refreshOutcomeMessage,
  verifiedDomainsAlert,
} from '@/utils/exposure';

defineProps<{
  /** The 400 message from a key save that hit a missing CREDENTIAL_ENCRYPTION_KEY, if any. */
  encryptionError: string | null;
}>();

const emit = defineEmits<{
  (e: 'changed'): void;
  (e: 'encryption-error', message: string | null): void;
  /** HIBP was asked which domains are verified: the page reloads what depends on it. */
  (e: 'domains-refreshed'): void;
  /** A verified domain was added as a monitored identity. */
  (e: 'identities-changed'): void;
}>();

const provider = ref<ExposureProvider | null>(null);
const loading = ref(false);

// The key field only ever holds what the admin typed in this session; the
// stored key is never fetched (the API can't return it), so it starts empty.
const apiKey = ref('');
const keyError = ref('');
const saving = ref(false);
const toggling = ref(false);
const testing = ref(false);
const removing = ref(false);
const busy = computed(() => saving.value || toggling.value || testing.value || removing.value);

type TestResult = { ok: true; lines: string[] } | { ok: false; message: string };
const testResult = ref<TestResult | null>(null);

// ---- Domain search (the key's verified domains) ----
const domainsView = ref<HibpVerifiedDomainsView | null>(null);
const domainsLoading = ref(false);
const domainsLoadError = ref<string | null>(null);
const rechecking = ref(false);
const monitoring = ref<string | null>(null);
const domainsAlert = computed(() => (domainsView.value ? verifiedDomainsAlert(domainsView.value) : null));
const hasDomainRows = computed(() => (domainsView.value?.domains?.length ?? 0) > 0);
const domainsIncomplete = computed(
  () => !!domainsView.value && (domainsView.value.truncated || domainsView.value.skipped_entries > 0)
);
// Ticks while a re-check is on cooldown, so the button comes back on its own.
const now = ref(Date.now());
let clock: ReturnType<typeof setInterval> | null = null;
const recheckWaitLabel = computed(() => {
  const at = domainsView.value?.next_refresh_allowed_at;
  if (!at || Date.parse(at) <= now.value) return '';
  return `Available ${formatRelative(at)}`;
});

const domainsMeta = computed(() => {
  const view = domainsView.value;
  if (!view) return '';
  const parts = [`As of ${formatWhen(view.listed_at, 'unknown')}.`];
  const plan = view.plan;
  if (plan) {
    const details = [`Plan: ${plan.name ?? 'unknown'}`];
    if (plan.domain_search_max_breached_accounts !== null) {
      details.push(`searches domains up to ${plan.domain_search_max_breached_accounts.toLocaleString()} breached addresses`);
    }
    details.push(
      plan.max_breached_domains !== null
        ? `up to ${plan.max_breached_domains.toLocaleString()} domains`
        : 'no limit on the number of domains'
    );
    parts.push(`${details.join(' · ')}.`);
  }
  return parts.join(' ');
});

const countLabel = (n: number | null) => (n === null ? 'Not searched yet' : n.toLocaleString());

async function loadDomains(showLoading = true) {
  if (showLoading) domainsLoading.value = true;
  try {
    domainsView.value = await exposureService.getHibpVerifiedDomains();
    domainsLoadError.value = null;
  } catch (error) {
    domainsLoadError.value = apiErrorMessage(error, 'the request failed');
  } finally {
    domainsLoading.value = false;
  }
}

/** Re-check with HIBP: toasts the outcome. `quiet`: best effort after a key save, no toasts. */
async function recheck(quiet = false) {
  if (rechecking.value) return;
  rechecking.value = true;
  try {
    const result = await exposureService.refreshHibpVerifiedDomains();
    domainsView.value = result;
    domainsLoadError.value = null;
    if (!quiet) {
      const outcome = refreshOutcomeMessage(result);
      ElMessage({ type: outcome.type, message: outcome.message });
    }
    emit('domains-refreshed');
  } catch (error) {
    if (!quiet) ElMessage.error(refreshFailureMessage(error));
    void loadDomains(false);
  } finally {
    rechecking.value = false;
  }
}

/** Monitor a verified domain: it is verified, so this stays within HIBP's ownership rule. */
async function monitor(domain: string) {
  monitoring.value = domain;
  try {
    const created = await exposureService.addIdentity({ kind: 'email_domain', value: domain });
    ElMessage.success(identityAddedMessage(domain, null, created.hibp_domain));
    emit('identities-changed');
    await loadDomains(false);
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, `Failed to monitor ${domain}`));
  } finally {
    monitoring.value = null;
  }
}

async function reload(showLoading = false) {
  if (showLoading) loading.value = true;
  try {
    const [providers] = await Promise.all([exposureService.getProviders(), loadDomains(showLoading)]);
    provider.value = providers.find((p) => p.name === 'hibp') ?? null;
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, 'Failed to load the HIBP provider'));
  } finally {
    loading.value = false;
  }
}

function onKeyInput() {
  keyError.value = '';
  testResult.value = null;
}

async function saveKey() {
  const checked = normalizeHibpKey(apiKey.value);
  if (!checked.ok) {
    keyError.value = checked.error;
    return;
  }
  // The first key switches the provider on (that's why it was entered); a
  // replacement leaves the enabled flag as the admin set it.
  const firstKey = !provider.value?.configured;
  saving.value = true;
  try {
    // The response is the provider's public view (configured/enabled), never the key.
    provider.value = await exposureService.saveHibpKey(checked.value, firstKey ? true : undefined);
    apiKey.value = '';
    testResult.value = null;
    emit('encryption-error', null);
    ElMessage.success(firstKey ? 'HIBP key saved and the provider enabled' : 'HIBP key replaced');
    emit('changed');
    // The new key's verified domains: asked once, best effort and quietly (the save itself succeeded).
    await loadDomains(false);
    void recheck(true);
  } catch (error) {
    const message = apiErrorMessage(error, 'Failed to save the HIBP key');
    if (isEncryptionKeyError(error)) emit('encryption-error', message);
    ElMessage.error(message);
  } finally {
    saving.value = false;
  }
}

async function setEnabled(enabled: boolean) {
  toggling.value = true;
  try {
    provider.value = await exposureService.setHibpEnabled(enabled);
    ElMessage.success(`Have I Been Pwned ${enabled ? 'enabled' : 'disabled'}`);
    emit('changed');
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, 'Failed to update the HIBP provider'));
  } finally {
    toggling.value = false;
  }
}

async function removeKey() {
  try {
    await ElMessageBox.confirm(
      'Remove the saved HIBP API key? Breach checks stop until a new key is saved. Existing findings are kept.',
      'Remove HIBP key',
      { confirmButtonText: 'Remove key', cancelButtonText: 'Cancel', type: 'warning' }
    );
  } catch {
    return; // cancelled
  }
  removing.value = true;
  try {
    provider.value = await exposureService.removeHibpKey();
    testResult.value = null;
    ElMessage.success('HIBP key removed');
    emit('changed');
    void loadDomains(false);
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, 'Failed to remove the HIBP key'));
  } finally {
    removing.value = false;
  }
}

async function testKey() {
  const typed = apiKey.value.trim();
  if (typed) {
    const checked = normalizeHibpKey(typed);
    if (!checked.ok) {
      keyError.value = checked.error;
      return;
    }
  }
  testing.value = true;
  testResult.value = null;
  try {
    const { subscription: s } = await exposureService.testHibpKey(typed || undefined);
    const lines = [`Plan: ${s.name ?? 'unknown'}${s.description ? ` (${s.description})` : ''}`];
    if (s.rpm !== null) lines.push(`Rate limit: ${s.rpm} requests per minute`);
    if (s.domain_search_max_breached_accounts !== null) {
      lines.push(`Domain search: up to ${s.domain_search_max_breached_accounts.toLocaleString()} breached accounts per domain`);
    }
    if (typeof s.max_breached_domains === 'number') {
      lines.push(`Verified domains: up to ${s.max_breached_domains.toLocaleString()}`);
    } else if (s.max_breached_domains === null) {
      lines.push('Verified domains: no maximum');
    }
    if (s.includes_stealer_logs !== null) lines.push(`Stealer logs: ${s.includes_stealer_logs ? 'included' : 'not included'}`);
    if (s.subscribed_until) lines.push(`Subscribed until: ${formatWhen(s.subscribed_until, s.subscribed_until)}`);
    testResult.value = { ok: true, lines };
  } catch (error) {
    testResult.value = { ok: false, message: apiErrorMessage(error, 'The key could not be tested') };
  } finally {
    testing.value = false;
  }
}

onMounted(() => {
  void reload(true);
  clock = setInterval(() => (now.value = Date.now()), 5_000);
});
onBeforeUnmount(() => {
  if (clock) clearInterval(clock);
});

defineExpose({ reload, reloadDomains: () => loadDomains(false) });
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-tags {
  display: flex;
  gap: 6px;
}

.card-intro {
  margin: 0 0 12px;
  font-size: 13px;
  color: var(--el-text-color-regular);
}

.card-intro a {
  color: var(--el-color-primary);
}

.card-alert {
  margin-bottom: 15px;
}

.inline-hint {
  margin-left: 10px;
}

.domain-search {
  min-height: 40px;
}

.alert-text {
  margin: 0;
  line-height: 1.5;
}

.alert-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
  margin-top: 8px;
  font-size: 13px;
}

.alert-actions a {
  color: var(--el-color-primary);
}

.domains-table {
  margin-bottom: 8px;
}

.domains-meta {
  margin: 4px 0;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.muted {
  color: var(--el-text-color-secondary);
}
</style>
