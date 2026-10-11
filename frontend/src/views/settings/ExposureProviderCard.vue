<template>
  <el-card>
    <template #header>
      <div class="card-header">
        <span>
          Have I Been Pwned
          <HelpTip text="Breach searches use your own HIBP API key (an HIBP subscription). The key is stored encrypted with CREDENTIAL_ENCRYPTION_KEY and is write-only: no screen or API ever shows it again, so this field always starts empty." />
        </span>
        <div class="header-tags" v-if="provider">
          <el-tag size="small" :type="provider.configured ? 'success' : 'warning'">
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
  </el-card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import HelpTip from '@/components/HelpTip.vue';
import exposureService, { type ExposureProvider } from '@/services/exposureService';
import {
  HIBP_API_KEY_URL,
  apiErrorMessage,
  formatWhen,
  isEncryptionKeyError,
  normalizeHibpKey,
} from '@/utils/exposure';

defineProps<{
  /** The 400 message from a key save that hit a missing CREDENTIAL_ENCRYPTION_KEY, if any. */
  encryptionError: string | null;
}>();

const emit = defineEmits<{
  (e: 'changed'): void;
  (e: 'encryption-error', message: string | null): void;
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

async function reload(showLoading = false) {
  if (showLoading) loading.value = true;
  try {
    const providers = await exposureService.getProviders();
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
    if (s.includes_stealer_logs !== null) lines.push(`Stealer logs: ${s.includes_stealer_logs ? 'included' : 'not included'}`);
    if (s.subscribed_until) lines.push(`Subscribed until: ${formatWhen(s.subscribed_until, s.subscribed_until)}`);
    testResult.value = { ok: true, lines };
  } catch (error) {
    testResult.value = { ok: false, message: apiErrorMessage(error, 'The key could not be tested') };
  } finally {
    testing.value = false;
  }
}

onMounted(() => reload(true));

defineExpose({ reload });
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
</style>
