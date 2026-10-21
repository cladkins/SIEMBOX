<template>
  <el-card>
    <template #header>
      <div class="card-header">
        <span>
          Certificate Transparency fallback (Cert Spotter)
          <HelpTip text="Certificate monitoring asks crt.sh first. When crt.sh is down or overloaded (or can't answer for a very large domain), the same names are asked of SSLMate's Cert Spotter. An API key is optional: it is stored encrypted with CREDENTIAL_ENCRYPTION_KEY and is write-only, so this field always starts empty." />
        </span>
        <div class="header-tags" v-if="provider">
          <el-tag v-if="provider.configured && !provider.usable" size="small" type="danger">
            Saved key can’t be decrypted
          </el-tag>
          <el-tag v-else size="small" :type="provider.configured ? 'success' : 'info'">
            {{ provider.configured ? 'Key configured' : 'No key — free limit' }}
          </el-tag>
          <el-tag v-if="rateLimitedLabel" size="small" type="warning" effect="plain">Rate-limited</el-tag>
        </div>
      </div>
    </template>

    <p class="card-intro">
      Used automatically when crt.sh fails, so new certificates are still seen while it is down.
      Without a key Cert Spotter allows only a few queries an hour, which a busy domain or several watched
      domains can use up.
      <a :href="provider?.signupUrl ?? CERTSPOTTER_SIGNUP_URL" target="_blank" rel="noopener noreferrer">
        Get a Cert Spotter API key
      </a>
      for a higher limit.
    </p>

    <el-alert
      v-if="rateLimitedLabel"
      type="warning"
      show-icon
      :closable="false"
      class="card-alert"
      :title="`Cert Spotter is rate-limiting requests until ${rateLimitedLabel}`"
      :description="provider?.configured ? 'Certificate checks that need the fallback are retried after that.' : 'Certificate checks that need the fallback are retried after that. An API key raises the limit.'"
    />

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
      <el-form-item :label="provider?.configured ? 'Replace key' : 'API key'" :error="keyError">
        <el-input
          v-model="apiKey"
          type="password"
          show-password
          autocomplete="new-password"
          :placeholder="provider?.configured ? 'Key configured — paste a new key to replace it' : 'Optional Cert Spotter API key'"
          :disabled="busy"
          aria-label="Cert Spotter API key"
          style="width: 360px"
          @input="keyError = ''"
        />
      </el-form-item>

      <el-form-item>
        <el-button type="primary" native-type="submit" :loading="saving" :disabled="!apiKey.trim() || (busy && !saving)">
          Save key
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
  </el-card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import HelpTip from '@/components/HelpTip.vue';
import exposureService, { type CertSpotterProvider } from '@/services/exposureService';
import { apiErrorMessage, formatWhen, isEncryptionKeyError } from '@/utils/exposure';

const CERTSPOTTER_SIGNUP_URL = 'https://sslmate.com/signup?for=ct_search_api';
// The backend's rule (token68 characters), checked here first for a clear message.
const KEY_RE = /^[A-Za-z0-9._~+/-]{8,256}$/;

const emit = defineEmits<{ (e: 'changed'): void }>();

const provider = ref<CertSpotterProvider | null>(null);
const loading = ref(false);
// Only what the admin typed in this session: the stored key is never fetched (the API can't return it).
const apiKey = ref('');
const keyError = ref('');
const saving = ref(false);
const removing = ref(false);
const encryptionError = ref<string | null>(null);
const busy = computed(() => saving.value || removing.value);

const rateLimitedLabel = computed(() => {
  const until = provider.value?.rate_limited_until;
  return until && Date.parse(until) > Date.now() ? formatWhen(until, until) : '';
});

async function reload(showLoading = false) {
  if (showLoading) loading.value = true;
  try {
    provider.value = await exposureService.getCertSpotterProvider();
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, 'Failed to load the Cert Spotter settings'));
  } finally {
    loading.value = false;
  }
}

async function saveKey() {
  const key = apiKey.value.trim();
  if (!KEY_RE.test(key)) {
    keyError.value = 'A Cert Spotter API key is 8–256 letters, digits or . _ ~ + / - (no spaces).';
    return;
  }
  const replacing = !!provider.value?.configured;
  saving.value = true;
  try {
    // The response is the public view (configured or not), never the key.
    provider.value = await exposureService.saveCertSpotterKey(key);
    apiKey.value = '';
    encryptionError.value = null;
    ElMessage.success(replacing ? 'Cert Spotter key replaced' : 'Cert Spotter key saved');
    emit('changed');
  } catch (error) {
    const message = apiErrorMessage(error, 'Failed to save the Cert Spotter key');
    if (isEncryptionKeyError(error)) encryptionError.value = message;
    ElMessage.error(message);
  } finally {
    saving.value = false;
  }
}

async function removeKey() {
  try {
    await ElMessageBox.confirm(
      'Remove the saved Cert Spotter API key? Cert Spotter is still used when crt.sh fails, within its small unauthenticated limit.',
      'Remove Cert Spotter key',
      { confirmButtonText: 'Remove key', cancelButtonText: 'Cancel', type: 'warning' }
    );
  } catch {
    return; // cancelled
  }
  removing.value = true;
  try {
    provider.value = await exposureService.removeCertSpotterKey();
    ElMessage.success('Cert Spotter key removed');
    emit('changed');
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, 'Failed to remove the Cert Spotter key'));
  } finally {
    removing.value = false;
  }
}

defineExpose({ reload });
onMounted(() => reload(true));
</script>

<style scoped>
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.header-tags {
  display: flex;
  gap: 6px;
}

.card-intro {
  margin: 0 0 16px;
  font-size: 13px;
  line-height: 1.5;
  color: var(--el-text-color-regular);
}

.card-intro a {
  color: var(--el-color-primary);
}

.card-alert {
  margin-bottom: 16px;
}
</style>
