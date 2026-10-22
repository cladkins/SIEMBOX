<template>
  <el-card class="public-url-card">
    <template #header>
      <div class="card-header">
        <span>Public URL <HelpTip text="Notifications (Email, Slack, NTFY) link straight to the alert at this address. SIEMBox builds links only from this saved value plus fixed paths, never from the address a request came in on. Leave it empty for no links: notifications then carry the alert reference (ALR-1234) only. The SIEMBOX_PUBLIC_URL environment variable sets it too; a value saved here wins." /></span>
      </div>
    </template>

    <el-form label-position="top" v-loading="loading" @submit.prevent="save">
      <el-form-item label="Public URL" :error="fieldError">
        <div class="url-row">
          <el-input
            v-model="draft"
            placeholder="https://siem.example.com"
            clearable
            maxlength="2048"
            data-testid="public-url-input"
            @input="fieldError = ''"
          />
          <el-button @click="useBrowserAddress" data-testid="public-url-use-browser">Use this browser's address</el-button>
        </div>
        <el-text size="small" type="info" class="help">
          The address people use to open SIEMBox in a browser, e.g. https://siem.example.com. Used for links in notifications.
        </el-text>
      </el-form-item>

      <el-form-item>
        <el-button type="primary" native-type="submit" :loading="saving" :disabled="!dirty" data-testid="public-url-save">
          Save
        </el-button>
        <el-button :disabled="!config?.public_url || saving" @click="clear" data-testid="public-url-clear">
          Clear (no links)
        </el-button>
      </el-form-item>
    </el-form>

    <el-alert v-if="config?.env_error" type="warning" :closable="false" show-icon class="note">
      {{ config.env_error }}
    </el-alert>

    <div v-if="config" class="preview" data-testid="public-url-preview">
      <div class="source-text">{{ sourceText }}</div>
      <div v-if="previewLink" class="preview-link">
        <el-text size="small" type="info">Test link (a notification for alert ALR-{{ PREVIEW_ALERT_ID }} links here):</el-text>
        <a :href="previewLink" target="_blank" rel="noopener noreferrer" data-testid="public-url-test-link">{{ previewLink }}</a>
      </div>
      <el-text v-if="dirty" size="small" type="warning">Unsaved: the preview shows the saved value.</el-text>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { ElMessage } from 'element-plus';
import { api } from '@/services/api';
import HelpTip from '@/components/HelpTip.vue';
import {
  PREVIEW_ALERT_ID,
  browserPublicUrl,
  previewAlertLink,
  publicUrlSourceText,
  type PublicUrlConfig,
} from '@/utils/publicUrl';

const loading = ref(false);
const saving = ref(false);
const config = ref<PublicUrlConfig | null>(null);
const draft = ref('');
const fieldError = ref('');

const dirty = computed(() => draft.value.trim() !== (config.value?.public_url ?? ''));
// Rendered as a link only from the server's validated value, never the draft.
const previewLink = computed(() => previewAlertLink(config.value?.effective_public_url ?? ''));
const sourceText = computed(() => (config.value ? publicUrlSourceText(config.value) : ''));

function apply(next: PublicUrlConfig) {
  config.value = next;
  draft.value = next.public_url;
}

async function load() {
  loading.value = true;
  try {
    apply((await api.getPublicUrl()).data);
  } catch {
    ElMessage.error('Failed to load the public URL');
  } finally {
    loading.value = false;
  }
}

function useBrowserAddress() {
  draft.value = browserPublicUrl(window.location.origin, import.meta.env.BASE_URL);
  fieldError.value = '';
}

async function put(value: string, done: string) {
  saving.value = true;
  try {
    apply((await api.updatePublicUrl(value)).data);
    fieldError.value = '';
    ElMessage.success(done);
  } catch (error: any) {
    const message = error.response?.data?.message || 'Failed to save the public URL';
    if (error.response?.status === 400) fieldError.value = message;
    else ElMessage.error(message);
  } finally {
    saving.value = false;
  }
}

function save() {
  if (!dirty.value) return;
  const value = draft.value.trim();
  void put(value, value ? 'Public URL saved' : 'Public URL cleared');
}

function clear() {
  draft.value = '';
  void put('', 'Public URL cleared');
}

onMounted(load);
</script>

<style scoped>
.public-url-card {
  margin-bottom: 20px;
}
.url-row {
  display: flex;
  gap: 8px;
  width: 100%;
  flex-wrap: wrap;
}
.url-row .el-input {
  flex: 1 1 320px;
  max-width: 560px;
}
.help {
  display: block;
  width: 100%;
  margin-top: 4px;
}
.note {
  margin-bottom: 12px;
}
.preview {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 4px;
}
.source-text {
  font-size: 13px;
  color: var(--el-text-color-regular);
}
.preview-link a {
  display: block;
  word-break: break-all;
  font-size: 13px;
}
</style>
