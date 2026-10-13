<template>
  <!-- Edit how SIEMBox reaches an API-polled source: address (manual sources only),
       port, HTTPS, endpoint path, and the saved token. Admin-only in the API
       (PATCH /log-discovery/sources/:id and the /poller writes), so parents only
       open it for admins. -->
  <el-dialog
    :model-value="modelValue"
    :title="title"
    width="620px"
    class="poll-source-edit-dialog"
    @update:model-value="(open: boolean) => emit('update:modelValue', open)"
    @open="load"
  >
    <div v-loading="loading" class="edit-body">
      <p class="dialog-hint">
        How SIEMBox reaches this source's API. Changing the address or endpoint makes the next poll
        start fresh; the saved token is kept unless you paste a new one.
      </p>

      <div v-if="target" class="current-url" data-test="effective-url">
        <span class="current-label">Polling</span>
        <code>{{ target.effective_url }}</code>
      </div>

      <el-alert
        v-if="poller?.last_status === 'error' && poller.last_error"
        type="error"
        :closable="false"
        show-icon
        title="Last poll failed"
        :description="poller.last_error"
        class="edit-alert"
        data-test="last-error"
      />

      <el-alert
        v-if="!loading && !target"
        type="info"
        :closable="false"
        show-icon
        title="This source has no API pull method to configure."
        class="edit-alert"
      />

      <el-form v-if="target" label-position="top" @submit.prevent>
        <el-form-item label="Address">
          <el-input v-model="form.ip_address" :disabled="!target.manual" data-test="address" />
          <span v-if="target.manual" class="field-hint">
            A literal IP address (not a DNS name). A saved token is never sent to a new address: changing it asks for
            the token again.
          </span>
          <span v-else class="field-hint">
            Found by a scan, so it is polled where the scan found it. Only a manually added source's address can change.
          </span>
        </el-form-item>

        <div class="inline-fields">
          <el-form-item label="Port">
            <el-input-number
              v-model="form.port"
              :min="1"
              :max="65535"
              :step="1"
              step-strictly
              controls-position="right"
              data-test="port"
            />
            <span class="field-hint">Default {{ target.defaults.port }}</span>
          </el-form-item>
          <el-form-item label="Use HTTPS">
            <el-switch v-model="form.tls" data-test="tls" />
            <span class="field-hint">Default {{ target.defaults.tls ? 'on' : 'off' }}</span>
          </el-form-item>
        </div>

        <el-form-item label="Endpoint">
          <el-input
            v-model="form.endpoint"
            :placeholder="target.defaults.endpoint"
            clearable
            data-test="endpoint"
          />
          <span class="field-hint">{{ endpointHint }}</span>
        </el-form-item>

        <el-form-item :label="tokenLabel" :required="tokenRequiredForAddress">
          <div class="token-fields">
            <el-input v-if="basicAuth" v-model="form.username" placeholder="Username" class="token-username" />
            <el-input
              v-model="form.secret"
              type="password"
              show-password
              clearable
              autocomplete="new-password"
              :placeholder="tokenPlaceholder"
              class="token-secret"
              data-test="secret"
            />
          </div>
          <span v-if="isHomeAssistant" class="field-hint">
            A long-lived access token created by a Home Assistant administrator (Profile, Security tab).
          </span>
        </el-form-item>
      </el-form>

      <el-alert
        v-if="errorText"
        type="error"
        :closable="false"
        show-icon
        :title="errorTitle"
        :description="errorText"
        class="edit-alert"
        data-test="save-error"
      />
      <el-alert
        v-if="pollResult"
        :type="pollResult.ok ? 'success' : 'error'"
        :closable="false"
        show-icon
        :title="pollResult.ok ? `Saved and polled: ${pollResult.count} new event(s)` : 'Saved, but the poll failed'"
        :description="pollResult.ok ? undefined : pollResult.error || 'Poll failed'"
        class="edit-alert"
        data-test="poll-result"
      />
    </div>

    <template #footer>
      <el-button @click="emit('update:modelValue', false)">Close</el-button>
      <el-button :loading="saving && !pollingNow" :disabled="!target || saving" data-test="save" @click="save(false)">
        Save
      </el-button>
      <el-button
        type="primary"
        :loading="pollingNow"
        :disabled="!target || saving"
        data-test="save-and-poll"
        @click="save(true)"
      >
        Save and poll now
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, reactive, ref } from 'vue';
import { ElMessage } from 'element-plus';
import logDiscoveryService, {
  type FingerprintEntry,
  type PollNowResult,
  type PollTargetView,
  type PollerStatus,
  type SourceTargetChanges,
} from '@/services/logDiscoveryService';

const props = defineProps<{
  modelValue: boolean;
  /** The source to edit (a row from GET /log-discovery/sources). */
  source: { id: number; ip: string; hostname: string | null; matched_fingerprint_id: string | null } | null;
  fingerprints: FingerprintEntry[];
}>();

const emit = defineEmits<{
  'update:modelValue': [open: boolean];
  /** Something was saved or polled: the parent should reload its list. */
  saved: [];
}>();

const loading = ref(false);
const saving = ref(false);
const pollingNow = ref(false);
const errorTitle = ref('Not saved');
const errorText = ref('');
const pollResult = ref<PollNowResult | null>(null);
const poller = ref<PollerStatus | null>(null);
const target = ref<PollTargetView | null>(null);
const form = reactive({
  ip_address: '',
  port: undefined as number | undefined,
  tls: false,
  endpoint: '',
  username: '',
  secret: '',
});

const fingerprintId = computed(() => target.value?.fingerprint_id ?? props.source?.matched_fingerprint_id ?? null);
const fingerprint = computed(() => props.fingerprints.find((f) => f.id === fingerprintId.value) || null);
const isHomeAssistant = computed(() => fingerprintId.value === 'home-assistant');
// AdGuard Home uses HTTP Basic: a username goes with the secret (as in the Onboard dialog).
const basicAuth = computed(() => fingerprint.value?.log_access.find((la) => la.method === 'api_pull')?.auth === 'basic');

/** A manual source moving to a new address while it has a saved token: the token must come again. */
const tokenRequiredForAddress = computed(() => {
  const view = target.value;
  if (!view?.manual || !poller.value?.configured) return false;
  const ip = form.ip_address.trim();
  return ip !== '' && ip !== view.ip_address;
});
const tokenLabel = computed(() => {
  if (tokenRequiredForAddress.value) return 'Token for the new address';
  return poller.value?.configured ? 'Replace token' : 'Token';
});
const tokenPlaceholder = computed(() => {
  if (tokenRequiredForAddress.value) return 'Required: the saved token is never sent to a new address';
  return poller.value?.configured ? 'Leave empty to keep the saved token' : 'Paste API token…';
});

const title = computed(() => {
  const name = fingerprint.value?.name || 'API-polled source';
  const host = props.source ? props.source.hostname || props.source.ip : '';
  return host ? `Edit ${name}: ${host}` : `Edit ${name}`;
});

const endpointHint = computed(() => {
  if (isHomeAssistant.value) {
    return (
      '/api/error_log on Container/Core installs, /api/hassio/core/logs on Home Assistant OS and Supervised; ' +
      "both need an administrator's long-lived token. Leave empty to try /api/error_log and fall back to " +
      '/api/hassio/core/logs automatically.'
    );
  }
  return `Leave empty for the default (${target.value?.defaults.endpoint}). A path on this host only, e.g. with a reverse-proxy prefix.`;
});

function fillForm(view: PollTargetView | null) {
  target.value = view;
  form.ip_address = view?.ip_address ?? props.source?.ip ?? '';
  form.port = view?.port;
  form.tls = view?.tls ?? false;
  form.endpoint = view?.overrides.endpoint ?? '';
}

async function load() {
  if (!props.source) return;
  loading.value = true;
  errorText.value = '';
  pollResult.value = null;
  form.secret = '';
  form.username = '';
  try {
    poller.value = await logDiscoveryService.getPollerStatus(props.source.id);
    fillForm(poller.value.target ?? null);
  } catch (err) {
    showError('Could not load this source', errorMessage(err));
  } finally {
    loading.value = false;
  }
}

/**
 * Only what changed is sent. On a scan-discovered source, setting a value back
 * to its default clears the override (null), so its URL is exactly the default
 * one again; a manual source always keeps explicit values.
 */
function buildChanges(view: PollTargetView): SourceTargetChanges {
  const changes: SourceTargetChanges = {};
  const ip = form.ip_address.trim();
  if (view.manual && ip !== view.ip_address) changes.ip_address = ip;

  const port = form.port ?? null;
  if (port === null) {
    if (view.overrides.port !== null) changes.port = null;
  } else if (port !== view.port) {
    changes.port = !view.manual && port === view.defaults.port ? null : port;
  }

  if (form.tls !== view.tls) changes.tls = !view.manual && form.tls === view.defaults.tls ? null : form.tls;

  const endpoint = form.endpoint.trim();
  if (endpoint !== (view.overrides.endpoint ?? '')) changes.endpoint = endpoint === '' ? null : endpoint;
  return changes;
}

function showError(title: string, message: string) {
  errorTitle.value = title;
  errorText.value = message;
}

/** The API's own message (e.g. a 400's validation reason), else the client error's. */
function errorMessage(err: unknown): string {
  const e = err as { response?: { data?: { message?: string } }; message?: string } | null;
  return e?.response?.data?.message || e?.message || 'Request failed';
}

async function save(pollNow: boolean) {
  const view = target.value;
  if (!props.source || !view) return;
  const id = props.source.id;
  const secret = form.secret.trim();
  errorText.value = '';
  pollResult.value = null;

  if (secret && basicAuth.value && !form.username.trim()) {
    return showError('Not saved', 'This device type needs a username with the token.');
  }
  if (pollNow && !poller.value?.configured && !secret) {
    return showError('Not saved', 'Paste a token first: this source has no saved token to poll with.');
  }
  const tokenWithMove = tokenRequiredForAddress.value;
  if (tokenWithMove && !secret) {
    return showError(
      'Not saved',
      'Paste the token for the new address. A saved token is never sent to a new address, so moving this source needs it again.'
    );
  }

  const changes = buildChanges(view);
  if (tokenWithMove && changes.ip_address !== undefined) {
    // Sent with the move so the server swaps it in the same update.
    changes.credential = basicAuth.value ? { secret, username: form.username.trim() } : { secret };
  }
  const changed = Object.keys(changes).length > 0;
  // Which step failed decides what the error says was (not) saved.
  let step: 'target' | 'token' | 'poll' = 'target';
  saving.value = true;
  pollingNow.value = pollNow;
  try {
    // The address this dialog showed. Both saves apply only while the source
    // still has it (else 409), so nothing typed here reaches a source another
    // admin moved in the meantime, and a token goes only to the address it was
    // entered for.
    let address = view.ip_address;
    if (changed) {
      const updated = await logDiscoveryService.updateSourceTarget(id, { ...changes, expected_ip_address: address });
      fillForm(updated.target);
      address = updated.source.ip_address; // the address just saved, which a token typed with it is for
      emit('saved');
    }
    step = 'token';
    if (changes.credential) {
      // Already saved with the address change.
      form.secret = '';
    } else if (secret) {
      await logDiscoveryService.savePollerCredential(id, secret, basicAuth.value ? form.username.trim() : undefined, {
        quiet: true,
        expectedIpAddress: address,
      });
      form.secret = '';
      emit('saved');
    }
    step = 'poll';
    if (pollNow) {
      pollResult.value = await logDiscoveryService.runPollNow(id, { quiet: true });
      emit('saved');
    } else if (changed || secret) {
      ElMessage.success('Saved. The next poll uses these settings.');
    } else {
      ElMessage.info('Nothing changed.');
    }
    // Reflect what was stored and the latest poll (a Home Assistant poll may have
    // switched to its Supervisor endpoint), keeping the poll result shown.
    poller.value = await logDiscoveryService.getPollerStatus(id);
    fillForm(poller.value.target ?? null);
  } catch (err) {
    const message = errorMessage(err);
    if (step === 'target') showError('Not saved', message);
    else if (step === 'token') {
      showError('Token not saved', changed ? `The connection settings were saved, but the token was not: ${message}` : message);
    } else showError('Saved, but the poll did not run', message);
  } finally {
    saving.value = false;
    pollingNow.value = false;
  }
}
</script>

<style scoped>
.dialog-hint {
  color: var(--el-text-color-secondary);
  font-size: 13px;
  margin: 0 0 12px;
}
.current-url {
  display: flex;
  align-items: baseline;
  gap: 8px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.current-label {
  font-weight: 600;
}
.current-url code {
  font-size: 12px;
  word-break: break-all;
  background: var(--el-fill-color-light);
  padding: 2px 6px;
  border-radius: 4px;
}
.edit-alert {
  margin-bottom: 12px;
}
.edit-alert :deep(.el-alert__description) {
  white-space: pre-wrap;
  word-break: break-word;
}
.inline-fields {
  display: flex;
  gap: 32px;
  flex-wrap: wrap;
}
.field-hint {
  display: block;
  color: var(--el-text-color-secondary);
  font-size: 12px;
  line-height: 1.4;
  margin-top: 2px;
  width: 100%;
}
.token-fields {
  display: flex;
  gap: 8px;
  width: 100%;
}
.token-username {
  width: 160px;
}
.token-secret {
  flex: 1;
}
</style>
