<template>
  <!-- Admin-only inline setup for the onboarding checklist. It writes through the
       same exposure client as Settings → Digital Risk, so both show the same data. -->
  <div v-loading="loading" class="dr-quick-setup">
    <el-form label-width="170px" label-position="left" size="small" @submit.prevent>
      <el-form-item label="Owned domain" :error="errors.own">
        <div class="qs-row">
          <el-input
            v-model="inputs.own"
            placeholder="example.com"
            aria-label="Owned domain to watch"
            :disabled="saving !== null"
            style="width: 260px"
            @input="errors.own = ''"
            @keyup.enter="addDomain('own')"
          />
          <el-button :loading="saving === 'own'" :disabled="!inputs.own.trim() || saving !== null" @click="addDomain('own')">
            Add
          </el-button>
        </div>
        <div v-if="ownDomains.length" class="qs-tags">
          <el-tag v-for="d in ownDomains.slice(0, MAX_TAGS)" :key="d.id" size="small" effect="plain">{{ d.domain }}</el-tag>
          <span v-if="ownDomains.length > MAX_TAGS" class="qs-more">+{{ ownDomains.length - MAX_TAGS }} more</span>
        </div>
      </el-form-item>

      <el-form-item label="Email domain or address" :error="errors.identity">
        <div class="qs-row">
          <el-input
            v-model="inputs.identity"
            placeholder="example.com or alice@example.com"
            aria-label="Email domain or address to monitor for breaches"
            :disabled="saving !== null"
            style="width: 260px"
            @input="errors.identity = ''"
            @keyup.enter="addIdentity"
          />
          <el-button :loading="saving === 'identity'" :disabled="!inputs.identity.trim() || saving !== null" @click="addIdentity">
            Add
          </el-button>
        </div>
        <div class="qs-hint">
          Checked against Have I Been Pwned. A whole email domain must first be verified in your
          <a :href="HIBP_DOMAIN_SEARCH_URL" target="_blank" rel="noopener noreferrer">HIBP domain dashboard</a>.
        </div>
        <div v-if="identities.length" class="qs-tags">
          <el-tag v-for="i in identities.slice(0, MAX_TAGS)" :key="i.id" size="small" effect="plain">
            {{ i.value }}<template v-if="i.kind === 'email_domain'"> (domain)</template>
          </el-tag>
          <span v-if="identities.length > MAX_TAGS" class="qs-more">+{{ identities.length - MAX_TAGS }} more</span>
        </div>
      </el-form-item>

      <el-form-item label="Brand domain" :error="errors.brand">
        <div class="qs-row">
          <el-input
            v-model="inputs.brand"
            placeholder="example.com"
            aria-label="Brand domain to protect from lookalikes"
            :disabled="saving !== null"
            style="width: 260px"
            @input="errors.brand = ''"
            @keyup.enter="addDomain('brand')"
          />
          <el-button :loading="saving === 'brand'" :disabled="!inputs.brand.trim() || saving !== null" @click="addDomain('brand')">
            Add
          </el-button>
        </div>
        <div v-if="brandDomains.length" class="qs-tags">
          <el-tag v-for="d in brandDomains.slice(0, MAX_TAGS)" :key="d.id" size="small" effect="plain">{{ d.domain }}</el-tag>
          <span v-if="brandDomains.length > MAX_TAGS" class="qs-more">+{{ brandDomains.length - MAX_TAGS }} more</span>
        </div>
      </el-form-item>

      <el-form-item label="HIBP API key (optional)" :error="errors.key">
        <template v-if="hibp?.configured">
          <el-tag type="success" size="small">Key configured</el-tag>
          <span class="qs-hint qs-inline">Replace or test it in Settings → Digital Risk.</span>
        </template>
        <template v-else>
          <div class="qs-row">
            <el-input
              v-model="inputs.key"
              type="password"
              show-password
              autocomplete="new-password"
              placeholder="32-character hex key"
              aria-label="HIBP API key"
              :disabled="saving !== null"
              style="width: 260px"
              @input="errors.key = ''"
              @keyup.enter="saveKey"
            />
            <el-button :loading="saving === 'key'" :disabled="!inputs.key.trim() || saving !== null" @click="saveKey">
              Save
            </el-button>
          </div>
          <div class="qs-hint">
            Needed for breach checks.
            <a :href="HIBP_API_KEY_URL" target="_blank" rel="noopener noreferrer">Get an HIBP API key</a>; it is
            stored encrypted and never shown again.
          </div>
        </template>
      </el-form-item>
    </el-form>

    <el-button size="small" @click="router.push('/settings/digital-risk')">Settings → Digital Risk →</el-button>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage } from 'element-plus';
import exposureService, {
  type DomainScope,
  type ExposureProvider,
  type MonitoredIdentity,
  type WatchedDomain,
} from '@/services/exposureService';
import {
  HIBP_API_KEY_URL,
  HIBP_DOMAIN_SEARCH_URL,
  apiErrorMessage,
  apiErrorStatus,
  guessIdentityKind,
  normalizeDomain,
  normalizeHibpKey,
  normalizeIdentityValue,
  type ValidationResult,
} from '@/utils/exposure';

const emit = defineEmits<{ (e: 'changed'): void }>();

const router = useRouter();
const MAX_TAGS = 5;

type Field = 'own' | 'identity' | 'brand' | 'key';
const inputs = reactive<Record<Field, string>>({ own: '', identity: '', brand: '', key: '' });
const errors = reactive<Record<Field, string>>({ own: '', identity: '', brand: '', key: '' });
const saving = ref<Field | null>(null);

const loading = ref(false);
const domains = ref<WatchedDomain[]>([]);
const identities = ref<MonitoredIdentity[]>([]);
const hibp = ref<ExposureProvider | null>(null);
const ownDomains = computed(() => domains.value.filter((d) => d.scope === 'own'));
const brandDomains = computed(() => domains.value.filter((d) => d.scope === 'brand'));

async function load(showLoading = false) {
  if (showLoading) loading.value = true;
  try {
    const [d, i, p] = await Promise.allSettled([
      exposureService.listDomains(),
      exposureService.listIdentities(),
      exposureService.getProviders(),
    ]);
    if (d.status === 'fulfilled') domains.value = d.value;
    if (i.status === 'fulfilled') identities.value = i.value;
    if (p.status === 'fulfilled') hibp.value = p.value.find((x) => x.name === 'hibp') ?? null;
  } finally {
    loading.value = false;
  }
}

/** Validate client-side, run the write, then refresh. The backend's 400 message wins. */
async function submit(field: Field, checked: ValidationResult, write: (value: string) => Promise<string>) {
  if (!checked.ok) {
    errors[field] = checked.error;
    return;
  }
  saving.value = field;
  try {
    const message = await write(checked.value);
    inputs[field] = '';
    ElMessage.success(message);
    await load();
    emit('changed');
  } catch (error) {
    const message = apiErrorMessage(error, 'Could not save; try again');
    if (apiErrorStatus(error) === 400) errors[field] = message;
    ElMessage.error(message);
  } finally {
    saving.value = null;
  }
}

function addDomain(scope: DomainScope) {
  if (saving.value !== null || !inputs[scope].trim()) return;
  return submit(scope, normalizeDomain(inputs[scope]), async (domain) => {
    await exposureService.addDomain({ domain, scope });
    return `Now watching ${domain}`;
  });
}

function addIdentity() {
  if (saving.value !== null || !inputs.identity.trim()) return;
  const kind = guessIdentityKind(inputs.identity);
  return submit('identity', normalizeIdentityValue(kind, inputs.identity), async (value) => {
    await exposureService.addIdentity({ kind, value });
    return `Now monitoring ${value} for breaches`;
  });
}

function saveKey() {
  if (saving.value !== null || !inputs.key.trim()) return;
  return submit('key', normalizeHibpKey(inputs.key), async (key) => {
    // Entering a key here means "use it": save it and switch the provider on.
    await exposureService.saveHibpKey(key, true);
    return 'HIBP key saved and the provider enabled';
  });
}

onMounted(() => load(true));
</script>

<style scoped>
.dr-quick-setup {
  max-width: 760px;
  margin-bottom: 8px;
}

.qs-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.qs-tags {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px;
  width: 100%;
  margin-top: 6px;
}

.qs-more,
.qs-hint {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.qs-hint {
  width: 100%;
  margin-top: 4px;
  line-height: 1.5;
}

.qs-hint a {
  color: var(--el-color-primary);
}

.qs-inline {
  width: auto;
  margin: 0 0 0 8px;
}
</style>
