<template>
  <el-card>
    <template #header>
      <div class="card-header">
        <span>{{ copy.title }} <HelpTip :text="copy.help" /></span>
        <el-tag size="small" type="info" effect="plain">{{ domains.length }}</el-tag>
      </div>
    </template>

    <p class="card-intro">{{ copy.intro }}</p>
    <p v-if="!domainMonitorAvailable" class="card-note">
      Domain monitoring collectors are coming in a later release. Domains you add now are saved and
      will be watched as soon as they ship.
    </p>

    <el-form class="add-form" inline @submit.prevent="add">
      <el-form-item :error="inputError">
        <el-input
          v-model="newDomain"
          :placeholder="copy.placeholder"
          :disabled="adding"
          :aria-label="`${copy.title}: domain to add`"
          clearable
          style="width: 260px"
          @input="inputError = ''"
        />
      </el-form-item>
      <el-form-item>
        <el-select v-model="newInterval" :disabled="adding" aria-label="Check interval" style="width: 150px">
          <el-option v-for="opt in INTERVAL_OPTIONS" :key="opt.value" :label="opt.label" :value="opt.value" />
        </el-select>
      </el-form-item>
      <el-form-item>
        <el-button type="primary" native-type="submit" :icon="Plus" :loading="adding" :disabled="!newDomain.trim()">
          Add domain
        </el-button>
      </el-form-item>
    </el-form>

    <el-table :data="domains" v-loading="loading" stripe :empty-text="copy.empty">
      <el-table-column prop="domain" label="Domain" min-width="180" />

      <el-table-column label="Enabled" width="80" align="center">
        <template #default="{ row }">
          <el-switch
            :model-value="row.enabled"
            :loading="isBusy(row, 'enabled')"
            :disabled="busy !== null && !isBusy(row, 'enabled')"
            :aria-label="`Watch ${row.domain}`"
            @change="(value: string | number | boolean) => setEnabled(row, value === true)"
          />
        </template>
      </el-table-column>

      <el-table-column label="Interval" width="140">
        <template #default="{ row }">
          <el-select
            :model-value="row.interval_minutes"
            size="small"
            :disabled="busy !== null"
            :aria-label="`Check interval for ${row.domain}`"
            @change="(value: number) => changeInterval(row, value)"
          >
            <el-option
              v-for="opt in intervalOptionsFor(row.interval_minutes)"
              :key="opt.value"
              :label="opt.label"
              :value="opt.value"
            />
          </el-select>
        </template>
      </el-table-column>

      <el-table-column label="Last checked" min-width="150">
        <template #default="{ row }">
          <div>{{ formatWhen(row.last_checked_at) }}</div>
          <el-text v-if="row.next_run_at" size="small" type="info">Next {{ formatRelative(row.next_run_at) }}</el-text>
        </template>
      </el-table-column>

      <el-table-column label="Status" min-width="180">
        <template #default="{ row }">
          <el-tag :type="checkStatusTag(row).type" size="small">{{ checkStatusTag(row).label }}</el-tag>
          <div v-if="row.last_error" class="row-error">{{ row.last_error }}</div>
        </template>
      </el-table-column>

      <el-table-column label="Actions" width="100" align="center" fixed="right">
        <template #default="{ row }">
          <el-button
            size="small"
            type="danger"
            :icon="Delete"
            :loading="isBusy(row, 'delete')"
            :disabled="busy !== null && !isBusy(row, 'delete')"
            @click="remove(row)"
          >
            Delete
          </el-button>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Delete, Plus } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import exposureService, {
  type DomainScope,
  type WatchedDomain,
  type WatchedDomainUpdate,
} from '@/services/exposureService';
import {
  DEFAULT_INTERVAL_MINUTES,
  INTERVAL_OPTIONS,
  apiErrorMessage,
  apiErrorStatus,
  checkStatusTag,
  formatRelative,
  formatWhen,
  intervalLabel,
  intervalOptionsFor,
  normalizeDomain,
} from '@/utils/exposure';

// One card per watched-domain scope: 'own' (the organization's domains) and
// 'brand' (names to protect from lookalikes). Both read the same list.
const props = defineProps<{
  scope: DomainScope;
  /** False until the domain collectors ship (GET /status features.domain_monitor_available). */
  domainMonitorAvailable: boolean;
}>();

const emit = defineEmits<{ (e: 'changed'): void }>();

const COPY: Record<DomainScope, { title: string; intro: string; help: string; placeholder: string; empty: string }> = {
  own: {
    title: 'Owned domains',
    intro:
      'Domains your organization owns. Domain monitoring watches them for certificates from unexpected CAs, DNS changes and registration (RDAP) changes.',
    help: 'Enter bare hostnames such as example.com: no scheme, port, path, wildcard or IP address. Enter internationalized names in punycode (xn--…).',
    placeholder: 'example.com',
    empty: 'No owned domains yet',
  },
  brand: {
    title: 'Brand / lookalike domains',
    intro:
      'Names to protect: newly registered lookalikes and typosquats of these domains (and certificates issued for them) are what phishing sites are built on.',
    help: 'Usually your main brand domains, e.g. example.com to catch examp1e.com or example-login.com. Same format as owned domains: a bare hostname, no scheme, port, path, wildcard or IP.',
    placeholder: 'example.com',
    empty: 'No brand domains yet',
  },
};
const copy = computed(() => COPY[props.scope]);

const allDomains = ref<WatchedDomain[]>([]);
const domains = computed(() => allDomains.value.filter((d) => d.scope === props.scope));
const loading = ref(false);

const newDomain = ref('');
const newInterval = ref(DEFAULT_INTERVAL_MINUTES);
const inputError = ref('');
const adding = ref(false);
type RowAction = 'enabled' | 'interval' | 'delete';
/** The row write in flight; every other row control waits for it. */
const busy = ref<{ id: number; action: RowAction } | null>(null);
const isBusy = (row: { id: number }, action: RowAction) =>
  busy.value?.id === row.id && busy.value.action === action;

/** Fetch the list; `showLoading` only for the first load, so writes don't flash the table. */
async function reload(showLoading = false) {
  if (showLoading) loading.value = true;
  try {
    allDomains.value = await exposureService.listDomains();
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, 'Failed to load watched domains'));
  } finally {
    loading.value = false;
  }
}

async function add() {
  // Pre-check only; the backend validates again and its message wins.
  const checked = normalizeDomain(newDomain.value);
  if (!checked.ok) {
    inputError.value = checked.error;
    return;
  }
  adding.value = true;
  try {
    await exposureService.addDomain({
      domain: checked.value,
      scope: props.scope,
      interval_minutes: newInterval.value,
    });
    newDomain.value = '';
    ElMessage.success(`Now watching ${checked.value}`);
    await reload();
    emit('changed');
  } catch (error) {
    const message = apiErrorMessage(error, 'Failed to add the domain');
    if (apiErrorStatus(error) === 400) inputError.value = message;
    ElMessage.error(message);
  } finally {
    adding.value = false;
  }
}

async function update(row: WatchedDomain, action: RowAction, changes: WatchedDomainUpdate, success: string) {
  busy.value = { id: row.id, action };
  try {
    await exposureService.updateDomain(row.id, changes);
    ElMessage.success(success);
    await reload();
    emit('changed');
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, `Failed to update ${row.domain}`));
  } finally {
    busy.value = null;
  }
}

function setEnabled(row: WatchedDomain, enabled: boolean) {
  return update(row, 'enabled', { enabled }, `${row.domain} ${enabled ? 'enabled' : 'disabled'}`);
}

function changeInterval(row: WatchedDomain, minutes: number) {
  return update(row, 'interval', { interval_minutes: minutes }, `${row.domain}: ${intervalLabel(minutes).toLowerCase()}`);
}

async function remove(row: WatchedDomain) {
  try {
    await ElMessageBox.confirm(
      `Stop watching ${row.domain}? Its findings are deleted too (their alerts stay in the alert queue).`,
      'Delete watched domain',
      { confirmButtonText: 'Delete', cancelButtonText: 'Cancel', type: 'warning' }
    );
  } catch {
    return; // cancelled
  }
  busy.value = { id: row.id, action: 'delete' };
  try {
    await exposureService.deleteDomain(row.id);
    ElMessage.success(`Stopped watching ${row.domain}`);
    await reload();
    emit('changed');
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, `Failed to delete ${row.domain}`));
  } finally {
    busy.value = null;
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

.card-intro {
  margin: 0 0 8px;
  font-size: 13px;
  color: var(--el-text-color-regular);
}

.card-note {
  margin: 0 0 12px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.add-form {
  margin-bottom: 4px;
}

.row-error {
  margin-top: 4px;
  font-size: 12px;
  line-height: 1.4;
  color: var(--el-color-danger);
  word-break: break-word;
}
</style>
