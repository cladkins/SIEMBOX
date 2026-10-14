<template>
  <el-card>
    <template #header>
      <div class="card-header">
        <span>
          Breach-monitored identities
          <HelpTip text="Email addresses and whole email domains checked against Have I Been Pwned in the background: the job wakes every 15 minutes and checks each identity on its own interval. Each breach an identity appears in becomes a finding and, the first time, an alert." />
        </span>
        <div class="header-actions">
          <el-button
            v-if="hasEmailDomains"
            size="small"
            :icon="Refresh"
            :loading="rechecking"
            @click="recheckVerification"
          >
            Re-check HIBP verification
          </el-button>
          <el-tag size="small" type="info" effect="plain">{{ identities.length }}</el-tag>
        </div>
      </div>
    </template>

    <el-alert type="info" :closable="false" class="card-alert">
      Email addresses use HIBP's breached-account search. A whole <strong>email domain</strong> uses HIBP's
      domain search, which only works for domains verified on your HIBP account
      (<a :href="HIBP_DOMAINS_DASHBOARD_URL" target="_blank" rel="noopener noreferrer">HIBP dashboard ↗</a>).
      SIEMBox checks which of your domains are verified and skips the others, with no errors and no wasted HIBP
      calls, until you verify them and re-check. Checks need an HIBP API key (see Have I Been Pwned below).
    </el-alert>

    <el-form class="add-form" inline @submit.prevent="add">
      <el-form-item>
        <el-select v-model="newKind" :disabled="adding" aria-label="Identity type" style="width: 160px" @change="inputError = ''">
          <el-option label="Email address" value="email" />
          <el-option label="Email domain" value="email_domain" />
        </el-select>
      </el-form-item>
      <el-form-item :error="inputError">
        <el-input
          v-model="newValue"
          :placeholder="newKind === 'email' ? 'alice@example.com' : 'example.com'"
          :disabled="adding"
          :aria-label="newKind === 'email' ? 'Email address to monitor' : 'Email domain to monitor'"
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
        <el-button type="primary" native-type="submit" :icon="Plus" :loading="adding" :disabled="!newValue.trim()">
          Add identity
        </el-button>
      </el-form-item>
    </el-form>

    <el-table :data="identities" v-loading="loading" stripe empty-text="No monitored identities yet">
      <el-table-column label="Identity" min-width="220">
        <template #default="{ row }">
          <div>{{ row.value }}</div>
          <el-tag size="small" effect="plain" :type="row.kind === 'email' ? 'primary' : 'warning'">
            {{ identityKindLabel(row.kind) }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column label="Enabled" width="80" align="center">
        <template #default="{ row }">
          <el-switch
            :model-value="row.enabled"
            :loading="isBusy(row, 'enabled')"
            :disabled="busy !== null && !isBusy(row, 'enabled')"
            :aria-label="`Monitor ${row.value}`"
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
            :aria-label="`Check interval for ${row.value}`"
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
        <template #default="{ row }">{{ formatWhen(row.last_checked_at) }}</template>
      </el-table-column>

      <el-table-column label="Status" min-width="240">
        <template #default="{ row }">
          <el-tag :type="checkStatusTag(row).type" size="small">{{ checkStatusTag(row).label }}</el-tag>
          <div v-if="hibpDomainLine(row)" class="hibp-line" :class="`hibp-line--${hibpDomainLine(row)!.type}`">
            <template v-if="hibpDomainLine(row)!.parentNote">{{ hibpDomainLine(row)!.parentNote }} </template>
            {{ hibpDomainLine(row)!.text }}
            <template v-if="hibpDomainLine(row)!.action === 'verify'">
              <a :href="HIBP_DOMAINS_DASHBOARD_URL" target="_blank" rel="noopener noreferrer">verify it in the HIBP dashboard ↗</a>,
              then
              <el-button link type="primary" size="small" :disabled="rechecking" @click="recheckVerification">
                Re-check HIBP verification
              </el-button>
            </template>
            <a
              v-else-if="hibpDomainLine(row)!.action === 'plans'"
              :href="HIBP_PRICING_URL"
              target="_blank"
              rel="noopener noreferrer"
            >HIBP plans ↗</a>
          </div>
          <div v-if="row.last_error" class="row-error" :class="{ 'row-error--warning': row.last_status === 'unverified' }">
            {{ row.last_error }}
          </div>
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
import { Delete, Plus, Refresh } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import exposureService, {
  type ExposureStatus,
  type IdentityKind,
  type MonitoredIdentity,
  type MonitoredIdentityUpdate,
} from '@/services/exposureService';
import {
  DEFAULT_INTERVAL_MINUTES,
  HIBP_DOMAINS_DASHBOARD_URL,
  HIBP_PRICING_URL,
  INTERVAL_OPTIONS,
  apiErrorMessage,
  apiErrorStatus,
  checkStatusTag,
  formatWhen,
  hibpDomainLine,
  identityAddedMessage,
  identityKindLabel,
  intervalLabel,
  intervalOptionsFor,
  normalizeIdentityValue,
  refreshFailureMessage,
  refreshOutcomeMessage,
} from '@/utils/exposure';

const props = defineProps<{
  /** GET /status, for whether a new identity will actually be checked; null while it loads. */
  status: ExposureStatus | null;
}>();

const emit = defineEmits<{
  /** A write succeeded. */
  (e: 'changed'): void;
  /** An identity was deleted, and its findings with it. */
  (e: 'deleted'): void;
  /** The list was (re)fetched; the status banner counts the failing rows. */
  (e: 'loaded', identities: MonitoredIdentity[]): void;
  /** HIBP was asked which domains are verified: the page reloads what depends on it. */
  (e: 'domains-refreshed'): void;
}>();

const identities = ref<MonitoredIdentity[]>([]);
const loading = ref(false);
const hasEmailDomains = computed(() => identities.value.some((i) => i.kind === 'email_domain'));
const rechecking = ref(false);

const newKind = ref<IdentityKind>('email');
const newValue = ref('');
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
    identities.value = await exposureService.listIdentities();
    emit('loaded', identities.value);
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, 'Failed to load monitored identities'));
  } finally {
    loading.value = false;
  }
}

async function add() {
  // Pre-check only; the backend validates again and its message wins.
  const checked = normalizeIdentityValue(newKind.value, newValue.value);
  if (!checked.ok) {
    inputError.value = checked.error;
    return;
  }
  adding.value = true;
  try {
    const created = await exposureService.addIdentity({
      kind: newKind.value,
      value: checked.value,
      interval_minutes: newInterval.value,
    });
    newValue.value = '';
    ElMessage.success(identityAddedMessage(checked.value, props.status, created.hibp_domain));
    await reload();
    emit('changed');
  } catch (error) {
    const message = apiErrorMessage(error, 'Failed to add the identity');
    if (apiErrorStatus(error) === 400) inputError.value = message;
    ElMessage.error(message);
  } finally {
    adding.value = false;
  }
}

async function update(row: MonitoredIdentity, action: RowAction, changes: MonitoredIdentityUpdate, success: string) {
  busy.value = { id: row.id, action };
  try {
    await exposureService.updateIdentity(row.id, changes);
    ElMessage.success(success);
    await reload();
    emit('changed');
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, `Failed to update ${row.value}`));
  } finally {
    busy.value = null;
  }
}

function setEnabled(row: MonitoredIdentity, enabled: boolean) {
  return update(row, 'enabled', { enabled }, `${row.value} ${enabled ? 'enabled' : 'disabled'}`);
}

function changeInterval(row: MonitoredIdentity, minutes: number) {
  return update(row, 'interval', { interval_minutes: minutes }, `${row.value}: ${intervalLabel(minutes).toLowerCase()}`);
}

async function remove(row: MonitoredIdentity) {
  try {
    await ElMessageBox.confirm(
      `Stop monitoring ${row.value}? Its findings are deleted too (their alerts stay in the alert queue).`,
      'Delete monitored identity',
      { confirmButtonText: 'Delete', cancelButtonText: 'Cancel', type: 'warning' }
    );
  } catch {
    return; // cancelled
  }
  busy.value = { id: row.id, action: 'delete' };
  try {
    await exposureService.deleteIdentity(row.id);
    ElMessage.success(`Stopped monitoring ${row.value}`);
    await reload();
    emit('changed');
    emit('deleted');
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, `Failed to delete ${row.value}`));
  } finally {
    busy.value = null;
  }
}

// Ask HIBP now which domains are verified (the server allows it once a minute
// install-wide and answers from its last check otherwise).
async function recheckVerification() {
  if (rechecking.value) return;
  rechecking.value = true;
  try {
    const result = await exposureService.refreshHibpVerifiedDomains();
    const outcome = refreshOutcomeMessage(result);
    ElMessage({ type: outcome.type, message: outcome.message });
    emit('domains-refreshed');
  } catch (error) {
    ElMessage.error(refreshFailureMessage(error));
  } finally {
    rechecking.value = false;
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

.card-alert {
  margin-bottom: 15px;
}

.card-alert a {
  color: var(--el-color-primary);
}

.add-form {
  margin-bottom: 4px;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.row-error {
  margin-top: 4px;
  font-size: 12px;
  line-height: 1.4;
  color: var(--el-color-danger);
  word-break: break-word;
}

.row-error--warning {
  color: var(--el-color-warning);
}

.hibp-line {
  margin-top: 4px;
  font-size: 12px;
  line-height: 1.5;
  word-break: break-word;
}

.hibp-line a {
  color: var(--el-color-primary);
}

.hibp-line .el-button {
  font-size: 12px;
  height: auto;
  padding: 0;
  vertical-align: baseline;
}

.hibp-line--success {
  color: var(--el-color-success);
}

.hibp-line--warning {
  color: var(--el-color-warning);
}

.hibp-line--info {
  color: var(--el-text-color-secondary);
}
</style>
