<template>
  <el-card>
    <template #header>
      <div class="card-header">
        <span>
          Breach-monitored identities
          <HelpTip text="Email addresses and whole email domains checked against Have I Been Pwned in the background: the job wakes every 15 minutes and checks each identity on its own interval. Each breach an identity appears in becomes a finding and, the first time, an alert." />
        </span>
        <el-tag size="small" type="info" effect="plain">{{ identities.length }}</el-tag>
      </div>
    </template>

    <el-alert type="info" :closable="false" class="card-alert">
      Email addresses use HIBP's breached-account search. A whole <strong>email domain</strong> uses HIBP's
      domain search, which only works for domains verified in your
      <a :href="HIBP_DOMAIN_SEARCH_URL" target="_blank" rel="noopener noreferrer">HIBP domain dashboard</a>:
      an unverified domain shows an error here and is retried after its interval. Checks need an HIBP API
      key (see Have I Been Pwned below).
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
import { onMounted, ref } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Delete, Plus } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import exposureService, {
  type IdentityKind,
  type MonitoredIdentity,
  type MonitoredIdentityUpdate,
} from '@/services/exposureService';
import {
  DEFAULT_INTERVAL_MINUTES,
  HIBP_DOMAIN_SEARCH_URL,
  INTERVAL_OPTIONS,
  apiErrorMessage,
  apiErrorStatus,
  checkStatusTag,
  formatWhen,
  identityKindLabel,
  intervalLabel,
  intervalOptionsFor,
  normalizeIdentityValue,
} from '@/utils/exposure';

const emit = defineEmits<{ (e: 'changed'): void }>();

const identities = ref<MonitoredIdentity[]>([]);
const loading = ref(false);

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
    await exposureService.addIdentity({
      kind: newKind.value,
      value: checked.value,
      interval_minutes: newInterval.value,
    });
    newValue.value = '';
    ElMessage.success(`Now monitoring ${checked.value}`);
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
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, `Failed to delete ${row.value}`));
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

.card-alert {
  margin-bottom: 15px;
}

.card-alert a {
  color: var(--el-color-primary);
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
