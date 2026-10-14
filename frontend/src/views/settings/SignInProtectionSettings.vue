<template>
  <div class="sign-in-protection" v-loading="loading && !data">
    <el-alert
      v-if="data && !data.settings.protection"
      type="error"
      show-icon
      :closable="false"
      class="block"
      title="Sign-in protection is off (LOGIN_PROTECTION=off)"
      description="Failed sign-ins are not counted or paused. It is meant for getting back in after a lockout: remove LOGIN_PROTECTION from the backend's environment and run docker compose up -d."
    />

    <!-- How SIEMBox sees you -->
    <el-card class="block">
      <template #header>
        <div class="card-header">
          <span>How SIEMBox sees you <HelpTip text="The address sign-in limits count you under, and how your request reached the API. If every user shows the same address (a reverse proxy SIEMBox does not trust), sign-in pauses for a network hit all of them: see DEPLOYMENT.md, 'Client addresses and reverse proxies'." /></span>
          <el-button size="small" :icon="Refresh" :loading="loading" @click="load">Refresh</el-button>
        </div>
      </template>
      <template v-if="you">
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="Your address">{{ you.address || 'unknown' }}</el-descriptions-item>
          <el-descriptions-item label="Sign-in network">{{ you.signInKey }}</el-descriptions-item>
          <el-descriptions-item label="Arrived">{{ viaWords(you.via) }}</el-descriptions-item>
          <el-descriptions-item label="Connected from">{{ you.peer || '—' }}</el-descriptions-item>
        </el-descriptions>
        <el-alert
          v-for="(warning, i) in warnings"
          :key="i"
          type="warning"
          :title="warning"
          :closable="false"
          show-icon
          class="warning"
        />
        <p v-if="warnings.length === 0" class="note ok">No problems found with how client addresses reach SIEMBox.</p>
      </template>
    </el-card>

    <!-- Pauses and counters -->
    <el-card class="block">
      <template #header>
        <div class="card-header">
          <span>Pauses and counters <HelpTip text="Every counter that is paused or failed in the last 24 hours. Clearing one ends its pause at once; failed attempts are counted again from zero. Browsers that signed in before are never held back by an account or network pause." /></span>
          <el-button size="small" type="danger" plain :disabled="!data || data.counters.length === 0" @click="clear({ all: true }, 'every sign-in counter')">
            Clear everything
          </el-button>
        </div>
      </template>
      <div v-if="data" class="stats">
        <el-statistic title="Failed sign-ins, last 24 h" :value="data.last24h.failures" />
        <el-statistic title="… for usernames that don't exist" :value="data.last24h.unknownUsernames" />
        <el-statistic title="Paused now" :value="pausedCount" />
        <el-statistic title="Attempts refused since restart" :value="data.refused.sinceStart" />
      </div>
      <el-table :data="data?.counters || []" stripe size="small" empty-text="No paused or failing sign-in counters">
        <el-table-column label="Counts" min-width="190">
          <template #default="{ row }">{{ row.scopeLabel }}</template>
        </el-table-column>
        <el-table-column label="Account" min-width="140">
          <template #default="{ row }">
            <span v-if="row.username">{{ row.username }}</span>
            <el-text v-else-if="row.scope === 'aip' || row.scope === 'acct'" type="info">unknown username</el-text>
            <el-text v-else type="info">—</el-text>
          </template>
        </el-table-column>
        <el-table-column label="Network" min-width="140">
          <template #default="{ row }">{{ row.network || '—' }}</template>
        </el-table-column>
        <el-table-column prop="failures" label="Failures" width="90" align="right" />
        <el-table-column label="Paused" width="110">
          <template #default="{ row }">
            <el-tag v-if="secondsLeft(row) > 0" type="warning" effect="light">{{ formatCountdown(secondsLeft(row)) }}</el-tag>
            <el-text v-else type="info">—</el-text>
          </template>
        </el-table-column>
        <el-table-column label="Last attempt" width="160">
          <template #default="{ row }">{{ row.last_failure_at ? formatDate(row.last_failure_at) : '—' }}</template>
        </el-table-column>
        <el-table-column label="Last user agent" min-width="160" show-overflow-tooltip>
          <template #default="{ row }">{{ row.last_user_agent || '—' }}</template>
        </el-table-column>
        <el-table-column label="Refused" width="90" align="right">
          <template #default="{ row }">{{ row.refusedSinceStart }}</template>
        </el-table-column>
        <el-table-column label="" width="190" align="right" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="clear({ key: row.key }, 'this counter')">Clear</el-button>
            <el-button v-if="row.network" size="small" @click="clear({ network: row.network }, `every counter of ${row.network}`)">
              Clear network
            </el-button>
          </template>
        </el-table-column>
      </el-table>
      <p class="note">Refreshes every 15 seconds. "Refused" counts attempts turned away while paused since the backend started.</p>
    </el-card>

    <!-- Settings in effect -->
    <el-card v-if="data" class="block">
      <template #header>
        <span>Settings in effect <HelpTip text="Read-only: these come from the backend's environment (LOGIN_PROTECTION, LOGIN_MAX_FAILURES, LOGIN_MAX_FAILURES_PER_ADDRESS, LOGIN_MAX_FAILURES_PER_ACCOUNT, AUTH_ALERTS, AUTH_FAILURE_AUDIT_RETENTION_DAYS). See DEPLOYMENT.md, 'Sign-in protection'." /></span>
      </template>
      <p class="note">
        A counter pauses for {{ data.settings.firstPauseSeconds }} seconds when it reaches its threshold (T failures in a
        row), and every further failure doubles the pause, up to the limit below. A counter starts over {{ data.settings.streakResetHours }} hours
        after its last failure. A paused network only holds back a username for 15 minutes after it failed from there, so
        one person guessing from a shared address doesn't lock out everyone behind it. A recognized browser is
        forgotten after {{ data.settings.browserRevokeFailures }} failures in a row.
      </p>
      <el-table :data="data.settings.scopes" size="small">
        <el-table-column label="Counter" min-width="220">
          <template #default="{ row }">{{ row.label }}</template>
        </el-table-column>
        <el-table-column label="Pauses after (T)" width="150">
          <template #default="{ row }">
            <span v-if="row.threshold > 0">{{ row.threshold }} failures</span>
            <el-text v-else type="info">off</el-text>
          </template>
        </el-table-column>
        <el-table-column label="Longest pause" width="130">
          <template #default="{ row }">{{ Math.round(row.capSeconds / 60) }} min</template>
        </el-table-column>
        <el-table-column label="A successful sign-in" width="190">
          <template #default="{ row }">{{ row.resetOnSuccess ? 'resets it' : 'only refunds its attempt' }}</template>
        </el-table-column>
        <el-table-column label="Set by" min-width="200">
          <template #default="{ row }">
            <code v-if="ENV_OF_SCOPE[row.scope]">{{ ENV_OF_SCOPE[row.scope] }}</code>
            <el-text v-else type="info">fixed</el-text>
          </template>
        </el-table-column>
      </el-table>
      <el-descriptions :column="3" size="small" class="effect">
        <el-descriptions-item label="Protection">{{ data.settings.protection ? 'on' : 'off' }}</el-descriptions-item>
        <el-descriptions-item label="Alerts">{{ data.settings.alerts ? 'on' : 'off' }}</el-descriptions-item>
        <el-descriptions-item label="Failed sign-in audit rows kept">
          {{ data.settings.failureAuditRetentionDays > 0 ? `${data.settings.failureAuditRetentionDays} days` : 'forever' }}
        </el-descriptions-item>
      </el-descriptions>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Refresh } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import { api } from '@/services/api';
import { formatCountdown } from '@/utils/signIn';
import { formatDate } from './format';

interface CounterRow {
  key: string;
  scope: string;
  scopeLabel: string;
  user_id: number | null;
  username: string | null;
  network: string | null;
  failures: number;
  paused_seconds: number;
  last_failure_at: string | null;
  last_user_agent: string | null;
  refusedSinceStart: number;
}

interface SignInProtection {
  clientAddress: {
    you: { address: string | null; via: string; peer: string | null; signInKey: string };
    warnings: string[];
  };
  counters: CounterRow[];
  last24h: { failures: number; unknownUsernames: number };
  refused: { sinceStart: number };
  settings: {
    protection: boolean;
    alerts: boolean;
    failureAuditRetentionDays: number;
    firstPauseSeconds: number;
    streakResetHours: number;
    browserRevokeFailures: number;
    scopes: Array<{ scope: string; label: string; threshold: number; capSeconds: number; resetOnSuccess: boolean }>;
  };
}

const ENV_OF_SCOPE: Record<string, string> = {
  aip: 'LOGIN_MAX_FAILURES',
  ip: 'LOGIN_MAX_FAILURES_PER_ADDRESS',
  acct: 'LOGIN_MAX_FAILURES_PER_ACCOUNT (0 = off)',
};

const data = ref<SignInProtection | null>(null);
const loading = ref(false);
const fetchedAt = ref(Date.now());
const now = ref(Date.now());
let refreshTimer: ReturnType<typeof setInterval> | null = null;
let clockTimer: ReturnType<typeof setInterval> | null = null;

const you = computed(() => data.value?.clientAddress.you ?? null);
const warnings = computed(() => data.value?.clientAddress.warnings ?? []);
const pausedCount = computed(() => (data.value?.counters ?? []).filter((row) => secondsLeft(row) > 0).length);

function secondsLeft(row: CounterRow): number {
  return Math.max(0, Math.ceil(row.paused_seconds - (now.value - fetchedAt.value) / 1000));
}

function viaWords(via: string): string {
  if (via === 'proxy-socket') return "through SIEMBox's web server (proxy socket)";
  if (via === 'trusted-proxy') return 'through a trusted proxy (TRUSTED_PROXIES)';
  return 'directly on the API port';
}

async function load() {
  loading.value = true;
  try {
    const { data: body } = await api.getSignInProtection();
    data.value = body;
    fetchedAt.value = Date.now();
    now.value = fetchedAt.value;
  } catch {
    // The API client has shown the error; keep the last data.
  } finally {
    loading.value = false;
  }
}

async function clear(target: { key: string } | { network: string } | { all: true }, what: string) {
  try {
    await ElMessageBox.confirm(`Clear ${what}? Any pause it holds ends now.`, 'Clear sign-in counters', {
      confirmButtonText: 'Clear',
      cancelButtonText: 'Cancel',
      type: 'warning',
    });
  } catch {
    return;
  }
  try {
    const { data: body } = await api.clearSignInCounters(target);
    ElMessage.success(`Cleared ${body.cleared} counter${body.cleared === 1 ? '' : 's'}`);
    await load();
  } catch {
    // The API client has shown the error.
  }
}

onMounted(() => {
  void load();
  refreshTimer = setInterval(() => void load(), 15_000);
  clockTimer = setInterval(() => (now.value = Date.now()), 1000);
});

onBeforeUnmount(() => {
  if (refreshTimer) clearInterval(refreshTimer);
  if (clockTimer) clearInterval(clockTimer);
});
</script>

<style scoped>
.block {
  margin-bottom: 20px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.warning {
  margin-top: 10px;
}
.note {
  font-size: 13px;
  color: var(--el-text-color-secondary);
  margin: 10px 0 0;
}
.note.ok {
  color: var(--el-color-success);
}
.stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
  margin-bottom: 16px;
}
.effect {
  margin-top: 14px;
}
</style>
