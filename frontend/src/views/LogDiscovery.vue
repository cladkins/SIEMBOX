<template>
  <div class="log-discovery-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <span class="title">Log Discovery</span>
          <div class="header-actions">
            <el-button @click="triggerScan('passive')" :loading="scanning">
              <el-icon><Aim /></el-icon>
              Scan (passive)
            </el-button>
            <el-button type="primary" @click="triggerScan('full')" :loading="scanning">
              <el-icon><Search /></el-icon>
              Scan (passive + active)
            </el-button>
            <el-button @click="refreshAll">
              <el-icon><Refresh /></el-icon>
              Refresh
            </el-button>
          </div>
        </div>
      </template>

      <el-alert
        v-if="scope?.vlan_warning"
        type="warning"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        :title="scope.vlan_warning"
      />

      <div class="scope-line">
        <span class="scope-label">Scan scope:</span>
        <el-tag v-for="cidr in scope?.cidrs || []" :key="cidr" size="small" style="margin-right: 6px">{{ cidr }}</el-tag>
        <span v-if="!scope?.cidrs?.length" class="scope-empty">No subnets added yet — passive discovery still works without one.</span>
        <el-button link size="small" @click="openManualCidrDialog">Add a subnet</el-button>
      </div>

      <div v-if="showDetectedCidrSuggestion" class="scope-line">
        <span class="scope-label">Detected LAN:</span>
        <el-tag type="success" size="small" style="margin-right: 6px">{{ scope?.detected_lan_cidr }}</el-tag>
        <el-button link size="small" type="primary" @click="addDetectedCidr">Add to scan scope</el-button>
      </div>

      <el-collapse v-if="scans.length > 0" style="margin: 16px 0">
        <el-collapse-item title="Recent scans" name="scans">
          <el-table :data="scans" size="small">
            <el-table-column prop="id" label="ID" width="70" />
            <el-table-column prop="mode" label="Mode" width="140" />
            <el-table-column label="Subnet" min-width="160">
              <template #default="{ row }">
                <span v-if="row.cidrs?.length">{{ row.cidrs.join(', ') }}</span>
                <span v-else class="scope-empty">none added</span>
              </template>
            </el-table-column>
            <el-table-column label="Status" width="120">
              <template #default="{ row }">
                <el-tag :type="scanStatusColor(row.status)" size="small">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Hosts">
              <template #default="{ row }">
                <span v-if="row.results_summary">
                  {{ row.results_summary.hosts_matched }} matched / {{ row.results_summary.hosts_seen }} seen
                </span>
                <span v-else>-</span>
              </template>
            </el-table-column>
            <el-table-column label="Started" width="180">
              <template #default="{ row }">{{ formatDate(row.started_at) }}</template>
            </el-table-column>
            <el-table-column label="" width="90">
              <template #default="{ row }">
                <el-button v-if="row.status === 'running'" size="small" type="danger" plain @click="cancelScan(row)">
                  Cancel
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-collapse-item>
      </el-collapse>

      <el-empty v-if="!loading && top.length === 0 && advanced.length === 0" description="No sources discovered yet">
        <el-text type="info">Run a scan to find log sources on your network.</el-text>
      </el-empty>

      <div v-if="top.length > 0" class="section">
        <h3>Recommended sources</h3>
        <discovery-sources-table
          :sources="top"
          :fingerprints="fingerprints"
          @confirm="confirmSource"
          @ignore="ignoreSource"
          @onboard="openOnboard"
        />
      </div>

      <el-collapse v-if="advanced.length > 0" style="margin-top: 16px">
        <el-collapse-item :title="`Advanced (${advanced.length} lower-value sources)`" name="advanced">
          <discovery-sources-table
            :sources="advanced"
            :fingerprints="fingerprints"
            @confirm="confirmSource"
            @ignore="ignoreSource"
            @onboard="openOnboard"
          />
        </el-collapse-item>
      </el-collapse>
    </el-card>

    <!-- Manual CIDR dialog -->
    <el-dialog v-model="showManualCidrDialog" title="Add a subnet to the scan scope" width="480px">
      <p class="dialog-hint">
        SIEMBOX only sees its own subnet by default. On an active or full scan, every subnet
        listed here gets swept host-by-host to find real devices your passive discovery can't
        see from inside the container's own network. Subnets larger than a /22 (1024 addresses)
        are rejected to keep the sweep bounded -- split a bigger range into smaller CIDRs instead.
      </p>
      <el-input v-model="manualCidrInput" placeholder="192.168.20.0/24, 10.10.4.0/24" />
      <template #footer>
        <el-button @click="showManualCidrDialog = false">Cancel</el-button>
        <el-button type="primary" @click="previewManualCidrs">Save</el-button>
      </template>
    </el-dialog>

    <!-- Onboard dialog -->
    <el-dialog v-model="showOnboardDialog" title="Onboard this source" width="640px">
      <div v-if="onboardTarget">
        <p>
          <strong>{{ onboardTarget.hostname || onboardTarget.ip }}</strong>
          — {{ fingerprintName(onboardTarget.matched_fingerprint_id) }}
        </p>
        <el-select v-if="onboardMethods.length > 1" v-model="onboardMethodIndex" @change="onOnboardMethodChange" style="margin-bottom: 12px">
          <el-option v-for="(m, idx) in onboardMethods" :key="idx" :label="m.method" :value="idx" />
        </el-select>

        <!-- API-pull polling panel: only for fingerprints with a real adapter. Left in place
             alongside the manual instructions below rather than replacing them -- the copy-paste
             cron+curl+logger recipe is still a valid fallback if you'd rather not store a token here. -->
        <div v-if="isPollableMethod" class="poller-panel">
          <div class="poller-head">
            Poll this API directly
            <el-tag v-if="pollerStatus?.configured" type="success" size="small">configured</el-tag>
            <el-tag v-else type="info" size="small">not configured</el-tag>
          </div>
          <el-text size="small" type="info">
            SIEMBox will pull events on its own schedule instead of you running the recipe below.
            The token is encrypted at rest and never shown again after saving.
          </el-text>

          <el-alert
            v-if="pollerStatus?.last_status === 'error'"
            type="error"
            :closable="false"
            show-icon
            :title="pollerStatus.last_error || 'Last poll failed'"
            style="margin: 8px 0"
          />

          <div class="poller-form">
            <el-input
              v-if="onboardMethod?.auth === 'basic'"
              v-model="pollerUsername"
              placeholder="Username"
              class="poller-username"
            />
            <el-input
              v-model="pollerSecret"
              :placeholder="pollerStatus?.configured ? 'Replace token…' : 'Paste API token…'"
              type="password"
              show-password
              clearable
              class="poller-secret"
            />
            <el-button type="primary" :loading="savingCredential" @click="savePollerCredential">
              {{ pollerStatus?.configured ? 'Update' : 'Save' }}
            </el-button>
            <el-button v-if="pollerStatus?.configured" type="danger" plain @click="revokePollerCredential">Revoke</el-button>
          </div>

          <div v-if="pollerStatus?.configured" class="poller-controls">
            <el-switch v-model="pollerEnabled" active-text="Polling on" inactive-text="Polling off" @change="togglePolling" />
            <span class="poller-interval-label">every</span>
            <el-input-number v-model="pollerInterval" :min="1" :max="1440" size="small" @change="updatePollerInterval" />
            <span class="poller-interval-label">min</span>
            <el-button link size="small" :loading="runningNow" @click="runPollNow">Poll now</el-button>
            <span v-if="pollerStatus.last_polled_at" class="poller-last-polled">
              last polled {{ formatDate(pollerStatus.last_polled_at) }}
              <template v-if="pollerStatus.last_status === 'ok'">— {{ pollerStatus.last_event_count ?? 0 }} event(s)</template>
            </span>
          </div>
        </div>

        <pre class="onboard-instructions">{{ onboardInstructions }}</pre>
      </div>
      <template #footer>
        <el-button @click="copyInstructions">Copy</el-button>
        <el-button type="primary" @click="confirmOnboard">I've applied this — mark onboarded</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Search, Refresh, Aim } from '@element-plus/icons-vue';
import logDiscoveryService, {
  type RankedSource,
  type DiscoveryScan,
  type ScopePreview,
  type FingerprintEntry,
  type DiscoveryScanMode,
  type PollerStatus,
} from '@/services/logDiscoveryService';
import DiscoverySourcesTable from '@/components/DiscoverySourcesTable.vue';

const loading = ref(false);
const scanning = ref(false);
const scope = ref<ScopePreview | null>(null);
const scans = ref<DiscoveryScan[]>([]);
const top = ref<RankedSource[]>([]);
const advanced = ref<RankedSource[]>([]);
const fingerprints = ref<FingerprintEntry[]>([]);

const showManualCidrDialog = ref(false);
const manualCidrInput = ref('');
// The CIDRs actually confirmed via the dialog -- distinct from scope.value.cidrs, which is
// just whatever GET /scope last echoed back (and gets overwritten on every refreshAll()).
// This is what's threaded into both loadScope() and every triggerScan() call, so a subnet
// you've added keeps applying to scans instead of silently resetting to none.
const manualCidrs = ref<string[]>([]);

const showOnboardDialog = ref(false);
const onboardTarget = ref<RankedSource | null>(null);
const onboardInstructions = ref('');
const onboardMethodIndex = ref(0);

const pollableFingerprintIds = ref<string[]>([]);
const pollerStatus = ref<PollerStatus | null>(null);
const pollerSecret = ref('');
const pollerUsername = ref('');
const pollerInterval = ref(5);
const pollerEnabled = ref(true);
const savingCredential = ref(false);
const runningNow = ref(false);

function formatDate(date: string) {
  return new Date(date).toLocaleString();
}

function scanStatusColor(status: string) {
  if (status === 'completed') return 'success';
  if (status === 'failed') return 'danger';
  return 'warning';
}

function fingerprintName(id: string | null): string {
  if (!id) return 'Unidentified host';
  return fingerprints.value.find((f) => f.id === id)?.name || id;
}

const onboardMethods = computed(() => {
  if (!onboardTarget.value?.matched_fingerprint_id) return [];
  const fp = fingerprints.value.find((f) => f.id === onboardTarget.value?.matched_fingerprint_id);
  return fp?.log_access || [];
});

const onboardMethod = computed(() => onboardMethods.value[onboardMethodIndex.value] || null);

const isPollableMethod = computed(
  () =>
    onboardMethod.value?.method === 'api_pull' &&
    !!onboardTarget.value?.matched_fingerprint_id &&
    pollableFingerprintIds.value.includes(onboardTarget.value.matched_fingerprint_id)
);

// Only ever non-null under the opt-in host-networking mode (see ScopePreview.detected_lan_cidr) --
// hidden once it's already been added so the suggestion doesn't linger after being accepted.
const showDetectedCidrSuggestion = computed(
  () => !!scope.value?.detected_lan_cidr && !manualCidrs.value.includes(scope.value.detected_lan_cidr)
);

async function loadScope() {
  scope.value = await logDiscoveryService.getScope(manualCidrs.value);
}

async function loadScans() {
  scans.value = await logDiscoveryService.getScans();
}

async function loadFingerprints() {
  fingerprints.value = await logDiscoveryService.getFingerprints();
}

async function loadPollableFingerprints() {
  pollableFingerprintIds.value = await logDiscoveryService.getPollableFingerprintIds();
}

async function loadSources() {
  loading.value = true;
  try {
    const result = await logDiscoveryService.getSources();
    top.value = result.top;
    advanced.value = result.advanced;
  } finally {
    loading.value = false;
  }
}

function refreshAll() {
  loadScope();
  loadScans();
  loadSources();
}

async function triggerScan(mode: DiscoveryScanMode) {
  scanning.value = true;
  try {
    const result = await logDiscoveryService.triggerScan(mode, manualCidrs.value);
    ElMessage.success(`Scan #${result.scan_id} started`);
    if (result.vlan_warning) ElMessage.warning(result.vlan_warning);
    setTimeout(refreshAll, 3000);
  } catch (err: any) {
    ElMessage.error(err.response?.data?.message || 'Failed to start scan');
  } finally {
    scanning.value = false;
  }
}

async function cancelScan(row: DiscoveryScan) {
  try {
    const result = await logDiscoveryService.cancelScan(row.id);
    if (result.cancelled) {
      ElMessage.success(`Scan #${row.id} cancelled`);
    } else {
      ElMessage.info(`Scan #${row.id} already finished (${result.scan.status})`);
    }
    loadScans();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.message || 'Failed to cancel scan');
  }
}

function openManualCidrDialog() {
  manualCidrInput.value = manualCidrs.value.join(', ');
  showManualCidrDialog.value = true;
}

async function previewManualCidrs() {
  const cidrs = manualCidrInput.value.split(',').map((c) => c.trim()).filter(Boolean);
  scope.value = await logDiscoveryService.getScope(cidrs);
  if (scope.value.rejected_cidrs.length > 0) {
    ElMessage.warning(`Ignored invalid or too-large CIDR(s) (max /22): ${scope.value.rejected_cidrs.join(', ')}`);
  }
  manualCidrs.value = scope.value.cidrs;
  showManualCidrDialog.value = false;
}

// Folds the detected LAN CIDR into the same manualCidrs/getScope flow previewManualCidrs()
// uses for hand-entered subnets -- one click, no separate endpoint.
async function addDetectedCidr() {
  const detected = scope.value?.detected_lan_cidr;
  if (!detected) return;
  const cidrs = Array.from(new Set([...manualCidrs.value, detected]));
  scope.value = await logDiscoveryService.getScope(cidrs);
  manualCidrs.value = scope.value.cidrs;
  ElMessage.success(`Added ${detected} to scan scope`);
}

async function confirmSource(source: RankedSource) {
  await logDiscoveryService.confirmSource(source.id);
  ElMessage.success('Confirmed');
  loadSources();
}

async function ignoreSource(source: RankedSource) {
  try {
    await ElMessageBox.confirm('Dismiss this source? It will not resurface in the ranked list.', 'Ignore source', {
      type: 'warning',
    });
  } catch {
    return; // user cancelled
  }
  await logDiscoveryService.ignoreSource(source.id);
  loadSources();
}

async function loadOnboardPreview() {
  if (!onboardTarget.value) return;
  const preview = await logDiscoveryService.previewOnboard(onboardTarget.value.id, onboardMethodIndex.value);
  onboardInstructions.value = preview.instructions;
}

async function loadPollerStatus() {
  if (!onboardTarget.value || !isPollableMethod.value) {
    pollerStatus.value = null;
    return;
  }
  pollerStatus.value = await logDiscoveryService.getPollerStatus(onboardTarget.value.id);
  pollerEnabled.value = pollerStatus.value.enabled ?? true;
  pollerInterval.value = pollerStatus.value.poll_interval_minutes ?? 5;
}

async function onOnboardMethodChange() {
  pollerSecret.value = '';
  pollerUsername.value = '';
  await Promise.all([loadOnboardPreview(), loadPollerStatus()]);
}

async function openOnboard(source: RankedSource) {
  onboardTarget.value = source;
  onboardMethodIndex.value = 0;
  pollerSecret.value = '';
  pollerUsername.value = '';
  pollerStatus.value = null;
  showOnboardDialog.value = true;
  await Promise.all([loadOnboardPreview(), loadPollerStatus()]);
}

async function savePollerCredential() {
  if (!onboardTarget.value || !pollerSecret.value.trim()) return;
  savingCredential.value = true;
  try {
    pollerStatus.value = await logDiscoveryService.savePollerCredential(
      onboardTarget.value.id,
      pollerSecret.value.trim(),
      pollerUsername.value.trim() || undefined
    );
    pollerSecret.value = '';
    pollerEnabled.value = pollerStatus.value.enabled ?? true;
    pollerInterval.value = pollerStatus.value.poll_interval_minutes ?? 5;
    ElMessage.success('Token saved — polling will start on the next cycle');
    loadSources();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.message || 'Failed to save token');
  } finally {
    savingCredential.value = false;
  }
}

async function revokePollerCredential() {
  if (!onboardTarget.value) return;
  try {
    await ElMessageBox.confirm('Stop polling this source and forget the saved token?', 'Revoke token', { type: 'warning' });
  } catch {
    return; // user cancelled
  }
  await logDiscoveryService.revokePollerCredential(onboardTarget.value.id);
  pollerStatus.value = { configured: false };
  ElMessage.success('Token revoked');
  loadSources();
}

async function togglePolling(enabled: boolean) {
  if (!onboardTarget.value) return;
  pollerStatus.value = await logDiscoveryService.setPolling(onboardTarget.value.id, { enabled });
  loadSources();
}

async function updatePollerInterval(minutes: number | undefined) {
  if (!onboardTarget.value || !minutes) return;
  pollerStatus.value = await logDiscoveryService.setPolling(onboardTarget.value.id, { poll_interval_minutes: minutes });
}

async function runPollNow() {
  if (!onboardTarget.value) return;
  runningNow.value = true;
  try {
    const result = await logDiscoveryService.runPollNow(onboardTarget.value.id);
    if (result.ok) {
      ElMessage.success(`Polled successfully — ${result.count} event(s)`);
    } else {
      ElMessage.error(result.error || 'Poll failed');
    }
    await loadPollerStatus();
  } finally {
    runningNow.value = false;
  }
}

async function copyInstructions() {
  await navigator.clipboard.writeText(onboardInstructions.value);
  ElMessage.success('Copied to clipboard');
}

async function confirmOnboard() {
  if (!onboardTarget.value) return;
  await logDiscoveryService.confirmOnboard(onboardTarget.value.id, onboardMethodIndex.value);
  ElMessage.success('Marked as onboarded');
  showOnboardDialog.value = false;
  loadSources();
}

onMounted(() => {
  loadFingerprints();
  loadPollableFingerprints();
  refreshAll();
});
</script>

<style scoped>
.log-discovery-container {
  padding: 20px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.title {
  font-size: 18px;
  font-weight: 600;
}
.header-actions {
  display: flex;
  gap: 8px;
}
.scope-line {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.scope-empty {
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
.scope-label {
  font-weight: 600;
  margin-right: 4px;
}
.section h3 {
  margin: 0 0 8px;
}
.onboard-instructions {
  background: var(--el-fill-color-light);
  padding: 12px;
  border-radius: 4px;
  white-space: pre-wrap;
  font-family: monospace;
  font-size: 13px;
  max-height: 320px;
  overflow-y: auto;
}
.dialog-hint {
  color: var(--el-text-color-secondary);
  font-size: 13px;
  margin-bottom: 12px;
}
.poller-panel {
  background: var(--el-fill-color-light);
  border-radius: 4px;
  padding: 12px;
  margin-bottom: 12px;
}
.poller-head {
  font-weight: 600;
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.poller-form {
  display: flex;
  gap: 8px;
  margin-top: 10px;
  flex-wrap: wrap;
}
.poller-secret {
  flex: 1;
  min-width: 200px;
}
.poller-username {
  width: 140px;
}
.poller-controls {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 10px;
  flex-wrap: wrap;
}
.poller-interval-label {
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
.poller-last-polled {
  color: var(--el-text-color-secondary);
  font-size: 12px;
  margin-left: auto;
}
</style>
