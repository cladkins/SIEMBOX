<template>
  <div class="log-discovery-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <span class="title">Log Discovery</span>
          <div class="header-actions">
            <el-select
              v-model="selectedShipperId"
              size="default"
              style="width: 230px"
              placeholder="Run from…"
            >
              <el-option :label="'Run from: Built-in'" :value="null" />
              <el-option
                v-for="s in shippers"
                :key="s.id"
                :label="`Run from: ${s.name}${s.status !== 'online' ? ` (${s.status})` : ''}`"
                :value="s.id"
                :disabled="s.status !== 'online'"
              />
            </el-select>
            <el-button @click="triggerScan('passive')" :loading="scanning">
              <el-icon><Aim /></el-icon>
              Scan (passive)
            </el-button>
            <el-button type="primary" @click="triggerScan('full')" :loading="scanning">
              <el-icon><Search /></el-icon>
              Scan (passive + active)
            </el-button>
            <el-button type="success" @click="openManualSourceDialog">
              <el-icon><Plus /></el-icon>
              Add API pull source
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
        <el-tag
          v-for="cidr in manualCidrs"
          :key="cidr"
          size="small"
          closable
          style="margin-right: 6px"
          @close="removeCidr(cidr)"
        >{{ cidr }}</el-tag>
        <span v-if="!manualCidrs.length" class="scope-empty">No subnets added yet — passive discovery still works without one.</span>
        <el-button link size="small" @click="openManualCidrDialog">Add a subnet</el-button>
      </div>

      <div v-if="showDetectedCidrSuggestion" class="scope-line">
        <span class="scope-label">Detected LAN:</span>
        <el-tag type="success" size="small" style="margin-right: 6px">{{ scope?.detected_lan_cidr }}</el-tag>
        <el-button link size="small" type="primary" @click="addDetectedCidr">Add to scan scope</el-button>
      </div>

      <div v-if="selectedShipperId" class="scope-line">
        <el-text size="small" type="info">
          Scans run on the selected log shipper, out on its LAN. Passive discovery (ARP/mDNS/SSDP) needs that shipper on host networking to see the segment — otherwise it falls back to the active sweep.
        </el-text>
      </div>

      <el-collapse v-if="scans.length > 0" style="margin: 16px 0">
        <el-collapse-item title="Recent scans" name="scans">
          <el-table :data="scans" size="small">
            <el-table-column prop="id" label="ID" width="70" />
            <el-table-column prop="mode" label="Mode" width="140" />
            <el-table-column label="Run from" width="130">
              <template #default="{ row }">
                <el-tag size="small" :type="row.assigned_shipper_name ? 'info' : undefined">
                  {{ row.assigned_shipper_name || 'Built-in' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Subnet" min-width="160">
              <template #default="{ row }">
                <span v-if="row.cidrs?.length">{{ row.cidrs.join(', ') }}</span>
                <span v-else class="scope-empty">none added</span>
              </template>
            </el-table-column>
            <el-table-column label="Status" width="120">
              <template #default="{ row }">
                <el-tooltip
                  v-if="row.status === 'failed' && row.error_message"
                  :content="row.error_message"
                  placement="top"
                >
                  <el-tag :type="scanStatusColor(row.status)" size="small" style="cursor: help">{{ row.status }}</el-tag>
                </el-tooltip>
                <el-tag v-else :type="scanStatusColor(row.status)" size="small">{{ row.status }}</el-tag>
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
                <el-button
                  v-if="row.status === 'running' || row.status === 'queued'"
                  size="small"
                  type="danger"
                  plain
                  @click="cancelScan(row)"
                >
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
          @delete="deleteSource"
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
            @delete="deleteSource"
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

    <!-- Add API pull source dialog (manual, scan-less). Separate from the Onboard dialog,
         which operates on an already-discovered source. -->
    <el-dialog v-model="showManualSourceDialog" title="Add an API pull source" width="560px">
      <p class="dialog-hint">
        Already know a device SIEMBox can poll (Authentik, Home Assistant, Pi-hole, AdGuard Home)?
        Add it here by type, address and token — no network scan needed. SIEMBox pulls its events on
        the schedule below; the token is encrypted at rest and never shown again after saving.
      </p>
      <el-form label-position="top">
        <el-form-item label="Device type">
          <el-select
            v-model="manualForm.fingerprint_id"
            placeholder="Select a device type"
            style="width: 100%"
            @change="onManualFingerprintChange"
          >
            <el-option v-for="f in pollableFingerprints" :key="f.id" :label="f.name" :value="f.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="IP address">
          <el-input v-model="manualForm.ip_address" placeholder="192.168.1.50" />
          <span class="field-hint">The poller connects directly to this IP — enter a literal address, not a DNS name.</span>
        </el-form-item>
        <el-form-item label="Port">
          <el-input-number v-model="manualForm.port" :min="1" :max="65535" controls-position="right" />
          <span class="field-hint">Pre-filled from the device type; edit it if the device runs on a custom port.</span>
        </el-form-item>
        <el-form-item label="Use HTTPS">
          <el-switch v-model="manualForm.tls" />
        </el-form-item>
        <el-form-item v-if="manualAuthBasic" label="Username">
          <el-input v-model="manualForm.username" placeholder="Username" />
        </el-form-item>
        <el-form-item label="API token / secret">
          <el-input
            v-model="manualForm.secret"
            type="password"
            show-password
            clearable
            placeholder="Paste API token…"
          />
        </el-form-item>
        <el-form-item label="Poll every (minutes)">
          <el-input-number v-model="manualForm.poll_interval_minutes" :min="1" :max="1440" controls-position="right" />
        </el-form-item>
        <el-form-item label="Start polling now">
          <el-switch v-model="manualForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showManualSourceDialog = false">Cancel</el-button>
        <el-button type="primary" :loading="submittingManual" @click="submitManualSource">Add source</el-button>
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
import { Search, Refresh, Aim, Plus } from '@element-plus/icons-vue';
import logDiscoveryService, {
  type RankedSource,
  type DiscoveryScan,
  type ScopePreview,
  type FingerprintEntry,
  type DiscoveryScanMode,
  type PollerStatus,
  type ShipperSummary,
} from '@/services/logDiscoveryService';
import DiscoverySourcesTable from '@/components/DiscoverySourcesTable.vue';

const loading = ref(false);
const scanning = ref(false);
const scope = ref<ScopePreview | null>(null);
const scans = ref<DiscoveryScan[]>([]);

// Optional LAN-side dispatch: run the scan from a log shipper (null = backend).
const shippers = ref<ShipperSummary[]>([]);
const selectedShipperId = ref<number | null>(null);
const top = ref<RankedSource[]>([]);
const advanced = ref<RankedSource[]>([]);
const fingerprints = ref<FingerprintEntry[]>([]);

const showManualCidrDialog = ref(false);
const manualCidrInput = ref('');
// The confirmed scan-scope CIDRs. Loaded from the server's persisted standing
// scope on mount and re-saved on every change, so a subnet you add sticks
// across page loads / devices instead of living only in this component. It's
// also what's threaded into loadScope() and every triggerScan() call.
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

// "Add API pull source" dialog: a manual, scan-less entry point. Reuses the same
// poller machinery (credential/polling/run-now) as the discovered-source flow.
const showManualSourceDialog = ref(false);
const submittingManual = ref(false);
const manualForm = ref<{
  fingerprint_id: string;
  ip_address: string;
  port: number | undefined;
  tls: boolean;
  username: string;
  secret: string;
  poll_interval_minutes: number;
  enabled: boolean;
}>({
  fingerprint_id: '',
  ip_address: '',
  port: undefined,
  tls: false,
  username: '',
  secret: '',
  poll_interval_minutes: 5,
  enabled: true,
});

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

// Only device types that actually have a poll adapter can be added manually.
const pollableFingerprints = computed(() =>
  fingerprints.value.filter((f) => pollableFingerprintIds.value.includes(f.id))
);
const manualFingerprint = computed(
  () => fingerprints.value.find((f) => f.id === manualForm.value.fingerprint_id) || null
);
const manualApiPull = computed(() => manualFingerprint.value?.log_access.find((la) => la.method === 'api_pull') || null);
// adguard-home uses HTTP Basic → it needs a username alongside the secret (mirrors the Onboard panel).
const manualAuthBasic = computed(() => manualApiPull.value?.auth === 'basic');

// Only ever non-null under the opt-in host-networking mode (see ScopePreview.detected_lan_cidr) --
// hidden once it's already been added so the suggestion doesn't linger after being accepted.
const showDetectedCidrSuggestion = computed(
  () => !!scope.value?.detected_lan_cidr && !manualCidrs.value.includes(scope.value.detected_lan_cidr)
);

async function loadScope() {
  scope.value = await logDiscoveryService.getScope(manualCidrs.value);
}

// Load the persisted standing scope into manualCidrs so the scope tags show it
// and triggerScan() uses it. Best-effort: a failure just leaves the scope empty.
async function loadScopeCidrs() {
  try {
    manualCidrs.value = await logDiscoveryService.getScopeCidrs();
  } catch {
    manualCidrs.value = [];
  }
}

// Persist a new scan-scope set server-side and reflect the server's accepted
// result back into local state. Shared by the add/preview/remove paths so the
// scope always matches what's stored.
async function persistScope(next: string[]) {
  try {
    const { cidrs, rejected } = await logDiscoveryService.saveScopeCidrs(next);
    manualCidrs.value = cidrs;
    if (rejected.length > 0) {
      ElMessage.warning(`Ignored invalid or too-large CIDR(s) (max /22): ${rejected.join(', ')}`);
    }
    await loadScope();
    return true;
  } catch (err: any) {
    ElMessage.error(err.response?.data?.message || 'Failed to save scan scope');
    return false;
  }
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

// The "Run from" picker is a convenience, not a dependency: if the shippers list
// can't be fetched, fall back to an empty list so the page still runs built-in scans.
async function loadShippers() {
  try {
    shippers.value = await logDiscoveryService.getShippers();
  } catch {
    shippers.value = [];
  }
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
    const result = await logDiscoveryService.triggerScan(mode, manualCidrs.value, selectedShipperId.value);
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

// The dialog is a full editor of the scope: whatever's in the box becomes the
// new persisted set (the box is pre-filled with the current scope on open).
async function previewManualCidrs() {
  const cidrs = manualCidrInput.value.split(',').map((c) => c.trim()).filter(Boolean);
  await persistScope(cidrs);
  showManualCidrDialog.value = false;
}

// Folds the detected LAN CIDR into the persisted scope -- one click, same flow
// as a hand-entered subnet.
async function addDetectedCidr() {
  const detected = scope.value?.detected_lan_cidr;
  if (!detected) return;
  const next = Array.from(new Set([...manualCidrs.value, detected]));
  if (await persistScope(next)) {
    ElMessage.success(`Added ${detected} to scan scope`);
  }
}

// Remove one subnet from the scan scope and persist the smaller set.
async function removeCidr(cidr: string) {
  const next = manualCidrs.value.filter((c) => c !== cidr);
  if (await persistScope(next)) {
    ElMessage.success(`Removed ${cidr} from scan scope`);
  }
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

function openManualSourceDialog() {
  manualForm.value = {
    fingerprint_id: '',
    ip_address: '',
    port: undefined,
    tls: false,
    username: '',
    secret: '',
    poll_interval_minutes: 5,
    enabled: true,
  };
  showManualSourceDialog.value = true;
}

// Prefill the port from the chosen device type's api_pull target_port, and default
// HTTPS on for Authentik (served on 9443/TLS) and off for the others — the admin can
// still override both. Clear a stale username when the new type isn't Basic-auth.
function onManualFingerprintChange() {
  manualForm.value.port = manualApiPull.value?.target_port;
  manualForm.value.tls = manualForm.value.fingerprint_id === 'authentik';
  if (!manualAuthBasic.value) manualForm.value.username = '';
}

async function submitManualSource() {
  const form = manualForm.value;
  if (!form.fingerprint_id) return ElMessage.warning('Pick a device type');
  if (!form.ip_address.trim()) return ElMessage.warning('Enter the IP address');
  if (!form.port) return ElMessage.warning('Enter the port');
  if (manualAuthBasic.value && !form.username.trim()) return ElMessage.warning('This device type needs a username');
  if (!form.secret.trim()) return ElMessage.warning('Paste the API token / secret');

  submittingManual.value = true;
  try {
    // 1) create the scan-less source, 2-3) reuse the existing poller routes to save
    // the credential + polling schedule, 4) poll once immediately for instant feedback.
    const { id } = await logDiscoveryService.createManualSource({
      ip_address: form.ip_address.trim(),
      fingerprint_id: form.fingerprint_id,
      port: form.port,
      tls: form.tls,
    });
    await logDiscoveryService.savePollerCredential(
      id,
      form.secret.trim(),
      manualAuthBasic.value ? form.username.trim() : undefined
    );
    await logDiscoveryService.setPolling(id, { poll_interval_minutes: form.poll_interval_minutes, enabled: form.enabled });
    const poll = await logDiscoveryService.runPollNow(id);
    if (poll.ok) {
      ElMessage.success(`Source added — first poll pulled ${poll.count} event(s)`);
    } else {
      ElMessage.warning(`Source added, but the first poll failed: ${poll.error || 'unknown error'}`);
    }
    showManualSourceDialog.value = false;
    loadSources();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.message || 'Failed to add source');
  } finally {
    submittingManual.value = false;
  }
}

async function deleteSource(source: RankedSource) {
  try {
    await ElMessageBox.confirm(
      `Delete ${source.hostname || source.ip}? This removes the source and stops polling it.`,
      'Delete source',
      { type: 'warning' }
    );
  } catch {
    return; // user cancelled
  }
  try {
    await logDiscoveryService.deleteSource(source.id);
    ElMessage.success('Source deleted');
    loadSources();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.message || 'Failed to delete source');
  }
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

onMounted(async () => {
  loadFingerprints();
  loadPollableFingerprints();
  loadShippers();
  // Load the persisted scope before the first scope fetch so the tags render it.
  await loadScopeCidrs();
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
.field-hint {
  display: block;
  color: var(--el-text-color-secondary);
  font-size: 12px;
  line-height: 1.4;
  margin-top: 2px;
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
