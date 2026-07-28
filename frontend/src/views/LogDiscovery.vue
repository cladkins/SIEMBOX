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
        <el-select v-if="onboardMethods.length > 1" v-model="onboardMethodIndex" @change="loadOnboardPreview" style="margin-bottom: 12px">
          <el-option v-for="(m, idx) in onboardMethods" :key="idx" :label="m.method" :value="idx" />
        </el-select>
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

async function loadScope() {
  scope.value = await logDiscoveryService.getScope(manualCidrs.value);
}

async function loadScans() {
  scans.value = await logDiscoveryService.getScans();
}

async function loadFingerprints() {
  fingerprints.value = await logDiscoveryService.getFingerprints();
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

async function openOnboard(source: RankedSource) {
  onboardTarget.value = source;
  onboardMethodIndex.value = 0;
  showOnboardDialog.value = true;
  await loadOnboardPreview();
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
</style>
