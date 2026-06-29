<template>
  <div class="endpoints">
    <div class="page-header">
      <div>
        <h2>Endpoints</h2>
        <p class="subtitle">Enrolled SIEMBOX Endpoint agents — inventory, vulnerabilities, and detections.</p>
        <p class="subtitle">
          Agent: <a href="https://github.com/cladkins/siembox-endpoint" target="_blank" rel="noopener">github.com/cladkins/siembox-endpoint</a>
        </p>
      </div>
      <div class="actions">
        <el-button @click="refresh" :loading="loading"><el-icon><Refresh /></el-icon> Refresh</el-button>
        <el-button type="primary" @click="openTokenDialog"><el-icon><Plus /></el-icon> Enroll an endpoint</el-button>
      </div>
    </div>

    <!-- Agent list -->
    <el-card>
      <el-table :data="endpoints" v-loading="loading" stripe>
        <el-table-column label="Host" min-width="180">
          <template #default="{ row }">
            <strong>{{ row.hostname || '(unknown)' }}</strong>
            <div class="muted">{{ row.ip || '' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="OS" min-width="160">
          <template #default="{ row }">
            {{ row.os || '—' }}<span v-if="row.os_version"> {{ row.os_version }}</span>
            <div class="muted">{{ row.arch || '' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="Status" width="110">
          <template #default="{ row }">
            <el-tag :type="row.live_status === 'online' ? 'success' : 'info'" size="small" effect="dark">
              {{ row.live_status }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Agent" width="100">
          <template #default="{ row }"><span class="muted">{{ row.agent_version || '—' }}</span></template>
        </el-table-column>
        <el-table-column label="Open vulns" width="110" align="center">
          <template #default="{ row }">
            <el-tag v-if="Number(row.open_vulns) > 0" type="warning" size="small">{{ row.open_vulns }}</el-tag>
            <span v-else class="muted">0</span>
          </template>
        </el-table-column>
        <el-table-column label="Detections (7d)" width="130" align="center">
          <template #default="{ row }">
            <el-tag v-if="Number(row.recent_detections) > 0" type="danger" size="small">{{ row.recent_detections }}</el-tag>
            <span v-else class="muted">0</span>
          </template>
        </el-table-column>
        <el-table-column label="Last seen" width="170">
          <template #default="{ row }">{{ row.last_seen ? formatDate(row.last_seen) : 'never' }}</template>
        </el-table-column>
        <el-table-column label="Last scan" width="190">
          <template #default="{ row }">
            <template v-if="row.last_scan_completed_at || row.last_scan_at">
              {{ formatDate(row.last_scan_completed_at || row.last_scan_at) }}
              <div class="muted" v-if="row.next_scan_at">next ≈ {{ formatDate(row.next_scan_at) }}</div>
            </template>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column label="" width="150" align="right">
          <template #default="{ row }">
            <el-button size="small" @click="openDetail(row)">Details</el-button>
            <el-button size="small" type="danger" plain @click="removeEndpoint(row)">Remove</el-button>
          </template>
        </el-table-column>
        <template #empty>No endpoints enrolled yet. Click <strong>Enroll an endpoint</strong> to generate a token.</template>
      </el-table>
    </el-card>

    <!-- YARA rules status -->
    <el-card style="margin-top: 16px">
      <template #header>
        <div class="card-header-row">
          <span>YARA rules</span>
          <el-button size="small" :loading="yara.refreshing" @click="pullYaraForge">Pull YARA-Forge now</el-button>
        </div>
      </template>
      <el-descriptions :column="4" size="small" border>
        <el-descriptions-item label="Version">
          <el-tag v-if="yara.status && yara.status.version > 0" type="success" size="small">v{{ yara.status.version }}</el-tag>
          <span v-else class="muted">none — agents use baseline only</span>
        </el-descriptions-item>
        <el-descriptions-item label="Source">{{ yara.status?.source || '—' }}</el-descriptions-item>
        <el-descriptions-item label="Size">{{ yara.status ? humanBytes(yara.status.bytes) : '—' }}</el-descriptions-item>
        <el-descriptions-item label="Updated">{{ yara.status?.created_at ? formatDate(yara.status.created_at) : '—' }}</el-descriptions-item>
      </el-descriptions>
      <p class="muted" style="margin: 8px 0 0">
        Served to agents at <code>GET /api/edr/agents/:id/yara</code>; each appends its built-in baseline.
        The starter bundle ships by default — enable the daily YARA-Forge import with
        <code>EDR_YARA_FORGE_ENABLED=true</code>.
      </p>
    </el-card>

    <!-- Enrollment tokens -->
    <el-card style="margin-top: 16px">
      <template #header><span>Enrollment tokens</span></template>
      <el-table :data="tokens" size="small" stripe>
        <el-table-column prop="label" label="Label" min-width="160">
          <template #default="{ row }">{{ row.label || '(no label)' }}</template>
        </el-table-column>
        <el-table-column label="Created" width="180">
          <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="Expires" width="180">
          <template #default="{ row }">{{ row.expires_at ? formatDate(row.expires_at) : 'never' }}</template>
        </el-table-column>
        <el-table-column label="Status" width="120">
          <template #default="{ row }">
            <el-tag v-if="row.used" type="info" size="small">used</el-tag>
            <el-tag v-else-if="row.expired" type="danger" size="small">expired</el-tag>
            <el-tag v-else type="success" size="small">active</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="" width="120" align="right">
          <template #default="{ row }">
            <el-button size="small" type="danger" plain @click="revokeToken(row)">
              {{ row.used || row.expired ? 'Remove' : 'Revoke' }}
            </el-button>
          </template>
        </el-table-column>
        <template #empty>No tokens issued.</template>
      </el-table>
    </el-card>

    <!-- Generate-token dialog -->
    <el-dialog v-model="tokenDialog" title="Enroll an endpoint" width="640px">
      <template v-if="!generated">
        <el-form label-width="130px">
          <el-form-item label="Label">
            <el-input v-model="tokenForm.label" placeholder="e.g. web-server-01 (optional)" />
          </el-form-item>
          <el-form-item label="Expires in (hours)">
            <el-input-number v-model="tokenForm.expires_in_hours" :min="0" :step="1" />
            <span class="muted" style="margin-left: 8px">0 = never expires. Tokens are single-use.</span>
          </el-form-item>
        </el-form>
      </template>

      <template v-else>
        <el-alert type="success" :closable="false" title="Token generated — copy it now, it won't be shown again." style="margin-bottom: 12px" />
        <div class="token-row">
          <el-input v-model="generated" readonly />
          <el-button @click="copy(generated)"><el-icon><CopyDocument /></el-icon></el-button>
        </div>
        <p style="margin: 14px 0 6px"><strong>Install on the endpoint</strong></p>
        <p class="muted" style="margin: 0 0 8px">
          Point the agent at this server and enroll with the token above. See the agent's
          <code>scripts/install.sh</code> / release assets in the
          <a href="https://github.com/cladkins/siembox-endpoint" target="_blank" rel="noopener">SIEMBOX Endpoint</a> repo.
        </p>
        <pre class="install">{{ installSnippet }}</pre>
      </template>

      <template #footer>
        <el-button @click="tokenDialog = false">Close</el-button>
        <el-button v-if="!generated" type="primary" :loading="generating" @click="generateToken">Generate</el-button>
        <el-button v-else type="primary" @click="resetToken">Generate another</el-button>
      </template>
    </el-dialog>

    <!-- Endpoint detail drawer -->
    <el-drawer v-model="detailOpen" :title="detail.agent ? (detail.agent.hostname || 'Endpoint') : 'Endpoint'" size="60%">
      <div v-if="detail.agent">
        <el-descriptions :column="2" border size="small" style="margin-bottom: 16px">
          <el-descriptions-item label="Hostname">{{ detail.agent.hostname || '—' }}</el-descriptions-item>
          <el-descriptions-item label="IP">{{ detail.agent.ip || '—' }}</el-descriptions-item>
          <el-descriptions-item label="OS">{{ detail.agent.os }} {{ detail.agent.os_version }}</el-descriptions-item>
          <el-descriptions-item label="Arch">{{ detail.agent.arch || '—' }}</el-descriptions-item>
          <el-descriptions-item label="Agent version">{{ detail.agent.agent_version || '—' }}</el-descriptions-item>
          <el-descriptions-item label="Last seen">{{ detail.agent.last_seen ? formatDate(detail.agent.last_seen) : 'never' }}</el-descriptions-item>
          <el-descriptions-item label="Last scan">
            <template v-if="detail.agent.last_scan_completed_at || detail.agent.last_scan_at">
              {{ formatDate(detail.agent.last_scan_completed_at || detail.agent.last_scan_at) }}
              <span class="muted" v-if="scanDuration(detail.agent)"> ({{ scanDuration(detail.agent) }})</span>
            </template>
            <template v-else>never</template>
          </el-descriptions-item>
          <el-descriptions-item label="Next scan ≈">{{ detail.agent.next_scan_at ? formatDate(detail.agent.next_scan_at) : '—' }}</el-descriptions-item>
          <el-descriptions-item label="Scan interval">{{ humanInterval(detail.agent.vuln_scan_interval_seconds) }}</el-descriptions-item>
        </el-descriptions>

        <el-tabs v-model="detailTab">
          <el-tab-pane :label="`Detections (${detail.detections.length})`" name="detections">
            <el-table :data="detail.detections" v-loading="detail.loading" size="small" stripe max-height="420">
              <el-table-column label="Severity" width="110">
                <template #default="{ row }"><el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag></template>
              </el-table-column>
              <el-table-column prop="title" label="Detection" min-width="240" show-overflow-tooltip />
              <el-table-column prop="status" label="Status" width="120" />
              <el-table-column label="When" width="170">
                <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
              </el-table-column>
              <template #empty>No detections for this endpoint.</template>
            </el-table>
          </el-tab-pane>
          <el-tab-pane :label="`Vulnerabilities (${detail.vulns.length})`" name="vulns">
            <el-table :data="detail.vulns" v-loading="detail.loading" size="small" stripe max-height="420">
              <el-table-column label="Severity" width="110">
                <template #default="{ row }">
                  <el-tag :type="severityType(row.vulnerability?.severity)" size="small">{{ row.vulnerability?.severity || '—' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="CVE" width="180">
                <template #default="{ row }">{{ row.vulnerability?.cve_id || '—' }}</template>
              </el-table-column>
              <el-table-column label="Title" min-width="240" show-overflow-tooltip>
                <template #default="{ row }">{{ row.vulnerability?.title || '—' }}</template>
              </el-table-column>
              <el-table-column label="CVSS" width="90" align="center">
                <template #default="{ row }">{{ row.vulnerability?.cvss_score ?? '—' }}</template>
              </el-table-column>
              <el-table-column prop="status" label="Status" width="100" />
              <template #empty>No vulnerabilities reported for this endpoint.</template>
            </el-table>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { api } from '@/services/api';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Refresh, Plus, CopyDocument } from '@element-plus/icons-vue';
import { format } from 'date-fns';

const loading = ref(false);
const endpoints = ref<any[]>([]);
const tokens = ref<any[]>([]);
const yara = reactive<{ status: any | null; refreshing: boolean }>({ status: null, refreshing: false });

const tokenDialog = ref(false);
const generating = ref(false);
const generated = ref('');
const tokenForm = reactive({ label: '', expires_in_hours: 0 });

const detailOpen = ref(false);
const detailTab = ref('detections');
const detail = reactive<{ agent: any; detections: any[]; vulns: any[]; loading: boolean }>({
  agent: null, detections: [], vulns: [], loading: false,
});

const serverUrl = computed(() => `https://${window.location.hostname}:8421`);
const installSnippet = computed(() =>
  `# agent.json on the endpoint\n{\n  "server_url": "${serverUrl.value}",\n  "enrollment_token": "${generated.value}"\n}\n\n# then run the agent:\nsiembox-agent -dir /etc/siembox-agent run`
);

async function fetchEndpoints() {
  const res = await api.getEndpoints();
  endpoints.value = res.data.agents || [];
}
async function fetchTokens() {
  const res = await api.getEnrollmentTokens();
  tokens.value = res.data.tokens || [];
}
async function fetchYaraStatus() {
  const res = await api.getYaraStatus();
  yara.status = res.data;
}
async function refresh() {
  loading.value = true;
  try { await Promise.all([fetchEndpoints(), fetchTokens(), fetchYaraStatus()]); }
  catch { ElMessage.error('Failed to load endpoints'); }
  finally { loading.value = false; }
}
onMounted(refresh);

async function pullYaraForge() {
  try {
    await ElMessageBox.confirm(
      'Download the latest YARA-Forge Extended pack (~3.4 MB) and publish it as a new bundle? ' +
        'Each enrolled endpoint then pulls the full rule set (~16.6 MB) on its next config poll.',
      'Pull YARA-Forge', { type: 'warning', confirmButtonText: 'Pull now', cancelButtonText: 'Cancel' }
    );
  } catch { return; }
  yara.refreshing = true;
  try {
    const res = await api.refreshYaraForge();
    ElMessage.success(res.data.updated ? `Published YARA bundle v${res.data.version}` : 'Already up to date');
    await fetchYaraStatus();
  } catch { ElMessage.error('YARA-Forge refresh failed (check server egress and logs)'); }
  finally { yara.refreshing = false; }
}

function openTokenDialog() {
  generated.value = '';
  tokenForm.label = '';
  tokenForm.expires_in_hours = 0;
  tokenDialog.value = true;
}
async function generateToken() {
  generating.value = true;
  try {
    const res = await api.createEnrollmentToken({
      label: tokenForm.label || undefined,
      expires_in_hours: tokenForm.expires_in_hours || undefined,
    });
    generated.value = res.data.token;
    fetchTokens();
  } catch { ElMessage.error('Failed to generate token'); }
  finally { generating.value = false; }
}
function resetToken() { generated.value = ''; }

async function revokeToken(row: any) {
  const active = !row.used && !row.expired;
  try {
    await ElMessageBox.confirm(
      active
        ? 'Revoke this enrollment token? It can no longer be used to enroll an endpoint.'
        : 'Remove this token from the list?',
      active ? 'Revoke token' : 'Remove token',
      { type: 'warning', confirmButtonText: active ? 'Revoke' : 'Remove', cancelButtonText: 'Cancel' }
    );
  } catch { return; }
  try {
    await api.revokeEnrollmentToken(row.token_hash);
    ElMessage.success(active ? 'Token revoked' : 'Token removed');
    fetchTokens();
  } catch { ElMessage.error('Failed to revoke token'); }
}

async function copy(text: string) {
  try { await navigator.clipboard.writeText(text); ElMessage.success('Copied'); }
  catch { ElMessage.warning('Copy failed — select and copy manually'); }
}

async function openDetail(agent: any) {
  detail.agent = agent;
  detail.detections = [];
  detail.vulns = [];
  detail.loading = true;
  detailTab.value = 'detections';
  detailOpen.value = true;
  try {
    const [d, v] = await Promise.all([
      api.getEndpointDetections(agent.agent_id),
      api.getEndpointVulnerabilities(agent.agent_id),
    ]);
    detail.detections = d.data.alerts || [];
    detail.vulns = v.data.vulnerabilities || [];
  } catch { ElMessage.error('Failed to load endpoint detail'); }
  finally { detail.loading = false; }
}

async function removeEndpoint(agent: any) {
  try {
    await ElMessageBox.confirm(
      `Remove endpoint "${agent.hostname || agent.agent_id}"? This deregisters the agent (its asset, alerts, and vulnerabilities are kept).`,
      'Remove endpoint', { type: 'warning', confirmButtonText: 'Remove', cancelButtonText: 'Cancel' }
    );
  } catch { return; }
  try { await api.deleteEndpoint(agent.agent_id); ElMessage.success('Endpoint removed'); refresh(); }
  catch { ElMessage.error('Failed to remove endpoint'); }
}

function formatDate(d: string) { return format(new Date(d), 'MMM dd, yyyy HH:mm'); }
function scanDuration(a: any): string {
  if (!a?.last_scan_started_at || !a?.last_scan_completed_at) return '';
  const ms = new Date(a.last_scan_completed_at).getTime() - new Date(a.last_scan_started_at).getTime();
  if (!(ms > 0)) return '';
  const s = Math.round(ms / 1000);
  return s < 60 ? `took ${s}s` : `took ${Math.floor(s / 60)}m ${s % 60}s`;
}
function humanInterval(sec?: number): string {
  if (!sec) return '—';
  if (sec === 86400) return 'daily';
  if (sec === 3600) return 'hourly';
  if (sec % 86400 === 0) return `every ${sec / 86400}d`;
  if (sec % 3600 === 0) return `every ${sec / 3600}h`;
  return `every ${Math.round(sec / 60)}m`;
}
function humanBytes(n: number): string {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${u[i]}`;
}
function severityType(sev: string): string {
  const m: Record<string, string> = { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', info: 'info' };
  return m[sev] || 'info';
}
</script>

<style scoped>
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
.card-header-row { display: flex; justify-content: space-between; align-items: center; }
.page-header h2 { margin: 0; }
.subtitle { margin: 4px 0 0; color: var(--el-text-color-secondary); font-size: 13px; }
.muted { color: var(--el-text-color-secondary); font-size: 12px; }
.token-row { display: flex; gap: 8px; }
.install {
  background: var(--siembox-bg-color, var(--el-fill-color-light));
  padding: 12px; border-radius: 4px; font-size: 12px; overflow-x: auto; margin: 0;
}
</style>
