<template>
  <div class="application-monitoring">
    <div class="page-header">
      <div>
        <h2>Application Monitoring</h2>
        <p class="subtitle">
          The software running on your network, from what SIEMBox already sees: log program names, which parser matched, nmap
          services, the container images log shippers report, endpoint-agent findings, and the user agents and DNS queries in
          your logs, matched against the catalog's application signatures.
        </p>
      </div>
      <el-button v-if="canRefresh" :loading="refreshing" @click="refresh">
        <el-icon><Refresh /></el-icon> Refresh now
      </el-button>
    </div>

    <el-alert v-if="loadError" type="error" :closable="false" :title="loadError" show-icon class="block" />
    <div v-if="status" class="status-line" data-test="status">
      <el-tag size="small" :type="status.enabled ? (status.caught_up ? 'success' : 'warning') : 'info'">
        {{ !status.enabled ? 'Switched off' : status.caught_up ? 'Up to date' : 'Building (processing existing logs)' }}
      </el-tag>
      <span>{{ signatureSourceText(status.signatures.source, status.signatures.count) }}</span>
      <span v-if="status.covered_until">· logs up to {{ ageLabel(status.covered_until) }}</span>
      <span>· listed for {{ status.retention_days }} days after last seen</span>
      <el-tooltip v-if="status.signatures.error || status.signatures.refused.length" placement="bottom">
        <template #content>
          <div v-if="status.signatures.error">{{ status.signatures.error }}</div>
          <div v-for="(r, i) in status.signatures.refused.slice(0, 10)" :key="i">{{ r.appId }} {{ r.location }}: {{ r.reason }}</div>
        </template>
        <el-tag size="small" type="warning">{{ status.signatures.refused.length ? 'signature problems' : 'catalog notice' }}</el-tag>
      </el-tooltip>
    </div>

    <el-card class="block">
      <div class="filters">
        <el-input v-model="filters.search" placeholder="Search applications" clearable class="f-search" @input="debouncedLoad">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-select v-model="filters.category" placeholder="Category" clearable class="f-select" @change="load">
          <el-option v-for="c in categories" :key="c" :label="categoryLabel(c)" :value="c" />
        </el-select>
        <el-select v-model="filters.source" placeholder="Evidence source" clearable class="f-select" @change="load">
          <el-option v-for="s in SOURCE_ORDER" :key="s" :label="SOURCE_LABELS[s].label" :value="s" />
        </el-select>
        <el-input v-model="filters.host" placeholder="Host, IP or shipper" clearable class="f-host" @input="debouncedLoad" />
      </div>

      <el-tabs v-model="tab" class="tabs">
        <el-tab-pane :label="`Inventory (${apps.length})`" name="inventory">
          <el-table v-loading="loading" :data="apps" size="small" class="clickable" empty-text="Nothing identified yet" @row-click="open">
            <el-table-column label="Application" min-width="190">
              <template #default="{ row }">
                <div class="app-name">{{ row.name }}</div>
                <div class="muted">{{ row.vendor }}</div>
              </template>
            </el-table-column>
            <el-table-column label="Category" width="140">
              <template #default="{ row }"><el-tag size="small" effect="plain">{{ categoryLabel(row.category) }}</el-tag></template>
            </el-table-column>
            <el-table-column label="Versions" min-width="170">
              <template #default="{ row }">
                <el-tag
                  v-for="v in row.versions.slice(0, 4)"
                  :key="v.version"
                  size="small"
                  :type="isBehind(v.version, row.latest_version) ? 'warning' : 'success'"
                  class="chip"
                  :title="`${v.locations} location(s)`"
                  >{{ v.version }}</el-tag
                >
                <span v-if="row.versions.length > 4" class="muted">+{{ row.versions.length - 4 }}</span>
                <span v-if="!row.versions.length" class="muted">—</span>
              </template>
            </el-table-column>
            <el-table-column label="Where" width="150">
              <template #default="{ row }">
                {{ whereLabel(row) }}
                <el-tag v-if="row.unmanaged" size="small" type="info" class="chip">network only</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Evidence" min-width="170">
              <template #default="{ row }">
                <el-tooltip v-for="s in row.sources" :key="s" :content="SOURCE_LABELS[s as InventorySource]?.hint ?? s" placement="top">
                  <el-tag size="small" type="info" effect="plain" class="chip">{{ sourceLabel(s) }}</el-tag>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column label="Vulnerabilities" width="120">
              <template #default="{ row }">
                <el-tag v-if="row.vulnerabilities.total" size="small" :type="row.vulnerabilities.critical ? 'danger' : 'warning'">
                  {{ row.vulnerabilities.total }} open
                </el-tag>
                <span v-else class="muted">—</span>
              </template>
            </el-table-column>
            <el-table-column label="Last seen" width="110">
              <template #default="{ row }">{{ ageLabel(row.last_seen) }}</template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane :label="`Version drift (${drifting.length})`" name="drift">
          <p class="intro">Applications seen at more than one version (each location counted at the newest version it was seen with). Versions behind the newest are amber.</p>
          <el-table :data="drifting" size="small" class="clickable" empty-text="Every application runs one version" @row-click="open">
            <el-table-column label="Application" prop="name" min-width="180" />
            <el-table-column label="Versions, oldest first" min-width="320">
              <template #default="{ row }">
                <el-tag
                  v-for="v in row.versions"
                  :key="v.version"
                  size="small"
                  :type="isBehind(v.version, row.latest_version) ? 'warning' : 'success'"
                  class="chip"
                  >{{ v.version }} × {{ v.locations }}</el-tag
                >
              </template>
            </el-table-column>
            <el-table-column label="Locations behind" width="150">
              <template #default="{ row }">{{ locationsBehind(row) }}</template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane :label="`Vulnerabilities (${vulns.length})`" name="vulnerabilities">
          <p class="intro">
            Open findings linked to an application. <strong>Exact</strong>: an endpoint-agent finding for one of its packages.
            <strong>Best effort</strong>: a finding on an asset where the application was seen whose title names the product.
          </p>
          <el-table v-loading="vulnsLoading" :data="vulns" size="small" empty-text="No open vulnerabilities linked to an application">
            <el-table-column label="Application" prop="app_name" min-width="150" />
            <el-table-column label="Version" prop="version" width="150" />
            <el-table-column label="Finding" min-width="230">
              <template #default="{ row }">
                <router-link v-if="canSeeVulnMgmt" :to="vulnerabilityLink(row.cve_id)">{{ row.cve_id }}</router-link>
                <span v-else>{{ row.cve_id }}</span>
                <div class="muted">{{ row.title }}</div>
              </template>
            </el-table-column>
            <el-table-column label="Severity" width="100">
              <template #default="{ row }"><SeverityBadge :severity="row.severity || 'medium'" /></template>
            </el-table-column>
            <el-table-column label="Asset" prop="asset" width="160" />
            <el-table-column label="Match" width="110">
              <template #default="{ row }">
                <el-tag size="small" :type="row.match === 'package' ? 'success' : 'info'">{{ row.match === 'package' ? 'Exact' : 'Best effort' }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane :label="`Unmanaged (${unmanaged.length})`" name="unmanaged">
          <p class="intro">
            Seen on the network, not inventoried: applications that only show up in clients' DNS queries or user agents, with no
            host, container, scan or endpoint evidence of yours. A SaaS your users rely on, a remote-access tool, a browser.
          </p>
          <el-table :data="unmanaged" size="small" class="clickable" empty-text="Nothing seen only on the network" @row-click="open">
            <el-table-column label="Application" prop="name" min-width="180" />
            <el-table-column label="Category" width="150">
              <template #default="{ row }">{{ categoryLabel(row.category) }}</template>
            </el-table-column>
            <el-table-column label="Clients" prop="clients" width="100" />
            <el-table-column label="Evidence" min-width="160">
              <template #default="{ row }">
                <el-tag v-for="s in row.sources" :key="s" size="small" type="info" effect="plain" class="chip">{{ sourceLabel(s) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Last seen" width="110">
              <template #default="{ row }">{{ ageLabel(row.last_seen) }}</template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane :label="`Not identified (${unmatched.length})`" name="unmatched">
          <p class="intro">
            The most frequent program names, container images and user-agent products no signature matches. If one is an
            application, <strong>Suggest signature</strong> opens a pre-filled file in the
            <a :href="`https://github.com/${status?.catalog_repo ?? 'cladkins/siembox-catalog'}`" target="_blank" rel="noopener noreferrer">catalog</a>
            (fill in the TODOs; its CI checks it).
          </p>
          <el-table v-loading="unmatchedLoading" :data="unmatched" size="small" empty-text="Everything seen is identified">
            <el-table-column label="Kind" width="140">
              <template #default="{ row }">{{ UNMATCHED_KIND[row.source] ?? row.source }}</template>
            </el-table-column>
            <el-table-column label="Value" min-width="200">
              <template #default="{ row }">
                <code>{{ row.value }}</code>
                <div v-if="row.sample && row.sample !== row.value" class="muted sample">{{ row.sample }}</div>
              </template>
            </el-table-column>
            <el-table-column label="Seen" width="110">
              <template #default="{ row }">{{ row.events.toLocaleString('en-US') }}</template>
            </el-table-column>
            <el-table-column label="Example location" prop="sample_location" width="160" />
            <el-table-column label="Last seen" width="110">
              <template #default="{ row }">{{ ageLabel(row.last_seen) }}</template>
            </el-table-column>
            <el-table-column width="150">
              <template #default="{ row }">
                <el-link :href="row.suggest_url" target="_blank" rel="noopener noreferrer" type="primary">Suggest signature</el-link>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <el-drawer v-model="detailOpen" :title="detail ? detail.name : 'Application'" size="60%" class="detail-drawer">
      <div v-loading="detailLoading">
        <template v-if="detail">
          <p class="muted">
            {{ detail.vendor }} · {{ categoryLabel(detail.category) }}
            <template v-if="detail.website"> · <a :href="detail.website" target="_blank" rel="noopener noreferrer">website</a></template>
          </p>
          <p v-if="detail.description">{{ detail.description }}</p>
          <el-descriptions :column="2" size="small" border class="block">
            <el-descriptions-item label="Where">{{ whereLabel(detail) }}</el-descriptions-item>
            <el-descriptions-item label="Evidence">{{ detail.sources.map(sourceLabel).join(', ') || '—' }}</el-descriptions-item>
            <el-descriptions-item label="First seen">{{ ageLabel(detail.first_seen) }}</el-descriptions-item>
            <el-descriptions-item label="Last seen">{{ ageLabel(detail.last_seen) }}</el-descriptions-item>
            <el-descriptions-item label="Versions" :span="2">
              <el-tag v-for="v in detail.versions" :key="v.version" size="small" class="chip" :type="isBehind(v.version, detail.latest_version) ? 'warning' : 'success'">
                {{ v.version }} × {{ v.locations }}
              </el-tag>
              <span v-if="!detail.versions.length" class="muted">no version seen</span>
            </el-descriptions-item>
          </el-descriptions>

          <h4>Locations ({{ detail.locations_total }})</h4>
          <el-table :data="detail.locations" size="small" class="block">
            <el-table-column label="Location" min-width="170">
              <template #default="{ row }">
                <router-link v-if="row.asset && canSeeAssets" :to="{ path: '/asset-inventory', query: { id: String(row.asset.id) } }">{{ row.label }}</router-link>
                <span v-else>{{ row.label }}</span>
                <div class="muted">{{ LOCATION_TYPE_LABELS[row.loc_type] ?? row.loc_type }}</div>
              </template>
            </el-table-column>
            <el-table-column label="Version" width="120">
              <template #default="{ row }">{{ row.current_version ?? '—' }}</template>
            </el-table-column>
            <el-table-column label="Evidence" min-width="260">
              <template #default="{ row }">
                <div v-for="(e, i) in row.evidence.slice(0, 3)" :key="i" class="evidence">
                  <el-tag size="small" type="info" effect="plain">{{ sourceLabel(e.source) }}</el-tag>
                  <span class="evidence-text">{{ evidenceText(e.evidence) }}</span>
                  <router-link v-if="logsLink(e.evidence, e.source, row.loc_key)" :to="logsLink(e.evidence, e.source, row.loc_key)!" class="logs-link">logs</router-link>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="Last seen" width="100">
              <template #default="{ row }">{{ ageLabel(row.last_seen) }}</template>
            </el-table-column>
          </el-table>

          <h4>Open vulnerabilities ({{ detail.vulnerability_list.length }})</h4>
          <el-table :data="detail.vulnerability_list" size="small" empty-text="None linked">
            <el-table-column label="Finding" min-width="200">
              <template #default="{ row }">
                <router-link v-if="canSeeVulnMgmt" :to="vulnerabilityLink(row.cve_id)">{{ row.cve_id }}</router-link>
                <span v-else>{{ row.cve_id }}</span>
                <div class="muted">{{ row.title }}</div>
              </template>
            </el-table-column>
            <el-table-column label="Severity" width="100">
              <template #default="{ row }"><SeverityBadge :severity="row.severity || 'medium'" /></template>
            </el-table-column>
            <el-table-column label="Asset" prop="asset" width="150" />
            <el-table-column label="Match" width="110">
              <template #default="{ row }">{{ row.match === 'package' ? `Exact${row.version ? ` (${row.version})` : ''}` : 'Best effort' }}</template>
            </el-table-column>
          </el-table>
        </template>
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { ElMessage } from 'element-plus';
import { Refresh, Search } from '@element-plus/icons-vue';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import SeverityBadge from '@/components/SeverityBadge.vue';
import {
  ageLabel,
  categoryLabel,
  driftOrder,
  isBehind,
  locationsBehind,
  logsLink,
  LOCATION_TYPE_LABELS,
  signatureSourceText,
  sourceLabel,
  SOURCE_LABELS,
  SOURCE_ORDER,
  vulnerabilityLink,
  whereLabel,
  type ApplicationRow,
  type InventorySource,
} from '@/utils/applications';

interface Status {
  enabled: boolean;
  retention_days: number;
  caught_up: boolean;
  covered_until: string | null;
  last_run_at: string | null;
  signatures: { source: string | null; count: number; error: string | null; refused: Array<{ appId: string; location: string; reason: string }> };
  catalog_repo: string;
}
interface Unmatched {
  source: string;
  value: string;
  events: number;
  locations: number;
  last_seen: string;
  sample_location: string | null;
  sample: string | null;
  suggest_url: string;
}
interface VulnRow {
  app_id: string;
  app_name: string;
  version: string;
  cve_id: string;
  title: string | null;
  severity: string | null;
  asset: string;
  match: string;
}
interface Detail extends ApplicationRow {
  description: string;
  website: string | null;
  locations_total: number;
  locations: Array<{
    loc_type: string;
    loc_key: string;
    label: string;
    asset: { id: number } | null;
    current_version: string | null;
    last_seen: string;
    evidence: Array<{ source: string; evidence: Record<string, unknown> | null }>;
  }>;
  vulnerability_list: Array<{ cve_id: string; title: string | null; severity: string | null; asset: string; match: string; version: string }>;
}

const UNMATCHED_KIND: Record<string, string> = { syslog_program: 'Log program', container: 'Container image', user_agent: 'User-agent product' };
const CATEGORIES = [
  'auth', 'automation', 'backup', 'browser', 'container-runtime', 'database', 'dev-tools', 'dns', 'file-sharing', 'game', 'home-automation',
  'http-client', 'mail', 'media-server', 'messaging', 'monitoring', 'network', 'operating-system', 'os-component', 'password-manager',
  'productivity', 'remote-access', 'reverse-proxy', 'saas', 'security', 'virtualization', 'vpn', 'web-server',
];

const authStore = useAuthStore();
const role = computed(() => authStore.user?.role ?? 'viewer');
const canRefresh = computed(() => ['admin', 'operator', 'analyst'].includes(role.value));
const canSeeVulnMgmt = computed(() => ['admin', 'operator'].includes(role.value));
const canSeeAssets = computed(() => ['admin', 'operator', 'analyst'].includes(role.value));

const tab = ref('inventory');
const filters = reactive({ search: '', category: '', source: '', host: '' });
const apps = ref<ApplicationRow[]>([]);
const status = ref<Status | null>(null);
const loading = ref(false);
const loadError = ref('');
const refreshing = ref(false);
const vulns = ref<VulnRow[]>([]);
const vulnsLoading = ref(false);
const unmatched = ref<Unmatched[]>([]);
const unmatchedLoading = ref(false);
const detailOpen = ref(false);
const detailLoading = ref(false);
const detail = ref<Detail | null>(null);

const categories = computed(() => {
  const seen = new Set(apps.value.map((a) => a.category));
  return CATEGORIES.filter((c) => seen.has(c) || c === filters.category);
});
const drifting = computed(() => driftOrder(apps.value));
const unmanaged = computed(() => apps.value.filter((a) => a.unmanaged));

function message(err: unknown, fallback: string): string {
  return (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? fallback;
}

function params(): Record<string, string> {
  const p: Record<string, string> = {};
  for (const [k, v] of Object.entries(filters)) if (v) p[k] = v;
  return p;
}

async function load() {
  loading.value = true;
  loadError.value = '';
  try {
    const { data } = await api.getApplications(params());
    apps.value = data.applications;
    status.value = data.status;
  } catch (err) {
    loadError.value = message(err, 'Could not load the application inventory.');
  } finally {
    loading.value = false;
  }
}

let timer: ReturnType<typeof setTimeout> | null = null;
function debouncedLoad() {
  if (timer) clearTimeout(timer);
  timer = setTimeout(load, 300);
}

async function loadVulns() {
  vulnsLoading.value = true;
  try {
    vulns.value = (await api.getApplicationVulnerabilities()).data.vulnerabilities;
  } catch (err) {
    ElMessage.error(message(err, 'Could not load the vulnerabilities.'));
  } finally {
    vulnsLoading.value = false;
  }
}

async function loadUnmatched() {
  unmatchedLoading.value = true;
  try {
    unmatched.value = (await api.getApplicationsUnmatched()).data.unmatched;
  } catch (err) {
    ElMessage.error(message(err, 'Could not load the unidentified list.'));
  } finally {
    unmatchedLoading.value = false;
  }
}

async function open(row: ApplicationRow) {
  detailOpen.value = true;
  detailLoading.value = true;
  detail.value = null;
  try {
    detail.value = (await api.getApplication(row.id)).data;
  } catch (err) {
    ElMessage.error(message(err, 'Could not load the application.'));
  } finally {
    detailLoading.value = false;
  }
}

async function refresh() {
  refreshing.value = true;
  try {
    const { data } = await api.refreshApplications();
    ElMessage.success(`Inventory refreshed: ${data.summary}`);
    await Promise.all([load(), loadVulns(), loadUnmatched()]);
  } catch (err) {
    ElMessage.warning(message(err, 'Could not refresh the inventory.'));
  } finally {
    refreshing.value = false;
  }
}

function evidenceText(e: Record<string, unknown> | null): string {
  if (!e) return '';
  if (typeof e.image === 'string') return e.image;
  if (typeof e.package === 'string') return `${e.package}${e.installed_version ? ` ${e.installed_version}` : ''}`;
  if (e.port !== undefined) return `${e.port}/${e.protocol ?? 'tcp'} ${e.service_name ?? ''}`.trim();
  if (typeof e.os_version === 'string') return e.os_version;
  if (typeof e.value === 'string') return e.value.length > 120 ? `${e.value.slice(0, 120)}…` : e.value;
  return '';
}

watch(tab, (t) => {
  if (t === 'vulnerabilities' && !vulns.value.length) void loadVulns();
  if (t === 'unmatched' && !unmatched.value.length) void loadUnmatched();
});

onMounted(async () => {
  await load();
  void loadVulns();
  void loadUnmatched();
});
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 12px;
}
.page-header h2 {
  margin: 0 0 4px;
}
.subtitle {
  margin: 0;
  max-width: 900px;
  color: var(--siembox-text-secondary, #909399);
  font-size: 14px;
}
.block {
  margin-bottom: 16px;
}
.status-line {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
  font-size: 13px;
  color: var(--siembox-text-secondary, #909399);
}
.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 8px;
}
.f-search {
  width: 240px;
}
.f-select {
  width: 180px;
}
.f-host {
  width: 200px;
}
.intro {
  margin: 0 0 12px;
  font-size: 13px;
  color: var(--siembox-text-secondary, #909399);
}
.app-name {
  font-weight: 500;
}
.muted {
  font-size: 12px;
  color: var(--siembox-text-secondary, #909399);
}
.sample {
  word-break: break-all;
}
.chip {
  margin: 0 4px 4px 0;
}
.clickable :deep(.el-table__row) {
  cursor: pointer;
}
.evidence {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 4px;
  font-size: 12px;
}
.evidence-text {
  word-break: break-all;
}
.logs-link {
  white-space: nowrap;
}
</style>
