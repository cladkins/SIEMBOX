<template>
  <div class="threat-intel">
    <div class="page-header">
      <h2>Threat Intel</h2>
      <p class="subtitle">
        Investigate an IP — its GeoIP country, the log events it produced, and the
        alerts it triggered. Drill in from the country breakdown or look one up directly.
      </p>
    </div>

    <el-card class="lookup-card">
      <el-form :inline="true" @submit.prevent="lookup">
        <el-form-item label="IP address">
          <el-input
            v-model="ipQuery"
            placeholder="e.g. 203.0.113.10"
            style="width: 320px"
            clearable
            @keyup.enter="lookup"
          />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="ipLoading" :disabled="!ipQuery.trim()" @click="lookup">
            <el-icon><Search /></el-icon> Look up
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="map-card">
      <template #header>
        <div class="card-header">
          <span>Alert Origins (last 30 days)</span>
          <el-text size="small" type="info">Click a country to list its IPs</el-text>
        </div>
      </template>
      <AlertsCountryMap :data="countries" @country-click="selectCountryByCode" />
    </el-card>

    <el-row :gutter="20">
      <el-col :xs="24" :md="10">
        <el-card>
          <template #header><span>Top Source Countries (30d)</span></template>
          <el-table
            :data="countries"
            v-loading="countriesLoading"
            stripe
            highlight-current-row
            @row-click="selectCountry"
            max-height="320"
          >
            <el-table-column label="Country" min-width="160">
              <template #default="{ row }">
                {{ row.country_name || row.country_code }}
                <el-tag v-if="row.foreign_count > 0" type="danger" size="small">foreign</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="Alerts" width="90" align="right" />
          </el-table>
          <div v-if="!countriesLoading && countries.length === 0" class="muted">
            No geo-located alerts yet.
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :md="14">
        <el-card v-if="selectedCountry">
          <template #header>
            <span>IPs in {{ selectedCountry.country_name || selectedCountry.country_code }}</span>
          </template>
          <el-table
            :data="countryIps"
            v-loading="countryIpsLoading"
            stripe
            max-height="320"
          >
            <el-table-column label="IP" min-width="160">
              <template #default="{ row }">
                <el-link type="primary" @click="loadIp(row.ip)">{{ row.ip }}</el-link>
              </template>
            </el-table-column>
            <el-table-column prop="alert_count" label="Alerts" width="90" align="right" />
            <el-table-column label="Last seen" width="180">
              <template #default="{ row }">{{ formatDate(row.last_seen) }}</template>
            </el-table-column>
          </el-table>
          <div v-if="!countryIpsLoading && countryIps.length === 0" class="muted">
            No alert source IPs recorded for this country.
          </div>
        </el-card>
        <el-card v-else class="hint-card">
          <el-empty description="Select a country to see its IPs, or look up an IP above." />
        </el-card>
      </el-col>
    </el-row>

    <!-- IP detail -->
    <el-card v-if="detail" class="detail-card" v-loading="ipLoading">
      <template #header>
        <div class="card-header">
          <span>{{ detail.ip }}</span>
          <ExplainWithAI kind="ip" :data="detail" label="Explain this IP" />
        </div>
      </template>

      <el-descriptions :column="3" border class="detail-desc">
        <el-descriptions-item label="Country">
          <span v-if="detail.geo">
            {{ detail.geo.country_name }} ({{ detail.geo.country_code }})
            <el-tag v-if="detail.geo.foreign" type="danger" size="small">foreign</el-tag>
          </span>
          <el-text v-else type="info">Unknown / private</el-text>
        </el-descriptions-item>
        <el-descriptions-item label="Alerts">{{ detail.counts.alerts }}</el-descriptions-item>
        <el-descriptions-item label="Log events">{{ detail.counts.events }}</el-descriptions-item>
      </el-descriptions>

      <!-- External threat intelligence: blocklist hits + on-demand reputation -->
      <div class="ti-section">
        <div class="ti-head">Threat intelligence</div>
        <el-skeleton v-if="tiLoading" :rows="2" animated />
        <template v-else-if="ti">
          <div class="ti-feeds">
            <template v-if="ti.feeds && ti.feeds.length">
              <span class="ti-label">Listed on:</span>
              <el-tag v-for="f in ti.feeds" :key="f.slug" type="danger" size="small" class="ti-tag">
                {{ f.name }}
              </el-tag>
            </template>
            <el-text v-else type="success">Not on any enabled blocklist.</el-text>
          </div>
          <div v-if="ti.reputation && ti.reputation.length" class="ti-rep">
            <div v-for="r in ti.reputation" :key="r.provider" class="rep-row">
              <strong>{{ r.label }}:</strong>
              <template v-if="r.ok">
                <el-tag :type="repType(r.classification)" size="small">{{ r.classification || 'n/a' }}</el-tag>
                <span v-if="r.score != null" class="rep-score">score {{ r.score }}</span>
                <span class="rep-summary">{{ r.summary }}</span>
                <el-link v-if="r.link" :href="r.link" target="_blank" rel="noopener" type="primary">details</el-link>
              </template>
              <el-text v-else type="warning">{{ r.error }}</el-text>
            </div>
          </div>
        </template>
      </div>

      <el-tabs v-model="detailTab" class="detail-tabs">
        <el-tab-pane :label="`Alerts (${detail.alerts.length})`" name="alerts">
          <el-table :data="detail.alerts" stripe max-height="360">
            <el-table-column prop="severity" label="Severity" width="110">
              <template #default="{ row }">
                <el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="title" label="Title" min-width="240" show-overflow-tooltip />
            <el-table-column prop="rule_name" label="Rule" min-width="160" show-overflow-tooltip />
            <el-table-column prop="status" label="Status" width="120" />
            <el-table-column label="Time" width="180">
              <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
            </el-table-column>
          </el-table>
          <el-empty v-if="detail.alerts.length === 0" description="No alerts referencing this IP" />
        </el-tab-pane>

        <el-tab-pane :label="`Log events (${detail.events.length})`" name="events">
          <el-table :data="detail.events" stripe max-height="360">
            <el-table-column label="Time" width="180">
              <template #default="{ row }">{{ formatDate(row.timestamp) }}</template>
            </el-table-column>
            <el-table-column prop="app_name" label="Source" width="160" show-overflow-tooltip />
            <el-table-column prop="event_type" label="Event" width="160" show-overflow-tooltip />
            <el-table-column label="Detail" min-width="280">
              <template #default="{ row }">
                <el-text size="small" class="event-detail">{{ eventSummary(row) }}</el-text>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-if="detail.events.length === 0" description="No log events from this IP" />
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- Feed + reputation-provider configuration -->
    <el-card class="feeds-card">
      <template #header>
        <div class="card-header">
          <span>Threat Feeds &amp; Reputation Providers</span>
          <el-button v-if="canRefresh" size="small" :loading="refreshingAll" @click="refreshAllFeeds">
            <el-icon><Refresh /></el-icon> Refresh all feeds
          </el-button>
        </div>
      </template>

      <el-table :data="feeds" v-loading="feedsLoading" stripe>
        <el-table-column label="Feed" min-width="240">
          <template #default="{ row }">
            <div class="feed-name">{{ row.name }}</div>
            <el-text size="small" type="info">{{ row.description }}</el-text>
          </template>
        </el-table-column>
        <el-table-column label="Category" width="110">
          <template #default="{ row }"><el-tag size="small" type="info">{{ row.category }}</el-tag></template>
        </el-table-column>
        <el-table-column label="Indicators" width="110" align="right">
          <template #default="{ row }">{{ (row.indicator_count || 0).toLocaleString() }}</template>
        </el-table-column>
        <el-table-column label="Last refresh" width="190">
          <template #default="{ row }">
            <div>{{ row.last_fetched_at ? formatDate(row.last_fetched_at) : 'never' }}</div>
            <el-tag v-if="row.last_status" :type="row.last_status === 'ok' ? 'success' : 'danger'" size="small">
              {{ row.last_status }}
            </el-tag>
            <el-tooltip v-if="row.last_error" :content="row.last_error" placement="top">
              <el-icon class="feed-warn"><Warning /></el-icon>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="Enabled" width="90">
          <template #default="{ row }">
            <el-switch v-model="row.enabled" :disabled="!isAdmin" @change="toggleFeed(row)" />
          </template>
        </el-table-column>
        <el-table-column label="" width="90">
          <template #default="{ row }">
            <el-button
              v-if="canRefresh"
              link
              type="primary"
              size="small"
              :loading="refreshingFeed === row.id"
              @click="refreshFeed(row)"
            >
              Refresh
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="providers">
        <div class="providers-head">Reputation providers — bring your own key</div>
        <el-text size="small" type="info">
          On-demand IP reputation, queried only when you look up an IP. Keys are encrypted at rest
          and never shown again.{{ isAdmin ? '' : ' (admin only)' }}
        </el-text>
        <div v-for="p in providers" :key="p.name" class="provider-row">
          <div class="provider-name">
            {{ p.label }}
            <el-tag v-if="p.configured" type="success" size="small">key set</el-tag>
            <el-tag v-else type="info" size="small">no key</el-tag>
          </div>
          <el-input
            v-model="providerKeys[p.name]"
            :placeholder="p.configured ? 'Replace key…' : 'Paste API key…'"
            type="password"
            show-password
            clearable
            class="provider-key"
            :disabled="!isAdmin"
          />
          <el-switch
            v-model="providerEnabled[p.name]"
            :disabled="!isAdmin || (!p.configured && !providerKeys[p.name])"
            active-text="On"
            inactive-text="Off"
          />
          <el-button
            v-if="isAdmin"
            size="small"
            type="primary"
            :loading="savingProvider === p.name"
            @click="saveProvider(p)"
          >
            Save
          </el-button>
          <el-link :href="p.signupUrl" target="_blank" rel="noopener" type="primary">Get a key</el-link>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { ElMessage } from 'element-plus';
import { Search, Refresh, Warning } from '@element-plus/icons-vue';
import { format } from 'date-fns';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import ExplainWithAI from '@/components/ExplainWithAI.vue';
import AlertsCountryMap from '@/components/AlertsCountryMap.vue';

const route = useRoute();
const authStore = useAuthStore();
const isAdmin = computed(() => authStore.user?.role === 'admin');
const canRefresh = computed(() => ['admin', 'operator'].includes(authStore.user?.role || ''));

const ipQuery = ref('');
const ipLoading = ref(false);
const detail = ref<any>(null);
const detailTab = ref('alerts');

// External threat intel for the looked-up IP (blocklist hits + reputation).
const ti = ref<any>(null);
const tiLoading = ref(false);

// Feed + reputation-provider configuration.
const feeds = ref<any[]>([]);
const providers = ref<any[]>([]);
const feedsLoading = ref(false);
const refreshingAll = ref(false);
const refreshingFeed = ref<number | null>(null);
const savingProvider = ref<string | null>(null);
const providerKeys = reactive<Record<string, string>>({});
const providerEnabled = reactive<Record<string, boolean>>({});

const countries = ref<any[]>([]);
const countriesLoading = ref(false);
const selectedCountry = ref<any>(null);
const countryIps = ref<any[]>([]);
const countryIpsLoading = ref(false);

function severityType(sev: string) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', info: 'info' }[sev] || 'info';
}
function repType(classification?: string) {
  return { malicious: 'danger', suspicious: 'warning', benign: 'success', unknown: 'info' }[classification || 'unknown'] || 'info';
}
function formatDate(d: string) {
  return d ? format(new Date(d), 'MMM dd, yyyy HH:mm') : '-';
}
function eventSummary(row: any): string {
  const d = row.parsed_data || {};
  return d.message || d.event || d.event_action || JSON.stringify(d).slice(0, 160);
}

async function loadCountries() {
  countriesLoading.value = true;
  try {
    const { data } = await api.getAlertsByCountry({ days: 30, limit: 50 });
    countries.value = Array.isArray(data) ? data : [];
  } catch {
    countries.value = [];
  } finally {
    countriesLoading.value = false;
  }
}

function selectCountryByCode(code: string) {
  const existing = countries.value.find((c) => c.country_code === code);
  selectCountry(existing || { country_code: code, country_name: code });
}

async function selectCountry(row: any) {
  selectedCountry.value = row;
  countryIps.value = [];
  countryIpsLoading.value = true;
  try {
    const { data } = await api.getThreatIntelCountry(row.country_code, 30);
    countryIps.value = data?.ips || [];
  } catch {
    countryIps.value = [];
  } finally {
    countryIpsLoading.value = false;
  }
}

async function loadIp(ip: string) {
  const target = (ip || '').trim();
  if (!target) return;
  ipQuery.value = target;
  ipLoading.value = true;
  loadTi(target);
  try {
    const { data } = await api.getThreatIntelIp(target);
    detail.value = data;
    detailTab.value = data.alerts.length > 0 ? 'alerts' : 'events';
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || 'Failed to look up IP');
    detail.value = null;
  } finally {
    ipLoading.value = false;
  }
}

// Blocklist hits + reputation for the IP (separate, possibly-slow call so the
// core detail isn't blocked on external provider latency).
async function loadTi(ip: string) {
  ti.value = null;
  tiLoading.value = true;
  try {
    const { data } = await api.lookupThreatIp(ip);
    ti.value = data;
  } catch {
    ti.value = { feeds: [], reputation: [] };
  } finally {
    tiLoading.value = false;
  }
}

function lookup() {
  if (ipQuery.value.trim()) loadIp(ipQuery.value.trim());
}

async function loadFeeds() {
  feedsLoading.value = true;
  try {
    const { data } = await api.getThreatFeeds();
    feeds.value = Array.isArray(data?.feeds) ? data.feeds : [];
    providers.value = Array.isArray(data?.providers) ? data.providers : [];
    providers.value.forEach((p: any) => {
      if (!(p.name in providerEnabled)) providerEnabled[p.name] = !!p.enabled;
    });
  } catch {
    feeds.value = [];
    providers.value = [];
  } finally {
    feedsLoading.value = false;
  }
}

async function toggleFeed(row: any) {
  try {
    await api.updateThreatFeed(row.id, { enabled: row.enabled });
    ElMessage.success(`${row.name} ${row.enabled ? 'enabled' : 'disabled'}`);
  } catch (error: any) {
    row.enabled = !row.enabled; // revert on failure
    ElMessage.error(error?.response?.data?.error || 'Failed to update feed');
  }
}

async function refreshFeed(row: any) {
  refreshingFeed.value = row.id;
  try {
    const { data } = await api.refreshThreatFeed(row.id);
    if (data?.ok) ElMessage.success(`${row.name}: ${data.count.toLocaleString()} indicators`);
    else ElMessage.error(`${row.name}: ${data?.error || 'refresh failed'}`);
    await loadFeeds();
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || 'Failed to refresh feed');
  } finally {
    refreshingFeed.value = null;
  }
}

async function refreshAllFeeds() {
  refreshingAll.value = true;
  try {
    const { data } = await api.refreshAllThreatFeeds();
    ElMessage.success(`Refreshed ${data?.refreshed ?? 0} feed(s)`);
    await loadFeeds();
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || 'Failed to refresh feeds');
  } finally {
    refreshingAll.value = false;
  }
}

async function saveProvider(p: any) {
  savingProvider.value = p.name;
  try {
    const key = providerKeys[p.name];
    const payload: { apiKey?: string; enabled: boolean } = { enabled: !!providerEnabled[p.name] };
    if (key && key.trim()) payload.apiKey = key.trim();
    await api.saveThreatProvider(p.name, payload);
    providerKeys[p.name] = '';
    ElMessage.success(`${p.label} saved`);
    await loadFeeds();
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || 'Failed to save provider');
  } finally {
    savingProvider.value = null;
  }
}

onMounted(async () => {
  loadFeeds();
  await loadCountries();
  // Deep links: ?ip= (clickthrough from other pages) and ?country= (from the
  // dashboard map).
  const ip = route.query.ip;
  if (typeof ip === 'string' && ip.trim()) loadIp(ip.trim());
  const country = route.query.country;
  if (typeof country === 'string' && country.trim()) selectCountryByCode(country.trim().toUpperCase());
});
</script>

<style scoped>
.threat-intel { padding: 0; }
.page-header { margin-bottom: 16px; }
.page-header h2 { margin: 0 0 4px; }
.subtitle { margin: 0; color: var(--siembox-text-secondary, #909399); font-size: 14px; }
.lookup-card { margin-bottom: 16px; }
.map-card { margin-bottom: 20px; }
.detail-card { margin-top: 20px; }
.detail-desc { margin-bottom: 8px; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.muted { color: var(--siembox-text-secondary, #909399); padding: 12px 0; text-align: center; font-size: 14px; }
.hint-card { display: flex; align-items: center; justify-content: center; }
.event-detail { word-break: break-word; }

/* IP-detail threat-intel block */
.ti-section { margin: 4px 0 12px; padding: 12px; border: 1px solid var(--el-border-color-lighter); border-radius: 6px; }
.ti-head { font-weight: 600; margin-bottom: 8px; }
.ti-label { margin-right: 6px; color: var(--siembox-text-secondary, #909399); }
.ti-tag { margin: 0 4px 4px 0; }
.ti-rep { margin-top: 8px; display: flex; flex-direction: column; gap: 4px; }
.rep-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.rep-score { color: var(--siembox-text-secondary, #909399); }
.rep-summary { color: var(--siembox-text-secondary, #909399); }

/* Feed + provider config */
.feeds-card { margin-top: 20px; }
.feed-name { font-weight: 500; }
.feed-warn { color: var(--el-color-danger); margin-left: 4px; vertical-align: middle; }
.providers { margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--el-border-color-lighter); }
.providers-head { font-weight: 600; margin-bottom: 4px; }
.provider-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-top: 12px; }
.provider-name { min-width: 140px; display: flex; align-items: center; gap: 6px; }
.provider-key { width: 240px; }
</style>
