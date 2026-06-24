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
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { ElMessage } from 'element-plus';
import { Search } from '@element-plus/icons-vue';
import { format } from 'date-fns';
import { api } from '@/services/api';
import ExplainWithAI from '@/components/ExplainWithAI.vue';

const route = useRoute();

const ipQuery = ref('');
const ipLoading = ref(false);
const detail = ref<any>(null);
const detailTab = ref('alerts');

const countries = ref<any[]>([]);
const countriesLoading = ref(false);
const selectedCountry = ref<any>(null);
const countryIps = ref<any[]>([]);
const countryIpsLoading = ref(false);

function severityType(sev: string) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', info: 'info' }[sev] || 'info';
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

function lookup() {
  if (ipQuery.value.trim()) loadIp(ipQuery.value.trim());
}

onMounted(() => {
  loadCountries();
  // Deep link: /threat-intel?ip=... (used by clickthrough from other pages).
  const ip = route.query.ip;
  if (typeof ip === 'string' && ip.trim()) loadIp(ip.trim());
});
</script>

<style scoped>
.threat-intel { padding: 0; }
.page-header { margin-bottom: 16px; }
.page-header h2 { margin: 0 0 4px; }
.subtitle { margin: 0; color: var(--siembox-text-secondary, #909399); font-size: 14px; }
.lookup-card { margin-bottom: 16px; }
.detail-card { margin-top: 20px; }
.detail-desc { margin-bottom: 8px; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.muted { color: var(--siembox-text-secondary, #909399); padding: 12px 0; text-align: center; font-size: 14px; }
.hint-card { display: flex; align-items: center; justify-content: center; }
.event-detail { word-break: break-word; }
</style>
