<template>
  <div class="threat-hunting">
    <div class="page-header">
      <h2>Threat Hunting</h2>
      <p class="subtitle">
        Give SIEMBox a threat report (a URL, pasted text or a STIX bundle) or a feed to watch. It extracts the
        indicators and hunt hypotheses, searches your logs for them, and publishes each hunt as STIX 2.1 over TAXII.
      </p>
    </div>

    <el-alert v-if="summary" :type="summary.failed ? 'warning' : 'info'" :closable="false" show-icon class="summary-alert">
      <template #title>
        {{ summary.hunts }} hunt(s) · {{ summary.hunts_with_matches }} with matches · {{ summary.indicators }} active
        indicator(s) · {{ summary.sources_enabled }} monitored source(s)
        <template v-if="summary.in_progress"> · {{ summary.in_progress }} in progress</template>
        <template v-if="summary.failed"> · {{ summary.failed }} failed</template>
      </template>
    </el-alert>

    <el-tabs v-model="tab">
      <!-- Hunts -->
      <el-tab-pane label="Hunts" name="hunts">
        <div class="toolbar">
          <el-button v-if="canAnalyst" type="primary" @click="openNewHunt">
            <el-icon><Plus /></el-icon> New hunt
          </el-button>
          <el-input v-model="filters.search" placeholder="Search title or URL" clearable style="width: 240px" @change="loadHunts" />
          <el-select v-model="filters.status" placeholder="Any status" clearable style="width: 150px" @change="loadHunts">
            <el-option v-for="s in STATUSES" :key="s" :label="s" :value="s" />
          </el-select>
          <el-button @click="refreshAll"><el-icon><Refresh /></el-icon></el-button>
        </div>

        <el-table :data="hunts" v-loading="huntsLoading" stripe @row-click="(row: any) => openHunt(row.id)" class="clickable">
          <el-table-column label="Hunt" min-width="260">
            <template #default="{ row }">
              <div class="hunt-title">{{ row.title }}</div>
              <el-text size="small" type="info">
                {{ originLabel(row) }}<template v-if="row.source_name"> · {{ row.source_name }}</template>
              </el-text>
            </template>
          </el-table-column>
          <el-table-column label="Status" width="120">
            <template #default="{ row }"><el-tag :type="statusType(row.status)" size="small">{{ row.status }}</el-tag></template>
          </el-table-column>
          <el-table-column prop="indicator_count" label="IOCs" width="70" align="right" />
          <el-table-column prop="hypothesis_count" label="Hypotheses" width="115" align="right" />
          <el-table-column label="Matches" width="95" align="right">
            <template #default="{ row }">
              <el-tag v-if="row.logs_matched > 0" type="danger" size="small">{{ row.logs_matched }}</el-tag>
              <span v-else-if="row.last_run_at" class="muted">0</span>
              <span v-else class="muted">-</span>
            </template>
          </el-table-column>
          <el-table-column label="Last run" width="160">
            <template #default="{ row }">{{ fmt(row.last_run_at) }}</template>
          </el-table-column>
          <el-table-column label="Created" width="160">
            <template #default="{ row }">{{ fmt(row.created_at) }}</template>
          </el-table-column>
        </el-table>
        <el-empty v-if="!huntsLoading && hunts.length === 0" description="No hunts yet. Start one from a report URL, or add a source to watch." />
        <el-pagination
          v-if="total > pageSize"
          layout="prev, pager, next, total"
          :total="total"
          :page-size="pageSize"
          v-model:current-page="page"
          @current-change="loadHunts"
          class="pager"
        />
      </el-tab-pane>

      <!-- Sources -->
      <el-tab-pane label="Monitored sources" name="sources">
        <p class="muted">
          SIEMBox checks each source on its interval. A feed (RSS or Atom) creates a hunt for every new article; the
          first check takes the newest 3. A page creates a new hunt when its indicators change.
        </p>
        <div class="toolbar">
          <el-button v-if="canAnalyst" type="primary" @click="openSource()"><el-icon><Plus /></el-icon> Add source</el-button>
        </div>
        <el-table :data="sources" v-loading="sourcesLoading" stripe>
          <el-table-column label="Source" min-width="260">
            <template #default="{ row }">
              <div>{{ row.name }}</div>
              <el-text size="small" type="info" truncated>{{ row.url }}</el-text>
            </template>
          </el-table-column>
          <el-table-column prop="kind" label="Kind" width="80" />
          <el-table-column label="Enabled" width="90">
            <template #default="{ row }">
              <el-switch :model-value="row.enabled" :disabled="!canAnalyst" @change="(v: any) => toggleSource(row, v)" />
            </template>
          </el-table-column>
          <el-table-column label="Every" width="90">
            <template #default="{ row }">{{ intervalLabel(row.check_interval_minutes) }}</template>
          </el-table-column>
          <el-table-column label="Last check" min-width="200">
            <template #default="{ row }">
              <span>{{ fmt(row.last_checked_at) }}</span>
              <el-tag v-if="row.last_status === 'error'" type="danger" size="small" class="ml">error</el-tag>
              <div v-if="row.last_error" class="error-text">{{ row.last_error }}</div>
            </template>
          </el-table-column>
          <el-table-column label="Hunts" width="80" align="right">
            <template #default="{ row }">
              <el-link type="primary" @click="showSourceHunts(row)">{{ row.hunts_created }}</el-link>
            </template>
          </el-table-column>
          <el-table-column v-if="canAnalyst" label="" width="210" align="right">
            <template #default="{ row }">
              <el-button size="small" :loading="checking === row.id" @click="checkSource(row)">Check now</el-button>
              <el-button size="small" @click="openSource(row)">Edit</el-button>
              <el-button size="small" type="danger" plain @click="deleteSource(row)">Delete</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- TAXII -->
      <el-tab-pane label="STIX / TAXII" name="taxii">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="TAXII 2.1 discovery">
            <code>{{ taxiiDiscovery }}</code>
          </el-descriptions-item>
          <el-descriptions-item label="API root"><code>{{ taxiiDiscovery }}hunts/</code></el-descriptions-item>
          <el-descriptions-item label="Collection">
            <code>{{ collectionId || 'see the API root' }}</code> (SIEMBox Threat Hunts, read-only)
          </el-descriptions-item>
          <el-descriptions-item label="Sign-in">
            HTTP Basic with a TAXII token as the password (any user name), or <code>Authorization: Bearer &lt;token&gt;</code>.
          </el-descriptions-item>
        </el-descriptions>
        <p class="muted">
          Each hunt is a STIX report with its indicators, vulnerabilities (CVEs), ATT&amp;CK attack-patterns, hypotheses
          (notes) and sightings of what the last run found. Download one hunt's bundle from its detail view.
        </p>

        <template v-if="isAdmin">
          <h3>TAXII client tokens</h3>
          <div class="toolbar">
            <el-input v-model="newTokenName" placeholder="Client name, e.g. OpenCTI" style="width: 260px" />
            <el-button type="primary" :disabled="!newTokenName.trim()" @click="createToken">Create token</el-button>
          </div>
          <el-alert v-if="createdToken" type="success" :closable="true" show-icon @close="createdToken = ''" class="token-alert">
            <template #title>Copy this token now. SIEMBox shows it only once.</template>
            <code class="token">{{ createdToken }}</code>
          </el-alert>
          <el-table :data="tokens" stripe>
            <el-table-column prop="name" label="Name" min-width="160" />
            <el-table-column label="Token" width="190"><template #default="{ row }"><code>{{ row.token_prefix }}…</code></template></el-table-column>
            <el-table-column label="Created" width="160"><template #default="{ row }">{{ fmt(row.created_at) }}</template></el-table-column>
            <el-table-column label="Last used" width="160"><template #default="{ row }">{{ fmt(row.last_used_at) }}</template></el-table-column>
            <el-table-column label="" width="120" align="right">
              <template #default="{ row }">
                <el-tag v-if="row.revoked_at" type="info" size="small">revoked</el-tag>
                <el-button v-else size="small" type="danger" plain @click="revokeToken(row)">Revoke</el-button>
              </template>
            </el-table-column>
          </el-table>
        </template>
        <el-text v-else type="info">An admin creates TAXII client tokens here.</el-text>
      </el-tab-pane>
    </el-tabs>

    <!-- New hunt -->
    <el-dialog v-model="newHunt.visible" title="New threat hunt" width="640px">
      <el-form label-position="top">
        <el-form-item>
          <el-radio-group v-model="newHunt.mode">
            <el-radio-button value="url">Report URL</el-radio-button>
            <el-radio-button value="text">Paste text</el-radio-button>
            <el-radio-button value="stix">STIX bundle</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="newHunt.mode === 'url'" label="URL of the report, advisory or blog post (https)">
          <el-input v-model="newHunt.url" placeholder="https://..." />
        </el-form-item>
        <el-form-item v-else-if="newHunt.mode === 'text'" label="Report text">
          <el-input v-model="newHunt.text" type="textarea" :rows="10" placeholder="Paste the report, an IOC list, an email..." />
        </el-form-item>
        <el-form-item v-else label="STIX 2.x bundle (.json)">
          <input type="file" accept=".json,application/json,application/stix+json" @change="readStixFile" />
          <el-text v-if="newHunt.stixName" size="small" type="info">{{ newHunt.stixName }}</el-text>
        </el-form-item>
        <el-form-item v-if="newHunt.mode !== 'stix'" label="Title (optional)">
          <el-input v-model="newHunt.title" placeholder="Named from the report when left blank" />
        </el-form-item>
        <el-row :gutter="16">
          <el-col :span="8">
            <el-form-item label="Search the last (days)">
              <el-input-number v-model="newHunt.lookback_days" :min="1" :max="90" />
            </el-form-item>
          </el-col>
          <el-col :span="8">
            <el-form-item label="Raise an alert on a match">
              <el-switch v-model="newHunt.alert_on_match" />
            </el-form-item>
          </el-col>
          <el-col v-if="newHunt.mode !== 'stix'" :span="8">
            <el-form-item label="Hypotheses with AI">
              <el-switch v-model="newHunt.use_ai" />
            </el-form-item>
          </el-col>
        </el-row>
        <el-text size="small" type="info">
          The AI step uses the AI Builder model (Settings → AI). Without one, SIEMBox still extracts the indicators.
        </el-text>
      </el-form>
      <template #footer>
        <el-button @click="newHunt.visible = false">Cancel</el-button>
        <el-button type="primary" :loading="newHunt.saving" :disabled="!newHuntReady" @click="submitHunt">Start hunt</el-button>
      </template>
    </el-dialog>

    <!-- Source editor -->
    <el-dialog v-model="sourceForm.visible" :title="sourceForm.id ? 'Edit source' : 'Add source'" width="560px">
      <el-form label-position="top">
        <el-form-item label="URL (https): an RSS/Atom feed or a page">
          <el-input v-model="sourceForm.url" placeholder="https://vendor.example/blog/feed/" />
        </el-form-item>
        <el-form-item label="Name">
          <el-input v-model="sourceForm.name" placeholder="Named after the host when left blank" />
        </el-form-item>
        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item label="Kind">
              <el-select v-model="sourceForm.kind">
                <el-option label="Detect" value="auto" />
                <el-option label="Feed (RSS/Atom)" value="feed" />
                <el-option label="Page" value="page" />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="Check every (minutes)">
              <el-input-number v-model="sourceForm.check_interval_minutes" :min="30" :max="10080" :step="30" />
            </el-form-item>
          </el-col>
          <el-col :span="8">
            <el-form-item label="Search the last (days)">
              <el-input-number v-model="sourceForm.lookback_days" :min="1" :max="90" />
            </el-form-item>
          </el-col>
          <el-col :span="8">
            <el-form-item label="Alert on a match"><el-switch v-model="sourceForm.alert_on_match" /></el-form-item>
          </el-col>
          <el-col :span="8">
            <el-form-item label="Hypotheses with AI"><el-switch v-model="sourceForm.use_ai" /></el-form-item>
          </el-col>
        </el-row>
      </el-form>
      <template #footer>
        <el-button @click="sourceForm.visible = false">Cancel</el-button>
        <el-button type="primary" :loading="sourceForm.saving" :disabled="!sourceForm.url.trim()" @click="saveSource">Save</el-button>
      </template>
    </el-dialog>

    <!-- Hunt detail -->
    <el-drawer v-model="drawer" :size="drawerSize" :title="detail?.title || 'Hunt'" destroy-on-close>
      <div v-if="detail" v-loading="detailLoading">
        <div class="detail-head">
          <el-tag :type="statusType(detail.status)">{{ detail.status }}</el-tag>
          <el-tag v-if="detail.extraction_method" type="info" size="small">{{ detail.extraction_method }}</el-tag>
          <span class="muted">Last {{ detail.lookback_days }} days · {{ originLabel(detail) }}</span>
        </div>
        <div class="actions">
          <template v-if="canAnalyst">
            <el-button type="primary" size="small" :disabled="busy" @click="runHunt">Run hunt</el-button>
            <el-button size="small" :disabled="busy || detail.origin === 'stix'" @click="reextract">Re-read report</el-button>
          </template>
          <el-button size="small" @click="downloadStix">Download STIX</el-button>
          <el-button v-if="detail.last_alert_id" size="small" @click="openAlert(detail.last_alert_id)">
            Open alert
          </el-button>
          <el-button v-if="canAnalyst" size="small" type="danger" plain :disabled="busy" @click="deleteHunt">Delete</el-button>
        </div>
        <el-alert v-if="detail.error" type="error" :title="detail.error" :closable="false" show-icon class="mb" />
        <el-alert v-if="detail.extraction_note" type="info" :title="detail.extraction_note" :closable="false" class="mb" />
        <el-alert
          v-if="detail.results_truncated"
          type="warning"
          title="Over 20,000 log lines matched; the counts cover the newest of them. Switch off noisy terms or shorten the window."
          :closable="false"
          class="mb"
        />
        <p v-if="detail.summary">{{ detail.summary }}</p>
        <p v-if="detail.source_url" class="muted">
          Source: <a :href="detail.source_url" target="_blank" rel="noopener noreferrer nofollow">{{ detail.source_url }}</a>
        </p>
        <el-row v-if="canAnalyst" :gutter="12" class="mb">
          <el-col :span="10">
            <el-input-number v-model="edit.lookback_days" :min="1" :max="90" size="small" /> days
          </el-col>
          <el-col :span="10">
            <el-switch v-model="edit.alert_on_match" active-text="Alert on a match" size="small" />
          </el-col>
          <el-col :span="4"><el-button size="small" @click="saveHuntSettings">Save</el-button></el-col>
        </el-row>

        <el-tabs v-model="detailTab">
          <el-tab-pane :label="`Hypotheses (${detail.hypotheses.length})`" name="hypotheses">
            <el-empty v-if="!detail.hypotheses.length" :image-size="60" description="No hypotheses. Add one with search terms to look for behaviour, not only indicators." />
            <el-card v-for="h in detail.hypotheses" :key="h.id" shadow="never" class="hyp" :class="{ disabled: !h.enabled }">
              <div class="hyp-head">
                <strong>{{ h.title }}</strong>
                <el-tag v-if="h.match_count" type="danger" size="small">{{ h.match_count }} line(s)</el-tag>
              </div>
              <p v-if="h.description" class="muted">{{ h.description }}</p>
              <div class="tags">
                <el-tag v-for="t in h.attack_techniques" :key="t" size="small" type="warning">{{ t }}</el-tag>
                <el-tag v-for="t in h.search_terms" :key="t" size="small" effect="plain">{{ t }}</el-tag>
                <el-text v-if="!h.search_terms.length" size="small" type="info">No search terms: add some to test this hypothesis.</el-text>
              </div>
              <div v-if="canAnalyst" class="hyp-actions">
                <el-switch :model-value="h.enabled" size="small" active-text="On" @change="(v: any) => setHypothesis(h, { enabled: v })" />
                <el-button size="small" link @click="openHypothesis(h)">Edit</el-button>
                <el-button size="small" link type="danger" @click="removeHypothesis(h)">Delete</el-button>
              </div>
            </el-card>
            <el-button v-if="canAnalyst" size="small" @click="openHypothesis()"><el-icon><Plus /></el-icon> Add hypothesis</el-button>
          </el-tab-pane>

          <el-tab-pane :label="`Indicators (${detail.indicators.length})`" name="indicators">
            <div v-if="canAnalyst" class="toolbar">
              <el-select v-model="newIoc.type" style="width: 110px" size="small">
                <el-option v-for="t in IOC_TYPES" :key="t" :label="t" :value="t" />
              </el-select>
              <el-input v-model="newIoc.value" size="small" placeholder="Add an indicator" style="width: 260px" @keyup.enter="addIoc" />
              <el-button size="small" :disabled="!newIoc.value.trim()" @click="addIoc">Add</el-button>
            </div>
            <el-table :data="detail.indicators" size="small" stripe max-height="480">
              <el-table-column prop="ioc_type" label="Type" width="80" />
              <el-table-column label="Value" min-width="220">
                <template #default="{ row }">
                  <code class="ioc" :class="{ off: !row.enabled }">{{ row.value }}</code>
                  <div v-if="row.context" class="ctx">{{ row.context }}</div>
                </template>
              </el-table-column>
              <el-table-column prop="found_by" label="By" width="60" />
              <el-table-column label="Lines" width="70" align="right">
                <template #default="{ row }">
                  <el-tag v-if="row.match_count" type="danger" size="small">{{ row.match_count }}</el-tag>
                  <span v-else class="muted">0</span>
                </template>
              </el-table-column>
              <el-table-column label="Last seen" width="150"><template #default="{ row }">{{ fmt(row.last_seen) }}</template></el-table-column>
              <el-table-column label="Hunt" width="70">
                <template #default="{ row }">
                  <el-switch :model-value="row.enabled" size="small" :disabled="!canAnalyst" @change="(v: any) => toggleIoc(row, v)" />
                </template>
              </el-table-column>
            </el-table>
          </el-tab-pane>

          <el-tab-pane :label="`Matches (${detail.logs_matched})`" name="matches">
            <el-empty v-if="!detail.matches.length" :image-size="60" :description="detail.last_run_at ? 'Nothing found in the window.' : 'Not run yet.'" />
            <el-table v-else :data="detail.matches" size="small" stripe max-height="520">
              <el-table-column label="Time" width="150"><template #default="{ row }">{{ fmt(row.log_timestamp) }}</template></el-table-column>
              <el-table-column label="Matched" width="180">
                <template #default="{ row }">
                  <code>{{ row.indicator_value || row.term }}</code>
                  <div v-if="row.hypothesis_title" class="ctx">{{ row.hypothesis_title }}</div>
                </template>
              </el-table-column>
              <el-table-column label="Host" width="130">
                <template #default="{ row }">{{ row.hostname || row.source_ip }}<div class="ctx">{{ row.app_name }}</div></template>
              </el-table-column>
              <el-table-column label="Log line" min-width="300">
                <template #default="{ row }"><span class="logline">{{ row.message }}</span></template>
              </el-table-column>
            </el-table>
            <el-text v-if="detail.matches.length" size="small" type="info">Up to 25 sample lines per indicator or search term are kept.</el-text>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-drawer>

    <AlertDetailDialog v-if="alertDetail" v-model="alertVisible" :alert="alertDetail" />

    <!-- Hypothesis editor -->
    <el-dialog v-model="hypForm.visible" :title="hypForm.id ? 'Edit hypothesis' : 'Add hypothesis'" width="560px" append-to-body>
      <el-form label-position="top">
        <el-form-item label="Hypothesis">
          <el-input v-model="hypForm.title" placeholder="e.g. The attacker ran rundll32 from a temp folder" />
        </el-form-item>
        <el-form-item label="Why, and what a match looks like">
          <el-input v-model="hypForm.description" type="textarea" :rows="3" />
        </el-form-item>
        <el-form-item label="Log search terms (one per line, matched anywhere in a log line, case-insensitive)">
          <el-input v-model="hypForm.terms" type="textarea" :rows="5" placeholder="rundll32.exe&#10;\AppData\Local\Temp\" />
        </el-form-item>
        <el-form-item label="ATT&CK techniques (comma separated)">
          <el-input v-model="hypForm.techniques" placeholder="T1218.011, T1059.001" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="hypForm.visible = false">Cancel</el-button>
        <el-button type="primary" :disabled="!hypForm.title.trim()" @click="saveHypothesis">Save</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onBeforeUnmount, watch } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Plus, Refresh } from '@element-plus/icons-vue';
import { format } from 'date-fns';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import AlertDetailDialog from '@/components/AlertDetailDialog.vue';

const authStore = useAuthStore();
const isAdmin = computed(() => authStore.user?.role === 'admin');
const canAnalyst = computed(() => ['admin', 'operator', 'analyst'].includes(authStore.user?.role || ''));

const STATUSES = ['pending', 'extracting', 'ready', 'running', 'completed', 'failed'];
const BUSY = ['pending', 'extracting', 'running'];
const IOC_TYPES = ['ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'cve'];

const tab = ref('hunts');
const summary = ref<any>(null);
const hunts = ref<any[]>([]);
const huntsLoading = ref(false);
const total = ref(0);
const page = ref(1);
const pageSize = 25;
const filters = reactive<{ search: string; status: string; source_id?: number }>({ search: '', status: '' });

const sources = ref<any[]>([]);
const sourcesLoading = ref(false);
const checking = ref<number | null>(null);

const tokens = ref<any[]>([]);
const collectionId = ref('');
const newTokenName = ref('');
const createdToken = ref('');
const taxiiDiscovery = `${window.location.origin}/api/taxii2/`;

const drawer = ref(false);
const detail = ref<any>(null);
const detailLoading = ref(false);
const detailTab = ref('hypotheses');
const edit = reactive({ lookback_days: 14, alert_on_match: false });
const newIoc = reactive({ type: 'ipv4', value: '' });
let pollTimer: ReturnType<typeof setTimeout> | null = null;

const isMobile = ref(window.innerWidth < 768);
const drawerSize = computed(() => (isMobile.value ? '100%' : '70%'));
const busy = computed(() => !!detail.value && BUSY.includes(detail.value.status));

function fmt(t: string | null | undefined): string {
  if (!t) return '-';
  try {
    return format(new Date(t), 'yyyy-MM-dd HH:mm');
  } catch {
    return String(t);
  }
}

function statusType(s: string): 'success' | 'warning' | 'danger' | 'info' | 'primary' {
  if (s === 'completed') return 'success';
  if (s === 'failed') return 'danger';
  if (BUSY.includes(s)) return 'warning';
  return 'info';
}

function originLabel(h: any): string {
  return ({ url: 'From a URL', text: 'From pasted text', stix: 'Imported STIX', source: 'From a monitored source' } as Record<string, string>)[h.origin] || h.origin;
}

function intervalLabel(min: number): string {
  if (min % 1440 === 0) return `${min / 1440} d`;
  if (min % 60 === 0) return `${min / 60} h`;
  return `${min} min`;
}

async function loadSummary() {
  try {
    summary.value = (await api.getHuntSummary()).data;
  } catch {
    /* toast shown by the API client */
  }
}

async function loadHunts() {
  huntsLoading.value = true;
  try {
    const { data } = await api.getHunts({
      limit: pageSize,
      offset: (page.value - 1) * pageSize,
      status: filters.status || undefined,
      search: filters.search || undefined,
      source_id: filters.source_id,
    });
    hunts.value = data.hunts;
    total.value = data.total;
  } finally {
    huntsLoading.value = false;
  }
}

async function loadSources() {
  sourcesLoading.value = true;
  try {
    sources.value = (await api.getHuntSources()).data.sources;
  } finally {
    sourcesLoading.value = false;
  }
}

async function loadTokens() {
  if (!isAdmin.value) return;
  const { data } = await api.getTaxiiTokens();
  tokens.value = data.tokens;
  collectionId.value = data.collection_id;
}

function refreshAll() {
  void loadSummary();
  void loadHunts();
}

// ---- New hunt

const newHunt = reactive({
  visible: false,
  mode: 'url' as 'url' | 'text' | 'stix',
  url: '',
  text: '',
  title: '',
  stix: null as unknown,
  stixName: '',
  lookback_days: 14,
  alert_on_match: true,
  use_ai: true,
  saving: false,
});

const newHuntReady = computed(() => {
  if (newHunt.mode === 'url') return newHunt.url.trim().startsWith('https://');
  if (newHunt.mode === 'text') return newHunt.text.trim().length >= 20;
  return !!newHunt.stix;
});

function openNewHunt() {
  Object.assign(newHunt, { visible: true, url: '', text: '', title: '', stix: null, stixName: '', saving: false });
}

function readStixFile(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      newHunt.stix = JSON.parse(String(reader.result));
      newHunt.stixName = file.name;
    } catch {
      newHunt.stix = null;
      ElMessage.error('That file is not JSON.');
    }
  };
  reader.readAsText(file);
}

async function submitHunt() {
  newHunt.saving = true;
  try {
    const opts = { lookback_days: newHunt.lookback_days, alert_on_match: newHunt.alert_on_match };
    let id: number;
    if (newHunt.mode === 'stix') {
      id = (await api.importStixHunt(newHunt.stix, opts)).data.id;
    } else {
      id = (
        await api.createHunt({
          ...(newHunt.mode === 'url' ? { url: newHunt.url.trim() } : { text: newHunt.text }),
          title: newHunt.title.trim() || undefined,
          use_ai: newHunt.use_ai,
          ...opts,
        })
      ).data.id;
    }
    newHunt.visible = false;
    ElMessage.success('Hunt started.');
    refreshAll();
    void openHunt(id);
  } finally {
    newHunt.saving = false;
  }
}

// ---- Hunt detail

function schedulePoll() {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
  if (drawer.value && detail.value && BUSY.includes(detail.value.status)) {
    pollTimer = setTimeout(() => void loadDetail(detail.value.id, true), 3000);
  }
}

async function loadDetail(id: number, quiet = false) {
  if (!quiet) detailLoading.value = true;
  try {
    const wasBusy = detail.value && BUSY.includes(detail.value.status);
    detail.value = (await api.getHunt(id)).data;
    edit.lookback_days = detail.value.lookback_days;
    edit.alert_on_match = detail.value.alert_on_match;
    if (wasBusy && !BUSY.includes(detail.value.status)) {
      refreshAll();
      if (detail.value.logs_matched > 0) detailTab.value = 'matches';
    }
  } finally {
    detailLoading.value = false;
    schedulePoll();
  }
}

async function openHunt(id: number) {
  drawer.value = true;
  detailTab.value = 'hypotheses';
  detail.value = null;
  await loadDetail(id);
}

watch(drawer, (open) => {
  if (!open && pollTimer) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
});

const alertDetail = ref<any>(null);
const alertVisible = ref(false);

async function openAlert(id: number) {
  try {
    alertDetail.value = (await api.getAlert(id, true)).data;
    alertVisible.value = true;
  } catch {
    ElMessage.warning('That alert no longer exists.');
  }
}

async function runHunt() {
  await api.runHunt(detail.value.id);
  await loadDetail(detail.value.id, true);
}

async function reextract() {
  await api.reextractHunt(detail.value.id);
  await loadDetail(detail.value.id, true);
}

async function downloadStix() {
  const { data } = await api.downloadHuntStix(detail.value.id);
  const url = URL.createObjectURL(data);
  const a = document.createElement('a');
  a.href = url;
  a.download = `siembox-hunt-${detail.value.id}.stix.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function deleteHunt() {
  await ElMessageBox.confirm('Delete this hunt and its results?', 'Delete hunt', { type: 'warning' });
  await api.deleteHunt(detail.value.id);
  drawer.value = false;
  refreshAll();
}

async function saveHuntSettings() {
  await api.updateHunt(detail.value.id, { lookback_days: edit.lookback_days, alert_on_match: edit.alert_on_match });
  ElMessage.success('Saved. Run the hunt to apply the new window.');
  await loadDetail(detail.value.id, true);
}

async function toggleIoc(row: any, enabled: boolean) {
  await api.setHuntIndicatorEnabled(detail.value.id, row.id, enabled);
  row.enabled = enabled;
}

async function addIoc() {
  await api.addHuntIndicator(detail.value.id, { type: newIoc.type, value: newIoc.value.trim() });
  newIoc.value = '';
  await loadDetail(detail.value.id, true);
}

const hypForm = reactive({ visible: false, id: 0, title: '', description: '', terms: '', techniques: '' });

function openHypothesis(h?: any) {
  Object.assign(hypForm, {
    visible: true,
    id: h?.id || 0,
    title: h?.title || '',
    description: h?.description || '',
    terms: (h?.search_terms || []).join('\n'),
    techniques: (h?.attack_techniques || []).join(', '),
  });
}

async function saveHypothesis() {
  const body = {
    title: hypForm.title.trim(),
    description: hypForm.description,
    search_terms: hypForm.terms.split('\n').map((t) => t.trim()).filter(Boolean),
    attack_techniques: hypForm.techniques.split(',').map((t) => t.trim()).filter(Boolean),
  };
  if (hypForm.id) await api.updateHuntHypothesis(detail.value.id, hypForm.id, body);
  else await api.addHuntHypothesis(detail.value.id, body);
  hypForm.visible = false;
  ElMessage.success('Saved. Run the hunt to test it.');
  await loadDetail(detail.value.id, true);
}

async function setHypothesis(h: any, patch: Record<string, unknown>) {
  await api.updateHuntHypothesis(detail.value.id, h.id, patch);
  Object.assign(h, patch);
}

async function removeHypothesis(h: any) {
  await ElMessageBox.confirm(`Delete "${h.title}"?`, 'Delete hypothesis', { type: 'warning' });
  await api.deleteHuntHypothesis(detail.value.id, h.id);
  await loadDetail(detail.value.id, true);
}

// ---- Sources

const sourceForm = reactive({
  visible: false,
  id: 0,
  url: '',
  name: '',
  kind: 'auto',
  check_interval_minutes: 360,
  lookback_days: 14,
  alert_on_match: true,
  use_ai: true,
  saving: false,
});

function openSource(row?: any) {
  Object.assign(sourceForm, {
    visible: true,
    id: row?.id || 0,
    url: row?.url || '',
    name: row?.name || '',
    kind: row?.kind || 'auto',
    check_interval_minutes: row?.check_interval_minutes || 360,
    lookback_days: row?.lookback_days || 14,
    alert_on_match: row ? row.alert_on_match : true,
    use_ai: row ? row.use_ai : true,
    saving: false,
  });
}

async function saveSource() {
  sourceForm.saving = true;
  try {
    const { id } = sourceForm;
    const body = {
      url: sourceForm.url,
      name: sourceForm.name,
      kind: sourceForm.kind,
      check_interval_minutes: sourceForm.check_interval_minutes,
      lookback_days: sourceForm.lookback_days,
      alert_on_match: sourceForm.alert_on_match,
      use_ai: sourceForm.use_ai,
    };
    if (id) await api.updateHuntSource(id, body);
    else await api.createHuntSource(body);
    sourceForm.visible = false;
    await loadSources();
    void loadSummary();
  } finally {
    sourceForm.saving = false;
  }
}

async function toggleSource(row: any, enabled: boolean) {
  await api.updateHuntSource(row.id, { enabled });
  row.enabled = enabled;
}

async function checkSource(row: any) {
  checking.value = row.id;
  try {
    const { data } = await api.checkHuntSource(row.id);
    if (data.ok) ElMessage.success(`Checked: ${data.hunts_created} new hunt(s).`);
    else ElMessage.error(data.error || 'The check failed.');
    await loadSources();
    refreshAll();
  } finally {
    checking.value = null;
  }
}

async function deleteSource(row: any) {
  await ElMessageBox.confirm(`Stop watching ${row.name}? Its hunts are kept.`, 'Delete source', { type: 'warning' });
  await api.deleteHuntSource(row.id);
  await loadSources();
}

function showSourceHunts(row: any) {
  filters.source_id = row.id;
  filters.search = '';
  tab.value = 'hunts';
  page.value = 1;
  void loadHunts();
  ElMessage.info(`Showing hunts from ${row.name}. Refresh the list to clear the filter.`);
}

// ---- TAXII tokens

async function createToken() {
  const { data } = await api.createTaxiiToken(newTokenName.value.trim());
  createdToken.value = data.token;
  newTokenName.value = '';
  await loadTokens();
}

async function revokeToken(row: any) {
  await ElMessageBox.confirm(`Revoke the token for ${row.name}? Clients using it stop syncing.`, 'Revoke token', { type: 'warning' });
  await api.revokeTaxiiToken(row.id);
  await loadTokens();
}

function onResize() {
  isMobile.value = window.innerWidth < 768;
}

watch(
  () => filters.search + filters.status,
  () => {
    filters.source_id = undefined;
  }
);

onMounted(() => {
  refreshAll();
  void loadSources();
  void loadTokens();
  window.addEventListener('resize', onResize);
});

onBeforeUnmount(() => {
  if (pollTimer) clearTimeout(pollTimer);
  window.removeEventListener('resize', onResize);
});
</script>

<style scoped>
.threat-hunting {
  padding: 4px;
}
.page-header h2 {
  margin: 0 0 4px;
}
.subtitle,
.muted {
  color: var(--el-text-color-secondary);
}
.summary-alert,
.mb {
  margin-bottom: 12px;
}
.toolbar {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.clickable :deep(tbody tr) {
  cursor: pointer;
}
.hunt-title {
  font-weight: 500;
}
.pager {
  margin-top: 12px;
}
.ml {
  margin-left: 6px;
}
.error-text {
  color: var(--el-color-danger);
  font-size: 12px;
}
.threat-hunting h3 {
  margin: 20px 0 10px;
}
.token-alert {
  margin: 8px 0;
}
.token {
  word-break: break-all;
  user-select: all;
}
.detail-head {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 8px;
}
.actions {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.hyp {
  margin-bottom: 10px;
}
.hyp.disabled {
  opacity: 0.55;
}
.hyp-head {
  display: flex;
  justify-content: space-between;
  gap: 8px;
}
.tags {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
  margin: 6px 0;
}
.hyp-actions {
  display: flex;
  gap: 10px;
  align-items: center;
}
.ioc {
  word-break: break-all;
}
.ioc.off {
  text-decoration: line-through;
  opacity: 0.6;
}
.ctx {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  word-break: break-word;
}
.logline {
  font-family: var(--el-font-family-mono, monospace);
  font-size: 12px;
  word-break: break-all;
}
</style>
