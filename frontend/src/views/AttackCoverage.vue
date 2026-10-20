<template>
  <div class="attack-coverage" data-testid="attack-coverage">
    <el-card class="attack-head">
      <div class="head-row">
        <div class="head-title">
          <h2>MITRE ATT&amp;CK coverage</h2>
          <div class="head-sub">
            Which Enterprise techniques your enabled rules can detect with the logs you actually receive.
            <template v-if="coverage">
              ATT&amp;CK v{{ coverage.attack_version }} ·
              {{ coverage.cached ? 'cached' : 'computed' }} {{ formatTime(coverage.computed_at) }}
            </template>
          </div>
        </div>
        <div class="head-actions">
          <el-button :loading="exporting" :disabled="!coverage" data-testid="export-layer" @click="exportLayer">
            <el-icon><Download /></el-icon> Export Navigator layer
          </el-button>
          <el-button
            v-if="canEdit"
            :loading="loading && refreshing"
            data-testid="refresh-coverage"
            @click="load(true)"
          >
            <el-icon><Refresh /></el-icon> Refresh
          </el-button>
        </div>
      </div>

      <!-- Headline numbers: overall, then each level. -->
      <div v-if="coverage" class="headline" data-testid="headline">
        <div class="headline-percent">
          <span class="big" data-testid="overall-percent">{{ formatPercent(coverage.summary.percent) }}</span>
          <span class="headline-caption">
            {{ coverage.summary.covered }} of {{ coverage.summary.counted }} in-scope techniques covered or proven
            <template v-if="coverage.summary.excluded"> ({{ coverage.summary.excluded }} not applicable)</template>
          </span>
        </div>
        <div class="legend" aria-label="Legend">
          <template v-if="mode === 'coverage'">
            <span v-for="lvl in LEVELS" :key="lvl" class="legend-item">
              <LevelBadge :level="lvl" />
              <span class="legend-count">{{ coverage.summary.by_level[lvl] ?? 0 }}</span>
            </span>
            <span class="legend-item"><LevelBadge level="none" excluded /></span>
          </template>
          <template v-else>
            <span v-for="b in ALERT_BUCKETS" :key="b.bucket" :class="['legend-swatch', `heat-${b.bucket}`]">{{ b.label }}</span>
          </template>
        </div>
      </div>
    </el-card>

    <el-card class="attack-toolbar-card">
      <div class="toolbar">
        <el-form-item label="Platforms" class="toolbar-item">
          <el-select
            v-model="platforms"
            multiple
            collapse-tags
            collapse-tags-tooltip
            placeholder="Inferred from your data"
            style="width: 280px"
            data-testid="platform-select"
            @change="onPlatformsChange"
          >
            <el-option v-for="p in ATTACK_PLATFORMS" :key="p" :label="p" :value="p" />
          </el-select>
          <el-button v-if="scopeSource === 'query'" link type="primary" class="reset-scope" @click="resetPlatforms">
            Use inferred
          </el-button>
        </el-form-item>
        <el-input
          v-model="search"
          clearable
          placeholder="Search ID or name (T1110, brute)"
          style="width: 240px"
          data-testid="technique-search"
        >
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-switch v-model="showSubs" active-text="Show sub-techniques" data-testid="toggle-subs" />
        <el-radio-group v-model="mode" size="small" data-testid="mode-toggle">
          <el-radio-button value="coverage">Coverage</el-radio-button>
          <el-radio-button value="alerts">Alerts (30 d)</el-radio-button>
        </el-radio-group>
      </div>
      <!-- Why this scope: what in your data implied each platform. -->
      <div v-if="coverage" class="scope-why" data-testid="scope-why">
        <template v-if="coverage.scope.source === 'query'">
          Scope chosen here: {{ coverage.scope.platforms.join(', ') }}. Inferred from your data:
          {{ coverage.scope.inferred.platforms.join(', ') || 'nothing' }}.
        </template>
        <template v-else>Scope inferred from your data:</template>
        <ul v-if="coverage.scope.inferred.inferred_from.length" class="scope-evidence">
          <li v-for="(e, i) in coverage.scope.inferred.inferred_from" :key="i">
            <strong>{{ e.platform }}</strong> — {{ sourceLabel(e.source) }}<template v-if="e.items.length && e.source !== 'default'">:
              {{ shortList(e.items) }}</template>
          </li>
        </ul>
        <span v-if="coverage.scope.inferred.unmapped_parsers.length" class="scope-unmapped">
          Parsers that imply no platform (still dry-run): {{ shortList(coverage.scope.inferred.unmapped_parsers) }}.
        </span>
      </div>
    </el-card>

    <el-alert
      v-if="coverage && nothingTagged(coverage.summary)"
      type="info"
      show-icon
      :closable="false"
      class="attack-banner"
      data-testid="nothing-tagged"
      title="No rule is tagged with an ATT&CK technique yet"
    >
      Every technique is at "No rule". The catalog's detection rules carry ATT&amp;CK technique tags: install them, or
      update installed ones, from Detection Rules → Browse Catalog (filter "Update available").
      <template v-if="canEdit">Until then you can tag your own rules in the rule editor (ATT&amp;CK techniques).</template>
    </el-alert>

    <el-alert v-if="error" type="error" show-icon :closable="false" class="attack-banner" data-testid="coverage-error" :title="error">
      <el-button size="small" @click="load(false)">Try again</el-button>
    </el-alert>

    <div v-loading="loading" class="matrix-wrap" element-loading-text="Working out coverage…">
      <el-empty
        v-if="!loading && !error && coverage && columns.every((c) => !c.cells.length)"
        :description="search ? `No technique matches “${search}”.` : 'No technique is in scope for these platforms.'"
      />
      <div v-else-if="coverage" class="matrix" role="grid" aria-label="ATT&CK matrix" data-testid="matrix">
        <div v-for="col in columns" :key="col.tactic.shortname" class="matrix-col" role="rowgroup">
          <div class="col-head" :title="`${col.tactic.id} ${col.tactic.name}`">
            <div class="col-name">{{ col.tactic.name }}</div>
            <div class="col-stats">
              <span class="col-percent" data-testid="tactic-percent">{{ formatPercent(col.tactic.percent) }}</span>
              <span class="col-count">{{ col.tactic.covered }}/{{ col.tactic.counted }}</span>
            </div>
          </div>
          <template v-for="cell in col.cells" :key="cell.technique.id">
            <button
              type="button"
              :class="cellClass(cell.technique)"
              :aria-label="cellAria(cell.technique)"
              :data-technique="cell.technique.id"
              data-testid="matrix-cell"
              @click="select(cell.technique.id)"
            >
              <span class="cell-mark" aria-hidden="true">{{ cellMark(cell.technique) }}</span>
              <span class="cell-text">
                <span class="cell-name">{{ cell.technique.name }}</span>
                <span class="cell-meta">
                  {{ cell.technique.id }}
                  <template v-if="mode === 'alerts'"> · {{ cell.technique.alerts_30d.toLocaleString() }}</template>
                  <template v-else-if="cell.technique.subtechniques?.total">
                    · {{ cell.technique.subtechniques.covered }}/{{ cell.technique.subtechniques.total }} sub
                  </template>
                </span>
              </span>
            </button>
            <button
              v-for="s in cell.subs"
              :key="s.id"
              type="button"
              :class="[...cellClass(s), 'is-sub']"
              :aria-label="cellAria(s)"
              :data-technique="s.id"
              data-testid="matrix-cell"
              @click="select(s.id)"
            >
              <span class="cell-mark" aria-hidden="true">{{ cellMark(s) }}</span>
              <span class="cell-text">
                <span class="cell-name">{{ s.name }}</span>
                <span class="cell-meta">
                  {{ s.id }}<template v-if="mode === 'alerts'"> · {{ s.alerts_30d.toLocaleString() }}</template>
                </span>
              </span>
            </button>
          </template>
        </div>
      </div>
    </div>

    <TechniquePanel
      :technique="selected"
      :by-id="byId"
      :tactics="coverage?.tactics ?? []"
      :can-edit="canEdit"
      :catalog="catalog"
      :catalog-loading="catalogLoading"
      :catalog-error="catalogError"
      @close="select(null)"
      @select="select"
      @changed="load(false)"
      @installed="onInstalled"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, shallowRef, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { format } from 'date-fns';
import { ElMessage } from 'element-plus';
import { Download, Refresh, Search } from '@element-plus/icons-vue';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import LevelBadge from '@/components/attack/LevelBadge.vue';
import TechniquePanel from '@/components/attack/TechniquePanel.vue';
import {
  ATTACK_PLATFORMS,
  EXCLUDED_INFO,
  LEVELS,
  LEVEL_INFO,
  alertBucket,
  buildMatrixColumns,
  formatPercent,
  nothingTagged,
  type AttackCoverage,
  type CoverageTechnique,
} from '@/utils/attack';

// Every role reads the page and exports the layer; marking techniques not
// applicable and forcing a recompute are analyst and up (the API's gates).
const authStore = useAuthStore();
const canEdit = computed(() => authStore.canAnalyst);
const route = useRoute();
const router = useRouter();

const coverage = shallowRef<AttackCoverage | null>(null);
const loading = ref(false);
const refreshing = ref(false);
const error = ref('');
const exporting = ref(false);

/** The platform select: the inferred scope until the user picks platforms. */
const platforms = ref<string[]>([]);
const chosen = ref<string[] | null>(null);
const scopeSource = computed(() => coverage.value?.scope.source ?? 'inferred');
const platformsParam = computed(() => (chosen.value && chosen.value.length ? chosen.value.join(',') : undefined));

const search = ref('');
const showSubs = ref(false);
const mode = ref<'coverage' | 'alerts'>('coverage');

const ALERT_BUCKETS = [
  { bucket: 0, label: 'none' },
  { bucket: 1, label: '1–9' },
  { bucket: 2, label: '10–99' },
  { bucket: 3, label: '100–999' },
  { bucket: 4, label: '1000+' },
];

const byId = computed(() => new Map((coverage.value?.techniques ?? []).map((t) => [t.id, t])));
const columns = computed(() =>
  coverage.value ? buildMatrixColumns(coverage.value, { search: search.value, showSubtechniques: showSubs.value }) : []
);

const selectedId = ref<string | null>(typeof route.query.technique === 'string' ? route.query.technique.toUpperCase() : null);
const selected = computed(() => (selectedId.value ? byId.value.get(selectedId.value) ?? null : null));

function select(id: string | null) {
  selectedId.value = id;
  const query = { ...route.query };
  if (id) query.technique = id;
  else delete query.technique;
  void router.replace({ query });
  if (id) loadCatalogOnce();
}

async function load(refresh: boolean) {
  loading.value = true;
  refreshing.value = refresh;
  error.value = '';
  try {
    const { data } = await api.getAttackCoverage(platformsParam.value, refresh);
    coverage.value = data;
    platforms.value = [...data.scope.platforms];
    if (refresh) ElMessage.success('Coverage recomputed');
  } catch (e: any) {
    error.value =
      e?.response?.data?.message ||
      e?.response?.data?.error ||
      (e?.response ? `Could not load the coverage (HTTP ${e.response.status})` : 'Could not reach the API to load the coverage');
  } finally {
    loading.value = false;
    refreshing.value = false;
  }
}

function onPlatformsChange(value: string[]) {
  chosen.value = value.length ? [...value] : null;
  void load(false);
}

function resetPlatforms() {
  chosen.value = null;
  void load(false);
}

// The detection catalog, for the panel's "fills a gap" suggestions: fetched on
// the first panel open (it may hit GitHub), not with the page.
const catalog = ref<any[]>([]);
const catalogLoading = ref(false);
const catalogError = ref('');
let catalogRequested = false;
async function loadCatalog() {
  catalogLoading.value = true;
  catalogError.value = '';
  try {
    const { data } = await api.getRuleCatalog(false, true);
    catalog.value = data.rules || [];
  } catch (e: any) {
    catalogError.value = e?.response?.data?.message || 'The detection catalog could not be loaded.';
  } finally {
    catalogLoading.value = false;
  }
}
function loadCatalogOnce() {
  if (catalogRequested) return;
  catalogRequested = true;
  void loadCatalog();
}
async function onInstalled() {
  await Promise.all([loadCatalog(), load(false)]);
}

async function exportLayer() {
  exporting.value = true;
  try {
    const res = await api.getAttackNavigatorLayer(platformsParam.value);
    const blob = res.data instanceof Blob ? res.data : new Blob([JSON.stringify(res.data)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'siembox-attack-coverage.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    ElMessage.success('Navigator layer downloaded: open it in ATT&CK Navigator → Open Existing Layer → Upload from local');
  } catch {
    ElMessage.error('Export failed');
  } finally {
    exporting.value = false;
  }
}

function cellClass(t: CoverageTechnique): string[] {
  const out = ['matrix-cell'];
  if (mode.value === 'alerts') out.push(`heat-${alertBucket(t.alerts_30d)}`);
  else out.push(t.excluded ? 'is-excluded' : `is-${t.level}`);
  if (t.excluded && mode.value === 'alerts') out.push('is-dimmed');
  if (t.id === selectedId.value) out.push('is-selected');
  return out;
}

function cellMark(t: CoverageTechnique): string {
  if (mode.value === 'alerts') return t.alerts_30d > 0 ? '▲' : '·';
  return t.excluded ? EXCLUDED_INFO.mark : LEVEL_INFO[t.level].mark;
}

function cellAria(t: CoverageTechnique): string {
  const level = t.excluded ? EXCLUDED_INFO.label : LEVEL_INFO[t.level].label;
  return `${t.id} ${t.name}: ${level}, ${t.alerts_30d} alerts in 30 days`;
}

const SOURCE_LABELS: Record<string, string> = {
  parsers: 'parsers with recent logs',
  assets: 'assets',
  endpoint_agents: 'endpoint agents',
  shipper_containers: 'containers reported by log shippers',
  default: 'the default scope: nothing in your data implies a platform yet',
};
function sourceLabel(source: string): string {
  return SOURCE_LABELS[source] ?? source;
}
function shortList(items: string[], max = 6): string {
  return items.length > max ? `${items.slice(0, max).join(', ')} and ${items.length - max} more` : items.join(', ');
}
function formatTime(iso: string): string {
  try {
    return format(new Date(iso), 'MMM dd, HH:mm');
  } catch {
    return iso;
  }
}

watch(
  () => route.query.technique,
  (t) => {
    const id = typeof t === 'string' ? t.toUpperCase() : null;
    if (id !== selectedId.value) {
      selectedId.value = id;
      if (id) loadCatalogOnce();
    }
  }
);

onMounted(() => {
  void load(false);
  if (selectedId.value) loadCatalogOnce();
});
</script>

<style scoped>
.attack-coverage {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.head-row {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 12px;
}
.head-title h2 {
  margin: 0;
  font-size: 18px;
}
.head-sub {
  margin-top: 4px;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
.head-actions {
  display: flex;
  gap: 8px;
  align-items: flex-start;
}
.headline {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-top: 14px;
}
.headline-percent {
  display: flex;
  align-items: baseline;
  gap: 10px;
}
.headline-percent .big {
  font-size: 28px;
  font-weight: 700;
}
.headline-caption {
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
}
.legend-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.legend-count {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.legend-swatch {
  padding: 1px 8px;
  border-radius: 4px;
  font-size: 12px;
  border: 1px solid var(--el-border-color);
}
.toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 14px;
}
.toolbar-item {
  margin-bottom: 0;
}
.reset-scope {
  margin-left: 6px;
}
.scope-why {
  margin-top: 10px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.scope-evidence {
  margin: 4px 0;
  padding-left: 18px;
}
.scope-unmapped {
  display: block;
}
.attack-banner :deep(.el-alert__description) {
  font-size: 13px;
}
.matrix-wrap {
  min-height: 200px;
}
.matrix {
  display: flex;
  gap: 6px;
  overflow-x: auto;
  padding-bottom: 8px;
  align-items: flex-start;
}
.matrix-col {
  flex: 0 0 150px;
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.col-head {
  position: sticky;
  top: 0;
  padding: 6px;
  background: var(--siembox-card-bg);
  border: 1px solid var(--el-border-color);
  border-radius: 4px;
  min-height: 52px;
}
.col-name {
  font-size: 12px;
  font-weight: 600;
  color: var(--el-text-color-primary);
}
.col-stats {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-top: 2px;
}
.col-percent {
  font-weight: 600;
  color: var(--el-text-color-primary);
}
.matrix-cell {
  display: flex;
  align-items: flex-start;
  gap: 5px;
  width: 100%;
  padding: 4px 5px;
  text-align: left;
  font: inherit;
  font-size: 11px;
  line-height: 1.25;
  color: var(--el-text-color-primary);
  background: var(--el-fill-color-lighter);
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 3px;
  cursor: pointer;
}
.matrix-cell:hover {
  border-color: var(--el-color-primary);
}
.matrix-cell:focus-visible {
  outline: 2px solid var(--el-color-primary);
  outline-offset: 1px;
}
.matrix-cell.is-selected {
  box-shadow: 0 0 0 2px var(--el-color-primary);
}
.matrix-cell.is-sub {
  margin-left: 10px;
  width: calc(100% - 10px);
}
.cell-mark {
  flex: 0 0 auto;
  width: 12px;
  font-weight: 700;
  text-align: center;
}
.cell-text {
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.cell-name {
  word-break: break-word;
}
.cell-meta {
  color: var(--el-text-color-secondary);
  font-variant-numeric: tabular-nums;
}
/* Coverage levels (the same tokens as LevelBadge; light and dark via Element Plus' palette). */
.matrix-cell.is-none {
  color: var(--el-text-color-regular);
}
.matrix-cell.is-disabled {
  background: var(--el-color-info-light-8);
  border-color: var(--el-color-info-light-5);
}
.matrix-cell.is-no_data {
  background: var(--el-color-warning-light-8);
  border-color: var(--el-color-warning);
}
.matrix-cell.is-covered {
  background: var(--el-color-success-light-8);
  border-color: var(--el-color-success-light-3);
}
.matrix-cell.is-proven {
  background: var(--el-color-success-light-5);
  border-color: var(--el-color-success-dark-2);
  font-weight: 600;
}
.matrix-cell.is-excluded {
  background: transparent;
  border-style: dashed;
  color: var(--el-text-color-secondary);
  font-style: italic;
}
/* Alerts heatmap: fixed steps (alertBucket), the count printed in every cell. */
.heat-0 {
  background: var(--el-fill-color-lighter);
}
.heat-1 {
  background: var(--el-color-danger-light-9);
  border-color: var(--el-color-danger-light-7);
}
.heat-2 {
  background: var(--el-color-danger-light-7);
  border-color: var(--el-color-danger-light-5);
}
.heat-3 {
  background: var(--el-color-danger-light-5);
  border-color: var(--el-color-danger-light-3);
}
.heat-4 {
  background: var(--el-color-danger-light-3);
  border-color: var(--el-color-danger);
  font-weight: 600;
}
.matrix-cell.is-dimmed {
  opacity: 0.6;
}
</style>
