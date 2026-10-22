<template>
  <el-card ref="cardRef" class="findings-card">
    <template #header>
      <div class="card-header">
        <span>
          Findings
          <HelpTip :text="helpText" />
        </span>
        <el-button size="small" :icon="Refresh" circle aria-label="Refresh findings" :loading="loading" @click="load()" />
      </div>
    </template>

    <div class="filters">
      <el-switch v-model="openOnly" active-text="Open only" aria-label="Show open findings only" @change="reloadFromStart" />
      <el-select v-model="severity" clearable placeholder="Any severity" aria-label="Filter by severity" class="filter-severity" @change="reloadFromStart">
        <el-option v-for="s in SEVERITIES_DESC" :key="s" :label="capitalize(s)" :value="s" />
      </el-select>
      <el-select v-model="typeValue" clearable placeholder="Any type" aria-label="Filter by type" class="filter-type" @change="reloadFromStart">
        <el-option v-if="typeFallback" :label="typeFallback.label" :value="typeFallback.value" />
        <el-option-group v-for="group in TYPE_GROUPS" :key="group.label" :label="group.label">
          <el-option v-for="o in group.options" :key="o.value" :label="o.label" :value="o.value" />
        </el-option-group>
      </el-select>
      <el-select
        v-model="assetValue"
        clearable
        filterable
        placeholder="Any domain or identity"
        aria-label="Filter by watched domain or monitored identity"
        class="filter-asset"
        @change="reloadFromStart"
      >
        <el-option v-if="assetFallback" :label="assetFallback.label" :value="assetFallback.value" />
        <el-option-group v-if="assetDomains.length" label="Watched domains">
          <el-option v-for="d in assetDomains" :key="`d:${d.id}`" :label="d.domain" :value="`d:${d.id}`" />
        </el-option-group>
        <el-option-group v-if="assetIdentities.length" label="Monitored identities">
          <el-option v-for="i in assetIdentities" :key="`i:${i.id}`" :label="i.value" :value="`i:${i.id}`" />
        </el-option-group>
      </el-select>
      <el-input
        v-model="searchInput"
        clearable
        :maxlength="MAX_SEARCH_LENGTH"
        placeholder="Search account, domain, breach…"
        aria-label="Search findings"
        :prefix-icon="Search"
        class="filter-search"
      />
      <el-select v-model="sort" aria-label="Sort findings" class="filter-sort" @change="reloadFromStart">
        <el-option label="Most severe first" value="severity" />
        <el-option label="Newest first" value="newest" />
      </el-select>
    </div>

    <!-- Click-through filters with no control of their own. -->
    <div v-if="chips.length" class="chips">
      <el-tag v-for="chip in chips" :key="chip.key" closable effect="plain" @close="dropChip(chip.key)">{{ chip.label }}</el-tag>
    </div>

    <el-table
      :data="findings"
      v-loading="loading"
      stripe
      row-key="id"
      :expand-row-keys="expandedKeys"
      class="findings-table"
      @expand-change="onExpandChange"
    >
      <template #empty>
        <div class="table-empty">
          <span>{{ emptyText }}</span>
          <el-button v-if="hasFilters" link type="primary" @click="clearFilters">Clear filters</el-button>
        </div>
      </template>

      <el-table-column type="expand">
        <template #default="{ row }">
          <div class="finding-detail">
            <template v-if="row.breach">
              <p v-if="row.breach.account"><strong>Account:</strong> {{ row.breach.account }}</p>
              <p>
                <strong>Breach:</strong> {{ row.breach.title }}
                <span v-if="row.breach.domain"> ({{ row.breach.domain }})</span>
                <span v-if="row.breach.date"> · breached {{ row.breach.date }}</span>
              </p>
              <p v-if="row.breach.dataClasses.length">
                <strong>Exposed data:</strong>
                <el-tag v-for="c in row.breach.dataClasses" :key="c" size="small" effect="plain" class="data-class">{{ c }}</el-tag>
              </p>
              <p v-if="row.breach.flags.length"><strong>Flags:</strong> {{ row.breach.flags.join(', ') }}</p>
              <!-- The breach provider's own credit, as HIBP passes it on: plain text, never a link. -->
              <p v-if="row.breach.attribution"><strong>Attribution:</strong> {{ row.breach.attribution }}</p>
            </template>
            <template v-else-if="row.domainLines">
              <div v-for="line in row.domainLines" :key="line.label" class="detail-line">
                <strong>{{ line.label }}: </strong>
                <a v-if="line.href" :href="line.href" target="_blank" rel="noopener noreferrer">{{ line.text }}</a>
                <template v-else-if="line.items">
                  <span v-if="!line.items.length" class="detail-none">none</span>
                  <el-tag
                    v-for="(item, i) in line.items"
                    :key="i"
                    size="small"
                    effect="plain"
                    :type="item.change === 'added' ? 'success' : item.change === 'removed' ? 'danger' : 'info'"
                    :title="item.change"
                    class="data-class"
                  >{{ changeMark(item) }}{{ item.text }}</el-tag>
                </template>
                <span v-else-if="line.text">{{ line.text }}</span>
                <ul v-if="line.list" class="detail-list">
                  <li v-for="(entry, i) in line.list" :key="i">
                    <a v-if="entry.href" :href="entry.href" target="_blank" rel="noopener noreferrer">{{ entry.text }}</a>
                    <template v-else>{{ entry.text }}</template>
                  </li>
                </ul>
              </div>
              <el-button link type="primary" size="small" class="raw-toggle" @click="toggleRaw(row.id)">
                {{ rawShown.has(row.id) ? 'Hide raw detail' : 'Raw detail' }}
              </el-button>
              <pre v-if="rawShown.has(row.id)" class="detail-json">{{ JSON.stringify(row.detail, null, 2) }}</pre>
            </template>
            <pre v-else class="detail-json">{{ JSON.stringify(row.detail, null, 2) }}</pre>
            <p v-if="row.alert_id">
              <strong>Alert:</strong>
              <router-link :to="alertLink(row.alert_id)">{{ formatAlertRef(row.alert_id) }} in the alert queue</router-link>
            </p>
          </div>
        </template>
      </el-table-column>

      <el-table-column label="Severity" width="100">
        <template #default="{ row }">
          <SeverityBadge :severity="row.severity" size="small" effect="light" :show-icon="false" />
        </template>
      </el-table-column>

      <el-table-column label="Finding" min-width="220">
        <template #default="{ row }">
          <div class="finding-title">{{ row.title || row.event_type }}</div>
          <el-text v-if="subjectOf(row)" size="small" type="info">{{ subjectOf(row) }}</el-text>
        </template>
      </el-table-column>

      <el-table-column label="Type" width="180">
        <template #default="{ row }">
          <span class="type-cell">
            <span class="type-dot" :style="{ backgroundColor: categoryColor(row.category) }" aria-hidden="true" />
            {{ findingTypeLabel(row.event_type, row.category) }}
          </span>
        </template>
      </el-table-column>

      <el-table-column label="Detected" width="180">
        <template #default="{ row }">
          <div class="seen-line"><span class="seen-label">First</span> {{ formatWhen(row.first_seen, '—') }}</div>
          <div class="seen-line"><span class="seen-label">Last</span> {{ formatWhen(row.last_seen, '—') }}</div>
        </template>
      </el-table-column>

      <el-table-column label="Alert" width="140">
        <template #default="{ row }">
          <template v-if="row.alert_id">
            <router-link :to="alertLink(row.alert_id)" class="alert-link" :aria-label="`Open alert ${formatAlertRef(row.alert_id)}`">{{ formatAlertRef(row.alert_id) }}</router-link>
            <el-tag v-if="row.alert_status" size="small" effect="plain" :type="alertStatusTag(row.alert_status).type" class="alert-status">
              {{ alertStatusTag(row.alert_status).label }}
            </el-tag>
          </template>
          <span v-else class="detail-none" title="No alert: it was deleted or removed by retention">—</span>
        </template>
      </el-table-column>

      <el-table-column label="State" width="130">
        <template #default="{ row }">
          <template v-if="row.resolved_at">
            <el-tag type="success" size="small" effect="plain">Resolved</el-tag>
            <div class="seen-line">{{ formatWhen(row.resolved_at, '') }}</div>
          </template>
          <el-tag v-else type="warning" size="small">Open</el-tag>
        </template>
      </el-table-column>

      <!-- Resolving is admin-only (the API refuses everyone else), so other roles never see the button. -->
      <el-table-column v-if="canResolve" label="Actions" width="100" align="center" fixed="right">
        <template #default="{ row }">
          <el-button
            v-if="!row.resolved_at"
            size="small"
            type="success"
            plain
            :loading="resolvingId === row.id"
            :disabled="resolvingId !== null && resolvingId !== row.id"
            @click="resolve(row)"
          >
            Resolve
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-pagination
      v-if="total > 0"
      v-model:current-page="page"
      v-model:page-size="pageSize"
      class="pager"
      :total="total"
      :page-sizes="[10, 25, 50, 100]"
      layout="total, sizes, prev, pager, next"
      @current-change="load()"
      @size-change="reloadFromStart"
    />

    <HibpAttribution v-if="showsBreachData" />
  </el-card>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { alertRefPath, formatAlertRef } from '@/utils/alertRef';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Refresh, Search } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import HibpAttribution from '@/components/HibpAttribution.vue';
import SeverityBadge from '@/components/SeverityBadge.vue';
import { useThemeStore } from '@/stores/theme';
import exposureService, {
  EXPOSURE_SEVERITIES,
  type ExposureFinding,
  type ExposureFindingSource,
  type ExposureSeverity,
  type MonitoredIdentity,
  type WatchedDomain,
} from '@/services/exposureService';
import {
  apiErrorMessage,
  apiErrorStatus,
  domainFindingDetail,
  formatDay,
  formatWhen,
  identityKindLabel,
  isHibpFinding,
  riskCategoryInfo,
  type DetailItem,
  type DetailLine,
  type DomainMonitorState,
  type TagType,
} from '@/utils/exposure';
import {
  MAX_SEARCH_LENGTH,
  findingTypeLabel,
  parseTypeKey,
  typeFilterGroups,
  typeKey,
  type FindingsFilters,
  type FindingsSort,
} from './dashboard';

const props = withDefaults(
  defineProps<{
    domainMonitor: DomainMonitorState;
    /** Show Resolve (admin only). Off unless the host says so, so a new host can't offer a button that 403s. */
    canResolve?: boolean;
    defaultOpenOnly?: boolean;
    defaultSort?: FindingsSort;
    /** The filters the first load uses (a deep link). */
    initialFilters?: FindingsFilters;
    /** The Asset filter's choices. */
    assets?: { domains: readonly WatchedDomain[]; identities: readonly MonitoredIdentity[] };
  }>(),
  {
    canResolve: false,
    defaultOpenOnly: false,
    defaultSort: 'newest',
    initialFilters: () => ({}),
    assets: () => ({ domains: [], identities: [] }),
  }
);
const emit = defineEmits<{ (e: 'changed'): void }>();

const SOURCE_LABELS: Record<ExposureFindingSource, string> = {
  'leaked-creds': 'Leaked credentials',
  'domain-monitor': 'Domain monitoring',
};
const SEVERITIES_DESC = [...EXPOSURE_SEVERITIES].reverse();
const TYPE_GROUPS = typeFilterGroups();
const ALERT_STATUS: Record<string, { type: TagType; label: string }> = {
  new: { type: 'danger', label: 'New' },
  investigating: { type: 'warning', label: 'Investigating' },
  closed: { type: 'success', label: 'Closed' },
  false_positive: { type: 'info', label: 'False positive' },
};

const REPEATS =
  'Re-checks only update Last seen and never alert twice; a resolved finding is never reopened. Each new finding also raised an alert in the alert queue.';
const helpText = computed(() =>
  props.domainMonitor === 'unavailable'
    ? `One finding per breach an identity appears in (domain findings will join them once domain monitoring ships). ${REPEATS}`
    : `Leaked-credential checks add one finding per breach an identity appears in; domain monitoring adds one per change it detects (a DNS or registration change, a new certificate, a newly registered lookalike). ${REPEATS}`
);

// Prefix of a value a domain change added or removed (the tag colour says it too).
const changeMark = (item: DetailItem) => (item.change === 'added' ? '+ ' : item.change === 'removed' ? '− ' : '');

// What "resolved" usually means, per source, in the Resolve confirmation.
const RESOLVE_EXAMPLES: Record<ExposureFindingSource, string> = {
  'leaked-creds': 'e.g. the password was changed',
  'domain-monitor': 'e.g. the change was expected, or has been dealt with',
};

/** The breach fields of a leaked-credential finding, for the expanded row. */
interface BreachView {
  account: string;
  title: string;
  domain: string;
  date: string;
  dataClasses: string[];
  flags: string[];
  /** The breach provider's credit (HIBP's Attribution field), shown as plain text. */
  attribution: string;
}
type FindingRow = ExposureFinding & { breach: BreachView | null; domainLines: DetailLine[] | null };

const themeStore = useThemeStore();
const cardRef = ref<{ $el: HTMLElement } | null>(null);
const findings = ref<FindingRow[]>([]);
// HIBP's data must be attributed wherever it is shown, and only there (a
// future non-HIBP provider's findings are not credited to HIBP).
const showsBreachData = computed(() => findings.value.some(isHibpFinding));
// Rows whose raw detail JSON is shown under the readable one.
const rawShown = ref(new Set<number>());
const expandedKeys = ref<number[]>([]);

function toggleRaw(id: number) {
  const next = new Set(rawShown.value);
  if (!next.delete(id)) next.add(id);
  rawShown.value = next;
}
const total = ref(0);
const page = ref(1);
const pageSize = ref(25);
const loading = ref(false);
const resolvingId = ref<number | null>(null);

// ---- Filters ---------------------------------------------------------------------------

const openOnly = ref(props.defaultOpenOnly);
const severity = ref<ExposureSeverity | ''>('');
/** typeKey(event_type, category), or '' for any type. */
const typeValue = ref('');
/** 'd:<domain id>', 'i:<identity id>', or '' for any. */
const assetValue = ref('');
const searchInput = ref('');
const search = ref('');
const sort = ref<FindingsSort>(props.defaultSort);
const sinceDays = ref<number | undefined>();
const since = ref<string | undefined>();
const alertId = ref<number | undefined>();
const source = ref<ExposureFindingSource | undefined>();
const account = ref<string | undefined>();
const lookalike = ref<string | undefined>();

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

const assetDomains = computed(() => [...props.assets.domains].sort((a, b) => a.domain.localeCompare(b.domain)));
const assetIdentities = computed(() => [...props.assets.identities].sort((a, b) => a.value.localeCompare(b.value)));

// A deep-linked value the option lists don't hold (yet) still gets a readable label.
const typeFallback = computed(() => {
  const value = typeValue.value;
  if (!value || TYPE_GROUPS.some((g) => g.options.some((o) => o.value === value))) return null;
  const { event_type, category } = parseTypeKey(value);
  return { value, label: event_type ? findingTypeLabel(event_type, category) : riskCategoryInfo(category).label };
});
const assetFallback = computed(() => {
  const value = assetValue.value;
  if (!value) return null;
  const id = Number(value.slice(2));
  const known = value.startsWith('d:') ? props.assets.domains.some((d) => d.id === id) : props.assets.identities.some((i) => i.id === id);
  return known ? null : { value, label: value.startsWith('d:') ? `Domain #${id}` : `Identity #${id}` };
});

type ChipKey = 'account' | 'lookalike' | 'since_days' | 'since' | 'alert_id' | 'source';
const chips = computed(() => {
  const out: Array<{ key: ChipKey; label: string }> = [];
  if (account.value) out.push({ key: 'account', label: `Account: ${account.value}` });
  if (lookalike.value) out.push({ key: 'lookalike', label: `Lookalike: ${lookalike.value}` });
  if (sinceDays.value !== undefined) out.push({ key: 'since_days', label: `Detected in the last ${sinceDays.value} days` });
  if (since.value) out.push({ key: 'since', label: `Detected since ${formatDay(since.value)}` });
  if (alertId.value !== undefined) out.push({ key: 'alert_id', label: `Alert ${formatAlertRef(alertId.value)}` });
  if (source.value) out.push({ key: 'source', label: `Source: ${SOURCE_LABELS[source.value]}` });
  return out;
});

const hasFilters = computed(
  () =>
    !!severity.value ||
    !!typeValue.value ||
    !!assetValue.value ||
    !!search.value ||
    chips.value.length > 0
);
const emptyText = computed(() =>
  hasFilters.value ? 'No findings match these filters' : openOnly.value ? 'No open findings' : 'No findings'
);

/** Set every filter from `f` (anything it leaves out goes back to the default). */
function setFilters(f: FindingsFilters) {
  // From an alert, the finding is wanted whether or not it is still open.
  openOnly.value = f.open_only ?? (f.alert_id !== undefined ? false : props.defaultOpenOnly);
  severity.value = f.severity ?? '';
  typeValue.value = f.event_type || f.category ? typeKey(f.event_type, f.category) : '';
  assetValue.value = f.domain_id !== undefined ? `d:${f.domain_id}` : f.identity_id !== undefined ? `i:${f.identity_id}` : '';
  search.value = f.search?.trim().slice(0, MAX_SEARCH_LENGTH) ?? '';
  searchInput.value = search.value;
  sort.value = f.sort ?? props.defaultSort;
  sinceDays.value = f.since_days;
  since.value = f.since;
  alertId.value = f.alert_id;
  source.value = f.source;
  account.value = f.account;
  lookalike.value = f.lookalike;
}

function dropChip(key: ChipKey) {
  if (key === 'account') account.value = undefined;
  else if (key === 'lookalike') lookalike.value = undefined;
  else if (key === 'since_days') sinceDays.value = undefined;
  else if (key === 'since') since.value = undefined;
  else if (key === 'alert_id') alertId.value = undefined;
  else source.value = undefined;
  void reloadFromStart();
}

function clearFilters() {
  setFilters({});
  void reloadFromStart();
}

// Typing searches after a pause, not on every key.
let searchTimer: ReturnType<typeof setTimeout> | null = null;
watch(searchInput, (value) => {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    searchTimer = null;
    const next = (value ?? '').trim();
    if (next === search.value) return;
    search.value = next;
    void reloadFromStart();
  }, 300);
});
onBeforeUnmount(() => {
  if (searchTimer) clearTimeout(searchTimer);
});

// ---- Loading ---------------------------------------------------------------------------

// Filters and paging can fire loads back to back; only the newest one's
// response is applied.
let latestLoad = 0;

async function load(): Promise<void> {
  const thisLoad = ++latestLoad;
  loading.value = true;
  try {
    const { event_type, category } = parseTypeKey(typeValue.value);
    const asset = assetValue.value;
    const assetId = asset ? Number(asset.slice(2)) : undefined;
    const result = await exposureService.listFindings({
      unresolved: openOnly.value,
      severity: severity.value || undefined,
      event_type,
      category,
      source: source.value,
      domain_id: asset.startsWith('d:') ? assetId : undefined,
      identity_id: asset.startsWith('i:') ? assetId : undefined,
      since_days: sinceDays.value,
      since: since.value,
      alert_id: alertId.value,
      search: search.value || undefined,
      account: account.value,
      lookalike: lookalike.value,
      sort: sort.value,
      limit: pageSize.value,
      offset: (page.value - 1) * pageSize.value,
    });
    if (thisLoad !== latestLoad) return;
    // Past the end (the last row of the last page was resolved away): step back.
    const lastPage = Math.max(1, Math.ceil(result.total / pageSize.value));
    if (result.findings.length === 0 && page.value > lastPage) {
      page.value = lastPage;
      return load();
    }
    findings.value = result.findings.map((f) => ({ ...f, breach: breachOf(f), domainLines: domainFindingDetail(f) }));
    total.value = result.total;
    // Opened from an alert: show that finding's detail straight away.
    expandedKeys.value = alertId.value !== undefined && result.findings.length === 1 ? [result.findings[0].id] : [];
  } catch (error) {
    if (thisLoad === latestLoad) ElMessage.error(apiErrorMessage(error, 'Failed to load findings'));
  } finally {
    if (thisLoad === latestLoad) loading.value = false;
  }
}

function reloadFromStart() {
  page.value = 1;
  return load();
}

function onExpandChange(_row: FindingRow, expanded: FindingRow[]) {
  expandedKeys.value = expanded.map((r) => r.id);
}

/**
 * Show the findings `filters` selects (every other filter back to its
 * default), from the first page, and bring the card into view. The page's
 * tiles, lists and deep links all go through here.
 */
async function applyFilters(filters: FindingsFilters): Promise<void> {
  if (searchTimer) {
    clearTimeout(searchTimer);
    searchTimer = null;
  }
  setFilters(filters);
  await nextTick(); // let the search box's watcher see the new value before the load
  if (searchTimer) {
    clearTimeout(searchTimer);
    searchTimer = null;
  }
  const loaded = reloadFromStart();
  cardRef.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' });
  await loaded;
}

// ---- Rows ------------------------------------------------------------------------------

/** What a finding was raised against, e.g. "Email domain: example.com". */
function subjectOf(row: ExposureFinding): string {
  if (row.identity_kind && row.identity_value) return `${identityKindLabel(row.identity_kind)}: ${row.identity_value}`;
  if (row.domain) return `Domain: ${row.domain}`;
  return '';
}

function categoryColor(category: string | undefined): string {
  const info = riskCategoryInfo(category);
  return themeStore.isDark ? info.dark : info.light;
}

function alertStatusTag(status: string): { type: TagType; label: string } {
  return ALERT_STATUS[status] ?? { type: 'info', label: status };
}

const alertLink = (id: number) => alertRefPath(id);

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

/** The breach fields of a leaked-credential finding's detail, or null for anything else. */
function breachOf(row: ExposureFinding): BreachView | null {
  const d = row.detail ?? {};
  if (row.source !== 'leaked-creds' || !str(d.breach_name)) return null;
  const flags = [
    d.is_verified === false ? 'unverified breach' : '',
    d.is_sensitive === true ? 'sensitive' : '',
    d.is_stealer_log === true ? 'stealer log' : '',
    d.is_spam_list === true ? 'spam list' : '',
    d.is_fabricated === true ? 'fabricated' : '',
  ].filter(Boolean);
  return {
    account: str(d.account),
    title: str(d.breach_title) || str(d.breach_name),
    domain: str(d.breach_domain),
    date: str(d.breach_date),
    dataClasses: Array.isArray(d.data_classes) ? d.data_classes.filter((c): c is string => typeof c === 'string') : [],
    flags,
    attribution: str(d.breach_attribution),
  };
}

async function resolve(row: ExposureFinding) {
  try {
    await ElMessageBox.confirm(
      `Mark this finding as resolved (${RESOLVE_EXAMPLES[row.source] ?? 'e.g. it has been dealt with'})? This can’t be undone, and later checks won’t reopen it.`,
      'Resolve finding',
      { confirmButtonText: 'Resolve', cancelButtonText: 'Cancel', type: 'info' }
    );
  } catch {
    return; // cancelled
  }
  resolvingId.value = row.id;
  try {
    await exposureService.resolveFinding(row.id);
    ElMessage.success('Finding resolved');
    await load();
    emit('changed');
  } catch (error) {
    if (apiErrorStatus(error) === 404) {
      // Gone meanwhile (deleted with its identity or domain): drop the stale row.
      ElMessage.error('That finding no longer exists; the list was refreshed');
      await load();
      emit('changed');
    } else {
      ElMessage.error(apiErrorMessage(error, 'Failed to resolve the finding'));
    }
  } finally {
    resolvingId.value = null;
  }
}

setFilters(props.initialFilters);
onMounted(load);

defineExpose({ reload: load, applyFilters });
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.filters {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}

.filter-severity {
  width: 140px;
}

.filter-type {
  width: 240px;
}

.filter-asset {
  width: 220px;
}

.filter-search {
  width: 240px;
}

.filter-sort {
  width: 170px;
}

/* Below a tablet the filters take the full row each, so nothing overflows the card. */
@media (max-width: 768px) {
  .filter-severity,
  .filter-type,
  .filter-asset,
  .filter-search,
  .filter-sort {
    width: 100%;
  }
}

.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 12px;
}

.table-empty {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: center;
}

.finding-title {
  font-weight: 500;
  color: var(--el-text-color-primary);
}

.type-cell {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  line-height: 1.4;
}

.type-dot {
  flex-shrink: 0;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.alert-link {
  margin-right: 6px;
  color: var(--el-color-primary);
  text-decoration: none;
}

.alert-link:hover {
  text-decoration: underline;
}

.alert-status {
  vertical-align: middle;
}

.seen-line {
  font-size: 12px;
  line-height: 1.6;
  white-space: nowrap;
}

.seen-label {
  display: inline-block;
  width: 32px;
  color: var(--el-text-color-secondary);
}

.finding-detail {
  padding: 4px 16px 4px 48px;
  font-size: 13px;
  color: var(--el-text-color-regular);
}

.finding-detail p {
  margin: 0 0 6px;
}

.finding-detail a {
  color: var(--el-color-primary);
}

.data-class {
  margin: 0 4px 4px 0;
}

.detail-json {
  margin: 0 0 6px;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-word;
}

.detail-line {
  margin: 0 0 6px;
  word-break: break-word;
}

/* el-tag is a fixed-height nowrap pill: let a long value (an SPF or DMARC
   record) wrap inside its tag instead of widening the table. */
.detail-line .el-tag {
  height: auto;
  min-height: 20px;
  max-width: 100%;
  white-space: normal;
  overflow-wrap: anywhere;
  line-height: 1.4;
}

.detail-none {
  color: var(--el-text-color-secondary);
}

.detail-list {
  margin: 4px 0 0;
  padding-left: 20px;
}

.raw-toggle {
  margin-bottom: 6px;
}

.pager {
  margin-top: 12px;
  justify-content: flex-end;
  flex-wrap: wrap;
}
</style>
