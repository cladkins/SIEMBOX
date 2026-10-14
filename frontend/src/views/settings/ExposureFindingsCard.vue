<template>
  <el-card>
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
      <el-select v-model="severity" clearable placeholder="Any severity" aria-label="Filter by severity" style="width: 150px" @change="reloadFromStart">
        <el-option v-for="s in EXPOSURE_SEVERITIES" :key="s" :label="capitalize(s)" :value="s" />
      </el-select>
      <el-select v-model="source" clearable placeholder="Any source" aria-label="Filter by source" style="width: 180px" @change="reloadFromStart">
        <el-option v-for="(label, value) in SOURCE_LABELS" :key="value" :label="label" :value="value" />
      </el-select>
    </div>

    <el-table :data="findings" v-loading="loading" stripe row-key="id" empty-text="No findings">
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
            <p v-if="row.alert_id"><strong>Alert:</strong> #{{ row.alert_id }} in the alert queue</p>
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

      <el-table-column label="Source" width="130">
        <template #default="{ row }">{{ SOURCE_LABELS[row.source as ExposureFindingSource] ?? row.source }}</template>
      </el-table-column>

      <el-table-column label="Seen" width="180">
        <template #default="{ row }">
          <div class="seen-line"><span class="seen-label">First</span> {{ formatWhen(row.first_seen, '—') }}</div>
          <div class="seen-line"><span class="seen-label">Last</span> {{ formatWhen(row.last_seen, '—') }}</div>
        </template>
      </el-table-column>

      <el-table-column label="State" width="140">
        <template #default="{ row }">
          <template v-if="row.resolved_at">
            <el-tag type="success" size="small" effect="plain">Resolved</el-tag>
            <div class="seen-line">{{ formatWhen(row.resolved_at, '') }}</div>
          </template>
          <el-tag v-else type="warning" size="small">Open</el-tag>
        </template>
      </el-table-column>

      <el-table-column label="Actions" width="100" align="center" fixed="right">
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
import { computed, onMounted, ref } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Refresh } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import HibpAttribution from '@/components/HibpAttribution.vue';
import SeverityBadge from '@/components/SeverityBadge.vue';
import exposureService, {
  EXPOSURE_SEVERITIES,
  type ExposureFinding,
  type ExposureFindingSource,
  type ExposureSeverity,
} from '@/services/exposureService';
import {
  apiErrorMessage,
  apiErrorStatus,
  domainFindingDetail,
  formatWhen,
  identityKindLabel,
  isHibpFinding,
  type DetailItem,
  type DetailLine,
  type DomainMonitorState,
} from '@/utils/exposure';

const props = defineProps<{ domainMonitor: DomainMonitorState }>();
const emit = defineEmits<{ (e: 'changed'): void }>();

const SOURCE_LABELS: Record<ExposureFindingSource, string> = {
  'leaked-creds': 'Leaked credentials',
  'domain-monitor': 'Domain monitoring',
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

const findings = ref<FindingRow[]>([]);
// HIBP's data must be attributed wherever it is shown, and only there (a
// future non-HIBP provider's findings are not credited to HIBP).
const showsBreachData = computed(() => findings.value.some(isHibpFinding));
// Rows whose raw detail JSON is shown under the readable one.
const rawShown = ref(new Set<number>());

function toggleRaw(id: number) {
  const next = new Set(rawShown.value);
  if (!next.delete(id)) next.add(id);
  rawShown.value = next;
}
const total = ref(0);
const page = ref(1);
const pageSize = ref(25);
const loading = ref(false);
const openOnly = ref(false);
const severity = ref<ExposureSeverity | ''>('');
const source = ref<ExposureFindingSource | ''>('');
const resolvingId = ref<number | null>(null);

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

// Filters and paging can fire loads back to back; only the newest one's
// response is applied.
let latestLoad = 0;

async function load(): Promise<void> {
  const thisLoad = ++latestLoad;
  loading.value = true;
  try {
    const result = await exposureService.listFindings({
      unresolved: openOnly.value,
      severity: severity.value || undefined,
      source: source.value || undefined,
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

/** What a finding was raised against, e.g. "Email domain: example.com". */
function subjectOf(row: ExposureFinding): string {
  if (row.identity_kind && row.identity_value) return `${identityKindLabel(row.identity_kind)}: ${row.identity_value}`;
  if (row.domain) return `Domain: ${row.domain}`;
  return '';
}

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

onMounted(load);

defineExpose({ reload: load });
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

.finding-title {
  font-weight: 500;
  color: var(--el-text-color-primary);
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

.detail-line a {
  color: var(--el-color-primary);
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
}
</style>
