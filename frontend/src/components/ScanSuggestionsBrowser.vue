<template>
  <el-dialog
    :model-value="modelValue"
    :title="title"
    width="980px"
    top="5vh"
    data-testid="scan-suggestions"
    @update:model-value="(v: boolean) => emit('update:modelValue', v)"
    @open="load(false)"
  >
    <p class="intro muted">
      Ready-made scans from the SIEMBox catalog. <strong>Add</strong> creates
      <template v-if="onlyPolicies">an endpoint scan policy that no endpoint follows yet; assign it to endpoints to start it.</template>
      <template v-else>a <strong>disabled</strong> schedule with the scan's options and timing (in your time zone, {{ zone }}); you then fill in
        the targets and enable it. Endpoint policies are added unassigned.</template>
      Suggestions never name targets.
    </p>

    <div class="filters">
      <el-select v-if="kindOptions.length > 1" v-model="kind" clearable placeholder="All types" style="width: 220px" data-testid="suggestion-kind">
        <el-option v-for="k in kindOptions" :key="k" :label="KIND_LABELS[k]" :value="k" />
      </el-select>
      <el-select v-model="category" clearable placeholder="All categories" style="width: 190px" data-testid="suggestion-category">
        <el-option v-for="c in categoryOptions" :key="c" :label="categoryLabel(c)" :value="c" />
      </el-select>
      <el-input v-model="query" clearable placeholder="Search name, description, tags" style="flex: 1; min-width: 180px" />
      <el-checkbox v-model="hideIntrusive">Hide intrusive</el-checkbox>
      <el-button :loading="loading" @click="load(true)">Refresh</el-button>
    </div>

    <el-alert
      v-if="catalog && catalog.source !== 'catalog'"
      type="info"
      :closable="false"
      show-icon
      class="source-note"
      :title="catalog.source === 'bundled' ? 'Showing the starter set built into SIEMBox' : 'Showing the last catalog read'"
      :description="catalog.error ?? undefined"
    />
    <el-alert v-else-if="catalog?.invalid?.length" type="warning" :closable="false" show-icon class="source-note"
      :title="`${catalog.invalid.length} catalog suggestion(s) could not be read and are not shown`" />

    <el-table :data="shown" v-loading="loading" row-key="id" size="small" max-height="60vh" data-testid="suggestion-table">
      <el-table-column type="expand">
        <template #default="{ row }">
          <div class="details" :data-testid="`suggestion-details-${row.id}`">
            <p>{{ row.description }}</p>
            <p><strong>When to use it.</strong> {{ row.why }}</p>
            <el-alert v-if="row.intrusive" type="error" :closable="false" show-icon title="Intrusive" :description="row.intrusive_note" class="intrusive" />
            <div class="detail-grid">
              <span class="label">Schedule</span>
              <span>{{ describeSuggestionSchedule(row, zone) }}</span>
              <span class="label">Options</span>
              <span><span v-for="line in describeOptions(row, zone)" :key="line" class="line">{{ line }}</span></span>
              <span class="label">You fill in</span>
              <span>
                <span class="line">{{ describeInputs(row) }}</span>
                <span v-for="i in row.inputs.filter((x: SuggestionInput) => x.hint)" :key="i.field" class="line muted">
                  {{ i.label || INPUT_LABELS[i.field] || i.field }}: {{ i.hint }}
                </span>
              </span>
              <span class="label">Load</span>
              <span>{{ row.load }}</span>
              <template v-if="row.tags.length">
                <span class="label">Tags</span>
                <span>{{ row.tags.join(', ') }}</span>
              </template>
            </div>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="Suggestion" min-width="300">
        <template #default="{ row }">
          <div class="name">{{ row.name }}</div>
          <div class="muted summary">{{ row.description }}</div>
        </template>
      </el-table-column>
      <el-table-column label="Type" width="130">
        <template #default="{ row }">
          <el-tag size="small" :type="kindTag(row.kind)">{{ KIND_SHORT[row.kind as SuggestionKind] }}</el-tag>
          <div class="muted">{{ categoryLabel(row.category) }}</div>
        </template>
      </el-table-column>
      <el-table-column label="Schedule" min-width="190">
        <template #default="{ row }">
          <span class="muted">{{ describeSuggestionSchedule(row, zone) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="" width="110">
        <template #default="{ row }">
          <el-tag v-if="row.intrusive" size="small" type="danger" effect="dark" data-testid="intrusive-tag">Intrusive</el-tag>
          <el-tag v-else size="small" :type="loadTag(row.load)" effect="plain">{{ row.load }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column v-if="canAdd" label="" width="90" align="right">
        <template #default="{ row }">
          <el-button size="small" type="primary" :loading="adding === row.id" :data-testid="`add-suggestion-${row.id}`" @click="add(row)">Add</el-button>
        </template>
      </el-table-column>
      <template #empty>{{ loading ? 'Loading…' : 'No suggestions match these filters.' }}</template>
    </el-table>
    <p v-if="!canAdd" class="muted">Operators and admins can add suggestions.</p>
  </el-dialog>
</template>

<script setup lang="ts">
/**
 * "Suggested scans": browse the catalog's suggested scans (filters by type and
 * category, details with why, schedule and intrusiveness) and add one. Used on
 * the Scheduled Scans page (every type) and in the Endpoints page's scan
 * policies card (`kinds` = endpoint policies only). Emits `added` with the
 * API's result ({ kind, scheduled_scan | policy, inputs }); the page opens the
 * created item's edit dialog.
 */
import { computed, ref } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { api } from '@/services/api';
import { browserTimeZone } from '@/utils/scheduleTiming';
import {
  INPUT_LABELS,
  KIND_LABELS,
  KIND_SHORT,
  categoriesOf,
  categoryLabel,
  describeInputs,
  describeOptions,
  describeSuggestionSchedule,
  filterSuggestions,
  loadTag,
  type ScanSuggestion,
  type ScanSuggestionCatalog,
  type SuggestionInput,
  type SuggestionKind,
} from '@/utils/scanSuggestions';

const props = withDefaults(defineProps<{ modelValue: boolean; kinds?: SuggestionKind[] | null; canAdd?: boolean; title?: string }>(), {
  kinds: null,
  canAdd: true,
  title: 'Suggested scans',
});
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; added: [result: any] }>();

const zone = browserTimeZone();
const catalog = ref<ScanSuggestionCatalog | null>(null);
const loading = ref(false);
const adding = ref('');
const kind = ref<SuggestionKind | ''>('');
const category = ref('');
const query = ref('');
const hideIntrusive = ref(false);

const onlyPolicies = computed(() => props.kinds?.length === 1 && props.kinds[0] === 'endpoint_policy');
const inScope = computed(() => filterSuggestions(catalog.value?.suggestions ?? [], { kinds: props.kinds }));
const kindOptions = computed(() => [...new Set(inScope.value.map((s) => s.kind))]);
const categoryOptions = computed(() => categoriesOf(filterSuggestions(inScope.value, { kind: kind.value })));
const shown = computed(() =>
  filterSuggestions(inScope.value, { kind: kind.value, category: category.value, query: query.value }).filter((s) => !hideIntrusive.value || !s.intrusive)
);

function kindTag(k: SuggestionKind): 'primary' | 'danger' | 'warning' | 'success' | 'info' {
  return ({ asset: 'primary', vulnerability: 'danger', container: 'warning', log_discovery: 'success', endpoint_policy: 'info' } as const)[k];
}

async function load(refresh: boolean) {
  if (catalog.value && !refresh) return;
  loading.value = true;
  try {
    catalog.value = (await api.getScanSuggestions(refresh)).data;
  } catch {
    ElMessage.error('Failed to load suggested scans');
  } finally {
    loading.value = false;
  }
}

async function add(s: ScanSuggestion) {
  if (s.intrusive) {
    try {
      await ElMessageBox.confirm(`${s.intrusive_note ?? ''}\n\nIt is added disabled; nothing runs until you enable it.`, `"${s.name}" is intrusive`, {
        confirmButtonText: 'Add it',
        cancelButtonText: 'Cancel',
        type: 'warning',
        customStyle: { whiteSpace: 'pre-line' },
      });
    } catch {
      return;
    }
  }
  adding.value = s.id;
  try {
    const { data } = await api.addScanSuggestion(s.id, zone);
    ElMessage.success(
      data.policy
        ? `Added the policy "${data.policy.name}"; assign it to endpoints to start it`
        : `Added "${s.name}" (disabled)${describeInputs(s).startsWith('Nothing') ? '' : '; fill in the targets and enable it'}`
    );
    emit('added', data);
    emit('update:modelValue', false);
  } catch (e) {
    const d = (e as { response?: { data?: { message?: string; error?: string } } })?.response?.data;
    ElMessage.error(d?.message || d?.error || 'Failed to add the suggestion');
  } finally {
    adding.value = '';
  }
}
</script>

<style scoped>
.intro {
  margin: 0 0 12px;
  line-height: 1.5;
}
.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  margin-bottom: 12px;
}
.source-note {
  margin-bottom: 10px;
}
.muted {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.name {
  font-weight: 600;
}
.summary {
  line-height: 1.4;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.details {
  padding: 4px 24px 8px 48px;
  line-height: 1.5;
}
.details p {
  margin: 0 0 8px;
}
.intrusive {
  margin-bottom: 8px;
}
.detail-grid {
  display: grid;
  grid-template-columns: 110px 1fr;
  gap: 4px 12px;
}
.label {
  color: var(--el-text-color-secondary);
}
.line {
  display: block;
}
</style>
