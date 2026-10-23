<template>
  <el-dialog
    :model-value="modelValue"
    title="SigmaHQ library"
    width="1100px"
    data-testid="sigma-library-dialog"
    @update:model-value="(v: boolean) => emit('update:modelValue', v)"
    @open="load()"
  >
    <el-alert :type="status.type" :closable="false" :title="status.text" class="sigma-status" data-testid="sigma-status" />

    <div class="sigma-toolbar">
      <el-radio-group v-model="view" size="small" @change="reload">
        <el-radio-button value="compatible">Compatible ({{ counts.compatible }})</el-radio-button>
        <el-radio-button value="convertible">All convertible ({{ counts.convertible }})</el-radio-button>
      </el-radio-group>
      <el-input v-model="search" placeholder="Search title, id, tag, author…" clearable size="small" style="width: 220px" />
      <el-select v-model="product" placeholder="Product" clearable size="small" style="width: 130px" @change="reload">
        <el-option v-for="f in facets.products" :key="f.value" :label="`${f.value} (${f.count})`" :value="f.value" />
      </el-select>
      <el-select v-model="category" placeholder="Category" clearable size="small" style="width: 150px" @change="reload">
        <el-option v-for="f in facets.categories" :key="f.value" :label="`${f.value} (${f.count})`" :value="f.value" />
      </el-select>
      <el-select v-model="level" placeholder="Level" clearable size="small" style="width: 110px" @change="reload">
        <el-option v-for="f in facets.levels" :key="f.value" :label="`${f.value} (${f.count})`" :value="f.value" />
      </el-select>
      <el-select v-model="ruleStatus" placeholder="Status" clearable size="small" style="width: 110px" @change="reload">
        <el-option v-for="f in facets.statuses" :key="f.value" :label="`${f.value} (${f.count})`" :value="f.value" />
      </el-select>
      <TacticSelect v-model="tactic" size="small" placeholder="Tactic" style="width: 150px" />
      <TechniqueSelect v-model="technique" size="small" placeholder="Technique" style="width: 180px" />
      <el-select v-model="addedFilter" placeholder="Added or not" size="small" style="width: 150px" @change="reload">
        <el-option label="Not added" value="not_added" />
        <el-option label="Added" value="added" />
        <el-option :label="`Update available (${counts.updates})`" value="updates" />
      </el-select>
      <div style="flex: 1" />
      <el-button
        v-if="canEdit && view === 'compatible'"
        size="small"
        type="primary"
        :loading="bulkAdding"
        :disabled="loading || counts.compatible === 0"
        data-testid="sigma-add-all"
        @click="addAllCompatible"
      >
        Add all compatible
      </el-button>
      <el-button v-if="canEdit" size="small" :loading="refreshing" data-testid="sigma-refresh" @click="refresh">
        <el-icon><Refresh /></el-icon> Refresh
      </el-button>
    </div>

    <div class="sigma-source">
      Rules by their authors from <a href="https://github.com/SigmaHQ/sigma" target="_blank" rel="noopener">SigmaHQ</a>
      ({{ source.asset || 'sigma_core+.zip' }}), under the
      <a href="https://github.com/SigmaHQ/Detection-Rule-License" target="_blank" rel="noopener">Detection Rule License 1.1</a>.
      Compatible: your recent logs carry every field a rule needs, from a parser that fits its log source.
      <span v-if="compatInfo">Checked {{ compatInfo.sampled_parsers }} parser(s) with recent logs.</span>
      Added rules start disabled.
    </div>

    <el-alert v-if="error" type="error" :closable="false" :title="error" style="margin-bottom: 10px" />
    <RegexProblemAlert :problem="problem" />

    <el-table :data="rows" v-loading="loading" stripe max-height="480" data-testid="sigma-table" :empty-text="emptyText">
      <el-table-column label="Rule" min-width="300">
        <template #default="{ row }">
          <a :href="row.url" target="_blank" rel="noopener" class="sigma-title">{{ row.title }} ↗</a>
          <el-tag v-if="row.parts > 1" size="small" type="info" effect="plain" class="sigma-chip">{{ row.parts }} rules</el-tag>
          <el-tag v-if="row.compatibility?.keyword" size="small" type="info" effect="plain" class="sigma-chip">keyword search</el-tag>
          <div class="sigma-sub">
            {{ row.author || 'Unknown author' }} · {{ row.status }}<span v-if="row.modified || row.date"> · {{ row.modified || row.date }}</span>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="Level" width="100">
        <template #default="{ row }">
          <el-tag v-if="row.level" :type="levelType(row.level)" size="small">{{ row.level }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="Log source" width="160">
        <template #default="{ row }">{{ logsourceLabel(row.logsource) }}</template>
      </el-table-column>
      <el-table-column label="ATT&CK" width="170">
        <template #default="{ row }">
          <TechniqueChips :tags="row.tags" />
        </template>
      </el-table-column>
      <el-table-column label="Your logs" min-width="190">
        <template #default="{ row }">
          <el-tooltip :content="compatibilityText(row).detail" placement="top">
            <el-tag :type="compatibilityText(row).type" size="small" effect="plain" class="sigma-compat">{{ compatibilityText(row).label }}</el-tag>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column label="" width="170" fixed="right">
        <template #default="{ row }">
          <template v-if="sigmaAction(row) === 'update'">
            <el-button v-if="canEdit" size="small" type="warning" :loading="busy === row.sigma_id" @click="update(row)">Update</el-button>
            <el-tag v-else type="warning" size="small">Update available</el-tag>
          </template>
          <template v-else-if="sigmaAction(row) === 'added'">
            <el-tag type="success" size="small">Added{{ row.installed.enabled === 0 ? ' (disabled)' : '' }}</el-tag>
            <el-button
              v-if="canEdit && row.installed.enabled === 0"
              size="small"
              link
              type="primary"
              :loading="busy === row.sigma_id"
              data-testid="sigma-enable"
              @click="enable(row)"
            >Enable</el-button>
          </template>
          <el-tooltip v-else-if="sigmaAction(row) === 'blocked'" :content="row.not_installable_reason || 'Cannot be added'" placement="top">
            <el-button size="small" disabled>Cannot add</el-button>
          </el-tooltip>
          <el-button v-else-if="canEdit" size="small" type="primary" :loading="busy === row.sigma_id" data-testid="sigma-add" @click="add(row)">
            Add
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <div class="sigma-pager">
      <el-pagination
        v-model:current-page="page"
        :page-size="pageSize"
        :total="total"
        layout="total, prev, pager, next"
        small
        @current-change="load()"
      />
    </div>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Refresh } from '@element-plus/icons-vue';
import { api } from '@/services/api';
import RegexProblemAlert from '@/components/RegexProblemAlert.vue';
import TechniqueChips from '@/components/attack/TechniqueChips.vue';
import TechniqueSelect from '@/components/attack/TechniqueSelect.vue';
import TacticSelect from '@/components/attack/TacticSelect.vue';
import { batchProblem, problemFromError, type InlineProblem } from '@/utils/regexSafety';
import {
  compatibilityText,
  levelType,
  libraryStatus,
  logsourceLabel,
  sigmaAction,
  type SigmaLibraryRow,
  type SigmaState,
} from '@/utils/sigmaLibrary';

/**
 * Detection Rules > SigmaHQ: the cached SigmaHQ release (GET /api/sigma/library),
 * the rules your logs can feed first, one-click add (disabled, for review) and
 * update. Viewers browse; adding, updating and Refresh are analyst and up.
 */
defineProps<{ modelValue: boolean; canEdit: boolean }>();
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; changed: [] }>();

type Facet = { value: string; count: number };
const rows = ref<Array<SigmaLibraryRow & Record<string, any>>>([]);
const state = ref<SigmaState | null>(null);
const source = ref<{ asset?: string }>({});
const counts = ref({ compatible: 0, convertible: 0, updates: 0, rules: 0 });
const facets = ref<{ products: Facet[]; categories: Facet[]; levels: Facet[]; statuses: Facet[] }>({
  products: [],
  categories: [],
  levels: [],
  statuses: [],
});
const compatInfo = ref<{ sampled_parsers: number } | null>(null);
const total = ref(0);
const page = ref(1);
const pageSize = 50;
const loading = ref(false);
const refreshing = ref(false);
const bulkAdding = ref(false);
const busy = ref<string | null>(null);
const error = ref('');
const problem = ref<InlineProblem | null>(null);

const view = ref<'compatible' | 'convertible'>('compatible');
const search = ref('');
const product = ref('');
const category = ref('');
const level = ref('');
const ruleStatus = ref('');
const tactic = ref<string | null>(null);
const technique = ref<string | null>(null);
const addedFilter = ref('');

const status = computed(() => libraryStatus(state.value));
const emptyText = computed(() =>
  !state.value?.release_tag
    ? 'No SigmaHQ release cached yet'
    : view.value === 'compatible'
      ? 'No SigmaHQ rule matches the fields your parsers produce yet: try "All convertible"'
      : 'No rules match these filters'
);

let searchTimer: ReturnType<typeof setTimeout> | null = null;
watch(search, () => {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(reload, 300);
});
watch([tactic, technique], reload);

function reload() {
  page.value = 1;
  void load();
}

async function load() {
  loading.value = true;
  error.value = '';
  try {
    const { data } = await api.getSigmaLibrary({
      view: view.value,
      q: search.value || undefined,
      product: product.value || undefined,
      category: category.value || undefined,
      level: level.value || undefined,
      status: ruleStatus.value || undefined,
      tactic: tactic.value || undefined,
      technique: technique.value || undefined,
      installed: addedFilter.value || undefined,
      page: page.value,
      page_size: pageSize,
    });
    rows.value = data.rules;
    state.value = data.state;
    source.value = data.source ?? {};
    counts.value = data.counts;
    facets.value = data.facets;
    compatInfo.value = data.compatibility;
    total.value = data.total;
  } catch (e: any) {
    error.value = e?.response?.data?.message || 'Failed to load the SigmaHQ library';
  } finally {
    loading.value = false;
  }
}

async function refresh() {
  refreshing.value = true;
  error.value = '';
  try {
    const { data } = await api.refreshSigmaLibrary();
    ElMessage.success(data.status === 'updated' ? `Stored SigmaHQ ${data.release_tag}` : `SigmaHQ ${data.release_tag} is already the latest release`);
  } catch (e: any) {
    // The cached copy stays; the status line says why.
    error.value = e?.response?.data?.message || 'Could not reach SigmaHQ';
  } finally {
    refreshing.value = false;
    await load();
  }
}

async function add(row: SigmaLibraryRow) {
  busy.value = row.sigma_id;
  problem.value = null;
  try {
    const { data } = await api.installSigmaRule(row.sigma_id);
    const n = data.rules.length;
    ElMessage.success(`Added "${row.title}"${n > 1 ? ` as ${n} rules` : ''}, disabled: enable it to start alerting`);
    emit('changed');
    await load();
  } catch (e) {
    problem.value = problemFromError(e, `"${row.title}" was not added`);
  } finally {
    busy.value = null;
  }
}

async function update(row: SigmaLibraryRow) {
  busy.value = row.sigma_id;
  problem.value = null;
  try {
    await api.updateSigmaRule(row.sigma_id);
    ElMessage.success(`Updated "${row.title}" (your enabled choice is kept)`);
    emit('changed');
    await load();
  } catch (e) {
    problem.value = problemFromError(e, `"${row.title}" was not updated`);
  } finally {
    busy.value = null;
  }
}

async function enable(row: SigmaLibraryRow) {
  if (!row.installed) return;
  busy.value = row.sigma_id;
  try {
    for (const id of row.installed.rule_ids) await api.updateRule(id, { enabled: true });
    ElMessage.success(`Enabled "${row.title}"`);
    emit('changed');
    await load();
  } catch {
    ElMessage.error('Failed to enable the rule');
  } finally {
    busy.value = null;
  }
}

async function addAllCompatible() {
  try {
    await ElMessageBox.confirm(
      `Add every compatible SigmaHQ rule not added yet (up to ${counts.value.compatible})? They are added disabled, for you to review and enable.`,
      'Add all compatible',
      { confirmButtonText: 'Add all', cancelButtonText: 'Cancel', type: 'info' }
    );
  } catch {
    return;
  }
  bulkAdding.value = true;
  problem.value = null;
  try {
    const { data } = await api.installSigmaBulk({ all_compatible: true });
    ElMessage.success(`Added ${data.added} SigmaHQ rule(s), disabled${data.failed.length ? `; ${data.failed.length} refused` : ''}`);
    problem.value = batchProblem(`${data.failed.length} rule(s) were not added`, {
      failed: data.failed.map((f: { sigma_id: string; reason: string }) => ({ name: f.sigma_id, reason: f.reason })),
    });
    emit('changed');
    await load();
  } catch (e) {
    problem.value = problemFromError(e, 'The bulk add failed');
  } finally {
    bulkAdding.value = false;
  }
}

defineExpose({ load });
</script>

<style scoped>
.sigma-status {
  margin-bottom: 10px;
}
.sigma-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  margin-bottom: 8px;
}
.sigma-source {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-bottom: 10px;
}
.sigma-title {
  font-weight: 600;
  color: var(--el-text-color-primary);
  text-decoration: none;
}
.sigma-title:hover {
  text-decoration: underline;
}
.sigma-chip {
  margin-left: 6px;
}
.sigma-sub {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.sigma-compat {
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
}
.sigma-pager {
  display: flex;
  justify-content: flex-end;
  margin-top: 10px;
}
</style>
