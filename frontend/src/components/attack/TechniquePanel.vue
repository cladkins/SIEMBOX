<template>
  <el-drawer
    :model-value="!!technique"
    :size="drawerSize"
    :title="technique ? `${technique.id} ${technique.name}` : ''"
    class="technique-panel"
    data-testid="technique-panel"
    @update:model-value="(open: boolean) => !open && emit('close')"
  >
    <div v-if="technique" class="panel-body">
      <div class="panel-head">
        <LevelBadge :level="technique.level" :proven-by="technique.proven_by" />
        <LevelBadge v-if="technique.excluded" :level="technique.level" excluded />
        <a :href="attackTechniqueUrl(technique.id)" target="_blank" rel="noopener" class="mitre-link">
          {{ technique.id }} on attack.mitre.org ↗
        </a>
      </div>
      <p v-if="parent" class="panel-sub">
        Sub-technique of
        <el-link type="primary" @click="emit('select', parent.id)">{{ parent.id }} {{ parent.name }}</el-link>
      </p>
      <p class="panel-sub">
        Tactics: {{ tacticNames }} · Platforms: {{ technique.platforms.join(', ') || '–' }}
      </p>
      <p class="panel-sub">{{ LEVEL_INFO[technique.level].description }}</p>

      <!-- Sub-techniques: counts, and each one's level (click to open it). -->
      <section v-if="technique.subtechniques && technique.subtechniques.ids.length" class="panel-section">
        <h4>
          Sub-techniques
          <span class="panel-count">
            {{ technique.subtechniques.covered }} of {{ technique.subtechniques.total }} covered<template
              v-if="technique.subtechniques.excluded"
            >, {{ technique.subtechniques.excluded }} not applicable</template>
          </span>
        </h4>
        <ul class="sub-list">
          <li v-for="s in subs" :key="s.id">
            <el-link type="primary" @click="emit('select', s.id)">{{ s.id }} {{ s.name }}</el-link>
            <LevelBadge :level="s.level" :excluded="s.excluded" :tooltip="false" />
          </li>
        </ul>
      </section>

      <!-- Rules tagged with it (a parent includes its sub-techniques' rules), with why each has its level. -->
      <section class="panel-section">
        <h4>Rules <span class="panel-count">{{ technique.rules.length }}</span></h4>
        <p v-if="!technique.rules.length" class="panel-empty">
          No rule is tagged with {{ technique.id }}<template v-if="technique.subtechniques"> or its sub-techniques</template>.
          <template v-if="canEdit">Tag one in the rule editor (ATT&amp;CK techniques), or install one below.</template>
        </p>
        <div v-for="r in technique.rules" :key="`${r.id}-${r.technique_id}`" class="rule-row" data-testid="panel-rule">
          <div class="rule-row-head">
            <router-link :to="{ path: '/rules', query: { rule: String(r.id) } }">{{ r.name }}</router-link>
            <LevelBadge :level="r.level" :proven-by="r.proven_by" :tooltip="false" />
            <span v-if="r.technique_id !== technique.id" class="panel-count">via {{ r.technique_id }}</span>
          </div>
          <div class="rule-reason" data-testid="panel-rule-reason">{{ r.reason }}</div>
        </div>
      </section>

      <!-- Not-installed catalog rules tagged with it. -->
      <section class="panel-section">
        <h4>From the catalog</h4>
        <p v-if="catalogLoading" class="panel-empty">Loading the detection catalog…</p>
        <p v-else-if="catalogError" class="panel-empty">{{ catalogError }}</p>
        <p v-else-if="!catalogSuggestions.length" class="panel-empty">
          No catalog rule that you have not installed is tagged with {{ technique.id }}.
        </p>
        <div v-for="c in catalogSuggestions" :key="c.name" class="rule-row" data-testid="panel-catalog-rule">
          <div class="rule-row-head">
            <strong>{{ c.name }}</strong>
            <el-tag v-if="c.severity" size="small" effect="plain">{{ c.severity }}</el-tag>
            <el-tag v-if="fillsGap" size="small" type="success" data-testid="fills-gap">Fills a gap</el-tag>
            <el-button
              v-if="canEdit"
              size="small"
              type="primary"
              :loading="installing === c.name"
              @click="install(c.name)"
            >Install</el-button>
          </div>
          <div v-if="c.description" class="rule-reason">{{ c.description }}</div>
        </div>
      </section>

      <!-- Recent alerts with this technique. -->
      <section class="panel-section">
        <h4>
          Recent alerts
          <span class="panel-count">{{ technique.alerts_30d }} in 30 days</span>
        </h4>
        <p v-if="alertsLoading" class="panel-empty">Loading…</p>
        <p v-else-if="!alerts.length" class="panel-empty">No alert carries {{ technique.id }}.</p>
        <ul v-else class="alert-list">
          <li v-for="a in alerts" :key="a.id">
            <SeverityBadge :severity="a.severity" size="small" effect="plain" />
            <router-link :to="alertRefPath(a.id)" class="alert-ref-link">{{ formatAlertRef(a.id) }}</router-link>
            <router-link :to="alertRefPath(a.id)">{{ a.title }}</router-link>
            <span class="panel-count">{{ formatDate(a.created_at) }}</span>
          </li>
        </ul>
        <router-link :to="{ path: '/alerts', query: { technique: technique.id } }" class="all-alerts" data-testid="panel-alerts-link">
          All alerts with {{ technique.id }} →
        </router-link>
      </section>

      <!-- Not applicable: analyst and up change it; everyone sees it. -->
      <section class="panel-section">
        <h4>Not applicable</h4>
        <el-alert v-if="exclusionError" type="error" :title="exclusionError" :closable="false" show-icon class="panel-alert" />
        <template v-if="technique.exclusion">
          <p class="panel-sub" data-testid="exclusion-note">
            <template v-if="technique.exclusion.inherited_from">
              Not applicable with its parent {{ technique.exclusion.inherited_from }}.
            </template>
            <template v-else>Marked not applicable</template>
            <template v-if="technique.exclusion.created_by"> by {{ technique.exclusion.created_by }}</template>
            <template v-if="technique.exclusion.created_at"> on {{ formatDate(technique.exclusion.created_at) }}</template>.
            <span v-if="technique.exclusion.note" class="exclusion-note">“{{ technique.exclusion.note }}”</span>
          </p>
          <el-button
            v-if="canEdit && !technique.exclusion.inherited_from"
            size="small"
            :loading="savingExclusion"
            data-testid="remove-exclusion"
            @click="removeExclusion"
          >Remove</el-button>
        </template>
        <template v-else-if="canEdit">
          <p class="panel-sub">Leaves it out of the percentages; it keeps its level.</p>
          <el-input
            v-model="note"
            type="textarea"
            :rows="2"
            maxlength="1000"
            show-word-limit
            placeholder="Why it does not apply (optional), e.g. no web servers on this network"
            data-testid="exclusion-note-input"
          />
          <el-button
            size="small"
            type="warning"
            :loading="savingExclusion"
            class="exclude-button"
            data-testid="mark-not-applicable"
            @click="markNotApplicable"
          >Mark not applicable</el-button>
        </template>
        <p v-else class="panel-empty">Applies. Analysts can mark a technique not applicable.</p>
      </section>
    </div>
  </el-drawer>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { alertRefPath, formatAlertRef } from '@/utils/alertRef';
import { format } from 'date-fns';
import { ElMessage } from 'element-plus';
import { api } from '@/services/api';
import LevelBadge from '@/components/attack/LevelBadge.vue';
import SeverityBadge from '@/components/SeverityBadge.vue';
import {
  LEVEL_INFO,
  attackTechniqueUrl,
  techniqueIdsFromTags,
  techniqueMatches,
  type CoverageTactic,
  type CoverageTechnique,
} from '@/utils/attack';

const props = defineProps<{
  technique: CoverageTechnique | null;
  byId: Map<string, CoverageTechnique>;
  tactics: CoverageTactic[];
  canEdit: boolean;
  /** The detection catalog listing (GET /api/rules/catalog), loaded by the page. */
  catalog: any[];
  catalogLoading: boolean;
  catalogError: string;
}>();
const emit = defineEmits<{ close: []; select: [id: string]; changed: []; installed: [] }>();

const drawerSize = computed(() => (typeof window !== 'undefined' && window.innerWidth < 640 ? '100%' : '520px'));

const parent = computed(() =>
  props.technique?.parent_id ? props.byId.get(props.technique.parent_id) ?? null : null
);
const subs = computed(() =>
  (props.technique?.subtechniques?.ids ?? []).map((id) => props.byId.get(id)).filter((s): s is CoverageTechnique => !!s)
);
const tacticNames = computed(() => {
  const names = new Map(props.tactics.map((t) => [t.shortname, t.name]));
  return (props.technique?.tactics ?? []).map((t) => names.get(t) ?? t).join(', ') || '–';
});

/** Not-installed, valid catalog rules tagged with this technique (a parent: or a sub-technique of it). */
const catalogSuggestions = computed(() => {
  const t = props.technique;
  if (!t) return [];
  return props.catalog.filter(
    (c) => c.valid !== false && !c.installed && techniqueIdsFromTags(c.tags).some((id) => techniqueMatches(id, t.id))
  );
});
const fillsGap = computed(() => !!props.technique && props.technique.level === 'none' && !props.technique.excluded);

const alerts = ref<any[]>([]);
const alertsLoading = ref(false);
const note = ref('');
const savingExclusion = ref(false);
const exclusionError = ref('');
const installing = ref('');

async function loadAlerts(id: string) {
  alertsLoading.value = true;
  try {
    const { data } = await api.getAlerts({ technique: id, limit: 5 });
    if (props.technique?.id === id) alerts.value = data.alerts ?? [];
  } catch {
    alerts.value = [];
  } finally {
    alertsLoading.value = false;
  }
}

watch(
  () => props.technique?.id,
  (id) => {
    note.value = '';
    exclusionError.value = '';
    alerts.value = [];
    if (id) void loadAlerts(id);
  },
  { immediate: true }
);

async function markNotApplicable() {
  if (!props.technique) return;
  savingExclusion.value = true;
  exclusionError.value = '';
  try {
    await api.setAttackExclusion(props.technique.id, note.value.trim());
    ElMessage.success(`${props.technique.id} marked not applicable`);
    emit('changed');
  } catch (error: any) {
    exclusionError.value = error?.response?.data?.message || error?.response?.data?.error || 'Could not save the exclusion';
  } finally {
    savingExclusion.value = false;
  }
}

async function removeExclusion() {
  if (!props.technique) return;
  savingExclusion.value = true;
  exclusionError.value = '';
  try {
    await api.deleteAttackExclusion(props.technique.id);
    ElMessage.success(`${props.technique.id} applies again`);
    emit('changed');
  } catch (error: any) {
    exclusionError.value = error?.response?.data?.message || error?.response?.data?.error || 'Could not remove the exclusion';
  } finally {
    savingExclusion.value = false;
  }
}

async function install(name: string) {
  installing.value = name;
  try {
    await api.installCatalogRule(name);
    ElMessage.success(`Installed "${name}"`);
    emit('installed');
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.message || `Failed to install "${name}"`);
  } finally {
    installing.value = '';
  }
}

function formatDate(d: string) {
  try {
    return format(new Date(d), 'MMM dd, yyyy HH:mm');
  } catch {
    return d;
  }
}
</script>

<style scoped>
.alert-ref-link {
  font-family: var(--el-font-family-mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
  font-size: 12px;
  white-space: nowrap;
}
.panel-body {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.panel-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.mitre-link {
  font-size: 13px;
  color: var(--el-color-primary);
}
.panel-sub {
  margin: 4px 0;
  font-size: 13px;
  color: var(--el-text-color-regular);
}
.panel-section {
  margin-top: 14px;
  padding-top: 10px;
  border-top: 1px solid var(--el-border-color-lighter);
}
.panel-section h4 {
  margin: 0 0 8px;
  font-size: 14px;
  display: flex;
  align-items: baseline;
  gap: 8px;
}
.panel-count {
  font-size: 12px;
  font-weight: normal;
  color: var(--el-text-color-secondary);
}
.panel-empty {
  margin: 0;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
.sub-list,
.alert-list {
  list-style: none;
  margin: 0;
  padding: 0;
}
.sub-list li,
.alert-list li {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 3px 0;
  font-size: 13px;
}
.rule-row {
  padding: 6px 0;
}
.rule-row + .rule-row {
  border-top: 1px dashed var(--el-border-color-lighter);
}
.rule-row-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  font-size: 13px;
}
.rule-reason {
  margin-top: 3px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  word-break: break-word;
}
.all-alerts {
  display: inline-block;
  margin-top: 6px;
  font-size: 13px;
}
.exclusion-note {
  font-style: italic;
}
.exclude-button {
  margin-top: 8px;
}
.panel-alert {
  margin-bottom: 8px;
}
</style>
