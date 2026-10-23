<template>
  <div class="content-packs">
    <el-card>
      <template #header>
        <div class="card-header">
          <div>
            <span>Content Packs</span>
            <div class="subtitle">
              One-click bundles of parsers, detections and SigmaHQ rules for a technology, with a setup guide.
              Packs come from the catalog; installing one pulls each item from the catalog (Sigma rules from the
              SigmaHQ library) and turns its detections on. When the catalog adds to a pack you installed, the pack
              shows what's new.<template v-if="!authStore.isAdmin"> An admin installs packs.</template>
            </div>
          </div>
          <el-button size="small" :loading="loading" @click="load(true)">
            <el-icon><Refresh /></el-icon> Refresh
          </el-button>
        </div>
      </template>

      <el-alert
        v-if="notice"
        :type="notice.type"
        :closable="false"
        show-icon
        :title="notice.title"
        :description="notice.text"
        class="page-alert"
      />
      <el-alert
        v-if="catalogUnavailable"
        type="warning"
        :closable="false"
        show-icon
        title="Detection catalog unavailable"
        description="Detection counts can't be shown right now (the catalog repo couldn't be reached). Parser counts are still accurate, and installing will retry the catalog."
        class="page-alert"
      />
      <el-alert
        v-if="sigmaPending"
        type="info"
        :closable="false"
        show-icon
        title="SigmaHQ library not loaded"
        class="page-alert"
      >
        <template #default>
          Packs that include SigmaHQ rules show them as pending until the library is loaded: refresh it on
          <router-link to="/rules">Detection Rules &gt; SigmaHQ</router-link>. Everything else in a pack installs now.
        </template>
      </el-alert>

      <div v-loading="loading" class="pack-grid">
        <el-card v-for="pack in packs" :key="pack.id" shadow="hover" class="pack-card" :data-pack="pack.id">
          <div class="pack-head">
            <el-icon :size="22" class="pack-icon"><component :is="iconFor(pack.icon)" /></el-icon>
            <div class="pack-title">{{ pack.name }}</div>
            <el-tag v-if="pack.whats_new" type="danger" size="small" effect="dark" class="whats-new-badge">
              What's new: {{ pack.whats_new.count }}
            </el-tag>
            <el-tag :type="statusType(pack.status)" size="small" effect="light">
              {{ statusLabel(pack.status) }}
            </el-tag>
          </div>

          <p class="pack-desc">{{ pack.description }}</p>

          <div class="pack-counts">
            <span>{{ countsLine(pack) }}</span>
            <span class="pack-version">v{{ pack.version }}</span>
          </div>
          <div class="pack-installed-counts">
            <span><strong>{{ pack.parserInstalled }}/{{ pack.parserTotal }}</strong> parsers</span>
            <span v-if="!pack.catalogUnavailable">
              <strong>{{ pack.detectionInstalled }}/{{ pack.detectionTotal }}</strong> detections
            </span>
            <span v-if="pack.sigmaTotal"><strong>{{ pack.sigmaInstalled }}/{{ pack.sigmaTotal }}</strong> Sigma</span>
          </div>
          <div v-if="pack.install" class="pack-record">
            Installed v{{ pack.install.version }} {{ formatWhen(pack.install.installed_at) }}<template
              v-if="pack.install.installed_by_username"
            > by {{ pack.install.installed_by_username }}</template>
          </div>

          <div v-if="pack.whats_new" class="whats-new">
            <div class="whats-new-title">
              What's new since you installed (v{{ pack.whats_new.from_version }} → v{{ pack.whats_new.to_version }}):
              {{ whatsNewSummary(pack.whats_new) }}
            </div>
            <ul class="new-items">
              <li v-for="item in newItems(pack)" :key="item.key"><span class="kind">{{ item.kind }}</span>{{ item.name }}</li>
            </ul>
            <el-button
              v-if="newItemsAll(pack).length > NEW_PREVIEW"
              link
              size="small"
              class="new-more"
              @click="toggleNew(pack.id)"
            >
              {{ expandedNew.has(pack.id) ? 'Show fewer' : `Show all ${newItemsAll(pack).length}` }}
            </el-button>
            <el-button
              v-if="authStore.isAdmin"
              type="danger"
              plain
              size="small"
              :loading="installing === pack.id + ':new'"
              :disabled="!!installing"
              @click="install(pack, true)"
            >
              Install what's new
            </el-button>
          </div>

          <el-collapse class="pack-setup">
            <el-collapse-item :title="`What's included (${installedCount(pack)}/${totalCount(pack)} installed)`">
              <div class="pack-items-group">Parsers</div>
              <ul class="pack-items">
                <li v-for="p in pack.parsers" :key="'p' + p.name" :class="{ missing: !p.inCatalog }">
                  <span class="item-name">{{ p.name }}</span>
                  <el-tag v-if="p.new" size="small" type="danger" effect="plain">new</el-tag>
                  <el-tooltip :disabled="!parserBadge(p).detail" :content="parserBadge(p).detail" placement="top">
                    <el-tag size="small" :type="parserBadge(p).type" effect="light">{{ parserBadge(p).label }}</el-tag>
                  </el-tooltip>
                </li>
              </ul>
              <template v-if="!pack.catalogUnavailable">
                <div class="pack-items-group">Detections</div>
                <ul v-if="pack.detections.length" class="pack-items">
                  <li v-for="d in pack.detections" :key="'d' + d.name" :class="{ missing: !d.inCatalog }">
                    <span class="item-name">{{ d.name }}</span>
                    <el-tag v-if="d.new" size="small" type="danger" effect="plain">new</el-tag>
                    <el-tooltip :disabled="!detectionBadge(d).detail" :content="detectionBadge(d).detail" placement="top">
                      <el-tag size="small" :type="detectionBadge(d).type" effect="light">{{ detectionBadge(d).label }}</el-tag>
                    </el-tooltip>
                  </li>
                </ul>
                <p v-else class="item-note">No detections in this pack yet.</p>
              </template>
              <template v-if="pack.sigma.length">
                <div class="pack-items-group">SigmaHQ rules</div>
                <ul class="pack-items">
                  <li v-for="s in pack.sigma" :key="'s' + s.id">
                    <span class="item-name">{{ s.title }}</span>
                    <el-tag v-if="s.new" size="small" type="danger" effect="plain">new</el-tag>
                    <el-tooltip :disabled="!sigmaBadge(s).detail" :content="sigmaBadge(s).detail" placement="top">
                      <el-tag size="small" :type="sigmaBadge(s).type" effect="light">{{ sigmaBadge(s).label }}</el-tag>
                    </el-tooltip>
                    <span v-if="sigmaCompatNote(s)" class="item-note">{{ sigmaCompatNote(s) }}</span>
                  </li>
                </ul>
                <p class="item-note">SigmaHQ rules: Detection Rule License 1.1, attribution on each rule.</p>
              </template>
            </el-collapse-item>
          </el-collapse>

          <div class="pack-actions">
            <el-button size="small" :type="authStore.isAdmin ? 'primary' : 'default'" @click="openGuide(pack)">
              {{ authStore.isAdmin ? `Setup guide & ${installLabel(pack).toLowerCase()}` : 'Setup guide' }}
            </el-button>
          </div>
        </el-card>
      </div>
    </el-card>

    <el-dialog
      v-model="guideOpen"
      :title="guidePack ? `${guidePack.name}: setup guide` : 'Setup guide'"
      width="760px"
      class="pack-guide-dialog"
      destroy-on-close
    >
      <template v-if="guidePack">
        <p class="pack-desc">{{ guidePack.description }}</p>
        <p class="guide-summary">
          Installs {{ countsLine(guidePack) }} (v{{ guidePack.version }}). Detections and Sigma rules are turned on;
          a Sigma rule you already added from the library keeps your on/off choice.
        </p>
        <ol class="guide-steps">
          <li v-for="(step, i) in guidePack.setup" :key="i" class="guide-step">
            <div class="guide-step-title">{{ step.title }}</div>
            <!-- Catalog markdown: raw HTML escaped, unsafe links dropped, then DOMPurify (utils/markdown.ts). -->
            <!-- eslint-disable-next-line vue/no-v-html -->
            <div class="guide-step-text" v-html="renderGuideMarkdown(step.text)" />
            <pre v-if="step.code" class="guide-code"><code>{{ step.code }}</code></pre>
          </li>
        </ol>
      </template>
      <template #footer>
        <el-button @click="guideOpen = false">Close</el-button>
        <el-button
          v-if="authStore.isAdmin && guidePack"
          type="primary"
          :loading="installing === guidePack.id"
          :disabled="!!installing"
          @click="install(guidePack, false)"
        >
          {{ installLabel(guidePack) }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, h } from 'vue';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import { ElMessage, ElMessageBox } from 'element-plus';
import {
  Refresh,
  Key,
  Connection,
  VideoPlay,
  Files,
  Share,
  House,
  Monitor,
  DataLine,
  Box,
  Lock,
  Cpu,
  Cloudy,
  Message,
} from '@element-plus/icons-vue';
import { renderGuideMarkdown } from '@/utils/markdown';
import {
  countsLine,
  detectionBadge,
  installLabel,
  parserBadge,
  sigmaBadge,
  sigmaCompatNote,
  sourceNotice,
  statusLabel,
  statusType,
  whatsNewSummary,
  type PackStatus,
  type PacksOverview,
} from '@/utils/contentPacks';

// Map the pack icon name -> component (the catalog's PACK_ICONS; fallback Box).
const ICON_MAP: Record<string, any> = { Key, Connection, VideoPlay, Files, Share, House, Monitor, DataLine, Box, Lock, Cpu, Cloudy, Message };
function iconFor(name: string) {
  return ICON_MAP[name] || Box;
}

const authStore = useAuthStore();
const overview = ref<PacksOverview | null>(null);
const packs = computed<PackStatus[]>(() => overview.value?.packs ?? []);
const loading = ref(false);
const installing = ref('');
const guideOpen = ref(false);
const guidePack = ref<PackStatus | null>(null);

const notice = computed(() => sourceNotice(overview.value?.source));
const catalogUnavailable = computed(() => packs.value.some((p) => p.catalogUnavailable));
const sigmaPending = computed(
  () => !!overview.value && !overview.value.sigma_library.loaded && packs.value.some((p) => p.sigma.some((s) => s.state === 'pending'))
);

// What's new: the first few items, all on request.
const NEW_PREVIEW = 6;
const expandedNew = ref(new Set<string>());
function newItemsAll(p: PackStatus) {
  const w = p.whats_new;
  if (!w) return [];
  return [
    ...w.parsers.map((n) => ({ key: `p:${n}`, kind: 'parser', name: n })),
    ...w.detections.map((n) => ({ key: `d:${n}`, kind: 'detection', name: n })),
    ...w.sigma.map((x) => ({ key: `s:${x.id}`, kind: 'Sigma', name: x.title })),
  ];
}
function newItems(p: PackStatus) {
  const all = newItemsAll(p);
  return expandedNew.value.has(p.id) ? all : all.slice(0, NEW_PREVIEW);
}
function toggleNew(id: string) {
  const next = new Set(expandedNew.value);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  expandedNew.value = next;
}

function totalCount(p: PackStatus) {
  return p.parserTotal + p.detectionTotal + p.sigmaTotal;
}
function installedCount(p: PackStatus) {
  return p.parserInstalled + p.detectionInstalled + p.sigmaInstalled;
}
function formatWhen(iso: string) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : `on ${d.toLocaleDateString()}`;
}

async function load(refresh = false) {
  loading.value = true;
  try {
    const { data } = await api.getContentPacks(refresh);
    overview.value = data;
    if (guidePack.value) guidePack.value = data.packs.find((p: PackStatus) => p.id === guidePack.value!.id) ?? null;
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to load content packs');
  } finally {
    loading.value = false;
  }
}

function openGuide(pack: PackStatus) {
  guidePack.value = pack;
  guideOpen.value = true;
}

async function install(pack: PackStatus, onlyNew: boolean) {
  installing.value = onlyNew ? `${pack.id}:new` : pack.id;
  try {
    const { data } = onlyNew ? await api.installContentPackNew(pack.id) : await api.installContentPack(pack.id);
    const p = data.parsers;
    const d = data.detections;
    const s = data.sigma;
    const parts = [`parsers: ${p.installed} new, ${p.updated} updated`, `detections: ${d.installed} new, ${d.updated} updated`];
    if (s && (s.installed || s.already || s.pending.length || s.failed.length)) {
      parts.push(`Sigma: ${s.installed} added${s.already ? `, ${s.already} already added` : ''}`);
    }
    type Row = { name: string; reason: string };
    const failures: Row[] = [
      ...(p.failed || []),
      ...(d.failed || []),
      ...(s?.failed || []).map((f: any) => ({ name: f.title, reason: f.reason })),
    ];
    const pending: Row[] = (s?.pending || []).map((f: any) => ({ name: f.title, reason: f.reason }));
    // Installed items with a regex the safety check could not prove safe.
    const warnings: Row[] = (data.warnings || []).flatMap((w: any) =>
      (w.warnings || []).map((line: string) => ({ name: w.name, reason: line }))
    );
    if (failures.length) parts.push(`${failures.length} skipped`);
    if (pending.length) parts.push(`${pending.length} pending`);
    ElMessage.success(`${pack.name} — ${parts.join('; ')}`);
    guideOpen.value = false;
    await load();

    // Show exactly what was skipped or is pending and why, then any regex warnings.
    if (failures.length || pending.length || warnings.length) {
      const row = (f: Row) =>
        h('div', { style: 'margin-bottom:6px' }, [
          h('strong', {}, f.name),
          h('span', { style: 'color:var(--el-text-color-secondary)' }, ` — ${f.reason}`),
        ]);
      const section = (title: string, rows: Row[]) =>
        rows.length ? [h('div', { style: 'margin:8px 0 4px;font-weight:600' }, title), ...rows.map(row)] : [];
      await ElMessageBox({
        title: `${pack.name}: not everything installed`,
        message: h('div', { style: 'max-height:300px;overflow:auto' }, [
          ...section('Skipped', failures),
          ...section('Pending (install the pack again once available)', pending),
          ...section('Regex warnings', warnings),
        ]),
        confirmButtonText: 'OK',
      }).catch(() => {});
    }
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Install failed');
  } finally {
    installing.value = '';
  }
}

onMounted(() => load());
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
}
.subtitle {
  font-size: 13px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
  max-width: 760px;
}
.page-alert {
  margin-bottom: 16px;
}
.pack-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
  gap: 16px;
}
.pack-card {
  display: flex;
  flex-direction: column;
}
.pack-head {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.pack-icon {
  color: var(--el-color-primary);
}
.pack-title {
  font-weight: 600;
  flex: 1 1 140px;
}
.pack-desc {
  font-size: 13px;
  color: var(--el-text-color-regular);
  margin: 10px 0;
}
.pack-counts,
.pack-installed-counts {
  display: flex;
  gap: 14px;
  font-size: 13px;
  color: var(--el-text-color-secondary);
  margin-bottom: 4px;
}
.pack-version {
  margin-left: auto;
  font-variant-numeric: tabular-nums;
}
.pack-record {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-bottom: 6px;
}
.whats-new {
  border: 1px solid var(--el-color-danger-light-5);
  background: var(--el-color-danger-light-9);
  border-radius: 6px;
  padding: 8px 10px;
  margin: 6px 0 8px;
  font-size: 13px;
}
.whats-new-title {
  font-weight: 600;
  margin-bottom: 4px;
}
.new-items {
  list-style: none;
  margin: 0 0 6px;
  padding: 0;
}
.new-items li {
  padding: 1px 0;
  word-break: break-word;
}
.kind {
  display: inline-block;
  min-width: 70px;
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.new-more {
  display: block;
  margin-bottom: 6px;
}
.pack-setup :deep(.el-collapse-item__content) {
  font-size: 13px;
  color: var(--el-text-color-secondary);
  padding-bottom: 8px;
}
.pack-items-group {
  font-weight: 600;
  color: var(--el-text-color-regular);
  margin: 6px 0 4px;
}
.pack-items {
  list-style: none;
  margin: 0 0 8px;
  padding: 0;
}
.pack-items li {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  padding: 2px 0;
  word-break: break-word;
}
.item-name {
  flex: 1;
  min-width: 0;
}
.pack-items li.missing .item-name {
  text-decoration: line-through;
  opacity: 0.7;
}
.item-note {
  color: var(--el-text-color-secondary);
  font-size: 12px;
  font-style: italic;
  margin: 4px 0 0;
}
.pack-actions {
  margin-top: 12px;
}
.guide-summary {
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
.guide-steps {
  padding-left: 20px;
  margin: 0;
}
.guide-step {
  margin-bottom: 14px;
}
.guide-step-title {
  font-weight: 600;
  margin-bottom: 4px;
}
.guide-step-text {
  line-height: 1.6;
}
.guide-step-text :deep(p) {
  margin: 4px 0;
}
.guide-step-text :deep(code) {
  background: var(--el-fill-color-light);
  padding: 0 4px;
  border-radius: 3px;
}
.guide-code {
  background: var(--el-fill-color-darker);
  color: var(--el-text-color-primary);
  padding: 8px 10px;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 12px;
  margin: 6px 0 0;
}
</style>
