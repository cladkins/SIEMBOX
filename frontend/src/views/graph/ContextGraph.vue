<template>
  <div class="context-graph">
    <div class="page-header">
      <p class="subtitle">Everything SIEMBox knows that is linked to an alert, IP, user, host, asset, application or domain.</p>
      <div class="header-controls">
        <GraphEntitySearch ref="search" @pick="onPick" @error="(m: string) => (notice = m)" />
        <el-radio-group :model-value="windowValue" size="small" aria-label="Time window" @change="onWindow">
          <el-radio-button v-for="w in WINDOW_PRESETS" :key="w" :value="w">{{ w }}</el-radio-button>
          <el-radio-button v-if="view.around" value="around" disabled>around alert</el-radio-button>
        </el-radio-group>
        <el-select :model-value="view.limit" size="small" style="width: 130px" aria-label="Neighbours per relation" @change="onLimit">
          <el-option v-for="n in RELATION_LIMITS" :key="n" :value="n" :label="`Per relation ${n}`" />
        </el-select>
        <el-popover placement="bottom" :width="240" trigger="click">
          <template #reference>
            <el-button size="small">Sources{{ view.include ? ` (${view.include.length})` : '' }}</el-button>
          </template>
          <div class="sources-pop">
            <el-checkbox
              v-for="o in ORIGINS"
              :key="o"
              :model-value="!view.include || view.include.includes(o)"
              @change="(on: boolean) => toggleOrigin(o, on)"
              >{{ ORIGIN_LABELS[o] }}</el-checkbox
            >
          </div>
        </el-popover>
        <el-button size="small" :icon="Link" :disabled="view.entities.length === 0" @click="copyLink">Copy link</el-button>
      </div>
    </div>

    <el-alert v-if="noParsers" type="info" show-icon :closable="false" class="section">
      No parsers are installed, so logs carry no users or client IPs yet. The graph can still show alerts, assets, vulnerabilities,
      findings and which hosts send logs.
      <router-link to="/parsers">Parsers</router-link>
    </el-alert>
    <el-alert v-if="notice" type="warning" show-icon class="section" :title="notice" @close="notice = ''" />

    <!-- Bad link -->
    <el-alert v-if="badLink" type="error" show-icon :closable="false" class="section" data-testid="graph-bad-link">
      That link doesn't name a valid {{ badLinkWhat }}. Search for what you want to start from.
    </el-alert>

    <!-- Landing: no entity -->
    <div v-if="view.entities.length === 0" class="landing" data-testid="graph-landing">
      <el-card class="section">
        <template #header><span>Start from…</span></template>
        <p class="muted">Search above for an IP, user, host, domain, alert number or CVE, or pick one of these.</p>
        <div class="start-grid">
          <div>
            <div class="start-title">Newest open critical and high alerts</div>
            <el-skeleton v-if="startAlertsLoading" :rows="3" animated />
            <p v-else-if="startAlerts.length === 0" class="muted small">No open critical or high alerts.</p>
            <ul v-else class="start-list">
              <li v-for="a in startAlerts" :key="a.id">
                <router-link :to="alertLink(a)">
                  <el-tag size="small" :color="SEVERITY_COLORS[a.severity]" effect="dark" class="sev">{{ a.severity }}</el-tag>
                  #{{ a.id }} {{ fullLabel(a.title) }}
                </router-link>
              </li>
            </ul>
          </div>
          <div>
            <div class="start-title">Recently viewed</div>
            <p v-if="recent.length === 0" class="muted small">Nothing yet.</p>
            <ul v-else class="start-list">
              <li v-for="r in recent" :key="r.entity">
                <router-link :to="{ path: '/graph', query: { entity: r.entity, window: '7d' } }">
                  <span class="muted">{{ TYPE_STYLES[r.type]?.label ?? r.type }}</span> {{ fullLabel(r.label) }}
                </router-link>
              </li>
            </ul>
          </div>
        </div>
      </el-card>
    </div>

    <template v-else>
      <!-- First load -->
      <el-card v-if="loading && nodeTotal === 0" class="section"><el-skeleton :rows="8" animated /></el-card>

      <!-- Failed first load (busy, network, 5xx) -->
      <el-alert v-else-if="loadFailure && nodeTotal === 0" type="error" show-icon :closable="false" class="section" data-testid="graph-error">
        <template #title>{{ loadFailure.kind === 'busy' ? 'SIEMBox is busy' : "Couldn't load the graph" }}</template>
        <p class="alert-line">{{ loadFailure.message }}</p>
        <el-button size="small" type="primary" @click="reload">Try again</el-button>
      </el-alert>

      <!-- Unknown entity -->
      <el-card v-else-if="unknownCentre" class="section" data-testid="graph-unknown">
        <p>
          Nothing is linked to <strong>{{ fullLabel(unknownCentre.label) }}</strong>
          <template v-if="windowInfo"> between {{ when(windowInfo.from) }} and {{ when(windowInfo.to) }}</template>.
        </p>
        <el-button v-if="view.window !== '90d'" size="small" @click="onWindow('90d')">Try 90 days</el-button>
        <router-link v-if="unknownCentre.type === 'ip'" :to="{ path: '/threat-intel', query: { ip: unknownCentre.key } }" class="ti-link">
          <el-button size="small">Look up in Threat Intel</el-button>
        </router-link>
      </el-card>

      <template v-if="nodeTotal > 0">
        <div v-if="busyRetrying" class="section muted small">SIEMBox is busy, trying again in a few seconds…</div>
        <el-alert
          v-for="w in sourceWarnings"
          :key="w.origin"
          type="warning"
          show-icon
          :closable="false"
          class="section"
          :title="w.text"
        >
          <el-button v-if="w.retry" link type="primary" size="small" @click="reload">Try again</el-button>
        </el-alert>
        <el-alert v-if="actionError" type="error" show-icon class="section" :title="actionError" @close="actionError = ''" />
        <el-alert v-if="atCap" type="warning" show-icon :closable="false" class="section" data-testid="graph-cap">
          The graph is at its {{ MAX_CANVAS_NODES }}-node limit. Hide some nodes or start from a new centre.
        </el-alert>
        <el-alert v-if="pathMessage" type="info" show-icon class="section" :title="pathMessage" @close="clearPath" />

        <div class="workspace">
          <div class="main-pane">
            <div class="toolbar">
              <el-button-group>
                <el-button size="small" :disabled="mode !== 'graph'" title="Fit (F)" @click="canvas?.fit()">Fit</el-button>
                <el-button size="small" :disabled="mode !== 'graph'" @click="canvas?.relayout()">Re-layout</el-button>
                <el-button size="small" :disabled="undoStack.length === 0" title="Undo (Ctrl+Z)" @click="undo">Undo</el-button>
                <el-button size="small" @click="resetView">Reset</el-button>
              </el-button-group>
              <el-radio-group v-model="mode" size="small" aria-label="View">
                <el-radio-button value="graph" :disabled="canvasFailed">Graph</el-radio-button>
                <el-radio-button value="list">List</el-radio-button>
              </el-radio-group>
              <el-button size="small" :icon="Refresh" :loading="loading" @click="reload">Refresh</el-button>
              <el-button v-if="hiddenTotal > 0" size="small" link @click="onShowHidden">Show hidden ({{ hiddenTotal }})</el-button>
              <span v-for="p in pendingList" :key="p" class="loading-chip">
                Loading… <el-button link size="small" @click="cancel(p)">Cancel</el-button>
              </span>
              <span v-if="generatedAt" class="muted small generated">Generated {{ hhmm(generatedAt) }}</span>
            </div>
            <div class="legend">
              <el-check-tag
                v-for="c in legend"
                :key="c.type"
                :checked="!view.hide.includes(c.type)"
                :title="view.hide.includes(c.type) ? `Show ${c.plural}` : `Hide all ${c.plural}`"
                @change="toggleType(c.type)"
              >
                <span class="swatch" :style="{ background: c.color }"></span>{{ c.label }} {{ c.count }}
              </el-check-tag>
              <span class="muted small edge-key">— recorded · - - seen in logs · ··· matched</span>
            </div>
            <div class="canvas-wrap">
              <GraphCanvas
                v-if="mode === 'graph' && !canvasFailed"
                ref="canvas"
                :elements="elements"
                :hops="hops"
                :dark="themeStore.isDark"
                :selected="selectedId"
                :pulsing="pendingList"
                :path="path"
                :initial-positions="savedPositions"
                :aria-label="`Context graph: ${visible.nodes.length} nodes and ${visible.edges.length} links. Use the List view for a table.`"
                @select="onCanvasSelect"
                @expand="expand"
                @moved="savePositionsSoon"
                @failed="onCanvasFailed"
              />
              <GraphListView
                v-else
                :nodes="visible.nodes"
                :edges="visible.edges"
                :centres="model.centres"
                :expanded="model.expanded"
                :selected="selectedId"
                :group-count="visible.groupNodes.length"
                @select="(id: string, kind: 'node' | 'edge') => select(id, kind)"
                @expand="expand"
              />
            </div>
          </div>

          <aside v-if="!narrow" class="side-pane">
            <GraphRelationTable
              v-if="table && tableGroup"
              :centre-id="table.nodeId"
              :group="tableGroup"
              :params="relationParams"
              :on-canvas="onCanvasIds"
              :room="room"
              @add="onAddItems"
              @close="table = null"
            />
            <GraphDetailsPanel
              v-else
              :node="selectedNode"
              :edge="selectedEdge"
              :groups="selectedGroups"
              :centres="model.centres"
              :expanded="model.expanded"
              :at-cap="atCap"
              :role="role"
              :labels="labels"
              @expand="expand"
              @centre="centreHere"
              @hide="hide"
              @table="openTable"
              @open-alert="openAlert"
            />
          </aside>
        </div>

        <div class="footer-bar">
          <span>
            Sources:
            <span v-for="(s, o) in sources" :key="o" class="src">{{ ORIGIN_LABELS[o as Origin] }} {{ s?.status === 'ok' ? '✓' : '!' }}</span>
          </span>
          <span>
            {{ visible.nodes.length }} nodes · {{ visible.edges.length }} links
            <template v-if="windowInfo"> · {{ when(windowInfo.from) }} – {{ when(windowInfo.to) }}</template>
          </span>
          <span>{{ nodeTotal }} / {{ MAX_CANVAS_NODES }} nodes</span>
        </div>
      </template>
    </template>

    <el-drawer v-if="narrow" v-model="drawerOpen" direction="btt" size="70%" title="Details" :with-header="true">
      <GraphRelationTable
        v-if="table && tableGroup"
        :centre-id="table.nodeId"
        :group="tableGroup"
        :params="relationParams"
        :on-canvas="onCanvasIds"
        :room="room"
        @add="onAddItems"
        @close="table = null"
      />
      <GraphDetailsPanel
        v-else
        :node="selectedNode"
        :edge="selectedEdge"
        :groups="selectedGroups"
        :centres="model.centres"
        :expanded="model.expanded"
        :at-cap="atCap"
        :role="role"
        :labels="labels"
        @expand="expand"
        @centre="centreHere"
        @hide="hide"
        @table="openTable"
        @open-alert="openAlert"
      />
    </el-drawer>

    <AlertDetailDialog v-model="alertDialogOpen" :alert="dialogAlert" readonly />
  </div>
</template>

<script setup lang="ts">
/**
 * The Context Graph page (/graph, every role). The URL is the view's state
 * (graph/model.ts parseView / viewQuery): entity= centres, window= or
 * around=, x= expanded nodes, hide=, limit=, include=. Expanding, hiding and
 * the legend rewrite it with router.replace; Centre here and a search pick
 * push, so Back walks the centres. The page never polls: Refresh and a window
 * change are the only reloads, so an idle tab can't trip a 401.
 */
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue';
import { formatAlertRef } from '@/utils/alertRef';
import { useRoute, useRouter } from 'vue-router';
import { ElMessage } from 'element-plus';
import { Link, Refresh } from '@element-plus/icons-vue';
import { format } from 'date-fns';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import { useThemeStore } from '@/stores/theme';
import type { Alert } from '@/stores/alerts';
import { SEVERITY_COLORS } from '@/utils/severity';
import AlertDetailDialog from '@/components/AlertDetailDialog.vue';
import GraphCanvas from '@/components/graph/GraphCanvas.vue';
import GraphDetailsPanel from '@/components/graph/GraphDetailsPanel.vue';
import GraphEntitySearch from '@/components/graph/GraphEntitySearch.vue';
import GraphListView from '@/components/graph/GraphListView.vue';
import GraphRelationTable from '@/components/graph/GraphRelationTable.vue';
import { classifyGraphError, type GraphFailure } from '@/graph/errors';
import { typeOfId } from '@/graph/entityKey';
import { fullLabel } from '@/graph/labels';
import type { Point } from '@/graph/layout';
import {
  addRelationItems,
  aroundOf,
  atNodeCap,
  capacity,
  emptyModel,
  hideNodes,
  hiddenCount,
  hopDistances,
  mergeNeighborhood,
  nodeCount,
  parseGroupNodeId,
  parseView,
  popUndo,
  pushUndo,
  shortestPath,
  showHidden,
  typeCounts,
  viewKey,
  viewQuery,
  visibleGraph,
  type GraphModel,
  type GraphView,
} from '@/graph/model';
import { ORIGIN_LABELS, TYPE_STYLES, toElements, typeColor } from '@/graph/style';
import {
  MAX_CANVAS_NODES,
  MAX_CENTRES,
  NODE_TYPES,
  ORIGINS,
  RELATION_LIMITS,
  WINDOW_PRESETS,
  type GraphNode,
  type GraphWindow,
  type NeighborhoodResponse,
  type NodeType,
  type Origin,
  type RelationItem,
  type RelId,
  type SourceStatus,
  type WindowPreset,
} from '@/graph/types';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();
const themeStore = useThemeStore();
const role = computed<string>(() => authStore.user?.role ?? 'viewer');

const parsed = computed(() => parseView(route.query));
const view = computed(() => parsed.value.view);
const windowValue = computed(() => (view.value.around ? 'around' : view.value.window ?? '7d'));

const model = shallowRef<GraphModel>(emptyModel());
const undoStack = shallowRef<GraphModel[]>([]);
const loading = ref(false);
const loadFailure = ref<GraphFailure | null>(null);
const badEntities = ref<string[]>([]);
const busyRetrying = ref(false);
const actionError = ref('');
const notice = ref('');
const exists = ref<Record<string, boolean>>({});
const sources = ref<Partial<Record<Origin, SourceStatus>>>({});
const windowInfo = ref<GraphWindow | null>(null);
const generatedAt = ref<string | null>(null);
const pending = ref<Record<string, AbortController>>({});
const selectedId = ref<string | null>(null);
const selectedKind = ref<'node' | 'edge' | null>(null);
const pathEnds = ref<string[]>([]);
const path = ref<{ nodes: string[]; edges: string[] } | null>(null);
const pathMessage = ref('');
const table = ref<{ nodeId: string; rel: RelId } | null>(null);
const canvasFailed = ref(false);
const canvas = ref<InstanceType<typeof GraphCanvas> | null>(null);
const search = ref<InstanceType<typeof GraphEntitySearch> | null>(null);
const savedPositions = ref<Record<string, Point> | null>(null);
const noParsers = ref(false);
const alertDialogOpen = ref(false);
const dialogAlert = ref<Alert | null>(null);
const startAlerts = ref<Alert[]>([]);
const startAlertsLoading = ref(false);
const narrow = ref(false);
const drawerOpen = ref(false);

const MODE_KEY = 'siembox.graph.mode';
const mode = ref<'graph' | 'list'>(readMode());
function readMode(): 'graph' | 'list' {
  try {
    return localStorage.getItem(MODE_KEY) === 'list' ? 'list' : 'graph';
  } catch {
    return 'graph';
  }
}
watch(mode, (m) => {
  try {
    localStorage.setItem(MODE_KEY, m);
  } catch {
    // The page works without it.
  }
});

let loadController: AbortController | null = null;
let loadSeq = 0;
let loadedKey: string | null = null;

// ---------------------------------------------------------------- derived

const visible = computed(() => visibleGraph(model.value, view.value.hide));
const elements = computed(() => toElements(visible.value, { centres: model.value.centres, dark: themeStore.isDark }));
const hops = computed(() => hopDistances(model.value));
const nodeTotal = computed(() => nodeCount(model.value));
const hiddenTotal = computed(() => hiddenCount(model.value));
const atCap = computed(() => atNodeCap(model.value));
const room = computed(() => capacity(model.value).nodes);
const pendingList = computed(() => Object.keys(pending.value));
const onCanvasIds = computed(() => new Set(Object.keys(model.value.nodes)));
const labels = computed(() => new Map(Object.values(model.value.nodes).map((n) => [n.id, fullLabel(n.label)])));

const selectedNode = computed<GraphNode | null>(() =>
  selectedKind.value === 'node' && selectedId.value ? model.value.nodes[selectedId.value] ?? null : null
);
const selectedEdge = computed(() => (selectedKind.value === 'edge' && selectedId.value ? model.value.edges[selectedId.value] ?? null : null));
const selectedGroups = computed(() => (selectedNode.value ? model.value.groups[selectedNode.value.id] ?? [] : []));
const tableGroup = computed(() => (table.value ? (model.value.groups[table.value.nodeId] ?? []).find((g) => g.rel === table.value!.rel) ?? null : null));

const relationParams = computed(() => windowParams(view.value));

const legend = computed(() => {
  const counts = typeCounts(model.value);
  return NODE_TYPES.filter((t) => counts[t] || view.value.hide.includes(t)).map((t) => ({
    type: t,
    label: TYPE_STYLES[t].label,
    plural: TYPE_STYLES[t].plural.toLowerCase(),
    count: counts[t] ?? 0,
    color: typeColor(t, themeStore.isDark),
  }));
});

const badLink = computed(() => parsed.value.invalid.length > 0 || badEntities.value.length > 0);
const badLinkWhat = computed(() => {
  const raw = parsed.value.invalid[0] ?? badEntities.value[0] ?? '';
  const type = typeOfId(raw.trim().toLowerCase());
  return type ? TYPE_STYLES[type].label.toLowerCase() : 'entity (type:value, for example ip:198.51.100.7)';
});

/** The one centre the server doesn't know, when nothing else is on the graph. */
const unknownCentre = computed<GraphNode | null>(() => {
  if (loading.value || model.value.centres.length !== 1) return null;
  const id = model.value.centres[0];
  if (exists.value[id] !== false) return null;
  const others = Object.keys(model.value.nodes).filter((n) => n !== id);
  return others.length === 0 ? model.value.nodes[id] ?? null : null;
});

const sourceWarnings = computed(() => {
  const out: Array<{ origin: Origin; text: string; retry: boolean }> = [];
  for (const [origin, status] of Object.entries(sources.value) as Array<[Origin, SourceStatus]>) {
    const name = ORIGIN_LABELS[origin] ?? origin;
    switch (status.status) {
      case 'timeout':
        out.push({ origin, text: `${name} relationships took too long and were left out; the other sources are complete.`, retry: true });
        break;
      case 'partial':
        out.push({ origin, text: `Some ${name.toLowerCase()} relationships took too long and are missing.`, retry: true });
        break;
      case 'disabled':
        out.push({ origin, text: `${name} relationships are switched off by an administrator.`, retry: false });
        break;
      case 'building':
        out.push({
          origin,
          text: `${name} relationships are still being built${status.covered_from ? ` (covering from ${when(status.covered_from)})` : ''}.`,
          retry: false,
        });
        break;
      case 'behind':
        out.push({
          origin,
          text: `${name} relationships are behind${status.covered_until ? ` (up to ${when(status.covered_until)})` : ''}.`,
          retry: false,
        });
        break;
      default:
        break;
    }
    if (status.incomplete_days?.length) {
      out.push({ origin, text: `${name} relationships are incomplete for ${status.incomplete_days.join(', ')}: too many distinct values.`, retry: false });
    }
  }
  return out;
});

// ---------------------------------------------------------------- helpers

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : format(d, 'MMM d HH:mm');
}
const hhmm = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : format(d, 'HH:mm');
};

function windowParams(v: GraphView): { window?: string; around?: string } {
  return v.around ? { around: v.around } : { window: v.window ?? '7d' };
}

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener('abort', () => {
      clearTimeout(timer);
      reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
    });
  });

/** One neighbourhood, retried once after Retry-After when the server is busy. */
async function fetchNeighborhood(id: string, v: GraphView, signal: AbortSignal): Promise<NeighborhoodResponse> {
  const params = { entity: id, limit: v.limit, include: v.include, ...windowParams(v) };
  try {
    return (await api.graphNeighborhood(params, signal)).data as NeighborhoodResponse;
  } catch (err) {
    const failure = classifyGraphError(err);
    if (failure.kind !== 'busy') throw err;
    busyRetrying.value = true;
    try {
      await sleep((failure.retryAfter ?? 2) * 1000, signal);
      return (await api.graphNeighborhood(params, signal)).data as NeighborhoodResponse;
    } finally {
      busyRetrying.value = false;
    }
  }
}

function mergeSources(response: NeighborhoodResponse) {
  const next = { ...sources.value };
  const rank = { ok: 0, behind: 1, building: 2, partial: 3, disabled: 4, timeout: 5 } as const;
  for (const [origin, status] of Object.entries(response.sources) as Array<[Origin, SourceStatus]>) {
    const before = next[origin];
    if (!before || rank[status.status] > rank[before.status]) next[origin] = status;
  }
  sources.value = next;
  windowInfo.value = response.window;
  generatedAt.value = response.generated_at;
}

// ---------------------------------------------------------------- storage

const POSITIONS_PREFIX = 'siembox.graph.pos.';
function positionsKey(v: GraphView) {
  return POSITIONS_PREFIX + viewKey(v);
}
function readPositions(v: GraphView): Record<string, Point> | null {
  try {
    const raw = sessionStorage.getItem(positionsKey(v));
    const parsedPositions = raw ? JSON.parse(raw) : null;
    return parsedPositions && typeof parsedPositions === 'object' ? parsedPositions : null;
  } catch {
    return null;
  }
}
let saveTimer: ReturnType<typeof setTimeout> | null = null;
function savePositionsSoon() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const positions = canvas.value?.positions();
    if (!positions) return;
    try {
      sessionStorage.setItem(positionsKey(view.value), JSON.stringify(positions));
    } catch {
      // Storage full or blocked: positions just aren't restored.
    }
  }, 400);
}

interface RecentEntry {
  entity: string;
  type: NodeType;
  label: string;
}
const recentKey = computed(() => `siembox.graph.recent.${authStore.user?.id ?? 'anon'}`);
const recent = ref<RecentEntry[]>([]);
function readRecent() {
  try {
    const list = JSON.parse(localStorage.getItem(recentKey.value) || '[]');
    recent.value = Array.isArray(list)
      ? list.filter((r) => r && typeof r.entity === 'string' && typeof r.label === 'string' && typeOfId(r.entity)).slice(0, 10)
      : [];
  } catch {
    recent.value = [];
  }
}
function remember(node: GraphNode) {
  const entry: RecentEntry = { entity: node.id, type: node.type, label: node.label };
  recent.value = [entry, ...recent.value.filter((r) => r.entity !== node.id)].slice(0, 10);
  try {
    localStorage.setItem(recentKey.value, JSON.stringify(recent.value));
  } catch {
    // The page works without it.
  }
}

// ---------------------------------------------------------------- loading

/** Load the view's centres and x= nodes afresh (positions on the canvas are kept). */
async function load() {
  const v = view.value;
  loadController?.abort();
  for (const c of Object.values(pending.value)) c.abort();
  pending.value = {};
  const controller = new AbortController();
  loadController = controller;
  const seq = ++loadSeq;
  loadedKey = viewKey(v);
  loading.value = true;
  loadFailure.value = null;
  badEntities.value = [];
  actionError.value = '';
  clearPath();
  table.value = null;
  if (v.entities.length === 0) {
    model.value = emptyModel();
    loading.value = false;
    return;
  }
  if (nodeCount(model.value) === 0) savedPositions.value = readPositions(v);
  sources.value = {};
  let next = emptyModel(v.entities);
  const nextExists: Record<string, boolean> = {};
  const bad: string[] = [];
  let failure: GraphFailure | null = null;
  for (const id of [...v.entities, ...v.x]) {
    const isCentre = v.entities.includes(id);
    try {
      const response = await fetchNeighborhood(id, v, controller.signal);
      if (seq !== loadSeq) return;
      if (isCentre) nextExists[response.center.id] = response.center.exists;
      const merged = mergeNeighborhood(next, response, id);
      if (!merged.ok) {
        actionError.value = 'Not everything in this link fits on the graph: some expansions were left out.';
        break;
      }
      next = merged.model;
      mergeSources(response);
      if (isCentre && response.center.exists) remember(response.center);
    } catch (err) {
      if (seq !== loadSeq) return;
      const f = classifyGraphError(err);
      if (f.kind === 'aborted') return;
      if (!isCentre) continue; // a stale x= node: leave it out
      next = { ...next, centres: next.centres.filter((c) => c !== id) };
      if (f.kind === 'bad' || f.kind === 'unavailable') bad.push(id);
      else failure = failure ?? f;
    }
  }
  if (seq !== loadSeq) return;
  model.value = next;
  undoStack.value = [];
  exists.value = nextExists;
  badEntities.value = bad;
  loadFailure.value = nodeCount(next) === 0 ? failure : null;
  if (failure && nodeCount(next) > 0) actionError.value = `Some centres couldn't be loaded: ${failure.message}`;
  if (selectedId.value && !next.nodes[selectedId.value] && !next.edges[selectedId.value]) select(null, null);
  loading.value = false;
  if (!selectedId.value && next.centres[0]) select(next.centres[0], 'node', false);
}

function reload() {
  void load();
}

watch(
  () => route.query,
  () => {
    if (route.name !== 'ContextGraph') return;
    // Expanding and hiding rewrite x= and hide= themselves: no reload for those.
    if (viewKey(view.value) !== loadedKey) void load();
  }
);

/** Write the model's expansions into the URL (replace: Back skips them). */
function writeExpanded(next: GraphModel) {
  const x = next.expanded.filter((id) => !next.centres.includes(id));
  void router.replace({ query: viewQuery({ ...view.value, x }) });
}

// ---------------------------------------------------------------- actions

function select(id: string | null, kind: 'node' | 'edge' | null, openDrawer = true) {
  selectedId.value = id;
  selectedKind.value = id ? kind : null;
  if (id) table.value = null;
  if (narrow.value && openDrawer) drawerOpen.value = !!id;
}

function onCanvasSelect(id: string | null, kind: 'node' | 'group' | 'edge' | null, shift: boolean) {
  if (kind === 'group' && id) {
    const g = parseGroupNodeId(id);
    if (g) openTable(g.nodeId, g.rel);
    return;
  }
  if (shift && kind === 'node' && id) {
    pathEnds.value = [...pathEnds.value.filter((p) => p !== id), id].slice(-2);
    if (pathEnds.value.length === 2) {
      const found = shortestPath(visible.value.edges, pathEnds.value[0], pathEnds.value[1]);
      path.value = found;
      pathMessage.value = found ? `Path: ${found.nodes.length - 1} hops. Press Esc to clear.` : 'Not connected in what is loaded. Expand more nodes.';
    }
    select(id, 'node');
    return;
  }
  if (!id) clearPath();
  select(id, kind === 'group' ? null : kind);
}

function clearPath() {
  path.value = null;
  pathEnds.value = [];
  pathMessage.value = '';
}

async function expand(id: string) {
  const node = model.value.nodes[id];
  if (!node || !node.expandable || pending.value[id] || model.value.expanded.includes(id)) return;
  if (atCap.value) {
    actionError.value = `The graph is at its ${MAX_CANVAS_NODES}-node limit. Hide some nodes or start from a new centre.`;
    return;
  }
  const controller = new AbortController();
  pending.value = { ...pending.value, [id]: controller };
  const seq = loadSeq;
  try {
    const response = await fetchNeighborhood(id, view.value, controller.signal);
    if (seq !== loadSeq) return;
    const merged = mergeNeighborhood(model.value, response, id);
    if (!merged.ok) {
      actionError.value = 'That would take the graph past its limit. Hide some nodes or start from a new centre.';
      return;
    }
    undoStack.value = pushUndo(undoStack.value, model.value);
    model.value = merged.model;
    mergeSources(response);
    writeExpanded(merged.model);
  } catch (err) {
    const f = classifyGraphError(err);
    // A failed expansion keeps the graph as it was.
    if (f.kind !== 'aborted') actionError.value = `Couldn't expand ${fullLabel(node.label)}: ${f.message}`;
  } finally {
    const rest = { ...pending.value };
    delete rest[id];
    pending.value = rest;
  }
}

function cancel(id: string) {
  pending.value[id]?.abort();
}

function hide(id: string) {
  const result = hideNodes(model.value, [id]);
  if (result.hidden.length === 0) return;
  undoStack.value = pushUndo(undoStack.value, model.value);
  model.value = result.model;
  if (selectedId.value && result.hidden.includes(selectedId.value)) select(null, null);
  clearPath();
  writeExpanded(result.model);
}

function onShowHidden() {
  undoStack.value = pushUndo(undoStack.value, model.value);
  model.value = showHidden(model.value);
}

function undo() {
  const { snapshot, stack } = popUndo(undoStack.value);
  if (!snapshot) return;
  undoStack.value = stack;
  model.value = snapshot;
  writeExpanded(snapshot);
}

function resetView() {
  void router.replace({ query: viewQuery({ ...view.value, x: [], hide: [] }) }).then(() => load());
}

function centreHere(id: string) {
  void router.push({ query: viewQuery({ ...view.value, entities: [id], x: [] }) });
}

function onPick(entity: string, replace: boolean) {
  const entities = replace ? [entity] : [...view.value.entities.filter((e) => e !== entity), entity];
  if (entities.length > MAX_CENTRES) {
    notice.value = `A view has at most ${MAX_CENTRES} centres. Shift+Enter replaces them.`;
    return;
  }
  void router.push({ path: '/graph', query: viewQuery({ ...view.value, entities, x: replace ? [] : view.value.x }) });
}

function onWindow(value: string | number | boolean | undefined) {
  if (!(WINDOW_PRESETS as readonly unknown[]).includes(value)) return;
  void router.replace({ query: viewQuery({ ...view.value, window: value as WindowPreset, around: undefined }) });
}

function onLimit(value: number) {
  void router.replace({ query: viewQuery({ ...view.value, limit: value as GraphView['limit'] }) });
}

function toggleOrigin(origin: Origin, on: boolean) {
  const current = view.value.include ?? [...ORIGINS];
  const include = on ? [...new Set([...current, origin])] : current.filter((o) => o !== origin);
  if (include.length === 0) return;
  void router.replace({ query: viewQuery({ ...view.value, include: include.length === ORIGINS.length ? undefined : include }) });
}

function toggleType(type: NodeType) {
  const hide = view.value.hide.includes(type) ? view.value.hide.filter((t) => t !== type) : [...view.value.hide, type];
  void router.replace({ query: viewQuery({ ...view.value, hide }) });
}

function openTable(nodeId: string, rel: RelId) {
  table.value = { nodeId, rel };
  if (narrow.value) drawerOpen.value = true;
}

function onAddItems(items: RelationItem[]) {
  if (!table.value) return;
  const result = addRelationItems(model.value, table.value.nodeId, table.value.rel, items);
  if (result.added.length === 0 && result.refused === 0) return;
  undoStack.value = pushUndo(undoStack.value, model.value);
  model.value = result.model;
  if (result.refused > 0) actionError.value = `${result.refused} didn't fit on the graph. Hide some nodes first.`;
}

async function openAlert(id: number) {
  try {
    const { data } = await api.getAlert(id, true);
    dialogAlert.value = data as Alert;
    alertDialogOpen.value = true;
  } catch {
    actionError.value = `Couldn't open alert ${formatAlertRef(id)}.`;
  }
}

async function copyLink() {
  const href = window.location.origin + router.resolve({ path: '/graph', query: route.query }).href;
  try {
    await navigator.clipboard.writeText(href);
    ElMessage.success('Link copied. Each person sees what their role allows.');
  } catch {
    notice.value = `Copy this link: ${href}`;
  }
}

function onCanvasFailed(error: unknown) {
  console.error('Context Graph canvas failed to start', error);
  canvasFailed.value = true;
  mode.value = 'list';
  notice.value = "The graph canvas couldn't start in this browser; showing the list view.";
}

function alertLink(a: Alert) {
  const around = aroundOf(a.created_at);
  return { path: '/graph', query: around ? { entity: `alert:${a.id}`, around } : { entity: `alert:${a.id}`, window: '7d' } };
}

async function loadLanding() {
  startAlertsLoading.value = true;
  try {
    const { data } = await api.get('/alerts', {
      params: { status: 'new', limit: 50 },
      skipErrorToast: true,
      skipNetworkErrorToast: true,
    });
    const list: Alert[] = Array.isArray(data?.alerts) ? data.alerts : [];
    const rank = (s: string) => (s === 'critical' ? 0 : s === 'high' ? 1 : 2);
    startAlerts.value = list
      .filter((a) => a.severity === 'critical' || a.severity === 'high')
      .sort((a, b) => rank(a.severity) - rank(b.severity) || Date.parse(b.created_at) - Date.parse(a.created_at))
      .slice(0, 5);
  } catch {
    startAlerts.value = [];
  } finally {
    startAlertsLoading.value = false;
  }
}

async function checkParsers() {
  try {
    const { data } = await api.get('/logs/parse-coverage', { skipErrorToast: true, skipNetworkErrorToast: true });
    noParsers.value = typeof data?.total === 'number' && data.total > 0 && data.parsed === 0;
  } catch {
    noParsers.value = false;
  }
}

// ---------------------------------------------------------------- keyboard and layout

function onKey(event: KeyboardEvent) {
  const target = event.target as HTMLElement | null;
  const typing = !!target && (/^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName) || target.isContentEditable);
  if (event.key === 'Escape') {
    clearPath();
    if (!alertDialogOpen.value) select(null, null);
    return;
  }
  if (typing || alertDialogOpen.value) return;
  if (event.key === '/') {
    event.preventDefault();
    search.value?.focus();
  } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'z') {
    event.preventDefault();
    undo();
  } else if (event.key === 'f' || event.key === 'F') {
    canvas.value?.fit();
  } else if ((event.key === 'Delete' || event.key === 'Backspace') && selectedNode.value) {
    hide(selectedNode.value.id);
  }
}

let narrowQuery: MediaQueryList | null = null;
const onNarrow = () => {
  narrow.value = !!narrowQuery?.matches;
};

onMounted(() => {
  window.addEventListener('keydown', onKey);
  narrowQuery = window.matchMedia?.('(max-width: 900px)') ?? null;
  onNarrow();
  narrowQuery?.addEventListener?.('change', onNarrow);
  readRecent();
  void checkParsers();
  if (view.value.entities.length === 0) void loadLanding();
  void load();
});

watch(
  () => view.value.entities.length === 0,
  (landing) => {
    if (landing) {
      readRecent();
      void loadLanding();
    }
  }
);

onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKey);
  narrowQuery?.removeEventListener?.('change', onNarrow);
  loadController?.abort();
  for (const c of Object.values(pending.value)) c.abort();
  if (saveTimer) clearTimeout(saveTimer);
});
</script>

<style scoped>
.context-graph {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-width: 0;
}
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}
.subtitle {
  margin: 0;
  font-size: 14px;
  color: var(--siembox-text-secondary);
}
.header-controls {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.header-controls .el-button + .el-button {
  margin-left: 0;
}
.section {
  margin: 0;
}
.alert-line {
  margin: 4px 0 8px;
}
.muted {
  color: var(--siembox-text-secondary);
}
.small {
  font-size: 12px;
}
.sources-pop {
  display: flex;
  flex-direction: column;
}
.start-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 16px;
}
.start-title {
  font-weight: 600;
  margin-bottom: 6px;
}
.start-list {
  list-style: none;
  margin: 0;
  padding: 0;
}
.start-list li {
  padding: 4px 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.start-list a {
  color: var(--el-color-primary);
  text-decoration: none;
}
.sev {
  border: none;
  margin-right: 4px;
}
.ti-link {
  margin-left: 8px;
}
.workspace {
  display: flex;
  gap: 12px;
  min-width: 0;
}
.main-pane {
  flex: 1 1 auto;
  min-width: 0;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--siembox-border-color);
  border-radius: 4px;
  background: var(--siembox-card-bg);
}
.side-pane {
  flex: 0 0 360px;
  width: 360px;
  max-height: 760px;
  overflow-y: auto;
  border: 1px solid var(--siembox-border-color);
  border-radius: 4px;
  background: var(--siembox-card-bg);
}
.toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  padding: 8px;
  border-bottom: 1px solid var(--siembox-border-color);
}
.toolbar .el-button + .el-button {
  margin-left: 0;
}
.generated {
  margin-left: auto;
}
.loading-chip {
  font-size: 12px;
  padding: 0 8px;
  border-radius: 10px;
  background: var(--el-color-primary-light-9);
}
.legend {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  padding: 6px 8px;
}
.swatch {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 4px;
}
.edge-key {
  margin-left: auto;
}
.canvas-wrap {
  overflow: auto;
  position: relative;
  height: 600px;
  min-width: 0;
}
.footer-bar {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  font-size: 12px;
  color: var(--siembox-text-secondary);
}
.src {
  margin-left: 6px;
}
@media (max-width: 900px) {
  .canvas-wrap {
    height: 60vh;
  }
  .edge-key,
  .generated {
    margin-left: 0;
  }
}
</style>
