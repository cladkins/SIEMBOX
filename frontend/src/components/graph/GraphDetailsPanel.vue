<template>
  <div class="details-panel" data-testid="graph-details">
    <!-- A node -->
    <template v-if="node">
      <div class="dp-head">
        <span class="dp-type">{{ typeLabel }}</span>
        <el-button link size="small" :icon="CopyDocument" aria-label="Copy" @click="copy(copyText)">Copy</el-button>
      </div>
      <div class="dp-title" :title="title">{{ title }}</div>
      <div class="dp-flags">
        <el-tag v-if="isCentre" size="small">centre</el-tag>
        <el-tag v-for="f in node.flags" :key="f" size="small" :type="f === 'threat_feed' ? 'danger' : 'info'">{{ FLAG_LABELS[f] ?? f }}</el-tag>
      </div>
      <el-descriptions v-if="facts.length" :column="1" size="small" border class="dp-facts">
        <el-descriptions-item v-for="f in facts" :key="f.name" :label="f.name">{{ f.value }}</el-descriptions-item>
      </el-descriptions>

      <div v-if="groups.length" class="dp-section">
        <div class="dp-section-title">Relations</div>
        <div v-for="g in groups" :key="g.rel" class="dp-rel">
          <span class="rel-label" :title="g.label">{{ fullLabel(g.label) }}</span>
          <span class="rel-count">{{ formatCount(g.total, g.total_capped) }}</span>
          <el-tag v-if="g.status === 'timeout'" size="small" type="warning">timed out</el-tag>
          <el-tag v-else-if="g.status === 'unavailable'" size="small" type="info">unavailable</el-tag>
          <el-tag v-if="g.very_common" size="small" type="warning" title="Very common: likely infrastructure">very common</el-tag>
          <span class="rel-actions">
            <el-button v-if="g.total > 0 && g.status === 'ok'" link size="small" @click="emit('table', node.id, g.rel)">Table</el-button>
          </span>
          <div v-if="g.total === 0 && noteText(g)" class="rel-note">{{ noteText(g) }}</div>
        </div>
      </div>
      <p v-else-if="node.expandable && !isExpanded" class="muted small">Expand it to see what it links to.</p>

      <div class="dp-actions">
        <el-button v-if="node.expandable" size="small" type="primary" :disabled="atCap || isExpanded" @click="emit('expand', node.id)">
          {{ isExpanded ? 'Expanded' : 'Expand' }}
        </el-button>
        <el-button v-if="node.expandable" size="small" :disabled="isCentre && centres.length === 1" @click="emit('centre', node.id)">Centre here</el-button>
        <el-button size="small" :disabled="isCentre && centres.length === 1" @click="emit('hide', node.id)">Hide</el-button>
      </div>

      <div v-if="openIn.length" class="dp-section">
        <div class="dp-section-title">Open in</div>
        <span v-for="(link, i) in openIn" :key="link.label">
          <router-link v-if="link.to" :to="link.to" class="dp-link">{{ link.label }}</router-link>
          <el-button v-else link type="primary" size="small" @click="link.action?.()">{{ link.label }}</el-button>
          <span v-if="i < openIn.length - 1" class="muted"> · </span>
        </span>
      </div>
    </template>

    <!-- An edge -->
    <template v-else-if="edge">
      <div class="dp-head"><span class="dp-type">Link</span></div>
      <div class="dp-title">{{ edgeLabel(edge.rel) }}</div>
      <p class="small">{{ endLabel(edge.source) }} → {{ endLabel(edge.target) }}</p>
      <div v-if="edge.new || edge.success_after_failures" class="dp-flags">
        <el-tag v-if="edge.new" size="small" type="warning" title="First seen in this window">NEW</el-tag>
        <el-tag v-if="edge.success_after_failures" size="small" type="danger">success after failures</el-tag>
      </div>
      <el-descriptions :column="1" size="small" border class="dp-facts">
        <el-descriptions-item label="Kind">{{ STYLE_MEANINGS[edge.style] }}</el-descriptions-item>
        <el-descriptions-item label="From">{{ ORIGIN_LABELS[edge.origin] ?? edge.origin }}</el-descriptions-item>
        <el-descriptions-item v-if="edge.role" label="Role">{{ roleLabel(edge.role) }}</el-descriptions-item>
        <el-descriptions-item v-if="edge.count !== undefined" label="Count">{{ edge.count.toLocaleString('en-US') }}</el-descriptions-item>
        <el-descriptions-item v-if="outcomeLabel(edge)" label="Outcome">{{ outcomeLabel(edge) }}</el-descriptions-item>
        <el-descriptions-item v-if="edge.versions?.length" label="Versions">{{ versionsLabel(edge.versions) }}</el-descriptions-item>
        <el-descriptions-item v-if="edge.sources?.length" label="Evidence">{{ edge.sources.map(sourceLabel).join(', ') }}</el-descriptions-item>
        <el-descriptions-item v-if="edge.network" label="Network evidence">seen only on the network (user agents, DNS queries), not on the device</el-descriptions-item>
        <el-descriptions-item v-if="edge.match" label="Match">{{ edge.match === 'exact' ? 'exact: an endpoint finding on one of its packages' : 'best effort: the finding names the product' }}</el-descriptions-item>
        <el-descriptions-item v-if="edge.first_seen" label="First seen">{{ when(edge.first_seen) }}</el-descriptions-item>
        <el-descriptions-item v-if="edge.last_seen" label="Last seen">{{ when(edge.last_seen) }}</el-descriptions-item>
      </el-descriptions>
      <div class="dp-actions">
        <el-button v-if="alertEnd" size="small" @click="emit('open-alert', alertEnd)">Open alert</el-button>
        <el-button v-if="hasEvidence && !showLogs" size="small" data-testid="graph-show-logs" @click="showLogs = true">Show logs</el-button>
      </div>
      <GraphEvidence v-if="hasEvidence && showLogs" :edge="edge" @close="showLogs = false" />
    </template>

    <div v-else class="dp-empty">
      <p>Select a node or a link to see its details.</p>
      <p class="muted small">Double-click a node to expand it. Shift-click two nodes to light up the path between them.</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { alertRefPath, formatAlertRef, parseAlertRef } from '@/utils/alertRef';
import { useRouter, type RouteLocationRaw } from 'vue-router';
import { ElMessage } from 'element-plus';
import { CopyDocument } from '@element-plus/icons-vue';
import { format } from 'date-fns';
import { factText, formatCount, fullLabel } from '@/graph/labels';
import { ORIGIN_LABELS, STYLE_MEANINGS, TYPE_STYLES, edgeLabel, outcomeLabel, roleLabel, versionsLabel } from '@/graph/style';
import { keyOfId } from '@/graph/entityKey';
import { EVIDENCE_RELS, type GraphEdge, type GraphNode, type NodeFlag, type RelationGroup, type RelId } from '@/graph/types';
import GraphEvidence from './GraphEvidence.vue';
import { sourceLabel as appSourceLabel } from '@/utils/applications';

const props = defineProps<{
  node: GraphNode | null;
  edge: GraphEdge | null;
  groups: RelationGroup[];
  centres: readonly string[];
  expanded: readonly string[];
  atCap: boolean;
  role: string;
  /** Labels of nodes on the canvas, for an edge's ends. */
  labels: ReadonlyMap<string, string>;
}>();

const emit = defineEmits<{
  expand: [id: string];
  centre: [id: string];
  hide: [id: string];
  table: [id: string, rel: RelId];
  'open-alert': [id: number];
}>();

const router = useRouter();

/** A dashed (seen in logs) edge of the rollup: its logs can be listed. */
const hasEvidence = computed(() => !!props.edge && props.edge.style === 'logs' && EVIDENCE_RELS.has(props.edge.rel));
const showLogs = ref(false);
watch(
  () => props.edge?.id,
  () => {
    showLogs.value = false;
  }
);

const FLAG_LABELS: Partial<Record<NodeFlag, string>> = {
  threat_feed: 'on a threat feed',
  foreign: 'foreign',
  private: 'private',
  sender_only: 'sender only',
  critical: 'critical asset',
  open_vulns: 'open vulnerabilities',
  closed: 'closed',
  unmanaged: 'seen only on the network',
};

/** Application Monitoring's names for its evidence sources. */
const sourceLabel = (s: string) => factText(appSourceLabel(s));

const NOTES: Record<string, string> = {
  log_expired: 'Logs older than the retention period are deleted.',
  sender_only: 'Seen only as a log sender: parsers that extract client IPs make its peers visible.',
  no_parser: 'No installed parser extracts this.',
};
const noteText = (g: RelationGroup) => (g.note ? NOTES[g.note] ?? factText(g.note.replace(/_/g, ' ')) : '');

const typeLabel = computed(() => (props.node ? TYPE_STYLES[props.node.type]?.label ?? props.node.type : ''));
const title = computed(() => (props.node ? fullLabel(props.node.label) : ''));
const isCentre = computed(() => !!props.node && props.centres.includes(props.node.id));
const isExpanded = computed(() => !!props.node && props.expanded.includes(props.node.id));

const when = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? factText(iso) : format(d, 'yyyy-MM-dd HH:mm');
};

const facts = computed(() => {
  if (!props.node) return [];
  return Object.entries(props.node.facts)
    .filter(([, v]) => v !== null && v !== '' && v !== undefined)
    .map(([name, v]) => ({
      name: name.replace(/_/g, ' '),
      value: typeof v === 'boolean' ? (v ? 'yes' : 'no') : /(_at|_seen|last_login)$/.test(name) && typeof v === 'string' ? when(v) : factText(v),
    }));
});

const endLabel = (id: string) => props.labels.get(id) ?? fullLabel(keyOfId(id));

const alertEnd = computed<number | null>(() => {
  if (!props.edge) return null;
  for (const id of [props.edge.source, props.edge.target]) {
    if (id.startsWith('alert:')) return Number(keyOfId(id));
  }
  return null;
});

/** A route the router lets this role open (so a link never bounces to the Dashboard). */
function allowed(to: RouteLocationRaw): boolean {
  const resolved = router.resolve(to);
  if (resolved.matched.length === 0) return false;
  if (resolved.matched.some((r) => r.meta.requiresAdmin) && props.role !== 'admin') return false;
  const roles = resolved.matched.find((r) => r.meta.allowedRoles)?.meta.allowedRoles;
  return !roles || roles.includes(props.role);
}

interface OpenLink {
  label: string;
  to?: RouteLocationRaw;
  action?: () => void;
}

/** What Copy puts on the clipboard: an alert's ALR-#### reference, otherwise the key. */
const copyText = computed(() => {
  const n = props.node;
  if (!n) return '';
  const id = n.type === 'alert' ? parseAlertRef(n.key) : null;
  return id !== null ? formatAlertRef(id) : n.key;
});

const openIn = computed<OpenLink[]>(() => {
  const n = props.node;
  if (!n) return [];
  const links: OpenLink[] = [];
  switch (n.type) {
    case 'ip':
      links.push({ label: 'Threat Intel', to: { path: '/threat-intel', query: { ip: n.key } } });
      links.push({ label: 'Logs', to: { path: '/logs' } });
      break;
    case 'alert':
      links.push({ label: 'Alert details', action: () => emit('open-alert', Number(n.key)) });
      links.push({ label: 'Alerts', to: alertRefPath(Number(n.key)) });
      break;
    case 'asset':
      links.push({ label: 'Asset Inventory', to: { path: '/asset-inventory', query: { id: n.key } } });
      break;
    case 'vuln':
      links.push({ label: 'Vulnerability Management', to: { path: '/vulnerability-management' } });
      break;
    case 'rule':
      links.push({ label: 'Rules', to: { path: '/rules' } });
      break;
    case 'shipper':
    case 'shipper_tag':
      links.push({ label: 'Log Shippers', to: { path: '/shippers' } });
      break;
    case 'finding':
    case 'identity':
    case 'domain':
      links.push({ label: 'Digital Risk', to: { path: '/digital-risk' } });
      break;
    case 'endpoint':
      links.push({ label: 'Endpoints', to: { path: '/endpoints' } });
      break;
    case 'account':
      links.push({ label: 'Users', to: { path: '/users' } });
      break;
    case 'application':
      // The page opens the application's detail drawer: locations, versions, vulnerabilities.
      links.push({ label: 'Application Monitoring', to: { path: '/application-monitoring', query: { app: n.key } } });
      break;
    default:
      break;
  }
  return links.filter((l) => !l.to || allowed(l.to));
});

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    ElMessage.success('Copied');
  } catch {
    ElMessage.warning('Copy is not available in this browser.');
  }
}
</script>

<style scoped>
.details-panel {
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  min-width: 0;
}
.dp-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.dp-type {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--siembox-text-secondary);
}
.dp-title {
  font-size: 16px;
  font-weight: 600;
  overflow-wrap: anywhere;
}
.dp-flags {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}
.dp-section-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--siembox-text-secondary);
  margin-bottom: 4px;
}
.dp-rel {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  padding: 3px 0;
  border-bottom: 1px solid var(--siembox-border-color);
}
.rel-label {
  flex: 1 1 140px;
  min-width: 0;
}
.rel-count {
  font-variant-numeric: tabular-nums;
}
.rel-actions {
  margin-left: auto;
}
.rel-note {
  flex-basis: 100%;
  font-size: 12px;
  color: var(--siembox-text-secondary);
}
.dp-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.dp-actions .el-button + .el-button {
  margin-left: 0;
}
.dp-link {
  color: var(--el-color-primary);
  text-decoration: none;
  font-size: 13px;
}
.muted {
  color: var(--siembox-text-secondary);
}
.small {
  font-size: 12px;
  margin: 0;
}
.dp-empty p {
  margin: 0 0 6px;
}
</style>
