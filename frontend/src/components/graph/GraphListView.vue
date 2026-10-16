<template>
  <div class="graph-list" data-testid="graph-list">
    <h3 class="list-title">Nodes ({{ nodes.length }})</h3>
    <el-table
      :data="nodeRows"
      size="small"
      row-key="id"
      highlight-current-row
      :current-row-key="selected ?? undefined"
      :row-class-name="rowClass"
      max-height="420"
      empty-text="Nothing on the graph"
      @row-click="(row: NodeRow) => emit('select', row.id, 'node')"
    >
      <el-table-column label="Type" width="140" sortable :sort-by="'typeLabel'">
        <template #default="{ row }">{{ row.typeLabel }}</template>
      </el-table-column>
      <el-table-column label="Name" min-width="200">
        <template #default="{ row }">
          <span
            tabindex="0"
            class="row-focus"
            @keydown.enter.prevent="emit('expand', row.id)"
            @keydown.space.prevent="emit('select', row.id, 'node')"
            >{{ row.label }}</span
          >
          <el-tag v-if="row.centre" size="small" class="tag">centre</el-tag>
          <el-tag v-for="f in row.flags" :key="f" size="small" type="warning" class="tag">{{ f }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="Links" width="80" align="right" prop="degree" sortable />
      <el-table-column width="96">
        <template #default="{ row }">
          <el-button v-if="row.expandable" link size="small" @click.stop="emit('expand', row.id)">Expand</el-button>
        </template>
      </el-table-column>
    </el-table>

    <h3 class="list-title">Links ({{ edges.length }})</h3>
    <el-table
      :data="edgeRows"
      size="small"
      row-key="id"
      max-height="320"
      empty-text="No links"
      @row-click="(row: EdgeRow) => emit('select', row.id, 'edge')"
    >
      <el-table-column label="From" min-width="150" prop="from" />
      <el-table-column label="Link" min-width="170" prop="rel" />
      <el-table-column label="To" min-width="150" prop="to" />
      <el-table-column label="Kind" width="130" prop="style" />
      <el-table-column label="Count" width="70" align="right" prop="count" />
    </el-table>
    <p v-if="groupCount > 0" class="muted">
      {{ groupCount }} relation{{ groupCount === 1 ? ' has' : 's have' }} more neighbours than shown: open a node's relations in the
      details panel to see them all.
    </p>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { fullLabel } from '@/graph/labels';
import { TYPE_STYLES, edgeLabel } from '@/graph/style';
import type { GraphEdge, GraphNode, NodeType } from '@/graph/types';

/** The graph as tables: keyboard and screen-reader friendly, and the fallback when the canvas can't start. */
const props = defineProps<{
  nodes: GraphNode[];
  edges: GraphEdge[];
  centres: readonly string[];
  /** Nodes already expanded (no Expand button). */
  expanded: readonly string[];
  selected: string | null;
  groupCount: number;
}>();

const emit = defineEmits<{ select: [id: string, kind: 'node' | 'edge']; expand: [id: string] }>();

interface NodeRow {
  id: string;
  type: NodeType;
  typeLabel: string;
  label: string;
  flags: string[];
  centre: boolean;
  degree: number;
  expandable: boolean;
}
interface EdgeRow {
  id: string;
  from: string;
  to: string;
  rel: string;
  style: string;
  count: number | string;
}

const STYLE_SHORT = { recorded: 'recorded', logs: 'seen in logs', heuristic: 'matched' } as const;

const labelOf = computed(() => new Map(props.nodes.map((n) => [n.id, fullLabel(n.label)])));

const nodeRows = computed<NodeRow[]>(() => {
  const degree = new Map<string, number>();
  for (const e of props.edges) {
    degree.set(e.source, (degree.get(e.source) ?? 0) + 1);
    degree.set(e.target, (degree.get(e.target) ?? 0) + 1);
  }
  const order = Object.keys(TYPE_STYLES);
  return props.nodes
    .map((n) => ({
      id: n.id,
      type: n.type,
      typeLabel: TYPE_STYLES[n.type]?.label ?? n.type,
      label: fullLabel(n.label),
      flags: n.flags.filter((f) => f === 'threat_feed' || f === 'critical' || f === 'closed'),
      centre: props.centres.includes(n.id),
      degree: degree.get(n.id) ?? 0,
      expandable: n.expandable && !props.expanded.includes(n.id),
    }))
    .sort((a, b) => Number(b.centre) - Number(a.centre) || order.indexOf(a.type) - order.indexOf(b.type) || a.label.localeCompare(b.label));
});

const edgeRows = computed<EdgeRow[]>(() =>
  props.edges.map((e) => ({
    id: e.id,
    from: labelOf.value.get(e.source) ?? e.source,
    to: labelOf.value.get(e.target) ?? e.target,
    rel: edgeLabel(e.rel),
    style: STYLE_SHORT[e.style] ?? e.style,
    count: e.count ?? '',
  }))
);

const rowClass = ({ row }: { row: NodeRow }) => (row.id === props.selected ? 'is-selected' : '');
</script>

<style scoped>
.graph-list {
  padding: 8px 12px;
}
.list-title {
  font-size: 14px;
  margin: 8px 0;
}
.tag {
  margin-left: 6px;
}
.muted {
  color: var(--siembox-text-secondary);
  font-size: 12px;
}
.row-focus:focus-visible {
  outline: 2px solid var(--el-color-primary);
  outline-offset: 2px;
}
:deep(.is-selected) td {
  background: var(--el-color-primary-light-9) !important;
}
</style>
