<template>
  <div class="relation-table" data-testid="graph-relation-table">
    <div class="rt-header">
      <strong>{{ fullLabel(group.label) }}</strong>
      <span class="muted">{{ totalText }}</span>
      <el-button link size="small" @click="emit('close')">Back</el-button>
    </div>
    <div class="rt-controls">
      <el-input v-model="q" size="small" clearable placeholder="Filter" aria-label="Filter this relation" @input="debouncedLoad" />
      <el-select v-model="sort" size="small" aria-label="Sort by" style="width: 130px" @change="load(0)">
        <el-option label="Count" value="count" />
        <el-option label="Last seen" value="last_seen" />
        <el-option label="First seen" value="first_seen" />
      </el-select>
    </div>
    <el-alert v-if="error" type="error" :closable="false" show-icon :title="error">
      <el-button link type="primary" size="small" @click="load(offset)">Try again</el-button>
    </el-alert>
    <p v-if="capped" class="muted small">Showing the {{ TOTAL_CAP.toLocaleString('en-US') }} most recent.</p>
    <p v-if="note" class="muted small">{{ note }}</p>
    <el-table
      v-loading="loading"
      :data="rows"
      size="small"
      max-height="380"
      row-key="id"
      empty-text="Nothing here"
      @selection-change="(sel: Row[]) => (selected = sel)"
    >
      <el-table-column type="selection" width="36" :selectable="(row: Row) => !row.onCanvas" />
      <el-table-column label="Name" min-width="150">
        <template #default="{ row }">
          <span :title="row.label">{{ row.label }}</span>
          <el-tag v-if="row.onCanvas" size="small" type="info" class="on-canvas">on graph</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="Count" width="70" align="right">
        <template #default="{ row }">{{ row.count ?? '' }}</template>
      </el-table-column>
      <el-table-column label="Last seen" width="120">
        <template #default="{ row }">{{ row.lastSeen }}</template>
      </el-table-column>
    </el-table>
    <div class="rt-footer">
      <el-button size="small" :disabled="offset === 0 || loading" @click="load(Math.max(0, offset - RELATION_PAGE_SIZE))">Previous</el-button>
      <el-button size="small" :disabled="nextOffset === null || loading" @click="load(nextOffset ?? 0)">Next</el-button>
      <el-button size="small" type="primary" :disabled="selected.length === 0 || room <= 0" @click="add">
        Add {{ selected.length || '' }} to graph
      </el-button>
    </div>
    <p v-if="room <= 0" class="muted small">The graph is at its node limit. Hide some nodes first.</p>
    <p v-else-if="selected.length > room" class="muted small">Only {{ room }} more fit on the graph; the first {{ room }} are added.</p>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { format } from 'date-fns';
import { api, type GraphRelationParams } from '@/services/api';
import { formatCount, fullLabel } from '@/graph/labels';
import { RELATION_PAGE_SIZE, TOTAL_CAP, type RelationGroup, type RelationItem, type RelationResponse } from '@/graph/types';
import { graphErrorMessage } from '@/graph/errors';

const props = defineProps<{
  centreId: string;
  group: RelationGroup;
  /** window / around / vuln_status of the view. */
  params: Omit<GraphRelationParams, 'entity' | 'rel'>;
  /** Ids already on the canvas. */
  onCanvas: ReadonlySet<string>;
  /** Nodes that still fit on the canvas. */
  room: number;
}>();

const emit = defineEmits<{ add: [items: RelationItem[]]; close: [] }>();

interface Row {
  id: string;
  label: string;
  count?: number;
  lastSeen: string;
  onCanvas: boolean;
  item: RelationItem;
}

const q = ref('');
const sort = ref<'count' | 'last_seen' | 'first_seen'>('count');
const loading = ref(false);
const error = ref('');
const items = ref<RelationItem[]>([]);
const offset = ref(0);
const nextOffset = ref<number | null>(null);
const total = ref(0);
const capped = ref(false);
const note = ref('');
const selected = ref<Row[]>([]);
let controller: AbortController | null = null;
let timer: ReturnType<typeof setTimeout> | null = null;

const rows = computed<Row[]>(() =>
  items.value.map((item) => ({
    id: item.node.id,
    label: fullLabel(item.node.label),
    count: item.edge.count,
    lastSeen: item.edge.last_seen ? format(new Date(item.edge.last_seen), 'MMM d HH:mm') : '',
    onCanvas: props.onCanvas.has(item.node.id),
    item,
  }))
);

const totalText = computed(() => `${formatCount(total.value, capped.value)} in all`);

async function load(at: number) {
  controller?.abort();
  controller = new AbortController();
  loading.value = true;
  error.value = '';
  try {
    const { data } = await api.graphRelation(
      {
        ...props.params,
        entity: props.centreId,
        rel: props.group.rel,
        offset: at,
        limit: RELATION_PAGE_SIZE,
        q: q.value.trim() || undefined,
        sort: sort.value,
        order: 'desc',
      },
      controller.signal
    );
    const answer = data as RelationResponse;
    items.value = answer.items;
    offset.value = at;
    nextOffset.value = answer.next_offset;
    total.value = answer.total;
    capped.value = answer.total_capped;
    note.value = answer.status === 'timeout' ? 'This relation took too long; what is shown may be incomplete.' : '';
  } catch (err) {
    const message = graphErrorMessage(err);
    if (message) error.value = message;
  } finally {
    loading.value = false;
  }
}

function debouncedLoad() {
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => load(0), 300);
}

function add() {
  emit('add', selected.value.slice(0, Math.max(0, props.room)).map((r) => r.item));
  selected.value = [];
}

watch(
  () => [props.centreId, props.group.rel],
  () => {
    q.value = '';
    load(0);
  },
  { immediate: true }
);

onBeforeUnmount(() => {
  controller?.abort();
  if (timer) clearTimeout(timer);
});
</script>

<style scoped>
.relation-table {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.rt-header {
  display: flex;
  align-items: baseline;
  gap: 8px;
  flex-wrap: wrap;
}
.rt-header .el-button {
  margin-left: auto;
}
.rt-controls,
.rt-footer {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.rt-footer .el-button + .el-button {
  margin-left: 0;
}
.muted {
  color: var(--siembox-text-secondary);
}
.small {
  font-size: 12px;
  margin: 0;
}
.on-canvas {
  margin-left: 6px;
}
</style>
