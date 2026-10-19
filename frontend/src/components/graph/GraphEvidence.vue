<template>
  <div class="evidence" data-testid="graph-evidence">
    <div class="ev-head">
      <span class="ev-title">Logs</span>
      <el-select
        v-if="days.length > 1"
        v-model="day"
        size="small"
        class="ev-day"
        aria-label="Day"
        @change="load(day)"
      >
        <el-option v-for="d in days" :key="d" :label="d" :value="d" />
      </el-select>
      <span v-else-if="day" class="muted small">{{ day }}</span>
      <el-button link size="small" @click="emit('close')">Close</el-button>
    </div>
    <div v-if="loading" class="muted small">Loading…</div>
    <el-alert v-else-if="error" type="warning" :closable="false" :title="error" show-icon />
    <template v-else>
      <p v-if="expired" class="muted small">Logs for {{ day }} are past the retention period and have been deleted.</p>
      <p v-else-if="partial" class="muted small">Too many events that day to list in time; try a narrower pair or another day.</p>
      <p v-else-if="!day" class="muted small">No logs for this link are kept any more.</p>
      <p v-else-if="logs.length === 0" class="muted small">No logs for this link on {{ day }}.</p>
      <ul v-else class="ev-list">
        <li v-for="log in logs" :key="log.id" class="ev-line">
          <div class="ev-meta">
            <span>{{ when(log.created_at) }}</span>
            <span v-if="log.hostname">{{ log.hostname }}</span>
            <span v-if="log.sender_ip">from {{ log.sender_ip }}</span>
            <span v-if="log.parser">· {{ log.parser }}</span>
          </div>
          <div class="ev-msg">{{ log.message }}</div>
        </li>
      </ul>
      <p v-if="logs.length" class="muted small">The latest {{ logs.length }} of that day. Counts on the link cover whole days.</p>
    </template>
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue';
import { format } from 'date-fns';
import { api } from '@/services/api';
import { graphErrorMessage } from '@/graph/errors';
import type { EvidenceLog, EvidenceResponse, GraphEdge } from '@/graph/types';

const props = defineProps<{ edge: GraphEdge }>();
const emit = defineEmits<{ close: [] }>();

const loading = ref(false);
const error = ref('');
const day = ref<string | null>(null);
const days = ref<string[]>([]);
const logs = ref<EvidenceLog[]>([]);
const partial = ref(false);
const expired = ref(false);
let controller: AbortController | null = null;

const when = (iso: string | null) => {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : format(d, 'yyyy-MM-dd HH:mm:ss');
};

async function load(onDay?: string | null) {
  controller?.abort();
  controller = new AbortController();
  loading.value = true;
  error.value = '';
  try {
    const res = await api.graphEvidence(
      { rel: props.edge.rel, a: props.edge.source, b: props.edge.target, ...(onDay ? { day: onDay } : {}) },
      controller.signal
    );
    const body = res.data as EvidenceResponse;
    day.value = body.day;
    if (body.days.length) days.value = body.days;
    logs.value = body.logs;
    partial.value = body.partial;
    expired.value = body.expired;
  } catch (err) {
    if ((err as { name?: string })?.name === 'CanceledError' || (err as { name?: string })?.name === 'AbortError') return;
    error.value = graphErrorMessage(err);
  } finally {
    loading.value = false;
  }
}

watch(
  () => props.edge.id,
  () => {
    days.value = [];
    void load();
  },
  { immediate: true }
);
onBeforeUnmount(() => controller?.abort());
</script>

<style scoped>
.evidence {
  display: flex;
  flex-direction: column;
  gap: 6px;
  border-top: 1px solid var(--siembox-border-color);
  padding-top: 8px;
  min-width: 0;
}
.ev-head {
  display: flex;
  align-items: center;
  gap: 8px;
}
.ev-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--siembox-text-secondary);
}
.ev-day {
  width: 130px;
}
.ev-head .el-button {
  margin-left: auto;
}
.ev-list {
  list-style: none;
  margin: 0;
  padding: 0;
  max-height: 360px;
  overflow-y: auto;
}
.ev-line {
  padding: 4px 0;
  border-bottom: 1px solid var(--siembox-border-color);
}
.ev-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  font-size: 11px;
  color: var(--siembox-text-secondary);
}
.ev-msg {
  font-family: var(--el-font-family-mono, monospace);
  font-size: 12px;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}
.muted {
  color: var(--siembox-text-secondary);
}
.small {
  font-size: 12px;
  margin: 0;
}
</style>
