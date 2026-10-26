<template>
  <el-autocomplete
    ref="input"
    v-model="text"
    class="graph-search"
    :fetch-suggestions="suggest"
    :debounce="250"
    :trigger-on-focus="false"
    :placeholder="placeholder"
    clearable
    :prefix-icon="Search"
    value-key="label"
    aria-label="Search the Context Graph"
    data-testid="graph-search"
    @select="onSelect"
    @keydown.enter="onEnter"
  >
    <template #default="{ item }">
      <div class="candidate">
        <span class="type">{{ typeLabel(item.type) }}</span>
        <span class="label">{{ fullLabel(item.label) }}</span>
        <span v-if="item.hint" class="hint">{{ factText(item.hint) }}</span>
      </div>
    </template>
  </el-autocomplete>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { Search } from '@element-plus/icons-vue';
import { api } from '@/services/api';
import { factText, fullLabel } from '@/graph/labels';
import { TYPE_STYLES } from '@/graph/style';
import type { NodeType, SearchCandidate, SearchResponse } from '@/graph/types';

/**
 * Typed candidates for what was typed (GET /api/graph/search). Enter or a
 * click adds the candidate as a centre; Shift+Enter replaces the centres.
 */
withDefaults(defineProps<{ placeholder?: string }>(), {
  placeholder: 'IP, user, host, domain, application, alert #, CVE…',
});

const emit = defineEmits<{ pick: [entity: string, replace: boolean]; error: [message: string] }>();

const text = ref('');
const input = ref<{ focus: () => void } | null>(null);
let shift = false;
let controller: AbortController | null = null;
let last: SearchCandidate[] = [];

const typeLabel = (type: NodeType) => TYPE_STYLES[type]?.label ?? type;

async function suggest(query: string, cb: (items: SearchCandidate[]) => void) {
  const q = query.trim();
  if (!q) {
    cb([]);
    return;
  }
  controller?.abort();
  controller = new AbortController();
  try {
    const { data } = await api.graphSearch(q, controller.signal);
    last = (data as SearchResponse).candidates ?? [];
    cb(last);
  } catch (err) {
    const status = (err as { response?: { status?: number; data?: { message?: string } } }).response?.status;
    if (status === 400) {
      emit('error', (err as { response: { data?: { message?: string } } }).response.data?.message || 'That search is not valid.');
    }
    cb([]);
  }
}

function onEnter(event: KeyboardEvent) {
  shift = event.shiftKey;
}

function onSelect(item: Record<string, unknown>) {
  const candidate = item as unknown as SearchCandidate;
  emit('pick', candidate.entity, shift);
  shift = false;
  text.value = '';
}

defineExpose({
  focus: () => input.value?.focus(),
});
</script>

<style scoped>
.graph-search {
  width: 340px;
  max-width: 100%;
}
.candidate {
  display: flex;
  gap: 8px;
  align-items: baseline;
  min-width: 0;
}
.candidate .type {
  font-size: 12px;
  color: var(--siembox-text-secondary);
  flex: none;
  min-width: 64px;
}
.candidate .label {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.candidate .hint {
  font-size: 12px;
  color: var(--siembox-text-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
