<template>
  <div class="ranked-bar-list">
    <div
      v-for="item in items"
      :key="item.key"
      class="bar-row"
      :class="{ 'is-clickable': clickable }"
      @click="onClick(item)"
    >
      <span class="bar-label">{{ item.label }}</span>
      <span class="bar-track">
        <span class="bar-fill" :style="{ width: fillPct(item.value) + '%', backgroundColor: item.color }" />
      </span>
      <span class="bar-value">{{ item.value.toLocaleString() }}</span>
    </div>
    <div v-if="items.length === 0" class="bar-empty">No data</div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

interface BarItem {
  key: string;
  label: string;
  value: number;
  color: string;
}

const props = withDefaults(defineProps<{ items: BarItem[]; clickable?: boolean }>(), {
  clickable: true,
});
const emit = defineEmits<{ (e: 'item-click', key: string): void }>();

const maxValue = computed(() => Math.max(1, ...props.items.map((i) => i.value)));

// A nonzero value always gets a visible sliver, even when tiny next to the
// max — otherwise a count of 1 next to a count of 200 renders as nothing.
function fillPct(value: number): number {
  if (value <= 0) return 0;
  return Math.max(3, (value / maxValue.value) * 100);
}

function onClick(item: BarItem) {
  if (props.clickable) emit('item-click', item.key);
}
</script>

<style scoped>
.ranked-bar-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 4px 0;
}

.bar-row {
  display: grid;
  grid-template-columns: 88px 1fr 50px;
  align-items: center;
  gap: 12px;
  padding: 5px 8px;
  border-radius: 4px;
  transition: background-color 0.15s;
}

.bar-row.is-clickable {
  cursor: pointer;
}

.bar-row.is-clickable:hover {
  background-color: var(--siembox-bg-color, #f5f7fa);
}

.bar-label {
  font-size: 13px;
  color: var(--siembox-text-color);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.bar-track {
  height: 10px;
  border-radius: 5px;
  background: var(--siembox-bg-color, #f0f2f5);
  overflow: hidden;
}

.bar-fill {
  display: block;
  height: 100%;
  border-radius: 5px;
  transition: width 0.3s ease;
}

.bar-value {
  font-size: 13px;
  font-weight: 600;
  color: var(--siembox-text-color);
  text-align: right;
}

.bar-empty {
  padding: 24px 0;
  text-align: center;
  color: var(--siembox-text-secondary, #909399);
  font-size: 13px;
}
</style>
