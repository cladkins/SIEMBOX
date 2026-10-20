<template>
  <el-select
    :model-value="modelValue ?? undefined"
    filterable
    :clearable="clearable"
    :filter-method="onFilter"
    :placeholder="placeholder"
    :loading="!index"
    :disabled="disabled"
    :teleported="teleported"
    class="technique-select"
    data-testid="technique-select"
    @update:model-value="onPick"
    @visible-change="onVisible"
  >
    <el-option v-for="t in options" :key="t.id" :label="`${t.id} ${t.fullName}`" :value="t.id">
      <span class="technique-option-id">{{ t.id }}</span>
      <span class="technique-option-name">{{ t.fullName }}</span>
    </el-option>
    <template #empty>
      <div class="technique-select-empty">{{ index ? 'No technique matches' : 'Loading ATT&CK techniques…' }}</div>
    </template>
  </el-select>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';
import { useAttackIndex } from '@/composables/useAttackIndex';
import { searchTechniques } from '@/utils/attack';

/**
 * Pick one ATT&CK technique by ID or name. The list shows the best 50 matches
 * at a time (the dataset has ~700 techniques and sub-techniques), so typing
 * narrows it. The selected value stays listed so its label renders.
 */
const props = withDefaults(
  defineProps<{
    modelValue?: string | null;
    placeholder?: string;
    clearable?: boolean;
    disabled?: boolean;
    teleported?: boolean;
  }>(),
  { modelValue: null, placeholder: 'Technique (ID or name)', clearable: true, disabled: false, teleported: true }
);
const emit = defineEmits<{ 'update:modelValue': [value: string | null]; pick: [value: string] }>();

const index = useAttackIndex();
const query = ref('');
const options = computed(() => {
  const found = searchTechniques(index.value, query.value, 50);
  const selected = props.modelValue ? index.value?.byId.get(props.modelValue) : undefined;
  return selected && !found.includes(selected) ? [selected, ...found] : found;
});

function onFilter(q: string) {
  query.value = q;
}

function onVisible(open: boolean) {
  if (!open) query.value = '';
}

function onPick(value: string | undefined) {
  const v = value || null;
  emit('update:modelValue', v);
  if (v) emit('pick', v);
}
</script>

<style scoped>
.technique-option-id {
  display: inline-block;
  min-width: 80px;
  font-variant-numeric: tabular-nums;
  color: var(--el-text-color-secondary);
}
.technique-option-name {
  margin-left: 6px;
}
.technique-select-empty {
  padding: 10px;
  font-size: 13px;
  color: var(--el-text-color-secondary);
  text-align: center;
}
</style>
