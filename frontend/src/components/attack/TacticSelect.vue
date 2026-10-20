<template>
  <el-select
    :model-value="modelValue ?? undefined"
    clearable
    :placeholder="placeholder"
    :loading="!index"
    :teleported="teleported"
    class="tactic-select"
    data-testid="tactic-select"
    @update:model-value="(v: string | undefined) => emit('update:modelValue', v || null)"
  >
    <el-option v-for="t in index?.tactics ?? []" :key="t.shortname" :label="t.name" :value="t.shortname">
      {{ t.name }} <span class="tactic-option-id">{{ t.id }}</span>
    </el-option>
  </el-select>
</template>

<script setup lang="ts">
import { useAttackIndex } from '@/composables/useAttackIndex';

/** Pick one ATT&CK tactic (hyphenated shortname, matrix order). */
withDefaults(defineProps<{ modelValue?: string | null; placeholder?: string; teleported?: boolean }>(), {
  modelValue: null,
  placeholder: 'Tactic',
  teleported: true,
});
const emit = defineEmits<{ 'update:modelValue': [value: string | null] }>();
const index = useAttackIndex();
</script>

<style scoped>
.tactic-option-id {
  margin-left: 6px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
</style>
