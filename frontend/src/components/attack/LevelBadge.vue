<template>
  <el-tooltip :content="info.description" placement="top" :disabled="!tooltip">
    <span :class="['attack-level-badge', excluded ? 'is-excluded' : `is-${level}`]" data-testid="level-badge">
      <span class="attack-level-mark" aria-hidden="true">{{ info.mark }}</span>
      {{ info.label }}<template v-if="level === 'proven' && provenBy && !excluded"> ({{ provenBy }})</template>
    </span>
  </el-tooltip>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { EXCLUDED_INFO, LEVEL_INFO, type CoverageLevel } from '@/utils/attack';

/** A coverage level as mark + text on its colour (never colour alone). */
const props = withDefaults(
  defineProps<{ level: CoverageLevel; excluded?: boolean; provenBy?: string | null; tooltip?: boolean }>(),
  { excluded: false, provenBy: null, tooltip: true }
);
const info = computed(() => (props.excluded ? EXCLUDED_INFO : LEVEL_INFO[props.level]));
</script>

<style scoped>
.attack-level-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 1px 8px;
  border-radius: 10px;
  border: 1px solid var(--el-border-color);
  font-size: 12px;
  line-height: 18px;
  color: var(--el-text-color-primary);
  white-space: nowrap;
}
.attack-level-mark {
  font-weight: 700;
}
.is-none {
  background: var(--el-fill-color-lighter);
  color: var(--el-text-color-secondary);
}
.is-disabled {
  background: var(--el-color-info-light-8);
  border-color: var(--el-color-info-light-5);
}
.is-no_data {
  background: var(--el-color-warning-light-8);
  border-color: var(--el-color-warning);
}
.is-covered {
  background: var(--el-color-success-light-8);
  border-color: var(--el-color-success-light-3);
}
.is-proven {
  background: var(--el-color-success-light-5);
  border-color: var(--el-color-success-dark-2);
  font-weight: 600;
}
.is-excluded {
  border-style: dashed;
  color: var(--el-text-color-secondary);
  font-style: italic;
}
</style>
