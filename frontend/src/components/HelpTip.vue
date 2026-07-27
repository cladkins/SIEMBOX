<template>
  <el-tooltip :content="text" placement="top" :show-after="150" popper-class="help-tip-popper">
    <el-icon class="help-tip-icon" :size="14"><InfoFilled /></el-icon>
  </el-tooltip>
</template>

<script setup lang="ts">
import { InfoFilled } from '@element-plus/icons-vue';

defineProps<{ text: string }>();
</script>

<style scoped>
.help-tip-icon {
  margin-left: 4px;
  color: var(--el-text-color-secondary);
  cursor: help;
  vertical-align: -2px;
}
</style>

<style>
/* Not scoped: popper renders outside the component tree. */
.help-tip-popper {
  max-width: 340px;
  line-height: 1.5;
}
</style>
