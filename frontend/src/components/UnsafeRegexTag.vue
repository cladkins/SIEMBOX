<template>
  <el-tooltip v-if="safety && safety.status === 'vulnerable'" :content="unsafeRegexTooltip(safety)" placement="top">
    <el-tag type="danger" size="small" effect="dark" class="unsafe-regex-tag" data-testid="unsafe-regex-tag">
      Unsafe regex
    </el-tag>
  </el-tooltip>
</template>

<script setup lang="ts">
import { unsafeRegexTooltip, type RegexSafetySummary } from '@/utils/regexSafety';

defineProps<{ safety?: RegexSafetySummary }>();
</script>

<style scoped>
.unsafe-regex-tag {
  margin-left: 6px;
}
</style>
