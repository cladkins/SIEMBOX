<script setup lang="ts">
import type { TopRules } from '../../types.ts';
import { CATEGORY_LABEL, SEV_COLOR, SEV_LABEL, SEV_SHAPE } from '../severity.ts';
import Num from '../Num.vue';

defineProps<{ data: TopRules }>();
</script>

<template>
  <p v-if="data.items.length === 0" class="bd-label bd-muted bd-empty">No alerts in this window</p>
  <ul v-else class="bd-list">
    <li v-for="(item, i) in data.items.slice(0, 6)" :key="i" class="bd-row">
      <span :style="{ color: SEV_COLOR[item.worst_severity] }" :aria-label="SEV_LABEL[item.worst_severity]">{{
        SEV_SHAPE[item.worst_severity]
      }}</span>
      <span class="bd-row-label">{{ item.label || CATEGORY_LABEL[item.category] }}</span>
      <span class="bd-row-value"><Num :value="item.count" /></span>
    </li>
  </ul>
</template>

<style scoped>
.bd-empty {
  margin: auto 0;
}
</style>
