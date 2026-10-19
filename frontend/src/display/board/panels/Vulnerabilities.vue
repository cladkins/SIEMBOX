<script setup lang="ts">
import type { Vulnerabilities } from '../../types.ts';
import { compact } from '../../format.ts';
import SevRows from './SevRows.vue';

defineProps<{ data: Vulnerabilities }>();
</script>

<template>
  <p v-if="!data.scanned" class="bd-label bd-muted bd-empty">No scans yet</p>
  <template v-else>
    <SevRows :counts="data.open_by_severity" />
    <p class="bd-label bd-muted bd-foot">{{ compact(data.affected_assets) }} affected assets</p>
  </template>
</template>

<style scoped>
.bd-empty {
  margin: auto 0;
}
.bd-foot {
  margin: auto 0 0;
}
</style>
