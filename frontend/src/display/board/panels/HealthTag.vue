<script setup lang="ts">
/** ✓ OK in neutral grey (not green); ▲ warning on amber; ✕ down on red. Always with a word. */
defineProps<{ level: 'ok' | 'warning' | 'down'; text: string }>();
</script>

<template>
  <span v-if="level === 'ok'" class="bd-health bd-muted">✓ {{ text }}</span>
  <span v-else class="bd-health bd-tag" :class="level === 'down' ? 'bd-fill-critical' : 'bd-fill-warning'"
    >{{ level === 'down' ? '✕' : '▲' }} {{ text }}</span
  >
</template>

<style scoped>
.bd-health {
  font-size: var(--bd-label);
  font-weight: 600;
  white-space: nowrap;
}
</style>
