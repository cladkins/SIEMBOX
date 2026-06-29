<template>
  <div class="ai-analyst-page">
    <AnalystChat embedded />
  </div>
</template>

<script setup lang="ts">
import AnalystChat from '@/components/AnalystChat.vue';
</script>

<style scoped>
/* Fill the main content area (header 60px + footer 28px + main padding ~40px). */
.ai-analyst-page {
  height: calc(100vh - 132px);
  min-height: 460px;
}
@media (max-width: 768px) {
  .ai-analyst-page {
    height: calc(100vh - 116px);
  }
}
</style>
