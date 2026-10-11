<template>
  <!-- Required wherever HIBP data is shown: its data is licensed CC BY 4.0. -->
  <p class="hibp-attribution">
    Breach data from
    <a :href="HIBP_HOME_URL" target="_blank" rel="noopener noreferrer">Have I Been Pwned</a>,
    licensed under
    <a :href="CC_BY_4_URL" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>.
  </p>
</template>

<script setup lang="ts">
import { CC_BY_4_URL, HIBP_HOME_URL } from '@/utils/exposure';
</script>

<style scoped>
.hibp-attribution {
  margin: 12px 0 0;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.hibp-attribution a {
  color: var(--el-color-primary);
  text-decoration: none;
}

.hibp-attribution a:hover {
  text-decoration: underline;
}
</style>
