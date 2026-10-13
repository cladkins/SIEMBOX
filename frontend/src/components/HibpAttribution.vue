<template>
  <!-- Breach data from HIBP is licensed CC BY 4.0: credit it, with a link, wherever it is shown.
       Pwned Passwords needs no attribution, but HIBP welcomes it. -->
  <p class="hibp-attribution">
    <template v-if="variant === 'passwords'">
      Password data from
      <a :href="HIBP_PASSWORDS_URL" target="_blank" rel="noopener noreferrer">Pwned Passwords</a>
      by Have I Been Pwned.
    </template>
    <template v-else>
      Breach data from
      <a :href="HIBP_HOME_URL" target="_blank" rel="noopener noreferrer">Have I Been Pwned</a>,
      licensed under
      <a :href="CC_BY_4_URL" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>.
    </template>
  </p>
</template>

<script setup lang="ts">
import { CC_BY_4_URL, HIBP_HOME_URL, HIBP_PASSWORDS_URL } from '@/utils/exposure';

withDefaults(defineProps<{ variant?: 'breach' | 'passwords' }>(), { variant: 'breach' });
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
