<script setup lang="ts">
import type { DigitalRisk } from '../../types.ts';
import Num from '../Num.vue';
import SevRows from './SevRows.vue';

defineProps<{ data: DigitalRisk }>();
</script>

<template>
  <p v-if="!data.configured" class="bd-label bd-muted bd-empty">Digital Risk is not set up</p>
  <template v-else>
    <SevRows :counts="data.open_by_severity" />
    <ul class="bd-list bd-foot">
      <li class="bd-row bd-muted">
        <span class="bd-row-label">Accounts to reset</span><span class="bd-row-value"><Num :value="data.accounts_to_reset" /></span>
      </li>
      <li class="bd-row bd-muted">
        <span class="bd-row-label">Impersonation open</span><span class="bd-row-value"><Num :value="data.impersonation_open" /></span>
      </li>
      <li class="bd-row bd-muted">
        <span class="bd-row-label">New in 7 days</span><span class="bd-row-value"><Num :value="data.new_7d" /></span>
      </li>
    </ul>
  </template>
</template>

<style scoped>
.bd-empty {
  margin: auto 0;
}
.bd-foot {
  margin-top: auto;
}
</style>
