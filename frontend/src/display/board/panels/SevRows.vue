<script setup lang="ts">
/** Counts by severity in the fixed order, shape and word first; only critical and high in colour. */
import type { Sev } from '../../types.ts';
import { SEV_COLOR, SEV_LABEL, SEV_ORDER, SEV_SHAPE } from '../severity.ts';
import Num from '../Num.vue';

defineProps<{ counts: Record<Sev, number>; hideZeroLow?: boolean }>();
const coloured = (sev: Sev) => sev === 'critical' || sev === 'high';
</script>

<template>
  <ul class="bd-list">
    <li v-for="sev in SEV_ORDER" :key="sev" class="bd-row">
      <span class="bd-row-label" :style="coloured(sev) && counts[sev] > 0 ? { color: SEV_COLOR[sev] } : undefined">
        {{ SEV_SHAPE[sev] }} {{ SEV_LABEL[sev] }}
      </span>
      <span class="bd-row-value"><Num :value="counts[sev]" /></span>
    </li>
  </ul>
</template>
