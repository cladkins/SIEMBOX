<script setup lang="ts">
import type { ThreatMap } from '../../types.ts';
import { compact, countryName } from '../../format.ts';
import Num from '../Num.vue';
import WorldMap from '../charts/WorldMap.vue';

defineProps<{ data: ThreatMap }>();
</script>

<template>
  <p v-if="data.countries.length === 0" class="bd-label bd-muted bd-empty">No alerts from public addresses in this window</p>
  <div v-else class="bd-threat">
    <WorldMap class="bd-threat-map" :countries="data.countries" />
    <div class="bd-threat-side">
      <ul class="bd-list">
        <li v-for="c in data.countries.slice(0, 5)" :key="c.code" class="bd-row">
          <span class="bd-row-label">{{ countryName(c.code) }}</span>
          <span class="bd-row-value"><Num :value="c.count" /></span>
        </li>
      </ul>
      <p class="bd-small bd-threat-foot">{{ compact(data.located) }} of {{ compact(data.total_in_window) }} alerts had a public address</p>
    </div>
  </div>
</template>

<style scoped>
.bd-empty {
  margin: auto 0;
}
.bd-threat {
  flex: 1 1 auto;
  display: flex;
  gap: 2vh;
  min-height: 0;
}
.bd-threat-map {
  flex: 3 1 0;
}
.bd-threat-side {
  flex: 2 1 0;
  min-width: 0;
  display: flex;
  flex-direction: column;
}
.bd-threat-foot {
  margin: auto 0 0;
}
</style>
