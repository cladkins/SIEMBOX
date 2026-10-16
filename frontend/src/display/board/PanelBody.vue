<script setup lang="ts">
/** Picks the component for a panel key's kind (BIG-DISPLAY.md §5.3). */
import { computed } from 'vue';
import type { PanelData } from '../types.ts';
import { splitKey } from './panelInfo.ts';
import OpenAlerts from './panels/OpenAlerts.vue';
import AlertPulse from './panels/AlertPulse.vue';
import RecentAlerts from './panels/RecentAlerts.vue';
import TopRules from './panels/TopRules.vue';
import Ingest from './panels/Ingest.vue';
import Sources from './panels/Sources.vue';
import Shippers from './panels/Shippers.vue';
import Endpoints from './panels/Endpoints.vue';
import ThreatMap from './panels/ThreatMap.vue';
import TopSources from './panels/TopSources.vue';
import DigitalRisk from './panels/DigitalRisk.vue';
import Vulnerabilities from './panels/Vulnerabilities.vue';

const props = defineProps<{ panelKey: string; data: PanelData; now: number; timezone: string | null }>();
const kind = splitKey(props.panelKey)[0];
// The server checked each panel's shape against its kind (services/display/redact.ts).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const d = computed(() => props.data as any);
</script>

<template>
  <OpenAlerts v-if="kind === 'open_alerts'" :data="d" :now="now" />
  <AlertPulse v-else-if="kind === 'alert_pulse'" :data="d" />
  <RecentAlerts v-else-if="kind === 'recent_alerts'" :data="d" :now="now" />
  <TopRules v-else-if="kind === 'top_rules'" :data="d" />
  <Ingest v-else-if="kind === 'ingest'" :data="d" />
  <Sources v-else-if="kind === 'sources'" :data="d" :timezone="timezone" />
  <Shippers v-else-if="kind === 'shippers'" :data="d" :now="now" />
  <Endpoints v-else-if="kind === 'endpoints'" :data="d" :now="now" />
  <ThreatMap v-else-if="kind === 'threat_map'" :data="d" />
  <TopSources v-else-if="kind === 'top_sources'" :data="d" :now="now" />
  <DigitalRisk v-else-if="kind === 'digital_risk'" :data="d" />
  <Vulnerabilities v-else-if="kind === 'vulnerabilities'" :data="d" />
</template>
