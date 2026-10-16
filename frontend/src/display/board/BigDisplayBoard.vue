<script setup lang="ts">
/**
 * The shared wall renderer (BIG-DISPLAY.md §5.2): the strip (name, view,
 * alarm chips, view n/N, freshness, clock), the grid for the current view,
 * the rotation bar and the attribution line. It takes everything as props
 * and holds no stores and no API client, so the display page (link mode) and
 * later the signed-in app (session and preview modes) render the same board.
 */
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import type { DisplaySnapshot } from '../types.ts';
import type { BoardStatus } from './status.ts';
import { clockText, duration, freshnessText } from '../format.ts';
import { gridLayout } from './layout.ts';
import { ATTRIBUTION_TEXT, panelTitle, viewAttributions } from './panelInfo.ts';
import PanelFrame from './PanelFrame.vue';
import PanelBody from './PanelBody.vue';
import './theme.css';

const props = defineProps<{
  snapshot: DisplaySnapshot;
  viewIndex: number;
  status: BoardStatus;
  mode: 'link' | 'session' | 'preview';
}>();

const FRAME_MS = 60_000;

const serverNow = computed(() => props.status.deviceNow + props.status.serverOffset);
const views = computed(() => props.snapshot.display.views);
const view = computed(() => views.value[Math.min(props.viewIndex, Math.max(0, views.value.length - 1))]);
/** Forbidden panels (signed-in mode) are dropped from the view. */
const panelKeys = computed(() =>
  (view.value?.panels ?? []).filter((key) => props.snapshot.panels[key]?.state !== 'forbidden').slice(0, 6)
);

const portrait = ref(false);
function measure() {
  portrait.value = window.innerHeight > window.innerWidth;
}
onMounted(() => {
  measure();
  window.addEventListener('resize', measure);
});
onBeforeUnmount(() => window.removeEventListener('resize', measure));

const layout = computed(() => gridLayout(panelKeys.value, portrait.value));
const gridStyle = computed(() => ({
  gridTemplateColumns: `repeat(${layout.value.columns}, minmax(0, 1fr))`,
  gridTemplateRows: `repeat(${layout.value.rows}, minmax(0, 1fr))`,
}));

const alarms = computed(() => props.snapshot.alarms.slice(0, 4));
const attributions = computed(() => viewAttributions(panelKeys.value, props.snapshot.attributions));
const timezone = computed(() => props.snapshot.display.timezone);

// A new critical alert: a static red frame on the open-alerts tile for 60 s.
const frameUntil = ref(0);
let lastUntouchedCritical: number | null = null;
watch(
  () => {
    const e = props.snapshot.panels.open_alerts;
    return e && (e.state === 'ok' || e.state === 'stale') && 'by_severity' in e.data
      ? e.data.by_severity.critical.untouched
      : null;
  },
  (count) => {
    if (count === null) return;
    if (lastUntouchedCritical !== null && count > lastUntouchedCritical) frameUntil.value = props.status.deviceNow + FRAME_MS;
    lastUntouchedCritical = count;
  },
  { immediate: true }
);
const framed = (key: string) => key === 'open_alerts' && props.status.deviceNow < frameUntil.value;

const freshnessLabel = computed(() => {
  const { freshness, lastSuccessAt, deviceNow } = props.status;
  if (freshness === 'connecting') return 'connecting…';
  if (freshness === 'lagging' && lastSuccessAt !== null) return `Data ${duration(deviceNow - lastSuccessAt)} old · reconnecting`;
  if (freshness === 'offline') return 'offline';
  return freshnessText(lastSuccessAt, deviceNow);
});
const offlineSince = computed(() =>
  props.status.lastSuccessAt === null ? '' : clockText(props.status.lastSuccessAt + props.status.serverOffset, timezone.value)
);
</script>

<template>
  <div class="bd-root bd-board" :class="`bd-board--${mode}`">
    <header class="bd-strip">
      <div class="bd-strip-title">
        <span class="bd-strip-name">{{ snapshot.display.name }}</span>
        <span v-if="view?.title" class="bd-muted"> · {{ view.title }}</span>
      </div>
      <ul class="bd-alarms" aria-label="Alarms">
        <li
          v-for="alarm in alarms"
          :key="alarm.key"
          class="bd-alarm"
          :class="alarm.level === 'critical' ? 'bd-fill-critical' : 'bd-fill-warning'"
        >
          {{ alarm.text }}
        </li>
      </ul>
      <div class="bd-strip-meta">
        <span v-if="views.length > 1" class="bd-muted">{{ viewIndex + 1 }}/{{ views.length }}</span>
        <span v-if="status.paused" class="bd-muted">Paused</span>
        <span
          class="bd-fresh"
          :class="{
            'bd-fill-warning bd-fresh--chip': status.freshness === 'lagging',
            'bd-fill-critical bd-fresh--chip': status.freshness === 'offline',
          }"
          data-testid="freshness"
          >{{ freshnessLabel }}</span
        >
        <span v-if="snapshot.display.clock" class="bd-clock">{{ clockText(serverNow, timezone) }}</span>
      </div>
    </header>

    <div v-if="status.freshness === 'offline'" class="bd-offline bd-fill-critical" role="status">
      NO CONNECTION TO SIEMBOX SINCE {{ offlineSince }} — numbers below are not live
    </div>

    <main class="bd-grid" :style="gridStyle">
      <PanelFrame
        v-for="(key, i) in layout.keys"
        :key="key"
        :style="layout.spans[i] > 1 ? { gridColumn: `span ${layout.spans[i]}` } : undefined"
        :title="panelTitle(key)"
        :envelope="snapshot.panels[key]"
        :timezone="timezone"
        :framed="framed(key)"
        :offline="status.freshness === 'offline'"
        :data-panel="key"
      >
        <template #default="{ data }">
          <PanelBody :panel-key="key" :data="data" :now="serverNow" :timezone="timezone" />
        </template>
      </PanelFrame>
      <p v-if="panelKeys.length === 0" class="bd-label bd-muted">This view has no panels.</p>
    </main>

    <footer class="bd-foot">
      <div v-if="status.progress !== null" class="bd-progress" aria-hidden="true">
        <div class="bd-progress-bar" :style="{ transform: `scaleX(${status.progress})` }"></div>
      </div>
      <p v-if="attributions.length" class="bd-attrib">
        <span v-for="a in attributions" :key="a">{{ ATTRIBUTION_TEXT[a] }}</span>
      </p>
    </footer>
  </div>
</template>

<style scoped>
.bd-board {
  display: flex;
  flex-direction: column;
  width: 100%;
  height: 100%;
  padding: 0 1.5vh 0.8vh;
  gap: 1.2vh;
  overflow: hidden;
}
.bd-strip {
  flex: 0 0 8vh;
  display: flex;
  align-items: center;
  gap: 2vh;
  font-size: var(--bd-label);
  white-space: nowrap;
  min-width: 0;
}
.bd-strip-title {
  flex: 0 1 auto;
  min-width: 8vw;
  max-width: 26vw;
  overflow: hidden;
  text-overflow: ellipsis;
}
.bd-strip-name {
  font-weight: 700;
}
.bd-alarms {
  flex: 1 1 0;
  display: flex;
  /* One row of whole chips: a chip that doesn't fit wraps onto a hidden second
     row (they come critical first, so the least urgent go). */
  flex-wrap: wrap;
  justify-content: center;
  align-content: flex-start;
  max-height: calc(var(--bd-chip) * 1.25 + 1.2vh);
  gap: 1vh;
  list-style: none;
  margin: 0;
  padding: 0;
  min-width: 0;
  overflow: hidden;
}
.bd-alarm {
  flex: 0 0 auto;
  line-height: 1.25;
  padding: 0.6vh 1.2vh;
  border-radius: 0.6vh;
  font-weight: 800;
  font-size: var(--bd-chip);
  white-space: nowrap;
}
/* Portrait: the alarm chips get a row of their own under the name and clock. */
@media (max-aspect-ratio: 4/5) {
  .bd-strip {
    flex: 0 0 auto;
    flex-wrap: wrap;
    padding: 1.5vh 0 0;
    row-gap: 1vh;
  }
  .bd-strip-title {
    flex: 1 1 0;
    max-width: none;
  }
  .bd-alarms {
    order: 3;
    flex: 1 0 100%;
  }
}
.bd-strip-meta {
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  gap: 1.6vh;
}
.bd-fresh {
  color: var(--bd-text-2);
  font-size: var(--bd-floor);
}
.bd-fresh--chip {
  color: var(--bd-on-fill);
  padding: 0.3vh 1vh;
  border-radius: 0.5vh;
  font-weight: 700;
}
.bd-clock {
  font-size: var(--bd-number);
  font-weight: 700;
}
.bd-offline {
  flex: 0 0 auto;
  padding: 1vh 2vh;
  border-radius: 0.8vh;
  font-size: var(--bd-label);
  font-weight: 800;
  text-align: center;
}
.bd-grid {
  flex: 1 1 auto;
  display: grid;
  gap: 1.5vh;
  min-height: 0;
}
.bd-foot {
  flex: 0 0 auto;
  display: flex;
  flex-direction: column;
  gap: 0.6vh;
}
.bd-progress {
  height: 0.5vh;
  background: var(--bd-border);
  border-radius: 0.25vh;
  overflow: hidden;
}
.bd-progress-bar {
  height: 100%;
  background: var(--bd-text-2);
  transform-origin: left center;
}
.bd-attrib {
  display: flex;
  gap: 3vh;
  margin: 0;
  font-size: var(--bd-floor);
  color: var(--bd-text-2);
}
</style>
