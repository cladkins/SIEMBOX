<script setup lang="ts">
/**
 * One tile: its title and the panel states of BIG-DISPLAY.md §5.5. Loading
 * shows words, never a spinner (spinners on a TV read as broken). Stale keeps
 * the last data, dimmed, and says how old it is. `forbidden` panels never get
 * here: the board drops them.
 */
import { computed } from 'vue';
import type { PanelData, PanelEnvelope } from '../types.ts';
import { clockText } from '../format.ts';

const props = defineProps<{
  title: string;
  envelope: PanelEnvelope | undefined;
  timezone: string | null;
  /** A new critical: a static red frame for 60 s. */
  framed?: boolean;
  /** The screen lost the server: every panel is marked STALE. */
  offline?: boolean;
}>();

const data = computed<PanelData | null>(() => {
  const e = props.envelope;
  return e && (e.state === 'ok' || e.state === 'stale') ? e.data : null;
});

const staleNote = computed(() => {
  const e = props.envelope;
  if (!e || e.state !== 'stale') return null;
  const at = Date.parse(e.as_of);
  const time = Number.isNaN(at) ? '' : ` from ${clockText(at, props.timezone)}`;
  return `Data${time} — ${e.reason === 'busy' ? 'database busy' : 'update failed'}`;
});
</script>

<template>
  <section
    class="bd-panel"
    :class="{ 'bd-panel--framed': framed, 'bd-panel--stale': envelope?.state === 'stale', 'bd-panel--offline': offline }"
  >
    <header class="bd-panel-head">
      <h2 class="bd-panel-title">{{ title }}</h2>
      <span v-if="offline" class="bd-tag bd-fill-warning">STALE</span>
    </header>
    <div class="bd-panel-body">
      <p v-if="!envelope" class="bd-panel-note">Loading…</p>
      <p v-else-if="envelope.state === 'unavailable'" class="bd-panel-note">Temporarily unavailable</p>
      <p v-else-if="envelope.state === 'not_configured'" class="bd-panel-note">{{ envelope.message }}</p>
      <template v-else-if="data">
        <div class="bd-panel-content">
          <slot :data="data" />
        </div>
        <p v-if="staleNote" class="bd-small bd-panel-stale">{{ staleNote }}</p>
      </template>
    </div>
  </section>
</template>

<style scoped>
.bd-panel {
  position: relative;
  display: flex;
  flex-direction: column;
  min-width: 0;
  min-height: 0;
  padding: 1.6vh 2vh;
  background: var(--bd-panel);
  border: 0.15vh solid var(--bd-border);
  border-radius: 1vh;
  overflow: hidden;
}
.bd-panel--framed {
  /* 4 px at 1080p, static: nothing on the wall flashes. */
  box-shadow: inset 0 0 0 0.4vh var(--bd-critical);
}
.bd-panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1vh;
  margin-bottom: 1vh;
}
.bd-panel-title {
  margin: 0;
  font-size: var(--bd-title);
  font-weight: 600;
  color: var(--bd-text-2);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.bd-panel-body {
  flex: 1 1 auto;
  display: flex;
  flex-direction: column;
  min-height: 0;
}
.bd-panel-content {
  flex: 1 1 auto;
  min-height: 0;
  display: flex;
  flex-direction: column;
  gap: 1vh;
}
.bd-panel-note {
  margin: auto 0;
  font-size: var(--bd-label);
  color: var(--bd-text-2);
}
.bd-panel--stale .bd-panel-content {
  opacity: 0.6;
}
.bd-panel-stale {
  margin: 0.6vh 0 0;
}
.bd-panel--offline .bd-panel-body {
  filter: saturate(0.3);
}
</style>
