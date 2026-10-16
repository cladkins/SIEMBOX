<script setup lang="ts">
/**
 * A wall screen opened with a display link (BIG-DISPLAY.md §4, §5).
 *
 * The link's secret is read from the URL fragment (#k=…) into memory, and is
 * sent only as X-Display-Token by client.ts. The page shares nothing with the
 * signed-in app: no router, no Pinia, no auth or theme store, no axios, no
 * localStorage. Opening it never reads, replaces or clears a user's session,
 * and no answer from the server can sign anyone out or navigate away: every
 * failure is a message on this screen (connection.ts).
 */
import { computed, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue';
import BigDisplayBoard from './board/BigDisplayBoard.vue';
import type { BoardStatus } from './board/status.ts';
import { fetchSnapshot, tokenFromHash } from './client.ts';
import { freshness, initialState, nextDelay, onResult, refusalMessage, retryNowOnWake } from './connection.ts';
import { dayMonth } from './format.ts';
import { ReloadPlanner } from './reload.ts';
import { burnInOffset, dwellProgress, initialControl, step, togglePause, viewIndex, type RotationInput } from './rotation.ts';
import type { DisplaySnapshot } from './types.ts';

const token = ref<string | null>(tokenFromHash(window.location.hash));
const snapshot = shallowRef<DisplaySnapshot | null>(null);
const conn = ref(initialState());
const deviceNow = ref(Date.now());
const serverOffset = ref(0);
const control = ref(initialControl());
const controlsVisible = ref(false);
const hintVisible = ref(true);

const planner = new ReloadPlanner(Date.now());
let generation = 0;
let pollTimer: ReturnType<typeof setTimeout> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;
let controlsTimer: ReturnType<typeof setTimeout> | null = null;
let hintTimer: ReturnType<typeof setTimeout> | null = null;
let wakeLock: { release: () => Promise<void> } | null = null;

const refreshSeconds = computed(() => snapshot.value?.display.refresh_seconds ?? 30);

function clearPoll() {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
}

function schedule() {
  clearPoll();
  const delay = nextDelay(conn.value, refreshSeconds.value);
  if (delay !== null) pollTimer = setTimeout(poll, delay);
}

async function poll() {
  clearPoll();
  if (!token.value) {
    conn.value = onResult(conn.value, { ok: false, error: 'token_required' }, Date.now());
    return;
  }
  const gen = generation;
  const result = await fetchSnapshot(token.value);
  if (gen !== generation) return; // the link in the address bar changed meanwhile
  const now = Date.now();
  conn.value = onResult(conn.value, result, now);
  if (result.ok) {
    snapshot.value = result.snapshot;
    const serverTime = Date.parse(result.snapshot.server_time);
    if (!Number.isNaN(serverTime)) serverOffset.value = serverTime - (result.sentAt + result.receivedAt) / 2;
    deviceNow.value = now;
    if (planner.afterSuccess(result.snapshot.app_version, now)) return;
  }
  schedule();
}

/** A new link pasted into the same tab: start again with its token. */
function onHashChange() {
  generation += 1;
  token.value = tokenFromHash(window.location.hash);
  snapshot.value = null;
  conn.value = initialState();
  control.value = initialControl();
  void poll();
}

function onWake() {
  if (document.visibilityState === 'visible') {
    void requestWakeLock();
    if (retryNowOnWake(conn.value)) void poll();
  }
}
function onOnline() {
  if (retryNowOnWake(conn.value)) void poll();
}

// --- Rotation ------------------------------------------------------------------

const rotationInput = computed<RotationInput>(() => ({
  serverNow: deviceNow.value + serverOffset.value,
  dwellSeconds: snapshot.value?.display.rotation.seconds ?? 20,
  views: snapshot.value?.display.views.length ?? 1,
  enabled: snapshot.value?.display.rotation.enabled ?? false,
}));
const currentView = computed(() => viewIndex(control.value, rotationInput.value));

const status = computed<BoardStatus>(() => ({
  deviceNow: deviceNow.value,
  serverOffset: serverOffset.value,
  lastSuccessAt: conn.value.lastSuccessAt,
  freshness: freshness(conn.value, deviceNow.value, refreshSeconds.value),
  paused: control.value.paused,
  progress: dwellProgress(control.value, rotationInput.value),
}));

const shift = computed(() => {
  if (!snapshot.value?.display.burn_in_shift) return undefined;
  const { x, y } = burnInOffset(deviceNow.value);
  return { transform: `translate(${x}px, ${y}px)` };
});

const refusal = computed(() => {
  const r = conn.value.refusal;
  return r ? refusalMessage(r, dayMonth(conn.value.expiresAt)) : null;
});

// --- Screen: full screen, cursor, keys, wake lock --------------------------------

function toggleFullscreen() {
  if (document.fullscreenElement) void document.exitFullscreen?.().catch(() => undefined);
  else void document.documentElement.requestFullscreen?.().catch(() => undefined);
}

function hideHint(fullscreen: boolean) {
  if (!hintVisible.value) return false;
  hintVisible.value = false;
  if (fullscreen && !document.fullscreenElement) toggleFullscreen();
  return true;
}

function onKey(event: KeyboardEvent) {
  if (event.ctrlKey || event.altKey || event.metaKey) return;
  const key = event.key;
  const fullscreenKey = key === 'Enter' || key === 'f' || key === 'F';
  // The first key also asks for full screen (the Fullscreen API needs a
  // gesture), unless it is the full-screen key, which toggles it below.
  hideHint(!fullscreenKey);
  switch (key) {
    case 'ArrowRight':
      control.value = step(control.value, rotationInput.value, 1);
      break;
    case 'ArrowLeft':
      control.value = step(control.value, rotationInput.value, -1);
      break;
    case ' ':
    case 'Spacebar':
    case 'MediaPlayPause':
      control.value = togglePause(control.value, rotationInput.value);
      break;
    case 'Enter':
    case 'f':
    case 'F':
      toggleFullscreen();
      break;
    case 'r':
    case 'R':
      void poll();
      break;
    default:
      return;
  }
  event.preventDefault();
}

function onPointer() {
  controlsVisible.value = true;
  if (controlsTimer) clearTimeout(controlsTimer);
  controlsTimer = setTimeout(() => (controlsVisible.value = false), 3000);
}

function onClick() {
  hideHint(true);
}

async function requestWakeLock() {
  const nav = navigator as Navigator & { wakeLock?: { request: (type: 'screen') => Promise<{ release: () => Promise<void> }> } };
  if (!nav.wakeLock || !window.isSecureContext) return;
  try {
    wakeLock = await nav.wakeLock.request('screen');
  } catch {
    wakeLock = null; // refused (battery saver, hidden tab): asked again when visible
  }
}

const insecure = !window.isSecureContext;

onMounted(() => {
  window.addEventListener('hashchange', onHashChange);
  window.addEventListener('online', onOnline);
  document.addEventListener('visibilitychange', onWake);
  window.addEventListener('keydown', onKey);
  window.addEventListener('mousemove', onPointer, { passive: true });
  tickTimer = setInterval(() => (deviceNow.value = Date.now()), 1000);
  hintTimer = setTimeout(() => (hintVisible.value = false), 10_000);
  planner.startEtagChecks();
  void requestWakeLock();
  void poll();
});

onBeforeUnmount(() => {
  window.removeEventListener('hashchange', onHashChange);
  window.removeEventListener('online', onOnline);
  document.removeEventListener('visibilitychange', onWake);
  window.removeEventListener('keydown', onKey);
  window.removeEventListener('mousemove', onPointer);
  clearPoll();
  if (tickTimer) clearInterval(tickTimer);
  if (controlsTimer) clearTimeout(controlsTimer);
  if (hintTimer) clearTimeout(hintTimer);
  planner.stop();
  void wakeLock?.release().catch(() => undefined);
});
</script>

<template>
  <div class="bd-root bd-app" :class="{ 'bd-app--cursor': controlsVisible }" @click="onClick">
    <div v-if="refusal" class="bd-message" role="alert" data-testid="refusal">
      <p class="bd-message-title">{{ refusal.title }}</p>
      <p class="bd-message-detail">{{ refusal.detail }}</p>
    </div>
    <div v-else-if="!snapshot" class="bd-message" role="status" data-testid="connecting">
      <p class="bd-message-title">Connecting to SIEMBox…</p>
      <p v-if="conn.failures > 0" class="bd-message-detail">Still trying. This screen keeps retrying by itself.</p>
    </div>
    <div v-else class="bd-shift" :style="shift">
      <BigDisplayBoard :snapshot="snapshot" :view-index="currentView" :status="status" mode="link" />
    </div>

    <div v-if="hintVisible && !refusal" class="bd-hint" role="note">
      <p>Press any key or click for full screen</p>
      <p v-if="insecure">Set this device to never sleep, or serve SIEMBox over HTTPS</p>
    </div>

    <nav v-if="controlsVisible && snapshot && !refusal" class="bd-controls" aria-label="Display controls" @click.stop>
      <button type="button" @click="control = step(control, rotationInput, -1)">◀ Previous</button>
      <button type="button" @click="control = togglePause(control, rotationInput)">
        {{ control.paused ? '▶ Resume' : '❚❚ Pause' }}
      </button>
      <button type="button" @click="control = step(control, rotationInput, 1)">Next ▶</button>
      <button type="button" @click="toggleFullscreen">⛶ Full screen</button>
    </nav>
  </div>
</template>

<style>
html,
body {
  margin: 0;
  height: 100%;
  background: #0b0f14;
  overflow: hidden;
}
#display {
  height: 100%;
}
</style>

<style scoped>
.bd-app {
  position: relative;
  width: 100vw;
  height: 100vh;
  overflow: hidden;
  cursor: none;
}
.bd-app--cursor {
  cursor: default;
}
.bd-shift {
  width: 100%;
  height: 100%;
}
.bd-message {
  height: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 0 8vw;
}
.bd-message-title {
  margin: 0 0 2vh;
  font-size: var(--bd-number);
  font-weight: 700;
}
.bd-message-detail {
  margin: 0;
  font-size: var(--bd-label);
  color: var(--bd-text-2);
}
.bd-hint {
  position: absolute;
  left: 50%;
  bottom: 6vh;
  transform: translateX(-50%);
  padding: 1.2vh 2.4vh;
  background: var(--bd-panel);
  border: 0.15vh solid var(--bd-border);
  border-radius: 1vh;
  font-size: var(--bd-floor);
  color: var(--bd-text-2);
  text-align: center;
}
.bd-hint p {
  margin: 0.3vh 0;
}
.bd-controls {
  position: absolute;
  right: 2vh;
  bottom: 4vh;
  display: flex;
  gap: 1vh;
  padding: 1vh;
  background: var(--bd-panel);
  border: 0.15vh solid var(--bd-border);
  border-radius: 1vh;
}
.bd-controls button {
  font: inherit;
  font-size: var(--bd-floor);
  color: var(--bd-text);
  background: var(--bd-bg);
  border: 0.15vh solid var(--bd-border);
  border-radius: 0.6vh;
  padding: 0.6vh 1.4vh;
  cursor: pointer;
}
</style>
