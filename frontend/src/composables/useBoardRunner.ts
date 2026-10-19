/**
 * Runs a Big Display board inside the signed-in app (BIG-DISPLAY.md §8.3,
 * §8.4): polls a snapshot at the board's refresh interval, keeps the clock
 * offset and rotation, and hands BigDisplayBoard its status. The wall page
 * (src/display/DisplayApp.vue) does the same for a display link with its own
 * fetch; this reuses its pure pieces (connection.ts, rotation.ts) only.
 *
 * `load` goes through the app's API client, so a 401 signs out as anywhere
 * else. A 4xx answer other than 429 (a layout the server refuses, a revoked
 * link) stops polling until refresh() is called again; anything else backs
 * off and retries, keeping the last board on screen.
 */
import { computed, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue';
import type { DisplaySnapshot } from '@/display/types';
import type { BoardStatus } from '@/display/board/status';
import { freshness, initialState, nextDelay, onResult } from '@/display/connection';
import { dwellProgress, initialControl, step, togglePause, viewIndex, type RotationInput } from '@/display/rotation';

function stopsPolling(error: unknown): boolean {
  const status = (error as { response?: { status?: number } })?.response?.status;
  return typeof status === 'number' && status >= 400 && status < 500 && status !== 429;
}

export function useBoardRunner(load: (signal: AbortSignal) => Promise<DisplaySnapshot>, options: { autoStart?: boolean } = {}) {
  const snapshot = shallowRef<DisplaySnapshot | null>(null);
  const error = shallowRef<unknown>(null);
  const loading = ref(false);
  const conn = ref(initialState());
  const deviceNow = ref(Date.now());
  const serverOffset = ref(0);
  const control = ref(initialControl());

  let pollTimer: ReturnType<typeof setTimeout> | null = null;
  let tickTimer: ReturnType<typeof setInterval> | null = null;
  let controller: AbortController | null = null;
  let stopped = false;

  const refreshSeconds = computed(() => snapshot.value?.display.refresh_seconds ?? 30);

  function clearPoll() {
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null;
  }

  async function refresh(): Promise<void> {
    stopped = false;
    clearPoll();
    controller?.abort();
    const mine = new AbortController();
    controller = mine;
    loading.value = true;
    const sentAt = Date.now();
    let halt = false;
    try {
      const next = await load(mine.signal);
      if (mine.signal.aborted) return;
      const receivedAt = Date.now();
      snapshot.value = next;
      error.value = null;
      conn.value = onResult(conn.value, { ok: true, snapshot: next, sentAt, receivedAt }, receivedAt);
      const serverTime = Date.parse(next.server_time);
      if (!Number.isNaN(serverTime)) serverOffset.value = serverTime - (sentAt + receivedAt) / 2;
      deviceNow.value = receivedAt;
    } catch (e) {
      if (mine.signal.aborted) return;
      error.value = e;
      halt = stopsPolling(e);
      if (!halt) conn.value = onResult(conn.value, { ok: false, error: 'network' }, Date.now());
    } finally {
      if (controller === mine) loading.value = false;
    }
    if (stopped || halt) return;
    const delay = nextDelay(conn.value, refreshSeconds.value);
    if (delay !== null) pollTimer = setTimeout(() => void refresh(), delay);
  }

  function stop() {
    stopped = true;
    clearPoll();
    controller?.abort();
    controller = null;
  }

  /** Start again from nothing (a different link or layout). */
  function reset() {
    snapshot.value = null;
    error.value = null;
    conn.value = initialState();
    control.value = initialControl();
  }

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

  const next = (direction: 1 | -1) => (control.value = step(control.value, rotationInput.value, direction));
  const togglePaused = () => (control.value = togglePause(control.value, rotationInput.value));

  onMounted(() => {
    tickTimer = setInterval(() => (deviceNow.value = Date.now()), 1000);
    if (options.autoStart !== false) void refresh();
  });
  onBeforeUnmount(() => {
    stop();
    if (tickTimer) clearInterval(tickTimer);
  });

  return { snapshot, error, loading, status, currentView, refresh, stop, reset, next, togglePaused };
}
