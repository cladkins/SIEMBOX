<template>
  <div class="bd-root big-display" :class="{ 'big-display--cursor': controlsVisible }" @mousemove="onPointer">
    <div v-if="!board.snapshot.value" class="message" role="status">
      <p class="message-title">{{ failure ? failure.title : 'Loading Big Display…' }}</p>
      <p v-if="failure" class="message-detail">{{ failure.detail }}</p>
      <button v-if="failure" type="button" class="control" @click="exit">Back to the Dashboard</button>
    </div>
    <BigDisplayBoard
      v-else
      :snapshot="board.snapshot.value"
      :view-index="board.currentView.value"
      :status="board.status.value"
      mode="session"
    />

    <p v-if="footerVisible && board.snapshot.value" class="footer" role="note" data-testid="session-footer">{{ footer }}</p>

    <nav v-if="controlsVisible" class="controls" aria-label="Big Display controls">
      <button type="button" class="control" @click="board.next(-1)">◀ Previous</button>
      <button type="button" class="control" @click="board.togglePaused">{{ board.status.value.paused ? '▶ Resume' : '❚❚ Pause' }}</button>
      <button type="button" class="control" @click="board.next(1)">Next ▶</button>
      <button type="button" class="control" @click="toggleFullscreen">⛶ Full screen</button>
      <button type="button" class="control" data-testid="big-display-exit" @click="exit">Exit</button>
    </nav>
  </div>
</template>

<script setup lang="ts">
/**
 * Big Display while signed in (BIG-DISPLAY.md §8.4): the wall board on the
 * user's own session and role, from GET /api/big-display/snapshot. Panels
 * the role may not see come back forbidden and the board drops them. An
 * admin's ?link=<id> shows that display link's board instead (its Preview
 * full screen), read with the admin's session, never the link's secret.
 *
 * It ends with the session (a 401 signs out as anywhere in the app); an
 * always-on screen needs a display link. Esc or Exit goes back to the
 * Dashboard. It never changes the app's theme.
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import BigDisplayBoard from '@/display/board/BigDisplayBoard.vue';
import { useBoardRunner } from '@/composables/useBoardRunner';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import { apiErrorStatus } from '@/utils/exposure';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();

const FOOTER_MS = 15_000;

/** A display link's id (?link=), for admins only. */
const linkId = computed(() => {
  const raw = route.query.link;
  return authStore.isAdmin && typeof raw === 'string' && /^[1-9]\d{0,8}$/.test(raw) ? Number(raw) : null;
});

const board = useBoardRunner(() =>
  (linkId.value !== null ? api.getDisplayLinkSnapshot(linkId.value) : api.getBigDisplaySnapshot()).then((r) => r.data)
);

const failure = computed(() => {
  const error = board.error.value;
  if (!error) return null;
  const status = apiErrorStatus(error);
  if (status === 404) return { title: 'No such display link.', detail: 'It may have been deleted.' };
  if (status === 409) return { title: 'This display link was revoked.', detail: 'Create a new one in Settings → Display links.' };
  if (status === 403) return { title: "You can't open this board.", detail: 'Ask an administrator.' };
  return { title: "Couldn't reach SIEMBox.", detail: 'This page keeps retrying by itself.' };
});

const footer = computed(() => {
  const who = authStore.user?.username ?? 'you';
  if (linkId.value !== null) {
    return `Preview of display link “${board.snapshot.value?.display.name ?? ''}”, as its screen shows it · signed in as ${who}`;
  }
  return `Signed in as ${who} · ends with your session · for an always-on screen, ask an admin for a display link`;
});
const footerVisible = ref(true);
const controlsVisible = ref(false);
let footerTimer: ReturnType<typeof setTimeout> | null = null;
let controlsTimer: ReturnType<typeof setTimeout> | null = null;

function onPointer() {
  controlsVisible.value = true;
  if (controlsTimer) clearTimeout(controlsTimer);
  controlsTimer = setTimeout(() => (controlsVisible.value = false), 3000);
}

function toggleFullscreen() {
  if (document.fullscreenElement) void document.exitFullscreen?.().catch(() => undefined);
  else void document.documentElement.requestFullscreen?.().catch(() => undefined);
}

function exit() {
  if (document.fullscreenElement) void document.exitFullscreen?.().catch(() => undefined);
  void router.push({ name: 'Dashboard' });
}

function onKey(event: KeyboardEvent) {
  if (event.ctrlKey || event.altKey || event.metaKey) return;
  switch (event.key) {
    case 'Escape':
      exit();
      break;
    case 'ArrowRight':
      board.next(1);
      break;
    case 'ArrowLeft':
      board.next(-1);
      break;
    case ' ':
    case 'Spacebar':
      board.togglePaused();
      break;
    case 'f':
    case 'F':
      toggleFullscreen();
      break;
    case 'r':
    case 'R':
      void board.refresh();
      break;
    default:
      return;
  }
  event.preventDefault();
}

onMounted(() => {
  window.addEventListener('keydown', onKey);
  footerTimer = setTimeout(() => (footerVisible.value = false), FOOTER_MS);
});
onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKey);
  if (footerTimer) clearTimeout(footerTimer);
  if (controlsTimer) clearTimeout(controlsTimer);
});
</script>

<style scoped>
.big-display {
  position: fixed;
  inset: 0;
  z-index: 3000;
  overflow: hidden;
  cursor: none;
}
.big-display--cursor {
  cursor: default;
}
.message {
  height: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 0 8vw;
}
.message-title {
  margin: 0 0 2vh;
  font-size: var(--bd-number);
  font-weight: 700;
}
.message-detail {
  margin: 0 0 3vh;
  font-size: var(--bd-label);
  color: var(--bd-text-2);
}
.footer {
  position: absolute;
  left: 50%;
  bottom: 5vh;
  transform: translateX(-50%);
  margin: 0;
  padding: 1vh 2vh;
  max-width: 90vw;
  background: var(--bd-panel);
  border: 0.15vh solid var(--bd-border);
  border-radius: 1vh;
  font-size: var(--bd-floor);
  color: var(--bd-text-2);
  text-align: center;
}
.controls {
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
.control {
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
