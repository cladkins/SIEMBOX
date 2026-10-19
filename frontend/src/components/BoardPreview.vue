<script setup lang="ts">
/**
 * A Big Display board shrunk into a pane (the display-link editor's live
 * preview). The board sizes its type in viewport units, so it is laid out at
 * the window's full size and scaled down to the pane's width: what the pane
 * shows is the window's shape, the same layout a screen of that shape gets.
 */
import { onBeforeUnmount, onMounted, ref } from 'vue';
import BigDisplayBoard from '@/display/board/BigDisplayBoard.vue';
import type { BoardStatus } from '@/display/board/status';
import type { DisplaySnapshot } from '@/display/types';

defineProps<{ snapshot: DisplaySnapshot; status: BoardStatus; viewIndex: number }>();

const pane = ref<HTMLElement | null>(null);
const scale = ref(0.3);
const aspect = ref(9 / 16);
let observer: ResizeObserver | null = null;

function measure() {
  const width = pane.value?.clientWidth ?? 0;
  if (!width) return;
  scale.value = width / window.innerWidth;
  aspect.value = window.innerHeight / window.innerWidth;
}

onMounted(() => {
  measure();
  window.addEventListener('resize', measure);
  if (pane.value && typeof ResizeObserver !== 'undefined') {
    observer = new ResizeObserver(measure);
    observer.observe(pane.value);
  }
});
onBeforeUnmount(() => {
  window.removeEventListener('resize', measure);
  observer?.disconnect();
});
</script>

<template>
  <div ref="pane" class="board-preview" :style="{ paddingTop: `${aspect * 100}%` }" data-testid="board-preview">
    <div class="board-preview-inner" :style="{ transform: `scale(${scale})` }">
      <BigDisplayBoard :snapshot="snapshot" :view-index="viewIndex" :status="status" mode="preview" />
    </div>
  </div>
</template>

<style scoped>
.board-preview {
  position: relative;
  width: 100%;
  overflow: hidden;
  border-radius: 6px;
  background: #0b0f14;
}
.board-preview-inner {
  position: absolute;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  transform-origin: 0 0;
  pointer-events: none;
}
</style>
