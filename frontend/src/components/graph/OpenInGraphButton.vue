<template>
  <!-- A real link (router-link custom), so middle-click and "open in new tab" work. -->
  <router-link v-if="target" v-slot="{ href, navigate }" :to="target" custom>
    <a :href="href" class="open-in-graph" data-testid="open-in-graph" @click="onClick($event, navigate)">
      <el-button :size="size" :icon="Share" tabindex="-1">{{ label }}</el-button>
    </a>
  </router-link>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import type { RouteLocationRaw } from 'vue-router';
import { Share } from '@element-plus/icons-vue';
import { toEntity } from '@/graph/entityKey';
import { aroundOf } from '@/graph/model';
import type { NodeType, WindowPreset } from '@/graph/types';

/**
 * "Open in Context Graph": the graph page centred on one entity. Renders
 * nothing when the value isn't a valid key of that type (an alert with no id,
 * an asset row without one), so it never links to a "bad link" page.
 */
const props = withDefaults(
  defineProps<{
    type: NodeType;
    value: unknown;
    /** A time window preset; ignored when `around` is given. */
    window?: WindowPreset;
    /** An alert's created_at: the window around it (alert − 24 h … + 1 h). */
    around?: string | null;
    label?: string;
    size?: 'small' | 'default' | 'large';
  }>(),
  { window: '7d', around: null, label: 'Open in Context Graph', size: 'default' }
);

const emit = defineEmits<{ navigate: [] }>();

const target = computed<RouteLocationRaw | null>(() => {
  const ref = toEntity(props.type, props.value);
  if (!ref) return null;
  const around = props.around ? aroundOf(props.around) : null;
  return { path: '/graph', query: around ? { entity: ref.id, around } : { entity: ref.id, window: props.window } };
});

function onClick(event: MouseEvent, navigate: (e?: MouseEvent) => unknown) {
  // A modified click opens a new tab as the browser does; only a plain one navigates here (and closes the dialog).
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) return;
  emit('navigate');
  navigate(event);
}
</script>

<style scoped>
.open-in-graph {
  display: inline-block;
  text-decoration: none;
  margin-right: 12px;
}
</style>
