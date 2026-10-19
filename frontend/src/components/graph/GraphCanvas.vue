<template>
  <div ref="container" class="graph-canvas" role="img" :aria-label="ariaLabel" data-testid="graph-canvas"></div>
</template>

<script setup lang="ts">
/**
 * The Cytoscape wrapper. Cytoscape is loaded here only (`await import`), so it
 * is its own lazy chunk (vite.config.ts codeSplitting group 'graph') that the
 * rest of the app never downloads. Must not import @/services/api or
 * @/stores/auth: it draws what it is given and reports what was clicked.
 *
 * Layout: the first draw is Cytoscape's concentric layout by hop distance;
 * after that new nodes are placed on an arc around the node they hang off
 * (graph/layout.ts) and existing nodes never move until relayout().
 */
import { onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue';
import type { Core, ElementDefinition as CyElement, EventObject, NodeSingular } from 'cytoscape';
import { placeAround, type Point } from '@/graph/layout';
import { stylesheet, type ElementDefinition, type GraphPalette } from '@/graph/style';

const props = defineProps<{
  elements: ElementDefinition[];
  /** Hops from the nearest centre, for the concentric layout. */
  hops: Record<string, number>;
  dark: boolean;
  selected: string | null;
  pulsing: readonly string[];
  path: { nodes: string[]; edges: string[] } | null;
  /** Saved positions to start from (sessionStorage), by node id. */
  initialPositions?: Record<string, Point> | null;
  ariaLabel?: string;
}>();

const emit = defineEmits<{
  /** A node, group node or edge was clicked (id null: the background). */
  select: [id: string | null, kind: 'node' | 'group' | 'edge' | null, shift: boolean];
  expand: [id: string];
  /** Positions changed (a drag, a layout): the page saves them. */
  moved: [];
  /** Cytoscape couldn't start: the page falls back to the list view. */
  failed: [error: unknown];
}>();

const container = ref<HTMLDivElement | null>(null);
const cy = shallowRef<Core | null>(null);
let resizeObserver: ResizeObserver | null = null;
let disposed = false;
const reducedMotion = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

function cssVar(name: string, fallback: string): string {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

function palette(): GraphPalette {
  return {
    dark: props.dark,
    text: cssVar('--siembox-text-color', props.dark ? '#e5eaf3' : '#303133'),
    textMuted: cssVar('--siembox-text-secondary', '#909399'),
    background: cssVar('--siembox-card-bg', props.dark ? '#1d1e1f' : '#ffffff'),
    card: cssVar('--siembox-card-bg', props.dark ? '#1d1e1f' : '#ffffff'),
    border: cssVar('--siembox-border-color', '#dcdfe6'),
    edge: props.dark ? '#6c6e72' : '#a8abb2',
    primary: cssVar('--el-color-primary', '#409eff'),
    danger: cssVar('--el-color-danger', '#f56c6c'),
    warning: cssVar('--el-color-warning', '#e6a23c'),
    highlight: props.dark ? '#ffd43b' : '#f08c00',
  };
}

function concentric(core: Core, eles = core.elements()) {
  const far = Math.max(1, ...Object.values(props.hops)) + 1;
  const hopOf = (n: NodeSingular): number => {
    if (n.data('kind') === 'group') return (props.hops[n.data('owner')] ?? far) + 1;
    return props.hops[n.id()] ?? far;
  };
  return eles.layout({
    name: 'concentric',
    concentric: (n: NodeSingular) => 100 - hopOf(n),
    levelWidth: () => 1,
    minNodeSpacing: 28,
    animate: false,
    fit: true,
    padding: 30,
  });
}

/** Where a new node goes: next to a placed neighbour (or its group's owner). */
function anchorOf(el: CyElement, placed: Set<string>): string | null {
  const owner = el.data.owner as string | undefined;
  if (owner && placed.has(owner)) return owner;
  const id = el.data.id as string;
  for (const edge of props.elements) {
    if (edge.group !== 'edges') continue;
    const { source, target } = edge.data as { source: string; target: string };
    if (source === id && placed.has(target)) return target;
    if (target === id && placed.has(source)) return source;
  }
  return null;
}

/** A small graph fitted to the canvas would be drawn huge: no closer than 1.5×. */
function capZoom(core: Core) {
  if (core.zoom() > 1.5) {
    core.zoom(1.5);
    core.center();
  }
}

/** Bring the canvas in line with props.elements: add, remove, update data and classes. */
function sync(first = false) {
  const core = cy.value;
  if (!core) return;
  const wanted = new Map(props.elements.map((e) => [e.data.id as string, e]));
  core.batch(() => {
    core.elements().forEach((ele) => {
      if (!wanted.has(ele.id())) ele.remove();
    });
  });
  const placed = new Set(core.nodes().map((n) => n.id()));
  const hadNodes = placed.size > 0;
  const newNodes: CyElement[] = [];
  const newEdges: CyElement[] = [];
  core.batch(() => {
    for (const el of props.elements) {
      const id = el.data.id as string;
      const existing = core.getElementById(id);
      if (existing.nonempty()) {
        existing.data(el.data);
        existing.classes(el.classes);
        continue;
      }
      const def: CyElement = { group: el.group, data: { ...el.data }, classes: el.classes };
      if (el.group === 'nodes') newNodes.push(def);
      else newEdges.push(def);
    }
  });
  if (newNodes.length === 0 && newEdges.length === 0) {
    applyHighlights();
    return;
  }
  const saved = first ? props.initialPositions ?? null : null;
  const unplaced: CyElement[] = [];
  for (const def of newNodes) {
    const pos = saved?.[def.data.id as string];
    if (pos) def.position = { ...pos };
    else unplaced.push(def);
  }
  if (hadNodes) {
    // Group the unplaced by the placed node they hang off; place each group on an arc.
    const byAnchor = new Map<string, CyElement[]>();
    const loose: CyElement[] = [];
    for (const def of unplaced) {
      const anchor = anchorOf(def, placed);
      if (!anchor) loose.push(def);
      else byAnchor.set(anchor, [...(byAnchor.get(anchor) ?? []), def]);
    }
    const existing: Point[] = core.nodes().map((n) => ({ ...n.position() }));
    for (const [anchor, defs] of byAnchor) {
      const at = core.getElementById(anchor).position();
      const points = placeAround({ x: at.x, y: at.y }, defs.length, existing);
      defs.forEach((def, i) => {
        def.position = points[i];
        existing.push(points[i]);
      });
    }
    // Nothing on the canvas links to them: start beside the graph.
    const box = core.nodes().boundingBox({});
    loose.forEach((def, i) => {
      def.position = { x: box.x2 + 120, y: box.y1 + i * 60 };
    });
  }
  core.add([...newNodes, ...newEdges]);
  if (!hadNodes && unplaced.length > 0) {
    concentric(core).run();
    capZoom(core);
  } else if (!hadNodes) {
    core.fit(undefined, 30);
    capZoom(core);
  }
  applyHighlights();
  emit('moved');
}

function applyHighlights() {
  const core = cy.value;
  if (!core) return;
  core.batch(() => {
    core.elements().removeClass('selected pulse path dim');
    if (props.selected) core.getElementById(props.selected).addClass('selected');
    for (const id of props.pulsing) core.getElementById(id).addClass('pulse');
    if (props.path) {
      const on = new Set([...props.path.nodes, ...props.path.edges]);
      core.elements().forEach((ele) => {
        ele.addClass(on.has(ele.id()) ? 'path' : 'dim');
      });
    }
  });
}

function hoverDim(node: NodeSingular | null) {
  const core = cy.value;
  if (!core || props.path) return;
  core.batch(() => {
    core.elements().removeClass('dim');
    if (node) core.elements().not(node.closedNeighborhood()).addClass('dim');
  });
}

async function start() {
  try {
    const { default: cytoscape } = await import('cytoscape');
    if (disposed || !container.value) return;
    const core = cytoscape({
      container: container.value,
      style: stylesheet(palette()) as never,
      wheelSensitivity: 0.3,
      minZoom: 0.1,
      maxZoom: 3,
      boxSelectionEnabled: false,
      selectionType: 'single',
    });
    cy.value = core;
    core.on('tap', (event: EventObject) => {
      const target = event.target;
      const shift = !!(event.originalEvent as MouseEvent | undefined)?.shiftKey;
      if (target === core) {
        emit('select', null, null, shift);
        return;
      }
      const kind = target.isEdge() ? 'edge' : target.data('kind') === 'group' ? 'group' : 'node';
      if (kind === 'edge' && target.data('kind') === 'group-edge') return;
      emit('select', target.id(), kind, shift);
    });
    core.on('dbltap', 'node', (event: EventObject) => {
      if (event.target.data('kind') === 'node') emit('expand', event.target.id());
    });
    core.on('mouseover', 'node', (event: EventObject) => hoverDim(event.target));
    core.on('mouseout', 'node', () => hoverDim(null));
    core.on('dragfree', 'node', () => emit('moved'));
    sync(true);
    resizeObserver = new ResizeObserver(() => core.resize());
    resizeObserver.observe(container.value);
  } catch (error) {
    emit('failed', error);
  }
}

watch(() => props.elements, () => sync());
watch(() => [props.selected, props.pulsing, props.path], applyHighlights);
watch(
  () => props.dark,
  () => {
    // Element Plus switches its variables on <html> first; read them on the next frame.
    requestAnimationFrame(() => cy.value?.style(stylesheet(palette()) as never));
  }
);

onMounted(start);
onBeforeUnmount(() => {
  disposed = true;
  resizeObserver?.disconnect();
  cy.value?.destroy();
  cy.value = null;
});

defineExpose({
  fit() {
    cy.value?.animate({ fit: { eles: cy.value.elements(), padding: 30 } }, { duration: reducedMotion ? 0 : 200 });
  },
  relayout() {
    const core = cy.value;
    if (!core) return;
    concentric(core).run();
    capZoom(core);
    emit('moved');
  },
  positions(): Record<string, Point> {
    const out: Record<string, Point> = {};
    cy.value?.nodes().forEach((n) => {
      const p = n.position();
      out[n.id()] = { x: Math.round(p.x), y: Math.round(p.y) };
    });
    return out;
  },
  centreOn(id: string) {
    const ele = cy.value?.getElementById(id);
    if (ele && ele.nonempty()) cy.value!.animate({ center: { eles: ele } }, { duration: reducedMotion ? 0 : 200 });
  },
});
</script>

<style scoped>
.graph-canvas {
  width: 100%;
  height: 100%;
  min-height: 560px;
  background: var(--siembox-card-bg);
  outline: none;
}
@media (max-width: 900px) {
  .graph-canvas {
    min-height: 60vh;
  }
}
</style>
