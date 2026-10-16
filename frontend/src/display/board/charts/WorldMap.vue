<script setup lang="ts">
/**
 * The threat map's choropleth. Chart.js, chartjs-chart-geo and the bundled
 * world atlas load only when a view shows the map (a lazy chunk the display
 * bundle check leaves out of its budget), and the chart is updated in place
 * on each snapshot instead of being rebuilt. Nothing is clickable.
 */
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { mapFill } from '../layout.ts';
import { reloadForStaleChunk } from '../../reload.ts';

const props = defineProps<{ countries: ReadonlyArray<{ code: string; count: number }> }>();
const canvas = ref<HTMLCanvasElement>();
const failed = ref(false);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let chart: any = null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let features: any[] = [];
let numericToAlpha2: Record<string, string> = {};
let disposed = false;

function values() {
  const counts = new Map(props.countries.map((c) => [c.code.toUpperCase(), c.count]));
  return features.map((f) => ({ feature: f, value: counts.get(numericToAlpha2[String(f.id)]) ?? 0 }));
}

async function draw() {
  let mods;
  try {
    mods = await Promise.all([
      import('chart.js'),
      import('chartjs-chart-geo'),
      import('topojson-client'),
      import('world-atlas/countries-110m.json'),
      import('@/assets/iso-numeric-alpha2.json'),
    ]);
  } catch {
    failed.value = true;
    reloadForStaleChunk();
    return;
  }
  if (disposed || !canvas.value) return;
  const [{ Chart }, geo, topojson, atlas, iso] = mods;
  Chart.register(geo.ChoroplethController, geo.GeoFeature, geo.ColorScale, geo.ProjectionScale);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const world = (atlas as any).default ?? atlas;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  features = (topojson.feature(world, world.objects.countries) as any).features.filter(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (f: any) => f.properties?.name !== 'Antarctica'
  );
  numericToAlpha2 = ((iso as { default?: Record<string, string> }).default ?? iso) as Record<string, string>;
  chart = new Chart(canvas.value, {
    type: 'choropleth',
    data: { labels: features.map((f) => f.properties.name), datasets: [{ label: 'Alerts', outline: features, data: values() }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      events: [],
      showOutline: false,
      showGraticule: false,
      borderColor: '#0b0f14',
      borderWidth: 0.5,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: {
        projection: { axis: 'x', projection: 'equalEarth' },
        color: { axis: 'x', min: 0, interpolate: mapFill, missing: mapFill(0), display: false, legend: { display: false } },
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
  });
}

watch(
  () => props.countries,
  () => {
    if (!chart) return;
    chart.data.datasets[0].data = values();
    chart.update('none');
  }
);

onMounted(draw);
onBeforeUnmount(() => {
  disposed = true;
  chart?.destroy();
  chart = null;
});
</script>

<template>
  <div class="bd-map">
    <canvas v-show="!failed" ref="canvas" role="img" aria-label="Alerts by country"></canvas>
    <p v-if="failed" class="bd-small">Map unavailable</p>
  </div>
</template>

<style scoped>
.bd-map {
  position: relative;
  flex: 1 1 auto;
  min-height: 0;
  min-width: 0;
}
.bd-map canvas {
  position: absolute;
  inset: 0;
}
</style>
