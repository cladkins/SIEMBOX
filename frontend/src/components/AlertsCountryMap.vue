<template>
  <div class="country-map">
    <canvas ref="canvasEl"></canvas>
    <div v-if="!hasData" class="map-empty">
      No geo-located alerts yet. Countries light up once a public source IP
      resolves to a country.
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch, computed } from 'vue';
import { Chart } from 'chart.js';
import { ChoroplethController, GeoFeature, ColorScale, ProjectionScale } from 'chartjs-chart-geo';
import { feature } from 'topojson-client';
// Bundled offline world atlas (topojson) + ISO numeric->alpha2 map, so the map
// renders with no external/CDN calls (matching the offline GeoIP design).
import worldData from 'world-atlas/countries-110m.json';
import isoMap from '@/assets/iso-numeric-alpha2.json';

Chart.register(ChoroplethController, GeoFeature, ColorScale, ProjectionScale);

const props = defineProps<{
  data: Array<{ country_code: string; country_name?: string; count: number; foreign_count?: number }>;
}>();
const emit = defineEmits<{ (e: 'country-click', code: string): void }>();

const canvasEl = ref<HTMLCanvasElement>();
let chart: Chart | null = null;

// GeoJSON country features from the atlas; each feature.id is a numeric ISO code.
const countries: any[] = (feature(worldData as any, (worldData as any).objects.countries) as any).features;
const numericToAlpha2: Record<string, string> = isoMap as any;

const hasData = computed(() => (props.data || []).some((r) => r.count > 0));

function countsByAlpha2(): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const row of props.data || []) {
    if (row.country_code) counts[row.country_code.toUpperCase()] = row.count;
  }
  return counts;
}

function render() {
  if (!canvasEl.value) return;
  chart?.destroy();
  chart = null;

  const counts = countsByAlpha2();
  const valueFor = (f: any) => counts[numericToAlpha2[String(f.id)]] || 0;

  const config: any = {
    type: 'choropleth',
    data: {
      labels: countries.map((c) => c.properties.name),
      datasets: [
        {
          label: 'Alerts',
          outline: countries,
          data: countries.map((c) => ({ feature: c, value: valueFor(c) })),
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      showOutline: true,
      showGraticule: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx: any) => {
              const v = ctx.raw?.value || 0;
              const name = ctx.raw?.feature?.properties?.name ?? '';
              return `${name}: ${v} alert${v === 1 ? '' : 's'}`;
            },
          },
        },
      },
      scales: {
        projection: { axis: 'x', projection: 'equalEarth' },
        color: {
          axis: 'x',
          quantize: 5,
          interpolate: 'reds',
          legend: { position: 'bottom-right', align: 'right' },
        },
      },
      onClick: (_e: any, els: any[]) => {
        if (!els || !els.length) return;
        const f = countries[els[0].index];
        const code = numericToAlpha2[String(f?.id)];
        if (code && (counts[code] || 0) > 0) emit('country-click', code);
      },
    },
  };

  chart = new Chart(canvasEl.value, config);
}

onMounted(render);
watch(() => props.data, render, { deep: true });
onBeforeUnmount(() => {
  chart?.destroy();
  chart = null;
});
</script>

<style scoped>
.country-map {
  height: 380px;
  position: relative;
}
.map-empty {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 0 24px;
  color: var(--siembox-text-secondary, #909399);
  font-size: 14px;
  pointer-events: none;
}
</style>
