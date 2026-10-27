<template>
  <div class="perf-chart">
    <div class="perf-chart-head">
      <span class="perf-chart-title">{{ title }}</span>
      <span v-if="subtitle" class="perf-chart-sub">{{ subtitle }}</span>
    </div>
    <p v-if="isEmpty" class="perf-chart-empty">No data in this range</p>
    <div v-else class="perf-chart-canvas" :style="{ height: `${height}px` }">
      <Line :key="themeKey" :data="chartData" :options="chartOptions" :aria-label="ariaLabel" />
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * One time-series line chart of the Performance tab: chart.js through
 * vue-chartjs (the libraries the app already uses), a linear x axis in epoch
 * milliseconds labelled by axisLabel (no date adapter needed), gaps drawn as
 * breaks (null points, see toXY), an optional dashed threshold line, and the
 * theme's ink re-read when the theme switches.
 */
import { computed, nextTick, ref, watch } from 'vue';
import { Line } from 'vue-chartjs';
import {
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  Tooltip,
  type ChartData,
  type ChartOptions,
  type TooltipItem,
} from 'chart.js';
import { useThemeStore } from '@/stores/theme';
import { axisLabel, tickStep, type XY } from '@/utils/endpointPerformance';

ChartJS.register(LineController, LineElement, PointElement, LinearScale, CategoryScale, Filler, Tooltip, Legend);

export interface PerfDataset {
  label: string;
  data: XY[];
  color: string;
  dashed?: boolean;
  fill?: boolean;
  /** A faint secondary line (e.g. the bucket maximum). */
  faint?: boolean;
}

const props = withDefaults(
  defineProps<{
    title: string;
    subtitle?: string;
    datasets: PerfDataset[];
    from: number;
    to: number;
    /** Format a y value for ticks and tooltips. */
    format?: (v: number) => string;
    yMax?: number;
    /** A dashed horizontal line (an alert threshold). */
    threshold?: number | null;
    height?: number;
  }>(),
  { subtitle: '', format: (v: number) => String(Math.round(v * 100) / 100), yMax: undefined, threshold: null, height: 190 }
);

const themeStore = useThemeStore();
const isEmpty = computed(() => props.datasets.every((d) => d.data.every((p) => p.y === null)));
const ariaLabel = computed(() => `${props.title} chart`);

function readInk() {
  const css = getComputedStyle(document.documentElement);
  const v = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback;
  return { grid: v('--siembox-border-color', '#dcdfe6'), text: v('--siembox-text-secondary', '#606266') };
}
const ink = ref(readInk());
const themeKey = ref(0);
watch(
  () => themeStore.isDark,
  () =>
    nextTick(() => {
      ink.value = readInk();
      themeKey.value++;
    })
);

const chartData = computed(() => {
  const sets = props.datasets.map((d) => ({
    label: d.label,
    data: d.data,
    borderColor: d.faint ? `${d.color}66` : d.color,
    backgroundColor: d.fill ? `${d.color}22` : 'transparent',
    fill: d.fill ? 'origin' : false,
    borderWidth: d.faint ? 1 : 1.75,
    borderDash: d.dashed ? [5, 4] : [],
    // Sparse data (a new agent, a short range) would be invisible as bare line segments.
    pointRadius: d.data.filter((p) => p.y !== null).length < 15 ? 2 : 0,
    pointHoverRadius: 3,
    pointHitRadius: 6,
    tension: 0.2,
    spanGaps: false,
  }));
  if (props.threshold !== null && props.threshold !== undefined) {
    sets.push({
      label: `Alert threshold (${props.format(props.threshold)})`,
      data: [
        { x: props.from, y: props.threshold },
        { x: props.to, y: props.threshold },
      ],
      borderColor: '#f56c6c',
      backgroundColor: 'transparent',
      fill: false,
      borderWidth: 1,
      borderDash: [2, 3],
      pointRadius: 0,
      pointHoverRadius: 0,
      pointHitRadius: 0,
      tension: 0,
      spanGaps: true,
    });
  }
  return { datasets: sets } as unknown as ChartData<'line'>;
});

const chartOptions = computed<ChartOptions<'line'>>(() => {
  const { grid, text } = ink.value;
  const range = props.to - props.from;
  const fmt = props.format;
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    parsing: false,
    normalized: true,
    interaction: { mode: 'nearest', axis: 'x', intersect: false },
    plugins: {
      legend: {
        display: props.datasets.length > 1 || props.threshold !== null,
        position: 'bottom',
        labels: { color: text, boxWidth: 10, boxHeight: 10, padding: 10, font: { size: 11 } },
      },
      tooltip: {
        callbacks: {
          title: (items: TooltipItem<'line'>[]) => {
            const x = (items[0]?.raw as XY | undefined)?.x;
            return x ? new Date(x).toLocaleString() : '';
          },
          label: (item: TooltipItem<'line'>) => {
            const y = (item.raw as XY).y;
            return `${item.dataset.label}: ${y === null ? '—' : fmt(y)}`;
          },
        },
      },
    },
    scales: {
      x: {
        type: 'linear',
        min: props.from,
        max: props.to,
        grid: { display: false },
        border: { color: grid },
        ticks: {
          color: text,
          maxRotation: 0,
          autoSkip: true,
          maxTicksLimit: 8,
          stepSize: tickStep(range),
          callback: (v) => axisLabel(Number(v), range),
        },
      },
      y: {
        beginAtZero: true,
        max: props.yMax,
        grid: { color: grid },
        border: { display: false },
        ticks: { color: text, maxTicksLimit: 5, callback: (v) => fmt(Number(v)) },
      },
    },
  };
});
</script>

<style scoped>
.perf-chart {
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 6px;
  padding: 8px 10px 4px;
  min-width: 0;
}
.perf-chart-head {
  display: flex;
  align-items: baseline;
  gap: 8px;
  margin-bottom: 4px;
}
.perf-chart-title {
  font-weight: 600;
  font-size: 13px;
}
.perf-chart-sub {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.perf-chart-canvas {
  position: relative;
}
.perf-chart-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 120px;
  margin: 0;
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
</style>
