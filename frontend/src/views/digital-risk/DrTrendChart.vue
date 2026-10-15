<template>
  <div class="dr-trend">
    <div class="trend-toolbar">
      <el-text size="small" type="info">
        Counted when SIEMBox first detected each finding, not the breach date. Times are UTC.
      </el-text>
      <el-switch v-model="showTable" active-text="Table" aria-label="Show the numbers as a table" :disabled="isEmpty" />
    </div>

    <p v-if="isEmpty" class="trend-empty">No findings detected or resolved in the last {{ window.days }} days</p>

    <el-table v-else-if="showTable" :data="tableRows" size="small" stripe max-height="320" class="trend-table">
      <el-table-column :label="bucketLabel" min-width="130">
        <template #default="{ row }">{{ row.label }}</template>
      </el-table-column>
      <el-table-column v-for="c in RISK_CATEGORIES" :key="c.key" :label="c.label" min-width="110" align="right">
        <template #default="{ row }">{{ row.new[c.key] }}</template>
      </el-table-column>
      <el-table-column label="Resolved" min-width="90" align="right" prop="resolved" />
      <el-table-column label="Open at the end" min-width="110" align="right" prop="open_at_end" />
      <el-table-column label="Monitoring added" min-width="140">
        <template #default="{ row }">{{ row.added || '—' }}</template>
      </el-table-column>
    </el-table>

    <div v-else class="trend-canvas">
      <Bar :key="themeKey" :data="chartData" :options="chartOptions" :aria-label="ariaLabel" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue';
import { Bar } from 'vue-chartjs';
import {
  BarController,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
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
import type { ExposureSummary, ExposureTrendBucket } from '@/services/exposureService';
import { RISK_CATEGORIES, pluralize } from '@/utils/exposure';
import { formatBucketLabel } from './dashboard';

// Only what this chart draws: stacked bars, one line, two axes, tooltip and legend.
ChartJS.register(BarController, BarElement, LineController, LineElement, PointElement, CategoryScale, LinearScale, Tooltip, Legend);

const props = defineProps<{
  trend: ExposureTrendBucket[];
  window: ExposureSummary['window'];
}>();

const themeStore = useThemeStore();
const showTable = ref(false);

const totalNew = (b: ExposureTrendBucket) => b.new.credentials + b.new.impersonation + b.new.domain_changes;
const sumNew = computed(() => props.trend.reduce((n, b) => n + totalNew(b), 0));
const sumResolved = computed(() => props.trend.reduce((n, b) => n + b.resolved, 0));
const isEmpty = computed(() => sumNew.value + sumResolved.value === 0);
const bucketLabel = computed(() => ({ day: 'Day', week: 'Week starting', month: 'Month' })[props.window.bucket]);
const ariaLabel = computed(
  () =>
    `${pluralize(sumNew.value, 'finding')} detected and ${sumResolved.value.toLocaleString()} resolved in the last ${props.window.days} days, per ${props.window.bucket}`
);

function addedText(b: ExposureTrendBucket): string {
  const parts = [];
  if (b.monitoring_added.identities) parts.push(pluralize(b.monitoring_added.identities, 'identity', 'identities'));
  if (b.monitoring_added.domains) parts.push(pluralize(b.monitoring_added.domains, 'domain'));
  return parts.join(', ');
}

const tableRows = computed(() =>
  props.trend.map((b) => ({ ...b, label: formatBucketLabel(b.start, props.window.bucket, true), added: addedText(b) }))
);

// The theme's surface and ink, read off the page once the theme class has switched.
interface Ink {
  card: string;
  grid: string;
  text: string;
  resolved: string;
}
function readInk(): Ink {
  const css = getComputedStyle(document.documentElement);
  const v = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback;
  return {
    card: v('--siembox-card-bg', '#fff'),
    grid: v('--siembox-border-color', '#dcdfe6'),
    text: v('--siembox-text-secondary', '#606266'),
    resolved: v('--siembox-text-tertiary', '#909399'),
  };
}
const ink = ref<Ink>(readInk());
// The chart is drawn again in the new theme's colours (a new key rebuilds it).
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
  const dark = themeStore.isDark;
  const data = {
    labels: props.trend.map((b) => formatBucketLabel(b.start, props.window.bucket)),
    datasets: [
      ...RISK_CATEGORIES.map((c) => ({
        type: 'bar' as const,
        label: c.label,
        data: props.trend.map((b) => b.new[c.key]),
        backgroundColor: dark ? c.dark : c.light,
        // A 2 px gap in the card's colour between stacked segments.
        borderColor: ink.value.card,
        borderWidth: { top: 2, right: 0, bottom: 0, left: 0 },
        borderRadius: 4,
        borderSkipped: 'start' as const,
        maxBarThickness: 28,
        stack: 'new',
        order: 2,
      })),
      {
        type: 'line' as const,
        label: 'Resolved',
        data: props.trend.map((b) => b.resolved),
        borderColor: ink.value.resolved,
        backgroundColor: 'transparent',
        pointBackgroundColor: ink.value.resolved,
        borderDash: [6, 4],
        borderWidth: 2,
        pointRadius: 2,
        pointHoverRadius: 5,
        pointHitRadius: 10,
        tension: 0,
        // Its own stack, so the line isn't piled on top of the bars.
        stack: 'resolved',
        order: 1,
      },
    ],
  };
  return data as unknown as ChartData<'bar'>;
});

const chartOptions = computed<ChartOptions<'bar'>>(() => {
  const { grid, text } = ink.value;
  const trend = props.trend;
  const bucket = props.window.bucket;
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: {
        display: true,
        position: 'bottom',
        // The categories in their fixed order, then Resolved (`order` only sets the drawing order).
        labels: { color: text, boxWidth: 12, boxHeight: 12, padding: 14, sort: (a, b) => (a.datasetIndex ?? 0) - (b.datasetIndex ?? 0) },
      },
      tooltip: {
        callbacks: {
          title: (items: TooltipItem<'bar'>[]) => {
            const b = trend[items[0]?.dataIndex ?? 0];
            return b ? formatBucketLabel(b.start, bucket, true) : '';
          },
          label: (item: TooltipItem<'bar'>) => `${item.dataset.label}: ${Number(item.raw).toLocaleString()}`,
          footer: (items: TooltipItem<'bar'>[]) => {
            const b = trend[items[0]?.dataIndex ?? 0];
            if (!b) return [];
            const lines = [`Total new ${totalNew(b).toLocaleString()}`, `Open at the end ${b.open_at_end.toLocaleString()}`];
            const added = addedText(b);
            if (added) lines.push(`Monitoring added: ${added}`);
            return lines;
          },
        },
      },
    },
    scales: {
      x: {
        stacked: true,
        grid: { display: false },
        border: { color: grid },
        ticks: { color: text, maxRotation: 0, autoSkip: true, autoSkipPadding: 12 },
      },
      y: {
        stacked: true,
        beginAtZero: true,
        grid: { color: grid },
        border: { display: false },
        ticks: { color: text, precision: 0 },
      },
    },
  };
});
</script>

<style scoped>
.trend-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}

.trend-canvas {
  position: relative;
  height: 280px;
}

.trend-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 200px;
  margin: 0;
  text-align: center;
  font-size: 13px;
  color: var(--siembox-text-secondary);
}
</style>
