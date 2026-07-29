<template>
  <div class="triage-panel">
    <el-alert
      v-if="!triageStore.enabled || triageStore.notConfigured"
      class="cfg-alert"
      type="warning"
      :closable="false"
      show-icon
      title="AI Triage is not configured"
    >
      An admin can enable automatic alert analysis in
      <router-link to="/settings">Settings → AI Triage</router-link>.
    </el-alert>

    <template v-else-if="!row">
      <el-text v-if="!eligible" type="info">
        Only {{ triageStore.minSeverity }}+ severity alerts are triaged automatically.
      </el-text>
      <el-text v-else type="info">No analysis yet.</el-text>
      <div class="actions">
        <el-button size="small" :loading="running" @click="runNow">Analyze now</el-button>
      </div>
    </template>

    <template v-else-if="row.status === 'pending' || row.status === 'analyzing'">
      <el-skeleton :rows="3" animated />
      <div class="analyzing-row">
        <el-icon class="spin"><Loading /></el-icon>
        <span>{{ row.status === 'analyzing' ? 'Analyzing' : 'Queued' }}… {{ elapsed }}s</span>
      </div>
    </template>

    <template v-else-if="row.status === 'failed'">
      <el-alert type="error" :closable="false" show-icon :title="row.error || 'Triage failed'" />
      <div class="actions">
        <el-button size="small" :loading="running" @click="runNow">Re-run</el-button>
      </div>
    </template>

    <template v-else-if="row.status === 'skipped'">
      <el-text type="info">Skipped — {{ row.error || 'no reason given' }}.</el-text>
      <div class="actions">
        <el-button size="small" :loading="running" @click="runNow">Analyze now</el-button>
      </div>
    </template>

    <template v-else-if="row.status === 'complete'">
      <div class="rep-row">
        <el-tag :type="verdictType(row.verdict)" size="large">{{ verdictLabel(row.verdict) }}</el-tag>
        <span class="risk-score">risk {{ row.risk_score ?? '—' }}/100</span>
        <el-tag size="small" type="info">{{ row.confidence || 'low' }} confidence</el-tag>
      </div>
      <p v-if="row.summary" class="summary">{{ row.summary }}</p>

      <div v-if="row.reasoning" class="md-body" v-html="renderMarkdown(row.reasoning)"></div>

      <div v-if="row.evidence && row.evidence.length" class="section">
        <h4>Evidence</h4>
        <ul class="evidence-list">
          <li v-for="(e, i) in row.evidence" :key="i">
            <el-tag size="small" type="info">{{ e.source }}</el-tag>
            {{ e.claim }}
            <span v-if="e.detail" class="evidence-detail">— {{ e.detail }}</span>
          </li>
        </ul>
      </div>

      <div v-if="row.suggested_queries && row.suggested_queries.length" class="section">
        <h4>Suggested next-step queries</h4>
        <ul class="query-list">
          <li v-for="(q, i) in row.suggested_queries" :key="i">
            <span class="query-label">{{ q.label }}</span>
            <span v-if="q.why" class="query-why">— {{ q.why }}</span>
            <el-button link size="small" @click="askAnalyst(q)">Ask the analyst</el-button>
          </li>
        </ul>
      </div>

      <div v-if="row.remediation" class="section">
        <el-alert type="info" :closable="false" show-icon title="Proposed remediation — not executed">
          <div class="remediation-body">
            <el-tag size="small" :type="urgencyType(row.remediation.urgency)">{{ row.remediation.urgency }} urgency</el-tag>
            <ol v-if="row.remediation.steps && row.remediation.steps.length" class="remediation-steps">
              <li v-for="(s, i) in row.remediation.steps" :key="i">{{ s }}</li>
            </ol>
            <p v-if="row.remediation.notes" class="remediation-notes">{{ row.remediation.notes }}</p>
            <el-button size="small" @click="useSuggestedStatus">
              Use suggested status ({{ formatStatus(row.remediation.proposed_status) }})
            </el-button>
          </div>
        </el-alert>
      </div>

      <el-collapse v-if="row.trace && row.trace.length" class="trace">
        <el-collapse-item :title="`Ran ${row.trace.length} tool${row.trace.length > 1 ? 's' : ''}`">
          <div v-for="t in row.trace" :key="t.step" class="trace-row">
            <el-tag size="small" :type="t.ok ? 'success' : 'danger'">{{ t.tool }}</el-tag>
            <span class="trace-ms">{{ t.ms }}ms</span>
            <span v-if="t.error" class="trace-err">{{ t.error }}</span>
          </div>
        </el-collapse-item>
      </el-collapse>

      <div class="footer-meta">
        <span v-if="row.provider">{{ row.provider }}/{{ row.model }}</span>
        <span v-if="row.degraded" class="degraded">⚠ analysis was incomplete — treat this verdict as low-confidence</span>
        <span v-if="row.truncated" class="degraded">⚠ stopped early at the analysis budget</span>
        <el-button v-if="canRerun" size="small" :loading="running" @click="runNow">Re-run</el-button>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { Loading } from '@element-plus/icons-vue';
import { ElMessage } from 'element-plus';
import { useTriageStore, type TriageSuggestedQuery } from '@/stores/triage';
import { useChatStore } from '@/stores/chat';
import { useAuthStore } from '@/stores/auth';
import { renderMarkdown } from '@/utils/markdown';

const props = defineProps<{
  alertId: number;
  severity: string;
}>();

const emit = defineEmits<{
  'use-status': [status: string];
}>();

const triageStore = useTriageStore();
const chatStore = useChatStore();
const authStore = useAuthStore();

const running = ref(false);
const elapsed = ref(0);
let elapsedTimer: number | null = null;

const row = computed(() => triageStore.byAlert[props.alertId] ?? null);
const eligible = computed(() => triageStore.eligibleByAlert[props.alertId] ?? true);
const canRerun = computed(() => ['admin', 'analyst', 'operator'].includes(authStore.user?.role || ''));

function verdictLabel(v: string | null): string {
  return (v || 'inconclusive').replace('_', ' ').toUpperCase();
}
function verdictType(v: string | null): string {
  return { true_positive: 'danger', suspicious: 'warning', false_positive: 'success', inconclusive: 'info' }[
    v || 'inconclusive'
  ] || 'info';
}
function urgencyType(u: string): string {
  return { immediate: 'danger', high: 'danger', medium: 'warning', low: 'info', none: 'info' }[u] || 'info';
}
function formatStatus(s: string): string {
  return s.replace('_', ' ').replace(/\b\w/g, (l) => l.toUpperCase());
}

async function runNow() {
  running.value = true;
  try {
    await triageStore.rerun(props.alertId);
  } catch {
    ElMessage.error('Failed to start triage');
  } finally {
    running.value = false;
  }
}

function useSuggestedStatus() {
  if (row.value?.remediation?.proposed_status) {
    emit('use-status', row.value.remediation.proposed_status);
  }
}

function askAnalyst(q: TriageSuggestedQuery) {
  const seed = `${q.label}${q.why ? ` — ${q.why}` : ''} (tool: ${q.tool})`;
  chatStore.openWithContext({ kind: 'alert', id: props.alertId }, seed);
}

function tickElapsed() {
  elapsed.value += 1;
}
watch(
  () => row.value?.status,
  (status) => {
    if (elapsedTimer) {
      window.clearInterval(elapsedTimer);
      elapsedTimer = null;
    }
    if (status === 'pending' || status === 'analyzing') {
      elapsed.value = 0;
      elapsedTimer = window.setInterval(tickElapsed, 1000);
    }
  },
  { immediate: true }
);

onMounted(async () => {
  await triageStore.checkHealth();
  await triageStore.fetchTriage(props.alertId);
});

onUnmounted(() => {
  if (elapsedTimer) window.clearInterval(elapsedTimer);
  triageStore.stopPolling(props.alertId);
});
</script>

<style scoped>
.triage-panel {
  padding: 4px 0;
}
.cfg-alert {
  margin-bottom: 8px;
}
.actions {
  margin-top: 10px;
}
.analyzing-row {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 8px;
  color: var(--siembox-text-secondary);
  font-size: 13px;
}
.spin {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
.rep-row {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.risk-score {
  color: var(--siembox-text-secondary);
  font-weight: 600;
}
.summary {
  font-weight: 500;
  margin: 4px 0 10px;
}
.md-body {
  background: var(--el-fill-color-light);
  border-radius: 8px;
  padding: 9px 12px;
  font-size: 14px;
  line-height: 1.55;
  margin-bottom: 12px;
}
.md-body :deep(p:first-child) {
  margin-top: 0;
}
.md-body :deep(p:last-child) {
  margin-bottom: 0;
}
.section {
  margin-bottom: 14px;
}
.section h4 {
  margin: 0 0 6px;
  font-size: 13px;
  color: var(--siembox-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.02em;
}
.evidence-list,
.query-list {
  margin: 0;
  padding-left: 18px;
  font-size: 13px;
}
.evidence-list li,
.query-list li {
  margin-bottom: 4px;
}
.evidence-detail,
.query-why {
  color: var(--siembox-text-secondary);
}
.query-label {
  font-weight: 500;
}
.remediation-body {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-top: 4px;
}
.remediation-steps {
  margin: 0;
  padding-left: 18px;
}
.remediation-notes {
  color: var(--siembox-text-secondary);
  font-size: 13px;
  margin: 0;
}
.trace {
  margin-top: 4px;
}
.trace-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  padding: 2px 0;
  color: var(--siembox-text-secondary);
}
.trace-ms {
  margin-left: auto;
}
.trace-err {
  color: var(--el-color-danger);
}
.footer-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 10px;
  font-size: 12px;
  color: var(--siembox-text-secondary);
}
.degraded {
  color: var(--el-color-warning);
}
</style>
