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
      <div v-if="row.summary || row.reasoning" class="analysis-body">
        <p v-if="row.summary" class="summary-line">{{ row.summary }}</p>
        <div v-if="row.reasoning" class="md-body" v-html="renderMarkdown(row.reasoning)"></div>
      </div>

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
            <div class="remediation-info">
              <el-tag size="small" :type="urgencyType(row.remediation.urgency)">{{ row.remediation.urgency }} urgency</el-tag>
              <ol v-if="row.remediation.steps && row.remediation.steps.length" class="remediation-steps">
                <li v-for="(s, i) in row.remediation.steps" :key="i">{{ s }}</li>
              </ol>
              <p v-if="row.remediation.notes" class="remediation-notes"><strong>Note:</strong> {{ row.remediation.notes }}</p>
            </div>
            <el-button size="small" @click="useSuggestedStatus">
              Use suggested status ({{ formatStatus(row.remediation.proposed_status) }})
            </el-button>
          </div>
        </el-alert>
      </div>

      <el-collapse v-if="row.trace && row.trace.length" class="trace">
        <el-collapse-item :title="`Ran ${row.trace.length} tool${row.trace.length > 1 ? 's' : ''}`">
          <div v-for="t in row.trace" :key="t.step" class="trace-item">
            <div class="trace-row" @click="toggleTraceStep(t.step)">
              <el-icon class="trace-caret" :class="{ open: isTraceStepOpen(t.step) }"><ArrowRight /></el-icon>
              <el-tag size="small" :type="t.ok ? 'success' : 'danger'">{{ t.tool }}</el-tag>
              <span class="trace-ms">{{ t.ms }}ms</span>
              <span v-if="t.error" class="trace-err">{{ t.error }}</span>
            </div>
            <div v-if="isTraceStepOpen(t.step)" class="trace-detail">
              <div class="trace-detail-block">
                <div class="trace-detail-label">Args</div>
                <pre class="trace-json">{{ formatTraceJson(t.args) }}</pre>
              </div>
              <div class="trace-detail-block">
                <div class="trace-detail-label">Result</div>
                <pre class="trace-json">{{ formatTraceJson(t.result) }}</pre>
              </div>
            </div>
          </div>
        </el-collapse-item>
      </el-collapse>

      <div class="footer-meta">
        <span v-if="row.provider">{{ row.provider }}/{{ row.model }}</span>
        <span v-if="row.degraded" class="degraded">⚠ analysis was incomplete — treat this verdict as low-confidence</span>
        <el-tooltip
          v-if="row.truncated"
          content="Hit the per-alert tool-call or time budget before reaching a final answer, so this verdict was synthesized from whatever it had gathered so far. Both are adjustable in Settings → AI Triage."
          placement="top"
        >
          <span class="degraded">⚠ stopped early at the analysis budget</span>
        </el-tooltip>
        <el-button v-if="canRerun" size="small" :loading="running" @click="runNow">Re-run</el-button>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { Loading, ArrowRight } from '@element-plus/icons-vue';
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

// Which trace steps are expanded to show their args/result — local to the
// panel instance, reset for free on alert switch since AlertDetailDialog
// keys AlertTriagePanel by alert id (remounts rather than reusing state).
const expandedTraceSteps = ref<Set<number>>(new Set());
function isTraceStepOpen(step: number): boolean {
  return expandedTraceSteps.value.has(step);
}
function toggleTraceStep(step: number): void {
  const next = new Set(expandedTraceSteps.value);
  if (next.has(step)) next.delete(step);
  else next.add(step);
  expandedTraceSteps.value = next;
}
/** `result` is a pre-stringified (and possibly truncated) JSON blob; `args` is a plain object. Pretty-print either, falling back to raw text if it doesn't parse. */
function formatTraceJson(value: unknown): string {
  if (value === undefined || value === null || value === '') return '(none)';
  if (typeof value === 'string') {
    try {
      return JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      return value;
    }
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
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
.analysis-body {
  background: var(--el-fill-color-light);
  border-radius: 8px;
  padding: 10px 14px;
  margin-bottom: 12px;
}
.summary-line {
  font-weight: 600;
  line-height: 1.4;
  margin: 0;
}
.summary-line + .md-body {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid var(--el-border-color-lighter);
}
.md-body {
  font-size: 14px;
  line-height: 1.55;
}
.md-body :deep(p:first-child) {
  margin-top: 0;
}
.md-body :deep(p:last-child) {
  margin-bottom: 0;
}
.md-body :deep(ol),
.md-body :deep(ul) {
  padding-left: 20px;
  margin: 6px 0;
}
.md-body :deep(li) {
  margin-bottom: 3px;
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
  gap: 12px;
  margin-top: 4px;
}
.remediation-info {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.remediation-steps {
  margin: 0;
  padding-left: 18px;
}
.remediation-steps li {
  margin-bottom: 3px;
}
.remediation-notes {
  color: var(--siembox-text-secondary);
  font-size: 13px;
  margin: 0;
}
.remediation-notes strong {
  color: var(--siembox-text-color);
}
.trace {
  margin-top: 4px;
}
.trace-item {
  border-bottom: 1px solid var(--el-border-color-lighter);
}
.trace-item:last-child {
  border-bottom: none;
}
.trace-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  padding: 4px 0;
  color: var(--siembox-text-secondary);
  cursor: pointer;
}
.trace-caret {
  font-size: 11px;
  transition: transform 0.15s ease;
}
.trace-caret.open {
  transform: rotate(90deg);
}
.trace-ms {
  margin-left: auto;
}
.trace-err {
  color: var(--el-color-danger);
}
.trace-detail {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 4px 0 10px 19px;
}
.trace-detail-label {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.02em;
  color: var(--siembox-text-secondary);
  margin-bottom: 3px;
}
.trace-json {
  background: var(--el-fill-color-light);
  border-radius: 6px;
  padding: 8px 10px;
  margin: 0;
  font-size: 12px;
  font-family: var(--el-font-family-mono, monospace);
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 240px;
  overflow-y: auto;
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
