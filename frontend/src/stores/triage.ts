/**
 * Agentic SOC triage store. Holds the fetched verdict per alert and owns the
 * poll for a run still in progress — owned here (not the component) so
 * polling survives the detail dialog being closed and reopened.
 */
import { defineStore } from 'pinia';
import { ref } from 'vue';
import { api } from '@/services/api';

export type TriageStatus = 'pending' | 'analyzing' | 'complete' | 'failed' | 'skipped';
export type TriageVerdictLabel = 'true_positive' | 'false_positive' | 'suspicious' | 'inconclusive';

export interface TriageEvidenceItem {
  claim: string;
  source: string;
  detail?: string;
}
export interface TriageSuggestedQuery {
  label: string;
  tool: string;
  args: Record<string, any>;
  why?: string;
}
export interface TriageRemediation {
  proposed_status: 'new' | 'investigating' | 'closed' | 'false_positive';
  urgency: 'none' | 'low' | 'medium' | 'high' | 'immediate';
  steps: string[];
  notes?: string;
}
export interface TriageRow {
  alert_id: number;
  status: TriageStatus;
  verdict: TriageVerdictLabel | null;
  risk_score: number | null;
  confidence: 'low' | 'medium' | 'high' | null;
  summary: string | null;
  reasoning: string | null;
  evidence: TriageEvidenceItem[] | null;
  suggested_queries: TriageSuggestedQuery[] | null;
  remediation: TriageRemediation | null;
  trace: Array<{ step: number; tool: string; args: any; ok: boolean; ms: number; error?: string; result?: string }> | null;
  provider: string | null;
  model: string | null;
  truncated: boolean;
  degraded: boolean;
  error: string | null;
  created_at: string;
  updated_at: string;
}

const POLL_INTERVAL_MS = 5000;
const MAX_POLLS = 42; // ~3.5 minutes, comfortably past the agent's own ~110s wall budget

const IN_PROGRESS: TriageStatus[] = ['pending', 'analyzing'];

export const useTriageStore = defineStore('triage', () => {
  const byAlert = ref<Record<number, TriageRow | null>>({});
  const eligibleByAlert = ref<Record<number, boolean>>({});
  const loading = ref<Record<number, boolean>>({});
  const enabled = ref(false);
  const notConfigured = ref(false);
  const minSeverity = ref<'low' | 'medium' | 'high' | 'critical'>('medium');

  const pollTimers: Record<number, number> = {};
  const pollCounts: Record<number, number> = {};

  async function checkHealth() {
    try {
      const res = await api.getTriageHealth();
      enabled.value = !!res.data?.enabled;
      notConfigured.value = !res.data?.configured;
      minSeverity.value = res.data?.minSeverity || 'medium';
    } catch {
      enabled.value = false;
      notConfigured.value = true;
    }
  }

  function stopPolling(alertId: number) {
    const t = pollTimers[alertId];
    if (t) {
      window.clearInterval(t);
      delete pollTimers[alertId];
    }
    delete pollCounts[alertId];
  }

  async function fetchTriage(alertId: number): Promise<TriageRow | null> {
    loading.value = { ...loading.value, [alertId]: true };
    try {
      const res = await api.getAlertTriage(alertId);
      const row: TriageRow | null = res.data?.triage ?? null;
      byAlert.value = { ...byAlert.value, [alertId]: row };
      eligibleByAlert.value = { ...eligibleByAlert.value, [alertId]: !!res.data?.eligible };
      if (row && IN_PROGRESS.includes(row.status)) {
        startPolling(alertId);
      } else {
        stopPolling(alertId);
      }
      return row;
    } catch {
      return null;
    } finally {
      loading.value = { ...loading.value, [alertId]: false };
    }
  }

  function startPolling(alertId: number) {
    if (pollTimers[alertId]) return; // already polling
    pollCounts[alertId] = 0;
    pollTimers[alertId] = window.setInterval(async () => {
      pollCounts[alertId] = (pollCounts[alertId] || 0) + 1;
      if (pollCounts[alertId] > MAX_POLLS) {
        stopPolling(alertId);
        return;
      }
      await fetchTriage(alertId);
    }, POLL_INTERVAL_MS);
  }

  async function rerun(alertId: number): Promise<void> {
    await api.rerunAlertTriage(alertId);
    byAlert.value = {
      ...byAlert.value,
      [alertId]: { ...(byAlert.value[alertId] || ({} as TriageRow)), status: 'pending' },
    };
    startPolling(alertId);
  }

  return {
    byAlert,
    eligibleByAlert,
    loading,
    enabled,
    notConfigured,
    minSeverity,
    checkHealth,
    fetchTriage,
    startPolling,
    stopPolling,
    rerun,
  };
});
