-- Migration 028: agentic SOC triage — one LLM verdict per alert.
--
-- alert_triage — one row per alert (alert_id is the PK), overwritten on
-- re-run (no history table; add alert_triage_history later if ever needed).
-- Cascades with the alert, so alert retention/cleanup reaps triage rows too.
--
-- `status='degraded'` is NOT a state — see the `degraded` boolean below.
-- `failed` = infra error (no key, provider unreachable, DB error), retryable.
-- `degraded` = the model ran but never emitted a usable schema, so a
-- conservative deterministic verdict was stored; NOT auto-retried forever.
--
-- Idempotent / re-runnable.

CREATE TABLE IF NOT EXISTS alert_triage (
    alert_id          INTEGER PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE,
    status             TEXT NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending','analyzing','complete','failed','skipped')),
    verdict            TEXT CHECK (verdict IN ('true_positive','false_positive','suspicious','inconclusive')),
    risk_score         SMALLINT CHECK (risk_score BETWEEN 0 AND 100),
    confidence         TEXT CHECK (confidence IN ('low','medium','high')),
    summary            TEXT,
    reasoning          TEXT,                 -- markdown
    evidence           JSONB,                -- [{claim, source, detail}]
    suggested_queries  JSONB,                -- [{label, tool, args, why}]
    remediation        JSONB,                -- {proposed_status, urgency, steps[], notes}
    trace              JSONB,                -- AnalystTraceEntry[] (same shape as chat_messages.trace)
    provider           TEXT,
    model              TEXT,
    iterations         SMALLINT,
    tool_calls         SMALLINT,
    duration_ms        INTEGER,
    truncated          BOOLEAN NOT NULL DEFAULT FALSE,
    degraded           BOOLEAN NOT NULL DEFAULT FALSE,
    error              TEXT,
    attempts           SMALLINT NOT NULL DEFAULT 0,
    triggered_by       TEXT NOT NULL DEFAULT 'auto'
                         CHECK (triggered_by IN ('auto','manual','reconciler')),
    requested_by       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    started_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Reconciler: find rows a dead process left claimed.
CREATE INDEX IF NOT EXISTS idx_alert_triage_inflight
  ON alert_triage (updated_at) WHERE status IN ('pending','analyzing');
-- Cost cap: count runs in the last 24h.
CREATE INDEX IF NOT EXISTS idx_alert_triage_created ON alert_triage (created_at DESC);
-- "Worst first" views / future dashboards.
CREATE INDEX IF NOT EXISTS idx_alert_triage_verdict ON alert_triage (verdict, risk_score DESC);
