# Agentic SOC Triage — Design

Automatic, per-alert LLM triage: a second consumer of the AI Security Analyst's
existing read-only tool loop (`backend/src/services/ai/`), pointed at a
different job — instead of answering an operator's typed question, it runs
automatically after alert creation and emits a structured, persisted verdict
instead of markdown prose. User-facing behavior is documented in the wiki:
[AI Security Analyst → Automated triage](../../wiki/AI-Security-Analyst.md#automated-triage).
This document is the internal design record.

## Why a second consumer, not a new subsystem

SIEMBox already had almost every building block this needed:

- **LLM client** (`aiService.ts`) — provider-agnostic (anthropic/openai/ollama),
  encrypted-key storage, a proven "own config, inherits a parent when unset"
  pattern (main → chat). Triage adds a third link: **triage → chat → main**.
- **Agentic loop shape** (`analystChat.ts`) — one JSON action per turn
  (`{"action":"tool",...}` / `{"action":"final",...}`), budget caps, a
  reprompt-then-synthesize fallback ladder.
- **Tool registry** (`analystTools.ts`) — read-only by construction ("there
  are no create/update/delete executors" — the file's own header comment).
  This is the extensibility seam: a new data source for the triage agent to
  consult is one new `AnalystTool` entry, not a loop or prompt change.

Reusing these keeps the safety model — read-only tools, untrusted tool data,
no code execution — in exactly one place instead of two parallel
implementations that could drift.

## What's actually new

| Module | Role |
|---|---|
| `triageAgent.ts` | The loop, forked from `analystChat.ts`'s shape but terminating in a **strict, schema-validated verdict object** instead of free markdown, with zero conversation history (system prompt + the serialized alert as the one user turn). |
| `triageService.ts` | Orchestration: the hot-path gate (severity check, config cache), a bounded/priority in-process queue, the daily-cap and dedupe-window cost controls, and the claim → analyze → persist run. |
| `AlertTriage.ts` (model) + `alert_triage` table | Persistence — one row per alert, `alert_id` as the PK so a re-run is an UPSERT. |
| `triageReconciler.ts` | A `setInterval` safety net (mirrors `scanReconciler.ts`'s "in-memory workers, reconciled on restart" precedent) that requeues runs orphaned by a backend restart and backfills alerts that never got a triage row at all. |

## The verdict contract

The model is asked for exactly one JSON object per turn: a tool call, or the
final verdict —

```json
{
  "action": "final",
  "verdict": "true_positive|false_positive|suspicious|inconclusive",
  "risk_score": 0-100,
  "confidence": "low|medium|high",
  "summary": "...",
  "reasoning": "...markdown...",
  "evidence": [{ "claim": "...", "source": "...", "detail": "..." }],
  "suggested_queries": [{ "label": "...", "tool": "...", "args": {...}, "why": "..." }],
  "proposed_status": "new|investigating|closed|false_positive",
  "urgency": "none|low|medium|high|immediate",
  "remediation_steps": ["..."],
  "remediation_notes": "..."
}
```

`normalizeVerdict()` (exported, pure, never throws) is the validation core:
enum synonyms are snapped (`"benign"` → `false_positive`, etc.), a missing or
out-of-range `risk_score` is clamped/defaulted from the verdict, arrays are
capped and coerced, and — the important one — any `suggested_queries` entry
naming a tool that isn't in the registry is **dropped**, so the UI can never
offer a query that can't run and the model can't invent capability.

**Repair ladder** when the model's output doesn't validate: up to two
reprompts carrying the specific validation issues back to the model (the same
"feed the model its own errors" pattern already proven in
`aiService.ts`'s `generateParser`/`generateDetection`) → a synthesis call with
tools stripped ("output ONLY the verdict object") → a deterministic in-code
fallback verdict derived from the alert's severity, marked `degraded: true`.
The function must always return something persistable; there is no user to
show an error message to.

## Trigger, cost controls, and the two alert-creation call sites

Alerts are created from **two** places, not one — `rulesEngine.ts`'s
`createAlert()` (syslog rule matches) and `edrService.ts`'s `ingestEvents()`
(endpoint-agent detections, via a raw SQL insert that bypasses `AlertModel.create()`
for its `ON CONFLICT` dedup clause). Both already fire-and-forget
`NotificationService.notifyAlert(...)` identically; `maybeTriageAlert(...)` is
added at both sites the same way — one line, mirroring an existing pattern,
not a new event bus.

`maybeTriageAlert` is deliberately synchronous-returning and never blocks
ingest: it checks a 30s-TTL cached operational config, applies the severity
gate, and pushes onto an in-process priority queue (critical/high ahead of
medium). Layered cost controls, since the severity gate alone doesn't bound a
burst (the EDR path has no per-rule cooldown, unlike the syslog rules
engine):

1. **Severity gate** — off by default; only alerts ≥ a configured minimum.
2. **Dedupe window** — skip if an equivalent alert (same rule + title) was
   triaged recently. The single highest-leverage control.
3. **Daily cap** — a hard ceiling on triage runs per 24h, applies to every
   trigger including manual re-run.
4. **Concurrency limit + bounded queue** — caps how many analyses run at
   once; on overflow, the newest alert is skipped (visibly, via
   `status='skipped'`) rather than growing unbounded.
5. **Per-analysis budget** — `maxToolCalls` (default 6) and `wallBudgetSeconds`
   (default 110) bound how deep and how long a single alert's analysis can go;
   both are admin-configurable (Settings → AI Triage /
   `TriageOperationalConfig`) and passed into `runAlertTriage` via
   `TriageAgentDeps`. `triageAgent.ts`'s internal iteration cap is *derived*
   from `maxToolCalls` (`+2`, for a reprompt and the final synthesis turn) so
   it can never silently override a raised tool-call budget. `TOTAL_TOOL_BYTES`
   (aggregate tool-result bytes fed back to the model) stays a fixed internal
   safety rail, not exposed — it protects the model's context, not analysis
   depth. Hitting either exposed cap forces `SYNTHESIS_PROMPT` to produce a
   verdict from whatever was already gathered (`truncated: true` on the
   result, surfaced in the UI as "stopped early at the analysis budget").

## Threat model notes

- **Prompt injection via alert content.** Titles/descriptions/`matched_data`
  are attacker-influenced and sit in the *user* turn here (a more privileged
  position than the tool-result turns the chat analyst already treats as
  untrusted). The structural defense is the schema validation above: the
  worst a successful injection achieves is a skewed verdict — it cannot name
  a nonexistent tool, produce an out-of-range score, or cause a write.
- **Unattended data egress.** Unlike the chat analyst (a human must type a
  question before anything is sent to a provider), triage sends every
  eligible alert automatically once enabled. This is why the feature ships
  **off by default**.
- **No new write path.** `remediation` is always inert data. Applying it
  (e.g. a status change) still requires an explicit human action through the
  existing `PUT /api/alerts/:id` — the triage agent has no executor, by the
  same construction as the chat analyst's tool registry.

## Extension points ("thin and extensible")

- **New data source** → add one entry to `analystTools.ts`'s `ALL_TOOLS`
  (name/description/args/`run`). Both the chat analyst and the triage agent
  pick it up automatically via `getToolsForRole`.
- **New detection type** → nothing. The agent reasons generically over
  whatever's in `matched_data`/`title`/`rule_name`, the same way the rules
  engine itself is generic over `rules/*.yaml` — a new detection category is
  purely new rule content, never a triage-agent code change.
