/**
 * Tests for the agentic triage loop and its verdict validation/repair ladder.
 * In-memory and DB-free (deps.complete/deps.executeTool are injected — no
 * network, no database). `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runAlertTriage, normalizeVerdict, TriageAgentDeps } from './triageAgent';

const ALERT = {
  id: 1,
  severity: 'high',
  title: 'SSH brute force from 203.0.113.5',
  description: '12 failed logins in 5 minutes',
  status: 'new',
  source: 'rule',
  asset_id: null,
  created_at: new Date().toISOString(),
  matched_data: { source_ip: '203.0.113.5', count: 12 },
};

const VALID_FINAL = {
  action: 'final',
  verdict: 'true_positive',
  risk_score: 82,
  confidence: 'high',
  summary: 'Repeated failed SSH logins from an external IP.',
  reasoning: 'The source IP is external and unrelated to any known asset.',
  evidence: [{ claim: '12 failed logins in 5 minutes', source: 'alert' }],
  suggested_queries: [{ label: 'Check IP reputation', tool: 'lookup_ip', args: { ip: '203.0.113.5' } }],
  proposed_status: 'investigating',
  urgency: 'high',
  remediation_steps: ['Block 203.0.113.5 at the firewall'],
};

function baseDeps(complete: TriageAgentDeps['complete']): TriageAgentDeps {
  return {
    complete,
    getConfig: async () => ({ provider: 'anthropic', model: 'test-model' }),
  };
}

test('happy path: a valid final verdict on the first turn is used as-is', async () => {
  const result = await runAlertTriage(
    { alert: ALERT },
    baseDeps(async () => JSON.stringify(VALID_FINAL))
  );

  assert.equal(result.degraded, false);
  assert.equal(result.verdict.verdict, 'true_positive');
  assert.equal(result.verdict.risk_score, 82);
  assert.equal(result.verdict.remediation.proposed_status, 'investigating');
  assert.equal(result.toolCalls, 0);
});

test('a tool call is executed via deps.executeTool before the final verdict', async () => {
  let calls = 0;
  const executed: any[] = [];
  const result = await runAlertTriage(
    { alert: ALERT },
    {
      ...baseDeps(async () => {
        calls++;
        if (calls === 1) return JSON.stringify({ action: 'tool', tool: 'get_alert', args: { id: 1 } });
        return JSON.stringify(VALID_FINAL);
      }),
      executeTool: async (name, args) => {
        executed.push({ name, args });
        return { id: 1, title: ALERT.title };
      },
    }
  );

  assert.equal(executed.length, 1);
  assert.equal(executed[0].name, 'get_alert');
  assert.equal(result.toolCalls, 1);
  assert.equal(result.trace.length, 1);
  assert.equal(result.trace[0].ok, true);
  assert.equal(result.verdict.verdict, 'true_positive');
});

test('malformed final is repromptED with the specific issue, then a corrected verdict is accepted', async () => {
  let calls = 0;
  const prompts: string[] = [];
  const result = await runAlertTriage(
    { alert: ALERT },
    baseDeps(async (_cfg, messages) => {
      calls++;
      prompts.push(messages[messages.length - 1].content);
      if (calls === 1) {
        // Unknown verdict enum AND no summary/reasoning -> not ok.
        return JSON.stringify({ action: 'final', verdict: 'maybe?', risk_score: 50 });
      }
      return JSON.stringify(VALID_FINAL);
    })
  );

  assert.equal(calls, 2);
  assert.match(prompts[1], /invalid/i);
  assert.equal(result.degraded, false);
  assert.equal(result.verdict.verdict, 'true_positive');
});

test('persistently malformed output falls through reprompts to synthesis, then a deterministic degraded fallback', async () => {
  const result = await runAlertTriage(
    { alert: ALERT },
    baseDeps(async () => 'not json at all, just prose')
  );

  assert.equal(result.degraded, true);
  assert.equal(result.verdict.verdict, 'inconclusive');
  assert.equal(result.verdict.confidence, 'low');
  assert.ok(result.verdict.remediation.steps.length > 0);
  assert.ok(result.issues.length > 0);
});

test('normalizeVerdict: unknown tool named in suggested_queries is dropped, known tool kept', () => {
  const { verdict, ok } = normalizeVerdict({
    verdict: 'suspicious',
    summary: 'x',
    suggested_queries: [
      { label: 'a', tool: 'lookup_ip', args: { ip: '1.2.3.4' } },
      { label: 'b', tool: 'delete_everything', args: {} },
    ],
  });

  assert.equal(ok, true);
  assert.equal(verdict.suggested_queries.length, 1);
  assert.equal(verdict.suggested_queries[0].tool, 'lookup_ip');
});

test('normalizeVerdict: out-of-range risk_score is clamped into 0-100', () => {
  const { verdict } = normalizeVerdict({ verdict: 'true_positive', summary: 'x', risk_score: 900 });
  assert.equal(verdict.risk_score, 100);

  const { verdict: v2 } = normalizeVerdict({ verdict: 'true_positive', summary: 'x', risk_score: -5 });
  assert.equal(v2.risk_score, 0);
});

test('normalizeVerdict: accepts a nested verdict/remediation shape as well as the flat wire shape', () => {
  const { ok, verdict } = normalizeVerdict({
    action: 'final',
    verdict: {
      verdict: 'suspicious',
      risk_score: 60,
      confidence: 'medium',
      summary: 'Nested shape',
      reasoning: 'Some reasoning',
      evidence: [],
      suggested_queries: [],
      remediation: { proposed_status: 'investigating', urgency: 'low', steps: ['do x'] },
    },
  });

  assert.equal(ok, true);
  assert.equal(verdict.verdict, 'suspicious');
  assert.equal(verdict.remediation.proposed_status, 'investigating');
  assert.deepEqual(verdict.remediation.steps, ['do x']);
});

test('normalizeVerdict: never throws on garbage input', () => {
  for (const bad of [null, undefined, 'a string', 42, [], { verdict: { verdict: {} } }]) {
    assert.doesNotThrow(() => normalizeVerdict(bad));
  }
});
