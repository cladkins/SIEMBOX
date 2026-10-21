/**
 * The AI Analyst's tool loop honours the admin-configured budgets (Settings ->
 * AI -> AI budgets) and says when it stopped early or was cut off. In-memory
 * and DB-free: deps.complete / deps.executeTool / deps.now are injected, as in
 * triageAgent.test.ts. `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runAnalystChat, AnalystChatDeps, defaultAnalystBudget } from './analystChat';
import { AiTimeoutError, CompletionOpts } from './aiService';

const INPUT = { messages: [{ role: 'user' as const, content: 'What should I look at first?' }], user: { id: 1, role: 'analyst' as const } };
const TOOL = JSON.stringify({ action: 'tool', tool: 'get_alert_stats', args: {} });

interface Call {
  opts: CompletionOpts;
  system: string;
}

/** deps whose completer answers with `script(call index, opts)` and records every call. */
function deps(
  script: (i: number, opts: CompletionOpts) => any,
  extra: Partial<AnalystChatDeps> = {}
): { deps: AnalystChatDeps; calls: Call[]; tools: string[] } {
  const calls: Call[] = [];
  const tools: string[] = [];
  return {
    calls,
    tools,
    deps: {
      getConfig: async () => ({ provider: 'openai', model: 'test-model', apiKey: 'k' }),
      complete: async (_cfg, messages, opts) => {
        calls.push({ opts, system: messages[0]?.content ?? '' });
        return script(calls.length - 1, opts);
      },
      executeTool: async (name) => {
        tools.push(name);
        return { ok: true };
      },
      ...extra,
    },
  };
}

test('defaults: 10 lookups, 180 s, 1500-token steps, 4000-token answers', () => {
  assert.deepEqual(defaultAnalystBudget(), {
    answerMaxTokens: 4000,
    stepMaxTokens: 1500,
    maxToolCalls: 10,
    wallBudgetSeconds: 180,
  });
});

test('a clean final answer: no notes, the working-step budget is sent', async () => {
  const d = deps(() => JSON.stringify({ action: 'final', answer: 'All quiet.' }), {
    budgets: { stepMaxTokens: 2222 },
  });
  const r = await runAnalystChat(INPUT, d.deps);
  assert.equal(r.answer, 'All quiet.');
  assert.deepEqual(r.notes, []);
  assert.equal(r.stopReason, undefined);
  assert.equal(r.outputTruncated, false);
  assert.equal(d.calls[0].opts.json, true);
  assert.equal(d.calls[0].opts.maxTokens, 2222);
});

test('max data lookups: exactly N tools run, then the answer is synthesized and says why it stopped', async () => {
  for (const maxToolCalls of [3, 12]) {
    const d = deps((_i, opts) => (opts.json ? TOOL : 'Here is what I found.'), {
      budgets: { maxToolCalls, answerMaxTokens: 5555 },
    });
    const r = await runAnalystChat(INPUT, d.deps);
    assert.equal(d.tools.length, maxToolCalls, `ran ${maxToolCalls} lookups`);
    assert.equal(r.stopReason, 'lookups');
    assert.match(r.answer, /^Here is what I found\./);
    assert.match(r.answer, new RegExp(`I used all ${maxToolCalls} data lookups`));
    assert.match(r.answer, /"Max data lookups" in Settings → AI → AI budgets/);
    const synth = d.calls[d.calls.length - 1];
    assert.equal(synth.opts.json, false, 'the synthesis turn is reachable and leaves JSON mode');
    assert.equal(synth.opts.maxTokens, 5555, 'the synthesis uses the answer-length budget');
    assert.match(d.calls[0].system, new RegExp(`~${maxToolCalls} tool calls`), 'the prompt states the budget');
  }
});

test('more than the old fixed 6 lookups are possible (old MAX_TOOL_CALLS = 6)', async () => {
  const d = deps((_i, opts) => (opts.json ? TOOL : 'answer'), { budgets: { maxToolCalls: 25 } });
  await runAnalystChat(INPUT, d.deps);
  assert.equal(d.tools.length, 25);
});

test('time budget: no step starts after it; each step is cut off at what is left of it', async () => {
  let clock = 1_000_000;
  const d = deps(
    (_i, opts) => {
      if (!opts.json) return 'Partial answer.';
      clock += 40_000; // every working step takes 40 s
      return TOOL;
    },
    { budgets: { wallBudgetSeconds: 100, maxToolCalls: 25 }, now: () => clock }
  );
  const r = await runAnalystChat(INPUT, d.deps);
  // Steps start at 0 s, 40 s and 80 s; at 120 s the 100 s budget is spent.
  assert.equal(d.tools.length, 3);
  assert.equal(r.stopReason, 'time');
  assert.match(r.answer, /I reached the 100-second time budget/);
  assert.match(r.answer, /"Time budget" in Settings → AI → AI budgets/);
  const stepTimeouts = d.calls.filter((c) => c.opts.json).map((c) => c.opts.timeoutMs);
  assert.deepEqual(stepTimeouts, [100_000, 60_000, 20_000], 'a step never runs past the budget');
  const synth = d.calls[d.calls.length - 1];
  assert.equal(synth.opts.timeoutMs, 120_000, 'the answer call has its own allowance');
});

test('a working step that times out at the budget ends gathering instead of failing the chat', async () => {
  const d = deps((i, opts) => {
    if (!opts.json) return 'Answer from what I had.';
    if (i === 0) return TOOL;
    throw new AiTimeoutError('Request to x timed out after 20s');
  });
  const r = await runAnalystChat(INPUT, d.deps);
  assert.equal(r.stopReason, 'time');
  assert.match(r.answer, /^Answer from what I had\./);
});

test('other provider errors still fail the chat (the not-configured banner relies on them)', async () => {
  const d = deps(() => {
    throw new Error('No OpenAI API key configured');
  });
  await assert.rejects(runAnalystChat(INPUT, d.deps), /No OpenAI API key configured/);
});

test('a truncated JSON working step falls through to synthesis: no reprompt, no error', async () => {
  const d = deps((_i, opts) =>
    opts.json
      ? { text: '{"action":"final","answer":"The top risk is CVE-2024-', truncated: true }
      : { text: 'The top risk is CVE-2024-1234 on host-a.', truncated: false }
  , { budgets: { stepMaxTokens: 800 } });
  const r = await runAnalystChat(INPUT, d.deps);
  assert.equal(d.calls.length, 2, 'one cut-off step, then the synthesis (it is not asked again)');
  assert.equal(d.calls[1].opts.json, false);
  assert.equal(r.stopReason, 'step_truncated');
  assert.equal(r.outputTruncated, true);
  assert.match(r.answer, /^The top risk is CVE-2024-1234 on host-a\./);
  assert.match(r.answer, /A working step hit the 800-token output limit/);
  assert.match(r.answer, /"Working-step length" in Settings → AI → AI budgets/);
});

test('an answer cut off at the answer-length cap carries the note', async () => {
  const d = deps((_i, opts) =>
    opts.json ? TOOL : { text: 'Long answer that stops mid', truncated: true }
  , { budgets: { maxToolCalls: 1, answerMaxTokens: 4000 } });
  const r = await runAnalystChat(INPUT, d.deps);
  assert.equal(r.outputTruncated, true);
  assert.match(r.answer, /This answer hit the 4000-token output limit, so it may be cut off/);
  assert.match(r.answer, /"Answer length" in Settings → AI → AI budgets/);
  assert.equal(r.notes.length, 2, 'the lookups note and the token note');
});

test('untruncated malformed output is still reprompted (only a cut-off step skips that)', async () => {
  const d = deps((i, opts) => {
    if (!opts.json) return 'synth';
    return i === 0 ? '{"oops": ' : JSON.stringify({ action: 'final', answer: 'Fixed.' });
  });
  const r = await runAnalystChat(INPUT, d.deps);
  assert.equal(r.answer, 'Fixed.');
  assert.equal(d.calls.length, 2);
});

test('iterations follow the lookup budget, so reprompts can never starve the synthesis turn', async () => {
  // 1 lookup -> 3 iterations: tool, reprompt, reprompt... then the lookup cap / steps end synthesizes.
  const d = deps((i, opts) => {
    if (!opts.json) return 'synthesized';
    return i === 0 ? TOOL : 'garbage';
  }, { budgets: { maxToolCalls: 1 } });
  const r = await runAnalystChat(INPUT, d.deps);
  assert.match(r.answer, /^synthesized/);
  assert.equal(d.calls[d.calls.length - 1].opts.json, false);
});
