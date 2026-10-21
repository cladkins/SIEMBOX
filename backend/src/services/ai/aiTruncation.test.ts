/**
 * Output-token truncation, per provider shape, and how each AI feature shows it.
 * globalThis.fetch is replaced by a stub that answers like each provider does
 * (no network, no live provider, no database). `npm test` (tsx --test).
 */
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  AiConfig,
  AiTimeoutError,
  callProviderChatDetailed,
  explain,
  generateDetection,
  generateParser,
  providerStopReason,
} from './aiService';

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

interface Sent {
  url: string;
  body: any;
}

/** Stub fetch: answers `reply` as JSON and records each request. */
function stubFetch(reply: unknown): Sent[] {
  const sent: Sent[] = [];
  globalThis.fetch = (async (url: any, init: any) => {
    sent.push({ url: String(url), body: JSON.parse(init.body) });
    return new Response(JSON.stringify(reply), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return sent;
}

const ANTHROPIC: AiConfig = { provider: 'anthropic', model: 'test-model', apiKey: 'k' };
const OPENAI: AiConfig = { provider: 'openai', model: 'test-model', apiKey: 'k', baseUrl: 'http://127.0.0.1:9/v1' };
const OLLAMA: AiConfig = { provider: 'ollama', model: 'test-model', baseUrl: 'http://127.0.0.1:9' };
const MSGS = [{ role: 'user' as const, content: 'hi' }];

test('providerStopReason: each provider\'s "hit the cap" signal, and only that', () => {
  assert.deepEqual(providerStopReason('openai', { choices: [{ finish_reason: 'length' }] }), {
    stopReason: 'length',
    truncated: true,
  });
  assert.equal(providerStopReason('openai', { choices: [{ finish_reason: 'stop' }] }).truncated, false);
  assert.deepEqual(providerStopReason('anthropic', { stop_reason: 'max_tokens' }), {
    stopReason: 'max_tokens',
    truncated: true,
  });
  assert.equal(providerStopReason('anthropic', { stop_reason: 'end_turn' }).truncated, false);
  assert.deepEqual(providerStopReason('ollama', { done_reason: 'length' }), { stopReason: 'length', truncated: true });
  assert.equal(providerStopReason('ollama', { done_reason: 'stop' }).truncated, false);
  assert.equal(providerStopReason('ollama', {}).truncated, false);
});

test('OpenAI-compatible: finish_reason "length" is reported as truncated; max_tokens is sent', async () => {
  const sent = stubFetch({ choices: [{ message: { content: '{"a":' }, finish_reason: 'length' }] });
  const out = await callProviderChatDetailed(OPENAI, MSGS, { maxTokens: 1234 });
  assert.deepEqual(out, { text: '{"a":', truncated: true, stopReason: 'length' });
  assert.equal(sent[0].body.max_tokens, 1234);

  stubFetch({ choices: [{ message: { content: 'done' }, finish_reason: 'stop' }] });
  assert.equal((await callProviderChatDetailed(OPENAI, MSGS, { maxTokens: 1234 })).truncated, false);
});

test('Anthropic: stop_reason "max_tokens" is reported as truncated; max_tokens is sent', async () => {
  const sent = stubFetch({ content: [{ type: 'text', text: 'partial' }], stop_reason: 'max_tokens' });
  const out = await callProviderChatDetailed(ANTHROPIC, MSGS, { maxTokens: 4000 });
  assert.deepEqual(out, { text: 'partial', truncated: true, stopReason: 'max_tokens' });
  assert.equal(sent[0].body.max_tokens, 4000);

  stubFetch({ content: [{ type: 'text', text: 'whole' }], stop_reason: 'end_turn' });
  assert.equal((await callProviderChatDetailed(ANTHROPIC, MSGS, { maxTokens: 4000 })).truncated, false);
});

test('Ollama: done_reason "length" is reported as truncated; num_predict is sent', async () => {
  const sent = stubFetch({ message: { content: 'partial' }, done: true, done_reason: 'length' });
  const out = await callProviderChatDetailed(OLLAMA, MSGS, { maxTokens: 1500 });
  assert.deepEqual(out, { text: 'partial', truncated: true, stopReason: 'length' });
  assert.equal(sent[0].body.options.num_predict, 1500);

  stubFetch({ message: { content: 'whole' }, done: true, done_reason: 'stop' });
  assert.equal((await callProviderChatDetailed(OLLAMA, MSGS, { maxTokens: 1500 })).truncated, false);
});

test('a call past its timeoutMs fails with AiTimeoutError naming the timeout', async () => {
  globalThis.fetch = ((_url: any, init: any) =>
    new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => {
        const e = new Error('aborted');
        e.name = 'AbortError';
        reject(e);
      });
    })) as typeof fetch;
  await assert.rejects(callProviderChatDetailed(OPENAI, MSGS, { timeoutMs: 1000 }), (e: unknown) => {
    assert.ok(e instanceof AiTimeoutError);
    assert.match((e as Error).message, /timed out after 1s/);
    return true;
  });
});

test('explain: sends its budget, and a cut-off explanation says so', async () => {
  const sent = stubFetch({ content: [{ type: 'text', text: 'It is a brute force' }], stop_reason: 'max_tokens' });
  const r = await explain({ kind: 'alert', data: { title: 'x' }, maxTokens: 777 }, ANTHROPIC);
  assert.equal(sent[0].body.max_tokens, 777);
  assert.equal(r.truncated, true);
  assert.match(r.explanation, /^It is a brute force/);
  assert.match(r.explanation, /hit the 777-token output limit/);
  assert.match(r.explanation, /"Explain answer length" in Settings → AI → AI budgets/);

  stubFetch({ content: [{ type: 'text', text: 'Complete.' }], stop_reason: 'end_turn' });
  const whole = await explain({ kind: 'alert', data: 'x' }, ANTHROPIC);
  assert.deepEqual(whole, { explanation: 'Complete.', truncated: false });
});

test('parser builder: a reply cut off at the cap names the limit and the setting', async () => {
  const seen: Array<number | undefined> = [];
  const r = await generateParser(
    { sample: 'sshd[1]: Failed password for root from 203.0.113.5', maxTokens: 9000 },
    async (_cfg, _s, _u, opts) => {
      seen.push(opts?.maxTokens);
      return { text: '{"schema":"siembox.parser/v1","name":"x","test_samples":[{"input":"ss', truncated: true };
    },
    OPENAI
  );
  assert.deepEqual(seen, [9000], 'the configured output budget is sent, and a cut-off reply is not retried');
  assert.equal(r.ok, false);
  assert.equal(r.truncated, true);
  assert.match(String(r.error), /hit the 9000-token output limit/);
  assert.match(String(r.error), /"Builder output length" in Settings → AI → AI budgets/);
});

test('detection builder: same for a cut-off rule; an uncut parse error keeps its own message', async () => {
  const r = await generateDetection(
    { description: 'ssh brute force', maxTokens: 300 },
    async () => ({ text: '{"name":"x","conditions":[{"field":', truncated: true }),
    OPENAI
  );
  assert.equal(r.truncated, true);
  assert.match(String(r.error), /hit the 300-token output limit/);

  const plain = await generateDetection({ description: 'x' }, async () => 'not json at all', OPENAI);
  assert.equal(plain.truncated, undefined);
  assert.doesNotMatch(String(plain.error), /token output limit/);
});
