/**
 * "Draft with AI" with a stubbed provider: a draft that fails the save's
 * checks is sent back once with its errors, a second failure is returned with
 * them, a cut-off answer says which budget to raise. DB- and network-free.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildDraftPrompt, draftSignatureWithAi, AI_DRAFT_SYSTEM_PROMPT } from './aiDraft';
import { checkSignature } from './customSignatures';
import { APP_CATEGORIES } from './appFormat';
import type { AiConfig, Completer } from '../ai/aiService';

const cfg: AiConfig = { provider: 'ollama', model: 'test-model' };
const items = [{ source: 'package', value: 'acme-agent', sample: 'acme-agent 1.2.3', detail: { version: '1.2.3', type: 'deb' } }];
const good = {
  id: 'acme-agent', name: 'Acme Agent', vendor: 'Acme', category: 'security', description: 'The Acme endpoint agent.',
  match: { package: ['acme-agent'] }, tests: [{ source: 'package', input: 'acme-agent' }],
};
const check = async (doc: unknown) => checkSignature(doc, { effective: [] });

function stub(answers: Array<string | { text: string; truncated: boolean }>): { complete: Completer; prompts: string[] } {
  const prompts: string[] = [];
  let i = 0;
  return {
    prompts,
    complete: async (_cfg, system, user) => {
      assert.equal(system, AI_DRAFT_SYSTEM_PROMPT);
      prompts.push(user);
      return answers[Math.min(i++, answers.length - 1)];
    },
  };
}

test('the prompt names the evidence, the categories and the regex rules', () => {
  const p = buildDraftPrompt(items, 'it is our EDR');
  assert.match(p, /kind=package value="acme-agent"/);
  assert.match(p, /detail=\{"version":"1\.2\.3","type":"deb"\}/);
  assert.match(p, /Hints from the user: it is our EDR/);
  for (const c of APP_CATEGORIES) assert.ok(AI_DRAFT_SYSTEM_PROMPT.includes(c));
  assert.match(AI_DRAFT_SYSTEM_PROMPT, /at most ONE capture group/);
});

test('a valid first draft is returned as is', async () => {
  const s = stub([JSON.stringify(good)]);
  const r = await draftSignatureWithAi({ items, maxTokens: 1000 }, { cfg, complete: s.complete, check });
  assert.equal(r.ok, true);
  assert.equal(r.attempts, 1);
  assert.equal((r.signature as any).schema, 'siembox.app/v1', 'the schema is filled in');
  assert.equal(r.check?.ready, true);
});

test('a failing draft is retried once with its errors, then fixed', async () => {
  const s = stub(['```json\n' + JSON.stringify({ ...good, category: 'endpoint' }) + '\n```', JSON.stringify(good)]);
  const r = await draftSignatureWithAi({ items, maxTokens: 1000 }, { cfg, complete: s.complete, check });
  assert.equal(r.ok, true);
  assert.equal(r.attempts, 2);
  assert.match(s.prompts[1], /FAILED these checks:\n- category must be one of/);
});

test('two failures return the last draft and its errors', async () => {
  const s = stub([JSON.stringify({ ...good, tests: [{ source: 'package', input: 'other' }] })]);
  const r = await draftSignatureWithAi({ items, maxTokens: 1000 }, { cfg, complete: s.complete, check });
  assert.equal(r.ok, false);
  assert.equal(r.attempts, 2);
  assert.ok(r.check?.errors.some((e) => e.includes('does not match')));
  assert.equal(s.prompts.length, 2);
});

test('an answer cut off at the token limit names the budget', async () => {
  const s = stub([{ text: '{"id": "acme', truncated: true }]);
  const r = await draftSignatureWithAi({ items, maxTokens: 300 }, { cfg, complete: s.complete, check });
  assert.equal(r.ok, false);
  assert.equal(r.truncated, true);
  assert.match(r.error ?? '', /Builder output length/);
});
