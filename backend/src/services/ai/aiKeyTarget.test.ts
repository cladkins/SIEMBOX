/**
 * A saved AI key only reaches the provider and base URL it was saved for
 * (aiService.ts: keyTarget, planAiSave, resolveAiSettings). Pure: the settings
 * are plain objects, as the save path reads them in its transaction, so no
 * database is needed. The DB-backed route test, with fake providers recording
 * every Authorization header, is routes/aiSettingsKeyTarget.db.test.ts.
 * Run with `npm test` (tsx --test).
 */
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { CredentialEncryption } from '../credentials/credentialEncryption';
import {
  AiKeyRequiredError,
  AiModelInput,
  AiScope,
  AiSettings,
  keyTarget,
  normalizeBaseUrl,
  planAiSave,
  resolveAiSettings,
} from './aiService';

// A throwaway key for this test process.
process.env.CREDENTIAL_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');

const ENV_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY'] as const;
const savedEnv: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of ENV_KEYS) {
    savedEnv[k] = process.env[k];
    delete process.env[k];
  }
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

const KEY_SETTING: Record<AiScope, string> = {
  main: 'ai_api_key',
  chat: 'ai_chat_api_key',
  triage: 'ai_triage_api_key',
};

/** A key as saves before this change stored it: the bare key, encrypted. */
function legacyEnvelope(apiKey: string): string {
  return JSON.stringify(CredentialEncryption.encrypt(apiKey));
}

/** Apply one save to `s` the way saveAiScope does (plan, then write every planned row). */
function save(s: AiSettings, scope: AiScope, input: AiModelInput): AiSettings {
  return { ...s, ...planAiSave(scope, s, input) };
}

/** The key each config would send, and where. */
function sends(s: AiSettings) {
  const r = resolveAiSettings(s);
  return {
    main: { key: r.main.apiKey, target: r.main.target },
    chat: { key: r.chat.apiKey, target: r.chat.target },
    triage: { key: r.triage.apiKey, target: r.triage.target },
  };
}

function assertKeyRequired(fn: () => unknown, scope: AiScope) {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof AiKeyRequiredError, 'an AiKeyRequiredError');
    assert.equal(e.scope, scope);
    assert.match(e.message, /^apiKey is required/);
    assert.match(e.message, /apiKey "" to remove the saved key/);
    return true;
  });
}

const A = 'http://a.example.test:8001/v1';
const B = 'http://b.example.test:8002/v1';

/** Main on OpenAI at A with a saved key. */
function mainAtA(): AiSettings {
  return save({}, 'main', { provider: 'openai', model: 'gpt-4o', baseUrl: A, apiKey: 'sk-main-A' });
}

test('normalizeBaseUrl: a value sent back unchanged is not a change, another address is', () => {
  const same = [
    'https://api.openai.com/v1',
    'https://api.openai.com/v1/',
    ' https://API.OpenAI.com/v1 ',
    'HTTPS://api.openai.com:443/v1//',
    'https://api.openai.com/v1#frag',
  ];
  for (const u of same) assert.equal(normalizeBaseUrl(u), 'https://api.openai.com/v1', u);
  const different = [
    'http://api.openai.com/v1',
    'https://api.openai.com:8443/v1',
    'https://api.openai.com/v2',
    'https://api.openai.com.evil.test/v1',
    'https://user@api.openai.com/v1',
    'https://api.openai.com/v1?x=1',
  ];
  for (const u of different) assert.notEqual(normalizeBaseUrl(u), 'https://api.openai.com/v1', u);
  assert.equal(normalizeBaseUrl('  not a url/ '), 'not a url');
});

test('keyTarget: provider plus the base URL requests go to; Anthropic never uses the base URL', () => {
  assert.equal(keyTarget('openai'), 'openai https://api.openai.com/v1');
  assert.equal(keyTarget('openai', ''), keyTarget('openai', 'https://api.openai.com/v1/'));
  assert.equal(keyTarget('ollama'), 'ollama http://localhost:11434');
  assert.equal(keyTarget('anthropic'), 'anthropic https://api.anthropic.com/v1');
  assert.equal(keyTarget('anthropic', 'http://evil.test/v1'), keyTarget('anthropic'));
  assert.notEqual(keyTarget('openai', A), keyTarget('ollama', A));
});

test('main: a base URL change without apiKey is refused and changes nothing', () => {
  const s = mainAtA();
  assertKeyRequired(() => planAiSave('main', s, { baseUrl: B }), 'main');
  // The same with the provider and model sent along, as the UI does.
  assertKeyRequired(
    () => planAiSave('main', s, { provider: 'openai', model: 'gpt-4o', baseUrl: B }),
    'main'
  );
  assert.deepEqual(sends(s).main, { key: 'sk-main-A', target: keyTarget('openai', A) });
});

test('main: a provider change without apiKey is refused (an Anthropic key never becomes a Bearer token)', () => {
  const s = save({}, 'main', { provider: 'anthropic', apiKey: 'sk-ant-1' });
  assertKeyRequired(() => planAiSave('main', s, { provider: 'openai', baseUrl: B }), 'main');
  assertKeyRequired(() => planAiSave('main', s, { provider: 'openai' }), 'main');
  // Ollama sends no key, but the saved key would stay behind: say what to do with it.
  assertKeyRequired(() => planAiSave('main', s, { provider: 'ollama' }), 'main');
  const ollama = save(s, 'main', { provider: 'ollama', apiKey: '' });
  assert.equal(ollama.ai_api_key, '');
  assert.equal(sends(ollama).main.key, undefined);
});

test('main: model-only changes and a base URL sent back unchanged keep the key', () => {
  let s = mainAtA();
  const stored = s.ai_api_key;
  for (const input of [
    { model: 'gpt-4.1' },
    { provider: 'openai' as const, model: 'gpt-4.1', baseUrl: A },
    { provider: 'openai' as const, model: 'gpt-4.1', baseUrl: `${A}/` },
    { provider: 'openai' as const, baseUrl: 'HTTP://A.Example.TEST:8001/v1' },
  ]) {
    const writes = planAiSave('main', s, input);
    assert.equal(
      writes.ai_api_key,
      undefined,
      `the saved key is not rewritten: ${JSON.stringify(input)}`
    );
    s = { ...s, ...writes };
    assert.equal(s.ai_api_key, stored);
    assert.equal(sends(s).main.key, 'sk-main-A');
  }
  // The OpenAI default spelled out is the same address as no base URL.
  let d = save({}, 'main', { provider: 'openai', apiKey: 'sk-default' });
  d = save(d, 'main', { provider: 'openai', baseUrl: 'https://api.openai.com/v1' });
  assert.equal(sends(d).main.key, 'sk-default');
  // So is any base URL for Anthropic, which is always called at api.anthropic.com.
  let ant = save({}, 'main', { provider: 'anthropic', apiKey: 'sk-ant-2' });
  ant = save(ant, 'main', { baseUrl: 'http://evil.test/v1' });
  assert.deepEqual(sends(ant).main, { key: 'sk-ant-2', target: keyTarget('anthropic') });
});

test('main: a new key or "" in the same request moves the config', () => {
  const s = mainAtA();
  const moved = save(s, 'main', { baseUrl: B, apiKey: 'sk-main-B' });
  assert.deepEqual(sends(moved).main, { key: 'sk-main-B', target: keyTarget('openai', B) });

  const cleared = save(s, 'main', { baseUrl: B, apiKey: '' });
  assert.equal(cleared.ai_api_key, '');
  assert.equal(sends(cleared).main.key, undefined);
  const nulled = save(s, 'main', { baseUrl: B, apiKey: null });
  assert.equal(nulled.ai_api_key, '');
});

test('main: without a saved key the move is free and the environment variable follows it', () => {
  process.env.OPENAI_API_KEY = 'sk-env';
  let s = save({}, 'main', { provider: 'openai', baseUrl: A });
  assert.deepEqual(sends(s).main, { key: 'sk-env', target: keyTarget('openai', A) });
  s = save(s, 'main', { baseUrl: B });
  assert.deepEqual(sends(s).main, { key: 'sk-env', target: keyTarget('openai', B) });
  const r = resolveAiSettings(s).main;
  assert.equal(r.keySource, 'env');
  assert.equal(r.keySaved, false);
});

test('a saved key goes back to the target it was saved for, without being asked for', () => {
  // The analyst's own key, saved at A while it followed main's base URL.
  let s = mainAtA();
  s = save(s, 'chat', { provider: 'openai', baseUrl: '', apiKey: 'sk-chat-A' });
  // Main moves to B: the analyst follows, and its key, saved for A, stays unused.
  s = save(s, 'main', { baseUrl: B, apiKey: 'sk-main-B' });
  const chat = resolveAiSettings(s).chat;
  assert.equal(chat.target, keyTarget('openai', B));
  assert.equal(chat.keyMismatch, true);
  assert.equal(chat.apiKey, 'sk-main-B', "main's key, at main's own target");
  // Pointing the analyst back at A needs no key: that is where its key was saved for.
  s = save(s, 'chat', { baseUrl: A });
  assert.deepEqual(sends(s).chat, { key: 'sk-chat-A', target: keyTarget('openai', A) });
  assert.equal(resolveAiSettings(s).chat.keyMismatch, false);
  // Anywhere else still needs one.
  assertKeyRequired(() => planAiSave('chat', s, { baseUrl: 'http://c.example.test/v1' }), 'chat');
});

test("chat: a base URL of its own never gets main's saved key", () => {
  let s = mainAtA();
  // Inheriting: same provider and base URL as main, so main's key.
  assert.deepEqual(sends(s).chat, { key: 'sk-main-A', target: keyTarget('openai', A) });
  // Its own base URL, no key of its own: allowed (nothing saved follows), but main's key stays at A.
  s = save(s, 'chat', { provider: 'openai', baseUrl: B });
  assert.deepEqual(sends(s).chat, { key: undefined, target: keyTarget('openai', B) });
  assert.equal(resolveAiSettings(s).chat.keySource, 'none');
  // Same through an inheriting provider with only the base URL overridden (API only).
  let t = mainAtA();
  t = save(t, 'chat', { baseUrl: B });
  assert.equal(sends(t).chat.key, undefined);
  // And triage pointed elsewhere doesn't get it either.
  let u = mainAtA();
  u = save(u, 'triage', { provider: 'openai', baseUrl: B });
  assert.equal(sends(u).triage.key, undefined);
  // An environment variable still applies there.
  process.env.OPENAI_API_KEY = 'sk-env';
  assert.equal(sends(s).chat.key, 'sk-env');
});

test("a key entered for main later doesn't reach an analyst pointed elsewhere beforehand", () => {
  // The analyst was set to OpenAI at B while no key was saved anywhere.
  let s = save({}, 'main', { provider: 'anthropic' });
  s = save(s, 'chat', { provider: 'openai', baseUrl: B });
  // Then main moves to OpenAI at A with a key: the analyst now has main's provider, but not its target.
  s = save(s, 'main', { provider: 'openai', baseUrl: A, apiKey: 'sk-main-A' });
  assert.deepEqual(sends(s).main, { key: 'sk-main-A', target: keyTarget('openai', A) });
  assert.deepEqual(sends(s).chat, { key: undefined, target: keyTarget('openai', B) });
});

test('chat: a provider or base URL change with its own key needs apiKey; inheriting again too', () => {
  let s = mainAtA();
  s = save(s, 'chat', { provider: 'ollama', baseUrl: 'http://ollama.example.test:11434' });
  s = save(s, 'chat', { provider: 'openai', baseUrl: B, apiKey: 'sk-chat-B' });
  assert.deepEqual(sends(s).chat, { key: 'sk-chat-B', target: keyTarget('openai', B) });

  assertKeyRequired(() => planAiSave('chat', s, { baseUrl: 'http://c.example.test/v1' }), 'chat');
  assertKeyRequired(() => planAiSave('chat', s, { provider: 'anthropic' }), 'chat');
  // Back to inheriting main (OpenAI at A): the analyst's key would go to A.
  assertKeyRequired(() => planAiSave('chat', s, { provider: '', model: '', baseUrl: '' }), 'chat');
  // Model only: kept.
  s = save(s, 'chat', { provider: 'openai', model: 'gpt-4.1', baseUrl: `${B}/` });
  assert.equal(sends(s).chat.key, 'sk-chat-B');
  // Inheriting again with the key removed: main's key, at main's target.
  s = save(s, 'chat', { provider: '', model: '', baseUrl: '', apiKey: '' });
  assert.deepEqual(sends(s).chat, { key: 'sk-main-A', target: keyTarget('openai', A) });
});

test("chat: an own key whose target moves with main is not sent to main's new base URL", () => {
  let s = mainAtA();
  // Same provider as main, base URL left blank: it follows main's.
  s = save(s, 'chat', { provider: 'openai', baseUrl: '', apiKey: 'sk-chat-own' });
  assert.deepEqual(sends(s).chat, { key: 'sk-chat-own', target: keyTarget('openai', A) });
  // Main moves to B with a key of its own (it could be a throwaway): the analyst's key stays out of it.
  s = save(s, 'main', { baseUrl: B, apiKey: 'sk-throwaway' });
  assert.deepEqual(sends(s).chat, { key: 'sk-throwaway', target: keyTarget('openai', B) });
  assert.equal(resolveAiSettings(s).chat.keyMismatch, true);
  // Main moves to B without a saved key at all: the analyst gets nothing.
  let t = save({}, 'main', { provider: 'openai', baseUrl: A });
  t = save(t, 'chat', { provider: 'openai', baseUrl: '', apiKey: 'sk-chat-own' });
  t = save(t, 'main', { baseUrl: B });
  assert.deepEqual(sends(t).chat, { key: undefined, target: keyTarget('openai', B) });
});

test('triage: same rules, through the analyst; the operational knobs save with it', () => {
  let s = mainAtA();
  // Inherits the analyst, which inherits main.
  assert.deepEqual(sends(s).triage, { key: 'sk-main-A', target: keyTarget('openai', A) });
  s = save(s, 'triage', { provider: 'openai', baseUrl: B, apiKey: 'sk-tri-B' });
  assertKeyRequired(() => planAiSave('triage', s, { baseUrl: A }), 'triage');
  // Back to inheriting, as the UI sends it (overrides cleared): the analyst's target, A.
  assertKeyRequired(
    () => planAiSave('triage', s, { provider: '', model: '', baseUrl: '' }),
    'triage'
  );
  // Inheriting the provider but keeping its own base URL is still B: no move, no key needed.
  assert.equal(sends(save(s, 'triage', { provider: '' })).triage.key, 'sk-tri-B');

  const writes = planAiSave(
    'triage',
    s,
    { provider: 'openai', model: 'gpt-4.1', baseUrl: B },
    { ai_triage_enabled: 'true' }
  );
  assert.equal(writes.ai_triage_enabled, 'true');
  assert.equal(writes.ai_triage_api_key, undefined);
  s = { ...s, ...writes };
  assert.equal(sends(s).triage.key, 'sk-tri-B');

  s = save(s, 'triage', { baseUrl: A, apiKey: 'sk-tri-A' });
  assert.deepEqual(sends(s).triage, { key: 'sk-tri-A', target: keyTarget('openai', A) });
});

test('a key saved before targets were recorded is bound to its current target by the first save', () => {
  const s: AiSettings = {
    ai_provider: 'openai',
    ai_base_url: A,
    ai_api_key: legacyEnvelope('sk-legacy-main'),
    ai_chat_provider: 'openai',
    ai_chat_api_key: legacyEnvelope('sk-legacy-chat'),
  };
  // Until then it counts as saved for where its config points.
  assert.deepEqual(sends(s).main, { key: 'sk-legacy-main', target: keyTarget('openai', A) });
  assert.deepEqual(sends(s).chat, { key: 'sk-legacy-chat', target: keyTarget('openai', A) });
  // Its own config moving needs a key, as for any saved key.
  assertKeyRequired(() => planAiSave('main', s, { baseUrl: B }), 'main');
  // Any save records both keys' current targets first (here a model-only one) ...
  const writes = planAiSave('triage', s, { model: 'gpt-4.1' });
  assert.ok(
    writes.ai_api_key && writes.ai_api_key !== s.ai_api_key,
    "main's key is re-sealed with its target"
  );
  assert.ok(writes.ai_chat_api_key && writes.ai_chat_api_key !== s.ai_chat_api_key);
  // ... so main moving to B with another key leaves the analyst's key at A, unused.
  const after = save(save(s, 'triage', { model: 'gpt-4.1' }), 'main', {
    baseUrl: B,
    apiKey: 'sk-main-B',
  });
  assert.deepEqual(sends(after).chat, { key: 'sk-main-B', target: keyTarget('openai', B) });
  // The same in one save: binding happens before the move.
  const direct = save(s, 'main', { baseUrl: B, apiKey: 'sk-main-B' });
  assert.equal(resolveAiSettings(direct).chat.keyMismatch, true);
  assert.equal(sends(direct).chat.key, 'sk-main-B');
});

test("public flags: keySaved is the config's own key, keyMismatch a key saved for elsewhere", () => {
  let s = mainAtA();
  const chat = resolveAiSettings(s).chat;
  assert.equal(chat.keySource, 'stored', "main's key, inherited");
  assert.equal(chat.keySaved, false);
  s = save(s, 'chat', { provider: 'openai', baseUrl: B, apiKey: 'sk-chat-B' });
  assert.equal(resolveAiSettings(s).chat.keySaved, true);
  assert.equal(resolveAiSettings(s).chat.keyMismatch, false);
  // An undecryptable key is neither sent nor reported as a match.
  const broken = {
    ...s,
    [KEY_SETTING.chat]: JSON.stringify({ encrypted: 'x', iv: 'y', authTag: 'z' }),
  };
  const r = resolveAiSettings(broken).chat;
  assert.equal(r.apiKey, undefined);
  assert.equal(r.keySaved, true);
  // ... and moving it still needs apiKey (its target is unknown).
  assertKeyRequired(() => planAiSave('chat', broken, { baseUrl: A }), 'chat');
});
