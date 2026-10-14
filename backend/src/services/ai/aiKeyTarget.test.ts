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
// The Settings page's copy of the comparison, checked against this one below.
import {
  keyNeeded,
  keyTargetOf,
  normalizeBaseUrl as pageNormalizeBaseUrl,
} from '../../../../frontend/src/views/settings/aiKeyTarget';

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

/** The key a version from before targets were recorded reads from a key row (and sends). */
function keyAsOlderVersionsRead(stored: string): string {
  const { encrypted, iv, authTag } = JSON.parse(stored);
  return CredentialEncryption.decrypt(encrypted, iv, authTag);
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
  // Any save records both keys' current targets first (here a model-only one),
  // in rows of their own: the key rows stay as they are.
  const writes = planAiSave('triage', s, { model: 'gpt-4.1' });
  assert.ok(writes.ai_api_key_target, "main's key gets its target recorded");
  assert.ok(writes.ai_chat_api_key_target);
  assert.equal(writes.ai_api_key, undefined, "main's key row is not rewritten");
  assert.equal(writes.ai_chat_api_key, undefined);
  assert.equal(writes.ai_triage_api_key_target, undefined, 'triage has no key to bind');
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

test('the key rows stay what older versions read, so a rollback keeps the saved keys working', () => {
  let s = mainAtA();
  s = save(s, 'chat', { provider: 'openai', baseUrl: B, apiKey: 'sk-chat-B' });
  s = save(s, 'triage', { provider: 'openai', baseUrl: A, apiKey: 'sk-tri-A' });
  // A version from before targets were recorded decrypts the key row and sends that.
  assert.equal(keyAsOlderVersionsRead(s.ai_api_key), 'sk-main-A');
  assert.equal(keyAsOlderVersionsRead(s.ai_chat_api_key), 'sk-chat-B');
  assert.equal(keyAsOlderVersionsRead(s.ai_triage_api_key), 'sk-tri-A');
  // The targets are rows of their own, encrypted too.
  for (const row of ['ai_api_key_target', 'ai_chat_api_key_target', 'ai_triage_api_key_target']) {
    assert.deepEqual(Object.keys(JSON.parse(s[row])).sort(), ['authTag', 'encrypted', 'iv'], row);
  }
  // Removing a key removes its target.
  const cleared = save(s, 'chat', { apiKey: '' });
  assert.equal(cleared.ai_chat_api_key, '');
  assert.equal(cleared.ai_chat_api_key_target, '');

  // Back on this version after the older one ran for a while:
  // - it replaced main's key (it records no target): the new key counts as
  //   saved for where main points, and the next save binds it there;
  const replacedRow = legacyEnvelope('sk-main-A2');
  let old = { ...s, ai_api_key: replacedRow };
  assert.deepEqual(sends(old).main, { key: 'sk-main-A2', target: keyTarget('openai', A) });
  assert.equal(resolveAiSettings(old).main.keyMismatch, false);
  old = save(old, 'main', { model: 'gpt-4.1' });
  assertKeyRequired(() => planAiSave('main', old, { baseUrl: B }), 'main');
  assert.equal(old.ai_api_key, replacedRow, 'binding leaves the key row as it is');
  assert.equal(
    resolveAiSettings({ ...old, ai_base_url: B }).main.keyMismatch,
    true,
    'bound to A: an older version moving main later does not take it along'
  );
  // - it moved the analyst to A and kept its key (as it allowed): that key
  //   stays bound to B, so it is not sent to A;
  const moved = { ...s, ai_chat_base_url: A };
  assert.equal(resolveAiSettings(moved).chat.keyMismatch, true);
  assert.deepEqual(sends(moved).chat, { key: 'sk-main-A', target: keyTarget('openai', A) });
  // - it moved triage to B with a new key: the new key, at B.
  const rekeyed = { ...s, ai_triage_base_url: B, ai_triage_api_key: legacyEnvelope('sk-tri-B') };
  assert.deepEqual(sends(rekeyed).triage, { key: 'sk-tri-B', target: keyTarget('openai', B) });
  assert.equal(resolveAiSettings(rekeyed).triage.keyMismatch, false);
});

test('model and base URL are saved trimmed; a base URL of only spaces is blank', () => {
  // The review's case: OpenAI at its default address with a saved key, and
  // spaces typed into Base URL. The page sees no change and asks for no key.
  let s = save({}, 'main', { provider: 'openai', model: 'gpt-4o', apiKey: 'sk-default' });
  const writes = planAiSave('main', s, { provider: 'openai', model: 'gpt-4o', baseUrl: '   ' });
  assert.equal(writes.ai_base_url, '');
  s = { ...s, ...writes };
  assert.deepEqual(sends(s).main, { key: 'sk-default', target: keyTarget('openai') });
  // Surrounding spaces are not stored (they would end up in the request URL).
  s = save(s, 'main', {
    provider: 'openai',
    model: ' gpt-4.1 ',
    baseUrl: ' https://api.openai.com/v1 ',
  });
  assert.equal(s.ai_base_url, 'https://api.openai.com/v1');
  assert.equal(s.ai_model, 'gpt-4.1');
  assert.equal(sends(s).main.key, 'sk-default');
  // Another address with spaces around it is still another address.
  assertKeyRequired(() => planAiSave('main', s, { baseUrl: ` ${B} ` }), 'main');
  // Values stored padded before saves trimmed resolve without the spaces.
  const padded = resolveAiSettings({
    ai_provider: 'openai',
    ai_model: ' gpt-4o ',
    ai_base_url: ` ${A} `,
  }).main;
  assert.equal(padded.baseUrl, A);
  assert.equal(padded.model, 'gpt-4o');
  const blank = resolveAiSettings({
    ai_provider: 'openai',
    ai_base_url: '   ',
    ai_chat_provider: 'ollama',
    ai_chat_base_url: '  ',
  });
  assert.equal(blank.main.baseUrl, 'https://api.openai.com/v1');
  assert.equal(blank.chat.baseUrl, 'http://localhost:11434');
});

test('the Settings page compares targets the way the backend does (frontend aiKeyTarget.ts)', () => {
  // Every combination of a provider and base URL setting for the AI Builder,
  // and for the analyst under it. The page knows the form's provider and base
  // URL, and the parent's provider and base URL as GET /api/settings/ai reports
  // them. It must ask for the key exactly when the backend would refuse the
  // save: two states have the same target for the page iff for the backend.
  const providers = ['anthropic', 'openai', 'ollama'];
  const urls = [
    '',
    '   ',
    A,
    ` ${A} `,
    `${A}/`,
    'HTTP://A.Example.TEST:8001/v1',
    B,
    'https://api.openai.com/v1',
    'http://localhost:11434/',
  ];
  const states: Array<{ label: string; backend: string; page: string }> = [];
  for (const mp of providers) {
    for (const mu of urls) {
      const main: AiSettings = { ai_provider: mp, ai_base_url: mu };
      const r = resolveAiSettings(main).main;
      states.push({
        label: `main ${mp} ${JSON.stringify(mu)}`,
        backend: r.target,
        page: keyTargetOf(mp, mu),
      });
      const parent = { provider: r.provider, baseUrl: r.baseUrl || '' };
      for (const cp of ['', ...providers]) {
        for (const cu of urls) {
          const chat = resolveAiSettings({
            ...main,
            ai_chat_provider: cp,
            ai_chat_base_url: cu,
          }).chat;
          states.push({
            label: `main ${mp} ${JSON.stringify(mu)}, analyst ${cp || 'inherit'} ${JSON.stringify(cu)}`,
            backend: chat.target,
            page: keyTargetOf(cp, cu, parent),
          });
        }
      }
    }
  }
  const pageFor = new Map<string, { page: string; label: string }>();
  const backendFor = new Map<string, { backend: string; label: string }>();
  for (const st of states) {
    const seenPage = pageFor.get(st.backend);
    if (seenPage) assert.equal(st.page, seenPage.page, `${st.label} vs ${seenPage.label}`);
    else pageFor.set(st.backend, st);
    const seenBackend = backendFor.get(st.page);
    if (seenBackend)
      assert.equal(st.backend, seenBackend.backend, `${st.label} vs ${seenBackend.label}`);
    else backendFor.set(st.page, st);
  }
});

// ---- Base URL normalization: linear, and the same results as before ----------

/**
 * normalizeBaseUrl as it was, with the regex CodeQL flagged (js/polynomial-redos:
 * quadratic on a long run of slashes that doesn't end the string). Kept here
 * only as the reference the linear version must match, on fixed inputs.
 */
function regexNormalizeBaseUrl(raw: string): string {
  const s = raw.trim();
  try {
    const u = new URL(s);
    const auth =
      u.username || u.password ? `${u.username}${u.password ? `:${u.password}` : ''}@` : '';
    return `${u.protocol}//${auth}${u.host}${u.pathname.replace(/\/+$/, '')}${u.search}`;
  } catch {
    return s.replace(/\/+$/, '');
  }
}

/** Base URLs, real and odd: every combination of the parts below, and some that aren't URLs. */
function baseUrlCorpus(): string[] {
  const out: string[] = [];
  const schemes = ['http://', 'https://', 'HTTPS://', 'HtTp://'];
  const hosts = [
    'api.openai.com',
    'API.OpenAI.COM',
    '127.0.0.1',
    '[::1]',
    'user:pw@Host.Example.test',
    'bücher.example',
    'host.docker.internal',
  ];
  const ports = ['', ':80', ':443', ':8001', ':011434'];
  const paths = [
    '',
    '/',
    '//',
    '///',
    '/v1',
    '/v1/',
    '/v1//',
    '//v1',
    '/a//b/',
    '/%7Ex/',
    '/a b/',
    '/v1/./x/../',
  ];
  const tails = ['', '?x=1', '?x=1/', '#frag', '#/', '?a=b#c/'];
  const pads: Array<[string, string]> = [
    ['', ''],
    [' ', ' '],
    ['\t', '\n '],
  ];
  for (const scheme of schemes)
    for (const host of hosts)
      for (const port of ports)
        for (const path of paths)
          for (const tail of tails)
            for (const [l, r] of pads) out.push(`${l}${scheme}${host}${port}${path}${tail}${r}`);
  // Not URLs: only surrounding space and trailing slashes go.
  out.push(
    '',
    '   ',
    '/',
    '//',
    '///',
    'not a url',
    ' not a url/ ',
    'not a url//',
    'localhost:11434/',
    ' host/path// ',
    'a/b/c///',
    '///x',
    'x///y',
    '/\t/',
    'http//missing-colon.test/v1/',
    'http://',
    'http:// space.test/'
  );
  return out;
}

test("normalizeBaseUrl gives the regex version's result for every base URL tried (backend and page)", () => {
  const corpus = baseUrlCorpus();
  assert.ok(corpus.length > 10000, `${corpus.length} inputs`);
  for (const u of corpus) {
    const want = regexNormalizeBaseUrl(u);
    assert.equal(normalizeBaseUrl(u), want, JSON.stringify(u));
    assert.equal(pageNormalizeBaseUrl(u), want, `page: ${JSON.stringify(u)}`);
  }
  // The cases the comparison relies on, spelled out.
  const pinned: Array<[string, string]> = [
    ['https://api.openai.com/v1/', 'https://api.openai.com/v1'], // a trailing slash
    ['https://api.openai.com/v1//', 'https://api.openai.com/v1'], // several
    ['https://api.openai.com//', 'https://api.openai.com'], // a path of only slashes
    ['https://api.openai.com/a//b/', 'https://api.openai.com/a//b'], // inner ones stay
    ['HTTPS://API.OpenAI.com/V1', 'https://api.openai.com/V1'], // scheme and host case, not the path's
    ['https://api.openai.com:443/v1', 'https://api.openai.com/v1'], // the default port
    ['http://h.test:80/v1', 'http://h.test/v1'],
    ['http://h.test:443/v1', 'http://h.test:443/v1'], // not http's default
    [' \thttps://api.openai.com/v1 \n', 'https://api.openai.com/v1'], // surrounding space
    ['https://api.openai.com/v1/?x=1#f', 'https://api.openai.com/v1?x=1'], // query kept, fragment dropped
    ['  not a url// ', 'not a url'],
    ['///', ''],
  ];
  for (const [input, want] of pinned) {
    assert.equal(normalizeBaseUrl(input), want, JSON.stringify(input));
    assert.equal(pageNormalizeBaseUrl(input), want, `page: ${JSON.stringify(input)}`);
  }
});

test('normalizeBaseUrl is linear: long runs of slashes take no time', () => {
  // The regex version takes seconds on the first of these (quadratic in the
  // run of slashes); the loop, well under a millisecond each.
  const run = '/'.repeat(100_000);
  const inputs: Array<[string, string]> = [
    [`${run}x`, `${run}x`],
    [`x${run}`, 'x'],
    [`http://h.test${run}x`, `http://h.test${run}x`],
    [`http://h.test/v1${run}`, 'http://h.test/v1'],
    [` ${run}x${run} `, `${run}x`],
  ];
  for (const normalize of [normalizeBaseUrl, pageNormalizeBaseUrl]) {
    const started = process.hrtime.bigint();
    for (const [input, want] of inputs) assert.equal(normalize(input), want);
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(ms < 1000, `${inputs.length} long inputs normalized in ${ms.toFixed(1)} ms`);
  }
});

// ---- keySavedFor, and the page's "key needed" ---------------------------------

test('keySavedFor: where the saved key goes; null without one, or when it cannot be read', () => {
  let s = mainAtA();
  assert.deepEqual(resolveAiSettings(s).main.keySavedFor, { provider: 'openai', baseUrl: A });
  assert.equal(
    resolveAiSettings(s).chat.keySavedFor,
    null,
    "no key of its own (main's is inherited)"
  );
  // Saved with trailing slashes: reported normalized.
  s = save(s, 'chat', { provider: 'openai', baseUrl: `${B}//`, apiKey: 'sk-chat-B' });
  assert.deepEqual(resolveAiSettings(s).chat.keySavedFor, { provider: 'openai', baseUrl: B });
  // Anthropic: its fixed address. OpenAI with no base URL: the default.
  const ant = save({}, 'main', { provider: 'anthropic', apiKey: 'sk-ant' });
  assert.deepEqual(resolveAiSettings(ant).main.keySavedFor, {
    provider: 'anthropic',
    baseUrl: 'https://api.anthropic.com/v1',
  });
  const def = save({}, 'main', { provider: 'openai', apiKey: 'sk-def' });
  assert.deepEqual(resolveAiSettings(def).main.keySavedFor, {
    provider: 'openai',
    baseUrl: 'https://api.openai.com/v1',
  });

  // It stays where it was saved for when the target moves with the parent.
  let f = mainAtA();
  f = save(f, 'chat', { provider: 'openai', baseUrl: '', apiKey: 'sk-chat-A' });
  f = save(f, 'triage', { provider: 'openai', baseUrl: '', apiKey: 'sk-tri-A' });
  f = save(f, 'main', { baseUrl: B, apiKey: 'sk-main-B' });
  const r = resolveAiSettings(f);
  const atA = { provider: 'openai', baseUrl: A };
  assert.deepEqual([r.chat.baseUrl, r.chat.keyMismatch, r.chat.keySavedFor], [B, true, atA]);
  assert.deepEqual([r.triage.baseUrl, r.triage.keyMismatch, r.triage.keySavedFor], [B, true, atA]);
  assert.deepEqual(r.main.keySavedFor, { provider: 'openai', baseUrl: B });

  // A key with no target recorded counts as saved for where its config points.
  const legacy = resolveAiSettings({
    ai_provider: 'openai',
    ai_base_url: A,
    ai_api_key: legacyEnvelope('sk-legacy'),
  }).main;
  assert.deepEqual(legacy.keySavedFor, atA);
  // An unreadable key: unknown, so any move needs a key.
  const broken = resolveAiSettings({
    ...s,
    [KEY_SETTING.chat]: JSON.stringify({ encrypted: 'x', iv: 'y', authTag: 'z' }),
  }).chat;
  assert.equal(broken.keySaved, true);
  assert.equal(broken.keySavedFor, null);
});

test('keyNeeded (the page): pointing a card back where its key was saved for needs no key, as for the API', () => {
  // The verifier's case. The Builder on OpenAI at A with its key; the analyst
  // on OpenAI with no base URL of its own and its own key (saved for A); the
  // Builder moves to B. The analyst card reads "Saved key not used".
  let s = mainAtA();
  s = save(s, 'chat', { provider: 'openai', model: 'gpt-4o', baseUrl: '', apiKey: 'sk-chat-A' });
  s = save(s, 'main', { provider: 'openai', model: 'gpt-4o', baseUrl: B, apiKey: 'sk-main-B' });
  const r = resolveAiSettings(s);
  assert.equal(r.chat.keyMismatch, true);
  // What the page holds after GET /api/settings/ai and /ai-chat.
  const aiSaved = { provider: r.main.provider, baseUrl: r.main.baseUrl || '' };
  const chatSaved = { provider: r.chat.provider, baseUrl: r.chat.baseUrl || '' };
  const reported = { keySaved: r.chat.keySaved, keySavedFor: r.chat.keySavedFor };
  const needed = (baseUrl: string, provider = 'openai') =>
    keyNeeded({ provider, baseUrl }, chatSaved, reported, aiSaved);

  // A typed back (any spelling of it): no key asked for, and the API takes it without one.
  for (const back of [A, `${A}/`, ` ${A} `, 'HTTP://A.Example.TEST:8001/v1']) {
    assert.equal(needed(back), false, JSON.stringify(back));
    const writes = planAiSave('chat', s, { provider: 'openai', model: 'gpt-4o', baseUrl: back });
    assert.equal(writes.ai_chat_api_key, undefined, 'the key row is kept');
  }
  const back = save(s, 'chat', { provider: 'openai', model: 'gpt-4o', baseUrl: A });
  assert.deepEqual(sends(back).chat, { key: 'sk-chat-A', target: keyTarget('openai', A) });
  assert.equal(resolveAiSettings(back).chat.keyMismatch, false);
  // Untouched (blank, following the Builder to B): no move, no key.
  assert.equal(needed(''), false);
  // Anywhere else: a key, as the API says.
  for (const [url, provider] of [
    ['http://c.example.test/v1', 'openai'],
    [A, 'ollama'],
    ['', 'anthropic'],
  ] as const) {
    assert.equal(needed(url, provider), true, `${provider} ${url}`);
    assertKeyRequired(() => planAiSave('chat', s, { provider, baseUrl: url }), 'chat');
  }
  // Without keySavedFor (an unreadable key, or the comparison before this fix)
  // the page can only compare with where the card points now: a key for A.
  assert.equal(
    keyNeeded({ provider: 'openai', baseUrl: A }, chatSaved, { keySaved: true }, aiSaved),
    true
  );
});

test('keyNeeded (the page) asks for a key exactly when the API would refuse the save', () => {
  // Each card after saves that leave its key saved for where it points, for
  // where it pointed before its parent moved, with no target recorded, or
  // unreadable; then every provider and base URL a form can hold, saved
  // without a key. The page lets the save through iff the API takes it.
  const C = 'http://c.example.test/v1';
  type Step = [AiScope, AiModelInput];
  const histories: Array<{ label: string; steps: Step[]; raw?: AiSettings }> = [
    { label: 'main at A', steps: [['main', { provider: 'openai', baseUrl: A, apiKey: 'k-m' }]] },
    {
      label: 'chat and triage follow main, then main moves',
      steps: [
        ['main', { provider: 'openai', baseUrl: A, apiKey: 'k-m' }],
        ['chat', { provider: 'openai', baseUrl: '', apiKey: 'k-c' }],
        ['triage', { provider: 'openai', baseUrl: '', apiKey: 'k-t' }],
        ['main', { provider: 'openai', baseUrl: B, apiKey: 'k-m2' }],
      ],
    },
    {
      label: 'chat at B of its own, triage follows chat, then chat moves',
      steps: [
        ['main', { provider: 'openai', baseUrl: A, apiKey: 'k-m' }],
        ['chat', { provider: 'openai', baseUrl: B, apiKey: 'k-c' }],
        ['triage', { provider: 'openai', baseUrl: '', apiKey: 'k-t' }],
        ['chat', { provider: 'openai', baseUrl: C, apiKey: 'k-c2' }],
      ],
    },
    {
      label: 'main changes provider under a following chat',
      steps: [
        ['main', { provider: 'openai', baseUrl: A }],
        ['chat', { provider: 'openai', baseUrl: '', apiKey: 'k-c' }],
        ['main', { provider: 'ollama', baseUrl: 'http://localhost:11434' }],
      ],
    },
    {
      label: 'anthropic keys',
      steps: [
        ['main', { provider: 'anthropic', apiKey: 'k-a' }],
        ['chat', { provider: 'openai', baseUrl: B, apiKey: 'k-c' }],
        ['triage', { provider: 'anthropic', apiKey: 'k-t' }],
      ],
    },
    {
      label: 'an older version moved main and chat, keeping their keys',
      steps: [
        ['main', { provider: 'openai', baseUrl: A, apiKey: 'k-m' }],
        ['chat', { provider: 'openai', baseUrl: B, apiKey: 'k-c' }],
      ],
      raw: { ai_base_url: B, ai_chat_base_url: C },
    },
    {
      label: 'keys with no target recorded',
      steps: [],
      raw: {
        ai_provider: 'openai',
        ai_base_url: A,
        ai_api_key: legacyEnvelope('k-legacy-m'),
        ai_chat_provider: 'openai',
        ai_chat_api_key: legacyEnvelope('k-legacy-c'),
      },
    },
    {
      label: 'an unreadable analyst key',
      steps: [['main', { provider: 'openai', baseUrl: A, apiKey: 'k-m' }]],
      raw: {
        ai_chat_provider: 'openai',
        ai_chat_api_key: JSON.stringify({ encrypted: 'x', iv: 'y', authTag: 'z' }),
      },
    },
  ];
  const urls = [
    '',
    '  ',
    A,
    `${A}/`,
    'HTTP://A.Example.TEST:8001/v1',
    B,
    ` ${B} `,
    C,
    'https://api.openai.com/v1',
    'http://localhost:11434/',
  ];
  const forms = ['anthropic', 'openai', 'ollama'].flatMap((provider) =>
    urls.map((baseUrl) => ({ provider, baseUrl }))
  );

  let checked = 0;
  let pointedBack = 0;
  for (const h of histories) {
    let s: AiSettings = {};
    for (const [scope, input] of h.steps) s = save(s, scope, input);
    s = { ...s, ...(h.raw || {}) };
    const r = resolveAiSettings(s);
    // What GET reports, as the page keeps it (aiSaved, chatSaved, triageSaved).
    const endpoint = (scope: AiScope) => ({
      provider: r[scope].provider as string,
      baseUrl: r[scope].baseUrl || '',
    });
    const parents: Record<AiScope, { provider: string; baseUrl: string } | undefined> = {
      main: undefined,
      chat: endpoint('main'),
      triage: endpoint('chat'),
    };
    for (const scope of ['main', 'chat', 'triage'] as AiScope[]) {
      const reported = { keySaved: r[scope].keySaved, keySavedFor: r[scope].keySavedFor };
      for (const form of forms) {
        const page = keyNeeded(form, endpoint(scope), reported, parents[scope]);
        let refused = false;
        try {
          planAiSave(scope, s, {
            provider: form.provider as 'openai',
            model: 'm',
            baseUrl: form.baseUrl,
          });
        } catch (e) {
          if (!(e instanceof AiKeyRequiredError)) throw e;
          refused = true;
        }
        const label = `${h.label}: ${scope} -> ${form.provider} ${JSON.stringify(form.baseUrl)}`;
        assert.equal(page, refused, label);
        checked++;
        if (r[scope].keyMismatch && !refused && endpoint(scope).baseUrl !== form.baseUrl.trim())
          pointedBack++;
      }
    }
  }
  assert.ok(checked > 500, `${checked} saves compared`);
  assert.ok(
    pointedBack > 0,
    'some saves point a card with an unused key back where it was saved for'
  );
});
