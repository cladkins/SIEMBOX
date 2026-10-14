/**
 * A saved AI key never follows a change of provider or base URL, end to end:
 * the real app on an ephemeral port, a real Postgres, an admin session, and two
 * fake OpenAI-compatible providers (A and B) that record the Authorization
 * header of every request they get. PUT /api/settings/ai, /ai-chat and
 * /ai-triage change the configs; the keys are then exercised the way the
 * product sends them: POST /api/ai/explain (AI Builder), POST /api/ai/chat
 * (AI Analyst) and, for AI Triage, the agent's own call
 * (callProviderChat(getTriageAiConfig()), as runAlertTriage makes it).
 *
 * Before the fix, PUT /api/settings/ai {"baseUrl": B} without an apiKey kept
 * the saved key and the next call sent "Authorization: Bearer <saved key>" to
 * B; switching anthropic -> openai sent the Anthropic key the same way. Now
 * such a change is a 400 naming apiKey, and the saved key is only sent to the
 * provider and base URL it was saved for.
 *
 * The AI settings are global rows, so this test saves every ai_* row it finds,
 * works on an empty set and puts the saved rows back afterwards. Never a real
 * provider: Anthropic is configured but never called. Skips itself when
 * Postgres isn't reachable. Run with `npm test` (tsx --test).
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import http from 'node:http';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { CredentialEncryption } from '../services/credentials/credentialEncryption';
import { callProviderChat, getAiConfig, getTriageAiConfig } from '../services/ai/aiService';
// The Settings page's rule for asking for the key, fed what GET reports.
import { keyNeeded, type AiEndpoint } from '../../../frontend/src/views/settings/aiKeyTarget';

const SKIP = 'Postgres with the settings schema is not reachable';
const TEST_USER_NAME = '^aikeytarget-[0-9a-f]{12}-admin$';
const LOCK = "hashtext('siembox:ai-settings')";

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
let token = '';
let userId = 0;
/** 5xx responses so far; each one is logged to application_errors (see after()). */
let serverErrors = 0;
/** The ai_* rows found before the test, put back after it. */
let savedRows: Array<{ key: string; value: string }> = [];
const savedEnv: Record<string, string | undefined> = {};
const ENV_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'CREDENTIAL_ENCRYPTION_KEY'] as const;

// ---- Fake providers ----------------------------------------------------------

interface Seen {
  provider: 'A' | 'B';
  path: string;
  authorization: string | undefined;
  model: string | undefined;
}
const seen: Seen[] = [];
const fakes: Record<'A' | 'B', { server?: Server; url: string }> = {
  A: { url: '' },
  B: { url: '' },
};

async function startFake(name: 'A' | 'B') {
  const s = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      let model: string | undefined;
      try {
        model = JSON.parse(body).model;
      } catch {
        model = undefined;
      }
      seen.push({
        provider: name,
        path: req.url || '',
        authorization: req.headers.authorization,
        model,
      });
      const answer = JSON.stringify({ action: 'final', answer: `ok from ${name}` });
      res.setHeader('content-type', 'application/json');
      if (req.url?.endsWith('/chat/completions')) {
        res.end(JSON.stringify({ choices: [{ message: { content: answer } }] }));
      } else {
        res.statusCode = 404;
        res.end('{}');
      }
    });
  });
  s.listen(0, '127.0.0.1');
  await once(s, 'listening');
  fakes[name] = { server: s, url: `http://127.0.0.1:${(s.address() as AddressInfo).port}/v1` };
}

/** Every Authorization header provider `name` received, in order. */
function authAt(name: 'A' | 'B'): Array<string | undefined> {
  return seen.filter((r) => r.provider === name).map((r) => r.authorization);
}

/** No request to any fake provider ever carried `key`. */
function assertNeverSent(key: string, where: Array<'A' | 'B'> = ['A', 'B']) {
  for (const r of seen) {
    if (where.includes(r.provider)) {
      assert.ok(
        !(r.authorization || '').includes(key),
        `${key} was never sent to ${r.provider} (${r.path})`
      );
    }
  }
}

// ---- Setup -------------------------------------------------------------------

before(async () => {
  try {
    for (const table of [
      'system_settings',
      'sessions',
      'users',
      'chat_sessions',
      'application_errors',
    ]) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  delete process.env.ANTHROPIC_API_KEY;
  delete process.env.OPENAI_API_KEY;
  // A throwaway key: the keys saved here are this test's own.
  process.env.CREDENTIAL_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');

  savedRows = (await pool.query(`SELECT key, value FROM system_settings WHERE key LIKE 'ai\\_%'`))
    .rows;

  const user = await UserModel.create({
    username: `aikeytarget-${tag}-admin`,
    email: `aikeytarget-${tag}-admin@siembox.invalid`,
    password: crypto.randomBytes(16).toString('hex'),
    role: 'admin',
  });
  userId = user.id;
  token = (await SessionModel.create(user.id, 1)).token;

  await startFake('A');
  await startFake('B');
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  for (const s of [server, fakes.A.server, fakes.B.server]) {
    if (s) await new Promise<void>((resolve) => s.close(() => resolve()));
  }
  if (dbReady) {
    await pool.query(`DELETE FROM system_settings WHERE key LIKE 'ai\\_%'`);
    for (const row of savedRows) {
      await pool.query('INSERT INTO system_settings (key, value) VALUES ($1, $2)', [
        row.key,
        row.value,
      ]);
    }
    // Every 5xx is logged to application_errors, fire-and-forget: wait for
    // those rows, then delete them before the user (whose delete only nulls
    // user_id there; sessions and chat threads cascade).
    for (let attempt = 0; attempt < 50; attempt++) {
      const logged = await pool.query(
        'SELECT count(*)::int AS n FROM application_errors WHERE user_id = $1',
        [userId]
      );
      if (logged.rows[0].n >= serverErrors) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const stale = `created_at < NOW() - INTERVAL '10 minutes'`;
    const leftover = await pool.query(
      `SELECT id FROM users WHERE username ~ $1 AND email LIKE '%@siembox.invalid' AND ${stale}`,
      [TEST_USER_NAME]
    );
    const doomed = [userId, ...leftover.rows.map((row) => row.id as number)];
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [doomed]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [doomed]);
  }
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  await closePools();
});

beforeEach(async () => {
  if (!dbReady) return;
  await pool.query(`DELETE FROM system_settings WHERE key LIKE 'ai\\_%'`);
  delete process.env.OPENAI_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  seen.length = 0;
});

// ---- Helpers -----------------------------------------------------------------

type ApiJson = Record<string, unknown>;

async function call(
  method: string,
  path: string,
  body?: unknown
): Promise<{ status: number; json: ApiJson }> {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status >= 500) serverErrors++;
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

async function put(area: 'ai' | 'ai-chat' | 'ai-triage', body: unknown, expectStatus = 200) {
  const r = await call('PUT', `/api/settings/${area}`, body);
  assert.equal(
    r.status,
    expectStatus,
    `PUT ${area} ${JSON.stringify(body)}: ${JSON.stringify(r.json)}`
  );
  return r.json;
}

/** A refused change: 400, naming apiKey. */
async function refused(area: 'ai' | 'ai-chat' | 'ai-triage', body: unknown) {
  const json = await put(area, body, 400);
  assert.match(String(json.message), /^apiKey is required/);
  assert.match(String(json.message), /only sent to the provider and base URL it was saved for/);
}

/** The AI Builder's call (POST /api/ai/explain); returns the HTTP status. */
async function explain(): Promise<number> {
  return (await call('POST', '/api/ai/explain', { kind: 'log', data: 'sshd: Failed password' }))
    .status;
}

/** The AI Analyst's call (POST /api/ai/chat). */
async function chat(): Promise<number> {
  return (await call('POST', '/api/ai/chat', { message: 'anything new?' })).status;
}

/** The triage agent's call, as runAlertTriage makes it. */
async function triage(): Promise<void> {
  await callProviderChat(await getTriageAiConfig(), [{ role: 'user', content: 'triage this' }], {
    maxTokens: 50,
  });
}

async function setting(key: string): Promise<string | undefined> {
  return (await pool.query('SELECT value FROM system_settings WHERE key = $1', [key])).rows[0]
    ?.value;
}

const bearer = (key: string) => `Bearer ${key}`;

/** GET /api/settings/<area>. */
async function current(area: 'ai' | 'ai-chat' | 'ai-triage'): Promise<ApiJson> {
  const r = await call('GET', `/api/settings/${area}`);
  assert.equal(r.status, 200);
  return r.json;
}

/** Where a config sends requests, as the Settings page keeps it from GET (aiSaved, chatSaved, ...). */
const endpointOf = (j: ApiJson): AiEndpoint => ({
  provider: String(j.provider),
  baseUrl: String(j.baseUrl ?? ''),
});

/** Whether the Settings page asks for the key before saving `form` on a card that GET reported as `j`. */
function pageAsksForKey(form: AiEndpoint, j: ApiJson, parent?: ApiJson): boolean {
  return keyNeeded(
    form,
    endpointOf(j),
    { keySaved: !!j.keySaved, keySavedFor: j.keySavedFor as AiEndpoint | null },
    parent && endpointOf(parent)
  );
}

// ---- Tests -------------------------------------------------------------------

test('AI Builder: a new base URL without apiKey is a 400, and the saved key never reaches it', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const A = fakes.A.url;
  const B = fakes.B.url;
  const saved = await put('ai', {
    provider: 'openai',
    model: 'gpt-4o',
    baseUrl: A,
    apiKey: 'sk-main-A',
  });
  assert.equal(saved.keySaved, true);
  assert.equal(await explain(), 200);
  assert.deepEqual(authAt('A'), [bearer('sk-main-A')]);

  // The reproduction from the #294 review: only the base URL, no key.
  await refused('ai', { baseUrl: B });
  await refused('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: B });
  assert.equal(await setting('ai_base_url'), A, 'nothing was saved');
  assert.equal(await explain(), 200);
  assert.equal(authAt('B').length, 0, 'B got no request');

  // Model only, with the base URL sent back as the UI does (here with a trailing slash): kept.
  const modelOnly = await put('ai', { provider: 'openai', model: 'gpt-4.1', baseUrl: `${A}/` });
  assert.equal(modelOnly.keySource, 'stored');
  assert.equal(await explain(), 200);
  assert.equal(seen.at(-1)?.model, 'gpt-4.1');
  assert.deepEqual(authAt('A'), [bearer('sk-main-A'), bearer('sk-main-A'), bearer('sk-main-A')]);

  // With the key for B in the same request.
  await put('ai', { provider: 'openai', model: 'gpt-4.1', baseUrl: B, apiKey: 'sk-main-B' });
  assert.equal(await explain(), 200);
  assert.deepEqual(authAt('B'), [bearer('sk-main-B')]);
  assertNeverSent('sk-main-A', ['B']);
  assertNeverSent('sk-main-B', ['A']);
});

test("AI Builder: switching provider needs that provider's key; the Anthropic key is never a Bearer token", async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const B = fakes.B.url;
  await put('ai', { provider: 'anthropic', model: 'claude-sonnet-4-6', apiKey: 'sk-ant-secret' });
  await refused('ai', { provider: 'openai', baseUrl: B });
  await refused('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: '' });
  // Still Anthropic, with its key (checked in-process: Anthropic is never called here).
  assert.deepEqual(await getAiConfig(), {
    provider: 'anthropic',
    model: 'claude-sonnet-4-6',
    baseUrl: undefined,
    apiKey: 'sk-ant-secret',
  });

  await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: B, apiKey: 'sk-oai-B' });
  assert.equal(await explain(), 200);
  assert.deepEqual(authAt('B'), [bearer('sk-oai-B')]);
  assertNeverSent('sk-ant-secret');

  // Ollama sends no key; switching to it still says what happens to the saved one.
  await refused('ai', { provider: 'ollama', baseUrl: 'http://127.0.0.1:9' });
  const ollama = await put('ai', { provider: 'ollama', baseUrl: 'http://127.0.0.1:9', apiKey: '' });
  assert.equal(ollama.keySaved, false);
  assert.equal(await setting('ai_api_key'), '');
});

test('AI Builder: an environment variable key is unaffected; it is used wherever the config points', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const A = fakes.A.url;
  const B = fakes.B.url;
  process.env.OPENAI_API_KEY = 'sk-env-openai';
  const atA = await put('ai', { provider: 'openai', baseUrl: A });
  assert.equal(atA.keySource, 'env');
  assert.equal(await explain(), 200);
  const atB = await put('ai', { provider: 'openai', baseUrl: B });
  assert.equal(atB.keySource, 'env');
  assert.equal(await explain(), 200);
  assert.deepEqual(authAt('A'), [bearer('sk-env-openai')]);
  assert.deepEqual(authAt('B'), [bearer('sk-env-openai')]);

  // A saved key removed in the same request as the move: the variable takes over at the new address.
  await put('ai', { provider: 'openai', baseUrl: B, apiKey: 'sk-saved-B' });
  await put('ai', { provider: 'openai', baseUrl: A, apiKey: '' });
  assert.equal(await explain(), 200);
  assert.deepEqual(authAt('A'), [bearer('sk-env-openai'), bearer('sk-env-openai')]);
  assertNeverSent('sk-saved-B');
});

test("AI Analyst: same rule, and main's saved key is not sent to a base URL of the analyst's own", async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const A = fakes.A.url;
  const B = fakes.B.url;
  await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: A, apiKey: 'sk-main-A' });
  assert.equal(await chat(), 200, 'inheriting main');
  assert.deepEqual(authAt('A'), [bearer('sk-main-A')]);

  // The analyst pointed at B without a key of its own: allowed, but main's key stays with main.
  const own = await put('ai-chat', { provider: 'openai', model: 'gpt-4o', baseUrl: B });
  assert.equal(own.configured, false);
  assert.equal(own.keySaved, false);
  assert.equal(await chat(), 500);
  assert.equal(authAt('B').length, 0, 'B got no request');

  await put('ai-chat', { provider: 'openai', model: 'gpt-4o', baseUrl: B, apiKey: 'sk-chat-B' });
  assert.equal(await chat(), 200);
  assert.deepEqual(authAt('B'), [bearer('sk-chat-B')]);

  await refused('ai-chat', { provider: 'openai', model: 'gpt-4o', baseUrl: A });
  await refused('ai-chat', { provider: 'anthropic' });
  // Back to inheriting (as the UI sends it) would take the analyst's key to A.
  await refused('ai-chat', { provider: '', model: '', baseUrl: '' });
  assert.equal(await setting('ai_chat_provider'), 'openai', 'nothing was saved');

  const modelOnly = await put('ai-chat', { provider: 'openai', model: 'gpt-4.1', baseUrl: B });
  assert.equal(modelOnly.keySource, 'stored');
  assert.equal(await chat(), 200);
  assert.deepEqual(authAt('B'), [bearer('sk-chat-B'), bearer('sk-chat-B')]);

  const inherit = await put('ai-chat', { provider: '', model: '', baseUrl: '', apiKey: '' });
  assert.equal(inherit.inheritsFrom, 'main');
  assert.equal(await chat(), 200);
  assert.deepEqual(authAt('A'), [bearer('sk-main-A'), bearer('sk-main-A')]);
  assertNeverSent('sk-main-A', ['B']);
  assertNeverSent('sk-chat-B', ['A']);
});

test('AI Triage: same rule; a refused change saves none of the knobs sent with it', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const A = fakes.A.url;
  const B = fakes.B.url;
  await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: A, apiKey: 'sk-main-A' });
  await put('ai-triage', {
    provider: 'openai',
    model: 'gpt-4o',
    baseUrl: B,
    apiKey: 'sk-tri-B',
    dailyCap: 10,
  });
  await triage();
  assert.deepEqual(authAt('B'), [bearer('sk-tri-B')]);

  await refused('ai-triage', { provider: 'openai', model: 'gpt-4o', baseUrl: A, dailyCap: 50 });
  await refused('ai-triage', { provider: '', model: '', baseUrl: '', enabled: false });
  assert.equal(
    await setting('ai_triage_daily_cap'),
    '10',
    'the knob in the refused request was not saved'
  );
  assert.equal(await setting('ai_triage_base_url'), B);

  const modelOnly = await put('ai-triage', {
    provider: 'openai',
    model: 'gpt-4.1',
    baseUrl: B,
    dailyCap: 50,
  });
  assert.equal(modelOnly.dailyCap, 50);
  await triage();
  assert.deepEqual(authAt('B'), [bearer('sk-tri-B'), bearer('sk-tri-B')]);

  await put('ai-triage', { provider: 'openai', model: 'gpt-4.1', baseUrl: A, apiKey: 'sk-tri-A' });
  await triage();
  assert.deepEqual(authAt('A'), [bearer('sk-tri-A')]);
  assertNeverSent('sk-tri-B', ['A']);
  assertNeverSent('sk-tri-A', ['B']);
  assertNeverSent('sk-main-A');
});

test("moving the AI Builder does not take the analyst's own key along", async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const A = fakes.A.url;
  const B = fakes.B.url;
  await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: A, apiKey: 'sk-main-A' });
  // Same provider as main and no base URL of its own: the analyst follows main's.
  await put('ai-chat', { provider: 'openai', model: 'gpt-4o', baseUrl: '', apiKey: 'sk-chat-own' });
  assert.equal(await chat(), 200);
  assert.deepEqual(authAt('A'), [bearer('sk-chat-own')]);

  // Main moves to B with a key of its own (any key will do for an attacker).
  await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: B, apiKey: 'sk-throwaway' });
  const after = (await call('GET', '/api/settings/ai-chat')).json;
  assert.equal(after.baseUrl, B);
  assert.equal(after.keyMismatch, true, 'the analyst reports its saved key as not used');
  assert.equal(await chat(), 200);
  assert.deepEqual(authAt('B'), [bearer('sk-throwaway')]);
  assertNeverSent('sk-chat-own', ['B']);
});

test('a key saved before this change is bound to where it was used by the next save', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const A = fakes.A.url;
  const B = fakes.B.url;
  // As an earlier version left them: main at A, the analyst inheriting with a bare encrypted key.
  const legacy = (k: string) => JSON.stringify(CredentialEncryption.encrypt(k));
  for (const [key, value] of [
    ['ai_provider', 'openai'],
    ['ai_base_url', A],
    ['ai_api_key', legacy('sk-legacy-main')],
    ['ai_chat_api_key', legacy('sk-legacy-chat')],
  ]) {
    await pool.query('INSERT INTO system_settings (key, value) VALUES ($1, $2)', [key, value]);
  }
  assert.equal(await chat(), 200);
  assert.deepEqual(authAt('A'), [bearer('sk-legacy-chat')]);
  await refused('ai', { baseUrl: B });

  const legacyChatRow = await setting('ai_chat_api_key');
  await put('ai', { provider: 'openai', baseUrl: B, apiKey: 'sk-main-B' });
  assert.equal(await chat(), 200);
  assert.deepEqual(authAt('B'), [bearer('sk-main-B')]);
  assertNeverSent('sk-legacy-chat', ['B']);
  assertNeverSent('sk-legacy-main', ['B']);

  // The key rows keep the earlier format (a rollback reads them as before):
  // the analyst's is untouched, its target is a row of its own, and main's new
  // key decrypts to the bare key.
  assert.equal(await setting('ai_chat_api_key'), legacyChatRow);
  assert.ok(await setting('ai_chat_api_key_target'));
  const { encrypted, iv, authTag } = JSON.parse((await setting('ai_api_key'))!);
  assert.equal(CredentialEncryption.decrypt(encrypted, iv, authTag), 'sk-main-B');
});

test('GET /ai-chat and /ai-triage report their own base URL, so a blank one is sent back blank', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const A = fakes.A.url;
  const B = fakes.B.url;
  await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: A, apiKey: 'sk-main-A' });
  // Both on the AI Builder's provider with no base URL of their own (spaces count as none).
  await put('ai-chat', { provider: 'openai', model: 'gpt-4o', baseUrl: '', apiKey: 'sk-chat-own' });
  await put('ai-triage', {
    provider: 'openai',
    model: 'gpt-4o',
    baseUrl: '  ',
    apiKey: 'sk-tri-own',
  });
  for (const area of ['ai-chat', 'ai-triage']) {
    const got = (await call('GET', `/api/settings/${area}`)).json;
    assert.equal(got.ownBaseUrl, '', `${area}: no base URL of its own`);
    assert.equal(got.baseUrl, A, `${area}: follows the AI Builder's`);
  }

  // The review's case: the AI Builder moves to B. Both follow it; their own keys stay at A, unused.
  await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: B, apiKey: 'sk-main-B' });
  const chatNow = (await call('GET', '/api/settings/ai-chat')).json;
  const triageNow = (await call('GET', '/api/settings/ai-triage')).json;
  assert.deepEqual(
    [chatNow.baseUrl, chatNow.ownBaseUrl, chatNow.keyMismatch],
    [B, '', true],
    'the analyst'
  );
  assert.deepEqual([triageNow.baseUrl, triageNow.ownBaseUrl, triageNow.keyMismatch], [B, '', true]);

  // What the Settings page sends for a model-only or knob-only save, its form
  // holding ownBaseUrl: no key asked for, and both keep following the AI Builder.
  await put('ai-chat', { provider: 'openai', model: 'gpt-4.1', baseUrl: chatNow.ownBaseUrl });
  await put('ai-triage', {
    provider: 'openai',
    model: 'gpt-4o',
    baseUrl: triageNow.ownBaseUrl,
    enabled: true,
  });
  assert.equal(await setting('ai_chat_base_url'), '');
  assert.equal(await setting('ai_triage_base_url'), '');
  assert.equal(await setting('ai_triage_enabled'), 'true');

  // Pointing the analyst back at A, where its key was saved for: a base URL of its own.
  const back = await put('ai-chat', { provider: 'openai', model: 'gpt-4.1', baseUrl: A });
  assert.deepEqual([back.ownBaseUrl, back.baseUrl, back.keyMismatch], [A, A, false]);
  assert.equal(await chat(), 200);
  assert.deepEqual(authAt('A'), [bearer('sk-chat-own')]);
  assertNeverSent('sk-chat-own', ['B']);
  assertNeverSent('sk-tri-own', ['B']);
});

test('a base URL of only spaces is blank, and model and base URL are stored trimmed', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const A = fakes.A.url;
  await put('ai', { provider: 'openai', model: 'gpt-4o', apiKey: 'sk-default' });
  // Was a 400 asking for apiKey: the page treats spaces as blank and asks for nothing.
  const blank = await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: '   ' });
  assert.equal(blank.baseUrl, 'https://api.openai.com/v1');
  assert.equal(blank.keySource, 'stored');
  assert.equal(await setting('ai_base_url'), '');

  // Padded values: stored without the spaces, so the request URL has none.
  await put('ai', {
    provider: 'openai',
    model: ' gpt-4o ',
    baseUrl: ` ${A} `,
    apiKey: 'sk-main-A',
  });
  assert.equal(await setting('ai_base_url'), A);
  assert.equal(await setting('ai_model'), 'gpt-4o');
  assert.equal(await explain(), 200);
  assert.deepEqual(
    seen.map((r) => [r.path, r.model, r.authorization]),
    [['/v1/chat/completions', 'gpt-4o', bearer('sk-main-A')]]
  );
});

test('saves queue: a base URL change waiting behind a key save sees the key and is refused', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const A = fakes.A.url;
  const B = fakes.B.url;
  await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: A });

  const holder = await pool.connect();
  const waiters = async () =>
    (
      await pool.query(
        `SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND database =
           (SELECT oid FROM pg_database WHERE datname = current_database())`
      )
    ).rows[0].n as number;
  const waitFor = async (n: number) => {
    for (let i = 0; i < 100 && (await waiters()) < n; i++)
      await new Promise((r) => setTimeout(r, 20));
    assert.equal(await waiters(), n, `${n} save(s) waiting`);
  };
  let keySave: Promise<{ status: number; json: ApiJson }>;
  let move: Promise<{ status: number; json: ApiJson }>;
  try {
    await holder.query('BEGIN');
    await holder.query(`SELECT pg_advisory_xact_lock(${LOCK})`);
    keySave = call('PUT', '/api/settings/ai', { apiKey: 'sk-race' });
    await waitFor(1);
    move = call('PUT', '/api/settings/ai', { baseUrl: B });
    await waitFor(2);
    // Neither has written anything yet.
    assert.equal(await setting('ai_api_key'), undefined);
    assert.equal(await setting('ai_base_url'), A);
  } finally {
    await holder.query('COMMIT');
    holder.release();
  }
  assert.equal((await keySave!).status, 200);
  const moved = await move!;
  assert.equal(moved.status, 400, JSON.stringify(moved.json));
  assert.equal(await setting('ai_base_url'), A);
  assert.equal(await explain(), 200);
  assert.deepEqual(authAt('A'), [bearer('sk-race')]);
  assertNeverSent('sk-race', ['B']);
});

test('model, baseUrl and apiKey must be strings (apiKey may be null)', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await put('ai', { provider: 'openai', baseUrl: fakes.A.url, apiKey: 'sk-main-A' });
  for (const area of ['ai', 'ai-chat', 'ai-triage'] as const) {
    assert.match(String((await put(area, { apiKey: 5 }, 400)).message), /^apiKey must be a string/);
    assert.match(
      String((await put(area, { baseUrl: { href: fakes.B.url } }, 400)).message),
      /^baseUrl must be a string/
    );
    assert.match(
      String((await put(area, { model: null }, 400)).message),
      /^model must be a string/
    );
  }
  assert.equal(await setting('ai_base_url'), fakes.A.url);
  const cleared = await put('ai', { apiKey: null });
  assert.equal(cleared.keySaved, false);
});

test('a baseUrl over 2048 characters is a 400 on all three routes, and nothing in the request is saved', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  // The shape that made the old trailing-slash regex quadratic, past the limit.
  const long = `http://h.test${'/'.repeat(2048)}x`;
  for (const area of ['ai', 'ai-chat', 'ai-triage'] as const) {
    const json = await put(
      area,
      { provider: 'openai', model: 'gpt-4o', baseUrl: long, dailyCap: 77 },
      400
    );
    assert.equal(json.message, 'baseUrl must be at most 2048 characters', area);
  }
  for (const key of [
    'ai_provider',
    'ai_base_url',
    'ai_chat_base_url',
    'ai_triage_base_url',
    'ai_triage_daily_cap',
  ])
    assert.equal(await setting(key), undefined, key);
  // 2048 is accepted (no key is saved, so the move needs none).
  const max = `http://h.test/${'a'.repeat(2048 - 'http://h.test/'.length)}`;
  assert.equal(max.length, 2048);
  const ok = await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: max });
  assert.equal(ok.baseUrl, max);
});

test('pointing a card back where its saved key was saved for: the page asks for no key and the API takes the save', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const A = fakes.A.url;
  const B = fakes.B.url;
  const C = 'http://127.0.0.1:9/v1';
  // The verifier's setup: the Builder on OpenAI at A with its key; the analyst
  // and triage on OpenAI with no base URL of their own and keys of their own,
  // saved for A. Then the Builder moves to B.
  await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: A, apiKey: 'sk-main-A' });
  await put('ai-chat', { provider: 'openai', model: 'gpt-4o', baseUrl: '', apiKey: 'sk-chat-own' });
  await put('ai-triage', {
    provider: 'openai',
    model: 'gpt-4o',
    baseUrl: '',
    apiKey: 'sk-tri-own',
  });
  const ai = await put('ai', {
    provider: 'openai',
    model: 'gpt-4o',
    baseUrl: B,
    apiKey: 'sk-main-B',
  });
  assert.deepEqual(ai.keySavedFor, { provider: 'openai', baseUrl: B });

  // Both cards read "Saved key not used"; GET says where their keys were saved for.
  const chatNow = await current('ai-chat');
  let triageNow = await current('ai-triage');
  for (const [name, j] of [
    ['analyst', chatNow],
    ['triage', triageNow],
  ] as const) {
    assert.deepEqual(
      [j.baseUrl, j.ownBaseUrl, j.keyMismatch, j.keySavedFor],
      [B, '', true, { provider: 'openai', baseUrl: A }],
      name
    );
  }

  // Triage first, while its parent (the analyst) is still at B. A typed in:
  // the page asks for no key, and the save it then sends (no apiKey) is taken.
  assert.equal(pageAsksForKey({ provider: 'openai', baseUrl: A }, triageNow, chatNow), false);
  assert.equal(pageAsksForKey({ provider: 'openai', baseUrl: `${A}/` }, triageNow, chatNow), false);
  assert.equal(
    pageAsksForKey({ provider: 'openai', baseUrl: '' }, triageNow, chatNow),
    false,
    'untouched'
  );
  // Anywhere else still needs the key, on the page and at the API.
  assert.equal(pageAsksForKey({ provider: 'openai', baseUrl: C }, triageNow, chatNow), true);
  await refused('ai-triage', { provider: 'openai', model: 'gpt-4o', baseUrl: C });
  const triageBack = await put('ai-triage', { provider: 'openai', model: 'gpt-4o', baseUrl: A });
  assert.deepEqual(
    [triageBack.baseUrl, triageBack.keySource, triageBack.keyMismatch],
    [A, 'stored', false]
  );
  await triage();
  assert.deepEqual(authAt('A'), [bearer('sk-tri-own')]);

  // The analyst: the verifier's case.
  const aiNow = await current('ai');
  assert.equal(pageAsksForKey({ provider: 'openai', baseUrl: A }, chatNow, aiNow), false);
  assert.equal(pageAsksForKey({ provider: 'openai', baseUrl: C }, chatNow, aiNow), true);
  const chatBack = await put('ai-chat', { provider: 'openai', model: 'gpt-4o', baseUrl: A });
  assert.deepEqual(
    [chatBack.ownBaseUrl, chatBack.baseUrl, chatBack.keySource, chatBack.keyMismatch],
    [A, A, 'stored', false]
  );
  assert.equal(await chat(), 200);
  assert.deepEqual(authAt('A'), [bearer('sk-tri-own'), bearer('sk-chat-own')]);
  // Triage, at A of its own, is unaffected.
  triageNow = await current('ai-triage');
  assert.deepEqual([triageNow.keySource, triageNow.keyMismatch], ['stored', false]);
  assertNeverSent('sk-chat-own', ['B']);
  assertNeverSent('sk-tri-own', ['B']);
  assertNeverSent('sk-main-B', ['A']);
});

test('the AI Builder pointed back after an earlier version moved it with its key: no key asked for', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const A = fakes.A.url;
  const B = fakes.B.url;
  await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: A, apiKey: 'sk-main-A' });
  // An earlier version, rolled back to, moved the Builder to B and kept the key (as it allowed).
  await pool.query(`UPDATE system_settings SET value = $1 WHERE key = 'ai_base_url'`, [B]);
  const moved = await current('ai');
  assert.deepEqual(
    [moved.baseUrl, moved.keySource, moved.keyMismatch, moved.keySavedFor],
    [B, 'none', true, { provider: 'openai', baseUrl: A }]
  );
  // The form shows B; A typed back in needs no key, anything else does.
  assert.equal(pageAsksForKey({ provider: 'openai', baseUrl: A }, moved), false);
  assert.equal(
    pageAsksForKey(
      { provider: 'openai', baseUrl: 'HTTP://127.0.0.1' + A.slice('http://127.0.0.1'.length) },
      moved
    ),
    false
  );
  assert.equal(
    pageAsksForKey({ provider: 'openai', baseUrl: 'https://api.openai.com/v1' }, moved),
    true
  );
  assert.equal(pageAsksForKey({ provider: 'anthropic', baseUrl: B }, moved), true);
  await refused('ai', {
    provider: 'openai',
    model: 'gpt-4o',
    baseUrl: 'https://api.openai.com/v1',
  });

  const back = await put('ai', { provider: 'openai', model: 'gpt-4o', baseUrl: A });
  assert.deepEqual([back.baseUrl, back.keySource, back.keyMismatch], [A, 'stored', false]);
  assert.equal(await explain(), 200);
  assert.deepEqual(authAt('A'), [bearer('sk-main-A')]);
  assert.equal(authAt('B').length, 0);
});
