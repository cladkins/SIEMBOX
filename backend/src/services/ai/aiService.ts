/**
 * AI parser builder — turn a raw log sample into a portable parser.
 *
 * Provider-agnostic (Anthropic / OpenAI / Ollama), bring-your-own-key. The model
 * proposes a `siembox.parser/v1` object; we run it through the SAME validator +
 * self-test loop the catalog/import use, feed any failures back to the model, and
 * return the best attempt. So the output is always checked against the real
 * engine, never trusted blind.
 */
import { query, getClient } from '../../config/database';
import { logger } from '../../utils/logger';
import { CredentialEncryption } from '../credentials/credentialEncryption';
import {
  validatePortableParser,
  runSelfTests,
  PortableParser,
  ValidationResult,
  SelfTestResult,
} from '../parser/parserPortable';
import { scanParserRedos, RedosFinding } from '../parser/redos';
import { validateRule, RuleValidationResult, PortableRule } from '../rules/rulePortable';

export type AiProvider = 'anthropic' | 'openai' | 'ollama';

export interface AiConfig {
  provider: AiProvider;
  model: string;
  baseUrl?: string;
  apiKey?: string;
}

const DEFAULT_MODELS: Record<AiProvider, string> = {
  anthropic: 'claude-sonnet-4-6',
  openai: 'gpt-4o',
  ollama: 'llama3.1',
};
const DEFAULT_BASE_URLS: Partial<Record<AiProvider, string>> = {
  openai: 'https://api.openai.com/v1',
  ollama: 'http://localhost:11434',
};

async function getSetting(key: string): Promise<string | undefined> {
  const r = await query('SELECT value FROM system_settings WHERE key = $1', [key]);
  return r.rows[0]?.value;
}

/** The provider's API key from its environment variable, if set. */
function envKeyFor(provider: AiProvider): string | undefined {
  if (provider === 'anthropic') return process.env.ANTHROPIC_API_KEY;
  if (provider === 'openai') return process.env.OPENAI_API_KEY;
  return undefined; // ollama needs none
}

// ---- The three model configs -------------------------------------------------
// The AI Builder ("main": explain/generate), the AI Analyst ("chat") and AI
// Triage each have a provider, model, base URL and key. The analyst inherits
// from main and triage from the analyst: with no provider of its own a config
// takes its parent's, and a model or base URL left blank is the parent's when
// the provider is the same (else the provider's default). All three are read
// from one snapshot of their settings, so a request never pairs one moment's
// key with another moment's address.

/** Which of the three configs. */
export type AiScope = 'main' | 'chat' | 'triage';
const SCOPES: AiScope[] = ['main', 'chat', 'triage'];

const SCOPE_SETTINGS: Record<
  AiScope,
  { provider: string; model: string; baseUrl: string; apiKey: string }
> = {
  main: {
    provider: 'ai_provider',
    model: 'ai_model',
    baseUrl: 'ai_base_url',
    apiKey: 'ai_api_key',
  },
  chat: {
    provider: 'ai_chat_provider',
    model: 'ai_chat_model',
    baseUrl: 'ai_chat_base_url',
    apiKey: 'ai_chat_api_key',
  },
  triage: {
    provider: 'ai_triage_provider',
    model: 'ai_triage_model',
    baseUrl: 'ai_triage_base_url',
    apiKey: 'ai_triage_api_key',
  },
};
const SCOPE_LABELS: Record<AiScope, string> = {
  main: 'AI Builder',
  chat: 'AI Analyst',
  triage: 'AI Triage',
};
const MODEL_SETTING_KEYS = SCOPES.flatMap((scope) => Object.values(SCOPE_SETTINGS[scope]));

/** The model settings of all three configs as stored (key -> value). */
export type AiSettings = Record<string, string>;

interface Queryable {
  query: (
    text: string,
    params?: unknown[]
  ) => Promise<{ rows: Array<{ key: string; value: string | null }> }>;
}

/** All three configs' settings, in one statement. */
async function readAiSettings(db: Queryable = { query }): Promise<AiSettings> {
  const r = await db.query('SELECT key, value FROM system_settings WHERE key = ANY($1)', [
    MODEL_SETTING_KEYS,
  ]);
  const settings: AiSettings = {};
  for (const row of r.rows) settings[row.key] = row.value ?? '';
  return settings;
}

// ---- Where a key is sent -----------------------------------------------------

/** Anthropic is always called here; SIEMBox doesn't use the base URL setting for it. */
const ANTHROPIC_BASE_URL = 'https://api.anthropic.com/v1';

/** The base URL a provider's requests, and so its API key, go to. */
function requestBaseUrl(provider: AiProvider, baseUrl?: string): string {
  if (provider === 'anthropic') return ANTHROPIC_BASE_URL;
  return baseUrl || DEFAULT_BASE_URLS[provider] || '';
}

/**
 * A base URL in comparable form, so that a value sent back unchanged, or with a
 * trailing slash, an upper-case host or the default port spelled out, is not a
 * change: trimmed; scheme and host lower case; default port, fragment and
 * trailing slashes dropped. A value that isn't a URL only loses surrounding
 * space and trailing slashes.
 */
export function normalizeBaseUrl(raw: string): string {
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

/** Where a config's API key is sent: its provider and the base URL its requests go to. */
export function keyTarget(provider: AiProvider, baseUrl?: string): string {
  return `${provider} ${normalizeBaseUrl(requestBaseUrl(provider, baseUrl))}`;
}

// ---- Saved keys --------------------------------------------------------------
// A key saved from the UI is encrypted together with the target it was saved
// for, and is only ever sent there. After a change of provider or base URL,
// of its own config or of the config it inherits from, it is not sent rather
// than sent to the new address. A key saved before targets were recorded holds
// only the key: it counts as saved for its config's current target, and the
// first save of any of the three configs records that target (planAiSave)
// before changing anything.

interface SavedKey {
  apiKey: string;
  /** null: saved before targets were recorded. */
  target: string | null;
}

function sealKey(apiKey: string, target: string): string {
  // CredentialEncryption.encrypt throws if CREDENTIAL_ENCRYPTION_KEY is unset.
  return JSON.stringify(CredentialEncryption.encrypt(JSON.stringify({ apiKey, target })));
}

function openKey(stored: string | undefined, setting: string): SavedKey | null {
  if (!stored) return null;
  let plain: string;
  try {
    const { encrypted, iv, authTag } = JSON.parse(stored);
    plain = CredentialEncryption.decrypt(encrypted, iv, authTag);
  } catch (e) {
    logger.warn(`AI: stored ${setting} could not be decrypted; not using it`, {
      error: e instanceof Error ? e.message : String(e),
    });
    return null;
  }
  if (plain.startsWith('{')) {
    try {
      const sealed = JSON.parse(plain);
      if (typeof sealed?.apiKey === 'string' && typeof sealed?.target === 'string') {
        return { apiKey: sealed.apiKey, target: sealed.target };
      }
    } catch {
      // not a sealed key: a key saved before targets were recorded
    }
  }
  return { apiKey: plain, target: null };
}

// ---- Resolving a config ------------------------------------------------------

export interface ResolvedModel {
  provider: AiProvider;
  model: string;
  baseUrl?: string;
  /** Where its key is sent (keyTarget). */
  target: string;
}

/** Provider, model, base URL and target of each config (the inheritance described above). */
function resolveModels(s: AiSettings): Record<AiScope, ResolvedModel> {
  const out = {} as Record<AiScope, ResolvedModel>;
  let parent: ResolvedModel | undefined;
  for (const scope of SCOPES) {
    const names = SCOPE_SETTINGS[scope];
    const provider = ((s[names.provider] as AiProvider) ||
      parent?.provider ||
      'anthropic') as AiProvider;
    const same = !!parent && provider === parent.provider;
    const model = s[names.model] || (same ? parent!.model : DEFAULT_MODELS[provider]) || '';
    const baseUrl = s[names.baseUrl] || (same ? parent!.baseUrl : DEFAULT_BASE_URLS[provider]);
    parent = out[scope] = { provider, model, baseUrl, target: keyTarget(provider, baseUrl) };
  }
  return out;
}

/** A config with the key it sends. Server-side only. */
export interface ResolvedAiConfig extends ResolvedModel {
  apiKey?: string;
  /** Where that key comes from: a saved key (its own or its parent's), an environment variable, or none. */
  keySource: 'stored' | 'env' | 'none';
  /** It has a key of its own saved. */
  keySaved: boolean;
  /** That key was saved for another provider or base URL, so it is not sent. */
  keyMismatch: boolean;
}

/**
 * The key each config sends: its own saved key when that was saved for where
 * it now sends requests; else its parent's saved key, but only to the
 * parent's own target; else the provider's environment variable (sent to
 * wherever the config points).
 */
export function resolveAiSettings(s: AiSettings): Record<AiScope, ResolvedAiConfig> {
  const models = resolveModels(s);
  const out = {} as Record<AiScope, ResolvedAiConfig>;
  let parent: ResolvedAiConfig | undefined;
  for (const scope of SCOPES) {
    const m = models[scope];
    const setting = SCOPE_SETTINGS[scope].apiKey;
    const saved = openKey(s[setting], setting);
    const savedHere = !!saved?.apiKey && (saved.target ?? m.target) === m.target;
    let apiKey: string | undefined;
    let keySource: ResolvedAiConfig['keySource'];
    if (savedHere) {
      apiKey = saved!.apiKey;
      keySource = 'stored';
    } else if (parent?.keySource === 'stored' && parent.target === m.target) {
      apiKey = parent.apiKey;
      keySource = 'stored';
    } else {
      apiKey = envKeyFor(m.provider);
      keySource = apiKey ? 'env' : 'none';
    }
    parent = out[scope] = {
      ...m,
      apiKey,
      keySource,
      keySaved: !!s[setting],
      keyMismatch: !!saved && !savedHere,
    };
  }
  return out;
}

function asAiConfig(r: ResolvedAiConfig): AiConfig {
  return { provider: r.provider, model: r.model, baseUrl: r.baseUrl, apiKey: r.apiKey };
}

/** What the settings pages see of a config: no key, only whether and where one is configured. */
export interface AiPublicConfig {
  provider: AiProvider;
  model: string;
  baseUrl?: string;
  configured: boolean;
  keySource: 'stored' | 'env' | 'none';
  /** This config has a key of its own saved: a change of its provider or base URL needs `apiKey`. */
  keySaved: boolean;
  /** That saved key was saved for another provider or base URL, so it is not sent. */
  keyMismatch: boolean;
}

function publicView(r: ResolvedAiConfig): AiPublicConfig {
  return {
    provider: r.provider,
    model: r.model,
    baseUrl: r.baseUrl,
    configured: r.provider === 'ollama' ? true : !!r.apiKey,
    keySource: r.keySource,
    keySaved: r.keySaved,
    keyMismatch: r.keyMismatch,
  };
}

/** Full AI Builder config incl. the resolved API key — server-side use only. */
export async function getAiConfig(): Promise<AiConfig> {
  return asAiConfig(resolveAiSettings(await readAiSettings()).main);
}

/** AI Builder config safe to expose to the UI (no key, just whether one is configured). */
export async function getAiPublicConfig(): Promise<AiPublicConfig> {
  return publicView(resolveAiSettings(await readAiSettings()).main);
}

/** Full AI Analyst (chat) config incl. resolved key — server-side use only. */
export async function getChatAiConfig(): Promise<AiConfig> {
  return asAiConfig(resolveAiSettings(await readAiSettings()).chat);
}

/** AI Analyst config safe for the UI (no key); `inheritsFrom` tells if it uses the main config's provider. */
export async function getChatAiPublicConfig(): Promise<
  AiPublicConfig & { inheritsFrom: 'chat' | 'main' }
> {
  const s = await readAiSettings();
  return {
    ...publicView(resolveAiSettings(s).chat),
    inheritsFrom: s.ai_chat_provider ? 'chat' : 'main',
  };
}

/** Full AI Triage config incl. resolved key — server-side use only. */
export async function getTriageAiConfig(): Promise<AiConfig> {
  return asAiConfig(resolveAiSettings(await readAiSettings()).triage);
}

// ---- Saving ------------------------------------------------------------------

/** A save that changes where a config's saved key would be sent without a new key (or "" to remove it). */
export class AiKeyRequiredError extends Error {
  constructor(readonly scope: AiScope) {
    super(
      `apiKey is required: this changes the ${SCOPE_LABELS[scope]} provider or base URL, and its saved API key is ` +
        'only sent to the provider and base URL it was saved for. Send the API key for the new one as apiKey, or ' +
        'apiKey "" to remove the saved key (the ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable is then ' +
        'used, if set).'
    );
    this.name = 'AiKeyRequiredError';
  }
}

export interface AiModelInput {
  /** '' (chat and triage only) reverts to inheriting the parent's provider; main ignores ''. */
  provider?: AiProvider | '';
  model?: string;
  baseUrl?: string;
  /** A new key; '' or null removes the saved one; absent keeps it. */
  apiKey?: string | null;
}

/**
 * The rows one save of `scope` writes, given the settings it read (pure: the
 * caller writes them in the same transaction it read them in). Throws
 * AiKeyRequiredError when the change moves the config's target (keyTarget:
 * provider, or the base URL its requests go to, compared normalized) while it
 * has a key of its own saved and the input has no apiKey; the one exception is
 * a move back to the target that key was saved for. A model-only change, or a
 * base URL sent back unchanged, keeps the key. A config without a saved key of
 * its own can move freely: its key comes from its parent (only to the
 * parent's target) or an environment variable.
 */
export function planAiSave(
  scope: AiScope,
  before: AiSettings,
  input: AiModelInput,
  extra: AiSettings = {}
): AiSettings {
  const writes: AiSettings = {};
  const was = resolveModels(before);
  const opened = {} as Record<AiScope, SavedKey | null>;
  // Record the target of keys saved before targets were, before anything moves.
  for (const sc of SCOPES) {
    const setting = SCOPE_SETTINGS[sc].apiKey;
    opened[sc] = openKey(before[setting], setting);
    if (opened[sc] && opened[sc]!.target === null)
      writes[setting] = sealKey(opened[sc]!.apiKey, was[sc].target);
  }

  const names = SCOPE_SETTINGS[scope];
  if (scope === 'main' ? !!input.provider : input.provider !== undefined)
    writes[names.provider] = input.provider || '';
  if (input.model !== undefined) writes[names.model] = input.model;
  if (input.baseUrl !== undefined) writes[names.baseUrl] = input.baseUrl;
  const target = resolveModels({ ...before, ...writes })[scope].target;

  if (input.apiKey === null || input.apiKey === '') {
    writes[names.apiKey] = ''; // removed: the env var (or the parent's key) applies
  } else if (typeof input.apiKey === 'string') {
    writes[names.apiKey] = sealKey(input.apiKey, target);
  } else if (before[names.apiKey] && target !== was[scope].target) {
    const savedFor = opened[scope] ? (opened[scope]!.target ?? was[scope].target) : null;
    if (savedFor !== target) throw new AiKeyRequiredError(scope);
  }
  return { ...writes, ...extra };
}

/** Save one config: read, decide and write in one transaction, one AI settings save at a time. */
async function saveAiScope(
  scope: AiScope,
  input: AiModelInput,
  extra: AiSettings = {}
): Promise<void> {
  const client = await getClient();
  try {
    await client.query('BEGIN');
    // Saves of the three configs depend on each other's settings, so they queue
    // here: a save never decides on settings another save is changing.
    await client.query("SELECT pg_advisory_xact_lock(hashtext('siembox:ai-settings'))");
    const writes = planAiSave(scope, await readAiSettings(client), input, extra);
    for (const [key, value] of Object.entries(writes)) {
      await client.query(
        `INSERT INTO system_settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
        [key, value]
      );
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw e;
  } finally {
    client.release();
  }
}

/** Persist the AI Builder's provider/model/base_url; encrypt+store the key when provided. */
export async function saveAiConfig(input: {
  provider?: AiProvider;
  model?: string;
  baseUrl?: string;
  apiKey?: string | null;
}): Promise<void> {
  await saveAiScope('main', input);
}

/** Persist the analyst's provider/model/base_url; encrypt+store the key. Empty provider reverts to inheriting main. */
export async function saveChatAiConfig(input: {
  provider?: AiProvider | '';
  model?: string;
  baseUrl?: string;
  apiKey?: string | null;
}): Promise<void> {
  await saveAiScope('chat', input);
}

// ---- Agentic SOC triage config ----------------------------------------------
// The THIRD model selection, for the unattended per-alert triage agent
// (triageAgent.ts). Inheritance chain is triage -> chat -> main (not straight
// to main): triage shares the chat analyst's JSON-tool-protocol requirement, so
// it makes more sense to inherit a model already known to follow that
// protocol. Also carries triage's operational knobs (enabled, severity gate,
// cost caps) alongside the model config, since the UI edits them together.

export interface TriageOperationalConfig {
  enabled: boolean;
  minSeverity: 'low' | 'medium' | 'high' | 'critical';
  dailyCap: number;
  maxConcurrent: number;
  dedupeHours: number;
  /** Per-analysis depth/cost cap — how many read-only tool calls the triage agent may make for one alert. */
  maxToolCalls: number;
  /** Per-analysis wall-clock cap, in seconds, before the agent is forced to synthesize a verdict from what it has. */
  wallBudgetSeconds: number;
}

/** Cheap operational-only read (no key decryption) — safe for the hot ingest path. */
export async function getTriageOperationalConfig(): Promise<TriageOperationalConfig> {
  const enabled = (await getSetting('ai_triage_enabled')) === 'true';
  const minSeverity = ((await getSetting('ai_triage_min_severity')) ||
    'medium') as TriageOperationalConfig['minSeverity'];
  const dailyCap = parseInt((await getSetting('ai_triage_daily_cap')) || '200', 10);
  const maxConcurrent = parseInt((await getSetting('ai_triage_max_concurrent')) || '2', 10);
  const dedupeHours = parseInt((await getSetting('ai_triage_dedupe_hours')) || '6', 10);
  const maxToolCalls = parseInt((await getSetting('ai_triage_max_tool_calls')) || '6', 10);
  const wallBudgetSeconds = parseInt(
    (await getSetting('ai_triage_wall_budget_seconds')) || '110',
    10
  );
  return {
    enabled,
    minSeverity,
    dailyCap: Number.isFinite(dailyCap) ? dailyCap : 200,
    maxConcurrent: Number.isFinite(maxConcurrent) ? maxConcurrent : 2,
    dedupeHours: Number.isFinite(dedupeHours) ? dedupeHours : 6,
    maxToolCalls: Number.isFinite(maxToolCalls) ? maxToolCalls : 6,
    wallBudgetSeconds: Number.isFinite(wallBudgetSeconds) ? wallBudgetSeconds : 110,
  };
}

/** Triage config safe for the UI (no key); `inheritsFrom` tells if it uses the analyst's provider. */
export async function getTriagePublicConfig(): Promise<
  AiPublicConfig & { inheritsFrom: 'triage' | 'chat' } & TriageOperationalConfig
> {
  const s = await readAiSettings();
  const op = await getTriageOperationalConfig();
  return {
    ...publicView(resolveAiSettings(s).triage),
    inheritsFrom: s.ai_triage_provider ? 'triage' : 'chat',
    ...op,
  };
}

/** Persist triage provider/model/base_url/key plus the operational knobs, in one transaction. Empty provider reverts to inheriting chat. */
export async function saveTriageConfig(input: {
  provider?: AiProvider | '';
  model?: string;
  baseUrl?: string;
  apiKey?: string | null;
  enabled?: boolean;
  minSeverity?: string;
  dailyCap?: number;
  maxConcurrent?: number;
  dedupeHours?: number;
  maxToolCalls?: number;
  wallBudgetSeconds?: number;
}): Promise<void> {
  const extra: AiSettings = {};
  if (input.enabled !== undefined) extra.ai_triage_enabled = input.enabled ? 'true' : 'false';
  if (input.minSeverity !== undefined) extra.ai_triage_min_severity = input.minSeverity;
  if (input.dailyCap !== undefined) extra.ai_triage_daily_cap = String(input.dailyCap);
  if (input.maxConcurrent !== undefined)
    extra.ai_triage_max_concurrent = String(input.maxConcurrent);
  if (input.dedupeHours !== undefined) extra.ai_triage_dedupe_hours = String(input.dedupeHours);
  if (input.maxToolCalls !== undefined) extra.ai_triage_max_tool_calls = String(input.maxToolCalls);
  if (input.wallBudgetSeconds !== undefined)
    extra.ai_triage_wall_budget_seconds = String(input.wallBudgetSeconds);
  await saveAiScope('triage', input, extra);
}

// ---- LLM call (provider-specific) -------------------------------------------

/** A single chat completion: system + user -> text. Injectable for tests. */
export type Completer = (
  cfg: AiConfig,
  system: string,
  user: string,
  opts?: { json?: boolean; maxTokens?: number }
) => Promise<string>;

/**
 * Output-token budget for parser/detection generation. The 2000 default was too
 * low once we started seeding the builder with several sample lines: the model
 * emits one test_sample per distinct event, and dense content (UniFi/hex logs
 * tokenize heavily) overflowed 2000 tokens, truncating the JSON mid-array
 * ("Expected ',' or ']' after array element"). Generation is user-initiated and
 * infrequent, so a generous cap costs nothing until the output is actually big.
 */
const GENERATION_MAX_TOKENS = 8000;

/** A message in a multi-turn conversation. */
export type ChatMsg = { role: 'system' | 'user' | 'assistant'; content: string };

/** fetch with a hard timeout and a clear, actionable connection error. */
async function llmFetch(url: string, options: any): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 120_000);
  try {
    return await fetch(url, { ...options, signal: ctrl.signal });
  } catch (e: any) {
    if (e?.name === 'AbortError')
      throw new Error(`Request to ${url} timed out after 120s`, { cause: e });
    throw new Error(
      `Could not reach ${url} (${e?.message || e}). The Base URL must be reachable from the SIEMBox backend CONTAINER — ` +
        `for a local Ollama, bind it to 0.0.0.0 (OLLAMA_HOST=0.0.0.0:11434) and use the host LAN IP or http://host.docker.internal:11434.`,
      { cause: e }
    );
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Multi-turn completion across providers. `messages` is the full conversation
 * (may include a leading `system` message). JSON mode defaults on. `maxTokens`
 * bounds the response (defaults to 2000, preserving the single-turn behaviour).
 */
export async function callProviderChat(
  cfg: AiConfig,
  messages: ChatMsg[],
  opts: { json?: boolean; maxTokens?: number } = {}
): Promise<string> {
  const jsonMode = opts.json !== false;
  const maxTokens = opts.maxTokens ?? 2000;

  if (cfg.provider === 'anthropic') {
    if (!cfg.apiKey) throw new Error('No Anthropic API key configured');
    // Anthropic requires `system` separate from messages[] — hoist all system turns.
    const systemText = messages
      .filter((m) => m.role === 'system')
      .map((m) => m.content)
      .join('\n\n');
    // Anthropic requires messages to alternate user/assistant — merge any
    // consecutive same-role turns (e.g. a tool-result user turn following another).
    const convo: { role: 'user' | 'assistant'; content: string }[] = [];
    for (const m of messages) {
      if (m.role === 'system') continue;
      const last = convo[convo.length - 1];
      if (last && last.role === m.role) last.content += '\n\n' + m.content;
      else convo.push({ role: m.role as 'user' | 'assistant', content: m.content });
    }
    const res = await llmFetch(`${requestBaseUrl('anthropic')}/messages`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': cfg.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: cfg.model,
        max_tokens: maxTokens,
        ...(systemText ? { system: systemText } : {}),
        messages: convo.length ? convo : [{ role: 'user', content: '' }],
      }),
    });
    if (!res.ok) throw new Error(`Anthropic API ${res.status}: ${(await res.text()).slice(0, 300)}`);
    const json: any = await res.json();
    return (json.content || []).map((b: any) => b.text || '').join('');
  }

  if (cfg.provider === 'openai') {
    if (!cfg.apiKey) throw new Error('No OpenAI API key configured');
    const res = await llmFetch(`${requestBaseUrl('openai', cfg.baseUrl)}/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${cfg.apiKey}` },
      body: JSON.stringify({
        model: cfg.model,
        messages,
        max_tokens: maxTokens,
        ...(jsonMode ? { response_format: { type: 'json_object' } } : {}),
      }),
    });
    if (!res.ok) throw new Error(`OpenAI API ${res.status}: ${(await res.text()).slice(0, 300)}`);
    const json: any = await res.json();
    return json.choices?.[0]?.message?.content || '';
  }

  // ollama
  const res = await llmFetch(`${requestBaseUrl('ollama', cfg.baseUrl)}/api/chat`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: cfg.model,
      stream: false,
      ...(jsonMode ? { format: 'json' } : {}),
      // Only bound output when a caller explicitly asks (keeps existing callers' behaviour).
      ...(opts.maxTokens ? { options: { num_predict: opts.maxTokens } } : {}),
      messages,
    }),
  });
  if (!res.ok) throw new Error(`Ollama API ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const json: any = await res.json();
  return json.message?.content || '';
}

/** Single-turn wrapper (system + user) — preserves every existing caller. */
async function callProvider(
  cfg: AiConfig,
  system: string,
  user: string,
  opts: { json?: boolean; maxTokens?: number } = {}
): Promise<string> {
  return callProviderChat(
    cfg,
    [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
    opts
  );
}

// ---- Prompt + generation loop ------------------------------------------------

const SYSTEM_PROMPT = `You write SIEMBox log parsers as a single JSON object ("siembox.parser/v1"). Output ONLY the JSON object — no markdown, no prose.

A parser:
{
  "schema": "siembox.parser/v1",
  "name": "<kebab-case>",
  "description": "<what it parses>",
  "parser_type": "regex" | "json",
  "priority": <1-1000, lower runs first>,
  "pattern": "<for regex: a JS regex with NAMED groups (?<group>...); for json: \\"\\">",
  "field_mappings": { "<regex group OR json key (dotted paths ok for json: a.b[0])>": "<canonical field>" },
  "derivations": [ <optional, see below> ],
  "event_type": "<short tag>",
  "enabled": true,
  "test_samples": [ { "input": "<a REAL raw log line>", "expect": { "<canonical field>": "<value>" } } ],
  "metadata": { "author": "ai", "log_source": "<source>", "tags": ["..."] }
}

Map to CANONICAL fields wherever possible: source_ip, dest_ip, source_port, dest_port, user, target_user, host, service, method, path, status_code, message, event. The engine fills aliases (client_ip/src_ip -> source_ip) and mirrors source_ip<->client_ip, so usually set one. For regex parsers ALWAYS capture the actor IP into a group mapped to source_ip when present. If you do NOT map "message", the engine sets it to the full raw log line; map a group to "message" only to surface a cleaner human-readable message, and make its test_samples "expect" that exact captured text.

derivations (optional, applied after mapping; fill EMPTY fields unless "overwrite": true; first match wins):
- { "when": { "<field>": { "contains"|"equals"|"in"|"matches"|"exists": ... } }, "set": { "<field>": "<value>" } }   (contains/matches are case-insensitive)
- { "extract": { "<field>": { "from": "<field>", "pattern": "<regex with a capture group>", "group": 1 } } }
Use derivations to set an "event" marker (e.g. login_failure / login_success) from message text.

test_samples are MANDATORY and are run through the real engine: each "expect" must equal what the parser produces for that "input". Include one sample per distinct event. Use documentation IPs (203.0.113.x, 198.51.100.x). Make the regex actually match the provided sample.`;

function buildUserPrompt(sample: string, hints?: string, prev?: { parser: any; errors: string[] }): string {
  let u = `Log sample(s):\n${sample.trim()}\n`;
  if (hints) u += `\nHints from the user: ${hints}\n`;
  if (prev) {
    u += `\nYour previous attempt FAILED validation/self-tests with these errors:\n- ${prev.errors.join('\n- ')}\n`;
    u += `Previous attempt:\n${JSON.stringify(prev.parser)}\n\nFix it. Output the corrected JSON object only.`;
  } else {
    u += `\nWrite the parser JSON for this log source.`;
  }
  return u;
}

export function extractJson(text: string): any {
  let s = (text || '').trim();
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) s = fence[1].trim();
  const start = s.search(/[{[]/);
  if (start > 0) s = s.slice(start);
  // trim trailing prose after the last closing brace
  const end = s.lastIndexOf('}');
  if (end >= 0) s = s.slice(0, end + 1);
  try {
    return JSON.parse(s);
  } catch (e) {
    // A response cut off at the token limit leaves more open braces/brackets
    // than closes. Surface that as an actionable message instead of a cryptic
    // "Expected ',' or ']' at position N".
    const opens = (s.match(/[{[]/g) || []).length;
    const closes = (s.match(/[}\]]/g) || []).length;
    if (opens > closes) {
      throw new Error(
        'The AI response was cut off before it finished (the JSON is incomplete). ' +
          'This usually means the output hit the model token limit — try fewer or shorter ' +
          'sample lines, or a hint that narrows the parser, then regenerate.',
        { cause: e }
      );
    }
    throw e;
  }
}

export interface GenerateResult {
  ok: boolean;
  parser: PortableParser | null;
  validation: ValidationResult | null;
  self_test: SelfTestResult | null;
  /** ReDoS findings for the final attempt (empty = every regex proven safe). */
  redos?: RedosFinding[];
  attempts: number;
  error?: string;
}

/**
 * Generate a parser from a sample, validating + self-testing each attempt and
 * feeding failures back to the model up to `maxAttempts` times.
 */
export async function generateParser(
  input: { sample: string; hints?: string; maxAttempts?: number },
  complete: Completer = callProvider,
  cfgOverride?: AiConfig
): Promise<GenerateResult> {
  const cfg = cfgOverride ?? (await getAiConfig());
  const maxAttempts = Math.max(1, Math.min(input.maxAttempts ?? 3, 5));

  let prev: { parser: any; errors: string[] } | undefined;
  let last: GenerateResult = { ok: false, parser: null, validation: null, self_test: null, attempts: 0 };

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let parser: PortableParser;
    try {
      const text = await complete(cfg, SYSTEM_PROMPT, buildUserPrompt(input.sample, input.hints, prev), {
        maxTokens: GENERATION_MAX_TOKENS,
      });
      parser = extractJson(text);
    } catch (e) {
      return { ...last, attempts: attempt, error: e instanceof Error ? e.message : String(e) };
    }

    // STRICT validation + the ReDoS scan: the exact gate the catalog CI runs on
    // a contribution, so a generated parser that passes here also passes there.
    // (strict:false used to let AI output through with warnings-as-passes, then
    // fail the user's catalog PR.)
    const validation = validatePortableParser(parser, { strict: true });
    const self_test = validation.ok ? runSelfTests(parser as PortableParser) : null;
    const redos = validation.ok ? scanParserRedos(parser as PortableParser) : [];
    const redosVulnerable = redos.filter((f) => f.status === 'vulnerable');
    const ok = validation.ok && (self_test ? self_test.ok : true) && redosVulnerable.length === 0;
    last = { ok, parser, validation, self_test, redos, attempts: attempt };
    if (ok) return last;

    const errors = [
      ...validation.errors,
      ...(self_test?.failures || []).flatMap((f) =>
        f.matched
          ? f.mismatches.map((m) => `sample[${f.index}] ${m.field}: expected ${JSON.stringify(m.expected)}, got ${JSON.stringify(m.actual)}`)
          : [`sample[${f.index}] parser did not match the input`]
      ),
      ...redosVulnerable.map(
        (f) =>
          `regex at ${f.location} is ReDoS-vulnerable (${f.complexity || 'catastrophic backtracking'}): rewrite it to be linear — anchor segments, avoid adjacent \\s+/.* over the same text, give captures like (.+?) explicit non-overlapping boundaries, prefer bounded character classes`
      ),
    ];
    prev = { parser, errors };
  }
  return last;
}

// ---- Detection-rule generation ----------------------------------------------

const DETECTION_SYSTEM_PROMPT = `You write SIEMBox detection rules as a single JSON object. Output ONLY the JSON object — no markdown, no prose.

A rule:
{
  "name": "<short unique name>",
  "description": "<what it detects and why>",
  "severity": "low" | "medium" | "high" | "critical",
  "enabled": true,
  "tags": ["..."],
  "conditions": [ { "field": "<canonical field>", "operator": "<op>", "value": <string|number|array> } ],
  "aggregation": { "field": "<field>", "timeframe": "<N s|m|h|d, e.g. 5m>", "threshold": <N>, "distinct_count": "<field, optional>" },
  "alert": { "title": "<short, may use {field} placeholders>", "description": "<what to do; may use {field} and {count}>" }
}

Rules evaluate against NORMALIZED parsed-log fields. Use canonical field names: source_ip, dest_ip, source_port, dest_port, user, target_user, host, service, method, path, status_code, message, event, event_type, country, auth_outcome.

Supported operators ONLY: equals, not_equals, contains, not_contains, regex, greater_than, less_than, in, not_in, exists, not_in_whitelist, on_threat_feed, not_on_threat_feed.
- "in"/"not_in": value is a comma-separated string OR an array.
- "greater_than"/"less_than": numeric value.
- "regex": value is a valid regex.
- "exists": value true/false.
- "on_threat_feed"/"not_on_threat_feed": true when the field's IP IS / IS NOT in the enabled threat-intelligence blocklist feeds. Use on an IP field (usually source_ip) with value: true. Do NOT invent a "threat_intel_match" field — use this operator. alert.title/description may use {threat_feeds} to name the matching feed(s).
- "not_in_whitelist": true when the field's IP is NOT in the operator's IP allow-list. Use on an IP field with value: true.

"aggregation" is OPTIONAL — include it for rate/brute-force/repeat detections ("5 failures in 5m"): set field (usually source_ip), timeframe, threshold, and distinct_count when you mean "N DISTINCT values". Omit aggregation for single-event rules.

conditions are ANDed. Keep them satisfiable by real parser output (e.g. event="login_failure", service="sshd"). alert.title/description may interpolate {source_ip}, {user}, {count}, etc.`;

function buildDetectionUserPrompt(
  description: string,
  context?: string,
  prev?: { rule: any; errors: string[] }
): string {
  let u = `Detection to build: ${description.trim()}\n`;
  if (context) u += `\nContext (available fields / values / source):\n${context.trim()}\n`;
  if (prev) {
    u += `\nYour previous attempt FAILED validation with these errors:\n- ${prev.errors.join('\n- ')}\n`;
    u += `Previous attempt:\n${JSON.stringify(prev.rule)}\n\nFix it. Output the corrected JSON object only.`;
  } else {
    u += `\nWrite the detection rule JSON.`;
  }
  return u;
}

export interface GenerateRuleResult {
  ok: boolean;
  rule: PortableRule | null;
  validation: RuleValidationResult | null;
  attempts: number;
  error?: string;
}

/**
 * Generate a detection rule from a natural-language description (+ optional
 * context about available fields), validating each attempt against the engine
 * contract and feeding failures back to the model.
 */
export async function generateDetection(
  input: { description: string; context?: string; maxAttempts?: number },
  complete: Completer = callProvider,
  cfgOverride?: AiConfig
): Promise<GenerateRuleResult> {
  const cfg = cfgOverride ?? (await getAiConfig());
  const maxAttempts = Math.max(1, Math.min(input.maxAttempts ?? 3, 5));

  let prev: { rule: any; errors: string[] } | undefined;
  let last: GenerateRuleResult = { ok: false, rule: null, validation: null, attempts: 0 };

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let rule: PortableRule;
    try {
      const text = await complete(
        cfg,
        DETECTION_SYSTEM_PROMPT,
        buildDetectionUserPrompt(input.description, input.context, prev),
        { maxTokens: GENERATION_MAX_TOKENS }
      );
      rule = extractJson(text);
    } catch (e) {
      return { ...last, attempts: attempt, error: e instanceof Error ? e.message : String(e) };
    }

    const validation = validateRule(rule, { strict: false });
    last = { ok: validation.ok, rule, validation, attempts: attempt };
    if (validation.ok) return last;
    prev = { rule, errors: validation.errors };
  }
  return last;
}

// ---- "Explain this" assistant ------------------------------------------------

const EXPLAIN_SYSTEM_PROMPT = `You are a senior SOC analyst helping a SIEMBox operator understand a security artifact (an alert, vulnerability, incident, or log). Given the artifact — and an optional question — explain it clearly and concisely in GitHub-flavored Markdown for a technically literate but possibly junior analyst.

Cover, briefly:
- What it is / what happened, in plain language.
- Why it matters — severity, the likely cause, and whether it reads as malicious, benign, or needs more context.
- Concrete next steps to investigate or remediate.

Be specific to the data provided; do NOT invent fields, IPs, CVEs, or values that aren't present. If the data is insufficient to be sure, say so. Keep it tight — a few short sections or bullet lists. Output Markdown only, with no preamble like "Sure" or "Here is".`;

export interface ExplainInput {
  /** What the artifact is: 'alert' | 'vulnerability' | 'incident' | 'log' | ... */
  kind: string;
  /** The artifact itself — an object (stringified) or raw text. */
  data: unknown;
  /** Optional operator question to focus the explanation. */
  question?: string;
}

/**
 * Free-text "explain this" over any security artifact, reusing the configured
 * provider/key. Unlike the generators this asks for prose (json:false), runs a
 * single call (no validate/refine loop), and clips oversized artifacts so a huge
 * raw log can't blow the context window.
 */
export async function explain(
  input: ExplainInput,
  cfgOverride?: AiConfig
): Promise<{ explanation: string }> {
  const cfg = cfgOverride ?? (await getAiConfig());

  const dataStr =
    typeof input.data === 'string' ? input.data : JSON.stringify(input.data, null, 2);
  const clipped =
    dataStr.length > 8000 ? `${dataStr.slice(0, 8000)}\n…(truncated)` : dataStr;

  let user = `Artifact type: ${input.kind || 'unknown'}\n\nArtifact:\n${clipped}\n`;
  if (input.question && input.question.trim()) {
    user += `\nThe operator asks: ${input.question.trim()}\n`;
  }
  user += `\nExplain it.`;

  const explanation = await callProvider(cfg, EXPLAIN_SYSTEM_PROMPT, user, { json: false });
  return { explanation: (explanation || '').trim() };
}
