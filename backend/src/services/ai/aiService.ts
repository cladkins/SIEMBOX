/**
 * AI parser builder — turn a raw log sample into a portable parser.
 *
 * Provider-agnostic (Anthropic / OpenAI / Ollama), bring-your-own-key. The model
 * proposes a `siembox.parser/v1` object; we run it through the SAME validator +
 * self-test loop the catalog/import use, feed any failures back to the model, and
 * return the best attempt. So the output is always checked against the real
 * engine, never trusted blind.
 */
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { CredentialEncryption } from '../credentials/credentialEncryption';
import {
  validatePortableParser,
  runSelfTests,
  PortableParser,
  ValidationResult,
  SelfTestResult,
} from '../parser/parserPortable';
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
async function setSetting(key: string, value: string): Promise<void> {
  await query(
    `INSERT INTO system_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
    [key, value]
  );
}

/** Resolve the API key: the stored (encrypted) key, else a provider env var. */
function envKeyFor(provider: AiProvider): string | undefined {
  if (provider === 'anthropic') return process.env.ANTHROPIC_API_KEY;
  if (provider === 'openai') return process.env.OPENAI_API_KEY;
  return undefined; // ollama needs none
}

/** Full config incl. the resolved API key — server-side use only. */
export async function getAiConfig(): Promise<AiConfig> {
  const provider = ((await getSetting('ai_provider')) as AiProvider) || 'anthropic';
  const model = (await getSetting('ai_model')) || DEFAULT_MODELS[provider] || '';
  const baseUrl = (await getSetting('ai_base_url')) || DEFAULT_BASE_URLS[provider];

  let apiKey: string | undefined;
  const stored = await getSetting('ai_api_key');
  if (stored) {
    try {
      const { encrypted, iv, authTag } = JSON.parse(stored);
      apiKey = CredentialEncryption.decrypt(encrypted, iv, authTag);
    } catch (e) {
      logger.warn('AI: stored api key could not be decrypted; falling back to env', {
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }
  if (!apiKey) apiKey = envKeyFor(provider);
  return { provider, model, baseUrl, apiKey };
}

/** Config safe to expose to the UI (no key, just whether one is configured). */
export async function getAiPublicConfig(): Promise<{
  provider: AiProvider;
  model: string;
  baseUrl?: string;
  configured: boolean;
  keySource: 'stored' | 'env' | 'none';
}> {
  const cfg = await getAiConfig();
  const hasStored = !!(await getSetting('ai_api_key'));
  const keySource = hasStored ? 'stored' : cfg.apiKey ? 'env' : 'none';
  return {
    provider: cfg.provider,
    model: cfg.model,
    baseUrl: cfg.baseUrl,
    configured: cfg.provider === 'ollama' ? true : !!cfg.apiKey,
    keySource,
  };
}

/** Persist provider/model/base_url; encrypt+store the key when provided. */
export async function saveAiConfig(input: {
  provider?: AiProvider;
  model?: string;
  baseUrl?: string;
  apiKey?: string | null;
}): Promise<void> {
  if (input.provider) await setSetting('ai_provider', input.provider);
  if (input.model !== undefined) await setSetting('ai_model', input.model);
  if (input.baseUrl !== undefined) await setSetting('ai_base_url', input.baseUrl);

  if (input.apiKey === null || input.apiKey === '') {
    await setSetting('ai_api_key', ''); // clear -> fall back to env
  } else if (typeof input.apiKey === 'string') {
    const enc = CredentialEncryption.encrypt(input.apiKey); // throws if CREDENTIAL_ENCRYPTION_KEY unset
    await setSetting('ai_api_key', JSON.stringify(enc));
  }
}

// ---- LLM call (provider-specific) -------------------------------------------

/** A single chat completion: system + user -> text. Injectable for tests. */
export type Completer = (cfg: AiConfig, system: string, user: string) => Promise<string>;

/** fetch with a hard timeout and a clear, actionable connection error. */
async function llmFetch(url: string, options: any): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 120_000);
  try {
    return await fetch(url, { ...options, signal: ctrl.signal });
  } catch (e: any) {
    if (e?.name === 'AbortError') throw new Error(`Request to ${url} timed out after 120s`);
    throw new Error(
      `Could not reach ${url} (${e?.message || e}). The Base URL must be reachable from the SIEMBox backend CONTAINER — ` +
        `for a local Ollama, bind it to 0.0.0.0 (OLLAMA_HOST=0.0.0.0:11434) and use the host LAN IP or http://host.docker.internal:11434.`
    );
  } finally {
    clearTimeout(timer);
  }
}

async function callProvider(
  cfg: AiConfig,
  system: string,
  user: string,
  opts: { json?: boolean } = {}
): Promise<string> {
  // The parser/detection generators need strict JSON; the "explain" assistant
  // wants free-text markdown. JSON mode defaults on to preserve generator behaviour.
  const jsonMode = opts.json !== false;
  if (cfg.provider === 'anthropic') {
    if (!cfg.apiKey) throw new Error('No Anthropic API key configured');
    const res = await llmFetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': cfg.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: cfg.model,
        max_tokens: 2000,
        system,
        messages: [{ role: 'user', content: user }],
      }),
    });
    if (!res.ok) throw new Error(`Anthropic API ${res.status}: ${(await res.text()).slice(0, 300)}`);
    const json: any = await res.json();
    return (json.content || []).map((b: any) => b.text || '').join('');
  }

  if (cfg.provider === 'openai') {
    if (!cfg.apiKey) throw new Error('No OpenAI API key configured');
    const base = cfg.baseUrl || DEFAULT_BASE_URLS.openai;
    const res = await llmFetch(`${base}/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${cfg.apiKey}` },
      body: JSON.stringify({
        model: cfg.model,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
        max_tokens: 2000,
        ...(jsonMode ? { response_format: { type: 'json_object' } } : {}),
      }),
    });
    if (!res.ok) throw new Error(`OpenAI API ${res.status}: ${(await res.text()).slice(0, 300)}`);
    const json: any = await res.json();
    return json.choices?.[0]?.message?.content || '';
  }

  // ollama
  const base = cfg.baseUrl || DEFAULT_BASE_URLS.ollama;
  const res = await llmFetch(`${base}/api/chat`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: cfg.model,
      stream: false,
      ...(jsonMode ? { format: 'json' } : {}),
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
    }),
  });
  if (!res.ok) throw new Error(`Ollama API ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const json: any = await res.json();
  return json.message?.content || '';
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

Map to CANONICAL fields wherever possible: source_ip, dest_ip, source_port, dest_port, user, target_user, host, service, method, path, status_code, message, event. The engine fills aliases (client_ip/src_ip -> source_ip) and mirrors source_ip<->client_ip, so usually set one. For regex parsers ALWAYS capture the actor IP into a group mapped to source_ip when present.

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

function extractJson(text: string): any {
  let s = (text || '').trim();
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) s = fence[1].trim();
  const start = s.search(/[{[]/);
  if (start > 0) s = s.slice(start);
  // trim trailing prose after the last closing brace
  const end = s.lastIndexOf('}');
  if (end >= 0) s = s.slice(0, end + 1);
  return JSON.parse(s);
}

export interface GenerateResult {
  ok: boolean;
  parser: PortableParser | null;
  validation: ValidationResult | null;
  self_test: SelfTestResult | null;
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
      const text = await complete(cfg, SYSTEM_PROMPT, buildUserPrompt(input.sample, input.hints, prev));
      parser = extractJson(text);
    } catch (e) {
      return { ...last, attempts: attempt, error: e instanceof Error ? e.message : String(e) };
    }

    const validation = validatePortableParser(parser, { strict: false });
    const self_test = validation.ok ? runSelfTests(parser as PortableParser) : null;
    const ok = validation.ok && (self_test ? self_test.ok : true);
    last = { ok, parser, validation, self_test, attempts: attempt };
    if (ok) return last;

    const errors = [
      ...validation.errors,
      ...(self_test?.failures || []).flatMap((f) =>
        f.matched
          ? f.mismatches.map((m) => `sample[${f.index}] ${m.field}: expected ${JSON.stringify(m.expected)}, got ${JSON.stringify(m.actual)}`)
          : [`sample[${f.index}] parser did not match the input`]
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

Supported operators ONLY: equals, not_equals, contains, not_contains, regex, greater_than, less_than, in, not_in, exists.
- "in"/"not_in": value is a comma-separated string OR an array.
- "greater_than"/"less_than": numeric value.
- "regex": value is a valid regex.
- "exists": value true/false.

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
        buildDetectionUserPrompt(input.description, input.context, prev)
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
