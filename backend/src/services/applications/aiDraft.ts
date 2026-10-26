/**
 * "Draft with AI" in the signature editor: the AI Builder's model (Settings
 * -> AI, the same provider and "Builder output length" budget as the parser
 * and detection builders) proposes a signature for Not identified values.
 * Every attempt goes through the same checks a save runs (checkSignature:
 * the validator, the regex safety gate, the tests against the whole set); a
 * failed first attempt is sent back once with its errors, and a second
 * failure is returned with them for the author to fix. Nothing is saved: the
 * draft opens in the editor.
 */
import { APP_CATEGORIES, APP_SCHEMA, MATCH_KINDS, OS_FAMILIES } from './appFormat';
import type { SignatureCheck } from './customSignatures';
import { asCompletion, extractJson, logOutputTruncated, type AiConfig, type Completer } from '../ai/aiService';

export const AI_DRAFT_MAX_ITEMS = 10;
export const AI_DRAFT_MAX_ATTEMPTS = 2;

export interface DraftItem {
  source: string;
  value: string;
  sample?: string | null;
  detail?: Record<string, unknown> | null;
}

export interface AiDraftResult {
  ok: boolean;
  signature: Record<string, unknown> | null;
  check: SignatureCheck | null;
  attempts: number;
  error?: string;
  truncated?: boolean;
}

export const AI_DRAFT_SYSTEM_PROMPT = `You write SIEMBox application signatures: a JSON object in the siembox.app/v1 format that tells SIEMBox which software some evidence (a log program name, a container image, an installed package, an nmap service, a user agent, a DNS domain) belongs to. Output ONLY the JSON object, no markdown, no prose.

{
  "schema": "${APP_SCHEMA}",
  "id": "<kebab-case id: a-z, 0-9, ->",
  "name": "<the product's name>",
  "vendor": "<who makes it; the project name for open source>",
  "category": "<one of: ${APP_CATEGORIES.join(', ')}>",
  "description": "<one sentence: what it is>",
  "website": "<https URL of the project, optional>",
  "cpe": { "vendor": "<NVD CPE vendor>", "product": "<NVD CPE product>" },   (optional; only when you are sure of the NVD names)
  "match": {
    "syslog_program": ["<program name, lower case; 'name/*' covers name/sub>"],
    "parser": ["<SIEMBox parser name>"],
    "service": { "names": ["<nmap service name, exact>"], "banner": ["<regex on nmap's product/version or banner; group 1 = version>"] },
    "container_image": ["<image name without tag, lower case; * matches anything, e.g. '*/linuxserver/sonarr'>"],
    "package": ["<package name, lower case, exact>"],
    "user_agent": ["<regex on the user agent; group 1 = version>"],
    "dns": ["<domain: 'example.com' covers it and every subdomain, '*.example.com' only subdomains>"],
    "os": { "family": "<${OS_FAMILIES.join('|')}>", "pretty_name": "<regex; group 1 = version>" }
  },
  "tests": [
    { "source": "<one of ${MATCH_KINDS.join(', ')}>", "input": "<a real value from the evidence>", "version": "<the version it must give, a string>" },
    { "source": "service", "input": { "name": "<service name>", "version": "<nmap version string>", "banner": "<banner>" } },
    { "source": "user_agent", "input": "curl/8.0", "match": false }
  ]
}

Rules:
- Use only the matcher kinds the evidence supports; leave the others out. Prefer exact names (syslog_program, package, container_image, service.names, dns) over regexes.
- Every matcher kind you use needs at least one matching test whose input is one of the given values or samples. Give "version" only when the input really carries one.
- Regexes are plain JavaScript regexes with no flags, at most ONE capture group (the version; use (?:...) for any other group), no named groups, no backreferences, and they must be linear: anchor them, use bounded tokens like (\\d+(?:\\.\\d+)*) for versions, never .* next to another part that can match the same text. They must not match the empty string.
- Do not claim generic values that would identify other software (a bare "http" service, "python-requests", "mozilla").
- The category must be one of the listed ones.`;

/** The user turn: the values (with samples), the author's hints, and the last attempt's errors. Pure. */
export function buildDraftPrompt(items: DraftItem[], hints?: string, prev?: { doc: unknown; errors: string[] }): string {
  const lines = items.slice(0, AI_DRAFT_MAX_ITEMS).map((it, i) => {
    const parts = [`${i + 1}. kind=${it.source} value=${JSON.stringify(it.value.slice(0, 300))}`];
    if (it.sample && it.sample !== it.value) parts.push(`sample=${JSON.stringify(it.sample.slice(0, 500))}`);
    if (it.detail && Object.keys(it.detail).length) parts.push(`detail=${JSON.stringify(it.detail).slice(0, 600)}`);
    return parts.join(' ');
  });
  let u = `Evidence no signature identifies yet (all of it is believed to be ONE application):\n${lines.join('\n')}\n`;
  if (hints && hints.trim()) u += `\nHints from the user: ${hints.trim().slice(0, 1000)}\n`;
  if (prev) {
    u += `\nYour previous attempt FAILED these checks:\n- ${prev.errors.slice(0, 20).join('\n- ')}\n`;
    u += `Previous attempt:\n${JSON.stringify(prev.doc).slice(0, 6000)}\n\nFix it. Output the corrected JSON object only.`;
  } else {
    u += '\nWrite the signature JSON.';
  }
  return u;
}

/**
 * Draft a signature for `items`. `check` runs the save's checks (it gates the
 * regexes before the tests run them); `complete` is the provider call
 * (injectable for tests).
 */
export async function draftSignatureWithAi(
  input: { items: DraftItem[]; hints?: string; maxTokens: number; deadlineMs?: number },
  deps: { cfg: AiConfig; complete: Completer; check: (doc: unknown) => Promise<SignatureCheck> }
): Promise<AiDraftResult> {
  const deadline = Date.now() + (input.deadlineMs ?? 300_000);
  let prev: { doc: unknown; errors: string[] } | undefined;
  let last: AiDraftResult = { ok: false, signature: null, check: null, attempts: 0 };
  for (let attempt = 1; attempt <= AI_DRAFT_MAX_ATTEMPTS; attempt++) {
    const left = deadline - Date.now();
    if (attempt > 1 && left < 15_000) return last;
    let doc: any;
    let out;
    try {
      out = asCompletion(await deps.complete(deps.cfg, AI_DRAFT_SYSTEM_PROMPT, buildDraftPrompt(input.items, input.hints, prev), { json: true, maxTokens: input.maxTokens, timeoutMs: left }));
      doc = extractJson(out.text);
    } catch (e) {
      if (out?.truncated) {
        logOutputTruncated('application signature builder', { limit: input.maxTokens, provider: deps.cfg.provider, model: deps.cfg.model });
        return {
          ...last,
          attempts: attempt,
          truncated: true,
          error: `The AI response hit the ${input.maxTokens}-token output limit before it finished. An admin can raise "Builder output length" in Settings → AI → AI budgets.`,
        };
      }
      return { ...last, attempts: attempt, error: e instanceof Error ? e.message : String(e) };
    }
    if (doc && typeof doc === 'object' && !Array.isArray(doc) && doc.schema === undefined) doc.schema = APP_SCHEMA;
    const check = await deps.check(doc);
    last = { ok: check.ok, signature: doc && typeof doc === 'object' ? doc : null, check, attempts: attempt };
    if (check.ok && check.contribute_errors.length === 0) return last;
    prev = { doc, errors: [...check.errors, ...check.contribute_errors] };
  }
  return last;
}
