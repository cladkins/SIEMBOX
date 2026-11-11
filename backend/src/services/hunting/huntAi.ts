/**
 * The AI step of Threat Hunting: read a threat report and propose hunt
 * hypotheses (what the attacker did, as something to look for in our logs),
 * with the log search terms that test each one.
 *
 * Optional. It uses the AI Builder model (Settings -> AI); without one, or when
 * the call fails, a hunt keeps the indicators the regex extractor found and a
 * hypothesis built from the ATT&CK techniques the report names.
 *
 * The model's output is never trusted as is: indicators it names are kept
 * only when they pass the same validators the extractor uses AND appear in
 * the report's text, so a hallucinated IP is dropped. Search terms are
 * bounded in number and length.
 */
import { callProvider, extractJson, getAiConfig, type AiConfig, type Completer } from '../ai/aiService';
import { IOC_TYPES, IocType, normalizeIoc, refang } from './iocExtract';

const MAX_REPORT_CHARS = 40_000;
const MAX_HYPOTHESES = 8;
const MAX_TERMS = 8;
const MIN_TERM = 4;
const MAX_TERM = 200;
const AI_TIMEOUT_MS = 120_000;
const AI_MAX_TOKENS = 4000;

export interface AiHypothesis {
  title: string;
  description: string | null;
  attack_techniques: string[];
  search_terms: string[];
}

export interface AiExtraction {
  title: string | null;
  summary: string | null;
  hypotheses: AiHypothesis[];
  /** Indicators the model found (validated against the text). */
  indicators: Array<{ type: IocType; value: string; context: string | null }>;
  /** Values in the text the model says are references, not indicators (a vendor's own site, say). */
  not_indicators: string[];
}

const SYSTEM = `You are a threat hunter. You read a threat intelligence report and plan a hunt in a SIEM that stores raw log lines (syslog, web server, firewall, DNS, authentication, endpoint logs).

Output ONLY one JSON object, no markdown:
{
  "title": "<short title for the hunt>",
  "summary": "<2-4 sentences: who, what, how>",
  "hypotheses": [
    {
      "title": "<a testable hypothesis, e.g. 'An attacker used rundll32 to load a DLL from a temp folder'>",
      "description": "<why, from the report, and what a match would look like in logs>",
      "attack_techniques": ["T1218.011"],
      "search_terms": ["<literal strings that appear in a matching LOG LINE>"]
    }
  ],
  "indicators": [ { "type": "ipv4|ipv6|domain|url|email|md5|sha1|sha256|cve", "value": "<exactly as in the report, refanged>", "context": "<what it is>" } ],
  "not_indicators": [ "<values in the report that are NOT indicators: the vendor's own site, references, examples>" ]
}

Rules:
- search_terms are case-insensitive substrings matched against raw log lines. Use distinctive literals from the report: file names, process names with arguments, registry paths, user agents, URL paths, named pipes, service names, command fragments. NOT generic words ("error", "login", "admin", "http", "powershell" alone).
- At most ${MAX_HYPOTHESES} hypotheses, at most ${MAX_TERMS} search_terms each, each ${MIN_TERM}-${MAX_TERM} characters.
- Only list indicators that appear in the report. Never invent one.
- attack_techniques are MITRE ATT&CK IDs (T1059 or T1059.001) the hypothesis maps to.`;

export function aiConfigured(cfg: AiConfig): boolean {
  return cfg.provider === 'ollama' || !!cfg.apiKey;
}

function cleanTerms(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const t of raw) {
    const s = String(t ?? '').replace(/\s+/g, ' ').trim();
    if (s.length < MIN_TERM || s.length > MAX_TERM) continue;
    if (!out.some((o) => o.toLowerCase() === s.toLowerCase())) out.push(s);
    if (out.length >= MAX_TERMS) break;
  }
  return out;
}

function cleanTechniques(raw: unknown, isTechnique: (id: string) => boolean): string[] {
  if (!Array.isArray(raw)) return [];
  return [
    ...new Set(
      raw.map((t) => String(t ?? '').trim().toUpperCase()).filter((t) => /^T\d{4}(?:\.\d{3})?$/.test(t) && isTechnique(t))
    ),
  ];
}

/** Turn the model's JSON into a validated extraction. Exported for tests. */
export function sanitizeAiOutput(json: any, reportText: string, isTechnique: (id: string) => boolean): AiExtraction {
  const text = refang(reportText).toLowerCase();
  const str = (v: unknown, max: number) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);

  const hypotheses: AiHypothesis[] = [];
  for (const h of Array.isArray(json?.hypotheses) ? json.hypotheses : []) {
    const title = str(h?.title, 300);
    if (!title) continue;
    hypotheses.push({
      title,
      description: str(h?.description, 2000),
      attack_techniques: cleanTechniques(h?.attack_techniques, isTechnique),
      search_terms: cleanTerms(h?.search_terms),
    });
    if (hypotheses.length >= MAX_HYPOTHESES) break;
  }

  const indicators: AiExtraction['indicators'] = [];
  for (const i of Array.isArray(json?.indicators) ? json.indicators : []) {
    const type = String(i?.type ?? '').toLowerCase() as IocType;
    if (!IOC_TYPES.includes(type)) continue;
    const value = normalizeIoc(type, String(i?.value ?? ''));
    if (!value || !text.includes(value.toLowerCase())) continue;
    indicators.push({ type, value, context: str(i?.context, 500) });
  }

  const notIndicators = (Array.isArray(json?.not_indicators) ? json.not_indicators : [])
    .map((v: unknown) => refang(String(v ?? '')).trim().toLowerCase())
    .filter((v: string) => v && v.length <= 2048)
    .slice(0, 200);

  return {
    title: str(json?.title, 300),
    summary: str(json?.summary, 3000),
    hypotheses,
    indicators,
    not_indicators: notIndicators,
  };
}

/**
 * Ask the AI Builder model for hypotheses. Returns null when no model is
 * configured; throws when the call or its JSON fails (the caller records the
 * reason and carries on without AI).
 */
export async function aiExtract(
  reportTitle: string | null,
  reportText: string,
  isTechnique: (id: string) => boolean,
  deps: { config?: AiConfig; complete?: Completer } = {}
): Promise<AiExtraction | null> {
  const cfg = deps.config ?? (await getAiConfig());
  if (!aiConfigured(cfg)) return null;
  const complete = deps.complete ?? callProvider;
  const body = refang(reportText).slice(0, MAX_REPORT_CHARS);
  const user =
    (reportTitle ? `Report title: ${reportTitle}\n\n` : '') +
    `Report text${reportText.length > MAX_REPORT_CHARS ? ' (truncated)' : ''}:\n"""\n${body}\n"""`;
  const out = await complete(cfg, SYSTEM, user, { json: true, maxTokens: AI_MAX_TOKENS, timeoutMs: AI_TIMEOUT_MS });
  const textOut = typeof out === 'string' ? out : out.text;
  return sanitizeAiOutput(extractJson(textOut), reportText, isTechnique);
}
