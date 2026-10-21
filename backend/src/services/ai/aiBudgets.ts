/**
 * AI budgets: how much each AI feature may write and how long it may work.
 *
 * Settings -> AI -> AI budgets (GET/PUT /api/settings/ai-budgets, admin only).
 * Stored as system_settings key/value rows like every other AI setting; a
 * feature with no row uses the code default below, so an install that never
 * changed a budget follows the defaults of the version it runs. A save stores
 * a value equal to its default as "no row" for the same reason (the form sends
 * every field). The triage lookup and time budgets are the rows the AI Triage
 * form always used (ai_triage_max_tool_calls, ai_triage_wall_budget_seconds),
 * so a value saved there is kept.
 *
 * Key names avoid the word "token": settingsRedaction.ts treats any key with a
 * credential-like word (key, token, secret...) as a secret.
 *
 * Time budgets and the request path: the AI Analyst answers inside one HTTP
 * request. Its worst case is the time budget (each working step's model call is
 * cut off at the budget's end) plus one final answer call (ANSWER_CALL_TIMEOUT_MS)
 * plus tool run time. MAX_ANALYST_WALL_SECONDS + 120 s = 360 s, under the 420 s
 * proxy_read_timeout in frontend/nginx.conf.template and the browser's analyst
 * call timeout (frontend/src/services/api.ts). Triage runs in the background
 * (no HTTP request), so its ceiling is the existing 280 s.
 */
import { query } from '../../config/database';

export interface AgentBudget {
  /** Output-token cap for the answer (analyst) / verdict (triage) synthesis call. */
  answerMaxTokens: number;
  /** Output-token cap for each JSON working step (a tool call, or a final answer given in JSON). */
  stepMaxTokens: number;
  /** Read-only data lookups (tool calls) per question / alert. */
  maxToolCalls: number;
  /** Seconds of gathering before the agent must answer with what it has. */
  wallBudgetSeconds: number;
}

export interface AiBudgets {
  analyst: AgentBudget;
  triage: AgentBudget;
  /** Parser / detection generation. */
  builder: { maxTokens: number };
  /** "Explain this" (Ask AI on an alert, vulnerability, log...). */
  explain: { maxTokens: number };
}

type Section = keyof AiBudgets;
interface FieldSpec {
  key: string;
  min: number;
  max: number;
  def: number;
  label: string;
}

/** The final model call after the time budget runs out (analyst answer / triage verdict). */
export const ANSWER_CALL_TIMEOUT_MS = 120_000;
export const MAX_ANALYST_WALL_SECONDS = 240;
export const MIN_OUTPUT_TOKENS = 256;
export const MAX_OUTPUT_TOKENS = 32_000;
const TOKENS = { min: MIN_OUTPUT_TOKENS, max: MAX_OUTPUT_TOKENS };

/** Every budget: its setting row, bounds and default. */
export const AI_BUDGET_FIELDS: { [S in Section]: { [F in keyof AiBudgets[S]]: FieldSpec } } = {
  analyst: {
    answerMaxTokens: { key: 'ai_chat_answer_max_output', ...TOKENS, def: 4000, label: 'AI Analyst answer length' },
    stepMaxTokens: { key: 'ai_chat_step_max_output', ...TOKENS, def: 1500, label: 'AI Analyst working-step length' },
    maxToolCalls: { key: 'ai_chat_max_tool_calls', min: 1, max: 25, def: 10, label: 'AI Analyst max data lookups' },
    wallBudgetSeconds: {
      key: 'ai_chat_wall_budget_seconds',
      min: 30,
      max: MAX_ANALYST_WALL_SECONDS,
      def: 180,
      label: 'AI Analyst time budget',
    },
  },
  triage: {
    answerMaxTokens: { key: 'ai_triage_answer_max_output', ...TOKENS, def: 3000, label: 'AI Triage verdict length' },
    stepMaxTokens: { key: 'ai_triage_step_max_output', ...TOKENS, def: 1500, label: 'AI Triage working-step length' },
    // Unattended and per alert, so these stay at their old defaults: raising
    // them multiplies cost by every analyzed alert. Admins can raise them.
    maxToolCalls: { key: 'ai_triage_max_tool_calls', min: 1, max: 25, def: 6, label: 'AI Triage max data lookups' },
    wallBudgetSeconds: { key: 'ai_triage_wall_budget_seconds', min: 20, max: 280, def: 110, label: 'AI Triage time budget' },
  },
  builder: {
    maxTokens: { key: 'ai_builder_max_output', ...TOKENS, def: 8000, label: 'AI builders output length' },
  },
  explain: {
    maxTokens: { key: 'ai_explain_max_output', ...TOKENS, def: 3000, label: 'Explain answer length' },
  },
};

const SECTIONS = Object.keys(AI_BUDGET_FIELDS) as Section[];

function eachField(fn: (section: Section, field: string, spec: FieldSpec) => void): void {
  for (const section of SECTIONS) {
    for (const [field, spec] of Object.entries(AI_BUDGET_FIELDS[section]) as [string, FieldSpec][]) {
      fn(section, field, spec);
    }
  }
}

/** Every budget's setting row. */
export const AI_BUDGET_SETTING_KEYS: string[] = [];
eachField((_s, _f, spec) => AI_BUDGET_SETTING_KEYS.push(spec.key));

/** The defaults, as an AiBudgets. */
export function defaultAiBudgets(): AiBudgets {
  const out: any = {};
  eachField((section, field, spec) => {
    (out[section] ||= {})[field] = spec.def;
  });
  return out as AiBudgets;
}

/** The bounds, for the settings page: { analyst: { answerMaxTokens: { min, max, default } } ... }. */
export function aiBudgetBounds(): Record<string, Record<string, { min: number; max: number; default: number }>> {
  const out: any = {};
  eachField((section, field, spec) => {
    (out[section] ||= {})[field] = { min: spec.min, max: spec.max, default: spec.def };
  });
  return out;
}

/**
 * Budgets from stored rows (pure). A missing, blank or non-numeric row is the
 * default; a number outside the bounds (a hand-edited row) is clamped into them.
 */
export function parseAiBudgets(rows: Record<string, string | null | undefined>): AiBudgets {
  const out = defaultAiBudgets() as any;
  eachField((section, field, spec) => {
    const raw = rows[spec.key];
    if (raw === undefined || raw === null || String(raw).trim() === '') return;
    const n = Math.floor(Number(raw));
    if (!Number.isFinite(n)) return;
    out[section][field] = Math.min(spec.max, Math.max(spec.min, n));
  });
  return out as AiBudgets;
}

/** A budget save the request got wrong (the route answers 400 with the message). */
export class AiBudgetValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AiBudgetValidationError';
  }
}

/**
 * Validate a (partial) PUT body: { analyst?: {...}, triage?: {...}, builder?: {...}, explain?: {...} }.
 * Returns the rows to write: key -> value, or key -> null to delete the row
 * (the value equals its default). Unknown sections or fields, and values that
 * are not whole numbers within the bounds, are refused.
 */
export function planAiBudgetSave(body: unknown): Record<string, string | null> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new AiBudgetValidationError('body must be an object of budget sections');
  }
  const writes: Record<string, string | null> = {};
  for (const [section, values] of Object.entries(body as Record<string, unknown>)) {
    const specs = (AI_BUDGET_FIELDS as any)[section] as Record<string, FieldSpec> | undefined;
    if (!specs) {
      throw new AiBudgetValidationError(`unknown budget section "${section}" (expected ${SECTIONS.join(', ')})`);
    }
    if (!values || typeof values !== 'object' || Array.isArray(values)) {
      throw new AiBudgetValidationError(`${section} must be an object`);
    }
    for (const [field, value] of Object.entries(values as Record<string, unknown>)) {
      const spec = specs[field];
      if (!spec) {
        throw new AiBudgetValidationError(
          `unknown field ${section}.${field} (expected ${Object.keys(specs).join(', ')})`
        );
      }
      if (typeof value !== 'number' || !Number.isInteger(value) || value < spec.min || value > spec.max) {
        throw new AiBudgetValidationError(
          `${section}.${field} (${spec.label}) must be a whole number between ${spec.min} and ${spec.max}`
        );
      }
      writes[spec.key] = value === spec.def ? null : String(value);
    }
  }
  return writes;
}

/** The current budgets (one statement). */
export async function getAiBudgets(): Promise<AiBudgets> {
  const r = await query('SELECT key, value FROM system_settings WHERE key = ANY($1)', [AI_BUDGET_SETTING_KEYS]);
  const rows: Record<string, string> = {};
  for (const row of r.rows) rows[row.key] = row.value ?? '';
  return parseAiBudgets(rows);
}

/** Validate and save a (partial) budgets body; throws AiBudgetValidationError on a bad one. */
export async function saveAiBudgets(body: unknown): Promise<void> {
  const writes = planAiBudgetSave(body);
  for (const [key, value] of Object.entries(writes)) {
    if (value === null) {
      await query('DELETE FROM system_settings WHERE key = $1', [key]);
    } else {
      await query(
        `INSERT INTO system_settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
        [key, value]
      );
    }
  }
}

/** The user-visible line for an answer cut off at an output-token cap. */
export function tokenLimitNote(limit: number, what: string, settingLabel: string): string {
  return `${what} hit the ${limit}-token output limit, so it may be cut off. An admin can raise "${settingLabel}" in Settings → AI → AI budgets.`;
}
