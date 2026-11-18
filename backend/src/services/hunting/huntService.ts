/**
 * Threat Hunting: turn a threat report into a hunt and run it against the logs.
 *
 * A hunt's life:
 *   pending     created from a URL, pasted text or a monitored source
 *   extracting  fetching the report, extracting indicators (iocExtract.ts) and,
 *               when an AI model is configured, hypotheses (huntAi.ts)
 *   ready       indicators and hypotheses stored; nothing searched yet
 *   running     searching raw_logs for every enabled indicator and every
 *               enabled hypothesis's search terms
 *   completed   results stored; an alert raised if the hunt asks for one
 *   failed      `error` says why
 * An imported STIX bundle skips straight to ready.
 *
 * Work runs in the background on one in-process queue (one hunt at a time:
 * a hunt is a scan of the lookback window of raw_logs). Hunts the backend was
 * working on when it stopped are queued again at startup (recoverHunts).
 *
 * The search is one pass over raw_logs per batch of terms: the lookback window
 * (timestamp index) filtered by raw_message ILIKE ANY(...), under a statement
 * timeout. Each candidate line is then checked in JS with occursIn(), which
 * keeps 1.2.3.4 from matching 11.2.3.45. Up to MAX_SAMPLES_PER_TERM lines per
 * indicator or hypothesis are stored as threat_hunt_matches (a snapshot, since
 * retention later deletes raw logs).
 */
import { createHash, randomUUID } from 'crypto';
import pool, { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { envInt } from '../../utils/envInt';
import { ErrorLogService } from '../errors/errorLogService';
import { AlertModel } from '../../models/Alert';
import { getTechnique, techniqueDisplayName } from '../attack/attackData';
import { canonicalDomain, canonicalHost, canonicalIp, JUNK_USERS } from '../graph/entityKey';
import { extractIocs, IocType, IOC_TYPES, normalizeIoc, occursIn, siteDomain } from './iocExtract';
import { aiExtract, AiExtraction } from './huntAi';
import { documentKind, fetchDocument, htmlToText, LARGE_FETCH_MAX_BYTES, SourceFetchError } from './fetchSource';
import { isMispEvent, looksLikeMispFeedIndex, MAX_MISP_INDICATORS, parseMispEvent } from './misp';
import {
  huntBundle,
  huntStixObjects,
  hypothesisStixId,
  indicatorStixId,
  ImportedHunt,
  parseStixInput,
  StixImportError,
  StixBundle,
  StixHunt,
  StixObject,
} from './stix';

export const MIN_LOOKBACK_DAYS = 1;
export const MAX_LOOKBACK_DAYS = 90;
export const DEFAULT_LOOKBACK_DAYS = 14;
const MAX_SOURCE_TEXT = 1_000_000;
const MAX_TERMS_PER_QUERY = 100;
/** Most matching log lines one run reads (newest first). */
const MAX_ROWS = 20_000;
const INITIAL_SLICE_MS = 6 * 3_600_000;
const MIN_SLICE_MS = 15 * 60_000;
const MAX_SLICE_MS = 7 * 86_400_000;
const MAX_SAMPLES_PER_TERM = 25;
/** Devices one run stores (most lines first) and raises an alert for. */
const MAX_STORED_DEVICES = 500;
export const MAX_ALERT_DEVICES = 25;
const MAX_MESSAGE_CHARS = 2000;
export const MAX_HUNT_TERMS = 600;
/** The limit on one search statement (one time slice of one batch of terms). */
const HUNT_STATEMENT_TIMEOUT_MS = envInt('HUNT_STATEMENT_TIMEOUT_MS', 120_000, 1000);
/** The limit on one whole run; past it the run keeps what it found and says how far back it got. */
const HUNT_MAX_RUNTIME_MS = envInt('HUNT_MAX_RUNTIME_MS', 30 * 60_000, 60_000);

export type HuntStatus = 'pending' | 'extracting' | 'ready' | 'running' | 'completed' | 'failed';
export type HuntOrigin = 'url' | 'text' | 'stix' | 'misp' | 'source';

export interface HuntRow {
  id: number;
  stix_uuid: string;
  title: string;
  title_locked: boolean;
  origin: HuntOrigin;
  source_url: string | null;
  source_id: number | null;
  source_name?: string | null;
  status: HuntStatus;
  summary: string | null;
  extraction_method: string | null;
  extraction_note: string | null;
  lookback_days: number;
  alert_on_match: boolean;
  use_ai: boolean;
  error: string | null;
  match_count: number;
  logs_matched: number;
  devices_matched: number;
  results_truncated: boolean;
  search_complete: boolean;
  searched_from: Date | null;
  progress: string | null;
  last_run_at: Date | null;
  last_alert_id: number | null;
  created_by: number | null;
  created_at: Date;
  updated_at: Date;
  indicator_count?: number;
  hypothesis_count?: number;
}

export interface IndicatorRow {
  id: number;
  hunt_id: number;
  stix_id: string;
  ioc_type: IocType;
  value: string;
  context: string | null;
  found_by: string;
  enabled: boolean;
  match_count: number;
  first_seen: Date | null;
  last_seen: Date | null;
  created_at: Date;
}

export interface HypothesisRow {
  id: number;
  hunt_id: number;
  stix_id: string;
  title: string;
  description: string | null;
  attack_techniques: string[];
  search_terms: string[];
  found_by: string;
  enabled: boolean;
  match_count: number;
  first_seen: Date | null;
  last_seen: Date | null;
  created_at: Date;
}

export class HuntError extends Error {
  constructor(
    readonly status: number,
    message: string
  ) {
    super(message);
    this.name = 'HuntError';
  }
}

export function clampLookback(raw: unknown, fallback = DEFAULT_LOOKBACK_DAYS): number {
  const n = parseInt(String(raw ?? ''), 10);
  if (Number.isNaN(n)) return fallback;
  return Math.min(Math.max(n, MIN_LOOKBACK_DAYS), MAX_LOOKBACK_DAYS);
}

const isTechnique = (id: string) => !!getTechnique(id);

// ---- Queue -----------------------------------------------------------------------

type Task = { huntId: number; kind: 'extract' | 'run' };
const queue: Task[] = [];
let working = false;
let stopped = false;
/** The hunt the queue is working on now, if any. */
let current: number | null = null;

/** Hunts waiting or in progress, for the UI. */
export function huntQueueDepth(): number {
  return queue.length + (working ? 1 : 0);
}

/**
 * Each queued hunt's place: 0 for the one being worked on, 1 for the next,
 * and so on. Hunts run one at a time, so a hunt from a monitored source can
 * wait behind others; the UI shows this instead of a bare "pending".
 */
export function huntQueuePositions(): Map<number, number> {
  const positions = new Map<number, number>();
  if (current !== null) positions.set(current, 0);
  for (const task of queue) if (!positions.has(task.huntId)) positions.set(task.huntId, positions.size + (current === null ? 1 : 0));
  return positions;
}

function enqueue(task: Task): void {
  if (stopped) return;
  if (queue.some((t) => t.huntId === task.huntId && t.kind === task.kind)) return;
  queue.push(task);
  void drain();
}

async function drain(): Promise<void> {
  if (working) return;
  working = true;
  try {
    while (queue.length && !stopped) {
      const task = queue.shift()!;
      current = task.huntId;
      try {
        if (task.kind === 'extract') await extractHunt(task.huntId);
        else await runHunt(task.huntId);
      } catch (err) {
        const message = (err as Error)?.message || String(err);
        logger.warn(`[Hunt] hunt ${task.huntId} ${task.kind} failed: ${message}`);
        await query(
          `UPDATE threat_hunts SET status = 'failed', error = $2, progress = NULL, updated_at = NOW() WHERE id = $1`,
          [task.huntId, message.slice(0, 1000)]
        ).catch(() => undefined);
        ErrorLogService.logBackgroundError('threat-hunt', `hunt ${task.huntId}: ${message}`, {
          dedupeKey: `hunt-${task.kind}`,
        });
      }
    }
  } finally {
    working = false;
    current = null;
  }
}

/** Startup: queue again what the last process left unfinished. */
export async function recoverHunts(): Promise<void> {
  stopped = false;
  const r = await query(
    `SELECT id, status FROM threat_hunts WHERE status IN ('pending', 'extracting', 'running') ORDER BY id`
  );
  for (const row of r.rows) enqueue({ huntId: row.id, kind: row.status === 'running' ? 'run' : 'extract' });
  if (r.rows.length) logger.info(`[Hunt] resumed ${r.rows.length} unfinished hunt(s)`);
}

export function stopHuntQueue(): void {
  stopped = true;
  queue.length = 0;
}

// ---- Creating hunts ----------------------------------------------------------------

export interface CreateHuntInput {
  origin: Exclude<HuntOrigin, 'stix'>;
  url?: string | null;
  text?: string | null;
  title?: string | null;
  lookbackDays?: number;
  alertOnMatch?: boolean;
  useAi?: boolean;
  sourceId?: number | null;
  createdBy?: number | null;
}

export async function createHunt(input: CreateHuntInput): Promise<HuntRow> {
  const r = await query(
    `INSERT INTO threat_hunts
       (stix_uuid, title, title_locked, origin, source_url, source_id, status, source_text, lookback_days, alert_on_match, use_ai, created_by)
     VALUES ($1, $2, $11, $3, $4, $5, 'pending', $6, $7, $8, $9, $10)
     RETURNING id`,
    [
      randomUUID(),
      (input.title || input.url || 'Untitled hunt').slice(0, 500),
      input.origin,
      input.url ?? null,
      input.sourceId ?? null,
      input.text ? input.text.slice(0, MAX_SOURCE_TEXT) : null,
      clampLookback(input.lookbackDays),
      input.alertOnMatch ?? false,
      input.useAi ?? true,
      input.createdBy ?? null,
      // A title the user typed is kept; otherwise extraction names the hunt.
      !!input.title,
    ]
  );
  const hunt = (await getHuntRow(r.rows[0].id)) as HuntRow;
  enqueue({ huntId: hunt.id, kind: 'extract' });
  return hunt;
}

/** A structured document (STIX bundle or MISP event) as a hunt, with how it was read. */
export function parseStructured(input: unknown): { parsed: ImportedHunt; method: 'stix' | 'misp'; note: string } {
  if (isMispEvent(input)) {
    const parsed = parseMispEvent(input);
    const notes = [`Read ${parsed.stats.objects} MISP attribute(s)`];
    if (parsed.stats.all_attributes) {
      notes.push('the event marks none for detection (to_ids), so every huntable attribute was used');
    }
    if (parsed.stats.truncated) {
      notes.push(`${parsed.stats.truncated} indicator(s) past the ${MAX_MISP_INDICATORS} limit were left out`);
    }
    return { parsed, method: 'misp', note: notes.join('; ') };
  }
  const parsed = parseStixInput(input);
  return {
    parsed,
    method: 'stix',
    note:
      `Read ${parsed.stats.objects} STIX object(s)` +
      (parsed.stats.skipped_patterns
        ? `; ${parsed.stats.skipped_patterns} indicator pattern(s) were not simple values and were skipped`
        : ''),
  };
}

export async function importStixHunt(
  input: unknown,
  opts: { lookbackDays?: number; alertOnMatch?: boolean; createdBy?: number | null; run?: boolean }
): Promise<HuntRow> {
  let structured: ReturnType<typeof parseStructured>;
  try {
    structured = parseStructured(input);
  } catch (err) {
    if (err instanceof StixImportError) {
      throw new StixImportError('Expected a STIX bundle (a JSON object with an "objects" array) or a MISP event (a JSON object with an "Event").');
    }
    throw err;
  }
  const { parsed, method, note } = structured;
  if (!parsed.indicators.length && !parsed.hypotheses.length) {
    throw new HuntError(400, `The ${method === 'misp' ? 'MISP event' : 'bundle'} holds nothing SIEMBox can hunt for.`);
  }
  const client = await pool.connect();
  let hunt: HuntRow;
  try {
    await client.query('BEGIN');
    const r = await client.query(
      `INSERT INTO threat_hunts
         (stix_uuid, title, origin, source_url, status, summary, extraction_method, extraction_note,
          lookback_days, alert_on_match, use_ai, created_by)
       VALUES ($1, $2, $9, $3, 'ready', $4, $9, $5, $6, $7, false, $8)
       RETURNING id`,
      [
        randomUUID(),
        parsed.title.slice(0, 500),
        parsed.source_url,
        parsed.summary,
        note,
        clampLookback(opts.lookbackDays),
        opts.alertOnMatch ?? false,
        opts.createdBy ?? null,
        method,
      ]
    );
    hunt = r.rows[0];
    for (const ind of parsed.indicators) {
      await client.query(
        `INSERT INTO threat_hunt_indicators (hunt_id, stix_id, ioc_type, value, context, found_by)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (hunt_id, ioc_type, value) DO NOTHING`,
        [hunt.id, ind.stix_id, ind.type, ind.value, ind.context, method]
      );
    }
    for (const h of parsed.hypotheses) {
      await client.query(
        `INSERT INTO threat_hunt_hypotheses (hunt_id, stix_id, title, description, attack_techniques, search_terms, found_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [hunt.id, h.stix_id, h.title, h.description, h.attack_techniques, h.search_terms.slice(0, 20), method]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
  if (opts.run !== false) enqueue({ huntId: hunt.id, kind: 'run' });
  return (await getHuntRow(hunt.id)) as HuntRow;
}

/** Queue a fresh extraction (re-fetch the URL, re-read the text) and a run. */
export async function reextractHunt(id: number): Promise<void> {
  const hunt = await getHuntRow(id);
  if (!hunt) throw new HuntError(404, 'Hunt not found');
  if (hunt.origin === 'stix' || hunt.origin === 'misp') {
    throw new HuntError(400, 'An imported file has no report to re-read.');
  }
  if (hunt.status === 'extracting' || hunt.status === 'running') throw new HuntError(409, 'The hunt is busy.');
  await query(`UPDATE threat_hunts SET status = 'pending', error = NULL, updated_at = NOW() WHERE id = $1`, [id]);
  enqueue({ huntId: id, kind: 'extract' });
}

export async function queueRun(id: number): Promise<void> {
  const hunt = await getHuntRow(id);
  if (!hunt) throw new HuntError(404, 'Hunt not found');
  if (hunt.status === 'pending' || hunt.status === 'extracting') {
    throw new HuntError(409, 'The hunt is still reading its report.');
  }
  if (hunt.status === 'running') throw new HuntError(409, 'The hunt is already running.');
  await query(`UPDATE threat_hunts SET status = 'running', error = NULL, updated_at = NOW() WHERE id = $1`, [id]);
  enqueue({ huntId: id, kind: 'run' });
}

// ---- Extraction -------------------------------------------------------------------

interface ReportText {
  title: string | null;
  text: string;
  url: string | null;
}

async function readReport(hunt: HuntRow & { source_text: string | null }): Promise<ReportText | { structured: unknown }> {
  if (hunt.origin === 'text' || !hunt.source_url) {
    return { title: null, text: hunt.source_text || '', url: null };
  }
  try {
    const doc = await fetchDocument(hunt.source_url, undefined, { maxBytes: LARGE_FETCH_MAX_BYTES });
    const kind = documentKind(doc);
    if (kind === 'stix' || kind === 'misp-event') return { structured: JSON.parse(doc.body) };
    if (kind === 'misp-manifest' || (kind === 'html' && looksLikeMispFeedIndex(doc.body))) {
      throw new SourceFetchError(
        'This URL is a MISP feed. Add it under Monitored sources (kind MISP feed) so each event becomes a hunt, or hunt one event file (<uuid>.json).'
      );
    }
    if (kind === 'feed') {
      throw new SourceFetchError('This URL is an RSS/Atom feed. Add it under Sources so each new article becomes a hunt.');
    }
    if (kind === 'html') {
      const page = htmlToText(doc.body);
      return { title: page.title, text: page.text, url: doc.url };
    }
    return { title: null, text: doc.body, url: doc.url };
  } catch (err) {
    // A feed item whose page can't be fetched still has the feed's own copy.
    if (hunt.source_text && !(err instanceof SourceFetchError && /RSS\/Atom|MISP feed/.test(err.message))) {
      return { title: null, text: hunt.source_text, url: hunt.source_url };
    }
    throw err;
  }
}

async function extractHunt(id: number): Promise<void> {
  const r = await query(`SELECT * FROM threat_hunts WHERE id = $1`, [id]);
  const hunt = r.rows[0] as (HuntRow & { source_text: string | null }) | undefined;
  if (!hunt) return;
  await query(`UPDATE threat_hunts SET status = 'extracting', error = NULL, updated_at = NOW() WHERE id = $1`, [id]);

  const report = await readReport(hunt);
  if ('structured' in report) {
    const { parsed, method, note } = parseStructured(report.structured);
    await storeExtraction(hunt, {
      title: hunt.title_locked ? hunt.title : parsed.title,
      summary: parsed.summary,
      text: null,
      method,
      note: `${note} from the URL`,
      indicators: parsed.indicators.map((i) => ({ ...i, found_by: method, enabled: true })),
      hypotheses: parsed.hypotheses.map((h) => ({ ...h, found_by: method })),
    });
    enqueue({ huntId: id, kind: 'run' });
    return;
  }

  if (report.text.trim().length < 20) throw new HuntError(422, 'The report has no readable text.');

  let referenceDomains: string[] = [];
  if (report.url) {
    try {
      referenceDomains = [siteDomain(new URL(report.url).hostname)];
    } catch {
      /* no URL host to skip */
    }
  }
  const found = extractIocs(report.text, { referenceDomains, isTechnique });

  let ai: AiExtraction | null = null;
  let note: string | null = null;
  if (hunt.use_ai) {
    try {
      ai = await aiExtract(report.title, report.text, isTechnique);
      if (!ai) note = 'No AI model is configured (Settings → AI), so hypotheses come from the ATT&CK techniques the report names.';
    } catch (err) {
      note = `The AI step failed (${((err as Error).message || '').slice(0, 300)}); indicators come from pattern matching only.`;
    }
  }

  const notIoc = new Set(ai?.not_indicators ?? []);
  const indicators = new Map<string, { stix_id: string; type: IocType; value: string; context: string | null; found_by: string; enabled: boolean }>();
  for (const i of found.indicators) {
    indicators.set(`${i.type}:${i.value}`, {
      stix_id: indicatorStixId(hunt.stix_uuid, i.type, i.value),
      type: i.type,
      value: i.value,
      context: i.context,
      found_by: 'regex',
      enabled: !notIoc.has(i.value.toLowerCase()),
    });
  }
  for (const i of ai?.indicators ?? []) {
    const key = `${i.type}:${i.value}`;
    const prior = indicators.get(key);
    if (prior) {
      prior.found_by = 'ai';
      prior.enabled = true;
      if (i.context) prior.context = i.context;
    } else {
      indicators.set(key, {
        stix_id: indicatorStixId(hunt.stix_uuid, i.type, i.value),
        type: i.type,
        value: i.value,
        context: i.context,
        found_by: 'ai',
        enabled: true,
      });
    }
  }

  let hypotheses: Array<{ stix_id: string; title: string; description: string | null; attack_techniques: string[]; search_terms: string[]; found_by: string }>;
  if (ai && ai.hypotheses.length) {
    hypotheses = ai.hypotheses.map((h) => ({ ...h, stix_id: hypothesisStixId(hunt.stix_uuid, h.title), found_by: 'ai' }));
  } else if (found.techniques.length) {
    const title = `Techniques from this report are in use here (${found.techniques.slice(0, 5).join(', ')}${found.techniques.length > 5 ? ', …' : ''})`;
    hypotheses = [
      {
        stix_id: hypothesisStixId(hunt.stix_uuid, title),
        title,
        description:
          'The report names these ATT&CK techniques. Add log search terms (process names, file paths, command fragments from the report) to test for them.',
        attack_techniques: found.techniques,
        search_terms: [],
        found_by: 'regex',
      },
    ];
  } else {
    hypotheses = [];
  }

  await storeExtraction(hunt, {
    title: hunt.title_locked ? hunt.title : ai?.title || report.title || titleFromText(report.text) || hunt.title,
    summary: ai?.summary ?? null,
    text: report.text,
    method: ai ? 'ai' : 'regex',
    note,
    indicators: [...indicators.values()],
    hypotheses,
  });
  enqueue({ huntId: id, kind: 'run' });
}

/** A hunt name from the report's first line, for pasted text without a title. */
function titleFromText(text: string): string | null {
  const line = text.split(/\r?\n/).map((l) => l.trim()).find((l) => l.length >= 8);
  if (!line) return null;
  return line.length > 90 ? `${line.slice(0, 87).replace(/\s+\S*$/, '')}…` : line;
}

async function storeExtraction(
  hunt: HuntRow,
  x: {
    title: string;
    summary: string | null;
    text: string | null;
    method: string;
    note: string | null;
    indicators: Array<{ stix_id: string; type: IocType; value: string; context: string | null; found_by: string; enabled: boolean }>;
    hypotheses: Array<{ stix_id: string; title: string; description: string | null; attack_techniques: string[]; search_terms: string[]; found_by: string }>;
  }
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // A re-extraction keeps what the analyst switched off.
    const off = await client.query(
      `SELECT ioc_type, value FROM threat_hunt_indicators WHERE hunt_id = $1 AND enabled = false`,
      [hunt.id]
    );
    const disabled = new Set(off.rows.map((r) => `${r.ioc_type}:${r.value}`));
    await client.query(`DELETE FROM threat_hunt_matches WHERE hunt_id = $1`, [hunt.id]);
    await client.query(`DELETE FROM threat_hunt_devices WHERE hunt_id = $1`, [hunt.id]);
    await client.query(`DELETE FROM threat_hunt_indicators WHERE hunt_id = $1 AND found_by <> 'user'`, [hunt.id]);
    await client.query(`DELETE FROM threat_hunt_hypotheses WHERE hunt_id = $1 AND found_by <> 'user'`, [hunt.id]);
    // Hypotheses the analyst wrote or edited are kept; an extracted one with the same title is not added again.
    const kept = await client.query(`SELECT lower(title) AS t FROM threat_hunt_hypotheses WHERE hunt_id = $1`, [hunt.id]);
    const keptTitles = new Set(kept.rows.map((r) => r.t as string));
    for (const i of x.indicators) {
      await client.query(
        `INSERT INTO threat_hunt_indicators (hunt_id, stix_id, ioc_type, value, context, found_by, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (hunt_id, ioc_type, value) DO NOTHING`,
        [hunt.id, i.stix_id, i.type, i.value, i.context, i.found_by, i.enabled && !disabled.has(`${i.type}:${i.value}`)]
      );
    }
    for (const h of x.hypotheses) {
      if (keptTitles.has(h.title.slice(0, 500).toLowerCase())) continue;
      await client.query(
        `INSERT INTO threat_hunt_hypotheses (hunt_id, stix_id, title, description, attack_techniques, search_terms, found_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [hunt.id, h.stix_id, h.title.slice(0, 500), h.description, h.attack_techniques, h.search_terms, h.found_by]
      );
    }
    await client.query(
      `UPDATE threat_hunts
          SET title = $2, summary = $3, source_text = COALESCE($4, source_text), extraction_method = $5,
              extraction_note = $6, status = 'ready', error = NULL, match_count = 0, logs_matched = 0, devices_matched = 0,
              results_truncated = false, updated_at = NOW()
        WHERE id = $1`,
      [hunt.id, x.title.slice(0, 500), x.summary, x.text ? x.text.slice(0, MAX_SOURCE_TEXT) : null, x.method, x.note]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
  logger.info(`[Hunt] hunt ${hunt.id}: ${x.indicators.length} indicator(s), ${x.hypotheses.length} hypothesis(es) via ${x.method}`);
}

// ---- Running a hunt ---------------------------------------------------------------

interface Term {
  needle: string;
  kind: IocType | 'keyword';
  indicatorId?: number;
  hypothesisId?: number;
}

interface LogRow {
  id: number;
  timestamp: Date;
  source_ip: string | null;
  hostname: string | null;
  app_name: string | null;
  raw_message: string;
}

export function escapeLike(s: string): string {
  return s.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/** Every term a hunt searches for. Exported for tests. */
export function huntTerms(indicators: IndicatorRow[], hypotheses: HypothesisRow[]): Term[] {
  const terms: Term[] = [];
  for (const i of indicators) {
    if (!i.enabled) continue;
    terms.push({ needle: i.value.toLowerCase(), kind: i.ioc_type, indicatorId: i.id });
  }
  for (const h of hypotheses) {
    if (!h.enabled) continue;
    for (const t of h.search_terms || []) {
      const needle = t.trim().toLowerCase();
      if (needle.length >= 3) terms.push({ needle, kind: 'keyword', hypothesisId: h.id });
    }
  }
  return terms.slice(0, MAX_HUNT_TERMS);
}

export interface SearchResult {
  rows: LogRow[];
  /** The newest MAX_ROWS lines matched, so older ones were not read. */
  truncated: boolean;
  /** The whole window was searched. */
  complete: boolean;
  /** The oldest log time the search covered. */
  searchedFrom: Date;
}

/** The SQL condition and parameters that match one batch of terms (lower-case needles). */
export function matchCondition(needles: string[], firstParam: number): { sql: string; params: unknown[] } {
  return {
    sql: `lower(raw_message) LIKE ANY($${firstParam}::text[])`,
    params: [needles.map((n) => `%${escapeLike(n)}%`)],
  };
}

/** Is this error a statement timeout? */
const isTimeout = (err: unknown) => (err as { code?: string })?.code === '57014';

/**
 * Search raw_logs for the needles over the lookback window, in time slices,
 * newest first. Each slice is one statement per batch of terms under
 * HUNT_STATEMENT_TIMEOUT_MS, so a busy SIEM's window never has to fit in one
 * statement: a slice that times out is split (down to MIN_SLICE_MS) and
 * retried, and a fast one lets the next slice grow (up to MAX_SLICE_MS). The
 * whole search stops at HUNT_MAX_RUNTIME_MS or after MAX_ROWS matching lines,
 * and says how far back it got.
 */
export async function searchLogs(
  needles: string[],
  lookbackDays: number,
  onProgress: (searchedMs: number, windowMs: number) => Promise<void> = async () => undefined,
  limits: { statementTimeoutMs?: number; maxRuntimeMs?: number; initialSliceMs?: number } = {}
): Promise<SearchResult> {
  const statementTimeoutMs = limits.statementTimeoutMs ?? HUNT_STATEMENT_TIMEOUT_MS;
  const byId = new Map<number, LogRow>();
  const windowEnd = Date.now();
  const windowMs = lookbackDays * 86_400_000;
  const windowStart = windowEnd - windowMs;
  const deadline = Date.now() + (limits.maxRuntimeMs ?? HUNT_MAX_RUNTIME_MS);
  const batches: string[][] = [];
  for (let i = 0; i < needles.length; i += MAX_TERMS_PER_QUERY) batches.push(needles.slice(i, i + MAX_TERMS_PER_QUERY));

  let sliceEnd = windowEnd;
  let sliceMs = limits.initialSliceMs ?? INITIAL_SLICE_MS;
  while (sliceEnd > windowStart) {
    if (Date.now() > deadline) {
      return { rows: [...byId.values()], truncated: false, complete: false, searchedFrom: new Date(sliceEnd) };
    }
    const sliceStart = Math.max(windowStart, sliceEnd - sliceMs);
    const started = Date.now();
    const found: LogRow[] = [];
    try {
      for (const batch of batches) {
        const cond = matchCondition(batch, 4);
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          await client.query("SELECT set_config('statement_timeout', $1, true), set_config('jit', 'off', true)", [
            String(statementTimeoutMs),
          ]);
          const r = await client.query(
            `SELECT id, timestamp, source_ip, hostname, app_name, raw_message
               FROM raw_logs
              WHERE timestamp >= $1 AND timestamp < $2
                AND ${cond.sql}
              ORDER BY timestamp DESC
              LIMIT $3`,
            [new Date(sliceStart), new Date(sliceEnd), MAX_ROWS - byId.size, ...cond.params]
          );
          await client.query('COMMIT');
          found.push(...r.rows);
        } catch (err) {
          await client.query('ROLLBACK').catch(() => undefined);
          throw err;
        } finally {
          client.release();
        }
      }
    } catch (err) {
      if (!isTimeout(err)) throw err;
      if (sliceMs <= MIN_SLICE_MS) {
        throw new HuntError(
          504,
          `Searching even ${Math.round(MIN_SLICE_MS / 60_000)} minutes of logs took longer than ` +
            `${Math.round(statementTimeoutMs / 1000)} s. Switch off short or common search terms, ` +
            'or raise HUNT_STATEMENT_TIMEOUT_MS.'
        );
      }
      sliceMs = Math.max(MIN_SLICE_MS, Math.floor(sliceMs / 4));
      continue;
    }
    for (const row of found) byId.set(Number(row.id), row);
    if (byId.size >= MAX_ROWS) {
      return { rows: [...byId.values()], truncated: true, complete: false, searchedFrom: new Date(sliceStart) };
    }
    sliceEnd = sliceStart;
    await onProgress(windowEnd - sliceEnd, windowMs);
    if (Date.now() - started < statementTimeoutMs / 4) sliceMs = Math.min(MAX_SLICE_MS, sliceMs * 2);
  }
  return { rows: [...byId.values()], truncated: false, complete: true, searchedFrom: new Date(windowStart) };
}

interface TermHits {
  /** The matching log lines' ids. */
  lineIds: Set<number>;
  count: number;
  first: Date | null;
  last: Date | null;
  samples: LogRow[];
}

/** Where matching lines were seen: one device (the syslog header host, else the sender IP). */
export interface DeviceHits {
  /** The Context Graph key: a host key, else an IP key, else UNKNOWN_DEVICE. */
  device: string;
  /** Which graph node the key names. */
  deviceType: 'host' | 'ip' | null;
  hostname: string | null;
  sourceIp: string | null;
  appNames: Set<string>;
  lineIds: Set<number>;
  first: Date | null;
  last: Date | null;
  /** The newest matching line. */
  lastRawLogId: number | null;
  /** Indicator id → lines on this device. */
  indicators: Map<number, number>;
  /** Hypothesis id → lines on this device (each line once). */
  hypotheses: Map<number, number>;
}

export const UNKNOWN_DEVICE = '(unknown)';

/** A log's device, keyed as the Context Graph keys its host and ip nodes. Exported for tests. */
export function deviceOf(hostname: string | null, sourceIp: string | null): { device: string; deviceType: 'host' | 'ip' | null } {
  const host = canonicalHost(hostname);
  if (host && !JUNK_USERS.has(host)) return { device: host, deviceType: 'host' };
  const ip = canonicalIp(sourceIp);
  if (ip) return { device: ip, deviceType: 'ip' };
  return { device: UNKNOWN_DEVICE, deviceType: null };
}

/** Which terms each log line holds, and on which device. Exported for tests. */
export function matchRows(
  terms: Term[],
  rows: LogRow[]
): { hits: Map<Term, TermHits>; logsMatched: Set<number>; devices: Map<string, DeviceHits> } {
  const hits = new Map<Term, TermHits>();
  const logsMatched = new Set<number>();
  const devices = new Map<string, DeviceHits>();
  for (const row of rows) {
    const hay = (row.raw_message || '').toLowerCase();
    const rowIndicators = new Set<number>();
    const rowHypotheses = new Set<number>();
    for (const term of terms) {
      if (!occursIn(hay, term.needle, term.kind)) continue;
      logsMatched.add(Number(row.id));
      if (term.indicatorId) rowIndicators.add(term.indicatorId);
      if (term.hypothesisId) rowHypotheses.add(term.hypothesisId);
      let h = hits.get(term);
      if (!h) {
        h = { lineIds: new Set(), count: 0, first: null, last: null, samples: [] };
        hits.set(term, h);
      }
      h.count++;
      h.lineIds.add(Number(row.id));
      const t = new Date(row.timestamp);
      if (!h.first || t < h.first) h.first = t;
      if (!h.last || t > h.last) h.last = t;
      if (h.samples.length < MAX_SAMPLES_PER_TERM) h.samples.push(row);
    }
    if (!rowIndicators.size && !rowHypotheses.size) continue;
    const { device, deviceType } = deviceOf(row.hostname, row.source_ip);
    let d = devices.get(device);
    if (!d) {
      d = {
        device,
        deviceType,
        hostname: row.hostname || null,
        sourceIp: row.source_ip || null,
        appNames: new Set(),
        lineIds: new Set(),
        first: null,
        last: null,
        lastRawLogId: null,
        indicators: new Map(),
        hypotheses: new Map(),
      };
      devices.set(device, d);
    }
    const t = new Date(row.timestamp);
    if (!d.first || t < d.first) d.first = t;
    if (!d.last || t > d.last) {
      d.last = t;
      d.lastRawLogId = Number(row.id);
      // The newest line's sender and host name, should a device's change.
      d.sourceIp = row.source_ip || d.sourceIp;
      d.hostname = row.hostname || d.hostname;
    }
    d.lineIds.add(Number(row.id));
    if (row.app_name && d.appNames.size < 10) d.appNames.add(row.app_name);
    for (const id of rowIndicators) d.indicators.set(id, (d.indicators.get(id) ?? 0) + 1);
    for (const id of rowHypotheses) d.hypotheses.set(id, (d.hypotheses.get(id) ?? 0) + 1);
  }
  return { hits, logsMatched, devices };
}

/** The devices with the most matching lines first (ties: the newest last line). Exported for tests. */
export function rankDevices(devices: Map<string, DeviceHits>): DeviceHits[] {
  return [...devices.values()].sort(
    (a, b) => b.lineIds.size - a.lineIds.size || (b.last?.getTime() ?? 0) - (a.last?.getTime() ?? 0) || a.device.localeCompare(b.device)
  );
}

/**
 * The keys a device's hunt alert carries in matched_data, so the Context Graph
 * (graph/resolvers/alerts.ts), Threat Intel's IP view and Asset-360 find it:
 *   host                    the device's host name (alert_hosts)
 *   client_ip, observer_ip  the sender: equal, so the graph draws it as the sender
 *   source_ip               the indicator IP with the most lines on the device
 *   domain                  the indicator domain (or URL host) with the most lines
 * Exported for tests.
 */
export function deviceAlertKeys(
  d: Pick<DeviceHits, 'hostname' | 'sourceIp' | 'deviceType' | 'device'>,
  matched: Array<{ type: IocType; value: string; lines: number }>
): Record<string, string> {
  const keys: Record<string, string> = {};
  if (d.deviceType === 'host') keys.host = d.device;
  const sender = canonicalIp(d.sourceIp);
  if (sender) {
    keys.client_ip = sender;
    keys.observer_ip = sender;
  }
  const byLines = [...matched].sort((a, b) => b.lines - a.lines);
  const ip = byLines.find((i) => i.type === 'ipv4' || i.type === 'ipv6');
  if (ip) keys.source_ip = ip.value;
  for (const i of byLines) {
    let domain: string | null = null;
    if (i.type === 'domain') domain = canonicalDomain(i.value);
    else if (i.type === 'url') {
      try {
        domain = canonicalDomain(new URL(i.value).hostname);
      } catch {
        domain = null;
      }
    }
    if (domain && !canonicalIp(domain)) {
      keys.domain = domain;
      break;
    }
  }
  return keys;
}

/** "Searched 6 of 30 days" for a run in progress. */
export function progressText(doneMs: number, totalMs: number): string {
  const days = (ms: number) => {
    const d = ms / 86_400_000;
    return d >= 10 ? Math.round(d).toString() : (Math.round(d * 10) / 10).toString();
  };
  return `Searched ${days(doneMs)} of ${days(totalMs)} days`;
}

/** Why a finished run covered only part of its window. */
function coverageText(searchedFrom: Date | null, lookbackDays: number, truncated: boolean): string {
  const covered = searchedFrom ? Math.max(0, Date.now() - searchedFrom.getTime()) : 0;
  const part = `${progressText(covered, lookbackDays * 86_400_000).replace('Searched', 'Searched the newest')}`;
  return truncated
    ? `${part}: over ${MAX_ROWS.toLocaleString('en-US')} log lines matched, so older logs were not read. Switch off noisy terms and run again.`
    : `${part}: the run hit its ${Math.round(HUNT_MAX_RUNTIME_MS / 60_000)}-minute limit (HUNT_MAX_RUNTIME_MS). Shorten the window or run again.`;
}

export async function runHunt(id: number): Promise<void> {
  const hunt = await getHuntRow(id);
  if (!hunt) return;
  await query(
    `UPDATE threat_hunts SET status = 'running', error = NULL, progress = 'Starting the log search', updated_at = NOW() WHERE id = $1`,
    [id]
  );
  const [indicators, hypotheses] = await Promise.all([getIndicators(id), getHypotheses(id)]);
  const terms = huntTerms(indicators, hypotheses);

  let rows: LogRow[] = [];
  let truncated = false;
  let complete = true;
  let searchedFrom: Date | null = null;
  if (terms.length) {
    const needles = [...new Set(terms.map((t) => t.needle))];
    ({ rows, truncated, complete, searchedFrom } = await searchLogs(needles, hunt.lookback_days, async (done, total) => {
      await query(`UPDATE threat_hunts SET progress = $2 WHERE id = $1`, [id, progressText(done, total)]).catch(
        () => undefined
      );
    }));
  }
  const { hits, logsMatched, devices } = matchRows(terms, rows);
  const ranked = rankDevices(devices);
  const indById = new Map(indicators.map((i) => [i.id, i]));
  const hypById = new Map(hypotheses.map((h) => [h.id, h]));
  const deviceIndicators = (d: DeviceHits) =>
    [...d.indicators]
      .map(([indId, lines]) => ({ id: indId, type: indById.get(indId)!.ioc_type, value: indById.get(indId)!.value, lines }))
      .sort((a, b) => b.lines - a.lines);
  const deviceHypotheses = (d: DeviceHits) =>
    [...d.hypotheses]
      .map(([hypId, lines]) => ({ id: hypId, title: hypById.get(hypId)!.title, lines }))
      .sort((a, b) => b.lines - a.lines);

  // Per indicator / hypothesis totals (a hypothesis sums its terms, counting each line once).
  const indTotals = new Map<number, TermHits>();
  const hypLines = new Map<number, { lines: Set<number>; first: Date | null; last: Date | null }>();
  for (const [term, h] of hits) {
    if (term.indicatorId) indTotals.set(term.indicatorId, h);
    if (term.hypothesisId) {
      let agg = hypLines.get(term.hypothesisId);
      if (!agg) {
        agg = { lines: new Set(), first: null, last: null };
        hypLines.set(term.hypothesisId, agg);
      }
      for (const lineId of h.lineIds) agg.lines.add(lineId);
      if (!agg.first || (h.first && h.first < agg.first)) agg.first = h.first;
      if (!agg.last || (h.last && h.last > agg.last)) agg.last = h.last;
    }
  }

  const client = await pool.connect();
  let matchCount = 0;
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM threat_hunt_matches WHERE hunt_id = $1`, [id]);
    await client.query(
      `UPDATE threat_hunt_indicators SET match_count = 0, first_seen = NULL, last_seen = NULL WHERE hunt_id = $1`,
      [id]
    );
    await client.query(
      `UPDATE threat_hunt_hypotheses SET match_count = 0, first_seen = NULL, last_seen = NULL WHERE hunt_id = $1`,
      [id]
    );
    for (const [indId, h] of indTotals) {
      matchCount += h.count;
      await client.query(
        `UPDATE threat_hunt_indicators SET match_count = $2, first_seen = $3, last_seen = $4 WHERE id = $1`,
        [indId, h.count, h.first, h.last]
      );
    }
    for (const [hypId, agg] of hypLines) {
      matchCount += agg.lines.size;
      await client.query(
        `UPDATE threat_hunt_hypotheses SET match_count = $2, first_seen = $3, last_seen = $4 WHERE id = $1`,
        [hypId, agg.lines.size, agg.first, agg.last]
      );
    }
    for (const [term, h] of hits) {
      for (const row of h.samples) {
        await client.query(
          `INSERT INTO threat_hunt_matches
             (hunt_id, indicator_id, hypothesis_id, term, raw_log_id, log_timestamp, source_ip, hostname, app_name, message)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
          [
            id,
            term.indicatorId ?? null,
            term.hypothesisId ?? null,
            term.needle.slice(0, 500),
            row.id,
            row.timestamp,
            row.source_ip,
            row.hostname,
            row.app_name,
            (row.raw_message || '').slice(0, MAX_MESSAGE_CHARS),
          ]
        );
      }
    }
    await client.query(`DELETE FROM threat_hunt_devices WHERE hunt_id = $1`, [id]);
    for (const d of ranked.slice(0, MAX_STORED_DEVICES)) {
      await client.query(
        `INSERT INTO threat_hunt_devices
           (hunt_id, device, hostname, source_ip, app_names, lines, first_seen, last_seen, indicators, hypotheses, last_raw_log_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          id,
          d.device,
          d.hostname?.slice(0, 255) ?? null,
          d.sourceIp,
          [...d.appNames].map((a) => a.slice(0, 100)),
          d.lineIds.size,
          d.first,
          d.last,
          JSON.stringify(deviceIndicators(d).slice(0, 100)),
          JSON.stringify(deviceHypotheses(d).slice(0, 50)),
          d.lastRawLogId,
        ]
      );
    }
    await client.query(
      `UPDATE threat_hunts
          SET status = 'completed', error = NULL, match_count = $2, logs_matched = $3, results_truncated = $4,
              search_complete = $5, searched_from = $6, progress = $7, devices_matched = $8, last_run_at = NOW(), updated_at = NOW()
        WHERE id = $1`,
      [
        id,
        matchCount,
        logsMatched.size,
        truncated,
        complete,
        searchedFrom,
        complete ? null : coverageText(searchedFrom, hunt.lookback_days, truncated),
        devices.size,
      ]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  logger.info(
    `[Hunt] hunt ${id}: ${terms.length} term(s), ${logsMatched.size} matching log line(s) on ${devices.size} device(s)`
  );
  if (hunt.alert_on_match && logsMatched.size > 0) {
    const search: HuntSearchScope = {
      from: searchedFrom,
      to: new Date(),
      complete,
      lookbackDays: hunt.lookback_days,
      devices: devices.size,
      lines: logsMatched.size,
    };
    await raiseHuntAlerts(hunt, ranked, deviceIndicators, deviceHypotheses, search);
  }
}

interface HuntSearchScope {
  from: Date | null;
  to: Date;
  complete: boolean;
  lookbackDays: number;
  /** Devices and lines the whole run matched. */
  devices: number;
  lines: number;
}

const isoMinute = (d: Date | null) => (d ? `${d.toISOString().slice(0, 16).replace('T', ' ')} UTC` : 'unknown');

/** The alert text for one device. Exported for tests. */
export function deviceAlertText(
  hunt: Pick<HuntRow, 'id' | 'title' | 'source_url'>,
  d: Pick<DeviceHits, 'device' | 'hostname' | 'sourceIp' | 'appNames' | 'lineIds' | 'first' | 'last'>,
  matched: Array<{ type: string; value: string; lines: number }>,
  hyps: Array<{ title: string; lines: number }>,
  search: HuntSearchScope,
  othersAlerted: number
): string {
  const where = [
    d.hostname ? `host ${d.hostname}` : null,
    d.sourceIp ? `sender ${d.sourceIp}` : null,
    d.appNames.size ? `app ${[...d.appNames].slice(0, 5).join(', ')}` : null,
  ].filter(Boolean);
  const lines = [
    `Threat hunt #${hunt.id} found ${d.lineIds.size} matching log line(s) on ${d.device}.`,
    `Seen on: ${where.length ? where.join(' · ') : 'a log with no host or sender'}`,
    `First seen ${isoMinute(d.first)}, last seen ${isoMinute(d.last)}.`,
    ...matched.slice(0, 10).map((i) => `Indicator ${i.type} ${i.value}: ${i.lines} line(s)`),
    ...hyps.slice(0, 5).map((h) => `Hypothesis "${h.title}": ${h.lines} line(s)`),
    `Searched all stored logs from ${isoMinute(search.from)} to ${isoMinute(search.to)}` +
      (search.complete ? ` (the full ${search.lookbackDays}-day window).` : ` (part of the ${search.lookbackDays}-day window; see the hunt).`),
    `The run matched ${search.lines} line(s) on ${search.devices} device(s)` +
      (othersAlerted > 0 ? `; ${othersAlerted} other device(s) have their own alert.` : '.'),
    ...(search.devices > MAX_ALERT_DEVICES
      ? [`Only the ${MAX_ALERT_DEVICES} devices with the most lines raise an alert; the hunt lists all of them.`]
      : []),
    ...(hunt.source_url ? [`Report: ${hunt.source_url}`] : []),
  ];
  return lines.join('\n');
}

/** The asset a device is: by host name, else (no host name) by its sender IP. */
async function deviceAsset(d: DeviceHits): Promise<number | null> {
  try {
    if (d.deviceType === 'host') {
      const r = await query(`SELECT id FROM assets WHERE lower(hostname) = $1 ORDER BY last_seen DESC NULLS LAST LIMIT 1`, [d.device]);
      return r.rows[0]?.id ?? null;
    }
    if (d.deviceType === 'ip') {
      const r = await query(`SELECT id FROM assets WHERE ip_address = $1::inet LIMIT 1`, [d.device]);
      return r.rows[0]?.id ?? null;
    }
  } catch {
    /* no asset link */
  }
  return null;
}

/** The parsed log of a raw log line, if it is still stored. */
async function parsedLogOf(rawLogId: number | null): Promise<number | null> {
  if (!rawLogId) return null;
  const r = await query(`SELECT id FROM parsed_logs WHERE raw_log_id = $1 ORDER BY id DESC LIMIT 1`, [rawLogId]).catch(() => null);
  return r?.rows[0]?.id ?? null;
}

/**
 * One alert per device with matching lines (the MAX_ALERT_DEVICES with the
 * most), so each says where the hunt's matches were seen and carries the keys
 * the Context Graph links on (deviceAlertKeys), plus the newest matching log
 * (parsed_log_id: the graph's "Logged by" and shipper) and the device's asset.
 * A device whose matching lines are the same as last run raises no new alert.
 */
async function raiseHuntAlerts(
  hunt: HuntRow,
  ranked: DeviceHits[],
  deviceIndicators: (d: DeviceHits) => Array<{ id: number; type: IocType; value: string; lines: number }>,
  deviceHypotheses: (d: DeviceHits) => Array<{ id: number; title: string; lines: number }>,
  search: HuntSearchScope
): Promise<void> {
  const alerted = ranked.slice(0, MAX_ALERT_DEVICES);
  let firstAlertId: number | null = null;
  for (const d of alerted) {
    const matched = deviceIndicators(d);
    const hyps = deviceHypotheses(d);
    const deviceHash = createHash('sha256').update(d.device).digest('hex').slice(0, 12);
    const fingerprint = createHash('sha256')
      .update([...d.lineIds].sort((a, b) => a - b).join(','))
      .digest('hex')
      .slice(0, 24);
    const eventId = `threat-hunt:${hunt.id}:${deviceHash}:${fingerprint}`;
    try {
      const [assetId, parsedLogId] = await Promise.all([deviceAsset(d), parsedLogOf(d.lastRawLogId)]);
      const created = await AlertModel.createSourced({
        source: 'threat-hunt',
        event_id: eventId,
        severity: matched.length ? 'high' : 'medium',
        title: `Threat hunt match on ${d.device}: ${hunt.title}`,
        description: deviceAlertText(hunt, d, matched, hyps, search, alerted.length - 1),
        asset_id: assetId,
        parsed_log_id: parsedLogId,
        matched_data: {
          ...deviceAlertKeys(d, matched),
          hunt_id: hunt.id,
          hunt_title: hunt.title,
          source_url: hunt.source_url,
          device: d.device,
          hostname: d.hostname,
          sender_ip: d.sourceIp,
          app_names: [...d.appNames],
          lines: d.lineIds.size,
          first_seen: d.first,
          last_seen: d.last,
          raw_log_id: d.lastRawLogId,
          matched_indicators: matched.slice(0, 50).map(({ type, value, lines }) => ({ type, value, lines })),
          matched_hypotheses: hyps.slice(0, 20).map(({ title, lines }) => ({ title, lines })),
          search_from: search.from,
          search_to: search.to,
          search_complete: search.complete,
          run_devices: search.devices,
          run_lines: search.lines,
        },
      });
      // The same lines on an earlier run: that run's alert stands for them.
      const alertId =
        created ?? ((await query(`SELECT id FROM alerts WHERE event_id = $1`, [eventId])).rows[0]?.id as number | undefined) ?? null;
      if (!alertId) continue;
      firstAlertId ??= alertId;
      await query(`UPDATE threat_hunt_devices SET alert_id = $3 WHERE hunt_id = $1 AND device = $2`, [hunt.id, d.device, alertId]);
    } catch (err) {
      logger.warn(`[Hunt] hunt ${hunt.id}: could not raise an alert for ${d.device}: ${(err as Error).message}`);
    }
  }
  if (firstAlertId) await query(`UPDATE threat_hunts SET last_alert_id = $2 WHERE id = $1`, [hunt.id, firstAlertId]);
}

// ---- Reading -----------------------------------------------------------------------

const HUNT_COLUMNS = `h.id, h.stix_uuid, h.title, h.title_locked, h.origin, h.source_url, h.source_id, s.name AS source_name, h.status,
  h.summary, h.extraction_method, h.extraction_note, h.lookback_days, h.alert_on_match, h.use_ai, h.error,
  h.match_count, h.logs_matched, h.devices_matched, h.results_truncated, h.search_complete, h.searched_from, h.progress, h.last_run_at, h.last_alert_id, h.created_by,
  h.created_at, h.updated_at`;

export async function getHuntRow(id: number): Promise<HuntRow | null> {
  const r = await query(
    `SELECT ${HUNT_COLUMNS} FROM threat_hunts h LEFT JOIN hunt_sources s ON s.id = h.source_id WHERE h.id = $1`,
    [id]
  );
  return r.rows[0] || null;
}

export async function listHunts(opts: {
  limit: number;
  offset: number;
  status?: string;
  sourceId?: number;
  search?: string;
}): Promise<{ hunts: HuntRow[]; total: number }> {
  const where: string[] = [];
  const params: unknown[] = [];
  if (opts.status) {
    params.push(opts.status);
    where.push(`h.status = $${params.length}`);
  }
  if (opts.sourceId) {
    params.push(opts.sourceId);
    where.push(`h.source_id = $${params.length}`);
  }
  if (opts.search) {
    params.push(`%${escapeLike(opts.search)}%`);
    where.push(`(h.title ILIKE $${params.length} OR h.source_url ILIKE $${params.length})`);
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const total = await query(`SELECT COUNT(*)::int AS n FROM threat_hunts h ${clause}`, params);
  params.push(opts.limit, opts.offset);
  const r = await query(
    `SELECT ${HUNT_COLUMNS},
            (SELECT COUNT(*)::int FROM threat_hunt_indicators i WHERE i.hunt_id = h.id AND i.enabled) AS indicator_count,
            (SELECT COUNT(*)::int FROM threat_hunt_hypotheses y WHERE y.hunt_id = h.id AND y.enabled) AS hypothesis_count
       FROM threat_hunts h LEFT JOIN hunt_sources s ON s.id = h.source_id
       ${clause}
      ORDER BY h.created_at DESC, h.id DESC
      LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params
  );
  const positions = huntQueuePositions();
  const hunts = r.rows.map((h: HuntRow) => ({ ...h, queue_position: positions.get(h.id) ?? null }));
  return { hunts, total: total.rows[0]?.n ?? 0 };
}

export async function getIndicators(huntId: number): Promise<IndicatorRow[]> {
  const r = await query(
    `SELECT * FROM threat_hunt_indicators WHERE hunt_id = $1 ORDER BY match_count DESC, ioc_type, value`,
    [huntId]
  );
  return r.rows;
}

export async function getHypotheses(huntId: number): Promise<HypothesisRow[]> {
  const r = await query(`SELECT * FROM threat_hunt_hypotheses WHERE hunt_id = $1 ORDER BY id`, [huntId]);
  return r.rows;
}

export async function getMatches(huntId: number, limit = 500): Promise<unknown[]> {
  const r = await query(
    `SELECT m.id, m.indicator_id, m.hypothesis_id, m.term, m.raw_log_id, m.log_timestamp, m.source_ip,
            m.hostname, m.app_name, m.message, i.ioc_type, i.value AS indicator_value, y.title AS hypothesis_title
       FROM threat_hunt_matches m
       LEFT JOIN threat_hunt_indicators i ON i.id = m.indicator_id
       LEFT JOIN threat_hunt_hypotheses y ON y.id = m.hypothesis_id
      WHERE m.hunt_id = $1
      ORDER BY m.log_timestamp DESC NULLS LAST, m.id DESC
      LIMIT $2`,
    [huntId, limit]
  );
  return r.rows;
}

/** Where the last run's matches were seen: one row per device, most lines first. */
export async function getDevices(huntId: number, limit = MAX_STORED_DEVICES): Promise<unknown[]> {
  const r = await query(
    `SELECT d.id, d.device, d.hostname, d.source_ip, d.app_names, d.lines, d.first_seen, d.last_seen,
            d.indicators, d.hypotheses, d.last_raw_log_id, d.alert_id, a.severity AS alert_severity, a.status AS alert_status
       FROM threat_hunt_devices d
       LEFT JOIN alerts a ON a.id = d.alert_id
      WHERE d.hunt_id = $1
      ORDER BY d.lines DESC, d.last_seen DESC NULLS LAST, d.device
      LIMIT $2`,
    [huntId, limit]
  );
  // device_type: which Context Graph node the device key names (host, ip, or none).
  return r.rows.map((row) => ({ ...row, device_type: deviceOf(row.hostname, row.source_ip).deviceType }));
}

export async function getHuntDetail(id: number) {
  const hunt = await getHuntRow(id);
  if (!hunt) return null;
  const [indicators, hypotheses, matches, devices] = await Promise.all([
    getIndicators(id),
    getHypotheses(id),
    getMatches(id),
    getDevices(id),
  ]);
  return {
    ...hunt,
    indicators,
    hypotheses,
    matches,
    devices,
    queue_depth: huntQueueDepth(),
    queue_position: huntQueuePositions().get(id) ?? null,
  };
}

function toStixHunt(hunt: HuntRow, indicators: IndicatorRow[], hypotheses: HypothesisRow[]): StixHunt {
  return { ...hunt, indicators, hypotheses };
}

export async function huntStixBundle(id: number): Promise<StixBundle | null> {
  const hunt = await getHuntRow(id);
  if (!hunt) return null;
  const [indicators, hypotheses] = await Promise.all([getIndicators(id), getHypotheses(id)]);
  return huntBundle(toStixHunt(hunt, indicators, hypotheses), techniqueDisplayName);
}

/** One TAXII object: a STIX object and when it was added to the collection. */
export interface CollectionObject {
  object: StixObject;
  dateAdded: Date;
}

export const MAX_TAXII_HUNTS = 1000;

/**
 * Every hunt's objects for the TAXII collection, oldest first. A hunt's
 * objects are dated by its updated_at (a re-run republishes them with a newer
 * `modified`). Objects several hunts share (the ATT&CK attack-patterns) are
 * listed once, at their latest date. Hunts still reading their report are left
 * out.
 */
export async function collectionObjects(): Promise<CollectionObject[]> {
  const r = await query(
    `SELECT ${HUNT_COLUMNS} FROM threat_hunts h LEFT JOIN hunt_sources s ON s.id = h.source_id
      WHERE h.status IN ('ready', 'running', 'completed')
      ORDER BY h.updated_at DESC, h.id DESC
      LIMIT $1`,
    [MAX_TAXII_HUNTS]
  );
  const hunts: HuntRow[] = r.rows;
  if (!hunts.length) return [];
  const ids = hunts.map((h) => h.id);
  const [inds, hyps] = await Promise.all([
    query(`SELECT * FROM threat_hunt_indicators WHERE hunt_id = ANY($1::int[]) ORDER BY id`, [ids]),
    query(`SELECT * FROM threat_hunt_hypotheses WHERE hunt_id = ANY($1::int[]) ORDER BY id`, [ids]),
  ]);
  const byHunt = <T extends { hunt_id: number }>(rows: T[]) => {
    const m = new Map<number, T[]>();
    for (const row of rows) {
      const list = m.get(row.hunt_id) ?? [];
      list.push(row);
      m.set(row.hunt_id, list);
    }
    return m;
  };
  const indMap = byHunt(inds.rows as IndicatorRow[]);
  const hypMap = byHunt(hyps.rows as HypothesisRow[]);

  const byId = new Map<string, CollectionObject>();
  for (const hunt of hunts) {
    const dateAdded = new Date(hunt.updated_at);
    const objects = huntStixObjects(toStixHunt(hunt, indMap.get(hunt.id) ?? [], hypMap.get(hunt.id) ?? []), techniqueDisplayName);
    for (const object of objects) {
      const prior = byId.get(object.id);
      if (!prior || prior.dateAdded < dateAdded) byId.set(object.id, { object, dateAdded });
    }
  }
  return [...byId.values()].sort(
    (a, b) => a.dateAdded.getTime() - b.dateAdded.getTime() || a.object.id.localeCompare(b.object.id)
  );
}

// ---- Editing -----------------------------------------------------------------------

export async function updateHunt(
  id: number,
  patch: { title?: string; lookback_days?: number; alert_on_match?: boolean }
): Promise<HuntRow | null> {
  const sets: string[] = [];
  const params: unknown[] = [id];
  if (typeof patch.title === 'string' && patch.title.trim()) {
    params.push(patch.title.trim().slice(0, 500));
    sets.push(`title = $${params.length}`, 'title_locked = true');
  }
  if (patch.lookback_days !== undefined) {
    params.push(clampLookback(patch.lookback_days));
    sets.push(`lookback_days = $${params.length}`);
  }
  if (typeof patch.alert_on_match === 'boolean') {
    params.push(patch.alert_on_match);
    sets.push(`alert_on_match = $${params.length}`);
  }
  if (sets.length) await query(`UPDATE threat_hunts SET ${sets.join(', ')}, updated_at = NOW() WHERE id = $1`, params);
  return getHuntRow(id);
}

export async function deleteHunt(id: number): Promise<boolean> {
  const r = await query(`DELETE FROM threat_hunts WHERE id = $1 AND status NOT IN ('extracting', 'running')`, [id]);
  if ((r.rowCount ?? 0) > 0) return true;
  const exists = await getHuntRow(id);
  if (exists) throw new HuntError(409, 'The hunt is busy; delete it once it finishes.');
  return false;
}

export async function setIndicatorEnabled(huntId: number, indicatorId: number, enabled: boolean): Promise<boolean> {
  const r = await query(
    `UPDATE threat_hunt_indicators SET enabled = $3 WHERE id = $2 AND hunt_id = $1`,
    [huntId, indicatorId, enabled]
  );
  if ((r.rowCount ?? 0) > 0) await query(`UPDATE threat_hunts SET updated_at = NOW() WHERE id = $1`, [huntId]);
  return (r.rowCount ?? 0) > 0;
}

export async function addIndicator(huntId: number, type: string, rawValue: string, context?: string | null): Promise<IndicatorRow> {
  if (!IOC_TYPES.includes(type as IocType)) throw new HuntError(400, `type must be one of ${IOC_TYPES.join(', ')}`);
  const value = normalizeIoc(type as IocType, rawValue);
  if (!value) throw new HuntError(400, `"${String(rawValue).slice(0, 100)}" is not a valid ${type} indicator (private and reserved addresses are not hunted).`);
  const hunt = await getHuntRow(huntId);
  if (!hunt) throw new HuntError(404, 'Hunt not found');
  const r = await query(
    `INSERT INTO threat_hunt_indicators (hunt_id, stix_id, ioc_type, value, context, found_by)
     VALUES ($1, $2, $3, $4, $5, 'user')
     ON CONFLICT (hunt_id, ioc_type, value) DO UPDATE SET enabled = true
     RETURNING *`,
    [huntId, indicatorStixId(hunt.stix_uuid, type as IocType, value), type, value, context ? String(context).slice(0, 500) : null]
  );
  await query(`UPDATE threat_hunts SET updated_at = NOW() WHERE id = $1`, [huntId]);
  return r.rows[0];
}

function cleanTerms(raw: unknown): string[] {
  if (!Array.isArray(raw)) throw new HuntError(400, 'search_terms must be an array of strings');
  const out: string[] = [];
  for (const t of raw) {
    const s = String(t ?? '').replace(/\s+/g, ' ').trim();
    if (!s) continue;
    if (s.length < 3 || s.length > 200) throw new HuntError(400, 'Each search term must be 3 to 200 characters.');
    if (!out.some((o) => o.toLowerCase() === s.toLowerCase())) out.push(s);
  }
  if (out.length > 20) throw new HuntError(400, 'At most 20 search terms per hypothesis.');
  return out;
}

function cleanTechniques(raw: unknown): string[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) throw new HuntError(400, 'attack_techniques must be an array');
  const out = [...new Set(raw.map((t) => String(t ?? '').trim().toUpperCase()).filter(Boolean))];
  const bad = out.find((t) => !/^T\d{4}(?:\.\d{3})?$/.test(t) || !isTechnique(t));
  if (bad) throw new HuntError(400, `${bad.slice(0, 20)} is not an ATT&CK technique ID`);
  return out;
}

export async function addHypothesis(
  huntId: number,
  body: { title?: unknown; description?: unknown; search_terms?: unknown; attack_techniques?: unknown }
): Promise<HypothesisRow> {
  const title = typeof body.title === 'string' ? body.title.trim().slice(0, 500) : '';
  if (!title) throw new HuntError(400, 'title is required');
  const hunt = await getHuntRow(huntId);
  if (!hunt) throw new HuntError(404, 'Hunt not found');
  const r = await query(
    `INSERT INTO threat_hunt_hypotheses (hunt_id, stix_id, title, description, attack_techniques, search_terms, found_by)
     VALUES ($1, $2, $3, $4, $5, $6, 'user') RETURNING *`,
    [
      huntId,
      hypothesisStixId(hunt.stix_uuid, title),
      title,
      typeof body.description === 'string' ? body.description.slice(0, 4000) : null,
      cleanTechniques(body.attack_techniques),
      cleanTerms(body.search_terms ?? []),
    ]
  );
  await query(`UPDATE threat_hunts SET updated_at = NOW() WHERE id = $1`, [huntId]);
  return r.rows[0];
}

export async function updateHypothesis(
  huntId: number,
  hypothesisId: number,
  body: { title?: unknown; description?: unknown; search_terms?: unknown; attack_techniques?: unknown; enabled?: unknown }
): Promise<HypothesisRow | null> {
  const sets: string[] = [];
  const params: unknown[] = [huntId, hypothesisId];
  if (typeof body.title === 'string' && body.title.trim()) {
    params.push(body.title.trim().slice(0, 500));
    sets.push(`title = $${params.length}`);
  }
  if (typeof body.description === 'string') {
    params.push(body.description.slice(0, 4000));
    sets.push(`description = $${params.length}`);
  }
  if (body.search_terms !== undefined) {
    params.push(cleanTerms(body.search_terms));
    sets.push(`search_terms = $${params.length}`);
  }
  if (body.attack_techniques !== undefined) {
    params.push(cleanTechniques(body.attack_techniques));
    sets.push(`attack_techniques = $${params.length}`);
  }
  if (typeof body.enabled === 'boolean') {
    params.push(body.enabled);
    sets.push(`enabled = $${params.length}`);
  }
  if (!sets.length) throw new HuntError(400, 'Nothing to change.');
  // An edited hypothesis is the analyst's now: a re-extraction keeps it.
  if (sets.some((s) => !s.startsWith('enabled'))) sets.push(`found_by = 'user'`);
  const r = await query(
    `UPDATE threat_hunt_hypotheses SET ${sets.join(', ')} WHERE hunt_id = $1 AND id = $2 RETURNING *`,
    params
  );
  if (r.rows[0]) await query(`UPDATE threat_hunts SET updated_at = NOW() WHERE id = $1`, [huntId]);
  return r.rows[0] || null;
}

export async function deleteHypothesis(huntId: number, hypothesisId: number): Promise<boolean> {
  const r = await query(`DELETE FROM threat_hunt_hypotheses WHERE hunt_id = $1 AND id = $2`, [huntId, hypothesisId]);
  if ((r.rowCount ?? 0) > 0) await query(`UPDATE threat_hunts SET updated_at = NOW() WHERE id = $1`, [huntId]);
  return (r.rowCount ?? 0) > 0;
}

export async function huntSummary() {
  const r = await query(
    `SELECT COUNT(*)::int AS hunts,
            COUNT(*) FILTER (WHERE status = 'completed' AND logs_matched > 0)::int AS hunts_with_matches,
            COUNT(*) FILTER (WHERE status IN ('pending', 'extracting', 'running'))::int AS in_progress,
            COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
            (SELECT COUNT(*)::int FROM threat_hunt_indicators WHERE enabled) AS indicators,
            (SELECT COUNT(*)::int FROM hunt_sources WHERE enabled) AS sources_enabled
       FROM threat_hunts`
  );
  return { ...r.rows[0], queue_depth: huntQueueDepth() };
}
