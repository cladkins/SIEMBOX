/**
 * The one write path for exposure findings.
 *
 * recordFinding() upserts on (source, fingerprint): the first sighting inserts
 * the finding and raises exactly one alert; every later sighting only moves
 * last_seen (a resolved finding stays resolved — a breach never "un-happens",
 * so seeing it again on the next check is not news).
 *
 * Alerts are created EDR-style, outside the rules engine (see
 * edrService.ingestEvents): rule_id NULL, source = the finding's source, and a
 * stable event_id deduped by the partial unique index from migration 016. The
 * finding insert, the alert insert and the link between them commit together,
 * so a crash can never leave a finding that will never get its alert. AI
 * auto-triage is deliberately not invoked for these alerts in v1.
 *
 * Privacy invariant: `detail` (stored on the finding AND copied into the
 * alert's matched_data) goes through sanitizeDetail(), which drops every key
 * that looks like it could hold a secret — at any depth — so a password, hash,
 * token or API key can't be persisted even if a caller passes one by mistake.
 */
import crypto from 'crypto';
import { getClient } from '../../config/database';
import { logger } from '../../utils/logger';
import { NotificationService, type ExposureNotice } from '../notifications/notificationService';
import type { ExposureFindingSource, ExposureSeverity } from '../../models/Exposure';

/** Keys that could carry secret material. Over-matching (e.g. "passport") is the safe direction. */
export const SECRET_KEY_PATTERN = /pass(word)?|pwd|hash|secret|token|api[_-]?key|credential/i;

// Deeper than any real detail payload; stops runaway (or cyclic) structures.
const MAX_DETAIL_DEPTH = 12;
const MAX_TITLE_LENGTH = 500;
const MAX_ALERT_TITLE_LENGTH = 255; // alerts.title is VARCHAR(255)

function scrub(value: unknown, depth: number): unknown {
  if (depth > MAX_DETAIL_DEPTH) return undefined;
  if (Array.isArray(value)) {
    return value.map((item) => scrub(item, depth + 1)).filter((item) => item !== undefined);
  }
  if (value instanceof Date) return value.toISOString();
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      if (SECRET_KEY_PATTERN.test(key)) continue;
      const clean = scrub(item, depth + 1);
      if (clean !== undefined) out[key] = clean;
    }
    return out;
  }
  if (typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint')
    return undefined;
  return value;
}

/**
 * A deep copy of `detail` with every secret-like key removed, at any depth
 * (including inside arrays). Values are kept as-is: the scrub is key-based.
 */
export function sanitizeDetail(detail: unknown): Record<string, unknown> {
  const clean = scrub(detail, 0);
  return clean !== null && typeof clean === 'object' && !Array.isArray(clean)
    ? (clean as Record<string, unknown>)
    : {};
}

/** Stable alerts.event_id for a finding: the same finding can only ever raise one alert. */
export function findingEventId(source: string, fingerprint: string): string {
  return crypto.createHash('sha256').update(`${source}:${fingerprint}`).digest('hex');
}

export interface FindingInput {
  source: ExposureFindingSource;
  identityId?: number | null;
  domainId?: number | null;
  eventType: string;
  fingerprint: string;
  title: string;
  severity: ExposureSeverity;
  detail: Record<string, unknown>;
  /** Alert description; defaults to the title. */
  description?: string;
}

export interface RecordFindingResult {
  findingId: number;
  /** True only on the first sighting of this (source, fingerprint). */
  isNew: boolean;
  /** The linked alert (new, or a pre-existing one with the same event_id). */
  alertId: number | null;
  /** True when this call created the alert — the cue to notify. */
  alertCreated: boolean;
}

export interface RecordFindingOptions {
  /**
   * Send the exposure notification for a newly created alert (default true).
   * Batch callers pass false and send one grouped notification themselves.
   */
  notify?: boolean;
}

export function toExposureNotice(input: FindingInput): ExposureNotice {
  return {
    source: input.source,
    severity: input.severity,
    title: input.title,
    description: input.description,
  };
}

export async function recordFinding(
  input: FindingInput,
  options: RecordFindingOptions = {}
): Promise<RecordFindingResult> {
  const detail = sanitizeDetail(input.detail);
  const title = input.title.slice(0, MAX_TITLE_LENGTH);
  const eventId = findingEventId(input.source, input.fingerprint);

  const client = await getClient();
  let result: RecordFindingResult;
  let connectionBroken = false;
  try {
    await client.query('BEGIN');

    // xmax = 0 only for a row this statement inserted; a conflict-update sets it.
    const upsert = await client.query(
      `INSERT INTO exposure_findings
         (source, identity_id, domain_id, event_type, fingerprint, title, severity, detail)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (source, fingerprint) DO UPDATE SET last_seen = NOW()
       RETURNING id, alert_id, (xmax = 0) AS inserted`,
      [
        input.source,
        input.identityId ?? null,
        input.domainId ?? null,
        input.eventType,
        input.fingerprint,
        title,
        input.severity,
        JSON.stringify(detail),
      ]
    );
    const row = upsert.rows[0];
    result = {
      findingId: Number(row.id),
      isNew: row.inserted === true,
      alertId: row.alert_id,
      alertCreated: false,
    };

    if (result.isNew) {
      const alert = await client.query(
        `INSERT INTO alerts
           (rule_id, parsed_log_id, severity, title, description, matched_data, status, source, event_id)
         VALUES (NULL, NULL, $1, $2, $3, $4, 'new', $5, $6)
         ON CONFLICT (event_id) WHERE event_id IS NOT NULL DO NOTHING
         RETURNING id`,
        [
          input.severity,
          title.slice(0, MAX_ALERT_TITLE_LENGTH),
          input.description ?? title,
          JSON.stringify(detail),
          input.source,
          eventId,
        ]
      );
      if ((alert.rowCount ?? 0) > 0) {
        result.alertId = alert.rows[0].id;
        result.alertCreated = true;
      } else {
        // The finding was deleted (its identity/domain removed) and has now come
        // back: its old alert still exists. Re-link it instead of raising a
        // duplicate — the operator has already been told about this exposure.
        const existing = await client.query(`SELECT id FROM alerts WHERE event_id = $1`, [eventId]);
        result.alertId = existing.rows[0]?.id ?? null;
      }
      if (result.alertId !== null) {
        await client.query(`UPDATE exposure_findings SET alert_id = $1 WHERE id = $2`, [
          result.alertId,
          result.findingId,
        ]);
      }
    }

    await client.query('COMMIT');
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      connectionBroken = true; // don't hand a dead connection back to the pool
    }
    throw err;
  } finally {
    client.release(connectionBroken || undefined);
  }

  if (result.alertCreated) {
    logger.info(
      `[Exposure] new ${input.severity} ${input.source} finding #${result.findingId} (alert #${result.alertId})`
    );
    if (options.notify !== false) {
      // notifyExposure never throws; it applies the opt-in + min-severity gates.
      await NotificationService.notifyExposure([toExposureNotice(input)]);
    }
  }
  return result;
}
