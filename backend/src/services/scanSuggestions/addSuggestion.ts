/**
 * "Add" on a suggested scan: create what it describes, disabled, for the
 * person to finish.
 *
 *  - asset / vulnerability / container / log_discovery: a scheduled scan of
 *    that type, DISABLED, named after the suggestion, with its options and its
 *    calendar timing in the caller's time zone, and no targets. It cannot be
 *    enabled or run until the targets are filled in (routes/scheduledScans.ts).
 *  - endpoint_policy: a named endpoint scan policy that no endpoint follows yet
 *    (it does nothing until it is assigned), every schedule and window in the
 *    caller's time zone. A name already taken gets " (2)", " (3)", ...
 *
 * The caller's time zone comes from their browser (body.timezone); without one
 * UTC is used. Nothing here reads a target from the request: a suggestion
 * never carries one, and the person adds them in the edit dialog.
 */
import { query } from '../../config/database';
import { ApiError } from '../../middleware/errorHandler';
import { ScheduledScanModel, type ScheduledScan } from '../../models/ScheduledScan';
import { isValidTimeZone, normalizeCalendarSchedule } from '../../utils/scheduleTiming';
import { scanOptionsShapeError, type ScheduledScanKind } from '../scanner/scheduleOptions';
import { createPolicy, normalizePolicyScans, type ScanPolicy } from '../edr/scanPolicies';
import { withTimezone, type ScanSuggestion } from './scanFormat';
import { fetchScanCatalog } from './scanCatalog';

export interface AddResult {
  suggestion_id: string;
  kind: ScanSuggestion['kind'];
  /** The created schedule (kind other than endpoint_policy). */
  scheduled_scan?: ScheduledScan;
  /** The created policy (endpoint_policy). */
  policy?: ScanPolicy;
  /** The inputs the person still fills in. */
  inputs: ScanSuggestion['inputs'];
}

export function parseTimezone(raw: unknown): string {
  if (raw === undefined || raw === null || raw === '') return 'UTC';
  if (!isValidTimeZone(raw)) throw new ApiError(400, 'timezone must be an IANA time zone name, e.g. America/Chicago or UTC');
  return raw;
}

export async function findSuggestion(id: unknown): Promise<ScanSuggestion> {
  if (typeof id !== 'string' || !/^[a-z0-9-]{1,64}$/.test(id)) throw new ApiError(400, 'Invalid suggestion id');
  const catalog = await fetchScanCatalog();
  const s = catalog.suggestions.find((x) => x.id === id);
  if (!s) throw new ApiError(404, `No suggested scan "${id}"`);
  return s;
}

/** The scheduled scan a suggestion becomes (pure; exported for tests). */
export function scheduleFromSuggestion(s: ScanSuggestion, timezone: string) {
  if (s.kind === 'endpoint_policy' || !s.schedule) throw new Error('not a scheduled-scan suggestion');
  const scan_options = JSON.parse(JSON.stringify(s.options)) as Record<string, any>;
  const shape = scanOptionsShapeError(s.kind as ScheduledScanKind, scan_options);
  if (shape) throw new ApiError(400, `This suggestion's options are not valid here: ${shape}`);
  return {
    name: s.name,
    scan_type: s.kind as ScheduledScanKind,
    scan_options,
    interval_minutes: null,
    schedule: normalizeCalendarSchedule({ ...s.schedule, timezone }),
    enabled: false,
  };
}

export async function addSuggestion(id: unknown, body: { timezone?: unknown } | undefined, userId: number | null): Promise<AddResult> {
  const timezone = parseTimezone(body?.timezone);
  const s = await findSuggestion(id);

  if (s.kind === 'endpoint_policy') {
    let scans;
    try {
      scans = normalizePolicyScans(withTimezone(s.options.scans, timezone));
    } catch (err) {
      throw new ApiError(400, `This suggestion's policy is not valid here: ${err instanceof Error ? err.message : 'invalid'}`);
    }
    // The first free name (checked first so a taken one is not a logged
    // constraint error; the unique index still decides a race).
    const taken = new Set<string>((await query('SELECT LOWER(name) AS name FROM edr_scan_policies')).rows.map((r) => r.name));
    for (let n = 1; n <= 20; n++) {
      const name = n === 1 ? s.name : `${s.name} (${n})`;
      if (taken.has(name.toLowerCase())) continue;
      try {
        const policy = await createPolicy({ name, description: s.description, scans }, userId);
        return { suggestion_id: s.id, kind: s.kind, policy, inputs: s.inputs };
      } catch (err) {
        if (err instanceof ApiError && err.statusCode === 409) continue;
        throw err;
      }
    }
    throw new ApiError(409, `Policies named "${s.name}" (2) to (20) already exist; rename some first`);
  }

  const scheduled_scan = await ScheduledScanModel.create({ ...scheduleFromSuggestion(s, timezone), created_by: userId });
  return { suggestion_id: s.id, kind: s.kind, scheduled_scan, inputs: s.inputs };
}
