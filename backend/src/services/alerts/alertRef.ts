/**
 * Human-readable alert references: `ALR-<id>` (ALR-4821).
 *
 * The reference is derived from the alert's permanent id (a SERIAL primary
 * key that Postgres never reuses, even after deletes), so it needs no column,
 * no migration and can never drift from the row it names. Everything that
 * shows, accepts or cites an alert goes through these functions; nobody
 * builds the string by hand. frontend/src/utils/alertRef.ts mirrors this file.
 */

export const ALERT_REF_PREFIX = 'ALR-';

/** Largest id an `alerts.id` SERIAL (int4) column can hold. */
export const MAX_ALERT_ID = 2147483647;

// Anchored, no nested quantifiers: one optional prefix, then 1-10 digits with
// no leading zero. Linear on any input; the length cap below bounds it anyway.
const REF_PATTERN = /^(?:alr-|#)?([1-9][0-9]{0,9})$/i;
const MAX_INPUT_LENGTH = 32;

/** `ALR-4821` for alert id 4821. */
export function formatAlertRef(id: number): string {
  return `${ALERT_REF_PREFIX}${id}`;
}

/**
 * The alert id named by `input`, or null when it is not a valid reference.
 * Accepts `ALR-4821`, `alr-4821`, `4821` and `#4821` (surrounding whitespace
 * ignored), and a positive integer number. Rejects 0, leading zeros, signs,
 * decimals, inner whitespace and ids beyond the int4 range.
 */
export function parseAlertRef(input: unknown): number | null {
  if (typeof input === 'number') {
    return Number.isInteger(input) && input >= 1 && input <= MAX_ALERT_ID ? input : null;
  }
  if (typeof input !== 'string' || input.length > MAX_INPUT_LENGTH) return null;
  const m = REF_PATTERN.exec(input.trim());
  if (!m) return null;
  const id = Number(m[1]);
  return id <= MAX_ALERT_ID ? id : null;
}

/** The row with `ref` added. */
export function withAlertRef<T extends { id: number }>(row: T): T & { ref: string } {
  return { ...row, ref: formatAlertRef(row.id) };
}
