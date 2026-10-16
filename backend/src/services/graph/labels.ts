/**
 * Text that reaches the graph from logs, alerts and findings is
 * attacker-controlled (a username, a host name, an alert title built from
 * them). Labels and string facts are cleaned here before they are sent:
 *
 *   - C0 and C1 control characters (U+0000-U+001F, U+007F-U+009F) are removed;
 *   - so are the bidi marks and overrides that can make text read differently
 *     from what it is (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069);
 *   - runs of whitespace become one space, and the ends are trimmed;
 *   - the result is cut to a maximum length (in code points), ending in "…".
 *
 * The frontend renders these as canvas text or Vue interpolation only, never
 * as HTML; this is defence in depth, plus a bound on response size. Masking
 * (for read-only display links) is not part of v1: the owner dropped
 * graph-specific display links.
 */

/** Longest node label. */
export const MAX_LABEL = 64;
/** Longest string fact (alerts.title is VARCHAR(255)). */
export const MAX_FACT = 256;

function isStripped(cp: number): boolean {
  return (
    cp <= 0x1f ||
    (cp >= 0x7f && cp <= 0x9f) ||
    cp === 0x061c ||
    cp === 0x200e ||
    cp === 0x200f ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2066 && cp <= 0x2069)
  );
}

/** True when `value` holds a character the sanitizer would remove. */
export function hasUnsafeChars(value: string): boolean {
  for (const ch of value) {
    if (isStripped(ch.codePointAt(0)!)) return true;
  }
  return false;
}

/** `value` without control and bidi characters, with whitespace collapsed and trimmed, at most `max` code points. */
export function sanitizeText(value: unknown, max: number = MAX_LABEL): string {
  if (value === null || value === undefined) return '';
  const out: string[] = [];
  let pendingSpace = false;
  for (const ch of String(value)) {
    // Tabs and newlines are controls too, but they separate words: one space.
    if (/\s/u.test(ch)) {
      pendingSpace = out.length > 0;
      continue;
    }
    if (isStripped(ch.codePointAt(0)!)) continue;
    if (pendingSpace) {
      out.push(' ');
      pendingSpace = false;
    }
    out.push(ch);
    if (out.length > max) break;
  }
  if (out.length <= max) return out.join('');
  return `${out.slice(0, Math.max(0, max - 1)).join('').trimEnd()}…`;
}

export const sanitizeLabel = (value: unknown): string => sanitizeText(value, MAX_LABEL);
export const sanitizeFact = (value: unknown): string => sanitizeText(value, MAX_FACT);
