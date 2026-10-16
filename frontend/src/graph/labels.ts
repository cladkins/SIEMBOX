/**
 * Text from logs, alerts and findings is attacker-controlled. The server
 * already cleans labels and facts (backend/src/services/graph/labels.ts);
 * this is the same sanitizer, run again on everything the page shows, as
 * defence in depth:
 *
 *   - C0 and C1 control characters (U+0000-U+001F, U+007F-U+009F) are removed;
 *   - so are the bidi marks and overrides that can make text read differently
 *     from what it is (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069);
 *   - runs of whitespace become one space, and the ends are trimmed;
 *   - the result is cut to a maximum length (in code points), ending in "…".
 *
 * The page renders text as Cytoscape canvas text or Vue interpolation only,
 * never as HTML (no v-html anywhere in the graph).
 */

/** Longest label on the canvas; the details panel shows the full label. */
export const CANVAS_LABEL = 24;
/** Longest label the server sends. */
export const MAX_LABEL = 64;
/** Longest string fact the server sends. */
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
export function sanitizeText(value: unknown, max: number = MAX_FACT): string {
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

/** A label as the canvas draws it: sanitized, at most 24 characters. */
export const canvasLabel = (value: unknown): string => sanitizeText(value, CANVAS_LABEL);
/** A label as the panel and the list show it, in full (the server's 64). */
export const fullLabel = (value: unknown): string => sanitizeText(value, MAX_LABEL);
/** A fact value as text. */
export const factText = (value: unknown): string => sanitizeText(value, MAX_FACT);

/** "1,204", or "1,000+" when the server stopped counting. */
export function formatCount(total: number, capped = false): string {
  return capped ? `${(1000).toLocaleString('en-US')}+` : total.toLocaleString('en-US');
}

/** "1 alert" / "3 alerts". */
export function plural(n: number, word: string, many = `${word}s`): string {
  return `${n.toLocaleString('en-US')} ${n === 1 ? word : many}`;
}
