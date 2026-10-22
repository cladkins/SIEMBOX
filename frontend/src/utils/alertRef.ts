/**
 * Human-readable alert references: `ALR-<id>` (ALR-4821).
 *
 * Mirrors backend/src/services/alerts/alertRef.ts: the reference is the
 * alert's permanent id with a prefix, so it needs no lookup. Every place that
 * shows, links or parses an alert reference goes through this module rather
 * than building the string by hand.
 */
import type { TokenizerAndRendererExtension } from 'marked';

export const ALERT_REF_PREFIX = 'ALR-';

/** Largest id an `alerts.id` SERIAL (int4) column can hold. */
export const MAX_ALERT_ID = 2147483647;

// Anchored, no nested quantifiers: linear on any input.
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

/** In-app route that opens the alert: `/alerts?alert=ALR-4821`. */
export function alertRefPath(id: number): string {
  return `/alerts?alert=${formatAlertRef(id)}`;
}

/** Absolute deep link for "Copy link" (origin is the UI's, e.g. window.location.origin). */
export function alertRefUrl(id: number, origin: string): string {
  return `${origin.replace(/\/+$/, '')}${alertRefPath(id)}`;
}

/** The alert id an in-app alert link points at, or null for any other href. */
export function alertIdFromHref(href: string | null | undefined): number | null {
  if (typeof href !== 'string') return null;
  const m = /^\/alerts\?alert=(ALR-[1-9][0-9]{0,9})$/.exec(href);
  return m ? parseAlertRef(m[1]) : null;
}

// A reference is a whole word: never glued to a letter, digit, "_" or "-"
// on either side, so "XALR-5", "MY_ALR-5" and "ALR-5-6" stay plain text.
const WORD_CHAR = /[0-9A-Za-z_-]$/;
// Where marked should stop a text run to try the tokenizer. marked hands
// start() the text after its first character, whose predecessor it cannot see,
// so the tokenizer re-checks the preceding token itself.
const REF_START = /(?:^|[^0-9A-Za-z_-])ALR-[1-9]/i;
const REF_TOKEN = /^ALR-([1-9][0-9]{0,9})(?![0-9A-Za-z_-])/i;

/**
 * marked extension that turns ALR-#### in AI output into a link to the
 * alert. The href and text are rebuilt from the parsed integer alone, so
 * nothing the model wrote reaches the HTML. References inside code spans,
 * code blocks and existing links are left as they are.
 */
export const alertRefMarkdown: TokenizerAndRendererExtension = {
  name: 'alertRef',
  level: 'inline',
  start(src: string) {
    const m = REF_START.exec(src);
    // m[0] is "ALR-1" at the very start, or one boundary character then "ALR-1".
    return m ? m.index + m[0].length - 'ALR-1'.length : undefined;
  },
  tokenizer(src: string, tokens) {
    if (this.lexer.state.inLink) return undefined;
    const prev = tokens[tokens.length - 1];
    if (prev && WORD_CHAR.test(prev.raw)) return undefined;
    const m = REF_TOKEN.exec(src);
    if (!m) return undefined;
    const id = parseAlertRef(m[1]);
    if (id === null) return undefined;
    return { type: 'alertRef', raw: m[0], alertId: id };
  },
  renderer(token) {
    const id = parseAlertRef(token.alertId);
    if (id === null) return '';
    const ref = formatAlertRef(id);
    return `<a href="${alertRefPath(id)}" class="alert-ref-link" data-alert-ref="${ref}">${ref}</a>`;
  },
};
