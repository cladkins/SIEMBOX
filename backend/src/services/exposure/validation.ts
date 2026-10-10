/**
 * Strict validation for what operators can put under exposure monitoring.
 *
 * Domains must be bare, lowercase DNS hostnames with a real TLD: no scheme,
 * port, path, query, user info, wildcard or IP address, at most 253
 * characters, 1-63 characters per label. Internationalized names are accepted
 * in their ASCII (punycode, "xn--") form only. Emails are a conservative
 * dot-atom local part plus a domain that passes the same check. Values are
 * normalized (trimmed, lowercased, trailing root dot dropped) before storage,
 * so the UNIQUE constraints see one spelling per domain/address.
 */
import { isIP } from 'net';
import type { IdentityKind } from '../../models/Exposure';

export type ValidationResult = { ok: true; value: string } | { ok: false; error: string };

const MAX_DOMAIN_LENGTH = 253;
const MAX_EMAIL_LENGTH = 254;
const MAX_LOCAL_PART_LENGTH = 64;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
// Alphabetic TLDs, or punycode TLDs (xn--...). All-numeric TLDs are never valid.
const TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
// RFC 5322 dot-atom: atext runs separated by single dots (no quoted local parts).
const LOCAL_PART_RE = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;

const fail = (error: string): ValidationResult => ({ ok: false, error });

export function normalizeDomain(input: unknown): ValidationResult {
  if (typeof input !== 'string') return fail('domain must be a string');
  let domain = input.trim().toLowerCase();
  if (!domain) return fail('domain is required');
  if (domain.length > MAX_DOMAIN_LENGTH + 1)
    return fail(`domain must be at most ${MAX_DOMAIN_LENGTH} characters`);
  if (/\s/.test(domain)) return fail('domain must not contain spaces');
  if (/[^\x21-\x7e]/.test(domain)) {
    return fail('enter internationalized domains in their ASCII (punycode, "xn--") form');
  }
  if (domain.endsWith('.')) domain = domain.slice(0, -1); // fully-qualified (root dot) form
  if (isIP(domain) || isIP(domain.replace(/^\[(.*)\]$/, '$1')))
    return fail('IP addresses are not domains');
  if (domain.includes('*'))
    return fail('wildcards are not supported; enter the parent domain (e.g. example.com)');
  if (/[/?#@\\:[\]]/.test(domain)) {
    return fail('enter a bare domain such as example.com, without a scheme, port, path or user');
  }
  if (domain.length > MAX_DOMAIN_LENGTH)
    return fail(`domain must be at most ${MAX_DOMAIN_LENGTH} characters`);

  const labels = domain.split('.');
  if (labels.length < 2) return fail('domain must include a top-level domain (e.g. example.com)');
  for (const label of labels) {
    if (!LABEL_RE.test(label)) {
      return fail(
        'each domain label must be 1-63 letters, digits or hyphens, and must not start or end with a hyphen'
      );
    }
  }
  if (!TLD_RE.test(labels[labels.length - 1]))
    return fail('domain has an invalid top-level domain');
  return { ok: true, value: domain };
}

export function normalizeEmail(input: unknown): ValidationResult {
  if (typeof input !== 'string') return fail('email must be a string');
  const email = input.trim().toLowerCase();
  if (!email) return fail('email is required');
  if (email.length > MAX_EMAIL_LENGTH)
    return fail(`email must be at most ${MAX_EMAIL_LENGTH} characters`);
  const at = email.indexOf('@');
  if (at <= 0 || at !== email.lastIndexOf('@'))
    return fail('enter a single address such as alice@example.com');

  const local = email.slice(0, at);
  if (local.length > MAX_LOCAL_PART_LENGTH || !LOCAL_PART_RE.test(local)) {
    return fail('the part before "@" is not a valid mailbox name');
  }
  const domain = normalizeDomain(email.slice(at + 1));
  if (!domain.ok) return fail(`email domain: ${domain.error}`);
  return { ok: true, value: `${local}@${domain.value}` };
}

export const IDENTITY_KINDS: readonly IdentityKind[] = ['email', 'email_domain'];

export function isIdentityKind(value: unknown): value is IdentityKind {
  return typeof value === 'string' && (IDENTITY_KINDS as readonly string[]).includes(value);
}

/** Validate a monitored identity's value for its kind. */
export function normalizeIdentityValue(kind: IdentityKind, value: unknown): ValidationResult {
  return kind === 'email' ? normalizeEmail(value) : normalizeDomain(value);
}
