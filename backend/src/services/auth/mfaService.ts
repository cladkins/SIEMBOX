/**
 * TOTP MFA service for local accounts. Opt-in and additive: a user enrolls
 * voluntarily, and nothing here runs in the login path until that user has
 * mfa_enabled = true. The TOTP secret is stored encrypted (AES-256-GCM via
 * CredentialEncryption); recovery codes are stored as bcrypt hashes and consumed
 * on use.
 *
 * Checking a code (verifyCode):
 * - Its shape decides how it is checked. Six digits (spaces ignored) are tried
 *   as a TOTP code only, so a wrong guess costs no bcrypt compare at all;
 *   ten base32 characters (dashes and case ignored) as a recovery code only;
 *   anything else fails at once.
 * - Each TOTP code works once: the time step it matched is claimed with one
 *   UPDATE on users.mfa_last_totp_step, which succeeds only for a step later
 *   than the last one accepted. A replayed code, or the same code sent twice
 *   at once, fails ('replay').
 * - A recovery code is removed by value in one UPDATE, which succeeds for one
 *   request only, so two concurrent uses of a code can't both sign in.
 * - Fail-closed: a secret that doesn't decrypt rejects the code.
 * Throttling (how many wrong codes) is the caller's job (routes/auth.ts).
 */
import bcrypt from 'bcrypt';
import { CredentialEncryption } from '../credentials/credentialEncryption';
import { UserModel, User } from '../../models/User';
import { generateSecret, matchTotpStep, otpauthUrl } from './totp';
import { logger } from '../../utils/logger';

const ISSUER = 'SIEMBox';
const RECOVERY_CODE_COUNT = 10;
const TOTP_SHAPE = /^\d{6}$/;
const RECOVERY_SHAPE = /^[a-z2-7]{10}$/;

function encryptSecret(secret: string): string {
  return JSON.stringify(CredentialEncryption.encrypt(secret));
}

function decryptSecret(stored: string): string {
  const { encrypted, iv, authTag } = JSON.parse(stored);
  return CredentialEncryption.decrypt(encrypted, iv, authTag);
}

/** Generate human-friendly recovery codes (display form has a dash). */
function generateRecoveryCodes(n = RECOVERY_CODE_COUNT): string[] {
  const codes: string[] = [];
  for (let i = 0; i < n; i++) {
    const raw = generateSecret(10).toLowerCase().slice(0, 10); // 10 chars of base32 a-z2-7
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5, 10)}`);
  }
  return codes;
}

/** Normalize a recovery code for hashing/compare: lowercase, alnum only. */
function normalizeRecovery(code: string): string {
  return String(code).toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** How an MFA code reads: a TOTP code, a recovery code, or neither. */
export function codeShape(code: string): 'totp' | 'recovery' | 'invalid' {
  if (TOTP_SHAPE.test(String(code).replace(/\s/g, ''))) return 'totp';
  if (RECOVERY_SHAPE.test(normalizeRecovery(code))) return 'recovery';
  return 'invalid';
}

export type MfaFailure =
  /** Wrong code (or not shaped like one). */
  | 'invalid'
  /** A TOTP code whose time step was already used. */
  | 'replay'
  /** The secret doesn't decrypt (CREDENTIAL_ENCRYPTION_KEY changed or lost). */
  | 'unavailable';

export type MfaResult = { ok: true; method: 'totp' | 'recovery' } | { ok: false; reason: MfaFailure };

/**
 * Begin enrollment: generate a secret and store it as PENDING (mfa stays
 * disabled until the user proves possession with enable()). Returns the secret +
 * otpauth URI for the authenticator app.
 */
export async function startEnrollment(user: User): Promise<{ secret: string; otpauthUrl: string }> {
  const secret = generateSecret();
  await UserModel.setMfaPending(user.id, encryptSecret(secret));
  return { secret, otpauthUrl: otpauthUrl({ issuer: ISSUER, account: user.username, secret }) };
}

/** enable() can't go ahead: MFA is already on, or the pending enrollment changed meanwhile (409). */
export class MfaEnrollmentConflict extends Error {}

/**
 * Finish enrollment: verify a TOTP code against the PENDING secret, then enable
 * MFA and return one-time recovery codes (shown once). The code's time step is
 * recorded, so the same code can't then be used to sign in.
 *
 * Never once MFA is on: the code would then be checked against the active
 * secret with no throttle (the caller of enable only ever needs the secret
 * setup just handed them), and a hit would replace the recovery codes.
 */
export async function enable(user: User, code: string): Promise<{ recoveryCodes: string[] }> {
  if (user.mfa_enabled) throw new MfaEnrollmentConflict('MFA is already enabled; disable it first to re-enroll');
  if (!user.mfa_secret) throw new Error('No pending MFA enrollment — start setup first');
  const secret = decryptSecret(user.mfa_secret);
  const match = matchTotpStep(secret, code);
  if (!match) throw new Error('Invalid code');

  const recoveryCodes = generateRecoveryCodes();
  const hashes = await Promise.all(recoveryCodes.map((c) => bcrypt.hash(normalizeRecovery(c), 10)));
  if (!(await UserModel.enableMfa(user.id, hashes, match.step, user.mfa_secret))) {
    throw new MfaEnrollmentConflict('MFA setup changed while it was being enabled; start setup again');
  }
  return { recoveryCodes };
}

/**
 * Check an MFA code (sign-in, or disabling MFA) and use it up: see the file
 * comment. Database errors are thrown (the caller answers 500); a secret that
 * doesn't decrypt is a failure, never an exception.
 */
export async function verifyCode(user: User, code: string): Promise<MfaResult> {
  if (!user.mfa_enabled || !user.mfa_secret) return { ok: false, reason: 'invalid' };
  const shape = codeShape(code);
  if (shape === 'invalid') return { ok: false, reason: 'invalid' };

  if (shape === 'totp') {
    let secret: string;
    try {
      secret = decryptSecret(user.mfa_secret);
    } catch {
      // Never log the error object here — it derives from the decrypted mfa_secret
      // and could leak secret/plaintext material. A static message + userId is
      // enough to know an MFA decrypt failed for this user; fail closed.
      logger.error('[MFA] secret decrypt failed during login', { userId: user.id });
      return { ok: false, reason: 'unavailable' };
    }
    const match = matchTotpStep(secret, code);
    if (!match) return { ok: false, reason: 'invalid' };
    if (!(await UserModel.claimTotpStep(user.id, match.step))) return { ok: false, reason: 'replay' };
    return { ok: true, method: 'totp' };
  }

  const normalized = normalizeRecovery(code);
  const hashes: string[] = Array.isArray(user.mfa_recovery_codes) ? user.mfa_recovery_codes : [];
  for (const hash of hashes) {
    let matches = false;
    try {
      matches = await bcrypt.compare(normalized, hash);
    } catch {
      // ignore a malformed stored hash and keep checking the rest
    }
    if (!matches) continue;
    if (!(await UserModel.consumeRecoveryCode(user.id, hash))) return { ok: false, reason: 'invalid' };
    // Log only the user id — never anything derived from the recovery-code hashes.
    logger.info('[MFA] recovery code consumed', { userId: user.id });
    return { ok: true, method: 'recovery' };
  }
  return { ok: false, reason: 'invalid' };
}

/** Disable MFA once a current code (TOTP or recovery, used up like at sign-in) checks out. */
export async function disable(user: User, code: string): Promise<MfaResult> {
  const result = await verifyCode(user, code);
  if (result.ok) await UserModel.disableMfa(user.id);
  return result;
}
