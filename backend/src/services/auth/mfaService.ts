/**
 * TOTP MFA service for local accounts. Opt-in and additive: a user enrolls
 * voluntarily, and nothing here runs in the login path until that user has
 * mfa_enabled = true. The TOTP secret is stored encrypted (AES-256-GCM via
 * CredentialEncryption); recovery codes are stored as bcrypt hashes and consumed
 * on use.
 */
import bcrypt from 'bcrypt';
import { CredentialEncryption } from '../credentials/credentialEncryption';
import { UserModel, User } from '../../models/User';
import { generateSecret, verifyTotp, otpauthUrl } from './totp';
import { logger } from '../../utils/logger';

const ISSUER = 'SIEMBox';
const RECOVERY_CODE_COUNT = 10;

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

/**
 * Finish enrollment: verify a TOTP code against the pending secret, then enable
 * MFA and return one-time recovery codes (shown once).
 */
export async function enable(user: User, code: string): Promise<{ recoveryCodes: string[] }> {
  if (!user.mfa_secret) throw new Error('No pending MFA enrollment — start setup first');
  const secret = decryptSecret(user.mfa_secret);
  if (!verifyTotp(secret, code)) throw new Error('Invalid code');

  const recoveryCodes = generateRecoveryCodes();
  const hashes = await Promise.all(recoveryCodes.map((c) => bcrypt.hash(normalizeRecovery(c), 10)));
  await UserModel.enableMfa(user.id, hashes);
  return { recoveryCodes };
}

/**
 * Verify an MFA code at login: TOTP first, then a one-time recovery code
 * (consumed on success). Fail-closed: any decrypt/parse error returns false
 * rather than throwing, so a key/config problem rejects MFA instead of crashing
 * the login route.
 */
export async function verifyLogin(user: User, code: string): Promise<boolean> {
  if (!user.mfa_enabled || !user.mfa_secret) return false;
  try {
    const secret = decryptSecret(user.mfa_secret);
    if (verifyTotp(secret, code)) return true;
  } catch (e) {
    logger.error('[MFA] secret decrypt failed during login', {
      userId: user.id,
      error: e instanceof Error ? e.message : String(e),
    });
    return false;
  }

  const hashes: string[] = Array.isArray(user.mfa_recovery_codes) ? user.mfa_recovery_codes : [];
  const normalized = normalizeRecovery(code);
  if (!normalized) return false;
  for (let i = 0; i < hashes.length; i++) {
    try {
      if (await bcrypt.compare(normalized, hashes[i])) {
        const remaining = hashes.filter((_, j) => j !== i);
        await UserModel.setRecoveryCodes(user.id, remaining);
        // Log only the user id — never anything derived from the recovery-code hashes.
        logger.info('[MFA] recovery code consumed', { userId: user.id });
        return true;
      }
    } catch {
      // ignore a malformed stored hash and keep checking the rest
    }
  }
  return false;
}

/** Disable MFA. Requires a valid current code (TOTP or recovery). */
export async function disable(user: User, code: string): Promise<void> {
  const ok = await verifyLogin(user, code);
  if (!ok) throw new Error('Invalid code');
  await UserModel.disableMfa(user.id);
}
