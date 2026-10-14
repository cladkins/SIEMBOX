/**
 * MFA code checks (mfaService.ts verifyCode / enable / disable): a code's shape
 * decides how it is checked (a wrong 6-digit guess costs no bcrypt compare at
 * all, while a recovery-shaped one is compared), a TOTP time step is accepted
 * once, a recovery code is used up by one UPDATE, and a secret that doesn't
 * decrypt fails closed.
 *
 * Hermetic: UserModel's claim/consume/enable/disable are recorded stubs, so no
 * database is involved (the real UPDATEs run against Postgres in
 * routes/signInProtection.db.test.ts). Run with `npm test` (tsx --test).
 */
import { test, before, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import type { User } from '../../models/User';

process.env.CREDENTIAL_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');

let MfaService: typeof import('./mfaService');
let UserModel: typeof import('../../models/User').UserModel;
let totp: typeof import('./totp');
let CredentialEncryption: typeof import('../credentials/credentialEncryption').CredentialEncryption;

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const RECOVERY = 'abcde-fgh23';
let recoveryHash = '';
let user: User;

before(async () => {
  MfaService = await import('./mfaService');
  UserModel = (await import('../../models/User')).UserModel;
  totp = await import('./totp');
  CredentialEncryption = (await import('../credentials/credentialEncryption')).CredentialEncryption;
  recoveryHash = await bcrypt.hash('abcdefgh23', 4);
});

const claims: Array<[number, number]> = [];
const consumed: Array<[number, string]> = [];
let claimResult = true;
let consumeResult = true;
let disabledCalls = 0;
const restore: Array<() => void> = [];

/** A 6-digit code that is valid for none of the steps in the window right now. */
function wrongCode(): string {
  const now = Date.now();
  const valid = new Set([-1, 0, 1].map((offset) => totp.totp(SECRET, { now: now + offset * 30_000 })));
  for (let n = 0; ; n++) {
    const code = String(n).padStart(6, '0');
    if (!valid.has(code)) return code;
  }
}

beforeEach(() => {
  claims.length = 0;
  consumed.length = 0;
  claimResult = true;
  consumeResult = true;
  disabledCalls = 0;
  user = {
    id: 42,
    username: 'mfa-user',
    email: 'mfa@siembox.invalid',
    password_hash: 'x',
    role: 'viewer',
    enabled: true,
    last_login: null,
    created_at: new Date(),
    updated_at: new Date(),
    mfa_enabled: true,
    mfa_secret: JSON.stringify(CredentialEncryption.encrypt(SECRET)),
    mfa_recovery_codes: [recoveryHash, '$2b$04$not-a-real-hash-but-skipped-quietly'],
  };
  const stubs = [
    mock.method(UserModel, 'claimTotpStep', async (id: number, step: number) => {
      claims.push([id, step]);
      return claimResult;
    }),
    mock.method(UserModel, 'consumeRecoveryCode', async (id: number, hash: string) => {
      consumed.push([id, hash]);
      return consumeResult;
    }),
    mock.method(UserModel, 'disableMfa', async () => {
      disabledCalls++;
    }),
  ];
  for (const stub of stubs) restore.push(() => stub.mock.restore());
});

afterEach(() => {
  while (restore.length) restore.pop()!();
});

function countCompares() {
  const original = bcrypt.compare;
  const spy = mock.method(bcrypt, 'compare', (...args: Parameters<typeof bcrypt.compare>) =>
    (original as (...a: unknown[]) => unknown).apply(bcrypt, args)
  );
  restore.push(() => spy.mock.restore());
  return () => spy.mock.callCount();
}

test('a wrong 6-digit code makes no bcrypt compare at all', async () => {
  const compares = countCompares();
  const wrong = wrongCode();
  assert.deepEqual(await MfaService.verifyCode(user, wrong), { ok: false, reason: 'invalid' });
  assert.deepEqual(await MfaService.verifyCode(user, `${wrong.slice(0, 3)} ${wrong.slice(3)}`), {
    ok: false,
    reason: 'invalid',
  });
  assert.equal(compares(), 0);
  assert.equal(claims.length, 0, 'nothing claimed for a wrong code');
});

test('input shaped like neither code fails at once, with no compare', async () => {
  const compares = countCompares();
  for (const junk of ['', '12345', '1234567', 'not-a-code', 'abcde-fgh2', 'abcde-fgh231', 'abcde-fgh18']) {
    assert.deepEqual(await MfaService.verifyCode(user, junk), { ok: false, reason: 'invalid' }, junk);
  }
  assert.equal(compares(), 0);
});

test('a recovery-shaped code is compared, and used up by one UPDATE', async () => {
  const compares = countCompares();
  assert.deepEqual(await MfaService.verifyCode(user, 'ABCDE-FGH23'), { ok: true, method: 'recovery' });
  assert.ok(compares() >= 1);
  assert.deepEqual(consumed, [[42, recoveryHash]]);

  // A wrong recovery-shaped code is compared against every stored hash.
  const before = compares();
  assert.deepEqual(await MfaService.verifyCode(user, 'zzzzz-zzzzz'), { ok: false, reason: 'invalid' });
  assert.equal(compares() - before, 2);
});

test('a recovery code whose consume UPDATE touches no row is rejected (another request used it)', async () => {
  consumeResult = false;
  assert.deepEqual(await MfaService.verifyCode(user, RECOVERY), { ok: false, reason: 'invalid' });
  assert.equal(consumed.length, 1);
});

test('a right TOTP code is accepted once: its step is claimed, and a replay is refused', async () => {
  const now = Date.now();
  const code = totp.totp(SECRET, { now });
  assert.deepEqual(await MfaService.verifyCode(user, code), { ok: true, method: 'totp' });
  assert.equal(claims.length, 1);
  const [id, step] = claims[0];
  assert.equal(id, 42);
  assert.ok(Math.abs(step - Math.floor(now / 30_000)) <= 1, 'the matched time step');

  claimResult = false; // the UPDATE found a step at or after this one
  assert.deepEqual(await MfaService.verifyCode(user, code), { ok: false, reason: 'replay' });
});

test('a secret that does not decrypt fails closed', async () => {
  user.mfa_secret = JSON.stringify({ encrypted: 'AAAA', iv: 'AAAAAAAAAAAAAAAA', authTag: 'AAAAAAAAAAAAAAAAAAAAAA==' });
  assert.deepEqual(await MfaService.verifyCode(user, totp.totp(SECRET)), { ok: false, reason: 'unavailable' });
  assert.equal(claims.length, 0);
});

test('no MFA enrolled: every code fails', async () => {
  user.mfa_enabled = false;
  assert.deepEqual(await MfaService.verifyCode(user, totp.totp(SECRET)), { ok: false, reason: 'invalid' });
});

test('enable() records the step of the code that proved the enrollment', async () => {
  const enabled: Array<[number, number, number, string]> = [];
  const stub = mock.method(UserModel, 'enableMfa', async (id: number, hashes: string[], step: number, pending: string) => {
    enabled.push([id, hashes.length, step, pending]);
    return true;
  });
  restore.push(() => stub.mock.restore());
  user.mfa_enabled = false;
  const now = Date.now();
  const { recoveryCodes } = await MfaService.enable(user, totp.totp(SECRET, { now }));
  assert.equal(recoveryCodes.length, 10);
  for (const code of recoveryCodes) assert.equal(MfaService.codeShape(code), 'recovery');
  assert.equal(enabled.length, 1);
  assert.equal(enabled[0][1], 10);
  assert.ok(Math.abs(enabled[0][2] - Math.floor(now / 30_000)) <= 1);
  assert.equal(enabled[0][3], user.mfa_secret, 'only for the pending secret the code was checked against');
  await assert.rejects(MfaService.enable(user, wrongCode()), /Invalid code/);
});

test('enable() never runs once MFA is on, nor saves over an enrollment that changed meanwhile', async () => {
  let saves = 0;
  let saved = true;
  const stub = mock.method(UserModel, 'enableMfa', async () => {
    saves++;
    return saved;
  });
  restore.push(() => stub.mock.restore());
  // MFA on: refused before the code is even checked against the active secret.
  for (const code of [totp.totp(SECRET), wrongCode()]) {
    await assert.rejects(MfaService.enable(user, code), (error: unknown) => error instanceof MfaService.MfaEnrollmentConflict);
  }
  assert.equal(saves, 0);
  // Pending, but enabled (or set up again) by another request in between: nothing is enabled.
  user.mfa_enabled = false;
  saved = false;
  await assert.rejects(MfaService.enable(user, totp.totp(SECRET)), (error: unknown) => error instanceof MfaService.MfaEnrollmentConflict);
  assert.equal(saves, 1);
});

test('disable() claims the code like a sign-in, and disables only when it checks out', async () => {
  assert.deepEqual(await MfaService.disable(user, 'zzzzz-zzzzz'), { ok: false, reason: 'invalid' });
  assert.equal(disabledCalls, 0);
  assert.deepEqual(await MfaService.disable(user, totp.totp(SECRET)), { ok: true, method: 'totp' });
  assert.equal(claims.length, 1);
  assert.equal(disabledCalls, 1);
});
