/**
 * The HIBP provider's `usable` flag without a database: whether a stored key
 * value decrypts with the current CREDENTIAL_ENCRYPTION_KEY. The UI uses it to
 * tell "saved and working" from "saved, but the backend can't decrypt it".
 * Run with `npm test` (tsx --test).
 */
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { CredentialEncryption } from '../credentials/credentialEncryption';
import { isStoredHibpKeyUsable, storedHibpKeyMatches } from './settings';

const KEY_A = 'a1'.repeat(32);
const KEY_B = 'b2'.repeat(32);
const HIBP_KEY = '0123456789abcdef0123456789abcdef';
const originalKey = process.env.CREDENTIAL_ENCRYPTION_KEY;
const originalDecrypt = CredentialEncryption.decrypt;

afterEach(() => {
  if (originalKey === undefined) delete process.env.CREDENTIAL_ENCRYPTION_KEY;
  else process.env.CREDENTIAL_ENCRYPTION_KEY = originalKey;
  CredentialEncryption.decrypt = originalDecrypt;
});

/** The exposure_hibp_key value saveHibpProvider() writes, encrypted with `encryptionKey`. */
function storedUnder(encryptionKey: string): string {
  process.env.CREDENTIAL_ENCRYPTION_KEY = encryptionKey;
  return JSON.stringify(CredentialEncryption.encrypt(HIBP_KEY));
}

test('usable only while the stored key decrypts with the current CREDENTIAL_ENCRYPTION_KEY', () => {
  const stored = storedUnder(KEY_A);
  assert.equal(isStoredHibpKeyUsable(stored), true);

  process.env.CREDENTIAL_ENCRYPTION_KEY = KEY_B; // changed since the key was saved
  assert.equal(isStoredHibpKeyUsable(stored), false);

  delete process.env.CREDENTIAL_ENCRYPTION_KEY; // removed from the environment
  assert.equal(isStoredHibpKeyUsable(stored), false);

  process.env.CREDENTIAL_ENCRYPTION_KEY = 'not-hex'; // malformed
  assert.equal(isStoredHibpKeyUsable(stored), false);

  process.env.CREDENTIAL_ENCRYPTION_KEY = KEY_A; // the original key put back
  assert.equal(isStoredHibpKeyUsable(stored), true);
});

test('no key saved, or a value that is not an encrypted key, is not usable', () => {
  process.env.CREDENTIAL_ENCRYPTION_KEY = KEY_A;
  for (const stored of ['', HIBP_KEY, 'null', '{}', '[]', '{"encrypted":"x","iv":"y","authTag":"z"}']) {
    assert.equal(isStoredHibpKeyUsable(stored), false, JSON.stringify(stored));
  }
});

test('a key that does not decrypt is tried once, not on every status request', () => {
  const stored = storedUnder(KEY_A);
  process.env.CREDENTIAL_ENCRYPTION_KEY = KEY_B;
  let calls = 0;
  CredentialEncryption.decrypt = (...args: Parameters<typeof originalDecrypt>) => {
    calls++;
    return originalDecrypt.apply(CredentialEncryption, args);
  };
  for (let i = 0; i < 5; i++) assert.equal(isStoredHibpKeyUsable(stored), false);
  assert.equal(calls, 1);

  // A new value (the key saved again) or a different encryption key is re-checked.
  const resaved = storedUnder(KEY_B);
  assert.equal(isStoredHibpKeyUsable(resaved), true);
  assert.equal(calls, 2);
  process.env.CREDENTIAL_ENCRYPTION_KEY = KEY_A;
  assert.equal(isStoredHibpKeyUsable(resaved), false);
  assert.equal(calls, 3);
});

test('storedHibpKeyMatches: the same key re-entered matches; another key, a clear or an unreadable value does not', () => {
  const stored = storedUnder(KEY_A);
  assert.equal(storedHibpKeyMatches(stored, HIBP_KEY), true);
  assert.equal(storedHibpKeyMatches(stored, 'f'.repeat(32)), false);
  assert.equal(storedHibpKeyMatches(stored, HIBP_KEY.slice(1)), false);
  assert.equal(storedHibpKeyMatches(stored, null), false, 'clearing a saved key is a change');
  assert.equal(storedHibpKeyMatches(stored, ''), false);
  assert.equal(storedHibpKeyMatches('', null), true, 'nothing saved, nothing to clear');
  assert.equal(storedHibpKeyMatches('', HIBP_KEY), false);

  process.env.CREDENTIAL_ENCRYPTION_KEY = KEY_B; // it can't be decrypted any more
  assert.equal(storedHibpKeyMatches(stored, HIBP_KEY), false, 'saving it again re-encrypts it');
  assert.equal(storedHibpKeyMatches(stored, null), false);
});
