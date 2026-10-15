/**
 * The password-change rules (passwordChange.ts): what a new password must be
 * (8 to 1024 characters, not the default password in any letter case, not the
 * current one), the exact default-password check sign-in runs after a correct
 * password, and the 403 PASSWORD_CHANGE_REQUIRED body for each reason.
 * Pure: no database. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  PASSWORD_CHANGE_REASONS,
  SHIPPED_DEFAULT_PASSWORD,
  assignedPasswordProblem,
  isPasswordChangeReason,
  isShippedDefaultPassword,
  newPasswordProblem,
  passwordChangeRequiredBody,
} from './passwordChange';

const LENGTH = 'New password must be 8 to 1024 characters';
const SAME = 'New password must be different from the current one';
const DEFAULT = "The default password can't be used";

test('the shipped default is "changeme"', () => {
  assert.equal(SHIPPED_DEFAULT_PASSWORD, 'changeme');
});

test('newPasswordProblem: 8 to 1024 characters', () => {
  assert.equal(newPasswordProblem('a'.repeat(8)), null);
  assert.equal(newPasswordProblem('a'.repeat(1024)), null);
  assert.equal(newPasswordProblem('a'.repeat(7)), LENGTH);
  assert.equal(newPasswordProblem('a'.repeat(1025)), LENGTH);
  assert.equal(newPasswordProblem(''), LENGTH);
  for (const notAString of [undefined, null, 12345678, ['changeme1'], { length: 9 }]) {
    assert.equal(newPasswordProblem(notAString), LENGTH, JSON.stringify(notAString));
  }
});

test('newPasswordProblem: the default password is refused in any case, and only it', () => {
  for (const password of ['changeme', 'CHANGEME', 'ChangeMe', 'cHaNgEmE']) {
    assert.equal(newPasswordProblem(password), DEFAULT, password);
  }
  for (const password of ['changeme1', ' changeme', 'changeme ', 'changemechangeme', 'change me']) {
    assert.equal(newPasswordProblem(password), null, password);
  }
});

test('newPasswordProblem: with the current password, an identical one is refused', () => {
  assert.equal(newPasswordProblem('correct horse', 'correct horse'), SAME);
  assert.equal(newPasswordProblem('correct horse', 'battery staple'), null);
  // Unchanged is said first: the user typed what they already have.
  assert.equal(newPasswordProblem('changeme', 'changeme'), SAME);
  assert.equal(newPasswordProblem('CHANGEME', 'changeme'), DEFAULT);
});

test('assignedPasswordProblem: an admin-set password follows the same rules, in its own words', () => {
  assert.equal(assignedPasswordProblem('a'.repeat(8)), null);
  assert.equal(assignedPasswordProblem('a'.repeat(1024)), null);
  assert.equal(assignedPasswordProblem('a'.repeat(7)), 'Password must be 8 to 1024 characters');
  assert.equal(assignedPasswordProblem('a'.repeat(1025)), 'Password must be 8 to 1024 characters');
  assert.equal(assignedPasswordProblem(12345678), 'Password must be 8 to 1024 characters');
  for (const password of ['changeme', 'CHANGEME', 'ChangeMe']) {
    assert.equal(assignedPasswordProblem(password), "Password can't be the default password", password);
  }
  assert.equal(assignedPasswordProblem('changeme1'), null);
});

test('isShippedDefaultPassword is exact', () => {
  assert.equal(isShippedDefaultPassword('changeme'), true);
  for (const password of ['changeme ', ' changeme', 'Changeme', 'CHANGEME', 'changeme1', '']) {
    assert.equal(isShippedDefaultPassword(password), false, JSON.stringify(password));
  }
});

test('isPasswordChangeReason accepts the four reasons only', () => {
  assert.deepEqual([...PASSWORD_CHANGE_REASONS], ['initial', 'default', 'admin', 'cli']);
  for (const reason of PASSWORD_CHANGE_REASONS) assert.equal(isPasswordChangeReason(reason), true);
  for (const other of ['', 'Initial', 'seed', null, undefined, 1]) assert.equal(isPasswordChangeReason(other), false);
});

test('passwordChangeRequiredBody: the shape, and a message for each reason', () => {
  const prefix = 'Choose a new password before doing anything else (PUT /api/auth/me/password): ';
  const expected: Record<string, string> = {
    initial: 'this is the password the account was created with.',
    default: "this account uses SIEMBox's default password.",
    admin: 'an administrator set a temporary password for this account.',
    cli: 'the password was reset from the command line.',
  };
  for (const reason of PASSWORD_CHANGE_REASONS) {
    assert.deepEqual(passwordChangeRequiredBody(reason), {
      status: 'error',
      statusCode: 403,
      code: 'PASSWORD_CHANGE_REQUIRED',
      reason,
      message: prefix + expected[reason],
    });
  }
  assert.deepEqual(passwordChangeRequiredBody(null), {
    status: 'error',
    statusCode: 403,
    code: 'PASSWORD_CHANGE_REQUIRED',
    reason: null,
    message: `${prefix}this account must choose a new password.`,
  });
  // A value the database should never hold is answered generically, not echoed.
  for (const value of ['bogus', 'toString', '__proto__']) {
    const odd = passwordChangeRequiredBody(value as never);
    assert.equal(odd.reason, null, value);
    assert.equal(odd.message, `${prefix}this account must choose a new password.`, value);
  }
});
