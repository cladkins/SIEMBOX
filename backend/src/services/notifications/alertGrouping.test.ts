/**
 * Per-EVENT alert notifications.
 *
 * The rules engine evaluates every rule against every log with no early exit,
 * because rules are independent hypotheses about the same evidence rather than
 * candidates competing to own it. One request can therefore raise several
 * alerts — `;cat /etc/passwd` satisfies both PROXY-001 (suspicious punctuation)
 * and PROXY-002 (command-injection signature).
 *
 * That fan-out used to mean one notification per rule: three pages for one
 * event, reading as three problems instead of one seen three ways. These pin
 * the grouped message, and — more importantly — the guarantee that grouping
 * never announces an alert the min-severity gate would have filtered on its
 * own. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAlertMessage, buildAlertGroupMessage, severityPasses } from './notificationService';

const SQLI = {
  severity: 'high',
  ruleName: 'SQL Injection Attempt',
  title: 'SQL Injection Attempt from 203.0.113.59',
  description: 'SQL injection pattern detected from 203.0.113.59.',
};
const CMDI = {
  severity: 'critical',
  ruleName: 'Command Injection Attempt',
  title: 'Command Injection Attempt from 203.0.113.59',
  description: 'Command injection pattern detected from 203.0.113.59.',
};
const SCANNER = {
  severity: 'medium',
  ruleName: 'Security Scanner User-Agent',
  title: 'Security Scanner User-Agent from 203.0.113.59',
};

test('a lone alert produces exactly the message it always did', () => {
  // The no-regression guarantee: grouping must not change the single-rule case,
  // which is what the EDR path and most events still produce.
  assert.deepEqual(buildAlertGroupMessage([SQLI]), buildAlertMessage(SQLI));
});

test('a group names every rule that fired', () => {
  const msg = buildAlertGroupMessage([SQLI, CMDI, SCANNER]);

  for (const a of [SQLI, CMDI, SCANNER]) {
    assert.ok(msg.body.includes(a.ruleName), `body does not mention ${a.ruleName}`);
  }
  assert.match(msg.body, /^3 detection rules matched a single event\./);
});

test('the worst severity leads the title and sets the message severity', () => {
  // What decides how urgently someone has to look. CMDI is critical but is not
  // first in the list, so this also pins that order of arrival does not win.
  const msg = buildAlertGroupMessage([SQLI, CMDI, SCANNER]);

  assert.equal(msg.severity, 'critical');
  assert.match(msg.title, /^\[SIEMBox\] CRITICAL alert: /);
  assert.ok(msg.title.includes(CMDI.title), 'the worst alert should title the message');
});

test('the title says how many other rules corroborated it', () => {
  assert.match(buildAlertGroupMessage([SQLI, CMDI]).title, /\(\+1 more\)$/);
  assert.match(buildAlertGroupMessage([SQLI, CMDI, SCANNER]).title, /\(\+2 more\)$/);
});

test('each severity is shown per rule, so a low finding is not read as critical', () => {
  const msg = buildAlertGroupMessage([CMDI, SCANNER]);

  assert.ok(msg.body.includes('[CRITICAL] Command Injection Attempt'));
  assert.ok(msg.body.includes('[MEDIUM] Security Scanner User-Agent'));
});

test('an alert with no description does not leave a dangling blank section', () => {
  const msg = buildAlertGroupMessage([SCANNER, { ...SCANNER, ruleName: 'Other', severity: 'low' }]);

  assert.ok(!msg.body.endsWith('\n'), 'trailing blank line');
  assert.ok(!msg.body.includes('\n\n\n'), 'double blank line inside body');
});

test('grouping cannot smuggle a sub-threshold alert past the severity gate', () => {
  // The property the engine relies on: the gate is applied PER alert and only
  // survivors are grouped, so a medium finding riding along with a critical one
  // is still filtered when the operator asked for high-and-above only.
  const raised = [CMDI, SQLI, SCANNER];
  const passing = raised.filter((a) => severityPasses(a.severity, 'high'));

  assert.deepEqual(
    passing.map((a) => a.ruleName),
    ['Command Injection Attempt', 'SQL Injection Attempt'],
    'medium should not survive a high threshold'
  );
});

test('a group whose alerts are all sub-threshold has nothing left to send', () => {
  const passing = [SCANNER, { ...SCANNER, severity: 'low' }].filter((a) =>
    severityPasses(a.severity, 'high')
  );
  assert.equal(passing.length, 0, 'nothing should survive, so no notification is sent');
});
