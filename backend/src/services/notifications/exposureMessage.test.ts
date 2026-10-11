/**
 * Exposure notifications. One new finding reads like an alert; a check that
 * surfaces many at once (a monitored email domain can return dozens of
 * accounts) must still produce ONE message, led by the worst finding, so a
 * first run can't flood Slack/email/ntfy. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildExposureMessage, type ExposureNotice } from './notificationService';

const notice = (severity: string, title: string, description?: string): ExposureNotice => ({
  source: 'leaked-creds',
  severity,
  title,
  description,
});

test('a single finding produces an alert-style message', () => {
  const msg = buildExposureMessage([
    notice(
      'high',
      'alice@example.com found in Adobe breach',
      'Source: Have I Been Pwned (https://haveibeenpwned.com).'
    ),
  ]);
  assert.equal(msg.title, '[SIEMBox] HIGH exposure: alice@example.com found in Adobe breach');
  assert.equal(msg.severity, 'high');
  assert.match(msg.body, /^Source: leaked-creds\nSeverity: high\n/);
  assert.match(msg.body, /haveibeenpwned\.com/);
});

test('many findings become one message led by the worst, listing at most ten', () => {
  const findings = [
    notice('medium', 'a@example.com found in Canva breach'),
    notice('high', 'b@example.com found in Adobe breach', 'worst one'),
    ...Array.from({ length: 12 }, (_, i) =>
      notice('low', `spam${i}@example.com found in Spam breach`)
    ),
  ];
  const msg = buildExposureMessage(findings);

  assert.equal(msg.severity, 'high');
  assert.equal(
    msg.title,
    '[SIEMBox] HIGH exposure: b@example.com found in Adobe breach (+13 more)'
  );
  const lines = msg.body.split('\n');
  assert.equal(lines[0], '14 new exposure findings.');
  assert.equal(lines[2], '- [HIGH] b@example.com found in Adobe breach');
  assert.equal(lines[3], '- [MEDIUM] a@example.com found in Canva breach');
  assert.equal(lines.filter((l) => l.startsWith('- [')).length, 10);
  assert.ok(lines.includes('- ...and 4 more'));
  assert.ok(lines.includes('worst one'));
});
