/**
 * Every alert notification names the alert by its ALR-#### reference, in the
 * subject (the email subject, Slack bold line, ntfy Title) and in the body, so
 * the operator can quote it in analysis. Exposure notifications name the alert
 * the finding raised.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAlertMessage, buildAlertGroupMessage, buildExposureMessage } from './notificationService';
import { toExposureNotice } from '../exposure/findingWriter';

const SQLI = { id: 4821, severity: 'high', ruleName: 'SQL Injection Attempt', title: 'SQL Injection from 203.0.113.59' };
const CMDI = { id: 4822, severity: 'critical', ruleName: 'Command Injection Attempt', title: 'Command Injection from 203.0.113.59' };

test('a single alert carries its reference in the title and body', () => {
  const msg = buildAlertMessage(SQLI);
  assert.equal(msg.title, '[SIEMBox] HIGH alert ALR-4821: SQL Injection from 203.0.113.59');
  assert.match(msg.body, /^Alert: ALR-4821\nRule: SQL Injection Attempt\n/);
});

test('a group leads with the worst alert reference and lists every reference', () => {
  const msg = buildAlertGroupMessage([SQLI, CMDI]);
  assert.equal(msg.title, '[SIEMBox] CRITICAL alert ALR-4822: Command Injection from 203.0.113.59 (+1 more)');
  assert.ok(msg.body.includes('- ALR-4821 [HIGH] SQL Injection Attempt: SQL Injection from 203.0.113.59'));
  assert.ok(msg.body.includes('- ALR-4822 [CRITICAL] Command Injection Attempt: Command Injection from 203.0.113.59'));
});

test('a message with no alert id (the test preview) has no reference and no stray space', () => {
  const msg = buildAlertMessage({ ...SQLI, id: undefined });
  assert.equal(msg.title, '[SIEMBox] HIGH alert: SQL Injection from 203.0.113.59');
  assert.ok(!msg.body.includes('ALR-'));
});

test('an exposure notification names the alert its finding raised', () => {
  const finding = {
    source: 'leaked-creds',
    severity: 'high',
    title: 'alice@example.com in a breach',
    description: 'd',
  } as Parameters<typeof toExposureNotice>[0];
  const one = buildExposureMessage([toExposureNotice(finding, 77)]);
  assert.match(one.body, /^Alert: ALR-77\n/);
  const two = buildExposureMessage([toExposureNotice(finding, 77), toExposureNotice(finding, 78)]);
  assert.ok(two.body.includes('- ALR-77 [HIGH]'));
  assert.ok(two.body.includes('- ALR-78 [HIGH]'));
  assert.ok(!buildExposureMessage([toExposureNotice(finding)]).body.includes('ALR-'));
});
