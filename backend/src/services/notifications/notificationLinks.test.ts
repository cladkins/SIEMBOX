/**
 * Links to the alert in notifications, per channel. With a public URL set,
 * every message links to `${publicUrl}/alerts?alert=ALR-n` (or the fixed page
 * it is about); without one, the message is exactly what it was before: the
 * ALR-#### reference and no link. Slack and email escape what an attacker can
 * put in an alert title, so the title can neither add a link nor HTML.
 * Pure: no database, no network. Run with `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAlertGroupMessage,
  buildAlertMessage,
  buildChannelTestMessage,
  buildExposureMessage,
  buildIngestionMessage,
  buildVulnScanMessage,
  emailContent,
  ntfyRequest,
  slackPayload,
  type NotificationMessage,
} from './notificationService';
import { alertLink, appLink } from './notificationLinks';

const BASE = 'https://siem.example.com';
const SUB = 'https://example.com/siembox';
const SQLI = { id: 4821, severity: 'high', ruleName: 'SQL Injection Attempt', title: 'SQL Injection from 203.0.113.59' };
const CMDI = { id: 4822, severity: 'critical', ruleName: 'Command Injection Attempt', title: 'Command Injection from 203.0.113.59' };
const ALERT_URL = `${BASE}/alerts?alert=ALR-4821`;

/** Every URL-looking string anywhere in what the channels would send. */
function allPayloads(msg: NotificationMessage): string {
  const ntfy = ntfyRequest(msg);
  const email = emailContent(msg);
  return [slackPayload(msg).text, JSON.stringify(ntfy.headers), ntfy.body, email.text, email.html ?? ''].join('\n');
}

test('link builders: fixed paths on the public URL, alert number parsed', () => {
  assert.deepEqual(alertLink(BASE, 4821), { label: 'Open ALR-4821', url: ALERT_URL });
  assert.deepEqual(alertLink(SUB, 7), { label: 'Open ALR-7', url: `${SUB}/alerts?alert=ALR-7` });
  assert.equal(alertLink(null, 4821), null);
  assert.equal(alertLink('', 4821), null);
  assert.equal(alertLink(BASE, '4821&x=<script>'), null);
  assert.equal(alertLink(BASE, 0), null);
  assert.equal(alertLink(BASE, 1.5), null);
  assert.deepEqual(appLink(BASE, 'digitalRisk', 'Digital Risk'), { label: 'Digital Risk', url: `${BASE}/digital-risk` });
});

test('single alert: Slack, email and ntfy carry the exact link', () => {
  const msg = buildAlertMessage(SQLI, BASE);
  assert.deepEqual(msg.links, [{ label: 'Open ALR-4821', url: ALERT_URL }]);

  assert.equal(
    slackPayload(msg).text,
    '*[SIEMBox] HIGH alert ALR-4821: SQL Injection from 203.0.113.59*\n' +
      'Alert: ALR-4821\nRule: SQL Injection Attempt\nSeverity: high\n\n' +
      `<${ALERT_URL}|Open ALR-4821>`
  );

  const email = emailContent(msg);
  assert.equal(email.subject, '[SIEMBox] HIGH alert ALR-4821: SQL Injection from 203.0.113.59');
  assert.equal(email.text, `Alert: ALR-4821\nRule: SQL Injection Attempt\nSeverity: high\n\nOpen ALR-4821: ${ALERT_URL}`);
  assert.ok(email.html?.includes(`<a href="${ALERT_URL}">Open ALR-4821</a>`));

  const ntfy = ntfyRequest(msg);
  assert.equal(ntfy.headers.Click, ALERT_URL);
  assert.equal(ntfy.body, `Alert: ALR-4821\nRule: SQL Injection Attempt\nSeverity: high\n\nOpen ALR-4821: ${ALERT_URL}`);
});

test('a sub-path public URL is kept in the link', () => {
  const msg = buildAlertMessage(SQLI, SUB);
  assert.equal(ntfyRequest(msg).headers.Click, `${SUB}/alerts?alert=ALR-4821`);
});

test('no public URL: no link anywhere, and the payloads are what they were', () => {
  for (const url of [undefined, null, '']) {
    const msg = buildAlertMessage(SQLI, url);
    assert.equal(msg.links, undefined);
    assert.equal(slackPayload(msg).text, `*${msg.title}*\n${msg.body}`);
    assert.deepEqual(emailContent(msg), { subject: msg.title, text: msg.body });
    const ntfy = ntfyRequest(msg);
    assert.equal(ntfy.body, msg.body);
    assert.equal(ntfy.headers.Click, undefined);
    assert.doesNotMatch(allPayloads(msg), /https?:\/\//);
  }
  for (const msg of [
    buildAlertGroupMessage([SQLI, CMDI]),
    buildExposureMessage([{ alertId: 9, source: 'leaked-creds', severity: 'high', title: 't' }]),
    buildExposureMessage([{ source: 'domain-monitor', severity: 'high', title: 't' }]),
    buildVulnScanMessage({ target: '10.0.0.5', summary: '1 high', severity: 'high' }),
    buildIngestionMessage({ healthy: false, stallMinutes: 30 }),
    buildChannelTestMessage('Ops Slack'),
  ]) {
    assert.equal(msg.links, undefined, msg.title);
    assert.doesNotMatch(allPayloads(msg), /https?:\/\//, msg.title);
  }
});

test('a group links the worst alert first, then each alert, then the Alerts list', () => {
  const msg = buildAlertGroupMessage([SQLI, CMDI], BASE);
  assert.deepEqual(msg.links, [
    { label: 'Open ALR-4822', url: `${BASE}/alerts?alert=ALR-4822` },
    { label: 'Open ALR-4821', url: ALERT_URL },
    { label: 'All alerts', url: `${BASE}/alerts` },
  ]);
  assert.equal(ntfyRequest(msg).headers.Click, `${BASE}/alerts?alert=ALR-4822`);
  assert.ok(
    slackPayload(msg).text.endsWith(
      `\n\n<${BASE}/alerts?alert=ALR-4822|Open ALR-4822>\n<${ALERT_URL}|Open ALR-4821>\n<${BASE}/alerts|All alerts>`
    )
  );
  assert.ok(emailContent(msg).text.endsWith(`All alerts: ${BASE}/alerts`));
});

test('the test-alert preview (no real alert) links to the Alerts list', () => {
  const msg = buildAlertMessage({ ...SQLI, id: undefined }, BASE);
  assert.deepEqual(msg.links, [{ label: 'All alerts', url: `${BASE}/alerts` }]);
});

test('exposure: the alert the finding raised, else Digital Risk', () => {
  const raised = buildExposureMessage([{ alertId: 77, source: 'leaked-creds', severity: 'high', title: 'a@example.com' }], BASE);
  assert.deepEqual(raised.links, [{ label: 'Open ALR-77', url: `${BASE}/alerts?alert=ALR-77` }]);

  const none = buildExposureMessage([{ source: 'domain-monitor', severity: 'high', title: 'example.com expires' }], BASE);
  assert.deepEqual(none.links, [{ label: 'Digital Risk', url: `${BASE}/digital-risk` }]);

  const many = buildExposureMessage(
    [
      { alertId: 77, source: 'leaked-creds', severity: 'medium', title: 'a' },
      { alertId: 78, source: 'leaked-creds', severity: 'high', title: 'b' },
      { source: 'leaked-creds', severity: 'low', title: 'c' },
    ],
    BASE
  );
  assert.deepEqual(many.links, [
    { label: 'Open ALR-78', url: `${BASE}/alerts?alert=ALR-78` },
    { label: 'Open ALR-77', url: `${BASE}/alerts?alert=ALR-77` },
    { label: 'Digital Risk', url: `${BASE}/digital-risk` },
  ]);
});

test('vulnerability, ingestion and channel-test messages link to their page', () => {
  assert.deepEqual(buildVulnScanMessage({ target: '10.0.0.5', summary: '1 high', severity: 'high' }, BASE).links, [
    { label: 'Vulnerability Management', url: `${BASE}/vulnerability-management` },
  ]);
  assert.deepEqual(buildIngestionMessage({ healthy: true, stallMinutes: 30 }, BASE).links, [
    { label: 'System status', url: `${BASE}/settings/system` },
  ]);
  assert.deepEqual(buildChannelTestMessage('Ops Slack', BASE).links, [
    { label: 'Open SIEMBox', url: `${BASE}/settings/notifications` },
  ]);
});

const HOSTILE = {
  id: 4821,
  severity: 'high',
  ruleName: 'Rule <!channel>',
  title: '<https://evil.example|Click to reset> & <script>alert("x")</script> \'q\'',
  description: 'see <https://evil.example> & "more"',
};

test('Slack: a hostile title cannot add a link or a mention', () => {
  const text = slackPayload(buildAlertMessage(HOSTILE, BASE)).text;
  assert.ok(!text.includes('<https://evil'), 'no link markup from the title or description');
  assert.ok(!text.includes('<!channel>'), 'no @channel from the rule name');
  assert.ok(text.includes('&lt;https://evil.example|Click to reset&gt; &amp; &lt;script&gt;'));
  // The only link markup is the one SIEMBox built.
  const links = text.match(/<[^<>]*>/g);
  assert.deepEqual(links, [`<${ALERT_URL}|Open ALR-4821>`]);
});

test('Slack: a | or > in the URL path cannot end the link early', () => {
  const text = slackPayload(buildAlertMessage(SQLI, 'https://example.com/a|b')).text;
  assert.ok(text.endsWith('<https://example.com/a%7Cb/alerts?alert=ALR-4821|Open ALR-4821>'));
});

test('email: the HTML part escapes the title and body; the href is escaped', () => {
  const html = emailContent(buildAlertMessage(HOSTILE, BASE)).html ?? '';
  assert.ok(!html.includes('<script>'), 'no script tag');
  assert.ok(!html.includes('href="https://evil'), 'no attacker href');
  assert.ok(html.includes('&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &#39;q&#39;'));
  assert.deepEqual(html.match(/href="[^"]*"/g), [`href="${ALERT_URL}"`]);
  // A path character that matters in HTML is escaped in the href.
  const odd = emailContent(buildAlertMessage(SQLI, 'https://example.com/a\'b')).html ?? '';
  assert.ok(odd.includes('href="https://example.com/a&#39;b/alerts?alert=ALR-4821"'));
});

test('ntfy: a title beyond ASCII is sent as an RFC 2047 encoded-word, an ASCII one as is', () => {
  const title = 'Test alert — ünïcode';
  const encoded = ntfyRequest({ title, body: 'b' }).headers.Title;
  assert.equal(encoded, `=?UTF-8?B?${Buffer.from(title, 'utf8').toString('base64')}?=`);
  assert.match(encoded, /^[\x20-\x7e]+$/);
  assert.equal(ntfyRequest({ title: 'Plain title', body: 'b' }).headers.Title, 'Plain title');
});

test('ntfy and the email text part carry the plain URL, untouched by the title', () => {
  const msg = buildAlertMessage(HOSTILE, BASE);
  assert.equal(ntfyRequest(msg).headers.Click, ALERT_URL);
  assert.ok(emailContent(msg).text.endsWith(`\n\nOpen ALR-4821: ${ALERT_URL}`));
});
