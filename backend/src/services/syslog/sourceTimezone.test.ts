/**
 * Zoneless syslog header timestamps are read in the sender's timezone
 * (default UTC), not the backend's local time. The production case: a UniFi
 * AP in America/Chicago sends "Nov  3 12:17:04" at 18:17 UTC; it must be
 * stored as 18:17 UTC, not 12:17 UTC. DB-free; `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSyslogMessage } from './syslogParser';
import {
  bsdTimestampToUtc,
  isValidTimezone,
  normalizeSourceIp,
  sourceTimezones,
  wallClockToUtc,
  zoneOffsetMs,
} from './sourceTimezone';

const NOW = new Date('2026-11-03T18:17:30Z');
const UNIFI = '<30>Nov  3 12:17:04 U7-Pro-Office hostapd: ath1: STA 11:22:33:44:55:66 IEEE 802.11: associated';

test('a Chicago-time header is stored at the right UTC instant (CST, UTC-6)', () => {
  const parsed = parseSyslogMessage(UNIFI, { timezone: 'America/Chicago', now: NOW });
  assert.equal(parsed.timestamp.toISOString(), '2026-11-03T18:17:04.000Z');
  assert.equal(parsed.appName, 'hostapd');
});

test('the default is UTC, whatever the backend process TZ is', () => {
  const parsed = parseSyslogMessage('<30>Nov  3 18:17:04 pve kernel: hello', { now: NOW });
  assert.equal(parsed.timestamp.toISOString(), '2026-11-03T18:17:04.000Z');
});

test('daylight saving time: October in Chicago is CDT (UTC-5)', () => {
  const parsed = parseSyslogMessage('<30>Oct 29 15:36:00 pve kernel: x', {
    timezone: 'America/Chicago',
    now: new Date('2026-10-29T21:00:00Z'),
  });
  assert.equal(parsed.timestamp.toISOString(), '2026-10-29T20:36:00.000Z');
});

test('year rollover: a December 31 line read on January 1 is last year', () => {
  const d = bsdTimestampToUtc('UTC', 11, 31, 23, 59, 59, new Date('2027-01-01T00:00:05Z'));
  assert.equal(d.toISOString(), '2026-12-31T23:59:59.000Z');
});

test('RFC 5424 timestamps keep their own offset; a zoneless one uses the source zone', () => {
  const withZone = parseSyslogMessage('<34>1 2026-11-03T12:17:04-06:00 host app - - - m', { timezone: 'Asia/Tokyo' });
  assert.equal(withZone.timestamp.toISOString(), '2026-11-03T18:17:04.000Z');
  const zoneless = parseSyslogMessage('<34>1 2026-11-03T12:17:04.250 host app - - - m', { timezone: 'America/Chicago' });
  assert.equal(zoneless.timestamp.toISOString(), '2026-11-03T18:17:04.250Z');
});

test('offsets and wall-clock conversion', () => {
  assert.equal(zoneOffsetMs('America/Chicago', Date.parse('2026-11-03T18:00:00Z')), -6 * 3600_000);
  assert.equal(zoneOffsetMs('America/Chicago', Date.parse('2026-07-01T18:00:00Z')), -5 * 3600_000);
  assert.equal(zoneOffsetMs('UTC', Date.now()), 0);
  assert.equal(wallClockToUtc('Europe/Berlin', 2026, 0, 15, 12, 0, 0).toISOString(), '2026-01-15T11:00:00.000Z');
});

test('timezone validation and source IP normalization', () => {
  assert.equal(isValidTimezone('America/Chicago'), true);
  assert.equal(isValidTimezone('UTC'), true);
  assert.equal(isValidTimezone('Mars/Olympus'), false);
  assert.equal(isValidTimezone(''), false);
  assert.equal(isValidTimezone(42), false);
  assert.equal(normalizeSourceIp('::ffff:192.168.1.20'), '192.168.1.20');
  assert.equal(normalizeSourceIp('fe80::1'), 'fe80::1');
});

test('per-source lookup: configured IPs get their zone, others the default', () => {
  sourceTimezones.set({ '192.168.1.20': 'America/Chicago' }, 'UTC');
  assert.equal(sourceTimezones.forSource('192.168.1.20'), 'America/Chicago');
  assert.equal(sourceTimezones.forSource('::ffff:192.168.1.20'), 'America/Chicago', 'TCP IPv4-mapped address');
  assert.equal(sourceTimezones.forSource('192.168.1.21'), 'UTC');
  assert.equal(sourceTimezones.forSource(null), 'UTC');
  sourceTimezones.set({}, 'Europe/Berlin');
  assert.equal(sourceTimezones.forSource('10.0.0.1'), 'Europe/Berlin');
});
