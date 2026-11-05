import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { COMMON_TIMEZONES, normalizeSourceIp, timezoneMap, timezoneOptions, utcOffsetLabel } from './syslogTimezones.ts';

describe('timezoneOptions', () => {
  it('lists the common zones first, then the rest sorted, without duplicates', () => {
    const opts = timezoneOptions(['Europe/Paris', 'America/Chicago', 'Asia/Kolkata', 'UTC']);
    assert.deepEqual(opts.slice(0, COMMON_TIMEZONES.length), [...COMMON_TIMEZONES]);
    assert.deepEqual(opts.slice(COMMON_TIMEZONES.length), ['Asia/Kolkata', 'Europe/Paris']);
  });
  it('falls back to the common list', () => {
    assert.deepEqual(timezoneOptions([]), [...COMMON_TIMEZONES]);
  });
});

describe('timezoneMap', () => {
  it('keys by normalized source IP', () => {
    const map = timezoneMap({
      default_timezone: 'UTC',
      sources: [{ source_ip: '::ffff:192.168.1.20', timezone: 'America/Chicago' }],
    });
    assert.equal(map.get('192.168.1.20'), 'America/Chicago');
    assert.equal(timezoneMap(null).size, 0);
  });
  it('normalizes IPv4-mapped addresses only', () => {
    assert.equal(normalizeSourceIp(' ::FFFF:10.0.0.1 '), '10.0.0.1');
    assert.equal(normalizeSourceIp('fe80::1'), 'fe80::1');
  });
});

describe('utcOffsetLabel', () => {
  it('shows the offset at the given instant, DST included', () => {
    assert.equal(utcOffsetLabel('America/Chicago', new Date('2026-11-05T18:00:00Z')), 'UTC-6');
    assert.equal(utcOffsetLabel('America/Chicago', new Date('2026-07-01T18:00:00Z')), 'UTC-5');
    assert.equal(utcOffsetLabel('Asia/Kolkata', new Date('2026-11-05T18:00:00Z')), 'UTC+5:30');
    assert.equal(utcOffsetLabel('UTC'), 'UTC');
  });
  it('is empty for an unknown zone', () => {
    assert.equal(utcOffsetLabel('Mars/Olympus'), '');
  });
});
